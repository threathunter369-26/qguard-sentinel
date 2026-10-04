"""Database engine, session management and tenant-scoped session guards.

Tenant isolation is enforced in two independent layers (defence in depth):

1. **PostgreSQL row level security.** Every tenant-scoped table carries an
   ``org_id`` and an RLS policy comparing it to the ``app.current_org_id``
   session setting. :func:`tenant_session` sets that setting with ``SET LOCAL``
   so it is scoped to the surrounding transaction and cannot leak across
   pooled connections.
2. **Application authorization.** The repository and service layers filter by
   ``org_id`` explicitly, so a missing or misapplied policy still cannot expose
   another tenant's rows.

Both layers are exercised by the tenant-isolation test suite.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, String, event, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column
from sqlalchemy.pool import NullPool

from qguard.common.config import get_settings
from qguard.common.logging import get_logger

log = get_logger(__name__)

#: Deterministic constraint naming so Alembic autogenerate produces stable diffs.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every QGuard model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[str]: JSONB,
        uuid.UUID: PGUUID(as_uuid=True),
        datetime: DateTime(timezone=True),
    }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


class UUIDPrimaryKeyMixin:
    """Server-generated UUID primary key.

    UUIDs rather than sequences: identifiers appear in URLs, reports and
    exported evidence manifests, where a guessable sequential id is an IDOR
    hazard and leaks volume information between tenants.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
        default=uuid.uuid4,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Retains rows for audit and retention purposes instead of hard-deleting."""

    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class OrgScopedMixin:
    """Marks a model as tenant-scoped.

    Declares a real foreign key to ``organizations`` so the database enforces
    referential integrity, and every such table receives a row level security
    policy in the migration that creates it.
    """

    @declared_attr
    def org_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        return mapped_column(
            PGUUID(as_uuid=True),
            ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )


class AuthorMixin:
    created_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), default=None)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), default=None)


#: PostgreSQL ``uuid[]`` column type, used for denormalised id lists where a
#: join table would add cost without adding meaning (e.g. a scan's target ids).
UUIDArray = ARRAY(PGUUID(as_uuid=True))


def short_str(length: int = 255, **kwargs: Any) -> Mapped[str]:
    return mapped_column(String(length), **kwargs)


# --------------------------------------------------------------------- engine
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def create_engine(url: str | None = None, **overrides: Any) -> AsyncEngine:
    settings = get_settings()
    url = url or settings.async_database_url
    kwargs: dict[str, Any] = {
        "echo": settings.database_echo,
        "pool_pre_ping": True,
        "future": True,
    }
    if settings.env == "test":
        # Tests manage their own transactional boundaries; pooling across event
        # loops in pytest-asyncio causes cross-loop reuse errors.
        kwargs["poolclass"] = NullPool
    else:
        kwargs["pool_size"] = settings.database_pool_size
        kwargs["max_overflow"] = settings.database_max_overflow
        kwargs["pool_recycle"] = 1800
    kwargs.update(overrides)

    engine = create_async_engine(url, **kwargs)

    statement_timeout = settings.database_statement_timeout_ms
    if statement_timeout > 0:

        @event.listens_for(engine.sync_engine, "connect")
        def _set_statement_timeout(dbapi_conn: Any, _record: Any) -> None:
            # A runaway analytics query must never pin a connection forever.
            with dbapi_conn.cursor() as cur:
                cur.execute(f"SET statement_timeout = {statement_timeout}")
                cur.execute("SET idle_in_transaction_session_timeout = 60000")

    return engine


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _session_factory


async def dispose_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None


# -------------------------------------------------------------------- sessions
@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Unscoped session. Only for system-level work (migrations, workers, auth)."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            if session.in_transaction():
                await session.commit()
        except Exception:
            await session.rollback()
            raise


async def apply_tenant_context(
    session: AsyncSession,
    org_id: uuid.UUID | str | None,
    user_id: uuid.UUID | str | None = None,
) -> None:
    """Bind the RLS session variables for the current transaction.

    ``SET LOCAL`` keeps the value bound to this transaction so a pooled
    connection handed to another tenant cannot inherit it.
    """
    if org_id is None:
        return
    # set_config() is parameterised, so the value can never be interpolated
    # into SQL text — important because org ids arrive from request context.
    await session.execute(
        text("SELECT set_config('app.current_org_id', :org, true)"),
        {"org": str(org_id)},
    )
    if user_id is not None:
        await session.execute(
            text("SELECT set_config('app.current_user_id', :uid, true)"),
            {"uid": str(user_id)},
        )


@asynccontextmanager
async def tenant_session(
    org_id: uuid.UUID | str,
    user_id: uuid.UUID | str | None = None,
) -> AsyncIterator[AsyncSession]:
    """Session with PostgreSQL row level security bound to one organization."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            await session.begin()
            await apply_tenant_context(session, org_id, user_id)
            yield session
            if session.in_transaction():
                await session.commit()
        except Exception:
            await session.rollback()
            raise


async def healthcheck(session: AsyncSession) -> dict[str, Any]:
    """Lightweight liveness probe used by ``/health``."""
    result = await session.execute(text("SELECT 1"))
    migration = await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
    return {
        "connected": result.scalar() == 1,
        "schema_version": migration.scalar(),
    }
