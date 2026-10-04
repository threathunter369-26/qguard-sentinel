"""API inventory: imported specifications and discovered endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class ApiSpecification(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """An imported OpenAPI, GraphQL or AsyncAPI definition."""

    __tablename__ = "api_specifications"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    spec_format: Mapped[str] = mapped_column(String(24), nullable=False)
    """``openapi3``, ``openapi3_1``, ``swagger2``, ``graphql``, ``asyncapi``, ``postman``."""
    spec_version: Mapped[str | None] = mapped_column(String(24))
    api_version: Mapped[str | None] = mapped_column(String(48))
    base_urls: Mapped[list[str]] = mapped_column(
        ARRAY(String(1024)), nullable=False, default=list, server_default="{}"
    )
    document: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """The parsed specification. Imports are fetched through the SSRF guard."""
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    security_schemes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    global_security: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    endpoint_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    unauthenticated_endpoint_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    source_url: Mapped[str | None] = mapped_column(String(2048))
    imported_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    parse_warnings: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default="{}"
    )

    endpoints: Mapped[list[ApiEndpoint]] = relationship(
        back_populates="specification", cascade="all, delete-orphan", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id", "name", "api_version", name="uq_api_specifications_org_name_version"
        ),
        CheckConstraint(
            "spec_format IN ('openapi3','openapi3_1','swagger2','graphql','asyncapi','postman')",
            name="spec_format_valid",
        ),
    )


class ApiEndpoint(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A single API operation, with the security properties assessed for it."""

    __tablename__ = "api_endpoints"

    specification_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_specifications.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    operation_id: Mapped[str | None] = mapped_column(String(240))
    summary: Mapped[str | None] = mapped_column(String(600))
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )

    requires_authentication: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    auth_schemes: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    scopes_required: Mapped[list[str]] = mapped_column(
        ARRAY(String(120)), nullable=False, default=list, server_default="{}"
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    request_schema: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    responses: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    is_deprecated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    is_state_changing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    handles_sensitive_data: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    has_object_identifier: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Path or body carries an object id — the precondition for a BOLA/IDOR check."""
    rate_limit_declared: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    risk_flags: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Static assessment notes keyed by check, e.g. ``{"missing_auth": {...}}``."""
    discovery_source: Mapped[str] = mapped_column(
        String(32), nullable=False, default="spec", server_default="'spec'"
    )
    """``spec``, ``crawl``, ``traffic`` or ``manual``."""
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    specification: Mapped[ApiSpecification | None] = relationship(
        back_populates="endpoints", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id", "specification_id", "method", "path", name="uq_api_endpoints_operation"
        ),
        Index("ix_api_endpoints_org_auth", "org_id", "requires_authentication"),
        Index("ix_api_endpoints_asset_method", "asset_id", "method"),
        CheckConstraint(
            "method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE',"
            "'QUERY','SUBSCRIPTION','MUTATION')",
            name="api_method_valid",
        ),
    )
