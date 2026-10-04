"""Pagination, sorting and filtering primitives.

The platform is specified to hold millions of findings, so no list endpoint ever
returns an unbounded result set. Two strategies are offered:

* **Offset pagination** for interactive tables that need a total count and the
  ability to jump to a page.
* **Keyset (cursor) pagination** for exports, streaming and deep traversal,
  where ``OFFSET`` degrades badly.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from typing import Any, Generic, Literal, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.common.errors import ValidationError

T = TypeVar("T")

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 25
#: Export endpoints stream instead of buffering, so they allow larger batches.
MAX_EXPORT_PAGE_SIZE = 5000


class PageParams(BaseModel):
    """Offset pagination and sort parameters."""

    page: int = Field(default=1, ge=1, le=100_000)
    page_size: int = Field(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)
    sort_by: str | None = None
    sort_dir: Literal["asc", "desc"] = "desc"

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


def page_params(
    page: int = Query(1, ge=1, le=100_000, description="1-indexed page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Items per page"),
    sort_by: str | None = Query(None, description="Field to sort by"),
    sort_dir: Literal["asc", "desc"] = Query("desc", description="Sort direction"),
) -> PageParams:
    """FastAPI dependency producing validated :class:`PageParams`."""
    return PageParams(page=page, page_size=page_size, sort_by=sort_by, sort_dir=sort_dir)


class PageMeta(BaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int
    has_next: bool
    has_previous: bool


class Page(BaseModel, Generic[T]):
    """Envelope returned by every paginated list endpoint."""

    items: list[T]
    meta: PageMeta

    @classmethod
    def build(cls, items: Sequence[T], total: int, params: PageParams) -> Page[T]:
        total_pages = max(1, (total + params.page_size - 1) // params.page_size)
        return cls(
            items=list(items),
            meta=PageMeta(
                page=params.page,
                page_size=params.page_size,
                total=total,
                total_pages=total_pages,
                has_next=params.page < total_pages,
                has_previous=params.page > 1,
            ),
        )


class CursorPage(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    has_more: bool = False


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> dict[str, Any]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise ValidationError("The pagination cursor is malformed.") from exc
    if not isinstance(data, dict):
        raise ValidationError("The pagination cursor is malformed.")
    return data


def apply_sort(
    stmt: Select[Any],
    model: Any,
    params: PageParams,
    *,
    allowed: Sequence[str],
    default: str,
) -> Select[Any]:
    """Apply an allow-listed ORDER BY.

    The sort field is matched against an explicit allow-list rather than being
    passed through to the ORM, so a crafted ``sort_by`` can neither reach an
    unexposed column nor be used for SQL injection.
    """
    field = params.sort_by or default
    if field not in allowed:
        raise ValidationError(
            f"Cannot sort by {field!r}.",
            details={"allowed_sort_fields": sorted(allowed)},
        )
    column = getattr(model, field, None)
    if column is None:
        raise ValidationError(f"Cannot sort by {field!r}.")
    ordering = column.desc() if params.sort_dir == "desc" else column.asc()
    # Tie-break on the primary key so paging is stable when the sort column has
    # duplicate values — otherwise rows can be skipped or repeated across pages.
    return stmt.order_by(ordering, model.id.desc())


async def paginate(
    session: AsyncSession,
    stmt: Select[Any],
    params: PageParams,
    *,
    model: Any,
    allowed_sort: Sequence[str],
    default_sort: str,
) -> tuple[list[Any], int]:
    """Execute a count query and a page query, returning ``(rows, total)``."""
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = (await session.execute(count_stmt)).scalar_one()
    stmt = apply_sort(stmt, model, params, allowed=allowed_sort, default=default_sort)
    rows = (await session.execute(stmt.offset(params.offset).limit(params.limit))).scalars().all()
    return list(rows), int(total)


class SearchParams(BaseModel):
    """Free-text search term, sanitised for use in a SQL ``LIKE`` pattern."""

    q: str | None = Field(default=None, max_length=256)

    @field_validator("q")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @property
    def like_pattern(self) -> str | None:
        """Escaped ``ILIKE`` pattern.

        ``%``, ``_`` and ``\\`` are escaped so a user-supplied term is matched
        literally instead of becoming a wildcard that scans the whole table.
        """
        if not self.q:
            return None
        escaped = self.q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"
