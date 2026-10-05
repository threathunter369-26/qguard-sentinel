"""Building list queries: filtering, sorting, pagination and counting.

Every collection endpoint in the platform goes through :func:`paginate`, so
they all behave the same way and all report a true total. The alternative —
each router writing its own ``limit``/``offset``/``count`` — is where
off-by-one bugs and estimated totals come from.

Sorting is the part that needs care. A sort field arrives as a string from the
client and ends up in an ``ORDER BY``, so it is never interpolated into SQL.
Each router declares a mapping from the names it publishes to the columns it
owns, and :func:`apply_sort` resolves against that mapping only. A name that
is not in the mapping is rejected with a message listing the ones that are,
rather than being dropped — a client that asked for a specific order and
silently got a different one has been given wrong data.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.sql.elements import ColumnElement

from qguard.api.schemas import MAX_PAGE_SIZE, Page, Pagination, SortOrder, TimeRange
from qguard.common.errors import ValidationError

T = TypeVar("T")

#: A router's published sort names mapped to the columns they refer to.
SortMap = dict[str, InstrumentedAttribute[Any]]


def apply_sort(
    stmt: Select[Any],
    sort: SortOrder,
    *,
    allowed: SortMap,
    default: InstrumentedAttribute[Any],
    tiebreaker: InstrumentedAttribute[Any] | None = None,
) -> Select[Any]:
    """Order a statement by a client-supplied field name.

    ``tiebreaker`` matters more than it looks: without a unique final sort key,
    two rows with equal sort values can come back in a different order on each
    page, so a client paging through the collection sees one row twice and
    misses another entirely.
    """
    if sort.sort_by:
        column = allowed.get(sort.sort_by)
        if column is None:
            raise ValidationError(
                f"{sort.sort_by!r} is not a sortable field for this collection.",
                details={"sortable_fields": sorted(allowed)},
            )
    else:
        column = default

    ordering: list[Any] = [column.desc() if sort.sort_dir == "desc" else column.asc()]
    if tiebreaker is not None and tiebreaker is not column:
        ordering.append(tiebreaker.desc() if sort.sort_dir == "desc" else tiebreaker.asc())
    return stmt.order_by(*ordering)


async def count_rows(session: AsyncSession, stmt: Select[Any]) -> int:
    """Count the rows a statement would return.

    The statement's own ordering and any eager loading are stripped: they
    cannot change the count, and ``ORDER BY`` on a counted subquery is both
    wasted work and, for a sort on a joined column, an error.
    """
    counted = stmt.order_by(None).options()
    total = await session.scalar(select(func.count()).select_from(counted.subquery()))
    return int(total or 0)


async def paginate(
    session: AsyncSession,
    stmt: Select[Any],
    pagination: Pagination,
    *,
    serialize: Any,
) -> Page[Any]:
    """Run a list query and return one page with a true total.

    The count runs first so an empty result is reported as a real zero rather
    than inferred from an empty page. Both queries run in one transaction, so
    the total and the page describe the same snapshot.
    """
    limit = min(pagination.limit, MAX_PAGE_SIZE)
    total = await count_rows(session, stmt)
    if total == 0:
        return Page.empty(limit=limit, offset=pagination.offset)
    if pagination.offset >= total:
        # Past the end is a valid request, not an error: the client may have
        # paged while rows were deleted. The true total still comes back.
        return Page.of([], total=total, limit=limit, offset=pagination.offset)

    rows = (await session.execute(stmt.limit(limit).offset(pagination.offset))).scalars().all()
    return Page.of(
        [serialize(row) for row in rows],
        total=total,
        limit=limit,
        offset=pagination.offset,
    )


def apply_time_range(
    stmt: Select[Any], window: TimeRange, column: InstrumentedAttribute[Any]
) -> Select[Any]:
    """Restrict a statement to a time window on one column."""
    if window.since is not None:
        stmt = stmt.where(column >= window.since)
    if window.until is not None:
        stmt = stmt.where(column <= window.until)
    return stmt


def apply_in(
    stmt: Select[Any],
    column: InstrumentedAttribute[Any],
    values: Sequence[str] | Sequence[uuid.UUID] | None,
) -> Select[Any]:
    """Restrict a statement to rows whose column is in a set, if one was given.

    An empty sequence is treated as "no filter" rather than "match nothing":
    an absent query parameter and an empty one arrive the same way over HTTP,
    and interpreting them as an impossible filter would make every such
    request return zero rows.
    """
    if not values:
        return stmt
    return stmt.where(column.in_(list(values)))


def apply_search(
    stmt: Select[Any],
    term: str | None,
    columns: Sequence[InstrumentedAttribute[Any]],
    *,
    min_length: int = 2,
) -> Select[Any]:
    """Case-insensitive substring search across several columns.

    The term is passed as a bound parameter and its LIKE metacharacters are
    escaped, so a search for ``100%`` matches the literal text rather than
    becoming a wildcard. Short terms are ignored: a one-character search
    matches most of the table and costs a full scan.
    """
    if not term or len(term.strip()) < min_length or not columns:
        return stmt
    cleaned = term.strip()
    escaped = cleaned.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
    pattern = f"%{escaped}%"
    clauses: list[ColumnElement[bool]] = [column.ilike(pattern, escape="\\") for column in columns]
    if len(clauses) == 1:
        return stmt.where(clauses[0])
    from sqlalchemy import or_

    return stmt.where(or_(*clauses))


def apply_array_overlap(
    stmt: Select[Any], column: InstrumentedAttribute[Any], values: Sequence[str] | None
) -> Select[Any]:
    """Restrict to rows whose array column shares any element with ``values``."""
    if not values:
        return stmt
    return stmt.where(column.overlap(list(values)))


async def group_count(
    session: AsyncSession,
    stmt: Select[Any],
    column: InstrumentedAttribute[Any],
) -> list[tuple[str, int]]:
    """Count rows per distinct value of one column, honouring a filtered query.

    Takes the same filtered statement the list endpoint uses, so a breakdown
    shown beside a table always describes exactly the rows in that table. A
    breakdown computed from a separate unfiltered query is the usual reason a
    chart and a table disagree.
    """
    base = stmt.order_by(None).subquery()
    target = base.c[column.key]
    rows = await session.execute(
        select(target, func.count())
        .select_from(base)
        .group_by(target)
        .order_by(func.count().desc())
    )
    return [(str(key), int(count)) for key, count in rows.all() if key is not None]


async def bucketed_count(
    session: AsyncSession,
    stmt: Select[Any],
    column: InstrumentedAttribute[Any],
    *,
    interval: str = "day",
) -> list[tuple[datetime, int]]:
    """Count rows per time bucket, for a trend series.

    ``interval`` is validated against a fixed set rather than passed through:
    it reaches ``date_trunc``, and accepting an arbitrary string there would
    be an injection point.
    """
    if interval not in ("hour", "day", "week", "month"):
        raise ValidationError(
            f"{interval!r} is not a supported trend interval.",
            details={"supported": ["hour", "day", "week", "month"]},
        )
    base = stmt.order_by(None).subquery()
    target = base.c[column.key]
    bucket = func.date_trunc(interval, target).label("bucket")
    rows = await session.execute(
        select(bucket, func.count())
        .select_from(base)
        .where(target.is_not(None))
        .group_by(bucket)
        .order_by(bucket)
    )
    return [(value, int(count)) for value, count in rows.all()]


__all__ = [
    "SortMap",
    "apply_array_overlap",
    "apply_in",
    "apply_search",
    "apply_sort",
    "apply_time_range",
    "bucketed_count",
    "count_rows",
    "group_count",
    "paginate",
]
