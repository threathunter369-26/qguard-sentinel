"""Shared request and response shapes for the HTTP API.

Everything that more than one router needs lives here: the pagination
envelope, the sort and filter parameters, and the small value types that
appear across resources. One definition means one documented behaviour — a
client that can page one collection can page all of them.

Two deliberate choices:

* **Pagination is always explicit.** A list endpoint never returns an
  unbounded collection, and the envelope always reports the true total so a
  client can tell "no results" from "first page of many". A scan that produced
  40,000 findings must not be able to hand the browser 40,000 rows.
* **Totals are real.** ``total`` is a counted value from the database, not an
  estimate and never the length of the returned page. The frontend displays it
  directly, so an approximation here would become a wrong number on a
  dashboard.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Any, Generic, Literal, TypeVar

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")

#: Largest page a client may request. A caller asking for more is given this
#: and told so through ``limit`` in the response, rather than being refused.
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50

#: Largest offset accepted. Deep offsets force the database to count through
#: every preceding row; past this point a filter is the right answer, and
#: saying so is better than serving a query that times out.
MAX_OFFSET = 100_000


class Page(BaseModel, Generic[T]):
    """One page of a collection, with the information needed to request more."""

    items: list[T]
    total: int = Field(description="Total rows matching the filters, ignoring pagination.")
    limit: int = Field(description="Page size actually applied, which may be lower than requested.")
    offset: int
    has_more: bool

    @classmethod
    def of(cls, items: Sequence[T], *, total: int, limit: int, offset: int) -> Page[T]:
        return cls(
            items=list(items),
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(items)) < total,
        )

    @classmethod
    def empty(cls, *, limit: int = DEFAULT_PAGE_SIZE, offset: int = 0) -> Page[T]:
        return cls(items=[], total=0, limit=limit, offset=offset, has_more=False)


class Pagination(BaseModel):
    """Page selection, supplied as query parameters."""

    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_PAGE_SIZE,
            description=f"Rows per page, at most {MAX_PAGE_SIZE}.",
        ),
    ] = DEFAULT_PAGE_SIZE
    offset: Annotated[
        int,
        Query(ge=0, le=MAX_OFFSET, description="Rows to skip."),
    ] = 0


class SortOrder(BaseModel):
    """Sort selection, validated against a per-router allow-list.

    The field name reaches a SQL ``ORDER BY``, so it is never interpolated:
    the router maps the requested name onto a column it owns, and an
    unrecognised name is rejected rather than ignored. Silently ignoring it
    would return data sorted differently from what the client asked for, which
    is worse than an error.
    """

    sort_by: Annotated[str | None, Query(description="Field to sort by.")] = None
    sort_dir: Annotated[Literal["asc", "desc"], Query(description="Sort direction.")] = "desc"


class TimeRange(BaseModel):
    """An inclusive time window."""

    since: Annotated[datetime | None, Query(description="Include rows at or after this time.")] = (
        None
    )
    until: Annotated[datetime | None, Query(description="Include rows at or before this time.")] = (
        None
    )

    @field_validator("until")
    @classmethod
    def _ordered(cls, value: datetime | None, info: Any) -> datetime | None:
        since = info.data.get("since")
        if value is not None and since is not None and value < since:
            raise ValueError("`until` must not be earlier than `since`.")
        return value


class ResourceRef(BaseModel):
    """A minimal reference to another resource, for embedding in a response.

    Returned instead of the full object so a list of 200 findings does not
    carry 200 copies of an asset. The client fetches the full resource when it
    needs it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str | None = None


class Acknowledgement(BaseModel):
    """Response to a request whose result is an action rather than a resource."""

    ok: bool = True
    message: str
    affected: int = 0


class CountByKey(BaseModel):
    """One bucket of an aggregation. Used wherever a breakdown is returned."""

    key: str
    count: int
    label: str | None = None


class SeverityCounts(BaseModel):
    """Counts by severity, in the platform's fixed order.

    All five keys are always present, zero included. A dashboard that has to
    handle a missing key renders differently depending on the data, which is
    how a chart ends up showing four bars one day and five the next.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    @classmethod
    def from_rows(cls, rows: Sequence[tuple[str, int]]) -> SeverityCounts:
        counts = dict(rows)
        return cls(
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            info=counts.get("info", 0),
        )


class TrendPoint(BaseModel):
    """One point in a time series. ``bucket`` is the start of the interval."""

    bucket: datetime
    count: int


class CoverageNote(BaseModel):
    """Why a number may be incomplete.

    Attached to any metric derived from scans that did not fully succeed. A
    dashboard figure with no caveat reads as authoritative, so where coverage
    is partial the API says so and the UI shows it — rather than presenting a
    number that quietly understates the problem.
    """

    is_complete: bool
    reason: str | None = None
    degraded_engine_runs: int = 0
    failed_engine_runs: int = 0
    unauthorized_engine_runs: int = 0
    last_successful_scan_at: datetime | None = None


class ProblemDetail(BaseModel):
    """Error body. Matches what the application's exception handlers emit."""

    error: str
    message: str
    detail: dict[str, Any] | None = None
    request_id: str | None = None


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "MAX_OFFSET",
    "MAX_PAGE_SIZE",
    "Acknowledgement",
    "CountByKey",
    "CoverageNote",
    "Page",
    "Pagination",
    "ProblemDetail",
    "ResourceRef",
    "SeverityCounts",
    "SortOrder",
    "TimeRange",
    "TrendPoint",
]
