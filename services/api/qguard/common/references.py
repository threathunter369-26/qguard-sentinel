"""Human-readable reference identifiers.

Records are addressed by UUID internally, but people quote findings in tickets,
reports and conversations, so each gets a short readable reference such as
``VULN-2026-000291``. References are per organization and per year, allocated
with a PostgreSQL sequence-free counter that is safe under concurrency: the
insert takes the next value inside the same transaction, holding an advisory
lock for the counter so two concurrent scans cannot claim the same number.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

#: Advisory lock namespace for reference allocation. Distinct from the audit
#: namespace so the two never block each other.
_REFERENCE_LOCK_NAMESPACE: Final = 0x51475246  # "QGRF"

PREFIXES: Final[dict[str, str]] = {
    "scan": "SCAN",
    "finding": "FND",
    "vulnerability": "VULN",
    "case": "CASE",
    "evidence": "EV",
    "incident": "INC",
    "engagement": "PT",
    "report": "RPT",
    "authorization": "AUTH",
}


def _counter_table(kind: str) -> tuple[str, str]:
    """Map a reference kind to the table and column holding its references."""
    mapping = {
        "scan": ("scans", "reference"),
        "finding": ("findings", "reference"),
        "vulnerability": ("vulnerabilities", "reference"),
        "case": ("cases", "case_number"),
        "evidence": ("evidence", "evidence_number"),
        "incident": ("incidents", "incident_number"),
        "engagement": ("engagements", "code"),
        "report": ("reports", "reference"),
        "authorization": ("test_authorizations", "reference"),
    }
    if kind not in mapping:
        raise ValueError(f"Unknown reference kind {kind!r}")
    return mapping[kind]


async def next_reference(
    session: AsyncSession,
    kind: str,
    org_id: uuid.UUID,
    *,
    width: int = 6,
    year: int | None = None,
) -> str:
    """Allocate the next reference of a kind for an organization.

    Derives the next number from the highest existing reference for the current
    year rather than keeping a separate counter table, so the sequence can
    never drift from the data it labels. An advisory lock serialises allocation
    for the duration of the transaction.
    """
    prefix = PREFIXES.get(kind)
    if prefix is None:
        raise ValueError(f"Unknown reference kind {kind!r}")
    table, column = _counter_table(kind)
    year = year or datetime.now(UTC).year
    pattern = f"{prefix}-{year}-%"

    # The lock key combines the org and the kind so allocations for different
    # record types, and different tenants, proceed in parallel.
    lock_key = (int.from_bytes(org_id.bytes[:2], "big") << 8) | (hash(kind) & 0xFF)
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:ns, :key)"),
        {"ns": _REFERENCE_LOCK_NAMESPACE, "key": lock_key},
    )

    highest = (
        await session.execute(
            text(
                f"SELECT max(substring({column} FROM '[0-9]+$')::bigint) "  # noqa: S608
                f"FROM {table} WHERE org_id = :org AND {column} LIKE :pattern"
            ),
            {"org": org_id, "pattern": pattern},
        )
    ).scalar_one_or_none()

    next_number = int(highest or 0) + 1
    return f"{prefix}-{year}-{next_number:0{width}d}"


async def allocate_references(
    session: AsyncSession, kind: str, org_id: uuid.UUID, count: int, *, width: int = 6
) -> list[str]:
    """Allocate a contiguous block of references.

    A scan can create thousands of findings; allocating one at a time would
    mean one query per finding. The block is reserved under a single lock.
    """
    if count <= 0:
        return []
    first = await next_reference(session, kind, org_id, width=width)
    prefix, year, number = first.rsplit("-", 2)[0], first.split("-")[1], int(first.split("-")[-1])
    return [f"{prefix}-{year}-{number + i:0{width}d}" for i in range(count)]
