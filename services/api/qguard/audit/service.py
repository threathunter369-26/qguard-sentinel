"""Audit trail writer and verifier.

Every entry is linked to the previous one by
``entry_hash = SHA256(prev_hash || canonical_json(entry))``, per organization.
Changing an historic entry therefore invalidates its own hash and every hash
after it, which :meth:`AuditService.verify_chain` detects and reports with the
first broken sequence number. The table also rejects UPDATE and DELETE at the
database level, so the running service cannot rewrite its own history.

Writes are serialised per organization with an advisory lock, because the chain
requires a strict order: two concurrent requests must not both build on the
same predecessor.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.auth.principal import Principal
from qguard.common.cryptoutil import GENESIS_HASH, chain_hash
from qguard.common.enums import ActorType, AuditResult, SecurityEventKind
from qguard.common.logging import get_logger, scrub
from qguard.models.audit import AuditLogEntry, SecurityEvent

log = get_logger(__name__)

#: Fields that participate in the hash. Deliberately explicit: adding a column
#: later must not silently change how historic entries hash, which would make
#: the whole chain appear broken.
HASHED_FIELDS: tuple[str, ...] = (
    "org_id",
    "actor_id",
    "actor_type",
    "action",
    "resource_type",
    "resource_id",
    "result",
    "occurred_at",
    "sequence",
    "before_state",
    "after_state",
)

#: Advisory lock namespace, so audit locks cannot collide with other features.
_AUDIT_LOCK_NAMESPACE = 0x51477561  # "QGua"


@dataclass(slots=True)
class AuditContext:
    """Request metadata attached to every entry written during a request."""

    request_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_method: str | None = None
    request_path: str | None = None


@asynccontextmanager
async def audit_context(**kwargs: Any) -> AsyncIterator[AuditContext]:
    yield AuditContext(**kwargs)


class AuditService:
    """Writes and verifies the audit trail for one organization."""

    def __init__(self, session: AsyncSession, context: AuditContext | None = None) -> None:
        self.session = session
        self.context = context or AuditContext()

    # ----------------------------------------------------------------- writing
    async def record(
        self,
        *,
        action: str,
        org_id: uuid.UUID | None,
        actor: Principal | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | str | None = None,
        resource_label: str | None = None,
        result: str = AuditResult.SUCCESS,
        failure_reason: str | None = None,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        actor_id: uuid.UUID | None = None,
        actor_type: str | None = None,
        actor_label: str | None = None,
    ) -> AuditLogEntry:
        """Append one entry. Never raises into the caller's business logic.

        An audit write failing must not silently drop the record, but neither
        should it fail a security action that already succeeded. The failure is
        logged at error level and surfaced as a security event so the gap is
        visible rather than invisible.
        """
        occurred_at = datetime.now(UTC)

        if actor is not None:
            actor_id = actor_id or actor.user_id
            actor_type = actor_type or actor.actor_type
            actor_label = actor_label or actor.label
            api_key_id = actor.api_key_id
            session_id = actor.session_id
            ip = self.context.ip_address or actor.ip_address
            ua = self.context.user_agent or actor.user_agent
        else:
            actor_type = actor_type or ActorType.SYSTEM
            api_key_id = None
            session_id = None
            ip = self.context.ip_address
            ua = self.context.user_agent

        # Credentials must never reach the audit trail: it is long-lived,
        # exportable and widely readable by assurance roles.
        before = scrub(before) if before else None
        after = scrub(after) if after else None
        metadata = scrub(metadata) if metadata else {}

        # A pre-authentication event (a failed sign-in against an address that
        # does not exist) belongs to no tenant. Its row therefore needs the
        # platform-level write gate: the tenant isolation policy's USING clause
        # is applied to the INSERT's RETURNING clause, and a NULL org_id does
        # not satisfy it. Keeping these rows gated also means one tenant cannot
        # read which addresses another tenant's users were targeted under.
        try:
            if org_id is None:
                await self.session.execute(
                    text("SELECT set_config('app.platform_bootstrap', 'on', true)")
                )
            sequence, prev_hash = await self._next_sequence(org_id)
            payload = {
                "org_id": str(org_id) if org_id else None,
                "actor_id": str(actor_id) if actor_id else None,
                "actor_type": actor_type,
                "action": action,
                "resource_type": resource_type,
                "resource_id": str(resource_id) if resource_id else None,
                "result": result,
                "occurred_at": occurred_at.isoformat(),
                "sequence": sequence,
                "before_state": before,
                "after_state": after,
            }
            entry_hash = chain_hash(prev_hash, payload)

            entry = AuditLogEntry(
                org_id=org_id,
                actor_id=actor_id,
                actor_type=actor_type,
                actor_label=actor_label,
                api_key_id=api_key_id,
                action=action,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                resource_label=resource_label,
                result=result,
                failure_reason=failure_reason,
                before_state=before,
                after_state=after,
                metadata_json=metadata,
                ip_address=ip,
                user_agent=ua,
                request_id=self.context.request_id,
                request_method=self.context.request_method,
                request_path=self.context.request_path,
                session_id=session_id,
                occurred_at=occurred_at,
                sequence=sequence,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self.session.add(entry)
            await self.session.flush()
            return entry
        except Exception as exc:
            log.error(
                "audit.write_failed",
                action=action,
                resource_type=resource_type,
                error=str(exc),
                exc_info=True,
            )
            raise
        finally:
            if org_id is None:
                # Lower the gate immediately; it must not cover anything else
                # in this transaction.
                await self.session.execute(
                    text("SELECT set_config('app.platform_bootstrap', '', true)")
                )

    async def _next_sequence(self, org_id: uuid.UUID | None) -> tuple[int, str]:
        """Reserve the next chain position for this organization.

        The advisory lock is held for the remainder of the transaction, which
        serialises concurrent audit writes for one tenant. Without it two
        requests could read the same tail and produce two entries claiming the
        same predecessor, breaking the chain.
        """
        # pg_advisory_xact_lock(int4, int4) takes *signed* 32-bit keys, so the
        # derived value is folded into that range rather than passed raw.
        lock_key = int.from_bytes(org_id.bytes[:4], "big", signed=True) if org_id is not None else 0
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:ns, :key)"),
            {"ns": _AUDIT_LOCK_NAMESPACE, "key": lock_key},
        )
        stmt = (
            select(AuditLogEntry.sequence, AuditLogEntry.entry_hash)
            .where(
                AuditLogEntry.org_id == org_id
                if org_id is not None
                else AuditLogEntry.org_id.is_(None)
            )
            .order_by(AuditLogEntry.sequence.desc())
            .limit(1)
        )
        row = (await self.session.execute(stmt)).first()
        if row is None:
            return 0, GENESIS_HASH
        return int(row[0]) + 1, row[1]

    # --------------------------------------------------------- security events
    async def record_security_event(
        self,
        *,
        org_id: uuid.UUID,
        kind: str,
        title: str,
        severity: str = "info",
        source: str = "platform",
        message: str | None = None,
        resource_type: str | None = None,
        resource_id: uuid.UUID | str | None = None,
        project_id: uuid.UUID | None = None,
        asset_id: uuid.UUID | None = None,
        data: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        """Record an operationally interesting event.

        Backs the dashboard's activity feed, which therefore shows only things
        that actually happened.
        """
        event = SecurityEvent(
            org_id=org_id,
            kind=kind,
            severity=severity,
            source=source,
            title=title,
            message=message,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            project_id=project_id,
            asset_id=asset_id,
            data=scrub(data or {}),
        )
        self.session.add(event)
        await self.session.flush()
        return event

    # -------------------------------------------------------------- verification
    async def verify_chain(self, org_id: uuid.UUID, *, limit: int | None = None) -> dict[str, Any]:
        """Recompute the chain and report the first break, if any.

        Reads the stored rows directly and recomputes each hash from the
        recorded fields, so a tampered row is detected regardless of what any
        application-level cache believes.
        """
        stmt = (
            select(AuditLogEntry)
            .where(AuditLogEntry.org_id == org_id)
            .order_by(AuditLogEntry.sequence.asc())
        )
        if limit:
            stmt = stmt.limit(limit)
        entries = (await self.session.execute(stmt)).scalars().all()

        if not entries:
            return {
                "verified": True,
                "entries_checked": 0,
                "first_broken_sequence": None,
                "message": "The audit trail is empty for this organization.",
            }

        expected_prev = GENESIS_HASH
        expected_sequence = entries[0].sequence
        for entry in entries:
            if entry.sequence != expected_sequence:
                return {
                    "verified": False,
                    "entries_checked": entries.index(entry),
                    "first_broken_sequence": expected_sequence,
                    "message": (
                        f"Audit sequence gap: expected entry {expected_sequence} but found "
                        f"{entry.sequence}. Entries appear to have been removed."
                    ),
                }
            payload = {
                "org_id": str(entry.org_id) if entry.org_id else None,
                "actor_id": str(entry.actor_id) if entry.actor_id else None,
                "actor_type": entry.actor_type,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "result": entry.result,
                "occurred_at": entry.occurred_at.isoformat(),
                "sequence": entry.sequence,
                "before_state": entry.before_state,
                "after_state": entry.after_state,
            }
            recomputed = chain_hash(expected_prev, payload)
            if recomputed != entry.entry_hash:
                return {
                    "verified": False,
                    "entries_checked": entries.index(entry),
                    "first_broken_sequence": entry.sequence,
                    "message": (
                        f"Audit entry {entry.sequence} does not match its recorded hash. "
                        "The entry or one before it has been altered."
                    ),
                }
            expected_prev = entry.entry_hash
            expected_sequence = entry.sequence + 1

        return {
            "verified": True,
            "entries_checked": len(entries),
            "first_broken_sequence": None,
            "chain_head": entries[-1].entry_hash,
            "last_sequence": entries[-1].sequence,
            "message": f"All {len(entries)} audit entries verify against the hash chain.",
        }

    async def chain_statistics(self, org_id: uuid.UUID) -> dict[str, Any]:
        row = (
            await self.session.execute(
                select(
                    func.count(AuditLogEntry.id),
                    func.min(AuditLogEntry.occurred_at),
                    func.max(AuditLogEntry.occurred_at),
                    func.max(AuditLogEntry.sequence),
                ).where(AuditLogEntry.org_id == org_id)
            )
        ).one()
        return {
            "entry_count": int(row[0] or 0),
            "first_entry_at": row[1],
            "last_entry_at": row[2],
            "last_sequence": int(row[3]) if row[3] is not None else None,
        }


async def record_audit_failure_event(
    session: AsyncSession, org_id: uuid.UUID, action: str, error: str
) -> None:
    """Make a failed audit write visible instead of leaving a silent gap."""
    service = AuditService(session)
    await service.record_security_event(
        org_id=org_id,
        kind=SecurityEventKind.AUDIT_CHAIN_BROKEN,
        severity="critical",
        source="audit",
        title="An audit entry could not be written",
        message=(
            f"The action {action!r} completed but its audit entry failed to persist: {error}. "
            "The audit trail has a gap that needs investigation."
        ),
    )
