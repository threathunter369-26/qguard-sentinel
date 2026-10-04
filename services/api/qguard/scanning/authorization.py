"""Test authorization: the platform's gate on active security testing.

No engine that sends traffic to a target runs unless an authorization that is
``active``, inside its validity window, and whose scope rules cover that target
says so. The decision is computed here, recorded on the engine run, and audited
when it refuses — so a refusal is visible evidence that the control worked,
not a silent gap in coverage.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from qguard_scanner.sdk.engine import ScopeVerdict
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.audit.service import AuditService
from qguard.auth.principal import Principal
from qguard.common.enums import AuthorizationStatus, SecurityEventKind
from qguard.common.errors import NotFoundError, ScopeAuthorizationError
from qguard.common.logging import get_logger
from qguard.common.net import ScopeMatcher, authorization_is_current
from qguard.models.audit import AuditAction
from qguard.models.scanning import TestAuthorization

log = get_logger(__name__)


@dataclass(slots=True)
class AuthorizationDecision:
    """A scope decision, with everything needed to explain and audit it."""

    allowed: bool
    reason: str
    authorization_id: uuid.UUID | None = None
    authorization_reference: str | None = None
    matched_rule: str | None = None
    allows_intrusive: bool = False
    max_requests_per_second: float | None = None
    permitted_engines: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "authorization_id": str(self.authorization_id) if self.authorization_id else None,
            "authorization_reference": self.authorization_reference,
            "matched_rule": self.matched_rule,
            "allows_intrusive": self.allows_intrusive,
            "max_requests_per_second": self.max_requests_per_second,
            "decided_at": datetime.now(UTC).isoformat(),
        }

    def to_verdict(self) -> ScopeVerdict:
        """Convert to the SDK shape engines receive."""
        return ScopeVerdict(
            allowed=self.allowed,
            reason=self.reason,
            matched_rule=self.matched_rule,
            authorization_id=str(self.authorization_id) if self.authorization_id else None,
            allows_intrusive=self.allows_intrusive,
            max_requests_per_second=self.max_requests_per_second,
        )


class AuthorizationService:
    """Resolves and enforces test authorizations."""

    def __init__(self, session: AsyncSession, audit: AuditService | None = None) -> None:
        self.session = session
        self.audit = audit or AuditService(session)

    # ----------------------------------------------------------- resolution
    async def active_authorizations(
        self, org_id: uuid.UUID, project_id: uuid.UUID | None = None
    ) -> list[TestAuthorization]:
        """Authorizations usable right now.

        Expiry is applied in the query rather than trusted from the stored
        status, so an authorization that lapsed without anyone updating the row
        is still treated as expired.
        """
        now = datetime.now(UTC)
        stmt = select(TestAuthorization).where(
            TestAuthorization.org_id == org_id,
            TestAuthorization.status == AuthorizationStatus.ACTIVE,
            TestAuthorization.revoked_at.is_(None),
            or_(TestAuthorization.valid_from.is_(None), TestAuthorization.valid_from <= now),
            or_(TestAuthorization.valid_until.is_(None), TestAuthorization.valid_until > now),
        )
        if project_id is not None:
            # A project-scoped authorization applies to its project; one with no
            # project applies organization-wide.
            stmt = stmt.where(
                or_(
                    TestAuthorization.project_id == project_id,
                    TestAuthorization.project_id.is_(None),
                )
            )
        return list((await self.session.execute(stmt)).scalars().all())

    async def decide(
        self,
        *,
        org_id: uuid.UUID,
        target: str,
        engine_key: str | None = None,
        project_id: uuid.UUID | None = None,
        authorization_id: uuid.UUID | None = None,
        intrusive: bool = False,
    ) -> AuthorizationDecision:
        """Decide whether ``target`` may be actively assessed.

        When ``authorization_id`` is given only that authorization is
        considered; otherwise every currently-active one is tried and the first
        that covers the target wins. Either way the default is refusal.
        """
        if authorization_id is not None:
            authorization = (
                await self.session.execute(
                    select(TestAuthorization).where(
                        TestAuthorization.id == authorization_id,
                        TestAuthorization.org_id == org_id,
                    )
                )
            ).scalar_one_or_none()
            if authorization is None:
                return AuthorizationDecision(
                    allowed=False,
                    reason="The authorization named for this scan does not exist.",
                )
            candidates = [authorization]
        else:
            candidates = await self.active_authorizations(org_id, project_id)

        if not candidates:
            return AuthorizationDecision(
                allowed=False,
                reason=(
                    "No active test authorization exists for this scope. Active security "
                    "testing is refused until one is created and approved."
                ),
            )

        refusals: list[str] = []
        for authorization in candidates:
            current, window_reason = authorization_is_current(
                authorization.status,
                authorization.valid_from,
                authorization.valid_until,
            )
            if not current or authorization.revoked_at is not None:
                refusals.append(f"{authorization.reference}: {window_reason}")
                continue

            if (
                engine_key
                and authorization.permitted_engines
                and engine_key not in authorization.permitted_engines
            ):
                refusals.append(
                    f"{authorization.reference}: the {engine_key!r} engine is not among the "
                    "engines this authorization permits."
                )
                continue

            if intrusive and not authorization.allow_intrusive:
                refusals.append(f"{authorization.reference}: intrusive checks are not permitted.")
                continue

            if not self._within_testing_window(authorization):
                refusals.append(
                    f"{authorization.reference}: the current time is outside the permitted "
                    "testing window."
                )
                continue

            matcher = ScopeMatcher(
                allow=list(authorization.scope_allow),
                deny=list(authorization.scope_deny),
                authorization_id=str(authorization.id),
            )
            decision = matcher.check(target)
            if decision.allowed:
                return AuthorizationDecision(
                    allowed=True,
                    reason=f"{authorization.reference}: {decision.reason}",
                    authorization_id=authorization.id,
                    authorization_reference=authorization.reference,
                    matched_rule=decision.matched_rule,
                    allows_intrusive=authorization.allow_intrusive,
                    max_requests_per_second=(
                        float(authorization.max_requests_per_second)
                        if authorization.max_requests_per_second is not None
                        else None
                    ),
                    permitted_engines=tuple(authorization.permitted_engines),
                )
            refusals.append(f"{authorization.reference}: {decision.reason}")

        return AuthorizationDecision(
            allowed=False,
            reason=(
                f"No active authorization covers {target!r}. " + " ".join(refusals[:5])
            ).strip(),
        )

    @staticmethod
    def _within_testing_window(authorization: TestAuthorization) -> bool:
        """Honour an authorization's permitted hours, when it sets any.

        Expressed as ``{"timezone": "UTC", "hours": [[22, 6]]}`` meaning
        22:00 to 06:00. A window that wraps midnight is handled.
        """
        window = authorization.testing_window or {}
        hours = window.get("hours")
        if not hours:
            return True
        now_hour = datetime.now(UTC).hour
        for entry in hours:
            try:
                start, end = int(entry[0]), int(entry[1])
            except (TypeError, ValueError, IndexError):
                continue
            if start <= end:
                if start <= now_hour < end:
                    return True
            elif now_hour >= start or now_hour < end:
                return True
        return False

    # ----------------------------------------------------------- enforcement
    async def require(
        self,
        *,
        principal: Principal,
        target: str,
        engine_key: str | None = None,
        project_id: uuid.UUID | None = None,
        authorization_id: uuid.UUID | None = None,
        intrusive: bool = False,
    ) -> AuthorizationDecision:
        """Decide, and raise with the reason when the answer is no.

        A refusal is audited and raised as a security event, because an attempt
        to test an unauthorized target is itself something an operator needs to
        see.
        """
        decision = await self.decide(
            org_id=principal.org_id,
            target=target,
            engine_key=engine_key,
            project_id=project_id,
            authorization_id=authorization_id,
            intrusive=intrusive,
        )
        if decision.allowed:
            return decision

        await self.audit.record(
            action=AuditAction.SCOPE_VIOLATION_BLOCKED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="test_authorization",
            resource_id=decision.authorization_id,
            result="denied",
            failure_reason=decision.reason,
            metadata={"target": target, "engine": engine_key, "intrusive": intrusive},
        )
        await self.audit.record_security_event(
            org_id=principal.org_id,
            kind=SecurityEventKind.SCOPE_VIOLATION_BLOCKED,
            severity="high",
            source="authorization",
            title=f"Active testing of {target} was refused",
            message=decision.reason,
            resource_type="test_authorization",
            data={"target": target, "engine": engine_key, "requested_by": principal.label},
        )
        log.warning(
            "authorization.refused",
            target=target,
            engine=engine_key,
            reason=decision.reason,
        )
        raise ScopeAuthorizationError(decision.reason, details={"target": target})

    def scope_checker_for(self, decisions: dict[str, AuthorizationDecision]) -> Any:
        """Build the callable engines use for their own scope checks.

        Pre-computed per target so the check inside an engine is synchronous
        and cannot accidentally issue a database query mid-scan. Anything not
        pre-approved is refused, so an engine that follows a redirect to an
        unexpected host stops there.
        """

        def check(target: str) -> ScopeVerdict:
            decision = decisions.get(target)
            if decision is not None:
                return decision.to_verdict()
            # Fall back to host matching: a crawl legitimately produces URLs
            # that were not in the original target list, but they must still be
            # covered by an authorization that was already resolved.
            from qguard_scanner.sdk.netguard import parse_target

            try:
                host = parse_target(target).host
            except Exception:
                return ScopeVerdict(
                    allowed=False, reason=f"{target!r} could not be parsed as a target."
                )
            for approved_target, decision in decisions.items():
                if not decision.allowed:
                    continue
                try:
                    approved_host = parse_target(approved_target).host
                except Exception as exc:
                    # An authorization rule that no longer parses cannot
                    # authorise anything; note it and keep looking.
                    log.warning(
                        "authorization.unparseable_rule",
                        rule=approved_target,
                        error=str(exc),
                    )
                    continue
                if approved_host == host:
                    return decision.to_verdict()
            return ScopeVerdict(
                allowed=False,
                reason=(
                    f"{target} was reached during the scan but no authorization resolved for "
                    "this run covers it, so it was not contacted."
                ),
            )

        return check

    # ------------------------------------------------------------- lifecycle
    async def approve(
        self, principal: Principal, authorization_id: uuid.UUID, note: str | None = None
    ) -> TestAuthorization:
        """Approve an authorization, making its scope testable.

        Approval is the single most consequential action in the platform, so it
        requires its own permission, cannot be self-granted implicitly, and is
        always audited.
        """
        authorization = await self._get(principal.org_id, authorization_id)
        if authorization.status == AuthorizationStatus.ACTIVE:
            return authorization

        before = {
            "status": authorization.status,
            "scope_allow": list(authorization.scope_allow),
            "scope_deny": list(authorization.scope_deny),
        }
        authorization.status = AuthorizationStatus.ACTIVE
        authorization.approved_by = principal.user_id
        authorization.approved_at = datetime.now(UTC)
        authorization.approver_note = note

        await self.audit.record(
            action=AuditAction.AUTHORIZATION_APPROVED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="test_authorization",
            resource_id=authorization.id,
            resource_label=authorization.reference,
            before=before,
            after={
                "status": authorization.status,
                "scope_allow": list(authorization.scope_allow),
                "allow_intrusive": authorization.allow_intrusive,
                "valid_until": authorization.valid_until,
            },
            metadata={"note": note},
        )
        return authorization

    async def revoke(
        self, principal: Principal, authorization_id: uuid.UUID, reason: str
    ) -> TestAuthorization:
        authorization = await self._get(principal.org_id, authorization_id)
        authorization.status = AuthorizationStatus.REVOKED
        authorization.revoked_at = datetime.now(UTC)
        authorization.revoked_reason = reason
        await self.audit.record(
            action=AuditAction.AUTHORIZATION_REVOKED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="test_authorization",
            resource_id=authorization.id,
            resource_label=authorization.reference,
            after={"status": authorization.status, "reason": reason},
        )
        return authorization

    async def _get(self, org_id: uuid.UUID, authorization_id: uuid.UUID) -> TestAuthorization:
        authorization = (
            await self.session.execute(
                select(TestAuthorization).where(
                    TestAuthorization.id == authorization_id,
                    TestAuthorization.org_id == org_id,
                )
            )
        ).scalar_one_or_none()
        if authorization is None:
            raise NotFoundError("That test authorization was not found.")
        return authorization

    async def expire_lapsed(self, org_id: uuid.UUID) -> int:
        """Mark authorizations whose window has closed.

        Cosmetic rather than load-bearing — :meth:`decide` already treats a
        lapsed authorization as expired — but it keeps the UI honest about
        what is still in force.
        """
        now = datetime.now(UTC)
        rows = (
            (
                await self.session.execute(
                    select(TestAuthorization).where(
                        TestAuthorization.org_id == org_id,
                        TestAuthorization.status == AuthorizationStatus.ACTIVE,
                        TestAuthorization.valid_until.is_not(None),
                        TestAuthorization.valid_until <= now,
                    )
                )
            )
            .scalars()
            .all()
        )
        for authorization in rows:
            authorization.status = AuthorizationStatus.EXPIRED
            await self.audit.record_security_event(
                org_id=org_id,
                kind=SecurityEventKind.AUTHORIZATION_EXPIRED,
                severity="medium",
                source="authorization",
                title=f"Test authorization {authorization.reference} has expired",
                message=(
                    "Active testing of this scope is now refused until the authorization "
                    "is renewed and approved."
                ),
                resource_type="test_authorization",
                resource_id=authorization.id,
            )
        return len(rows)
