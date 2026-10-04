"""Authentication flows: sign-in, MFA, token refresh, sessions and API keys.

Security properties implemented here:

* **No account enumeration.** A wrong password and an unknown address produce
  the same error and comparable timing.
* **Progressive lockout.** Repeated failures lock the account temporarily, with
  a capped backoff so the control cannot be turned into a denial of service.
* **Refresh token rotation with reuse detection.** Each refresh issues a new
  token and revokes the old one. Presenting an already-rotated token is treated
  as theft: the whole session family is revoked and the event is audited.
* **MFA that cannot be skipped.** The password step yields only a challenge
  token, which carries no authorization and is accepted at one endpoint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.audit.service import AuditContext, AuditService
from qguard.auth import mfa as mfa_module
from qguard.auth.permissions import ALL_PERMISSION_KEYS
from qguard.auth.principal import Principal
from qguard.auth.providers import (
    LocalAuthProvider,
    LoginCandidate,
    get_auth_provider,
    lockout_until,
)
from qguard.auth.rbac import resolve_principal
from qguard.auth.tokens import (
    MFA_CHALLENGE_TOKEN_TYPE,
    IssuedTokens,
    decode_token,
    issue_mfa_challenge_token,
    issue_token_pair,
)
from qguard.common.config import get_settings
from qguard.common.cryptoutil import (
    api_key_parts,
    hash_password,
    hash_token,
    verify_password,
)
from qguard.common.database import apply_tenant_context
from qguard.common.enums import ActorType, AuditResult, SecurityEventKind, UserStatus
from qguard.common.errors import (
    AuthenticationError,
    ConflictError,
    InvalidCredentialsError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from qguard.common.logging import get_logger
from qguard.models.audit import AuditAction
from qguard.models.identity import ApiKey, Organization, User, UserSession

log = get_logger(__name__)


class AuthService:
    """Authentication operations.

    Takes a *system* session (no tenant context bound), because sign-in has to
    resolve an identity before the tenant is known. Tenant context is applied
    as soon as the organization is determined.
    """

    def __init__(self, session: AsyncSession, audit_context: AuditContext | None = None) -> None:
        self.session = session
        self.audit = AuditService(session, audit_context)
        self.provider = get_auth_provider()

    # ------------------------------------------------- security-state durability
    async def _commit_security_state(
        self,
        org_id: uuid.UUID | None = None,
        user_id: uuid.UUID | None = None,
    ) -> None:
        """Persist security bookkeeping that must survive a failing request.

        Lockout counters, refresh-token reuse revocations and failed-attempt
        audit entries are all written on the path to *raising* an error. The
        request transaction is rolled back when that error propagates, so
        without an explicit commit here those controls would silently never
        take effect — the counter would reset on every attempt and the audit
        trail would have no record of the failure.

        Committing ends the transaction and therefore discards the ``SET
        LOCAL`` tenant context, so it is re-applied on the new transaction.
        """
        await self.session.commit()
        await self.session.begin()
        if org_id is not None:
            await apply_tenant_context(self.session, org_id, user_id)

    # --------------------------------------------------------------- sign-in
    async def _lookup_candidate(self, email: str) -> LoginCandidate | None:
        """Resolve an address through the privileged SECURITY DEFINER function.

        The function is the only cross-tenant read of ``users`` in the runtime:
        it is keyed on the exact address and returns nothing beyond what the
        credential check needs.
        """
        row = (
            await self.session.execute(
                text(
                    "SELECT user_id, org_id, email, password_hash, status, auth_provider, "
                    "mfa_enabled, mfa_secret_encrypted, failed_login_count, locked_until, "
                    "is_superadmin, full_name FROM app.find_login_identity(:email)"
                ),
                {"email": email},
            )
        ).first()
        if row is None:
            return None
        return LoginCandidate(
            user_id=row[0],
            org_id=row[1],
            email=row[2],
            password_hash=row[3],
            status=row[4],
            auth_provider=row[5],
            mfa_enabled=row[6],
            mfa_secret_encrypted=row[7],
            failed_login_count=row[8] or 0,
            locked_until=row[9],
            is_superadmin=row[10],
            full_name=row[11],
        )

    async def login(
        self,
        email: str,
        password: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_label: str | None = None,
    ) -> tuple[IssuedTokens | None, str | None, User | None]:
        """Verify a password.

        Returns ``(tokens, challenge_token, user)``. When MFA is enabled,
        ``tokens`` is ``None`` and a challenge token is returned instead.
        """
        email = email.strip().lower()
        candidate = await self._lookup_candidate(email)

        try:
            identity = await self.provider.verify_password_credentials(candidate, password)
        except Exception as exc:
            await self._record_failed_login(email, candidate, exc, ip_address)
            raise

        await apply_tenant_context(self.session, identity.org_id, identity.user_id)
        user = (
            await self.session.execute(select(User).where(User.id == identity.user_id))
        ).scalar_one()

        # A successful password check clears the failure counter and lockout.
        user.failed_login_count = 0
        user.locked_until = None
        if identity.needs_password_rehash:
            # Argon2 parameters were raised since this hash was made; upgrade
            # it transparently now that the plaintext is briefly available.
            user.password_hash = hash_password(password)
            user.password_changed_at = datetime.now(UTC)

        if identity.requires_mfa:
            await self.audit.record(
                action=AuditAction.LOGIN,
                org_id=identity.org_id,
                actor_id=user.id,
                actor_type=ActorType.USER,
                actor_label=user.email,
                resource_type="user",
                resource_id=user.id,
                result=AuditResult.SUCCESS,
                metadata={"stage": "password_verified", "mfa_required": True},
            )
            return None, issue_mfa_challenge_token(user.id, identity.org_id), user

        tokens = await self._establish_session(
            user,
            mfa_satisfied=False,
            ip_address=ip_address,
            user_agent=user_agent,
            device_label=device_label,
        )
        await self.audit.record(
            action=AuditAction.LOGIN,
            org_id=identity.org_id,
            actor_id=user.id,
            actor_type=ActorType.USER,
            actor_label=user.email,
            resource_type="user",
            resource_id=user.id,
            result=AuditResult.SUCCESS,
            metadata={"stage": "complete", "mfa_required": False},
        )
        return tokens, None, user

    async def _record_failed_login(
        self,
        email: str,
        candidate: LoginCandidate | None,
        error: Exception,
        ip_address: str | None,
    ) -> None:
        """Audit a failed sign-in and advance the lockout counter.

        Recorded even for an unknown address — with a null ``org_id`` — because
        credential stuffing against addresses that do not exist is exactly the
        signal an operator wants to see.
        """
        settings = get_settings()
        if candidate is not None:
            await apply_tenant_context(self.session, candidate.org_id, None)
            new_count = candidate.failed_login_count + 1
            locked = lockout_until(new_count)
            await self.session.execute(
                update(User)
                .where(User.id == candidate.user_id)
                .values(
                    failed_login_count=new_count,
                    locked_until=locked,
                    status=UserStatus.LOCKED
                    if locked and new_count >= settings.max_failed_logins * 3
                    else User.__table__.c.status,
                )
            )
            await self.audit.record(
                action=AuditAction.LOGIN_FAILED,
                org_id=candidate.org_id,
                actor_id=candidate.user_id,
                actor_type=ActorType.USER,
                actor_label=email,
                resource_type="user",
                resource_id=candidate.user_id,
                result=AuditResult.FAILURE,
                failure_reason=type(error).__name__,
                metadata={"failed_login_count": new_count, "locked": bool(locked)},
            )
            if locked:
                await self.audit.record_security_event(
                    org_id=candidate.org_id,
                    kind=SecurityEventKind.ACCOUNT_LOCKED,
                    severity="high",
                    source="auth",
                    title=f"Account locked after {new_count} failed sign-in attempts",
                    message=(
                        f"{email} was locked until {locked.isoformat()} following repeated "
                        "failed sign-ins."
                    ),
                    resource_type="user",
                    resource_id=candidate.user_id,
                    data={"ip_address": ip_address, "failed_login_count": new_count},
                )
        else:
            await self.audit.record(
                action=AuditAction.LOGIN_FAILED,
                org_id=None,
                actor_type=ActorType.ANONYMOUS,
                actor_label=email,
                result=AuditResult.FAILURE,
                failure_reason="unknown_account",
                metadata={"ip_address": ip_address},
            )
        await self._commit_security_state(
            candidate.org_id if candidate else None,
            candidate.user_id if candidate else None,
        )

    async def complete_mfa(
        self,
        challenge_token: str,
        code: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_label: str | None = None,
    ) -> tuple[IssuedTokens, User]:
        """Exchange a challenge token plus a TOTP or recovery code for tokens."""
        payload = decode_token(challenge_token, expected_type=MFA_CHALLENGE_TOKEN_TYPE)
        user_id = uuid.UUID(payload["sub"])
        org_id = uuid.UUID(payload["org"])

        await apply_tenant_context(self.session, org_id, user_id)
        user = (
            await self.session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if user is None or user.status != UserStatus.ACTIVE:
            raise AuthenticationError("This account can no longer complete sign-in.")
        if not user.mfa_enabled or not user.mfa_secret_encrypted:
            raise ConflictError("Multi-factor authentication is not enabled for this account.")

        used_recovery_code = False
        if mfa_module.verify_totp(user.mfa_secret_encrypted, code, email=user.email):
            pass
        elif matched := mfa_module.verify_recovery_code(list(user.mfa_recovery_hashes), code):
            # Recovery codes are single-use, so the one just presented is
            # removed before the session is established.
            user.mfa_recovery_hashes = [h for h in user.mfa_recovery_hashes if h != matched]
            used_recovery_code = True
        else:
            await self.audit.record(
                action=AuditAction.MFA_CHALLENGE_FAILED,
                org_id=org_id,
                actor_id=user.id,
                actor_type=ActorType.USER,
                actor_label=user.email,
                resource_type="user",
                resource_id=user.id,
                result=AuditResult.FAILURE,
                failure_reason="invalid_code",
            )
            await self._commit_security_state(org_id, user_id)
            raise InvalidCredentialsError("That verification code is not valid.")

        tokens = await self._establish_session(
            user,
            mfa_satisfied=True,
            ip_address=ip_address,
            user_agent=user_agent,
            device_label=device_label,
        )
        await self.audit.record(
            action=AuditAction.LOGIN,
            org_id=org_id,
            actor_id=user.id,
            actor_type=ActorType.USER,
            actor_label=user.email,
            resource_type="user",
            resource_id=user.id,
            result=AuditResult.SUCCESS,
            metadata={
                "stage": "complete",
                "mfa_required": True,
                "used_recovery_code": used_recovery_code,
                "recovery_codes_remaining": len(user.mfa_recovery_hashes),
            },
        )
        return tokens, user

    async def _establish_session(
        self,
        user: User,
        *,
        mfa_satisfied: bool,
        ip_address: str | None,
        user_agent: str | None,
        device_label: str | None,
        parent_session_id: uuid.UUID | None = None,
    ) -> IssuedTokens:
        session_row = UserSession(
            org_id=user.org_id,
            user_id=user.id,
            refresh_token_hash="",  # replaced below once the token is minted
            parent_session_id=parent_session_id,
            ip_address=ip_address,
            user_agent=(user_agent or "")[:512] or None,
            device_label=device_label,
            mfa_satisfied=mfa_satisfied,
            expires_at=datetime.now(UTC)
            + timedelta(seconds=get_settings().refresh_token_ttl_seconds),
            last_used_at=datetime.now(UTC),
        )
        self.session.add(session_row)
        await self.session.flush()

        tokens = issue_token_pair(
            user_id=user.id,
            org_id=user.org_id,
            session_id=session_row.id,
            email=user.email,
            mfa_satisfied=mfa_satisfied,
        )
        session_row.refresh_token_hash = tokens.refresh_token_hash
        session_row.expires_at = tokens.refresh_expires_at

        user.last_login_at = datetime.now(UTC)
        user.last_login_ip = ip_address
        await self.session.flush()
        return tokens

    # --------------------------------------------------------------- refresh
    async def refresh(
        self,
        refresh_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[IssuedTokens, User]:
        """Rotate a refresh token, detecting reuse of an already-rotated one."""
        token_hash = hash_token(refresh_token)
        row = (
            await self.session.execute(
                text(
                    "SELECT session_id, user_id, org_id, expires_at, revoked_at, mfa_satisfied "
                    "FROM app.find_session_identity(:h)"
                ),
                {"h": token_hash},
            )
        ).first()
        if row is None:
            raise AuthenticationError("That refresh token is not recognised.")

        session_id, user_id, org_id, expires_at, revoked_at, mfa_satisfied = row
        await apply_tenant_context(self.session, org_id, user_id)

        if revoked_at is not None:
            # The token was already rotated. Either it was replayed or it was
            # stolen; both warrant revoking every session descended from it.
            await self._revoke_session_family(session_id, org_id, reason="refresh_token_reuse")
            await self.audit.record(
                action=AuditAction.TOKEN_REUSE_DETECTED,
                org_id=org_id,
                actor_id=user_id,
                actor_type=ActorType.USER,
                resource_type="user_session",
                resource_id=session_id,
                result=AuditResult.DENIED,
                failure_reason="A revoked refresh token was presented.",
                metadata={"ip_address": ip_address},
            )
            await self.audit.record_security_event(
                org_id=org_id,
                kind=SecurityEventKind.LOGIN_FAILED,
                severity="critical",
                source="auth",
                title="A revoked refresh token was presented",
                message=(
                    "A refresh token that had already been rotated was presented again. "
                    "Every session in that family has been revoked as a precaution."
                ),
                resource_type="user_session",
                resource_id=session_id,
                data={"ip_address": ip_address, "user_agent": user_agent},
            )
            # Commit before raising: the whole point of the revocation is that
            # the stolen token stops working, which it would not if the
            # rollback undid it.
            await self._commit_security_state(org_id, user_id)
            raise AuthenticationError(
                "This session has been revoked because a reused refresh token was detected. "
                "Sign in again."
            )

        if expires_at.replace(tzinfo=expires_at.tzinfo or UTC) <= datetime.now(UTC):
            raise AuthenticationError("This session has expired. Sign in again.")

        old_session = (
            await self.session.execute(select(UserSession).where(UserSession.id == session_id))
        ).scalar_one()
        user = (
            await self.session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if user is None or user.status != UserStatus.ACTIVE:
            raise AuthenticationError("This account can no longer be used to sign in.")

        old_session.revoked_at = datetime.now(UTC)
        old_session.revoked_reason = "rotated"
        tokens = await self._establish_session(
            user,
            mfa_satisfied=mfa_satisfied,
            ip_address=ip_address,
            user_agent=user_agent,
            device_label=old_session.device_label,
            parent_session_id=old_session.parent_session_id or old_session.id,
        )
        await self.audit.record(
            action=AuditAction.TOKEN_REFRESHED,
            org_id=org_id,
            actor_id=user.id,
            actor_type=ActorType.USER,
            actor_label=user.email,
            resource_type="user_session",
            resource_id=session_id,
            result=AuditResult.SUCCESS,
        )
        return tokens, user

    async def _revoke_session_family(
        self, session_id: uuid.UUID, org_id: uuid.UUID, *, reason: str
    ) -> int:
        """Revoke a session and every session rotated from the same original."""
        target = (
            await self.session.execute(select(UserSession).where(UserSession.id == session_id))
        ).scalar_one_or_none()
        if target is None:
            return 0
        root_id = target.parent_session_id or target.id
        result = await self.session.execute(
            update(UserSession)
            .where(
                UserSession.org_id == org_id,
                UserSession.revoked_at.is_(None),
                (UserSession.id == root_id) | (UserSession.parent_session_id == root_id),
            )
            .values(revoked_at=datetime.now(UTC), revoked_reason=reason)
        )
        return int(result.rowcount or 0)

    async def logout(self, principal: Principal, *, all_sessions: bool = False) -> int:
        if principal.user_id is None:
            return 0
        stmt = (
            update(UserSession)
            .where(
                UserSession.org_id == principal.org_id,
                UserSession.user_id == principal.user_id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC), revoked_reason="logout")
        )
        if not all_sessions and principal.session_id:
            stmt = stmt.where(UserSession.id == principal.session_id)
        result = await self.session.execute(stmt)
        count = int(result.rowcount or 0)
        await self.audit.record(
            action=AuditAction.LOGOUT,
            org_id=principal.org_id,
            actor=principal,
            resource_type="user_session",
            resource_id=principal.session_id,
            metadata={"sessions_revoked": count, "all_sessions": all_sessions},
        )
        return count

    async def revoke_session(self, principal: Principal, session_id: uuid.UUID) -> None:
        row = (
            await self.session.execute(
                select(UserSession).where(
                    UserSession.id == session_id,
                    UserSession.org_id == principal.org_id,
                    UserSession.user_id == principal.user_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError("That session was not found for your account.")
        row.revoked_at = datetime.now(UTC)
        row.revoked_reason = "revoked_by_user"
        await self.audit.record(
            action=AuditAction.SESSION_REVOKED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="user_session",
            resource_id=session_id,
        )

    async def list_sessions(self, principal: Principal) -> list[UserSession]:
        return list(
            (
                await self.session.execute(
                    select(UserSession)
                    .where(
                        UserSession.org_id == principal.org_id,
                        UserSession.user_id == principal.user_id,
                        UserSession.revoked_at.is_(None),
                        UserSession.expires_at > datetime.now(UTC),
                    )
                    .order_by(UserSession.last_used_at.desc().nullslast())
                )
            )
            .scalars()
            .all()
        )

    # -------------------------------------------------------------- passwords
    async def change_password(
        self, principal: Principal, current_password: str, new_password: str
    ) -> None:
        if not isinstance(self.provider, LocalAuthProvider):
            raise ConflictError(
                "Passwords are managed by the configured identity provider, not by this platform."
            )
        user = (
            await self.session.execute(select(User).where(User.id == principal.user_id))
        ).scalar_one()
        if not verify_password(current_password, user.password_hash):
            await self.audit.record(
                action=AuditAction.PASSWORD_CHANGED,
                org_id=principal.org_id,
                actor=principal,
                resource_type="user",
                resource_id=user.id,
                result=AuditResult.FAILURE,
                failure_reason="The current password did not match.",
            )
            await self._commit_security_state(principal.org_id, principal.user_id)
            raise InvalidCredentialsError("The current password is not correct.")
        if verify_password(new_password, user.password_hash):
            raise ValidationError("The new password must differ from the current one.")

        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)

        # Changing a password invalidates other sessions: if the change was
        # prompted by a suspected compromise, leaving them live defeats it.
        revoked = await self.session.execute(
            update(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.org_id == principal.org_id,
                UserSession.revoked_at.is_(None),
                UserSession.id != (principal.session_id or uuid.uuid4()),
            )
            .values(revoked_at=datetime.now(UTC), revoked_reason="password_changed")
        )
        await self.audit.record(
            action=AuditAction.PASSWORD_CHANGED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
            metadata={"other_sessions_revoked": int(revoked.rowcount or 0)},
        )

    # -------------------------------------------------------------------- MFA
    async def start_mfa_enrolment(self, principal: Principal) -> mfa_module.MFAEnrolment:
        user = (
            await self.session.execute(select(User).where(User.id == principal.user_id))
        ).scalar_one()
        if user.mfa_enabled:
            raise ConflictError(
                "Multi-factor authentication is already enabled. Disable it first to re-enrol."
            )
        enrolment = mfa_module.start_enrolment(user.email)
        # Stored but not yet active: MFA only turns on once a generated code is
        # confirmed, so a mis-scanned QR cannot lock the user out.
        user.mfa_secret_encrypted = enrolment.secret_encrypted
        user.mfa_recovery_hashes = list(enrolment.recovery_code_hashes)
        await self.session.flush()
        return enrolment

    async def confirm_mfa_enrolment(self, principal: Principal, code: str) -> None:
        user = (
            await self.session.execute(select(User).where(User.id == principal.user_id))
        ).scalar_one()
        if not user.mfa_secret_encrypted:
            raise ConflictError("Start multi-factor enrolment before confirming it.")
        if not mfa_module.verify_totp(user.mfa_secret_encrypted, code, email=user.email):
            raise InvalidCredentialsError("That code is not valid. Check your authenticator app.")
        user.mfa_enabled = True
        user.mfa_enrolled_at = datetime.now(UTC)
        await self.audit.record(
            action=AuditAction.MFA_ENROLLED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
        )

    async def disable_mfa(self, principal: Principal, current_password: str, code: str) -> None:
        """Disable MFA. Requires both the password and a current code.

        Demanding both means a stolen session alone cannot remove the second
        factor.
        """
        user = (
            await self.session.execute(select(User).where(User.id == principal.user_id))
        ).scalar_one()
        if not user.mfa_enabled or not user.mfa_secret_encrypted:
            raise ConflictError("Multi-factor authentication is not enabled.")
        if not verify_password(current_password, user.password_hash):
            raise InvalidCredentialsError("The password is not correct.")
        if not mfa_module.verify_totp(
            user.mfa_secret_encrypted, code, email=user.email
        ) and not mfa_module.verify_recovery_code(list(user.mfa_recovery_hashes), code):
            raise InvalidCredentialsError("That verification code is not valid.")

        user.mfa_enabled = False
        user.mfa_secret_encrypted = None
        user.mfa_recovery_hashes = []
        user.mfa_enrolled_at = None
        await self.audit.record(
            action=AuditAction.MFA_DISABLED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="user",
            resource_id=user.id,
            metadata={"note": "Both the password and a valid second factor were presented."},
        )

    # --------------------------------------------------------------- API keys
    async def create_api_key(
        self,
        principal: Principal,
        *,
        name: str,
        scopes: list[str],
        project_ids: list[uuid.UUID],
        expires_in_days: int | None,
    ) -> tuple[ApiKey, str]:
        """Mint an API key, never exceeding the creator's own permissions."""
        unknown = set(scopes) - ALL_PERMISSION_KEYS
        if unknown:
            raise ValidationError(
                "Those permission scopes do not exist.",
                details={"unknown_scopes": sorted(unknown)},
            )

        requested = set(scopes) or set(principal.effective_permissions)
        granted = requested & set(principal.effective_permissions)
        refused = requested - granted
        if refused:
            # Refuse rather than silently narrowing: a caller who thinks a key
            # has a permission it lacks will be debugging the wrong thing.
            raise PermissionDeniedError(
                "An API key cannot be granted permissions you do not hold yourself.",
                details={"refused_scopes": sorted(refused)},
            )

        for project_id in project_ids:
            if project_id not in principal.project_ids and not principal.has_permission(
                "project:read"
            ):
                raise PermissionDeniedError(
                    "An API key cannot be scoped to a project you cannot access.",
                    details={"project_id": str(project_id)},
                )

        full_key, prefix, key_hash = api_key_parts()
        api_key = ApiKey(
            org_id=principal.org_id,
            name=name,
            prefix=prefix,
            key_hash=key_hash,
            created_by=principal.user_id,
            scopes=sorted(granted),
            project_ids=list(project_ids),
            expires_at=(
                datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None
            ),
        )
        self.session.add(api_key)
        await self.session.flush()
        await self.audit.record(
            action=AuditAction.API_KEY_CREATED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="api_key",
            resource_id=api_key.id,
            resource_label=name,
            after={
                "name": name,
                "prefix": prefix,
                "scopes": sorted(granted),
                "expires_at": api_key.expires_at,
            },
        )
        return api_key, full_key

    async def revoke_api_key(self, principal: Principal, key_id: uuid.UUID) -> None:
        key = (
            await self.session.execute(
                select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == principal.org_id)
            )
        ).scalar_one_or_none()
        if key is None:
            raise NotFoundError("That API key was not found.")
        if key.revoked_at is not None:
            return
        key.revoked_at = datetime.now(UTC)
        await self.audit.record(
            action=AuditAction.API_KEY_REVOKED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="api_key",
            resource_id=key.id,
            resource_label=key.name,
        )

    async def list_api_keys(self, principal: Principal) -> list[ApiKey]:
        return list(
            (
                await self.session.execute(
                    select(ApiKey)
                    .where(ApiKey.org_id == principal.org_id)
                    .order_by(ApiKey.created_at.desc())
                )
            )
            .scalars()
            .all()
        )

    # ------------------------------------------------------------ principals
    async def principal_from_access_token(
        self,
        token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Principal:
        """Resolve a bearer access token into a principal."""
        from qguard.auth.providers import SupabaseAuthProvider
        from qguard.auth.tokens import parse_access_token

        if isinstance(self.provider, SupabaseAuthProvider):
            payload = await self.provider.verify_bearer_token(token)
            external_id = str(payload["sub"])
            user = (
                await self.session.execute(
                    text(
                        "SELECT id, org_id FROM users WHERE external_id = :eid "
                        "AND deleted_at IS NULL LIMIT 1"
                    ).bindparams(eid=external_id)
                )
            ).first()
            if user is None:
                raise AuthenticationError(
                    "This Supabase account is not provisioned in the platform. An "
                    "administrator must invite it first."
                )
            user_id, org_id = user
            await apply_tenant_context(self.session, org_id, user_id)
            return await resolve_principal(
                self.session,
                user_id=user_id,
                org_id=org_id,
                mfa_satisfied=bool(payload.get("aal") in ("aal2", "aal3")),
                ip_address=ip_address,
                user_agent=user_agent,
            )

        claims = parse_access_token(token)
        await apply_tenant_context(self.session, claims.org_id, claims.user_id)

        if claims.session_id is not None:
            # A revoked session must stop working immediately, not when its
            # short-lived access token happens to expire.
            row = (
                await self.session.execute(
                    select(UserSession.revoked_at, UserSession.expires_at).where(
                        UserSession.id == claims.session_id
                    )
                )
            ).first()
            if row is None:
                raise AuthenticationError("The session for this token no longer exists.")
            if row[0] is not None:
                raise AuthenticationError("This session has been revoked. Sign in again.")

        return await resolve_principal(
            self.session,
            user_id=claims.user_id,
            org_id=claims.org_id,
            session_id=claims.session_id,
            mfa_satisfied=claims.mfa_satisfied,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def principal_from_api_key(
        self,
        raw_key: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Principal:
        key_hash = hash_token(raw_key)
        row = (
            await self.session.execute(
                text(
                    "SELECT api_key_id, org_id, created_by, scopes, project_ids, expires_at, "
                    "revoked_at FROM app.find_api_key_identity(:h)"
                ),
                {"h": key_hash},
            )
        ).first()
        if row is None:
            raise AuthenticationError("That API key is not recognised.")

        key_id, org_id, created_by, scopes, project_ids, expires_at, revoked_at = row
        if revoked_at is not None:
            raise AuthenticationError("That API key has been revoked.")
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise AuthenticationError("That API key has expired.")

        await apply_tenant_context(self.session, org_id, created_by)
        principal = await resolve_principal(
            self.session,
            user_id=created_by,
            org_id=org_id,
            api_key_id=key_id,
            token_scopes=frozenset(scopes or []),
            mfa_satisfied=True,  # machine credentials present no second factor
            ip_address=ip_address,
            user_agent=user_agent,
        )
        await self.session.execute(
            update(ApiKey)
            .where(ApiKey.id == key_id)
            .values(last_used_at=datetime.now(UTC), last_used_ip=ip_address)
        )
        if project_ids:
            principal.project_ids = frozenset(project_ids)
        return principal

    async def organization_name(self, org_id: uuid.UUID) -> str:
        name = (
            await self.session.execute(select(Organization.name).where(Organization.id == org_id))
        ).scalar_one_or_none()
        return name or "Unknown organization"

    def profile_payload(self, user: User) -> dict[str, Any]:
        return {
            "id": user.id,
            "org_id": user.org_id,
            "email": user.email,
            "full_name": user.full_name,
            "job_title": user.job_title,
            "status": user.status,
            "is_superadmin": user.is_superadmin,
            "mfa_enabled": user.mfa_enabled,
            "timezone": user.timezone,
            "last_login_at": user.last_login_at,
            "created_at": user.created_at,
        }
