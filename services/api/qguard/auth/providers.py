"""Authentication provider abstraction.

Two providers ship: a fully self-hosted local provider (Argon2id + TOTP against
PostgreSQL) and a Supabase provider that verifies Supabase-issued JWTs and maps
them onto platform users. Both satisfy the same protocol, so the rest of the
platform never branches on which is configured.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx
import jwt
from jwt import PyJWKClient

from qguard.common.config import get_settings
from qguard.common.cryptoutil import hash_password, password_needs_rehash, verify_password
from qguard.common.errors import (
    AccountLockedError,
    AuthenticationError,
    ConfigurationError,
    InvalidCredentialsError,
)
from qguard.common.logging import get_logger

log = get_logger(__name__)


@dataclass(slots=True)
class VerifiedIdentity:
    """The outcome of a successful credential check."""

    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    requires_mfa: bool = False
    mfa_secret_encrypted: str | None = None
    full_name: str | None = None
    external_id: str | None = None
    needs_password_rehash: bool = False


@dataclass(slots=True)
class LoginCandidate:
    """A row returned by the privileged sign-in lookup."""

    user_id: uuid.UUID
    org_id: uuid.UUID
    email: str
    password_hash: str | None
    status: str
    auth_provider: str
    mfa_enabled: bool
    mfa_secret_encrypted: str | None
    failed_login_count: int
    locked_until: datetime | None
    is_superadmin: bool
    full_name: str | None


class AuthProvider(Protocol):
    """Contract every authentication backend satisfies."""

    name: str

    async def verify_password_credentials(
        self, candidate: LoginCandidate | None, password: str
    ) -> VerifiedIdentity: ...

    async def verify_bearer_token(self, token: str) -> dict[str, Any]: ...


class LocalAuthProvider:
    """Self-hosted authentication against the platform's own user table."""

    name = "local"

    async def verify_password_credentials(
        self, candidate: LoginCandidate | None, password: str
    ) -> VerifiedIdentity:
        settings = get_settings()

        if candidate is not None and candidate.locked_until:
            locked_until = candidate.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=UTC)
            if locked_until > datetime.now(UTC):
                raise AccountLockedError(
                    "This account is temporarily locked after repeated failed sign-in "
                    f"attempts. Try again after {locked_until.isoformat()}."
                )

        # verify_password() runs a dummy Argon2 verification when the hash is
        # absent, so an unknown address and a wrong password take the same time
        # and the response cannot be used to enumerate accounts.
        stored = candidate.password_hash if candidate else None
        if not verify_password(password, stored) or candidate is None:
            raise InvalidCredentialsError()

        if candidate.auth_provider != "local":
            # The account is federated; a local password must not be accepted
            # for it even if a stale hash is still on the row.
            raise InvalidCredentialsError()

        if candidate.status != "active":
            raise AuthenticationError(
                f"This account is {candidate.status.replace('_', ' ')} and cannot sign in."
            )

        if len(password) < settings.password_min_length:
            # Only reachable for a legacy password shorter than the current
            # policy. Authentication succeeds and the caller is asked to change it.
            log.info("auth.password_below_policy", user_id=str(candidate.user_id))

        return VerifiedIdentity(
            user_id=candidate.user_id,
            org_id=candidate.org_id,
            email=candidate.email,
            requires_mfa=candidate.mfa_enabled,
            mfa_secret_encrypted=candidate.mfa_secret_encrypted,
            full_name=candidate.full_name,
            needs_password_rehash=bool(stored) and password_needs_rehash(stored),
        )

    async def verify_bearer_token(self, token: str) -> dict[str, Any]:
        from qguard.auth.tokens import decode_token

        return decode_token(token)

    @staticmethod
    def hash_new_password(password: str) -> str:
        return hash_password(password)


class SupabaseAuthProvider:
    """Verifies Supabase-issued JWTs and maps them onto platform users.

    Supabase owns the credential: the platform never sees the password. It
    verifies the token's signature, then resolves the Supabase subject to a
    platform user row that carries the tenancy and role grants.

    Both key arrangements are supported: the legacy shared HS256 secret and the
    asymmetric keys newer projects publish at a JWKS endpoint. The JWKS client
    caches keys and refreshes on rotation.
    """

    name = "supabase"

    def __init__(self) -> None:
        self._jwk_client: PyJWKClient | None = None

    def _jwks(self) -> PyJWKClient:
        settings = get_settings()
        if self._jwk_client is None:
            url = settings.supabase_jwks_url
            if not url and settings.supabase_url:
                url = f"{settings.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
            if not url:
                raise ConfigurationError(
                    "Supabase JWT verification needs QG_SUPABASE_JWKS_URL or QG_SUPABASE_URL."
                )
            self._jwk_client = PyJWKClient(url, cache_keys=True, lifespan=3600)
        return self._jwk_client

    async def verify_password_credentials(
        self, candidate: LoginCandidate | None, password: str
    ) -> VerifiedIdentity:
        # Supabase holds the credential, so the platform does not offer a
        # password endpoint in this mode: the client authenticates with
        # Supabase and presents the resulting JWT.
        raise ConfigurationError(
            "This deployment authenticates through Supabase. Sign in with the Supabase "
            "client and present the issued token to this API."
        )

    async def verify_bearer_token(self, token: str) -> dict[str, Any]:
        settings = get_settings()
        options = {"require": ["exp", "sub"], "verify_aud": bool(settings.supabase_jwt_audience)}

        try:
            if settings.supabase_jwt_secret:
                payload = jwt.decode(
                    token,
                    settings.supabase_jwt_secret,
                    algorithms=["HS256"],
                    audience=settings.supabase_jwt_audience or None,
                    options=options,
                )
            else:
                signing_key = self._jwks().get_signing_key_from_jwt(token)
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256", "ES256"],
                    audience=settings.supabase_jwt_audience or None,
                    options=options,
                )
        except jwt.ExpiredSignatureError as exc:
            from qguard.common.errors import TokenExpiredError

            raise TokenExpiredError() from exc
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError("The Supabase token is not valid.") from exc

        if not payload.get("sub"):
            raise AuthenticationError("The Supabase token has no subject claim.")
        return payload

    async def fetch_user(self, access_token: str) -> dict[str, Any]:
        """Read the Supabase user record, used when provisioning a new account."""
        settings = get_settings()
        if not settings.supabase_url:
            raise ConfigurationError("QG_SUPABASE_URL is not configured.")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{settings.supabase_url.rstrip('/')}/auth/v1/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "apikey": settings.supabase_anon_key or "",
                },
            )
        if response.status_code != 200:
            raise AuthenticationError("Supabase rejected the token when reading the profile.")
        return response.json()


_provider: AuthProvider | None = None


def get_auth_provider() -> AuthProvider:
    global _provider
    if _provider is None:
        settings = get_settings()
        _provider = (
            SupabaseAuthProvider() if settings.auth_provider == "supabase" else LocalAuthProvider()
        )
    return _provider


def reset_auth_provider() -> None:
    """Clear the cached provider. Used by tests that switch configuration."""
    global _provider
    _provider = None


def lockout_until(failed_count: int) -> datetime | None:
    """Compute a lockout expiry from the failure count.

    Lockout is applied only once the threshold is reached, and is time-boxed so
    a burst of wrong passwords does not permanently deny a legitimate user —
    which would turn the control into a denial-of-service vector.
    """
    settings = get_settings()
    if failed_count < settings.max_failed_logins:
        return None
    # Back off progressively for repeated lockouts, capped at one hour.
    multiplier = min(4, 1 + (failed_count - settings.max_failed_logins) // 2)
    return datetime.now(UTC) + timedelta(seconds=min(3600, settings.lockout_seconds * multiplier))
