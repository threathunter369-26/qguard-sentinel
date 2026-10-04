"""Access and refresh token handling.

Access tokens are short-lived, signed JWTs carrying only identity and tenancy —
never the permission set. Permissions are resolved from the database on every
request, so revoking a role takes effect immediately rather than when the token
expires.

Refresh tokens are opaque random strings; only their SHA-256 hash is stored.
They are single-use: presenting one rotates it, and presenting a rotated token
is treated as theft and revokes the whole session family.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError

from qguard.common.config import get_settings
from qguard.common.cryptoutil import generate_token, hash_token
from qguard.common.errors import AuthenticationError, TokenExpiredError

ACCESS_TOKEN_TYPE = "access"
MFA_CHALLENGE_TOKEN_TYPE = "mfa_challenge"
ISSUER = "qguard-sentinel"


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: uuid.UUID
    org_id: uuid.UUID
    session_id: uuid.UUID | None
    email: str | None
    mfa_satisfied: bool
    issued_at: datetime
    expires_at: datetime
    token_type: str = ACCESS_TOKEN_TYPE


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    refresh_token_hash: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    token_type: str = "Bearer"

    @property
    def expires_in(self) -> int:
        return max(0, int((self.access_expires_at - datetime.now(UTC)).total_seconds()))


def issue_access_token(
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    session_id: uuid.UUID | None = None,
    email: str | None = None,
    mfa_satisfied: bool = False,
    ttl_seconds: int | None = None,
) -> tuple[str, datetime]:
    settings = get_settings()
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=ttl_seconds or settings.access_token_ttl_seconds)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "org": str(org_id),
        "typ": ACCESS_TOKEN_TYPE,
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": str(uuid.uuid4()),
        "mfa": mfa_satisfied,
    }
    if session_id:
        payload["sid"] = str(session_id)
    if email:
        payload["email"] = email
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires


def issue_mfa_challenge_token(user_id: uuid.UUID, org_id: uuid.UUID) -> str:
    """Short-lived token proving the password step succeeded.

    Carries no authorization: it can only be exchanged at the MFA verification
    endpoint, so a stolen challenge token grants nothing on its own.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "org": str(org_id),
        "typ": MFA_CHALLENGE_TOKEN_TYPE,
        "iss": ISSUER,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, *, expected_type: str = ACCESS_TOKEN_TYPE) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError() from exc
    except InvalidTokenError as exc:
        # Never echo the parser's reason back to the caller: it distinguishes
        # a malformed token from a wrong signature, which is an oracle.
        raise AuthenticationError("The access token is not valid.") from exc

    if payload.get("typ") != expected_type:
        raise AuthenticationError("The token is not valid for this operation.")
    return payload


def parse_access_token(token: str) -> AccessTokenClaims:
    payload = decode_token(token, expected_type=ACCESS_TOKEN_TYPE)
    try:
        return AccessTokenClaims(
            user_id=uuid.UUID(payload["sub"]),
            org_id=uuid.UUID(payload["org"]),
            session_id=uuid.UUID(payload["sid"]) if payload.get("sid") else None,
            email=payload.get("email"),
            mfa_satisfied=bool(payload.get("mfa", False)),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthenticationError("The access token is malformed.") from exc


def new_refresh_token() -> tuple[str, str, datetime]:
    """Return ``(token, token_hash, expires_at)`` for a fresh refresh token."""
    settings = get_settings()
    token = generate_token(48)
    expires = datetime.now(UTC) + timedelta(seconds=settings.refresh_token_ttl_seconds)
    return token, hash_token(token), expires


def issue_token_pair(
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    session_id: uuid.UUID,
    email: str | None,
    mfa_satisfied: bool,
) -> IssuedTokens:
    access_token, access_expires = issue_access_token(
        user_id=user_id,
        org_id=org_id,
        session_id=session_id,
        email=email,
        mfa_satisfied=mfa_satisfied,
    )
    refresh_token, refresh_hash, refresh_expires = new_refresh_token()
    return IssuedTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_token_hash=refresh_hash,
        access_expires_at=access_expires,
        refresh_expires_at=refresh_expires,
    )
