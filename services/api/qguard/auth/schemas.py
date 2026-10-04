"""Request and response schemas for authentication endpoints."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from qguard.common.config import get_settings
from qguard.common.types import EmailAddress

#: Passwords that are long but trivially guessable still fail the check below.
_COMMON_PATTERNS = re.compile(
    r"(password|qwerty|letmein|welcome|admin123|changeme|iloveyou|000000|123456"
    r"|abc123|monkey|dragon|sunshine|princess|football|baseball|trustno1"
    r"|qguard|sentinel)",
    re.IGNORECASE,
)


def validate_password_strength(password: str) -> str:
    """Enforce the password policy.

    Length does most of the work (NIST SP 800-63B), with character-class and
    common-pattern checks as a backstop. The message always states every
    unmet requirement at once so a user is not made to guess repeatedly.
    """
    settings = get_settings()
    problems: list[str] = []
    if len(password) < settings.password_min_length:
        problems.append(f"be at least {settings.password_min_length} characters long")
    if len(password) > 256:
        problems.append("be no longer than 256 characters")
    if not re.search(r"[a-z]", password):
        problems.append("include a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("include an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("include a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("include a symbol")
    if _COMMON_PATTERNS.search(password):
        problems.append("not contain a common or product-related word")
    if len(set(password)) < 6:
        problems.append("use at least six distinct characters")
    if problems:
        raise ValueError("The password must " + ", ".join(problems) + ".")
    return password


class LoginRequest(BaseModel):
    email: EmailAddress
    password: str = Field(min_length=1, max_length=256)
    #: Opt-in device label, shown in the active-sessions list.
    device_label: str | None = Field(default=None, max_length=160)


class MFAVerifyRequest(BaseModel):
    challenge_token: str = Field(min_length=10, max_length=4096)
    code: str = Field(min_length=6, max_length=16)
    device_label: str | None = Field(default=None, max_length=160)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"  # noqa: S105 - an HTTP scheme name, not a secret
    expires_in: int
    mfa_satisfied: bool
    user: UserProfile


class MFAChallengeResponse(BaseModel):
    """Returned when the password step succeeded but MFA is still required."""

    mfa_required: bool = True
    challenge_token: str
    message: str = "Enter the six-digit code from your authenticator app."


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    full_name: str
    job_title: str | None = None
    status: str
    is_superadmin: bool
    mfa_enabled: bool
    timezone: str
    last_login_at: datetime | None = None
    created_at: datetime


class PrincipalResponse(BaseModel):
    """The caller's identity plus the resolved authorization context.

    The frontend uses ``permissions`` to decide which navigation entries and
    actions to render. It is a convenience only: every endpoint re-checks
    server-side, so hiding a control is never the access control itself.
    """

    user: UserProfile
    organization_name: str
    permissions: list[str]
    roles: list[str]
    team_ids: list[uuid.UUID]
    project_ids: list[uuid.UUID]
    mfa_satisfied: bool


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _strength(cls, value: str) -> str:
        return validate_password_strength(value)


class MFAEnrolStartResponse(BaseModel):
    """Enrolment material, returned exactly once.

    The secret and recovery codes are not retrievable afterwards: the secret is
    stored encrypted and the codes only as hashes.
    """

    provisioning_uri: str
    secret: str
    recovery_codes: list[str]
    message: str = (
        "Scan the URI with your authenticator app, then confirm with a generated code. "
        "Store the recovery codes somewhere safe — they are shown only now."
    )


class MFAEnrolConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MFADisableRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=16)


class SessionSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str | None
    user_agent: str | None
    device_label: str | None
    mfa_satisfied: bool
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime
    is_current: bool = False


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    #: A key can never exceed the permissions of the user creating it; the
    #: service intersects this list with the creator's own grants.
    scopes: list[str] = Field(default_factory=list, max_length=200)
    project_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    expires_in_days: int | None = Field(default=90, ge=1, le=730)


class ApiKeyCreatedResponse(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    #: The only time the full key is ever returned.
    key: str
    scopes: list[str]
    expires_at: datetime | None
    message: str = "Copy this key now. It cannot be retrieved again."


class ApiKeySummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    project_ids: list[uuid.UUID]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
