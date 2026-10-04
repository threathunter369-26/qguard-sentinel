"""Authentication endpoints: sign-in, MFA, sessions and API keys."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from qguard.api.deps import (
    AuditDep,
    CurrentPrincipal,
    DbSession,
    MfaVerified,
    client_ip,
    get_auth_service,
    require_permission,
)
from qguard.auth.permissions import Perm
from qguard.auth.schemas import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeySummary,
    LoginRequest,
    MFAChallengeResponse,
    MFADisableRequest,
    MFAEnrolConfirmRequest,
    MFAEnrolStartResponse,
    MFAVerifyRequest,
    PasswordChangeRequest,
    PrincipalResponse,
    RefreshRequest,
    SessionSummary,
    TokenResponse,
    UserProfile,
)
from qguard.auth.service import AuthService
from qguard.common.errors import AuthenticationError

router = APIRouter(prefix="/auth", tags=["auth"])

AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


@router.post(
    "/login",
    summary="Sign in with email and password",
    response_model=None,
    responses={
        200: {"description": "Signed in, or an MFA challenge is required."},
        401: {"description": "The credentials are not valid."},
        423: {"description": "The account is temporarily locked."},
        429: {"description": "Too many sign-in attempts."},
    },
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    service: AuthServiceDep,
) -> TokenResponse | MFAChallengeResponse:
    """Verify credentials.

    When the account has MFA enabled the response carries only a short-lived
    challenge token, which grants no access by itself and is accepted solely at
    `/auth/mfa/verify`.
    """
    tokens, challenge, user = await service.login(
        payload.email,
        payload.password,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        device_label=payload.device_label,
    )
    if challenge is not None:
        response.status_code = status.HTTP_200_OK
        return MFAChallengeResponse(challenge_token=challenge)

    assert tokens is not None and user is not None
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        mfa_satisfied=False,
        user=UserProfile(**service.profile_payload(user)),
    )


@router.post("/mfa/verify", summary="Complete sign-in with a second factor")
async def verify_mfa(
    payload: MFAVerifyRequest,
    request: Request,
    service: AuthServiceDep,
) -> TokenResponse:
    """Exchange an MFA challenge token plus a TOTP or recovery code for tokens."""
    tokens, user = await service.complete_mfa(
        payload.challenge_token,
        payload.code,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        device_label=payload.device_label,
    )
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        mfa_satisfied=True,
        user=UserProfile(**service.profile_payload(user)),
    )


@router.post("/refresh", summary="Rotate an access token")
async def refresh(
    payload: RefreshRequest,
    request: Request,
    service: AuthServiceDep,
) -> TokenResponse:
    """Exchange a refresh token for a new pair.

    Refresh tokens are single-use. Presenting one that has already been
    rotated revokes every session descended from it, because that pattern
    indicates the token was captured.
    """
    tokens, user = await service.refresh(
        payload.refresh_token,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return TokenResponse(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_in=tokens.expires_in,
        mfa_satisfied=True,
        user=UserProfile(**service.profile_payload(user)),
    )


@router.post("/logout", summary="Revoke the current session", status_code=200)
async def logout(
    principal: CurrentPrincipal,
    service: AuthServiceDep,
    all_sessions: bool = False,
) -> dict[str, object]:
    revoked = await service.logout(principal, all_sessions=all_sessions)
    return {"sessions_revoked": revoked}


@router.get("/me", summary="The caller's identity and effective permissions")
async def me(
    principal: CurrentPrincipal,
    session: DbSession,
    service: AuthServiceDep,
) -> PrincipalResponse:
    """Return the caller's profile plus resolved authorization context.

    `permissions` lets the frontend hide controls the caller cannot use. That
    is presentation only — every endpoint re-checks server-side.
    """
    from sqlalchemy import select

    from qguard.models.identity import User

    user = (
        await session.execute(select(User).where(User.id == principal.user_id))
    ).scalar_one_or_none()
    if user is None:
        raise AuthenticationError("The account for this token no longer exists.")

    return PrincipalResponse(
        user=UserProfile(**service.profile_payload(user)),
        organization_name=await service.organization_name(principal.org_id),
        permissions=sorted(principal.effective_permissions),
        roles=sorted({g.role_key for g in principal.grants}),
        team_ids=sorted(principal.team_ids),
        project_ids=sorted(principal.project_ids),
        mfa_satisfied=principal.mfa_satisfied,
    )


@router.post("/password", summary="Change your own password")
async def change_password(
    payload: PasswordChangeRequest,
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> dict[str, str]:
    """Change the caller's password.

    Other sessions are revoked, since a password change is often a response to
    suspected compromise and leaving them live would defeat the point.
    """
    await service.change_password(principal, payload.current_password, payload.new_password)
    return {
        "status": "updated",
        "message": "Your password has been changed and your other sessions were signed out.",
    }


@router.post("/mfa/enrol", summary="Begin MFA enrolment")
async def start_mfa_enrolment(
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> MFAEnrolStartResponse:
    """Generate a TOTP secret and recovery codes.

    MFA is not active until a generated code is confirmed, so a mis-scanned QR
    code cannot lock the account out.
    """
    enrolment = await service.start_mfa_enrolment(principal)
    from qguard.common.cryptoutil import decrypt_value

    return MFAEnrolStartResponse(
        provisioning_uri=enrolment.provisioning_uri,
        secret=decrypt_value(enrolment.secret_encrypted, aad=f"mfa:{principal.email}"),
        recovery_codes=list(enrolment.recovery_codes),
    )


@router.post("/mfa/enrol/confirm", summary="Confirm and activate MFA")
async def confirm_mfa_enrolment(
    payload: MFAEnrolConfirmRequest,
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> dict[str, str]:
    await service.confirm_mfa_enrolment(principal, payload.code)
    return {
        "status": "enabled",
        "message": "Multi-factor authentication is now required for your account.",
    }


@router.post("/mfa/disable", summary="Disable MFA")
async def disable_mfa(
    payload: MFADisableRequest,
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> dict[str, str]:
    """Disable MFA. Requires the password *and* a current second factor."""
    await service.disable_mfa(principal, payload.current_password, payload.code)
    return {"status": "disabled", "message": "Multi-factor authentication has been turned off."}


@router.get("/sessions", summary="List your active sessions")
async def list_sessions(
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> list[SessionSummary]:
    rows = await service.list_sessions(principal)
    return [
        SessionSummary(
            id=row.id,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            device_label=row.device_label,
            mfa_satisfied=row.mfa_satisfied,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            expires_at=row.expires_at,
            is_current=row.id == principal.session_id,
        )
        for row in rows
    ]


@router.delete(
    "/sessions/{session_id}",
    summary="Revoke one of your sessions",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_session(
    session_id: uuid.UUID,
    principal: CurrentPrincipal,
    service: AuthServiceDep,
) -> None:
    await service.revoke_session(principal, session_id)


@router.get("/api-keys", summary="List API keys")
async def list_api_keys(
    principal: Annotated[object, Depends(require_permission(Perm.USER_MANAGE_API_KEYS))],
    service: AuthServiceDep,
) -> list[ApiKeySummary]:
    rows = await service.list_api_keys(principal)  # type: ignore[arg-type]
    return [ApiKeySummary.model_validate(row) for row in rows]


@router.post(
    "/api-keys",
    summary="Create an API key",
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    payload: ApiKeyCreateRequest,
    principal: MfaVerified,
    service: AuthServiceDep,
) -> ApiKeyCreatedResponse:
    """Mint an API key for CI or scanner integrations.

    A key can never hold a permission its creator lacks. Creating one requires
    a session verified with a second factor, because the key outlives the
    session that created it.
    """
    principal.require(Perm.USER_MANAGE_API_KEYS)
    key, full_key = await service.create_api_key(
        principal,
        name=payload.name,
        scopes=payload.scopes,
        project_ids=payload.project_ids,
        expires_in_days=payload.expires_in_days,
    )
    return ApiKeyCreatedResponse(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        key=full_key,
        scopes=list(key.scopes),
        expires_at=key.expires_at,
    )


@router.delete(
    "/api-keys/{key_id}",
    summary="Revoke an API key",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_api_key(
    key_id: uuid.UUID,
    principal: Annotated[object, Depends(require_permission(Perm.USER_MANAGE_API_KEYS))],
    service: AuthServiceDep,
    audit: AuditDep,
) -> None:
    await service.revoke_api_key(principal, key_id)  # type: ignore[arg-type]
