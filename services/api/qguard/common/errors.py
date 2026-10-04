"""Platform error taxonomy and the single consistent API error envelope.

Error responses always look like::

    {"error": {"code": "not_found", "message": "...", "details": {...},
               "request_id": "..."}}

Internal failures never leak stack traces or SQL to the client, but they are
always logged with full context and a correlating ``request_id``.
"""

from __future__ import annotations

from typing import Any


class QGuardError(Exception):
    """Base class for every expected platform error."""

    status_code: int = 500
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        self.message = message or self.message
        self.details = details or {}
        if code:
            self.code = code
        super().__init__(self.message)

    def to_payload(self, request_id: str | None = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            error["details"] = self.details
        if request_id:
            error["request_id"] = request_id
        return {"error": error}


# ------------------------------------------------------------------ 4xx client
class ValidationError(QGuardError):
    status_code = 422
    code = "validation_error"
    message = "The request payload is invalid."


class AuthenticationError(QGuardError):
    status_code = 401
    code = "authentication_required"
    message = "Authentication is required."


class InvalidCredentialsError(AuthenticationError):
    code = "invalid_credentials"
    # Deliberately generic: never reveal whether the account exists.
    message = "Invalid email or password."


class MFARequiredError(AuthenticationError):
    status_code = 401
    code = "mfa_required"
    message = "Multi-factor authentication is required to complete sign-in."


class AccountLockedError(AuthenticationError):
    status_code = 423
    code = "account_locked"
    message = "This account is temporarily locked after repeated failed sign-ins."


class TokenExpiredError(AuthenticationError):
    code = "token_expired"
    message = "The access token has expired."


class PermissionDeniedError(QGuardError):
    status_code = 403
    code = "permission_denied"
    message = "You do not have permission to perform this action."


class TenantIsolationError(PermissionDeniedError):
    code = "tenant_isolation_violation"
    message = "The requested resource does not belong to your organization."


class NotFoundError(QGuardError):
    status_code = 404
    code = "not_found"
    message = "The requested resource was not found."


class ConflictError(QGuardError):
    status_code = 409
    code = "conflict"
    message = "The request conflicts with the current state of the resource."


class InvalidStateTransitionError(ConflictError):
    code = "invalid_state_transition"
    message = "That status change is not allowed from the current state."


class PayloadTooLargeError(QGuardError):
    status_code = 413
    code = "payload_too_large"
    message = "The uploaded payload exceeds the configured maximum size."


class UnsupportedMediaTypeError(QGuardError):
    status_code = 415
    code = "unsupported_media_type"
    message = "That file type is not accepted for this endpoint."


class RateLimitExceededError(QGuardError):
    status_code = 429
    code = "rate_limit_exceeded"
    message = "Too many requests. Slow down and retry later."


# ----------------------------------------------------- domain-specific errors
class ScopeAuthorizationError(PermissionDeniedError):
    """Raised when a target is not covered by an approved test authorization.

    This is the platform's hard safety boundary: active security testing is
    refused unless an in-date, approved authorization explicitly covers the
    target. The refusal is always audited.
    """

    code = "target_not_authorized"
    message = (
        "The target is not covered by an active, approved test authorization. "
        "Active security testing is refused."
    )


class ScannerUnavailableError(QGuardError):
    status_code = 503
    code = "scanner_unavailable"
    message = "The requested scanner engine is not available."


class ScannerExecutionError(QGuardError):
    """A scanner failed. Surfaced to the user verbatim — never masked as success."""

    status_code = 500
    code = "scanner_failed"
    message = "The scanner engine failed to complete."


class IntelligenceUnavailableError(QGuardError):
    """An external intelligence source could not be reached.

    Callers degrade the engine run to ``DEGRADED`` rather than reporting a
    clean result derived from missing data.
    """

    status_code = 503
    code = "intelligence_unavailable"
    message = "Vulnerability intelligence data is currently unavailable."


class EvidenceIntegrityError(QGuardError):
    status_code = 409
    code = "evidence_integrity_failure"
    message = "Evidence integrity verification failed; the stored hash does not match."


class StorageError(QGuardError):
    status_code = 500
    code = "storage_error"
    message = "The storage backend could not complete the operation."


class SandboxError(QGuardError):
    status_code = 500
    code = "sandbox_error"
    message = "Sandboxed analysis failed to execute."


class SandboxTimeoutError(SandboxError):
    status_code = 504
    code = "sandbox_timeout"
    message = "Sandboxed analysis exceeded its execution budget."


class UnsafeTargetError(QGuardError):
    """Raised by the SSRF guard for a destination the platform refuses to reach."""

    status_code = 400
    code = "unsafe_target"
    message = "The requested destination is blocked by the platform's network policy."


class ConfigurationError(QGuardError):
    status_code = 500
    code = "configuration_error"
    message = "The platform is misconfigured for this operation."


class FeatureDisabledError(QGuardError):
    status_code = 409
    code = "feature_disabled"
    message = "That capability is disabled by platform configuration."
