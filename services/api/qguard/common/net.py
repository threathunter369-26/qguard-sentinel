"""Settings-aware wrappers around the shared network guard.

The checks themselves live in :mod:`qguard_scanner.sdk.netguard` because both
the engines and the API need them, and ``qguard-api`` depends on
``qguard-scanner``. This module only supplies the deployment's configured
policy — the deny list and whether private ranges are reachable — and adapts
the SDK's exception to the platform's HTTP error envelope.
"""

from __future__ import annotations

from datetime import datetime

from qguard_scanner.sdk.netguard import (
    ALLOWED_URL_SCHEMES,
    DEFAULT_DENY_NETWORKS,
    METADATA_ENDPOINTS,
    ScopeDecision,
    ScopeMatcher,
    TargetInfo,
    authorization_is_current,
    classify_ip,
    normalize_host,
    parse_target,
    resolve_host,
)
from qguard_scanner.sdk.netguard import (
    UnsafeTargetError as _SdkUnsafeTargetError,
)
from qguard_scanner.sdk.netguard import (
    resolve_and_validate as _sdk_resolve_and_validate,
)

from qguard.common.config import get_settings
from qguard.common.errors import UnsafeTargetError

__all__ = [
    "ALLOWED_URL_SCHEMES",
    "DEFAULT_DENY_NETWORKS",
    "METADATA_ENDPOINTS",
    "ScopeDecision",
    "ScopeMatcher",
    "TargetInfo",
    "UnsafeTargetError",
    "authorization_is_current",
    "classify_ip",
    "normalize_host",
    "parse_target",
    "resolve_and_validate",
    "resolve_host",
]


def resolve_and_validate(
    target: str,
    *,
    allow_private: bool | None = None,
    require_scheme: bool = False,
) -> TargetInfo:
    """Validate a destination the platform will fetch, using configured policy.

    Raises the platform's :class:`~qguard.common.errors.UnsafeTargetError`,
    which the API layer maps to a 400 response, rather than the SDK's plain
    ``ValueError``.
    """
    settings = get_settings()
    try:
        return _sdk_resolve_and_validate(
            target,
            allow_private=(
                settings.allow_private_network_targets if allow_private is None else allow_private
            ),
            require_scheme=require_scheme,
            deny_networks=settings.scan_deny_networks,
        )
    except _SdkUnsafeTargetError as exc:
        raise UnsafeTargetError(exc.message) from exc


def safe_parse_target(target: str, *, default_scheme: str | None = "https") -> TargetInfo:
    """Parse a target without resolving it, raising the platform's error type."""
    try:
        return parse_target(target, default_scheme=default_scheme)
    except _SdkUnsafeTargetError as exc:
        raise UnsafeTargetError(exc.message) from exc


def authorization_window_ok(
    status: str,
    valid_from: datetime | None,
    valid_until: datetime | None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Check an authorization's lifecycle window."""
    return authorization_is_current(status, valid_from, valid_until, now)
