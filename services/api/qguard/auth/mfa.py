"""Time-based one-time password enrolment and verification.

TOTP seeds are encrypted at rest with the application key and are never
returned by any endpoint after enrolment completes. Recovery codes are stored
only as hashes, so the platform cannot reveal them a second time either.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import pyotp

from qguard.common.config import get_settings
from qguard.common.cryptoutil import (
    constant_time_compare,
    decrypt_value,
    encrypt_value,
    hash_token,
)

RECOVERY_CODE_COUNT = 10
#: One step either side, to tolerate clock skew without widening the window
#: enough to matter for brute force.
TOTP_VALID_WINDOW = 1


@dataclass(frozen=True, slots=True)
class MFAEnrolment:
    secret_encrypted: str
    provisioning_uri: str
    recovery_codes: tuple[str, ...]
    recovery_code_hashes: tuple[str, ...]


def start_enrolment(email: str) -> MFAEnrolment:
    """Generate a new TOTP secret and single-use recovery codes.

    The plaintext secret and codes are returned exactly once, for display, and
    only the encrypted secret and the code hashes are intended for storage.
    """
    settings = get_settings()
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=settings.mfa_issuer)

    codes = tuple(_format_recovery_code() for _ in range(RECOVERY_CODE_COUNT))
    return MFAEnrolment(
        secret_encrypted=encrypt_value(secret, aad=f"mfa:{email}"),
        provisioning_uri=uri,
        recovery_codes=codes,
        recovery_code_hashes=tuple(hash_token(c) for c in codes),
    )


def _format_recovery_code() -> str:
    raw = secrets.token_hex(5).upper()
    return f"{raw[:5]}-{raw[5:]}"


def verify_totp(secret_encrypted: str, code: str, *, email: str) -> bool:
    """Verify a TOTP code against the stored encrypted secret."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    try:
        secret = decrypt_value(secret_encrypted, aad=f"mfa:{email}")
    except Exception:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=TOTP_VALID_WINDOW)


def verify_recovery_code(stored_hashes: list[str], code: str) -> str | None:
    """Verify a recovery code and return the hash that matched, or ``None``.

    The caller removes the returned hash from the stored list, which is what
    makes each code single-use.
    """
    candidate = hash_token((code or "").strip().upper())
    for stored in stored_hashes:
        if constant_time_compare(candidate, stored):
            return stored
    return None
