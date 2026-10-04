"""Cryptographic helpers used by the platform itself.

Covers password hashing, constant-time token handling, envelope encryption for
stored secrets (MFA seeds, feed credentials), evidence hashing and the
append-only hash chaining used by the audit log and chain of custody.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qguard.common.config import get_settings
from qguard.common.errors import ConfigurationError

# OWASP Password Storage Cheat Sheet (2024) Argon2id guidance: >=19 MiB memory,
# >=2 iterations, parallelism 1.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

READ_CHUNK = 1024 * 1024


# ------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Verify a password in constant time with respect to account existence.

    When ``stored_hash`` is ``None`` (unknown account, or an SSO-only account) a
    dummy verification still runs so the response time does not reveal whether
    the account exists.
    """
    if not stored_hash:
        with suppress(VerifyMismatchError, VerificationError, InvalidHashError):
            _hasher.verify(_DUMMY_HASH, "not-the-password")
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


_DUMMY_HASH = _hasher.hash("qguard-timing-equalizer")


# ---------------------------------------------------------------------- tokens
def generate_token(num_bytes: int = 32) -> str:
    """URL-safe random token (used for sessions, API keys, invite links)."""
    return secrets.token_urlsafe(num_bytes)


def hash_token(token: str) -> str:
    """Hash a bearer token for storage.

    Tokens are already high-entropy random values, so a single SHA-256 is
    appropriate; the database therefore never holds a usable credential.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def api_key_parts() -> tuple[str, str, str]:
    """Return ``(full_key, prefix, key_hash)`` for a newly minted API key."""
    prefix = "qgs_" + secrets.token_hex(4)
    body = secrets.token_urlsafe(32)
    full = f"{prefix}.{body}"
    return full, prefix, hash_token(full)


# ---------------------------------------------------------------- hashing files
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_stream(stream: BinaryIO) -> dict[str, str]:
    """Compute SHA-256, SHA-1 and MD5 in a single pass.

    SHA-256 is authoritative for integrity. SHA-1 and MD5 are recorded only
    because forensic tooling and threat-intel feeds are still keyed on them.
    """
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()  # noqa: S324
    size = 0
    while chunk := stream.read(READ_CHUNK):
        size += len(chunk)
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": str(size),
    }


def hash_file(path: str | Path) -> dict[str, str]:
    with open(path, "rb") as handle:
        return hash_stream(handle)


# ------------------------------------------------------------- hash chaining
GENESIS_HASH = "0" * 64


def chain_hash(previous_hash: str | None, payload: dict[str, Any]) -> str:
    """Compute the next entry hash in a tamper-evident append-only chain.

    ``H(prev || canonical_json(payload))``. Any retroactive edit to an earlier
    record invalidates every subsequent hash, which the verification endpoint
    detects and reports.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    material = f"{previous_hash or GENESIS_HASH}|{canonical}".encode()
    return hashlib.sha256(material).hexdigest()


# -------------------------------------------------------- envelope encryption
def _load_key() -> bytes:
    settings = get_settings()
    raw = settings.encryption_key
    if not raw:
        if settings.env in ("development", "test"):
            # Deterministic per-process development key. Never used in prod:
            # the production config validator requires an explicit key.
            return hashlib.sha256(f"qguard-dev-{settings.jwt_secret}".encode()).digest()
        raise ConfigurationError(
            "QG_ENCRYPTION_KEY must be configured before storing encrypted values."
        )
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:
        key = raw.encode("utf-8")
    if len(key) not in (16, 24, 32):
        key = hashlib.sha256(key).digest()
    return key


def encrypt_value(plaintext: str, *, aad: str | None = None) -> str:
    """AES-256-GCM encrypt a short secret for at-rest storage.

    Returns ``v1:<base64(nonce||ciphertext)>``. The version prefix allows key
    rotation without ambiguity about how an existing row was encrypted.
    """
    aesgcm = AESGCM(_load_key())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad.encode() if aad else None)
    return "v1:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_value(ciphertext: str, *, aad: str | None = None) -> str:
    if not ciphertext.startswith("v1:"):
        raise ConfigurationError("Unsupported ciphertext version.")
    blob = base64.urlsafe_b64decode(ciphertext[3:])
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(_load_key()).decrypt(nonce, ct, aad.encode() if aad else None).decode("utf-8")
    except InvalidTag as exc:
        raise ConfigurationError(
            "Stored value failed authenticated decryption; the encryption key may have changed."
        ) from exc


# -------------------------------------------------------------- secret redaction
def redact_secret(value: str, *, keep_start: int = 4, keep_end: int = 2) -> str:
    """Produce a non-recoverable preview of a detected secret.

    Secrets detection must be actionable without the platform becoming a second
    copy of the credential store, so only a short prefix/suffix survives and
    anything short enough to brute-force from the preview is fully masked.
    """
    value = value.strip()
    if len(value) <= keep_start + keep_end + 4:
        return "*" * 12
    return f"{value[:keep_start]}{'*' * 8}{value[-keep_end:]}"


def fingerprint_secret(value: str) -> str:
    """Stable, non-reversible identifier for a detected secret.

    Lets the platform recognise the same credential across files and scans, and
    confirm rotation, without ever persisting the credential itself.
    """
    settings = get_settings()
    return hmac.new(
        key=hashlib.sha256(settings.jwt_secret.encode()).digest(),
        msg=value.strip().encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character. Used to rank secret candidates."""
    if not data:
        return 0.0
    import math
    from collections import Counter

    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
