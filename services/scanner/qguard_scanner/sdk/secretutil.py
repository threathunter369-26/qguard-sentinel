"""Handling of credentials an engine has detected.

Every engine that can find a secret — the secrets engine in source trees, the
mobile engine in a compiled application, an importer reading a third-party
report — needs the same two operations, and they must behave identically
everywhere so that one credential found twice correlates to one finding rather
than two.

The rule the platform holds to: **a detected credential is never stored.** A
finding carries a redacted preview, which lets a reviewer who already holds
the credential recognise which one it is, and a keyed fingerprint, which lets
the platform recognise the same credential across scans and engines without
retaining it. Neither is reversible.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from collections import Counter

#: Default salt for fingerprinting. A deployment overrides it so fingerprints
#: are not comparable between organisations.
DEFAULT_FINGERPRINT_SALT = "qguard-secrets"


def redact(value: str, *, keep_start: int = 4, keep_end: int = 2) -> str:
    """Produce a non-recoverable preview of a credential.

    A value short enough that a prefix and suffix would narrow it to a feasible
    search space is masked completely — a preview is only useful if it does not
    help an attacker who sees it.
    """
    value = value.strip()
    if len(value) <= keep_start + keep_end + 4:
        return "*" * 12
    return f"{value[:keep_start]}{'*' * 8}{value[-keep_end:]}"


def fingerprint(value: str, salt: str = DEFAULT_FINGERPRINT_SALT) -> str:
    """Stable, non-reversible identifier for a detected secret.

    Keyed, because an unkeyed digest of a weak or common credential is
    effectively reversible against a precomputed table. The same credential
    always produces the same fingerprint under one salt, which is what lets
    correlation deduplicate it across engines and scans.
    """
    return hmac.new(
        key=hashlib.sha256(salt.encode("utf-8")).digest(),
        msg=value.strip().encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def shannon_entropy(data: str) -> float:
    """Shannon entropy of a string in bits per character.

    Used to separate a high-entropy credential from a low-entropy identifier
    that happens to match a pattern. A generated API key approaches the
    theoretical maximum for its alphabet; a word, a path or a placeholder does
    not.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


__all__ = [
    "DEFAULT_FINGERPRINT_SALT",
    "fingerprint",
    "redact",
    "shannon_entropy",
]
