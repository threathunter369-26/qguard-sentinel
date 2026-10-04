"""Shared validated field types.

The platform is deployed inside organizations, so identifiers routinely use
internal namespaces — ``.internal``, ``.corp``, ``.local``, ``.test`` — that a
public-deliverability email validator rejects outright. Those addresses are
perfectly valid for an internal security platform, so email validation here
checks syntax and normalises case without requiring the domain to be
publicly resolvable.
"""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import AfterValidator, StringConstraints

# RFC 5322 in full is not worth implementing; this is the pragmatic subset that
# accepts every address a real directory contains while rejecting the malformed
# input that would otherwise reach the database or an audit record.
_LOCAL_PART = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_EMAIL_RE = re.compile(
    rf"^{_LOCAL_PART}@{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})+$",
)


def validate_email_address(value: str) -> str:
    """Validate and normalise an email address.

    Accepts internal and reserved domains (``admin@acme.internal``,
    ``soc@corp.local``) because an on-premises security platform's users live
    there. Normalises the whole address to lower case so uniqueness is
    case-insensitive, matching the database's ``email = lower(email)``
    constraint.
    """
    value = value.strip()
    if not value:
        raise ValueError("An email address is required.")
    if len(value) > 320:
        raise ValueError("The email address is too long (maximum 320 characters).")
    if value.count("@") != 1:
        raise ValueError("The email address must contain exactly one @ sign.")

    local, _, domain = value.partition("@")
    if len(local) > 64:
        raise ValueError("The part before the @ sign is too long (maximum 64 characters).")
    if len(domain) > 253:
        raise ValueError("The domain part is too long (maximum 253 characters).")
    if not _EMAIL_RE.match(value):
        raise ValueError(
            "That is not a valid email address. Expected something like "
            "name@example.com (internal domains such as .internal or .local are fine)."
        )
    return value.lower()


#: Email address accepting internal domains, normalised to lower case.
EmailAddress = Annotated[str, AfterValidator(validate_email_address)]

#: A short identifier used in URLs and references (project keys, slugs).
Slug = Annotated[
    str,
    StringConstraints(min_length=1, max_length=80, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
]

#: An uppercase project key used in generated references, e.g. ``WEBAPP``.
ProjectKey = Annotated[
    str, StringConstraints(min_length=2, max_length=32, pattern=r"^[A-Z][A-Z0-9_]*$")
]

#: A CVE identifier.
CVEId = Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$")]

#: A CWE identifier.
CWEId = Annotated[str, StringConstraints(pattern=r"^CWE-\d+$")]

#: A MITRE ATT&CK technique or sub-technique identifier.
TechniqueId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(?:\.\d{3})?$")]

#: A lowercase hex SHA-256 digest.
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: A free-text tag.
Tag = Annotated[str, StringConstraints(min_length=1, max_length=80)]
