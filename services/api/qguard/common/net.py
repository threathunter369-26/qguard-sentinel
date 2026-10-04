"""Network target validation, SSRF guards and authorization scope matching.

Two distinct protections live here and must not be confused:

* :func:`resolve_and_validate` is an **SSRF guard**. It applies to destinations
  the *platform* fetches on a user's behalf (importing an OpenAPI document,
  pulling a threat feed, calling a webhook). It refuses link-local metadata
  endpoints and, in multi-tenant deployments, private ranges.

* :class:`ScopeMatcher` implements **authorization scope enforcement**. It
  decides whether a target is covered by an approved, in-date test
  authorization. Active security testing is refused when it is not, no matter
  how the request was constructed.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

from qguard.common.config import get_settings
from qguard.common.errors import UnsafeTargetError

#: Cloud instance-metadata endpoints. Always refused, in every environment.
METADATA_ENDPOINTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / DigitalOcean / OpenStack
        "fd00:ec2::254",  # AWS IMDSv2 over IPv6
        "metadata.google.internal",
        "metadata.goog",
        "100.100.100.200",  # Alibaba Cloud
    }
)

ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$"
)

_PORT_RANGE_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


@dataclass(slots=True)
class TargetInfo:
    """A validated network destination."""

    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str = "/"
    resolved_ips: list[str] = field(default_factory=list)
    is_ip_literal: bool = False

    @property
    def normalized_url(self) -> str:
        scheme = self.scheme or "https"
        default_port = 443 if scheme == "https" else 80
        netloc = self.host if (self.port in (None, default_port)) else f"{self.host}:{self.port}"
        return urlunparse((scheme, netloc, self.path or "/", "", "", ""))


def normalize_host(host: str) -> str:
    """Lower-case, strip brackets/trailing dot, and reject obvious injections."""
    host = host.strip().strip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise UnsafeTargetError("An empty host is not a valid target.")
    if any(ch in host for ch in " \t\r\n\0/\\@"):
        raise UnsafeTargetError("The host contains characters that are not allowed.")
    return host


def parse_target(target: str, *, default_scheme: str | None = None) -> TargetInfo:
    """Parse a URL, ``host:port`` pair or bare host into a :class:`TargetInfo`."""
    target = target.strip()
    if not target:
        raise UnsafeTargetError("An empty target cannot be assessed.")

    if "://" in target:
        parsed = urlparse(target)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ALLOWED_URL_SCHEMES:
            raise UnsafeTargetError(
                f"URL scheme {scheme or '(none)'!r} is not permitted; use http or https."
            )
        if not parsed.hostname:
            raise UnsafeTargetError("The URL does not contain a host.")
        host = normalize_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as exc:
            raise UnsafeTargetError("The URL contains an invalid port.") from exc
        path = parsed.path or "/"
    else:
        scheme = default_scheme
        host_part = target
        port = None
        # IPv6 literal with optional port: [::1]:8080
        if host_part.startswith("["):
            closing = host_part.find("]")
            if closing == -1:
                raise UnsafeTargetError("Malformed IPv6 literal in target.")
            host = normalize_host(host_part[1:closing])
            remainder = host_part[closing + 1 :]
            if remainder.startswith(":"):
                port = _parse_port(remainder[1:])
        elif host_part.count(":") == 1:
            maybe_host, _, maybe_port = host_part.partition(":")
            host = normalize_host(maybe_host)
            port = _parse_port(maybe_port)
        else:
            host = normalize_host(host_part)
        path = "/"

    is_literal = _is_ip_literal(host)
    if not is_literal and not _HOSTNAME_RE.match(host):
        raise UnsafeTargetError(f"{host!r} is not a valid hostname.")

    return TargetInfo(
        raw=target,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        is_ip_literal=is_literal,
    )


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise UnsafeTargetError(f"{value!r} is not a valid port.") from exc
    if not 1 <= port <= 65535:
        raise UnsafeTargetError(f"Port {port} is outside the valid range 1-65535.")
    return port


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def classify_ip(ip: str) -> dict[str, bool]:
    addr = ipaddress.ip_address(ip)
    return {
        "private": addr.is_private,
        "loopback": addr.is_loopback,
        "link_local": addr.is_link_local,
        "multicast": addr.is_multicast,
        "reserved": addr.is_reserved,
        "unspecified": addr.is_unspecified,
        "global": addr.is_global,
    }


def resolve_host(host: str) -> list[str]:
    """Resolve a host to every A/AAAA address.

    All addresses are checked, not just the first: a DNS record that mixes a
    public and a link-local address would otherwise slip past validation, and
    re-resolution at connect time is where rebinding attacks land.
    """
    if _is_ip_literal(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        detail = exc.strerror or str(exc)
        raise UnsafeTargetError(f"DNS resolution failed for {host!r}: {detail}") from exc
    addresses: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in addresses:
            addresses.append(addr)
    if not addresses:
        raise UnsafeTargetError(f"{host!r} did not resolve to any address.")
    return addresses


def resolve_and_validate(
    target: str,
    *,
    allow_private: bool | None = None,
    require_scheme: bool = False,
) -> TargetInfo:
    """Validate a destination the platform itself will connect to (SSRF guard).

    Raises :class:`UnsafeTargetError` for metadata endpoints, denied networks
    and — when ``allow_private`` is false — any private, loopback or
    link-local address.
    """
    settings = get_settings()
    if allow_private is None:
        allow_private = settings.allow_private_network_targets

    info = parse_target(target, default_scheme=None if require_scheme else "https")
    if require_scheme and not info.scheme:
        raise UnsafeTargetError("A full URL including scheme is required here.")

    if info.host in METADATA_ENDPOINTS:
        raise UnsafeTargetError("Cloud instance metadata endpoints are permanently blocked.")

    addresses = resolve_host(info.host)
    info.resolved_ips = addresses
    deny_networks = settings.deny_networks

    for raw_ip in addresses:
        if raw_ip in METADATA_ENDPOINTS:
            raise UnsafeTargetError("Cloud instance metadata endpoints are permanently blocked.")
        addr = ipaddress.ip_address(raw_ip)
        for network in deny_networks:
            if addr.version == network.version and addr in network:
                raise UnsafeTargetError(f"{raw_ip} falls inside the denied network {network}.")
        flags = classify_ip(raw_ip)
        if flags["link_local"] or flags["multicast"] or flags["unspecified"]:
            raise UnsafeTargetError(
                f"{raw_ip} is a link-local, multicast or unspecified address and is blocked."
            )
        if not allow_private and (flags["private"] or flags["loopback"] or flags["reserved"]):
            raise UnsafeTargetError(
                f"{raw_ip} is a private or reserved address; this deployment only permits "
                "internet-routable targets."
            )
    return info


# --------------------------------------------------------------- scope matching
@dataclass(slots=True)
class ScopeDecision:
    """Outcome of a scope check, with the reason always recorded."""

    allowed: bool
    reason: str
    matched_rule: str | None = None
    authorization_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "matched_rule": self.matched_rule,
            "authorization_id": self.authorization_id,
        }


class ScopeMatcher:
    """Evaluates a target against an authorization's allow/deny rules.

    Rule syntax (all case-insensitive):

    ===========================  ==========================================
    ``example.com``              exact host
    ``*.example.com``            host glob (does **not** match the apex)
    ``10.0.0.0/8``               CIDR range
    ``https://app.example.com/`` URL prefix
    ``example.com:8443``         host with a specific port
    ``example.com:8000-8100``    host with a port range
    ===========================  ==========================================

    Deny rules always win. An empty allow list denies everything: scope is
    opt-in, never opt-out.
    """

    def __init__(
        self,
        allow: list[str] | None,
        deny: list[str] | None = None,
        *,
        authorization_id: str | None = None,
    ) -> None:
        self.allow = [r.strip().lower() for r in (allow or []) if r and r.strip()]
        self.deny = [r.strip().lower() for r in (deny or []) if r and r.strip()]
        self.authorization_id = authorization_id

    def check(self, target: str) -> ScopeDecision:
        try:
            info = parse_target(target, default_scheme="https")
        except UnsafeTargetError as exc:
            return ScopeDecision(False, f"Target could not be parsed: {exc.message}")

        for rule in self.deny:
            if self._matches(info, rule):
                return ScopeDecision(
                    False,
                    f"Target {info.host} is explicitly excluded from scope by rule {rule!r}.",
                    matched_rule=rule,
                    authorization_id=self.authorization_id,
                )

        if not self.allow:
            return ScopeDecision(
                False,
                "The authorization defines no in-scope targets, so nothing is permitted.",
                authorization_id=self.authorization_id,
            )

        for rule in self.allow:
            if self._matches(info, rule):
                return ScopeDecision(
                    True,
                    f"Target {info.host} is in scope via rule {rule!r}.",
                    matched_rule=rule,
                    authorization_id=self.authorization_id,
                )

        return ScopeDecision(
            False,
            f"Target {info.host} is not covered by any in-scope rule of this authorization.",
            authorization_id=self.authorization_id,
        )

    # -------------------------------------------------------------- internals
    def _matches(self, info: TargetInfo, rule: str) -> bool:
        if "://" in rule:
            return self._match_url_prefix(info, rule)
        if "/" in rule:
            return self._match_cidr(info, rule)
        host_rule, port_rule = self._split_port(rule)
        if port_rule is not None and not self._match_port(info, port_rule):
            return False
        return self._match_host(info.host, host_rule)

    @staticmethod
    def _split_port(rule: str) -> tuple[str, str | None]:
        if rule.startswith("["):
            closing = rule.find("]")
            if closing != -1:
                remainder = rule[closing + 1 :]
                host = rule[1:closing]
                if remainder.startswith(":"):
                    return host, remainder[1:]
                return host, None
        if rule.count(":") == 1:
            host, _, port = rule.partition(":")
            if _PORT_RANGE_RE.match(port):
                return host, port
        return rule, None

    @staticmethod
    def _match_port(info: TargetInfo, port_rule: str) -> bool:
        match = _PORT_RANGE_RE.match(port_rule)
        if not match:
            return False
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else low
        effective = info.port
        if effective is None:
            effective = 443 if (info.scheme or "https") == "https" else 80
        return low <= effective <= high

    @staticmethod
    def _match_host(host: str, rule: str) -> bool:
        if rule == host:
            return True
        if rule.startswith("*."):
            # `*.example.com` covers sub-domains only. Including the apex here
            # would silently widen an engagement's agreed scope.
            suffix = rule[1:]  # ".example.com"
            return host.endswith(suffix) and host != suffix.lstrip(".")
        if "*" in rule or "?" in rule:
            return fnmatch.fnmatch(host, rule)
        return False

    @staticmethod
    def _match_cidr(info: TargetInfo, rule: str) -> bool:
        try:
            network = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
        candidates = info.resolved_ips or ([info.host] if info.is_ip_literal else [])
        if not candidates:
            try:
                candidates = resolve_host(info.host)
            except UnsafeTargetError:
                return False
        for raw in candidates:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr.version == network.version and addr in network:
                return True
        return False

    @staticmethod
    def _match_url_prefix(info: TargetInfo, rule: str) -> bool:
        rule_info = urlparse(rule)
        if not rule_info.hostname:
            return False
        if normalize_host(rule_info.hostname) != info.host:
            return False
        if rule_info.scheme and info.scheme and rule_info.scheme.lower() != info.scheme:
            return False
        if rule_info.port and info.port and rule_info.port != info.port:
            return False
        rule_path = rule_info.path or "/"
        if rule_path in ("", "/"):
            return True
        return (info.path or "/").startswith(rule_path)


def authorization_is_current(
    status: str,
    valid_from: datetime | None,
    valid_until: datetime | None,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Check an authorization's lifecycle window.

    Returns ``(ok, reason)``. An expired authorization is treated exactly like a
    missing one — scope approval does not survive its end date.
    """
    now = now or datetime.now(UTC)
    if status != "active":
        return False, f"The authorization is {status.replace('_', ' ')}, not active."
    if valid_from and now < valid_from:
        return False, f"The authorization does not take effect until {valid_from.isoformat()}."
    if valid_until and now > valid_until:
        return False, f"The authorization expired on {valid_until.isoformat()}."
    return True, "The authorization is active and within its validity window."
