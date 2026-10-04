"""Network exposure assessment.

An **active** engine: it opens TCP connections to the target, so it runs only
when an approved authorization covers it. The SDK enforces that before
``analyze`` is reached, and this engine additionally asks the scope checker
about every ``host:port`` pair it is about to touch — an authorization may
cover a host for web testing while excluding its management ports, and the
narrower rule has to win.

What it establishes:

* **Which ports accept a connection.** A refused connection and a timed-out
  one mean different things — closed versus filtered — and the result keeps
  them apart instead of collapsing both into "not open".
* **What is listening.** A banner is read where the service offers one, and a
  minimal ``HEAD`` request identifies HTTP-bearing ports. Nothing is written,
  no credentials are offered, and no exploit is attempted.
* **What exposure means.** Reachability is reported against the catalogue's
  reasoning: a datastore or management plane reachable from the scan origin is
  a finding; a web port is an observation.

The scan is a connect scan, not a raw-socket SYN scan. That is deliberate: it
needs no elevated privileges, it completes the handshake so the result is
unambiguous, and it is indistinguishable from an ordinary client, which is
what makes it safe to point at production.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from dataclasses import dataclass, field
from typing import Any

from qguard_scanner.rules.service_catalog import (
    DEFAULT_PORT_FOR_SERVICE,
    PORT_PROFILES,
    TLS_PORTS,
    BannerIdentification,
    ServiceDefinition,
    identify_banner,
    lookup_port,
    probe_for,
    service_for_product,
)
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import Evidence, NetworkLocation, ScanFinding
from qguard_scanner.sdk.http import RateLimiter
from qguard_scanner.sdk.netguard import UnsafeTargetError, parse_target, resolve_host
from qguard_scanner.sdk.registry import register_engine

#: Hard ceiling on how many ports one run may probe, whatever the request asks
#: for. A scan large enough to look like a denial of service is refused rather
#: than silently truncated.
MAX_PORTS = 1024

#: Maximum bytes read from a banner. Enough to identify a service; small
#: enough that a chatty or hostile endpoint cannot exhaust memory.
BANNER_BYTES = 2048

#: Seconds to wait for a service to greet the client unprompted. A service
#: that greets does so immediately, so a long wait only delays the scan — and
#: loses services that close an idle connection before the probe is sent.
PASSIVE_BANNER_TIMEOUT = 1.5

#: Seconds to wait for an answer after a probe is sent.
BANNER_TIMEOUT = 3.0


def _one_line(text: str, limit: int) -> str:
    """Collapse a banner to a single line for an evidence summary.

    A multi-line HTTP response header block is useful evidence and unreadable
    as a one-line summary, so the summary carries a collapsed excerpt while
    the full banner stays in the finding's artifacts.
    """
    if not text:
        return ""
    collapsed = " ".join(text.split())
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")


@dataclass(slots=True)
class PortState:
    """The outcome of one port probe."""

    port: int
    #: ``open`` | ``closed`` | ``filtered`` | ``error`` | ``out_of_scope``
    state: str
    detail: str = ""
    banner: str = ""
    #: The service the port conventionally carries, from the port number alone.
    port_service: ServiceDefinition | None = None
    #: The service identified from the banner. This is an observation rather
    #: than a convention, so where the two disagree this one is authoritative.
    banner_service: ServiceDefinition | None = None
    identification: BannerIdentification | None = None
    tls_expected: bool = False
    probe_sent: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def service(self) -> ServiceDefinition | None:
        """The service to assess this port as.

        Banner evidence wins over the port number: an SSH server on 2222 is
        SSH, and reporting it as an unknown listener would lose the finding
        that matters while adding one that does not.
        """
        return self.banner_service or self.port_service

    @property
    def on_unconventional_port(self) -> bool:
        """Whether the identified service is listening somewhere unexpected."""
        service = self.service
        if service is None:
            return False
        expected = DEFAULT_PORT_FOR_SERVICE.get(service.name)
        return expected is not None and expected != self.port

    def as_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "detail": self.detail,
            "service": self.service.name if self.service else None,
            "service_source": (
                "banner"
                if self.banner_service is not None
                else "port"
                if self.port_service is not None
                else None
            ),
            "product": self.identification.product if self.identification else None,
            "version": self.identification.version if self.identification else None,
            "probe_sent": self.probe_sent,
        }


@dataclass(slots=True)
class _Issue:
    """An internal finding, converted to a :class:`ScanFinding` at the end."""

    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    port: int
    summary: str
    impact: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    discriminator: str | None = None
    matched_value: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)


@register_engine
class NetworkEngine(SecurityEngine):
    """TCP connect scan with service identification and exposure assessment."""

    metadata = EngineMetadata(
        key="network",
        name="Network exposure",
        description=(
            "Establishes which TCP ports a host accepts connections on, identifies "
            "the listening services, and assesses what their reachability means."
        ),
        version="1.0.0",
        target_kinds=("host", "ip_address", "url", "server", "network_device"),
        capabilities=frozenset({EngineCapability.NETWORK}),
        categories=(
            "network_exposure",
            "security_misconfiguration",
            "insecure_communication",
            "information_disclosure",
        ),
    )

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        try:
            info = parse_target(ctx.target.value)
        except UnsafeTargetError as exc:
            return EngineResult.failed(self.key, f"The target could not be parsed: {exc}")

        host = info.host
        ports, port_warning = self._resolve_ports(ctx, info.port)
        if not ports:
            return EngineResult.failed(
                self.key,
                "No ports were selected for the scan, so nothing could be assessed. "
                "Supply a `ports` list or a `port_profile` the engine recognises.",
            )

        # Resolution happens once, up front: a host that does not resolve is a
        # failed scan with a stated reason, not an empty clean result.
        try:
            addresses = await asyncio.to_thread(resolve_host, host)
        except UnsafeTargetError as exc:
            return EngineResult.failed(
                self.key, f"{host} could not be resolved, so no port could be probed: {exc}"
            )

        await ctx.report_progress(5, f"probing {len(ports)} ports on {host}")

        # Per-port scope checks: an authorization may cover a host for web
        # testing while excluding its management ports.
        in_scope: list[int] = []
        out_of_scope: list[PortState] = []
        for port in ports:
            verdict = ctx.check_scope(f"{host}:{port}")
            if verdict.allowed:
                in_scope.append(port)
            else:
                out_of_scope.append(
                    PortState(port=port, state="out_of_scope", detail=verdict.reason)
                )

        if not in_scope:
            return EngineResult.failed(
                self.key,
                (
                    f"Every one of the {len(ports)} requested ports on {host} falls outside "
                    "the authorization covering this target, so no port was probed. "
                    f"The authorization refused the first one because: "
                    f"{out_of_scope[0].detail}"
                ),
                stats={"ports_requested": len(ports), "ports_out_of_scope": len(out_of_scope)},
            )

        limiter = RateLimiter(ctx.max_requests_per_second)
        semaphore = asyncio.Semaphore(max(1, min(ctx.max_concurrency, 64)))
        connect_timeout = min(ctx.http_timeout_seconds, 10.0)

        async def probe(port: int) -> PortState:
            async with semaphore:
                ctx.raise_if_cancelled()
                await limiter.acquire()
                return await self._probe_port(host, port, connect_timeout)

        results = await asyncio.gather(*(probe(p) for p in in_scope), return_exceptions=True)

        states: list[PortState] = list(out_of_scope)
        probe_errors: list[str] = []
        for port, outcome in zip(in_scope, results, strict=True):
            if isinstance(outcome, BaseException):
                if isinstance(outcome, asyncio.CancelledError):
                    raise outcome
                probe_errors.append(f"port {port}: {type(outcome).__name__}: {outcome}")
                states.append(
                    PortState(port=port, state="error", detail=f"{type(outcome).__name__}")
                )
            else:
                states.append(outcome)

        states.sort(key=lambda s: s.port)
        open_ports = [s for s in states if s.is_open]
        filtered = [s for s in states if s.state == "filtered"]
        closed = [s for s in states if s.state == "closed"]

        await ctx.report_progress(
            75, f"{len(open_ports)} of {len(in_scope)} probed ports accepted a connection"
        )

        issues: list[_Issue] = []
        for state in open_ports:
            issues.extend(self._assess_port(state, host))
        issues.extend(self._assess_posture(open_ports, host))

        findings = [self._to_finding(issue, host, ctx) for issue in issues]

        stats: dict[str, Any] = {
            "host": host,
            "resolved_addresses": addresses,
            "ports_requested": len(ports),
            "ports_probed": len(in_scope),
            "ports_out_of_scope": [s.port for s in out_of_scope],
            "open_ports": [s.port for s in open_ports],
            "filtered_ports": [s.port for s in filtered],
            "closed_port_count": len(closed),
            "port_states": [s.as_dict() for s in states],
            "scan_method": "tcp_connect",
        }

        warnings = list(probe_errors)
        if port_warning:
            warnings.append(port_warning)

        # Honest reporting of partial coverage. Each of these means the port
        # list was not fully assessed, so an empty finding set would be a
        # misleading "nothing here".
        degraded_reasons: list[str] = []
        if out_of_scope:
            degraded_reasons.append(
                f"{len(out_of_scope)} of {len(ports)} requested ports were not probed "
                "because the authorization covering this target excludes them"
            )
        if probe_errors:
            degraded_reasons.append(
                f"{len(probe_errors)} ports could not be probed because the connection "
                f"attempt itself errored ({probe_errors[0]})"
            )
        if filtered and not open_ports:
            degraded_reasons.append(
                f"all {len(filtered)} probed ports timed out without a response, which "
                "means they are filtered by a firewall rather than confirmed closed — "
                "the host's actual exposure could not be established from this origin"
            )
        elif len(filtered) > len(in_scope) // 2:
            degraded_reasons.append(
                f"{len(filtered)} of {len(in_scope)} ports timed out rather than being "
                "refused, so their true state is unknown"
            )

        common = {
            "stats": stats,
            "items_examined": len(in_scope),
            "checks_executed": len(in_scope),
            "requests_sent": len(in_scope),
            "warnings": warnings,
        }
        if degraded_reasons:
            return EngineResult.degraded(
                self.key, findings, reason="; ".join(degraded_reasons), **common
            )
        return EngineResult.completed(self.key, findings, **common)

    # ------------------------------------------------------------ port set
    @staticmethod
    def _resolve_ports(ctx: EngineContext, target_port: int | None) -> tuple[list[int], str | None]:
        """Decide which ports to probe, and say so when the request was trimmed."""
        warning: str | None = None
        raw = ctx.option("ports")
        ports: list[int] = []

        if raw:
            for item in raw:
                with contextlib.suppress(TypeError, ValueError):
                    value = int(item)
                    if 1 <= value <= 65535:
                        ports.append(value)
        else:
            profile = str(ctx.option("port_profile", "quick"))
            if profile not in PORT_PROFILES:
                warning = (
                    f"Port profile {profile!r} is not recognised, so the 'quick' profile "
                    f"was used instead. Available profiles: {', '.join(sorted(PORT_PROFILES))}."
                )
                profile = "quick"
            ports = list(PORT_PROFILES[profile])

        # A target given as host:port or a URL always includes that port.
        if target_port is not None and target_port not in ports:
            ports.append(target_port)

        unique = sorted(set(ports))
        if len(unique) > MAX_PORTS:
            warning = (
                f"{len(unique)} ports were requested, which exceeds this engine's ceiling "
                f"of {MAX_PORTS}; the first {MAX_PORTS} were probed and the rest were not "
                "assessed."
            )
            unique = unique[:MAX_PORTS]
        return unique, warning

    # -------------------------------------------------------------- probing
    async def _probe_port(self, host: str, port: int, connect_timeout: float) -> PortState:
        """Open a TCP connection and, if it succeeds, identify the service."""
        port_service = lookup_port(port)
        tls_expected = port in TLS_PORTS
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=connect_timeout
            )
        except TimeoutError:
            return PortState(
                port=port,
                state="filtered",
                detail=(
                    f"no response within {connect_timeout:.0f}s — the port is filtered by "
                    "a firewall, not confirmed closed"
                ),
                port_service=port_service,
                tls_expected=tls_expected,
            )
        except ConnectionRefusedError:
            return PortState(
                port=port,
                state="closed",
                detail="the host actively refused the connection",
                port_service=port_service,
                tls_expected=tls_expected,
            )
        except (OSError, socket.gaierror) as exc:
            return PortState(
                port=port,
                state="error",
                detail=f"{type(exc).__name__}: {exc}",
                port_service=port_service,
                tls_expected=tls_expected,
            )

        banner = ""
        probe_sent: str | None = None
        try:
            banner, probe_sent = await self._read_banner(
                reader, writer, port, port_service, tls_expected
            )
        except Exception as exc:
            # A banner read failure is not a scan failure: the connect test
            # already succeeded, which is the result that matters.
            banner = ""
            detail = f"connection accepted; the banner read failed ({type(exc).__name__})"
        else:
            detail = "connection accepted"
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        identification = identify_banner(banner) if banner else BannerIdentification()
        return PortState(
            port=port,
            state="open",
            detail=detail,
            banner=banner,
            port_service=port_service,
            banner_service=service_for_product(identification.product),
            identification=identification,
            tls_expected=tls_expected,
            probe_sent=probe_sent,
        )

    @staticmethod
    async def _read_banner(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        port: int,
        service: ServiceDefinition | None,
        tls_expected: bool,
    ) -> tuple[str, str | None]:
        """Read whatever the service will say about itself.

        A passive read comes first: many services greet the client, and
        listening costs nothing. Only when the socket stays silent is a probe
        sent, and every probe is read-only — a status or version query, or an
        HTTP ``HEAD``, which retrieves headers without a body. Nothing
        authenticates, writes or changes state, which is what makes this safe
        to point at production.

        Returns the banner and, when one was sent, a description of the probe,
        so the finding's evidence records exactly what produced the response.
        """
        if tls_expected:
            # A cleartext read on a TLS port returns handshake bytes, which say
            # nothing useful. The certificate engine is the tool for that port.
            return "", None

        try:
            passive = await asyncio.wait_for(
                reader.read(BANNER_BYTES), timeout=PASSIVE_BANNER_TIMEOUT
            )
        except TimeoutError:
            passive = b""
        if passive:
            return passive.decode("utf-8", errors="replace").strip(), None

        probe = probe_for(service, port)
        writer.write(probe)
        await writer.drain()
        description = probe.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        try:
            answered = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout=BANNER_TIMEOUT)
        except TimeoutError:
            return "", description
        return answered.decode("utf-8", errors="replace").strip(), description

    # ------------------------------------------------------------ assessment
    def _assess_port(self, state: PortState, host: str) -> list[_Issue]:
        """Everything that follows from one open port."""
        issues: list[_Issue] = []
        service = state.service
        identification = state.identification or BannerIdentification()
        descriptor = identification.descriptor
        banner_excerpt = _one_line(state.banner, 300)

        if service is not None:
            issues.append(
                _Issue(
                    rule_id=f"NET-EXPOSED-{service.name.upper().replace('-', '_')}",
                    category=self._category_for(service),
                    title=f"{service.label} reachable on {host}:{state.port}",
                    description=(
                        f"{host}:{state.port} accepted a TCP connection, so "
                        f"{service.label} is reachable from where this scan ran. "
                        f"{service.rationale}"
                        + (
                            f" The service identified itself as {descriptor}."
                            if identification.product
                            else ""
                        )
                        + (
                            f" It is listening on port {state.port} rather than the "
                            f"conventional {DEFAULT_PORT_FOR_SERVICE.get(service.name)}; "
                            "the identification comes from the service's own banner, not "
                            "from the port number, so the port being non-standard neither "
                            "weakens the finding nor hides the service."
                            if state.on_unconventional_port
                            else ""
                        )
                    ),
                    severity=service.exposure_severity,
                    # Reachability is directly observed; what it means for this
                    # deployment depends on where the scan origin sits, so a
                    # catalogued service is high rather than confirmed.
                    confidence="high" if identification.product else "medium",
                    port=state.port,
                    summary=(
                        f"TCP connect to {host}:{state.port} succeeded"
                        + (f"; banner: {banner_excerpt}" if banner_excerpt else "")
                    ),
                    impact=service.rationale,
                    remediation=service.remediation,
                    cwe=service.cwe,
                    discriminator=f"port:{state.port}",
                    matched_value=banner_excerpt or None,
                    artifacts={
                        "port": state.port,
                        "service": service.name,
                        "category": service.category,
                        "is_cleartext": service.is_cleartext,
                        "is_administrative": service.is_administrative,
                        "is_datastore": service.is_datastore,
                        "secure_alternative": service.secure_alternative,
                        "product": identification.product,
                        "version": identification.version,
                        "identified_from": (
                            "banner" if state.banner_service is not None else "port number"
                        ),
                        "banner": state.banner[:2000],
                        "conventional_port": DEFAULT_PORT_FOR_SERVICE.get(service.name),
                        "probe_sent": state.probe_sent,
                    },
                    mitre=["T1046"],
                )
            )
        else:
            issues.append(
                _Issue(
                    rule_id="NET-UNIDENTIFIED-SERVICE",
                    category="network_exposure",
                    title=f"Unidentified service reachable on {host}:{state.port}",
                    description=(
                        f"{host}:{state.port} accepted a TCP connection, but the port has "
                        "no catalogued service and the response did not identify the "
                        "software. An open port whose purpose is not known cannot be "
                        "assessed or attested to, which is itself the finding: confirm "
                        "what process is listening and whether it is meant to be reachable."
                        + (
                            f" The service responded with: {banner_excerpt}"
                            if banner_excerpt
                            else " The service sent nothing when connected to."
                        )
                    ),
                    severity="low",
                    confidence="high",
                    port=state.port,
                    summary=(
                        f"TCP connect to {host}:{state.port} succeeded"
                        + (f"; response: {banner_excerpt}" if banner_excerpt else "; no banner")
                    ),
                    impact=(
                        "An unknown listening service is unassessed attack surface. It may "
                        "be a forgotten development tool, an unmanaged agent, or an "
                        "attacker's implant."
                    ),
                    remediation=(
                        "Identify the owning process on the host and either document the "
                        "service so it can be assessed, or close the port."
                    ),
                    cwe="CWE-1327",
                    discriminator=f"port:{state.port}",
                    matched_value=banner_excerpt or None,
                    artifacts={
                        "port": state.port,
                        "banner_present": bool(state.banner),
                        "probe_sent": state.probe_sent,
                    },
                    mitre=["T1046"],
                )
            )

        # A precise version in a banner tells an attacker which exploits apply
        # without them having to probe for it.
        if identification.discloses_version:
            issues.append(
                _Issue(
                    rule_id="NET-VERSION-DISCLOSURE",
                    category="information_disclosure",
                    title=f"Service version disclosed on {host}:{state.port}",
                    description=(
                        f"The service on {host}:{state.port} advertises itself as "
                        f"{descriptor} before any authentication. A precise version lets "
                        "an attacker select known exploits for that exact build instead of "
                        "probing, which shortens reconnaissance and leaves less in the logs."
                    ),
                    severity="low",
                    confidence="high",
                    port=state.port,
                    summary=f"banner: {banner_excerpt}",
                    impact=(
                        "Version disclosure is not exploitable on its own; it makes every "
                        "other weakness on the host cheaper to find and exploit."
                    ),
                    remediation=(
                        "Suppress the version in the service banner where the software "
                        "supports it, and keep the build patched — suppression hides the "
                        "version, it does not fix the vulnerabilities."
                    ),
                    cwe="CWE-200",
                    discriminator=f"port:{state.port}:version",
                    matched_value=descriptor,
                    artifacts={
                        "port": state.port,
                        "product": identification.product,
                        "version": identification.version,
                    },
                    mitre=["T1592"],
                )
            )

        # The service answered a command with no credentials offered. This is
        # observed behaviour, not an inference from the port number.
        for reason in identification.unauthenticated_reasons:
            issues.append(
                _Issue(
                    rule_id="NET-UNAUTHENTICATED-SERVICE",
                    category="broken_authentication",
                    title=(f"{descriptor} on {host}:{state.port} answered without authentication"),
                    description=(
                        f"A read-only command was sent to {host}:{state.port} with no "
                        f"credentials and the service answered. {reason} Anything reachable "
                        "on this port has the service's full authority."
                    ),
                    severity="critical",
                    confidence="confirmed",
                    port=state.port,
                    summary=f"unauthenticated response: {banner_excerpt}",
                    impact=(
                        "An unauthenticated datastore or management service grants read, "
                        "and usually write, to everything it holds. Where the service can "
                        "write files, this commonly extends to code execution on the host."
                    ),
                    remediation=(
                        "Enable authentication on the service, then restrict it to the "
                        "private network. Both are needed: network restriction alone fails "
                        "the moment anything inside the network is compromised."
                    ),
                    cwe="CWE-306",
                    discriminator=f"port:{state.port}:unauthenticated",
                    matched_value=banner_excerpt or None,
                    artifacts={"port": state.port, "evidence": reason},
                    mitre=["T1078"],
                )
            )

        if identification.note and not identification.unauthenticated_reasons:
            issues.append(
                _Issue(
                    rule_id="NET-SERVICE-NOTE",
                    category="security_misconfiguration",
                    title=f"{descriptor} on {host}:{state.port} warrants review",
                    description=f"{identification.note}",
                    severity="medium",
                    confidence="medium",
                    port=state.port,
                    summary=f"banner: {banner_excerpt}",
                    remediation=(
                        "Confirm the service is the intended one for this port and is "
                        "configured for production."
                    ),
                    discriminator=f"port:{state.port}:note",
                    artifacts={"port": state.port, "product": identification.product},
                )
            )

        return issues

    def _assess_posture(self, open_ports: list[PortState], host: str) -> list[_Issue]:
        """Findings that only appear when the open ports are considered together."""
        issues: list[_Issue] = []
        if not open_ports:
            return issues

        cleartext = [s for s in open_ports if s.service is not None and s.service.is_cleartext]
        if len(cleartext) > 1:
            names = ", ".join(f"{s.service.label} ({s.port})" for s in cleartext if s.service)
            issues.append(
                _Issue(
                    rule_id="NET-CLEARTEXT-CLUSTER",
                    category="insecure_communication",
                    title=f"{len(cleartext)} cleartext protocols reachable on {host}",
                    description=(
                        f"{host} accepts connections on {len(cleartext)} ports whose "
                        f"protocols carry credentials or data without transport "
                        f"encryption: {names}. Individually each is a finding; together "
                        "they indicate the host predates, or was never brought into, the "
                        "organisation's transport-encryption baseline."
                    ),
                    severity="high",
                    confidence="high",
                    port=cleartext[0].port,
                    summary=f"cleartext services open: {names}",
                    impact=(
                        "Any observer on the network path recovers credentials for each of "
                        "these services. Credentials reused elsewhere extend the "
                        "compromise beyond this host."
                    ),
                    remediation=(
                        "Migrate each service to its encrypted equivalent and close the "
                        "cleartext port. Treat the host as a candidate for rebuild rather "
                        "than fixing the protocols one at a time."
                    ),
                    cwe="CWE-319",
                    discriminator="posture:cleartext",
                    artifacts={
                        "ports": [s.port for s in cleartext],
                        "services": [s.service.name for s in cleartext if s.service],
                    },
                    mitre=["T1040"],
                )
            )

        datastores = [s for s in open_ports if s.service is not None and s.service.is_datastore]
        administrative = [
            s for s in open_ports if s.service is not None and s.service.is_administrative
        ]
        if datastores and administrative:
            issues.append(
                _Issue(
                    rule_id="NET-FLAT-EXPOSURE",
                    category="security_misconfiguration",
                    title=f"Datastore and management ports both reachable on {host}",
                    description=(
                        f"{host} exposes both data-tier ports "
                        f"({', '.join(str(s.port) for s in datastores)}) and management "
                        f"ports ({', '.join(str(s.port) for s in administrative)}) to the "
                        "same origin. Network segmentation exists so that reaching the "
                        "application tier does not also mean reaching the data and the "
                        "management plane; here, one position reaches all three."
                    ),
                    severity="high",
                    confidence="high",
                    port=datastores[0].port,
                    summary=(
                        f"datastore ports {[s.port for s in datastores]} and management "
                        f"ports {[s.port for s in administrative]} are both reachable"
                    ),
                    impact=(
                        "An attacker who gains any foothold with this network position "
                        "moves directly to the data and to host control, with no further "
                        "boundary to cross."
                    ),
                    remediation=(
                        "Separate the tiers: restrict data-tier ports to the application "
                        "tier's addresses and management ports to a bastion or management "
                        "network."
                    ),
                    cwe="CWE-668",
                    discriminator="posture:segmentation",
                    artifacts={
                        "datastore_ports": [s.port for s in datastores],
                        "management_ports": [s.port for s in administrative],
                    },
                    mitre=["T1210"],
                )
            )

        return issues

    @staticmethod
    def _category_for(service: ServiceDefinition) -> str:
        if service.is_cleartext:
            return "insecure_communication"
        if service.is_datastore or service.is_administrative:
            return "network_exposure"
        if service.category == "suspicious":
            return "network_exposure"
        return "network_exposure"

    # -------------------------------------------------------------- mapping
    @staticmethod
    def _to_finding(issue: _Issue, host: str, ctx: EngineContext) -> ScanFinding:
        return ScanFinding(
            engine="network",
            rule_id=issue.rule_id,
            category=issue.category,
            title=issue.title,
            description=issue.description,
            severity=issue.severity,
            confidence=issue.confidence,
            evidence=Evidence(
                summary=issue.summary,
                matched_value=issue.matched_value,
                artifacts=issue.artifacts,
            ),
            impact=issue.impact,
            remediation=issue.remediation,
            references=issue.references,
            network_location=NetworkLocation(host=host, port=issue.port, protocol="tcp"),
            target=ctx.target,
            cwe=issue.cwe,
            mitre_techniques=issue.mitre,
            correlation_discriminator=issue.discriminator,
        )
