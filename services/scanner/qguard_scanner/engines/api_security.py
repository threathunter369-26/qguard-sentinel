"""API security assessment.

An **active** engine: it sends requests to the API, so it runs only when an
approved authorization covers the target. That gating applies to the whole
engine, including the specification review, because the two halves are one
assessment — a specification claim is only worth acting on once it has been
checked against the running service, and the checking is what needs
permission.

The engine works from an OpenAPI 3.x or Swagger 2.0 specification, supplied
as a local file (``spec_path``), fetched from a URL (``spec_url``), passed
inline (``spec_inline``), or discovered at the conventional well-known paths.
A specification is what makes API testing tractable: without it a scanner is
guessing at routes, and guessed routes produce guessed findings.

Two kinds of finding come out, and they are never conflated:

* **Specification findings** — what the document itself declares. An endpoint
  the specification marks as needing no authentication is a documented design
  decision, reported with the evidence being the document.
* **Verified findings** — what the API actually did. An endpoint the
  specification says requires a credential, which returned ``200`` to a
  request carrying none, is a confirmed authentication bypass.

Only safe methods are ever sent. ``GET``, ``HEAD`` and ``OPTIONS`` are
retrieval operations; ``POST``, ``PUT``, ``PATCH`` and ``DELETE`` are never
issued, so the engine cannot create, modify or destroy data in the system it
is assessing. Rate-limit probing sends a burst and is therefore gated on an
authorization that permits intrusive testing.

Object-level authorization (BOLA) cannot be confirmed without two accounts'
credentials, which this engine is not given. Rather than guess, endpoints
keyed by an object identifier are reported as requiring manual verification,
with the reason stated — they are exactly the endpoints a pentest engagement
should target.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qguard_scanner.engines.openapi_spec import (
    ApiSpecification,
    Endpoint,
    SpecParseError,
    load_document,
    parse_specification,
)
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import Evidence, NetworkLocation, ScanFinding
from qguard_scanner.sdk.http import AssessmentHttpClient, ProbeResult
from qguard_scanner.sdk.registry import register_engine

#: Conventional locations an API specification is published at. Checked only
#: when no specification was supplied.
WELL_KNOWN_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
    "/v2/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api-docs",
    "/docs/openapi.json",
    "/.well-known/openapi.json",
)

#: Largest specification the engine will parse. A document beyond this size is
#: refused rather than risking memory exhaustion on untrusted input.
MAX_SPEC_BYTES = 8 * 1024 * 1024

#: Default ceiling on how many endpoints receive live traffic. Keeps an
#: assessment of a 2,000-endpoint API from becoming a load test.
DEFAULT_MAX_PROBES = 60

#: Markers of a framework error page in a response body. Matching one means
#: an unauthenticated request reached code that failed and returned internals.
ERROR_DISCLOSURE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"Traceback \(most recent call last\)"), "a Python traceback"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "a Java stack trace"),
    (re.compile(r"\bin /[\w/.-]+\.php on line \d+", re.IGNORECASE), "a PHP error with a file path"),
    (re.compile(r"\bat [\w.]+ \([^)]*:\d+:\d+\)"), "a JavaScript stack trace"),
    (re.compile(r"\bgoroutine \d+ \[running\]"), "a Go panic trace"),
    (
        re.compile(r"(?:SQLSTATE|SQLException|psycopg2\.|sqlalchemy\.exc\.)", re.IGNORECASE),
        "a database driver error",
    ),
    (re.compile(r"\bDEBUG\s*=\s*True\b"), "a debug-mode indicator"),
)


@dataclass(slots=True)
class _Issue:
    """An internal finding, converted to a :class:`ScanFinding` at the end."""

    rule_id: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    summary: str
    path: str | None = None
    method: str | None = None
    url: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    owasp_asvs: list[str] = field(default_factory=list)
    discriminator: str | None = None
    matched_value: str | None = None
    request: str | None = None
    response: str | None = None
    response_status: int | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    is_exploitable: bool = False
    exploitability_note: str | None = None
    mitre: list[str] = field(default_factory=list)


@register_engine
class ApiSecurityEngine(SecurityEngine):
    """OpenAPI-driven API security assessment."""

    metadata = EngineMetadata(
        key="api",
        name="API security",
        description=(
            "Reviews an OpenAPI or Swagger specification and verifies its security "
            "claims against the running API using safe, non-mutating requests."
        ),
        version="1.0.0",
        target_kinds=("api", "url", "web_application", "host"),
        capabilities=frozenset({EngineCapability.NETWORK}),
        categories=(
            "api_security",
            "broken_authentication",
            "broken_access_control",
            "security_misconfiguration",
            "sensitive_data_exposure",
            "information_disclosure",
        ),
    )

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        base_url = self._base_url(ctx.target.value)
        static_only = bool(ctx.option("static_only", False))
        degraded_reasons: list[str] = []
        warnings: list[str] = []

        async with AssessmentHttpClient(
            user_agent=ctx.user_agent,
            timeout_seconds=ctx.http_timeout_seconds,
            max_requests_per_second=ctx.max_requests_per_second,
            max_concurrency=ctx.max_concurrency,
        ) as client:
            spec, spec_source, discovery = await self._load_specification(ctx, client, base_url)
            if spec is None:
                return EngineResult.failed(
                    self.key,
                    (
                        "No API specification could be read, so no endpoint could be "
                        f"assessed. {spec_source}"
                    ),
                    stats={"spec_discovery": discovery},
                    requests_sent=client.stats.requests_sent,
                )

            await ctx.report_progress(
                25, f"reviewing {len(spec.endpoints)} endpoints from {spec.title}"
            )

            issues = self._review_specification(spec, base_url)
            if discovery.get("exposed_at"):
                issues.append(self._spec_exposure_issue(spec, discovery))

            if spec.warnings:
                degraded_reasons.append(
                    "the specification was only partly readable: " + "; ".join(spec.warnings[:3])
                )

            probe_stats: dict[str, Any] = {"probed": 0, "skipped": 0, "reason": None}
            effective_base = spec.base_url(base_url)

            if static_only:
                degraded_reasons.append(
                    "static_only was requested, so no request was sent and the "
                    "specification's security claims were not verified against the "
                    "running API"
                )
            elif effective_base is None:
                degraded_reasons.append(
                    "the specification declares no absolute server URL and the target is "
                    "not a URL, so no endpoint could be reached and the specification's "
                    "security claims were not verified"
                )
            elif "{" in effective_base:
                degraded_reasons.append(
                    f"the server URL {effective_base!r} still contains an unresolved "
                    "template variable, so no endpoint could be reached and the "
                    "specification's security claims were not verified"
                )
            else:
                await ctx.report_progress(45, f"verifying authentication against {effective_base}")
                verified, probe_stats = await self._verify_endpoints(
                    ctx, client, spec, effective_base
                )
                issues.extend(verified)
                if probe_stats.get("errors"):
                    degraded_reasons.append(
                        f"{len(probe_stats['errors'])} endpoint probes failed to complete "
                        f"({probe_stats['errors'][0]}), so those endpoints were not verified"
                    )
                if probe_stats.get("truncated"):
                    degraded_reasons.append(
                        f"{probe_stats['skipped']} of {len(spec.endpoints)} endpoints were "
                        "not probed because the per-run probe ceiling was reached"
                    )

            stats: dict[str, Any] = {
                "specification": spec.stats(),
                "spec_source": spec_source,
                "spec_discovery": discovery,
                "probes": probe_stats,
                "http": client.stats.as_dict(),
                "base_url": effective_base,
                "static_only": static_only,
            }
            requests_sent = client.stats.requests_sent

        findings = [self._to_finding(issue, ctx) for issue in issues]
        common = {
            "stats": stats,
            "items_examined": len(spec.endpoints),
            "checks_executed": len(spec.endpoints),
            "requests_sent": requests_sent,
            "warnings": warnings,
        }
        if degraded_reasons:
            return EngineResult.degraded(
                self.key, findings, reason="; ".join(degraded_reasons), **common
            )
        return EngineResult.completed(self.key, findings, **common)

    # ------------------------------------------------------- specification
    @staticmethod
    def _base_url(target: str) -> str | None:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"
        return None

    async def _load_specification(
        self, ctx: EngineContext, client: AssessmentHttpClient, base_url: str | None
    ) -> tuple[ApiSpecification | None, str, dict[str, Any]]:
        """Obtain the specification, reporting precisely where it came from."""
        discovery: dict[str, Any] = {"attempted": [], "exposed_at": None}

        inline = ctx.option("spec_inline")
        if isinstance(inline, str) and inline.strip():
            return self._parse(inline, "supplied inline", discovery)

        spec_path = ctx.option("spec_path")
        if spec_path:
            path = Path(str(spec_path))
            if ctx.workdir is not None and not path.is_absolute():
                path = ctx.workdir / path
            if not path.is_file():
                return None, f"The specification file {path} does not exist.", discovery
            size = path.stat().st_size
            if size > MAX_SPEC_BYTES:
                return (
                    None,
                    (
                        f"The specification file {path} is {size} bytes, which exceeds the "
                        f"{MAX_SPEC_BYTES}-byte limit, so it was not parsed."
                    ),
                    discovery,
                )
            try:
                text = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
            except OSError as exc:
                return None, f"The specification file {path} could not be read: {exc}", discovery
            return self._parse(text, f"read from {path}", discovery)

        spec_url = ctx.option("spec_url")
        if spec_url:
            url = str(spec_url)
            verdict = ctx.check_scope(url)
            if not verdict.allowed:
                return (
                    None,
                    (
                        f"The specification URL {url} is not covered by the authorization "
                        f"for this target, so it was not fetched: {verdict.reason}"
                    ),
                    discovery,
                )
            response = await client.get(url)
            discovery["attempted"].append({"url": url, "status": response.status_code})
            if not response.ok:
                return None, f"Fetching {url} failed: {response.error}", discovery
            if response.status_code != 200:
                return (
                    None,
                    f"Fetching {url} returned HTTP {response.status_code}, not a specification.",
                    discovery,
                )
            return self._parse(response.body, f"fetched from {url}", discovery)

        if base_url is None:
            return (
                None,
                (
                    "No specification was supplied and the target is not a URL, so none "
                    "could be discovered. Supply spec_path, spec_url or spec_inline."
                ),
                discovery,
            )

        # Discovery is last, and its success is itself reportable: a
        # specification readable without credentials hands an attacker the
        # complete route map.
        for candidate in WELL_KNOWN_SPEC_PATHS:
            ctx.raise_if_cancelled()
            url = f"{base_url.rstrip('/')}{candidate}"
            if not ctx.check_scope(url).allowed:
                continue
            response = await client.get(url)
            discovery["attempted"].append({"url": url, "status": response.status_code})
            if response.status_code != 200 or not response.body:
                continue
            spec, source, discovery = self._parse(response.body, f"discovered at {url}", discovery)
            if spec is not None:
                discovery["exposed_at"] = url
                return spec, source, discovery

        return (
            None,
            (
                f"No specification was supplied, and none of the {len(WELL_KNOWN_SPEC_PATHS)} "
                "conventional locations returned one. Supply spec_path, spec_url or "
                "spec_inline to assess this API."
            ),
            discovery,
        )

    @staticmethod
    def _parse(
        text: str, source: str, discovery: dict[str, Any]
    ) -> tuple[ApiSpecification | None, str, dict[str, Any]]:
        if len(text.encode("utf-8", errors="ignore")) > MAX_SPEC_BYTES:
            return (
                None,
                f"The specification {source} exceeds the {MAX_SPEC_BYTES}-byte limit.",
                discovery,
            )
        try:
            document = load_document(text)
            spec = parse_specification(document, source=source)
        except SpecParseError as exc:
            return None, f"The specification {source} could not be parsed: {exc}", discovery
        return spec, source, discovery

    # ------------------------------------------------- specification review
    def _review_specification(
        self, spec: ApiSpecification, target_base: str | None
    ) -> list[_Issue]:
        issues: list[_Issue] = []
        issues.extend(self._review_security_schemes(spec))
        issues.extend(self._review_servers(spec, target_base))
        issues.extend(self._review_endpoints(spec))
        issues.extend(self._review_rate_limiting(spec))
        return issues

    def _review_security_schemes(self, spec: ApiSpecification) -> list[_Issue]:
        issues: list[_Issue] = []

        if not spec.security_schemes:
            issues.append(
                _Issue(
                    rule_id="API-NO-SECURITY-SCHEMES",
                    category="broken_authentication",
                    title=f"{spec.title} declares no authentication mechanism",
                    description=(
                        f"The specification for {spec.title} defines no security scheme at "
                        f"all, across {len(spec.endpoints)} endpoints. Either the API is "
                        "genuinely unauthenticated, or authentication exists but is "
                        "undocumented — and an undocumented control is one no client "
                        "implements correctly and no reviewer can verify."
                    ),
                    severity="high",
                    confidence="high",
                    summary=(
                        f"no securitySchemes/securityDefinitions in the specification "
                        f"({spec.spec_version})"
                    ),
                    impact=(
                        "If the API is genuinely unauthenticated, every endpoint is open to "
                        "anyone who can reach it. If it is not, the specification misleads "
                        "every consumer and reviewer of the API."
                    ),
                    remediation=(
                        "Declare the authentication scheme the API actually enforces, and "
                        "apply it with a document-level `security` requirement so new "
                        "endpoints inherit it by default."
                    ),
                    cwe="CWE-306",
                    owasp_asvs=["V4.1.1"],
                    discriminator="spec:no-security-schemes",
                    artifacts={"endpoint_count": len(spec.endpoints)},
                )
            )
        elif not spec.global_security:
            unauthenticated = [e for e in spec.endpoints if e.is_unauthenticated([])]
            issues.append(
                _Issue(
                    rule_id="API-NO-DEFAULT-SECURITY",
                    category="security_misconfiguration",
                    title=f"{spec.title} applies no default authentication requirement",
                    description=(
                        f"{spec.title} declares "
                        f"{len(spec.security_schemes)} security scheme(s) but no "
                        "document-level `security` requirement, so authentication is "
                        "opt-in per operation. "
                        f"{len(unauthenticated)} of {len(spec.endpoints)} operations "
                        "currently declare none. Opt-in authentication fails by omission: "
                        "the next endpoint added without a `security` block is public, and "
                        "nothing in the document flags it."
                    ),
                    severity="medium",
                    confidence="high",
                    summary=(
                        f"{len(unauthenticated)}/{len(spec.endpoints)} operations declare no "
                        "security requirement and the document sets no default"
                    ),
                    impact=(
                        "Authentication gaps appear silently as the API grows, because the "
                        "secure state requires an action and the insecure state requires none."
                    ),
                    remediation=(
                        "Set a document-level `security` requirement and override it with "
                        "`security: []` on the specific operations that are intentionally "
                        "public, so every exception is explicit and reviewable."
                    ),
                    cwe="CWE-1188",
                    owasp_asvs=["V4.1.1"],
                    discriminator="spec:no-default-security",
                    artifacts={
                        "schemes": sorted(spec.security_schemes),
                        "unauthenticated_operations": [e.identifier for e in unauthenticated[:50]],
                    },
                )
            )

        for name, scheme in spec.security_schemes.items():
            if scheme.carries_credential_in_url:
                issues.append(
                    _Issue(
                        rule_id="API-KEY-IN-QUERY-STRING",
                        category="sensitive_data_exposure",
                        title=f"Security scheme {name!r} carries its API key in the query string",
                        description=(
                            f"The {name!r} scheme passes its credential as the query "
                            f"parameter {scheme.parameter_name!r}. Query strings are "
                            "recorded in web server access logs, reverse proxy logs, CDN "
                            "logs, browser history and `Referer` headers sent to third "
                            "parties. A credential in a URL is a credential in every log "
                            "on the request path."
                        ),
                        severity="high",
                        confidence="high",
                        summary=f"apiKey in query: {scheme.parameter_name}",
                        impact=(
                            "The API key is disclosed to every system that logs URLs, "
                            "including ones outside the API owner's control. Log retention "
                            "then keeps the credential long after it would otherwise rotate."
                        ),
                        remediation=(
                            "Move the credential to a request header (`Authorization` or a "
                            "dedicated header), and rotate every key that has been sent in "
                            "a URL."
                        ),
                        cwe="CWE-598",
                        owasp_asvs=["V3.5.3"],
                        discriminator=f"spec:scheme:{name}:query",
                        matched_value=scheme.parameter_name,
                        artifacts={"scheme": name, "parameter": scheme.parameter_name},
                        mitre=["T1552"],
                    )
                )
            if scheme.is_basic:
                issues.append(
                    _Issue(
                        rule_id="API-BASIC-AUTHENTICATION",
                        category="broken_authentication",
                        title=f"Security scheme {name!r} uses HTTP Basic authentication",
                        description=(
                            f"The {name!r} scheme uses HTTP Basic authentication, which "
                            "sends the password — base64-encoded, not encrypted — on every "
                            "single request. The credential cannot be scoped, cannot carry "
                            "an expiry, and cannot be revoked short of changing the "
                            "password, so one captured request yields durable access."
                        ),
                        severity="medium",
                        confidence="high",
                        summary=f"securityScheme {name}: http basic",
                        impact=(
                            "Any disclosure of a single request — a log, a proxy, a crash "
                            "report — discloses the long-lived password itself rather than "
                            "a scoped, expiring token."
                        ),
                        remediation=(
                            "Replace Basic authentication with short-lived bearer tokens or "
                            "OAuth 2.0, so a captured credential expires and can be scoped "
                            "and revoked."
                        ),
                        cwe="CWE-522",
                        owasp_asvs=["V2.1.1"],
                        discriminator=f"spec:scheme:{name}:basic",
                        artifacts={"scheme": name},
                    )
                )

        return issues

    def _review_servers(self, spec: ApiSpecification, target_base: str | None) -> list[_Issue]:
        issues: list[_Issue] = []
        if not spec.servers:
            return issues

        cleartext = [s for s in spec.servers if s.lower().startswith("http://")]
        if cleartext:
            issues.append(
                _Issue(
                    rule_id="API-CLEARTEXT-SERVER",
                    category="insecure_communication",
                    title=f"{spec.title} publishes a plain-HTTP server URL",
                    description=(
                        "The specification lists "
                        + ", ".join(cleartext)
                        + " as a server, so clients generated from this document will send "
                        "credentials and data without transport encryption. A client that "
                        "follows the specification correctly is the one that gets "
                        "intercepted."
                    ),
                    severity="high",
                    confidence="high",
                    summary=f"http:// server URLs: {', '.join(cleartext)}",
                    impact=(
                        "Credentials and response data are readable and modifiable by any "
                        "observer on the network path."
                    ),
                    remediation=(
                        "Publish only `https://` server URLs and redirect HTTP to HTTPS at "
                        "the edge with HSTS set."
                    ),
                    cwe="CWE-319",
                    owasp_asvs=["V9.1.1"],
                    discriminator="spec:cleartext-server",
                    matched_value=cleartext[0],
                    artifacts={"servers": spec.servers},
                    mitre=["T1040"],
                )
            )

        unresolved = [s for s in spec.servers if "{" in s]
        if unresolved and not spec.base_url(target_base):
            issues.append(
                _Issue(
                    rule_id="API-UNRESOLVED-SERVER-TEMPLATE",
                    category="security_misconfiguration",
                    title=f"{spec.title} has no usable server URL",
                    description=(
                        "Every server URL in the specification contains a template variable "
                        "with no default value ("
                        + ", ".join(unresolved)
                        + "), so no concrete endpoint can be derived from the document. The "
                        "specification cannot be used to generate a working client, and it "
                        "cannot be used to verify the API's behaviour automatically."
                    ),
                    severity="low",
                    confidence="high",
                    summary=f"server URLs with unresolved variables: {', '.join(unresolved)}",
                    remediation=(
                        "Give each server variable a `default`, or list concrete server URLs "
                        "per environment."
                    ),
                    discriminator="spec:unresolved-server",
                    artifacts={"servers": spec.servers},
                )
            )
        return issues

    def _review_endpoints(self, spec: ApiSpecification) -> list[_Issue]:
        issues: list[_Issue] = []
        unauthenticated_reads: list[str] = []

        for endpoint in spec.endpoints:
            unauthenticated = endpoint.is_unauthenticated(spec.global_security)

            if unauthenticated and endpoint.is_mutating:
                issues.append(
                    _Issue(
                        rule_id="API-UNAUTHENTICATED-MUTATION",
                        category="broken_access_control",
                        title=f"{endpoint.identifier} changes state without authentication",
                        description=(
                            f"The specification declares {endpoint.identifier} as requiring "
                            "no credential, and the method changes state. Anyone who can "
                            "reach the API can invoke it. "
                            + (
                                "The operation accepts a request body, so the caller also "
                                "controls what is written."
                                if endpoint.request_body_properties
                                else ""
                            )
                        ),
                        severity="high",
                        confidence="high",
                        summary=(f"{endpoint.identifier}: effective security requirement is empty"),
                        path=endpoint.path,
                        method=endpoint.method.upper(),
                        impact=(
                            "Unauthenticated writes allow anyone to create, modify or delete "
                            "data. Where the endpoint drives a side effect — email, payment, "
                            "provisioning — it can be abused at the API owner's expense."
                        ),
                        remediation=(
                            "Apply a `security` requirement to this operation. If it is "
                            "genuinely public, document why, and rate-limit it."
                        ),
                        cwe="CWE-306",
                        owasp_asvs=["V4.1.1"],
                        discriminator=f"endpoint:{endpoint.identifier}:unauthenticated",
                        artifacts={
                            "operation_id": endpoint.operation_id,
                            "tags": endpoint.tags,
                            "body_properties": sorted(endpoint.request_body_properties),
                        },
                        mitre=["T1190"],
                    )
                )
            elif unauthenticated:
                unauthenticated_reads.append(endpoint.identifier)

            identifier_params = endpoint.identifier_path_parameters
            if identifier_params:
                issues.append(self._bola_issue(endpoint, identifier_params, unauthenticated))

            if endpoint.is_mutating and (privileged := endpoint.privileged_body_properties()):
                issues.append(self._mass_assignment_issue(endpoint, privileged))

            for parameter in endpoint.parameters:
                if parameter.location in ("query", "path") and parameter.is_sensitive_name:
                    issues.append(self._sensitive_parameter_issue(endpoint, parameter))

            if not unauthenticated and not any(
                code in endpoint.response_codes for code in ("401", "403")
            ):
                issues.append(
                    _Issue(
                        rule_id="API-NO-AUTH-FAILURE-RESPONSE",
                        category="api_security",
                        title=(
                            f"{endpoint.identifier} requires authentication but documents no "
                            "failure response"
                        ),
                        description=(
                            f"{endpoint.identifier} carries a security requirement yet "
                            "documents no 401 or 403 response. Clients generated from this "
                            "document will not handle an authentication failure, and a "
                            "reviewer cannot tell from the specification whether the "
                            "operation distinguishes 'not authenticated' from 'not "
                            "permitted' — a distinction that matters, because conflating "
                            "them hides authorization bugs."
                        ),
                        severity="low",
                        confidence="high",
                        summary=(
                            f"documented responses: {', '.join(endpoint.response_codes) or 'none'}"
                        ),
                        path=endpoint.path,
                        method=endpoint.method.upper(),
                        remediation=(
                            "Document 401 for a missing or invalid credential and 403 for a "
                            "valid credential without permission."
                        ),
                        cwe="CWE-1059",
                        discriminator=f"endpoint:{endpoint.identifier}:no-auth-response",
                        artifacts={"response_codes": endpoint.response_codes},
                    )
                )

            if endpoint.method == "trace":
                issues.append(
                    _Issue(
                        rule_id="API-TRACE-METHOD",
                        category="security_misconfiguration",
                        title=f"TRACE is exposed on {endpoint.path}",
                        description=(
                            f"The specification declares a TRACE operation on "
                            f"{endpoint.path}. TRACE echoes the request back, including "
                            "headers, which historically enabled Cross-Site Tracing to read "
                            "cookies marked HttpOnly. It serves no purpose in a production "
                            "API."
                        ),
                        severity="medium",
                        confidence="high",
                        summary=f"TRACE {endpoint.path} declared in the specification",
                        path=endpoint.path,
                        method="TRACE",
                        remediation=(
                            "Remove the TRACE operation and disable the method at the edge."
                        ),
                        cwe="CWE-16",
                        discriminator=f"endpoint:{endpoint.identifier}:trace",
                    )
                )

            if endpoint.deprecated:
                issues.append(
                    _Issue(
                        rule_id="API-DEPRECATED-ENDPOINT-LIVE",
                        category="api_security",
                        title=f"{endpoint.identifier} is deprecated but still published",
                        description=(
                            f"{endpoint.identifier} is marked deprecated in the "
                            "specification. A deprecated endpoint that is still reachable is "
                            "usually also still unmaintained: it misses the hardening, "
                            "validation and logging applied to its replacement, while "
                            "remaining fully exploitable."
                        ),
                        severity="low",
                        confidence="high",
                        summary=f"{endpoint.identifier} has deprecated: true",
                        path=endpoint.path,
                        method=endpoint.method.upper(),
                        impact=(
                            "Deprecated endpoints are a common path around controls added to "
                            "their replacements."
                        ),
                        remediation=(
                            "Set a removal date, confirm no client still calls it, and remove "
                            "the implementation — not just the documentation."
                        ),
                        cwe="CWE-1104",
                        discriminator=f"endpoint:{endpoint.identifier}:deprecated",
                    )
                )

        # Unauthenticated reads are reported as one finding: a public API has
        # many by design, and 200 separate low findings would bury the rest.
        if unauthenticated_reads:
            issues.append(
                _Issue(
                    rule_id="API-UNAUTHENTICATED-READ-SURFACE",
                    category="api_security",
                    title=(
                        f"{len(unauthenticated_reads)} read operations require no authentication"
                    ),
                    description=(
                        f"{len(unauthenticated_reads)} of {len(spec.endpoints)} operations are "
                        "declared as readable without a credential. That may be correct for a "
                        "public API; it is listed so the intent can be confirmed per endpoint "
                        "rather than assumed, because an endpoint made public by omission "
                        "looks identical to one made public by design."
                    ),
                    severity="info",
                    confidence="high",
                    summary=f"unauthenticated read operations: {len(unauthenticated_reads)}",
                    remediation=(
                        "Confirm each of these is intentionally public. For those that are, "
                        "apply rate limiting and ensure no response field is scoped to a user."
                    ),
                    discriminator="spec:unauthenticated-reads",
                    artifacts={"operations": unauthenticated_reads[:200]},
                )
            )

        return issues

    @staticmethod
    def _bola_issue(
        endpoint: Endpoint, identifier_params: list[Any], unauthenticated: bool
    ) -> _Issue:
        names = ", ".join(f"{{{p.name}}}" for p in identifier_params)
        if unauthenticated:
            return _Issue(
                rule_id="API-BOLA-UNAUTHENTICATED",
                category="broken_access_control",
                title=f"{endpoint.identifier} exposes objects by identifier with no authentication",
                description=(
                    f"{endpoint.identifier} is keyed by the object identifier(s) {names} and "
                    "the specification requires no credential to call it. Object-level "
                    "authorization cannot exist here: there is no identity to authorize, so "
                    "every object is reachable by anyone who can enumerate or guess an "
                    "identifier. Where identifiers are sequential, enumeration is trivial."
                ),
                severity="critical",
                confidence="high",
                summary=f"{endpoint.identifier} takes {names} with an empty security requirement",
                path=endpoint.path,
                method=endpoint.method.upper(),
                impact=(
                    "Every object addressable by this endpoint can be read by any "
                    "unauthenticated caller, which is a bulk data exposure rather than a "
                    "single-record one."
                ),
                remediation=(
                    "Require authentication, then authorize per object: check that the "
                    "authenticated principal owns or may access the specific identifier "
                    "requested, not merely that it is logged in."
                ),
                cwe="CWE-639",
                owasp_asvs=["V4.2.1"],
                discriminator=f"endpoint:{endpoint.identifier}:bola-unauth",
                artifacts={"identifier_parameters": [p.name for p in identifier_params]},
                mitre=["T1190"],
            )
        return _Issue(
            rule_id="API-BOLA-REQUIRES-VERIFICATION",
            category="broken_access_control",
            title=f"{endpoint.identifier} needs object-level authorization testing",
            description=(
                f"{endpoint.identifier} is keyed by the object identifier(s) {names} and "
                "requires authentication. Whether it also authorizes *per object* cannot be "
                "determined from the specification or from an unauthenticated scan — it "
                "needs two accounts and an attempt to read one's object with the other's "
                "token. This is recorded so the endpoint is tested, not because a flaw has "
                "been observed: broken object-level authorization is consistently the most "
                "common serious API flaw, and it is invisible to a scanner without "
                "credentials."
            ),
            severity="info",
            confidence="low",
            summary=f"{endpoint.identifier} takes {names}; per-object authorization untested",
            path=endpoint.path,
            method=endpoint.method.upper(),
            impact=(
                "If per-object authorization is missing, any authenticated user can read or "
                "modify any other user's objects by changing the identifier."
            ),
            remediation=(
                "Test with two accounts: authenticate as A, request B's object identifier, "
                "and confirm the response is 403 or 404 rather than B's data. Automate that "
                "test so a regression is caught."
            ),
            cwe="CWE-639",
            owasp_asvs=["V4.2.1"],
            discriminator=f"endpoint:{endpoint.identifier}:bola-review",
            artifacts={
                "identifier_parameters": [p.name for p in identifier_params],
                "requires_manual_verification": True,
            },
        )

    @staticmethod
    def _mass_assignment_issue(endpoint: Endpoint, privileged: list[str]) -> _Issue:
        return _Issue(
            rule_id="API-MASS-ASSIGNMENT",
            category="broken_access_control",
            title=f"{endpoint.identifier} accepts privileged fields in its request body",
            description=(
                f"The request body schema for {endpoint.identifier} declares the "
                f"client-settable properties: {', '.join(privileged)}. These name "
                "server-controlled state — ownership, role, status, identifiers or "
                "balances. If the handler binds the body onto its model without an "
                'allow-list, a caller sets them directly. Sending `"role": "admin"` '
                "alongside a legitimate profile update is the whole attack."
            ),
            severity="medium",
            confidence="medium",
            summary=f"privileged body properties: {', '.join(privileged)}",
            path=endpoint.path,
            method=endpoint.method.upper(),
            impact=(
                "Privilege escalation, ownership transfer or financial manipulation, "
                "depending on which field binds. The request looks entirely legitimate in "
                "logs."
            ),
            remediation=(
                "Bind request bodies to an explicit input schema that contains only "
                "client-settable fields, and mark server-controlled properties `readOnly` "
                "in the specification so the contract matches the implementation."
            ),
            cwe="CWE-915",
            owasp_asvs=["V5.1.2"],
            discriminator=f"endpoint:{endpoint.identifier}:mass-assignment",
            matched_value=", ".join(privileged),
            artifacts={
                "properties": privileged,
                "all_body_properties": sorted(endpoint.request_body_properties),
            },
        )

    @staticmethod
    def _sensitive_parameter_issue(endpoint: Endpoint, parameter: Any) -> _Issue:
        return _Issue(
            rule_id="API-SENSITIVE-PARAMETER-IN-URL",
            category="sensitive_data_exposure",
            title=(f"{endpoint.identifier} carries {parameter.name!r} in the {parameter.location}"),
            description=(
                f"{endpoint.identifier} declares {parameter.name!r} as a "
                f"{parameter.location} parameter. Its name indicates a credential or "
                "personal identifier, and both path and query components appear in web "
                "server logs, proxy logs, CDN logs, browser history and `Referer` headers. "
                "Transport encryption does not help: the value is logged in cleartext at "
                "every hop that terminates TLS."
            ),
            severity="high",
            confidence="medium",
            summary=f"{parameter.location} parameter {parameter.name!r} on {endpoint.identifier}",
            path=endpoint.path,
            method=endpoint.method.upper(),
            impact=(
                "The value is retained in logs across systems the API owner may not "
                "control, for as long as those logs are kept."
            ),
            remediation=(
                "Move the value into a request header or, for a mutating operation, the "
                "request body. Rotate any credential that has been sent in a URL."
            ),
            cwe="CWE-598",
            owasp_asvs=["V3.5.3"],
            discriminator=f"endpoint:{endpoint.identifier}:param:{parameter.name}",
            matched_value=parameter.name,
            artifacts={"parameter": parameter.name, "location": parameter.location},
            mitre=["T1552"],
        )

    @staticmethod
    def _review_rate_limiting(spec: ApiSpecification) -> list[_Issue]:
        documents_429 = any("429" in e.response_codes for e in spec.endpoints)
        if documents_429 or not spec.endpoints:
            return []
        return [
            _Issue(
                rule_id="API-NO-RATE-LIMIT-DOCUMENTED",
                category="api_security",
                title=f"{spec.title} documents no rate limiting",
                description=(
                    f"None of the {len(spec.endpoints)} operations document a 429 response, "
                    "so the specification makes no claim that rate limiting exists. Without "
                    "it, authentication endpoints are open to credential stuffing, "
                    "identifier-keyed endpoints to enumeration, and expensive operations to "
                    "resource exhaustion. The absence of documentation is not proof that "
                    "limiting is absent — it is a gap to confirm."
                ),
                severity="low",
                confidence="low",
                summary="no operation documents a 429 response",
                impact=(
                    "Unlimited request rates make brute force, enumeration and resource "
                    "exhaustion attacks practical against otherwise sound endpoints."
                ),
                remediation=(
                    "Apply rate limiting at the gateway, document the 429 response and the "
                    "`Retry-After` header, and limit authentication endpoints more strictly "
                    "than the rest."
                ),
                cwe="CWE-770",
                owasp_asvs=["V11.1.4"],
                discriminator="spec:no-rate-limit",
                artifacts={"endpoint_count": len(spec.endpoints)},
            )
        ]

    @staticmethod
    def _spec_exposure_issue(spec: ApiSpecification, discovery: dict[str, Any]) -> _Issue:
        url = str(discovery["exposed_at"])
        return _Issue(
            rule_id="API-SPECIFICATION-EXPOSED",
            category="information_disclosure",
            title="The API specification is published without authentication",
            description=(
                f"The full specification for {spec.title} was retrieved from {url} with no "
                f"credential, disclosing {len(spec.endpoints)} operations with their "
                "parameters, schemas and authentication requirements. That is the complete "
                "attack surface map, including internal and administrative routes that "
                "would otherwise need to be discovered. Whether this is acceptable depends "
                "on the API: for a public API it is intended, for an internal one it is a "
                "disclosure."
            ),
            severity="medium",
            confidence="confirmed",
            summary=f"GET {url} returned a parseable specification with no credential",
            url=url,
            impact=(
                "Reconnaissance is eliminated. Administrative and deprecated routes, "
                "parameter names and body schemas are handed over directly, which is also "
                "what makes mass assignment and parameter-pollution attacks cheap to build."
            ),
            remediation=(
                "If the API is not public, require authentication on the specification "
                "endpoint or serve it only from internal networks. Publish a filtered "
                "specification externally if consumers need one."
            ),
            cwe="CWE-200",
            discriminator="api:spec-exposed",
            artifacts={
                "url": url,
                "endpoint_count": len(spec.endpoints),
                "title": spec.title,
            },
            is_exploitable=True,
            exploitability_note=(
                "Directly retrievable with an unauthenticated GET; no exploitation step is "
                "required beyond the request itself."
            ),
            mitre=["T1595"],
        )

    # ------------------------------------------------------- live verification
    async def _verify_endpoints(
        self,
        ctx: EngineContext,
        client: AssessmentHttpClient,
        spec: ApiSpecification,
        base: str,
    ) -> tuple[list[_Issue], dict[str, Any]]:
        """Check what the API does, for the endpoints that can be safely called.

        Only secured, safe-method endpoints with no required path parameter are
        probed. A path parameter would have to be invented, and a fabricated
        identifier produces an ambiguous response — 404 could mean "no such
        object" or "authorization denied" — so those endpoints are reported as
        needing manual testing instead of guessed at.
        """
        max_probes = int(ctx.option("max_probes", DEFAULT_MAX_PROBES))
        candidates: list[Endpoint] = []
        skipped_reasons: dict[str, int] = {}

        for endpoint in spec.endpoints:
            if not endpoint.is_safe_method:
                skipped_reasons["mutating method is never sent"] = (
                    skipped_reasons.get("mutating method is never sent", 0) + 1
                )
                continue
            if endpoint.is_unauthenticated(spec.global_security):
                # Already reported from the specification; calling it would add
                # nothing and would send avoidable traffic.
                skipped_reasons["declared public"] = skipped_reasons.get("declared public", 0) + 1
                continue
            if any(p.required for p in endpoint.path_parameters):
                skipped_reasons["requires a path identifier"] = (
                    skipped_reasons.get("requires a path identifier", 0) + 1
                )
                continue
            candidates.append(endpoint)

        truncated = len(candidates) > max_probes
        probed = candidates[:max_probes]
        semaphore = asyncio.Semaphore(max(1, min(ctx.max_concurrency, 16)))

        async def probe(endpoint: Endpoint) -> tuple[Endpoint, ProbeResult | None, str | None]:
            async with semaphore:
                ctx.raise_if_cancelled()
                url = spec.resolve_url(base, endpoint.path)
                verdict = ctx.check_scope(url)
                if not verdict.allowed:
                    return endpoint, None, f"out of scope: {verdict.reason}"
                response = await client.request(endpoint.method.upper(), url)
                return endpoint, response, None

        outcomes = await asyncio.gather(*(probe(e) for e in probed), return_exceptions=True)

        issues: list[_Issue] = []
        errors: list[str] = []
        out_of_scope = 0
        enforced = 0
        inconclusive = 0

        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                if isinstance(outcome, asyncio.CancelledError):
                    raise outcome
                errors.append(f"{type(outcome).__name__}: {outcome}")
                continue
            endpoint, response, refusal = outcome
            if refusal is not None:
                out_of_scope += 1
                continue
            if response is None or not response.ok:
                errors.append(
                    f"{endpoint.identifier}: {response.error if response else 'no response'}"
                )
                continue

            status = response.status_code or 0
            if 200 <= status < 300:
                issues.append(self._auth_bypass_issue(endpoint, response, spec))
            elif status in (401, 403):
                enforced += 1
            elif status >= 500:
                issues.append(self._server_error_issue(endpoint, response))
            else:
                inconclusive += 1

            if disclosure := self._error_disclosure_issue(endpoint, response):
                issues.append(disclosure)

        stats = {
            "probed": len(probed),
            "skipped": len(spec.endpoints) - len(probed),
            "skip_reasons": skipped_reasons,
            "truncated": truncated,
            "authentication_enforced": enforced,
            "inconclusive": inconclusive,
            "out_of_scope": out_of_scope,
            "errors": errors,
        }
        return issues, stats

    @staticmethod
    def _auth_bypass_issue(
        endpoint: Endpoint, response: ProbeResult, spec: ApiSpecification
    ) -> _Issue:
        requirement = endpoint.effective_security(spec.global_security)
        schemes = sorted({name for req in requirement for name in req})
        return _Issue(
            rule_id="API-AUTHENTICATION-NOT-ENFORCED",
            category="broken_authentication",
            title=f"{endpoint.identifier} returns data without authentication",
            description=(
                f"The specification requires {', '.join(schemes) or 'authentication'} for "
                f"{endpoint.identifier}, but a request carrying no credential at all "
                f"returned HTTP {response.status_code} with "
                f"{response.body_bytes} bytes of body. The declared control is not "
                "enforced at runtime. This is observed behaviour, not an inference from "
                "the document."
            ),
            severity="critical",
            confidence="confirmed",
            summary=(
                f"{endpoint.method.upper()} {response.url} with no credential returned "
                f"HTTP {response.status_code} ({response.body_bytes} bytes)"
            ),
            path=endpoint.path,
            method=endpoint.method.upper(),
            url=response.url,
            impact=(
                "Whatever this endpoint returns is public. If the gap is in shared "
                "middleware rather than this handler, every endpoint relying on that "
                "middleware is equally open."
            ),
            remediation=(
                "Enforce the declared security requirement in the handler or middleware, "
                "and add a test that an unauthenticated request receives 401. Then check "
                "whether the same gap affects the other endpoints that share the "
                "middleware."
            ),
            cwe="CWE-306",
            owasp_asvs=["V4.1.1"],
            discriminator=f"endpoint:{endpoint.identifier}:auth-not-enforced",
            request=response.evidence_request(),
            response=response.evidence_response(512),
            response_status=response.status_code,
            artifacts={
                "declared_schemes": schemes,
                "status_code": response.status_code,
                "body_bytes": response.body_bytes,
            },
            is_exploitable=True,
            exploitability_note=(
                "Confirmed by a single unauthenticated request during this scan; the "
                "response is in the evidence."
            ),
            mitre=["T1190"],
        )

    @staticmethod
    def _server_error_issue(endpoint: Endpoint, response: ProbeResult) -> _Issue:
        return _Issue(
            rule_id="API-UNAUTHENTICATED-SERVER-ERROR",
            category="api_security",
            title=f"{endpoint.identifier} returns {response.status_code} to an anonymous request",
            description=(
                f"An unauthenticated {endpoint.method.upper()} to {endpoint.path} returned "
                f"HTTP {response.status_code}. The request reached application code and "
                "failed there, rather than being rejected at the authentication boundary. "
                "Code executing before authentication is code an anonymous caller can "
                "reach, and an unhandled error in it is both a stability problem and a "
                "signal that the boundary sits further in than intended."
            ),
            severity="medium",
            confidence="high",
            summary=(
                f"{endpoint.method.upper()} {response.url} with no credential returned "
                f"HTTP {response.status_code}"
            ),
            path=endpoint.path,
            method=endpoint.method.upper(),
            url=response.url,
            impact=(
                "Anonymous callers can drive the endpoint into an error path, which is a "
                "denial-of-service lever and a source of information disclosure."
            ),
            remediation=(
                "Reject unauthenticated requests before any handler logic runs, and handle "
                "the underlying error so it returns a controlled response."
            ),
            cwe="CWE-755",
            discriminator=f"endpoint:{endpoint.identifier}:anon-5xx",
            request=response.evidence_request(),
            response=response.evidence_response(512),
            response_status=response.status_code,
            artifacts={"status_code": response.status_code},
        )

    @staticmethod
    def _error_disclosure_issue(endpoint: Endpoint, response: ProbeResult) -> _Issue | None:
        if not response.body:
            return None
        for pattern, label in ERROR_DISCLOSURE_PATTERNS:
            match = pattern.search(response.body)
            if match is None:
                continue
            excerpt = response.body[max(0, match.start() - 80) : match.end() + 200]
            return _Issue(
                rule_id="API-ERROR-DETAIL-DISCLOSED",
                category="information_disclosure",
                title=f"{endpoint.identifier} returns internal error detail",
                description=(
                    f"The response from {endpoint.identifier} contains {label}. Framework "
                    "error output discloses file paths, library versions, SQL fragments and "
                    "internal structure — the information an attacker would otherwise have "
                    "to infer. It also indicates the service is running with debug output "
                    "enabled."
                ),
                severity="medium",
                confidence="high",
                summary=f"response body contains {label}",
                path=endpoint.path,
                method=endpoint.method.upper(),
                url=response.url,
                impact=(
                    "Internal paths, component versions and query structure are disclosed, "
                    "which makes targeting the next stage of an attack substantially cheaper."
                ),
                remediation=(
                    "Disable debug mode in this environment and return a generic error body "
                    "with a correlation identifier, logging the detail server-side."
                ),
                cwe="CWE-209",
                discriminator=f"endpoint:{endpoint.identifier}:error-disclosure",
                matched_value=label,
                request=response.evidence_request(),
                response=excerpt,
                response_status=response.status_code,
                artifacts={"marker": label},
            )
        return None

    # -------------------------------------------------------------- mapping
    @staticmethod
    def _to_finding(issue: _Issue, ctx: EngineContext) -> ScanFinding:
        host: str | None = None
        port: int | None = None
        scheme: str | None = None
        if issue.url:
            parsed = urlparse(issue.url)
            host = parsed.hostname
            port = parsed.port
            scheme = parsed.scheme
        else:
            parsed = urlparse(
                ctx.target.value if "://" in ctx.target.value else f"https://{ctx.target.value}"
            )
            host = parsed.hostname
            port = parsed.port
            scheme = parsed.scheme

        return ScanFinding(
            engine="api",
            rule_id=issue.rule_id,
            category=issue.category,
            title=issue.title,
            description=issue.description,
            severity=issue.severity,
            confidence=issue.confidence,
            evidence=Evidence(
                summary=issue.summary,
                request=issue.request,
                response=issue.response,
                response_status=issue.response_status,
                matched_value=issue.matched_value,
                artifacts=issue.artifacts,
            ),
            impact=issue.impact,
            remediation=issue.remediation,
            references=issue.references,
            network_location=NetworkLocation(
                url=issue.url,
                host=host,
                port=port,
                scheme=scheme,
                method=issue.method,
                path=issue.path,
            ),
            target=ctx.target,
            cwe=issue.cwe,
            owasp_asvs=issue.owasp_asvs,
            mitre_techniques=issue.mitre,
            correlation_discriminator=issue.discriminator,
            is_exploitable=issue.is_exploitable,
            exploitability_note=issue.exploitability_note,
        )
