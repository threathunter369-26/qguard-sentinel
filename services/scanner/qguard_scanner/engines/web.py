"""Web application assessment.

An **active** engine: it sends requests to the target, so it runs only when an
approved test authorization covers that target. The SDK enforces that before
``analyze`` is reached.

The checks are deliberately non-destructive. Everything here is an observation
of how the application responds to ordinary, well-formed requests — security
headers, cookie attributes, CORS reflection, information disclosure, exposed
administrative paths, HTTP methods, and TLS redirection. Nothing writes data,
nothing attempts to exploit, and no payload is sent that could corrupt state.
That is a design choice, not a limitation: the overwhelming majority of real
web findings are configuration, and a scanner that stays safe can be pointed at
production.

Where a check cannot distinguish a real finding from an expected design, the
finding says so and carries lower confidence rather than asserting certainty.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

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

#: Required security headers, with why each matters and what good looks like.
SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "severity": "medium",
        "title": "HTTP Strict Transport Security not set",
        "why": (
            "Without HSTS a browser will try plain HTTP first on a typed or bookmarked "
            "address, which gives an on-path attacker one request to strip TLS and "
            "capture the session cookie."
        ),
        "fix": "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
        "cwe": "CWE-319",
        "https_only": True,
    },
    "content-security-policy": {
        "severity": "medium",
        "title": "Content Security Policy not set",
        "why": (
            "A CSP is the control that limits the damage of a cross-site scripting "
            "bug. Without one, any injected script runs with the page's full authority."
        ),
        "fix": (
            "Start with `default-src 'self'; object-src 'none'; base-uri 'none'` and "
            "tighten from there. Avoid 'unsafe-inline', which removes most of the benefit."
        ),
        "cwe": "CWE-693",
    },
    "x-content-type-options": {
        "severity": "low",
        "title": "X-Content-Type-Options not set",
        "why": (
            "Without `nosniff` a browser may second-guess the declared content type and "
            "execute an uploaded file as script."
        ),
        "fix": "Send `X-Content-Type-Options: nosniff`.",
        "cwe": "CWE-430",
    },
    "x-frame-options": {
        "severity": "low",
        "title": "No framing protection",
        "why": (
            "Without X-Frame-Options or a CSP frame-ancestors directive the page can be "
            "framed by another site and used for clickjacking."
        ),
        "fix": "Send `X-Frame-Options: DENY`, or `frame-ancestors 'none'` in the CSP.",
        "cwe": "CWE-1021",
        "satisfied_by_csp": "frame-ancestors",
    },
    "referrer-policy": {
        "severity": "low",
        "title": "Referrer-Policy not set",
        "why": (
            "Default referrer behaviour sends the full URL to third parties, which leaks "
            "path and query data — including tokens embedded in URLs."
        ),
        "fix": "Send `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
        "cwe": "CWE-200",
    },
}

#: Headers that disclose software and version information.
DISCLOSURE_HEADERS: dict[str, str] = {
    "server": "the web server and often its exact version",
    "x-powered-by": "the application framework and version",
    "x-aspnet-version": "the ASP.NET runtime version",
    "x-aspnetmvc-version": "the ASP.NET MVC version",
    "x-generator": "the generating platform",
    "x-drupal-cache": "that the site runs Drupal",
    "x-runtime": "server response timing, which assists timing analysis",
}

#: Technology fingerprints, so the asset inventory records a real stack.
FINGERPRINTS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("nginx", re.compile(r"(?i)\bnginx(?:/([\d.]+))?"), "server"),
    ("apache", re.compile(r"(?i)\bapache(?:/([\d.]+))?"), "server"),
    ("iis", re.compile(r"(?i)microsoft-iis(?:/([\d.]+))?"), "server"),
    ("express", re.compile(r"(?i)\bexpress\b"), "framework"),
    ("django", re.compile(r"(?i)\bdjango\b|csrftoken"), "framework"),
    ("rails", re.compile(r"(?i)\brails\b|_session_id"), "framework"),
    ("laravel", re.compile(r"(?i)laravel_session|\blaravel\b"), "framework"),
    ("next.js", re.compile(r"(?i)\b_next/static|x-powered-by:\s*next\.js"), "framework"),
    ("react", re.compile(r"(?i)__REACT_DEVTOOLS|data-reactroot"), "frontend"),
    ("vue", re.compile(r"(?i)\bvue(?:\.js)?\b|data-v-"), "frontend"),
    ("wordpress", re.compile(r"(?i)wp-content|wp-includes|\bwordpress\b"), "cms"),
    ("drupal", re.compile(r"(?i)\bdrupal\b|/sites/default/files"), "cms"),
    ("cloudflare", re.compile(r"(?i)\bcloudflare\b|cf-ray"), "cdn"),
    ("php", re.compile(r"(?i)\bphp(?:/([\d.]+))?|phpsessid"), "runtime"),
    ("tomcat", re.compile(r"(?i)\btomcat(?:/([\d.]+))?|jsessionid"), "server"),
)

#: Paths that commonly expose configuration or administrative surface. Only
#: fetched with GET, which is a read.
SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/.git/config", "high", "A Git repository is served, exposing full source history."),
    ("/.env", "critical", "An environment file is served, which usually contains credentials."),
    ("/.svn/entries", "high", "A Subversion directory is served."),
    ("/.DS_Store", "low", "A macOS directory index is served, disclosing file names."),
    ("/server-status", "medium", "Apache mod_status is reachable, disclosing live requests."),
    ("/.well-known/security.txt", "info", "No security contact is published."),
    ("/actuator/env", "critical", "Spring Boot Actuator env endpoint is exposed."),
    ("/actuator/health", "low", "Spring Boot Actuator is reachable."),
    ("/debug/pprof/", "high", "Go pprof profiling endpoints are exposed."),
    ("/phpinfo.php", "high", "phpinfo() output is served, disclosing full configuration."),
    ("/.aws/credentials", "critical", "An AWS credentials file is served."),
    ("/config.json", "medium", "A configuration file is served."),
    ("/swagger.json", "low", "An API specification is published."),
    ("/openapi.json", "low", "An API specification is published."),
    ("/graphql", "low", "A GraphQL endpoint is reachable."),
    ("/admin", "low", "An administrative path responds."),
    ("/wp-login.php", "low", "A WordPress login page is reachable."),
    ("/.git/HEAD", "high", "A Git repository is served."),
    ("/backup.sql", "critical", "A database dump is served."),
    ("/.htpasswd", "critical", "An htpasswd credential file is served."),
)

#: Error-page and response patterns that disclose internals.
LEAK_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    (
        "stack_trace",
        re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)"),
        "medium",
        "A stack trace is returned to the client, disclosing internal structure.",
    ),
    (
        "sql_error",
        re.compile(r"(?i)SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}|SQLSTATE\["),
        "high",
        "A database error is returned, which both discloses schema detail and "
        "indicates unvalidated input reaching the database.",
    ),
    (
        "internal_path",
        re.compile(r"(?:/home/\w+/|/var/www/[\w/]+|C:\\\\(?:inetpub|Users)\\\\)"),
        "low",
        "An internal filesystem path appears in the response.",
    ),
    (
        "private_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}|192\.168\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3})\.\d{1,3}\b"
        ),
        "low",
        "An internal IP address appears in the response, disclosing network layout.",
    ),
    (
        "debug_mode",
        re.compile(
            r"(?i)(?:DEBUG\s*=\s*True|Werkzeug Debugger|Whoops!|"
            r"Rails\.application\.config\.consider_all_requests_local)"
        ),
        "critical",
        "Debug output is enabled, which commonly exposes an interactive console.",
    ),
)


@dataclass(slots=True)
class _Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: str
    remediation: str
    url: str
    method: str = "GET"
    evidence_summary: str = ""
    request: str | None = None
    response: str | None = None
    status_code: int | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    owasp: str | None = None
    discriminator: str | None = None


@register_engine
class WebEngine(SecurityEngine):
    """Non-destructive web application assessment."""

    metadata = EngineMetadata(
        key="web",
        name="Web Application Security",
        description=(
            "Assesses a web application's security headers, cookie attributes, CORS "
            "policy, HTTP methods, information disclosure and exposed administrative "
            "paths. All checks are read-only and non-destructive, so the engine is safe "
            "to point at production within an approved scope."
        ),
        version="1.0.0",
        target_kinds=("url", "host", "web_application"),
        capabilities=frozenset({EngineCapability.NETWORK}),
        categories=(
            "security_misconfiguration",
            "insecure_communication",
            "session_management",
            "information_disclosure",
            "cross_site_scripting",
            "broken_access_control",
            "network_exposure",
        ),
    )

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        base = self._normalise(ctx.target.value)
        check_paths = bool(ctx.option("check_sensitive_paths", True))
        max_paths = int(ctx.option("max_sensitive_paths", len(SENSITIVE_PATHS)))

        findings: list[_Finding] = []
        warnings: list[str] = []
        technologies: dict[str, Any] = {}
        checks = 0

        async with AssessmentHttpClient(
            user_agent=ctx.user_agent,
            timeout_seconds=ctx.http_timeout_seconds,
            max_requests_per_second=ctx.max_requests_per_second,
            max_concurrency=ctx.max_concurrency,
            # Assessment traffic: an internal target with a self-signed or
            # expired certificate must still be assessable. The certificate
            # problem is reported by the certificate engine rather than
            # silently aborting this one.
            verify_tls=False,
        ) as client:
            await ctx.report_progress(5, f"fetching {base}")
            root = await client.get(base)
            checks += 1

            if not root.ok:
                # Unreachable is a failure, not an empty clean result.
                return EngineResult.failed(
                    self.key,
                    (
                        f"{base} could not be reached: {root.error}. No assessment was "
                        "performed, so nothing can be concluded about this target's "
                        "security."
                    ),
                    stats={"target": base, **client.stats.as_dict()},
                    requests_sent=client.stats.requests_sent,
                )

            technologies = self._fingerprint(root)
            findings.extend(self._check_headers(root, base))
            findings.extend(self._check_cookies(root, base))
            findings.extend(self._check_disclosure_headers(root, base))
            findings.extend(self._check_body_leaks(root, base))
            checks += 5

            await ctx.report_progress(30, "checking TLS redirection")
            findings.extend(await self._check_https_redirect(client, base))
            checks += 1

            await ctx.report_progress(45, "checking CORS policy")
            findings.extend(await self._check_cors(client, base))
            checks += 1

            await ctx.report_progress(60, "checking HTTP methods")
            findings.extend(await self._check_methods(client, base))
            checks += 1

            if check_paths:
                await ctx.report_progress(70, "checking for exposed paths")
                path_findings, path_checks = await self._check_paths(client, base, max_paths, ctx)
                findings.extend(path_findings)
                checks += path_checks

            if client.stats.blocked_targets:
                warnings.append(
                    f"{len(client.stats.blocked_targets)} request(s) were refused by the "
                    "platform's network policy and were not performed."
                )
            if client.stats.timeouts:
                warnings.append(
                    f"{client.stats.timeouts} request(s) timed out, so the corresponding "
                    "checks are inconclusive."
                )

            stats: dict[str, Any] = {
                "target": base,
                "technologies": technologies,
                "checks_executed": checks,
                **client.stats.as_dict(),
            }
            scan_findings = [self._to_finding(f, ctx) for f in findings]

            if warnings:
                return EngineResult.degraded(
                    self.key,
                    scan_findings,
                    reason=(
                        "Some checks could not complete: "
                        + " ".join(warnings)
                        + " The absence of findings for those checks is not a clean result."
                    ),
                    stats=stats,
                    items_examined=checks,
                    checks_executed=checks,
                    requests_sent=client.stats.requests_sent,
                    warnings=warnings,
                )

            return EngineResult.completed(
                self.key,
                scan_findings,
                stats=stats,
                items_examined=checks,
                checks_executed=checks,
                requests_sent=client.stats.requests_sent,
            )

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _normalise(target: str) -> str:
        if "://" not in target:
            return f"https://{target}"
        return target

    @staticmethod
    def _fingerprint(response: ProbeResult) -> dict[str, Any]:
        """Identify the stack from headers and body markers."""
        haystack = "\n".join(
            [*(f"{k}: {v}" for k, v in response.headers.items()), response.body[:65536]]
        )
        detected: dict[str, Any] = {}
        for name, pattern, kind in FINGERPRINTS:
            match = pattern.search(haystack)
            if match:
                version = match.group(1) if match.groups() else None
                detected[name] = {"kind": kind, "version": version}
        return detected

    # ---------------------------------------------------------------- checks
    @staticmethod
    def _check_headers(response: ProbeResult, base: str) -> list[_Finding]:
        findings: list[_Finding] = []
        is_https = base.startswith("https://")
        csp = response.header("content-security-policy") or ""

        for header, spec in SECURITY_HEADERS.items():
            if spec.get("https_only") and not is_https:
                continue
            if response.has_header(header):
                continue
            # Framing protection can come from either header; treat the CSP
            # directive as satisfying it rather than reporting a false positive.
            satisfied = spec.get("satisfied_by_csp")
            if satisfied and satisfied in csp:
                continue
            findings.append(
                _Finding(
                    rule_id=f"web.missing-header.{header}",
                    title=spec["title"],
                    description=f"The response does not include `{header}`. {spec['why']}",
                    severity=spec["severity"],
                    confidence="high",
                    category="security_misconfiguration",
                    cwe=spec["cwe"],
                    remediation=spec["fix"],
                    url=base,
                    evidence_summary=f"`{header}` absent from the response to GET {base}",
                    response=response.evidence_response(256),
                    status_code=response.status_code,
                    owasp="A05:2021",
                    artifacts={"header": header, "present_headers": sorted(response.headers)},
                    discriminator=f"missing-header:{header}",
                )
            )

        if csp:
            weaknesses = []
            if "'unsafe-inline'" in csp:
                weaknesses.append(
                    "'unsafe-inline' permits inline script, which removes most of the "
                    "protection a CSP provides against cross-site scripting"
                )
            if "'unsafe-eval'" in csp:
                weaknesses.append("'unsafe-eval' permits dynamic code evaluation")
            if re.search(r"(?:default|script)-src[^;]*\*(?:\s|;|$)", csp):
                weaknesses.append("a wildcard source permits script from any origin")
            if weaknesses:
                findings.append(
                    _Finding(
                        rule_id="web.weak-csp",
                        title="Content Security Policy is permissive",
                        description=(
                            "A CSP is present but weakened: "
                            + "; ".join(weaknesses)
                            + ". A policy that allows inline or wildcard script is close "
                            "to having no policy where XSS is concerned."
                        ),
                        severity="low",
                        confidence="high",
                        category="security_misconfiguration",
                        cwe="CWE-693",
                        remediation=(
                            "Remove 'unsafe-inline' and 'unsafe-eval' and adopt nonces or "
                            "hashes for the scripts that genuinely need to be inline."
                        ),
                        url=base,
                        evidence_summary="CSP present but permissive",
                        response=f"content-security-policy: {csp[:500]}",
                        owasp="A05:2021",
                        artifacts={"csp": csp[:1000], "weaknesses": weaknesses},
                        discriminator="weak-csp",
                    )
                )
        return findings

    @staticmethod
    def _check_cookies(response: ProbeResult, base: str) -> list[_Finding]:
        raw = response.headers.get("set-cookie")
        if not raw:
            return []
        findings: list[_Finding] = []
        is_https = base.startswith("https://")

        # httpx collapses repeated Set-Cookie headers; split on the boundary
        # between cookies rather than on every comma, since Expires contains one.
        for cookie in re.split(r",(?=\s*[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)", raw):
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            looks_session = bool(
                re.search(r"(?i)sess|sid|auth|token|jwt|login|remember|csrf|xsrf", name)
            )
            problems: list[str] = []
            if "httponly" not in lowered:
                problems.append(
                    "HttpOnly is absent, so JavaScript can read it — which is what turns "
                    "an XSS bug into session theft"
                )
            if is_https and "secure" not in lowered:
                problems.append(
                    "Secure is absent, so it will be sent over plain HTTP if the browser "
                    "ever makes such a request"
                )
            if "samesite" not in lowered:
                problems.append(
                    "SameSite is absent, so the cookie is attached to cross-site requests "
                    "and the application depends on another CSRF defence"
                )
            elif "samesite=none" in lowered and "secure" not in lowered:
                problems.append("SameSite=None requires Secure, which is absent")

            if not problems:
                continue
            findings.append(
                _Finding(
                    rule_id="web.insecure-cookie",
                    title=f"Cookie {name!r} lacks protective attributes",
                    description=(
                        f"The cookie {name!r} is set without: "
                        + "; ".join(problems)
                        + "."
                        + (
                            " The name suggests it carries session or authentication "
                            "state, which makes these attributes important rather than "
                            "merely advisable."
                            if looks_session
                            else " If this cookie does not carry security-relevant state "
                            "the impact is limited."
                        )
                    ),
                    severity="medium" if looks_session else "low",
                    confidence="high" if looks_session else "medium",
                    category="session_management",
                    cwe="CWE-1004",
                    remediation=(
                        "Set `HttpOnly; Secure; SameSite=Lax` (or Strict) on every "
                        "session cookie, and `SameSite=None; Secure` only where a "
                        "cross-site flow genuinely requires it."
                    ),
                    url=base,
                    evidence_summary=(
                        f"Set-Cookie for {name!r} missing {len(problems)} attribute(s)"
                    ),
                    response=f"set-cookie: {cookie[:300]}",
                    owasp="A05:2021",
                    artifacts={
                        "cookie_name": name,
                        "missing": problems,
                        "looks_like_session": looks_session,
                    },
                    discriminator=f"cookie:{name}",
                )
            )
        return findings

    @staticmethod
    def _check_disclosure_headers(response: ProbeResult, base: str) -> list[_Finding]:
        disclosed = {
            header: response.header(header)
            for header in DISCLOSURE_HEADERS
            if response.has_header(header)
        }
        if not disclosed:
            return []
        versioned = {k: v for k, v in disclosed.items() if v and re.search(r"\d+\.\d+", v)}
        return [
            _Finding(
                rule_id="web.version-disclosure",
                title="Response headers disclose software versions",
                description=(
                    "The response includes "
                    + ", ".join(f"`{k}: {v}`" for k, v in list(disclosed.items())[:5])
                    + ". These disclose "
                    + "; ".join(DISCLOSURE_HEADERS[k] for k in list(disclosed)[:3])
                    + "."
                    + (
                        " A precise version lets an attacker look up known "
                        "vulnerabilities for exactly this build without probing, which "
                        "removes the noise that would otherwise be detected."
                        if versioned
                        else " No precise version is disclosed, which limits the value to "
                        "an attacker."
                    )
                ),
                severity="low" if versioned else "info",
                confidence="high",
                category="information_disclosure",
                cwe="CWE-200",
                remediation=(
                    "Suppress or genericise these headers at the reverse proxy "
                    "(`server_tokens off` in nginx, `ServerTokens Prod` in Apache, "
                    "and remove X-Powered-By in the application)."
                ),
                url=base,
                evidence_summary=f"{len(disclosed)} disclosure header(s) present",
                response="\n".join(f"{k}: {v}" for k, v in disclosed.items()),
                owasp="A05:2021",
                artifacts={"headers": disclosed, "versioned": list(versioned)},
                discriminator="version-disclosure",
            )
        ]

    @staticmethod
    def _check_body_leaks(response: ProbeResult, base: str) -> list[_Finding]:
        findings: list[_Finding] = []
        for name, pattern, severity, why in LEAK_PATTERNS:
            match = pattern.search(response.body)
            if not match:
                continue
            excerpt = response.body[max(0, match.start() - 80) : match.end() + 120].strip()
            findings.append(
                _Finding(
                    rule_id=f"web.information-disclosure.{name}",
                    title=f"Response discloses internal information ({name.replace('_', ' ')})",
                    description=why,
                    severity=severity,
                    confidence="medium",
                    category="information_disclosure" if name != "sql_error" else "injection",
                    cwe="CWE-209" if name in ("stack_trace", "sql_error") else "CWE-200",
                    remediation=(
                        "Return a generic error page to clients and keep detail in "
                        "server-side logs only. Disable debug mode outside development."
                    ),
                    url=base,
                    evidence_summary=f"{name} pattern matched in the response body",
                    response=excerpt[:500],
                    status_code=response.status_code,
                    owasp="A05:2021",
                    artifacts={"pattern": name},
                    discriminator=f"leak:{name}",
                )
            )
        return findings

    @staticmethod
    async def _check_https_redirect(client: AssessmentHttpClient, base: str) -> list[_Finding]:
        parsed = urlparse(base)
        if parsed.scheme != "https":
            return [
                _Finding(
                    rule_id="web.no-tls",
                    title="Target is served over plain HTTP",
                    description=(
                        f"The target was assessed at {base}, which is unencrypted. "
                        "Credentials, session cookies and response data are readable and "
                        "modifiable by anyone on the network path."
                    ),
                    severity="high",
                    confidence="high",
                    category="insecure_communication",
                    cwe="CWE-319",
                    remediation="Serve the application over HTTPS only and redirect HTTP to HTTPS.",
                    url=base,
                    evidence_summary="The target URL scheme is http",
                    owasp="A02:2021",
                    discriminator="no-tls",
                )
            ]

        http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
        response = await client.get(http_url, follow_redirects=False)
        if not response.ok:
            # Plain HTTP refused outright is the desired outcome.
            return []
        location = response.header("location") or ""
        if response.status_code in (301, 302, 307, 308) and location.startswith("https://"):
            return []
        return [
            _Finding(
                rule_id="web.no-https-redirect",
                title="Plain HTTP is served without redirecting to HTTPS",
                description=(
                    f"A request to {http_url} returned HTTP {response.status_code}"
                    + (f" with Location: {location}" if location else " with no redirect")
                    + ". A client that reaches the application over HTTP has already sent "
                    "its request — including any cookie — in the clear before any "
                    "redirect can help."
                ),
                severity="medium",
                confidence="high",
                category="insecure_communication",
                cwe="CWE-319",
                remediation=(
                    "Return a 301 to the HTTPS URL for every HTTP request, and send HSTS "
                    "on the HTTPS response so subsequent visits never use HTTP."
                ),
                url=http_url,
                evidence_summary=f"HTTP {response.status_code} on plain HTTP",
                request=response.evidence_request(),
                response=response.evidence_response(256),
                status_code=response.status_code,
                owasp="A02:2021",
                discriminator="no-https-redirect",
            )
        ]

    @staticmethod
    async def _check_cors(client: AssessmentHttpClient, base: str) -> list[_Finding]:
        # A deliberately foreign origin: if it comes back reflected, the policy
        # accepts any site.
        probe_origin = "https://qguard-scope-probe.invalid"
        response = await client.get(base, headers={"Origin": probe_origin})
        if not response.ok:
            return []
        allow_origin = response.header("access-control-allow-origin")
        credentials_header = response.header("access-control-allow-credentials") or ""
        allow_credentials = credentials_header.lower()
        if not allow_origin:
            return []

        reflected = allow_origin.strip() == probe_origin
        wildcard = allow_origin.strip() == "*"
        if not (reflected or wildcard):
            return []

        if reflected and allow_credentials == "true":
            return [
                _Finding(
                    rule_id="web.cors-reflects-any-origin-with-credentials",
                    title="CORS reflects any origin and allows credentials",
                    description=(
                        f"The application echoed the arbitrary origin {probe_origin!r} in "
                        "Access-Control-Allow-Origin and set "
                        "Access-Control-Allow-Credentials: true. Any website a user "
                        "visits can therefore make authenticated requests to this "
                        "application with the user's cookies and read the responses."
                    ),
                    severity="high",
                    confidence="high",
                    category="security_misconfiguration",
                    cwe="CWE-942",
                    remediation=(
                        "Validate the Origin header against an explicit allow-list and "
                        "echo only a permitted origin. Never combine origin reflection "
                        "with credentialed requests."
                    ),
                    url=base,
                    evidence_summary=(f"Origin {probe_origin} reflected with credentials allowed"),
                    request=f"GET {base}\nOrigin: {probe_origin}",
                    response=(
                        f"access-control-allow-origin: {allow_origin}\n"
                        f"access-control-allow-credentials: {allow_credentials}"
                    ),
                    status_code=response.status_code,
                    owasp="A05:2021",
                    artifacts={
                        "probe_origin": probe_origin,
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_credentials,
                    },
                    discriminator="cors-reflect-credentials",
                )
            ]
        return [
            _Finding(
                rule_id="web.cors-permissive",
                title="Permissive CORS policy",
                description=(
                    f"Access-Control-Allow-Origin is {allow_origin!r}"
                    + (
                        " — the arbitrary probe origin was reflected, so the policy "
                        "accepts any site."
                        if reflected
                        else " — a wildcard, so any site may read responses."
                    )
                    + " Credentials are not allowed, which limits this to data the "
                    "application serves without authentication. Confirm that none of it "
                    "is sensitive."
                ),
                severity="low",
                confidence="medium",
                category="security_misconfiguration",
                cwe="CWE-942",
                remediation=(
                    "Restrict Access-Control-Allow-Origin to the origins that genuinely "
                    "need cross-site access."
                ),
                url=base,
                evidence_summary=f"access-control-allow-origin: {allow_origin}",
                request=f"GET {base}\nOrigin: {probe_origin}",
                response=f"access-control-allow-origin: {allow_origin}",
                owasp="A05:2021",
                artifacts={"allow_origin": allow_origin, "reflected": reflected},
                discriminator="cors-permissive",
            )
        ]

    @staticmethod
    async def _check_methods(client: AssessmentHttpClient, base: str) -> list[_Finding]:
        response = await client.options(base)
        if not response.ok:
            return []
        allow = response.header("allow") or response.header("access-control-allow-methods") or ""
        if not allow:
            return []
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        # TRACE enables cross-site tracing; the write methods are only a finding
        # when advertised at the root, which is rarely intended.
        risky = methods & {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}
        if not risky:
            return []
        severity = "medium" if risky & {"TRACE", "TRACK", "CONNECT"} else "low"
        return [
            _Finding(
                rule_id="web.risky-http-methods",
                title=f"Risky HTTP methods advertised: {', '.join(sorted(risky))}",
                description=(
                    f"The server advertises `Allow: {allow}`. "
                    + (
                        "TRACE and TRACK echo the request back, which historically "
                        "enabled cross-site tracing to read headers a script cannot. "
                        if risky & {"TRACE", "TRACK"}
                        else ""
                    )
                    + (
                        "PUT, DELETE and PATCH at this path would modify server state; "
                        "confirm they are authenticated and intended."
                        if risky & {"PUT", "DELETE", "PATCH"}
                        else ""
                    )
                ),
                severity=severity,
                confidence="medium",
                category="security_misconfiguration",
                cwe="CWE-16",
                remediation=(
                    "Disable TRACE and TRACK at the web server, and restrict "
                    "state-changing methods to the routes that implement them."
                ),
                url=base,
                method="OPTIONS",
                evidence_summary=f"Allow: {allow}",
                request=f"OPTIONS {base}",
                response=f"allow: {allow}",
                status_code=response.status_code,
                owasp="A05:2021",
                artifacts={"methods": sorted(methods), "risky": sorted(risky)},
                discriminator="risky-methods",
            )
        ]

    @staticmethod
    async def _check_paths(
        client: AssessmentHttpClient, base: str, max_paths: int, ctx: EngineContext
    ) -> tuple[list[_Finding], int]:
        findings: list[_Finding] = []
        checks = 0
        for index, (path, severity, why) in enumerate(SENSITIVE_PATHS[:max_paths]):
            if ctx.is_cancelled():
                break
            url = urljoin(base, path)
            # Every candidate is re-checked against scope: a redirect or a
            # rewritten host must not take the engine outside its authorization.
            if not ctx.check_scope(url).allowed:
                continue
            response = await client.get(url, follow_redirects=False)
            checks += 1
            if index % 5 == 0:
                await ctx.report_progress(
                    70 + int(20 * index / max(1, max_paths)),
                    f"checked {index}/{min(max_paths, len(SENSITIVE_PATHS))} path(s)",
                )
            if not response.ok:
                continue

            if path == "/.well-known/security.txt":
                if response.status_code == 404:
                    findings.append(
                        _Finding(
                            rule_id="web.no-security-txt",
                            title="No security.txt published",
                            description=(
                                "No /.well-known/security.txt is served, so a researcher "
                                "who finds a vulnerability has no documented way to "
                                "report it. This is a process gap rather than a technical "
                                "weakness."
                            ),
                            severity="info",
                            confidence="high",
                            category="logging_and_monitoring",
                            cwe="CWE-1059",
                            remediation=(
                                "Publish /.well-known/security.txt with a contact address "
                                "and policy link, per RFC 9116."
                            ),
                            url=url,
                            evidence_summary="GET returned 404",
                            status_code=404,
                            discriminator="no-security-txt",
                        )
                    )
                continue

            if response.status_code not in (200, 206, 401, 403):
                continue
            # 401/403 means the path exists but is protected: worth reporting as
            # attack surface, not as an exposure.
            protected = response.status_code in (401, 403)
            body_sample = response.body[:200]
            if response.status_code == 200 and len(response.body.strip()) == 0:
                continue
            # An SPA that returns index.html for everything would otherwise make
            # every path look present.
            if (
                response.status_code == 200
                and "<!doctype html" in body_sample.lower()
                and (path.endswith((".env", ".git/config", ".htpasswd", "credentials")))
            ):
                continue

            findings.append(
                _Finding(
                    rule_id=f"web.exposed-path{path.replace('/', '.')}",
                    title=(
                        f"{path} is reachable" + (" but protected" if protected else " and served")
                    ),
                    description=(
                        f"A GET to {url} returned HTTP {response.status_code}. {why}"
                        + (
                            " The path requires authentication, so this is attack "
                            "surface to be aware of rather than a direct exposure."
                            if protected
                            else ""
                        )
                    ),
                    severity="info" if protected else severity,
                    confidence="medium",
                    category="information_disclosure" if not protected else "network_exposure",
                    cwe="CWE-200" if not protected else "CWE-668",
                    remediation=(
                        "Remove the file from the document root, or block the path at the "
                        "web server. Configuration files, version control directories and "
                        "profiling endpoints should never be web-reachable."
                    ),
                    url=url,
                    evidence_summary=f"HTTP {response.status_code} for {path}",
                    request=f"GET {url}",
                    response=response.evidence_response(300),
                    status_code=response.status_code,
                    owasp="A05:2021",
                    artifacts={"path": path, "protected": protected},
                    discriminator=f"exposed-path:{path}",
                )
            )
        return findings, checks

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(item: _Finding, ctx: EngineContext) -> ScanFinding:
        parsed = urlparse(item.url)
        return ScanFinding(
            engine="web",
            rule_id=item.rule_id,
            category=item.category,
            title=item.title,
            description=item.description,
            severity=item.severity,
            confidence=item.confidence,
            cwe=item.cwe,
            owasp_top10=item.owasp,
            remediation=item.remediation,
            reproduction=(
                f"{item.method} {item.url}"
                + (f"\n{item.request}" if item.request and "\n" in item.request else "")
            ),
            evidence=Evidence(
                summary=item.evidence_summary or item.title,
                request=item.request or f"{item.method} {item.url}",
                response=item.response,
                response_status=item.status_code,
                artifacts=item.artifacts,
            ),
            network_location=NetworkLocation(
                url=item.url,
                host=parsed.hostname,
                port=parsed.port,
                scheme=parsed.scheme,
                method=item.method,
                path=parsed.path or "/",
            ),
            correlation_discriminator=item.discriminator,
            target=ctx.target,
            references=[
                f"https://cwe.mitre.org/data/definitions/{item.cwe.split('-')[-1]}.html",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            raw={"rule_id": item.rule_id, **item.artifacts},
        )
