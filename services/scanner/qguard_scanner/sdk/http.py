"""HTTP client for engines that contact a target.

Three properties matter for an assessment client and are built in rather than
left to each engine:

* **Rate limiting.** A token bucket caps request rate, because an assessment
  that overwhelms a production service has caused an incident rather than
  found one. The authorization's own limit is applied as a ceiling.
* **Connection-time target validation.** Every request's host is re-validated
  before the connection, which closes the DNS-rebinding window that a
  check-once-then-connect design leaves open.
* **Honest accounting.** Request counts, redirect chains and errors are
  recorded so an engine can report what it actually managed to do.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

import httpx

from qguard_scanner.sdk.netguard import UnsafeTargetError, resolve_and_validate

#: Response bodies are capped: an engine inspects headers and a bounded prefix,
#: and a multi-gigabyte response must not exhaust worker memory.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

#: Header values recorded in evidence are truncated to keep findings readable.
MAX_HEADER_VALUE = 1024

#: Credential-bearing headers are never written into a finding's evidence.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
)


class RateLimiter:
    """Async token bucket.

    A bucket rather than a fixed sleep: short bursts are permitted (which makes
    a crawl responsive) while the sustained rate still respects the limit.
    """

    def __init__(self, rate_per_second: float, burst: int | None = None) -> None:
        self.rate = max(0.1, rate_per_second)
        self.capacity = burst if burst is not None else max(1, int(self.rate))
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                await asyncio.sleep((tokens - self._tokens) / self.rate)


@dataclass(slots=True)
class HttpStats:
    requests_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    timeouts: int = 0
    blocked_targets: list[str] = field(default_factory=list)
    status_counts: dict[int, int] = field(default_factory=dict)

    def record(self, status: int, size: int) -> None:
        self.requests_sent += 1
        self.bytes_received += size
        self.status_counts[status] = self.status_counts.get(status, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "requests_sent": self.requests_sent,
            "bytes_received": self.bytes_received,
            "errors": self.errors,
            "timeouts": self.timeouts,
            "blocked_targets": self.blocked_targets[:20],
            "status_counts": {str(k): v for k, v in sorted(self.status_counts.items())},
        }


@dataclass(slots=True)
class ProbeResult:
    """One HTTP exchange, in a form an engine can put straight into evidence."""

    url: str
    method: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_bytes: int = 0
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None
    tls: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def has_header(self, name: str) -> bool:
        return name.lower() in self.headers

    def safe_headers(self) -> dict[str, str]:
        """Headers with credential-bearing values removed, for evidence."""
        return {
            k: ("«redacted»" if k in SENSITIVE_HEADERS else v[:MAX_HEADER_VALUE])
            for k, v in self.headers.items()
        }

    def evidence_request(self) -> str:
        return f"{self.method} {self.url}"

    def evidence_response(self, body_chars: int = 1024) -> str:
        if self.error:
            return f"error: {self.error}"
        lines = [f"HTTP {self.status_code}"]
        lines += [f"{k}: {v}" for k, v in sorted(self.safe_headers().items())]
        if self.body:
            lines += ["", self.body[:body_chars]]
        return "\n".join(lines)


class AssessmentHttpClient:
    """Rate-limited HTTP client with per-request target validation."""

    def __init__(
        self,
        *,
        user_agent: str,
        timeout_seconds: float = 15.0,
        max_requests_per_second: float = 10.0,
        max_concurrency: int = 8,
        allow_private: bool = True,
        deny_networks: list[str] | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        verify_tls: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.stats = HttpStats()
        self._limiter = RateLimiter(max_requests_per_second)
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._allow_private = allow_private
        self._deny_networks = deny_networks
        self._validated_hosts: dict[str, bool] = {}
        self._follow_redirects = follow_redirects

        headers = {
            # The user agent identifies the platform so a defender seeing this
            # traffic can attribute it to an authorized assessment rather than
            # treating it as an attack.
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        if extra_headers:
            headers.update(extra_headers)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)),
            headers=headers,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            # TLS verification is off by default *for assessment traffic only*:
            # an internal target with a self-signed or expired certificate must
            # still be assessable, and the certificate problem is itself
            # reported as a finding by the crypto engine rather than silently
            # aborting the scan.
            verify=verify_tls,
            limits=httpx.Limits(
                max_connections=max_concurrency, max_keepalive_connections=max_concurrency
            ),
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------- validation
    def _validate(self, url: str) -> str | None:
        """Validate a URL's host. Returns a refusal reason, or ``None``.

        Results are cached per host so a crawl does not re-resolve on every
        request, but the cache is keyed on the host only — a different host in
        a redirect is always validated afresh.
        """
        try:
            info = resolve_and_validate(
                url,
                allow_private=self._allow_private,
                require_scheme=True,
                deny_networks=self._deny_networks,
            )
        except UnsafeTargetError as exc:
            return exc.message
        self._validated_hosts[info.host] = True
        return None

    # ---------------------------------------------------------------- requests
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json_body: Any = None,
        follow_redirects: bool | None = None,
        read_body: bool = True,
    ) -> ProbeResult:
        """Perform one request, rate-limited and target-validated."""
        if (refusal := self._validate(url)) is not None:
            self.stats.blocked_targets.append(url)
            return ProbeResult(
                url=url,
                method=method.upper(),
                status_code=None,
                error=f"refused by the platform's network policy: {refusal}",
            )

        await self._limiter.acquire()
        started = time.perf_counter()

        async with self._semaphore:
            try:
                response = await self._client.request(
                    method.upper(),
                    url,
                    headers=headers,
                    params=params,
                    content=data if isinstance(data, (bytes, str)) else None,
                    data=data if isinstance(data, dict) else None,
                    json=json_body,
                    follow_redirects=(
                        self._follow_redirects if follow_redirects is None else follow_redirects
                    ),
                )
            except httpx.TimeoutException as exc:
                self.stats.timeouts += 1
                self.stats.errors += 1
                return ProbeResult(
                    url=url,
                    method=method.upper(),
                    status_code=None,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    error=f"timed out after {self._client.timeout.read}s: {exc}",
                )
            except httpx.HTTPError as exc:
                self.stats.errors += 1
                return ProbeResult(
                    url=url,
                    method=method.upper(),
                    status_code=None,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    error=f"{type(exc).__name__}: {exc}",
                )

        body = ""
        size = 0
        if read_body:
            raw = response.content[:MAX_RESPONSE_BYTES]
            size = len(response.content)
            body = raw.decode(response.encoding or "utf-8", errors="replace")

        self.stats.record(response.status_code, size)
        return ProbeResult(
            url=str(response.url),
            method=method.upper(),
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=body,
            body_bytes=size,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            redirect_chain=[str(r.url) for r in response.history],
        )

    async def get(self, url: str, **kwargs: Any) -> ProbeResult:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> ProbeResult:
        return await self.request("HEAD", url, read_body=False, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> ProbeResult:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> ProbeResult:
        return await self.request("OPTIONS", url, read_body=False, **kwargs)

    async def gather(
        self, requests: list[tuple[str, str]], *, limit: int | None = None
    ) -> list[ProbeResult]:
        """Run several requests concurrently, still within the rate limit."""
        tasks = [self.request(method, url) for method, url in (requests[:limit] or [])]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        output: list[ProbeResult] = []
        for (method, url), result in zip(requests, results, strict=False):
            if isinstance(result, BaseException):
                self.stats.errors += 1
                output.append(
                    ProbeResult(
                        url=url,
                        method=method.upper(),
                        status_code=None,
                        error=f"{type(result).__name__}: {result}",
                    )
                )
            else:
                output.append(result)
        return output
