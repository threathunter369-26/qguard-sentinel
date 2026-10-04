"""The engine contract.

Every security engine subclasses :class:`SecurityEngine`. The contract is
deliberately narrow — an engine receives a target and a context, and returns a
result — so an engine can be rewritten, replaced or run out-of-process without
anything else changing.

Two rules are structural rather than advisory:

* **A failure is never reported as a clean result.** :class:`EngineResult`
  distinguishes ``completed``, ``degraded``, ``failed`` and ``unauthorized``,
  and the terminal non-success states require a stated reason.
* **Active engines cannot run without authorization.** An engine that sends
  traffic to a target declares ``is_passive = False``; the orchestrator then
  refuses to run it unless an approved authorization covers the target.
"""

from __future__ import annotations

import abc
import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from qguard_scanner.sdk.finding import ScanFinding, ScanTarget


class EngineStatus(StrEnum):
    """Terminal state of one engine run."""

    COMPLETED = "completed"
    DEGRADED = "degraded"
    """Produced results, but an input was unavailable so coverage is incomplete."""
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    UNAUTHORIZED = "unauthorized"
    """Refused because no approved authorization covered the target."""


class EngineCapability(StrEnum):
    """What an engine needs, so the orchestrator can gate it correctly."""

    NETWORK = "network"
    """Sends traffic to the target. Requires a test authorization."""
    FILESYSTEM = "filesystem"
    INTELLIGENCE = "intelligence"
    """Consults an external vulnerability database."""
    SANDBOX = "sandbox"
    """Parses untrusted artifacts and must run isolated from the API process."""
    INTRUSIVE = "intrusive"
    """May modify state or be noticeably disruptive. Needs explicit permission."""
    CREDENTIALS = "credentials"


@dataclass(frozen=True, slots=True)
class EngineMetadata:
    """Static description of an engine, used for discovery and the UI."""

    key: str
    name: str
    description: str
    version: str
    target_kinds: tuple[str, ...]
    capabilities: frozenset[EngineCapability] = field(default_factory=frozenset)
    categories: tuple[str, ...] = ()
    """Finding categories this engine can produce."""

    @property
    def is_passive(self) -> bool:
        return EngineCapability.NETWORK not in self.capabilities

    @property
    def requires_authorization(self) -> bool:
        return not self.is_passive

    @property
    def is_intrusive(self) -> bool:
        return EngineCapability.INTRUSIVE in self.capabilities

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "target_kinds": list(self.target_kinds),
            "capabilities": sorted(self.capabilities),
            "categories": list(self.categories),
            "is_passive": self.is_passive,
            "requires_authorization": self.requires_authorization,
            "is_intrusive": self.is_intrusive,
        }


ProgressCallback = Callable[[int, str], Awaitable[None]]


@dataclass(slots=True)
class ScopeVerdict:
    """The authorization decision for one target."""

    allowed: bool
    reason: str
    matched_rule: str | None = None
    authorization_id: str | None = None
    allows_intrusive: bool = False
    max_requests_per_second: float | None = None


#: Signature of the callable the orchestrator supplies for scope checks. The
#: engine never decides for itself whether a target is in scope.
ScopeChecker = Callable[[str], ScopeVerdict]


@dataclass(slots=True)
class EngineContext:
    """Everything an engine is given for one run.

    An engine reads from this and writes nothing outside it: no database
    access, no global state, no knowledge of other engines.
    """

    target: ScanTarget
    config: dict[str, Any] = field(default_factory=dict)
    workdir: Path | None = None
    """A scratch directory the engine owns for the duration of the run."""
    scope_checker: ScopeChecker | None = None
    progress: ProgressCallback | None = None
    max_requests_per_second: float = 10.0
    max_concurrency: int = 8
    http_timeout_seconds: float = 15.0
    user_agent: str = "QGuardSentinel/1.0 (authorized security assessment)"
    allow_intrusive: bool = False
    deadline_seconds: float | None = None
    cancelled: Callable[[], bool] | None = None

    _started_at: float = field(default_factory=time.monotonic, init=False)

    # ---------------------------------------------------------------- helpers
    def option(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    async def report_progress(self, percent: int, message: str) -> None:
        if self.progress is not None:
            await self.progress(max(0, min(100, percent)), message[:500])

    def check_scope(self, target: str) -> ScopeVerdict:
        """Ask the orchestrator whether a target may be contacted.

        Defaults to refusal: an engine running without a scope checker has no
        basis for believing a target is authorized, and failing open here would
        defeat the platform's main safety boundary.
        """
        if self.scope_checker is None:
            return ScopeVerdict(
                allowed=False,
                reason=(
                    "No authorization context was supplied for this run, so no target can "
                    "be contacted."
                ),
            )
        return self.scope_checker(target)

    def is_cancelled(self) -> bool:
        if self.cancelled is not None and self.cancelled():
            return True
        if self.deadline_seconds is not None:
            return (time.monotonic() - self._started_at) > self.deadline_seconds
        return False

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise asyncio.CancelledError("The engine run was cancelled or exceeded its deadline.")

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started_at


@dataclass(slots=True)
class EngineResult:
    """The outcome of one engine run.

    The status is always explicit. A scanner that could not do its job reports
    ``failed`` with the real reason, or ``degraded`` when it produced partial
    results — it never returns ``completed`` with an empty finding list, which
    would read as "nothing wrong here".
    """

    engine: str
    status: EngineStatus
    findings: list[ScanFinding] = field(default_factory=list)
    error_type: str | None = None
    error_message: str | None = None
    degraded_reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    scope_verdict: ScopeVerdict | None = None
    stats: dict[str, Any] = field(default_factory=dict)
    items_examined: int = 0
    checks_executed: int = 0
    requests_sent: int = 0
    duration_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.status is EngineStatus.FAILED and not self.error_message:
            raise ValueError(
                "A failed engine result must carry error_message stating the real reason."
            )
        if self.status is EngineStatus.DEGRADED and not self.degraded_reason:
            raise ValueError(
                "A degraded engine result must carry degraded_reason explaining what was "
                "unavailable and therefore which coverage is missing."
            )
        if self.status is EngineStatus.UNAUTHORIZED and self.scope_verdict is None:
            raise ValueError(
                "An unauthorized engine result must carry the scope verdict that refused it."
            )

    @property
    def succeeded(self) -> bool:
        return self.status in (EngineStatus.COMPLETED, EngineStatus.DEGRADED)

    @property
    def is_trustworthy(self) -> bool:
        """Whether an empty finding list from this run means 'nothing found'.

        Only a fully completed run supports that reading. Anything else means
        'we do not know', and the UI must present it that way.
        """
        return self.status is EngineStatus.COMPLETED

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.effective_severity()] += 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "status": str(self.status),
            "finding_count": len(self.findings),
            "severity_counts": self.severity_counts(),
            "error_type": self.error_type,
            "error_message": self.error_message,
            "degraded_reason": self.degraded_reason,
            "warnings": self.warnings,
            "items_examined": self.items_examined,
            "checks_executed": self.checks_executed,
            "requests_sent": self.requests_sent,
            "duration_seconds": round(self.duration_seconds, 3),
            "is_trustworthy": self.is_trustworthy,
            "stats": self.stats,
        }

    # ----------------------------------------------------------- constructors
    @classmethod
    def completed(cls, engine: str, findings: Sequence[ScanFinding], **kwargs: Any) -> EngineResult:
        return cls(engine=engine, status=EngineStatus.COMPLETED, findings=list(findings), **kwargs)

    @classmethod
    def degraded(
        cls, engine: str, findings: Sequence[ScanFinding], reason: str, **kwargs: Any
    ) -> EngineResult:
        return cls(
            engine=engine,
            status=EngineStatus.DEGRADED,
            findings=list(findings),
            degraded_reason=reason,
            **kwargs,
        )

    @classmethod
    def failed(cls, engine: str, error: BaseException | str, **kwargs: Any) -> EngineResult:
        if isinstance(error, BaseException):
            error_type = type(error).__name__
            message = str(error) or error_type
        else:
            error_type = "EngineError"
            message = error
        return cls(
            engine=engine,
            status=EngineStatus.FAILED,
            error_type=error_type,
            error_message=message,
            **kwargs,
        )

    @classmethod
    def unauthorized(cls, engine: str, verdict: ScopeVerdict, **kwargs: Any) -> EngineResult:
        return cls(
            engine=engine,
            status=EngineStatus.UNAUTHORIZED,
            scope_verdict=verdict,
            error_type="ScopeAuthorizationError",
            error_message=verdict.reason,
            **kwargs,
        )

    @classmethod
    def skipped(cls, engine: str, reason: str, **kwargs: Any) -> EngineResult:
        return cls(
            engine=engine,
            status=EngineStatus.SKIPPED,
            warnings=[reason],
            **kwargs,
        )


class SecurityEngine(abc.ABC):
    """Base class for every security assessment engine."""

    metadata: EngineMetadata

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if abc.ABC not in cls.__bases__ and not hasattr(cls, "metadata"):
            raise TypeError(f"{cls.__name__} must define a class-level `metadata`.")

    # ------------------------------------------------------------- properties
    @property
    def key(self) -> str:
        return self.metadata.key

    def accepts(self, target: ScanTarget) -> bool:
        """Whether this engine can assess the given target kind."""
        return target.kind in self.metadata.target_kinds

    # ----------------------------------------------------------------- hooks
    @abc.abstractmethod
    async def analyze(self, ctx: EngineContext) -> EngineResult:
        """Perform the assessment.

        Implementations return an :class:`EngineResult`. Raising is acceptable
        — :meth:`run` converts an exception into a ``failed`` result with the
        real reason attached — but returning a result with an accurate status
        is preferred because it can carry partial findings.
        """

    async def preflight(self, ctx: EngineContext) -> str | None:
        """Check prerequisites before the run.

        Return a reason string to skip the run, or ``None`` to proceed. Used to
        report a missing tool or an unreadable target honestly rather than
        producing an empty, apparently-clean result.
        """
        return None

    # ------------------------------------------------------------- execution
    async def run(self, ctx: EngineContext) -> EngineResult:
        """Execute the engine with the platform's guarantees applied.

        Enforces authorization for active engines, converts exceptions into an
        explicit failure with its reason, and records timing. Engines should
        not override this.
        """
        started = time.monotonic()

        try:
            if not self.accepts(ctx.target):
                return EngineResult.skipped(
                    self.key,
                    f"The {self.metadata.name} engine does not handle {ctx.target.kind!r} targets.",
                    duration_seconds=time.monotonic() - started,
                )

            # Active engines are gated on authorization before anything else
            # happens, so a refusal cannot be bypassed by an engine that
            # forgets to check.
            if self.metadata.requires_authorization:
                verdict = ctx.check_scope(ctx.target.value)
                if not verdict.allowed:
                    return EngineResult.unauthorized(
                        self.key, verdict, duration_seconds=time.monotonic() - started
                    )
                if self.metadata.is_intrusive and not (
                    verdict.allows_intrusive and ctx.allow_intrusive
                ):
                    return EngineResult.unauthorized(
                        self.key,
                        ScopeVerdict(
                            allowed=False,
                            reason=(
                                "This engine performs intrusive checks, which the "
                                "authorization covering this target does not permit."
                            ),
                            authorization_id=verdict.authorization_id,
                        ),
                        duration_seconds=time.monotonic() - started,
                    )
                if verdict.max_requests_per_second is not None:
                    # The authorization's rate limit is a ceiling, never a floor.
                    ctx.max_requests_per_second = min(
                        ctx.max_requests_per_second, verdict.max_requests_per_second
                    )

            if (skip_reason := await self.preflight(ctx)) is not None:
                return EngineResult.skipped(
                    self.key, skip_reason, duration_seconds=time.monotonic() - started
                )

            result = await self.analyze(ctx)
            result.duration_seconds = time.monotonic() - started
            if self.metadata.requires_authorization and result.scope_verdict is None:
                result.scope_verdict = ctx.check_scope(ctx.target.value)
            return result

        except asyncio.CancelledError:
            return EngineResult(
                engine=self.key,
                status=EngineStatus.CANCELLED,
                warnings=["The run was cancelled before it completed."],
                duration_seconds=time.monotonic() - started,
            )
        except Exception as exc:
            # The reason is preserved verbatim. An engine crash must surface as
            # "Scanner Status: Failed — <reason>", never as a clean result.
            return EngineResult.failed(self.key, exc, duration_seconds=time.monotonic() - started)
