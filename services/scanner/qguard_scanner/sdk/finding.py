"""The normalised finding every engine emits.

One shape for every source — SAST, DAST, SCA, secrets, mobile, container,
crypto — is what makes cross-engine correlation, compliance mapping and
reporting uniform. An engine that cannot fill a field leaves it unset rather
than inventing a value.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low", "tentative"]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
#: Matches CVSS v3.x and v4.0 vector strings.
_CVSS_RE = re.compile(r"^CVSS:(3\.[01]|4\.0)/")


class CodeLocation(BaseModel):
    """Where a finding sits in source code or a packaged artifact."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    start_column: int | None = Field(default=None, ge=1)
    symbol: str | None = None
    """Enclosing function, method or class, when the analyser knows it."""
    snippet: str | None = None
    """A few lines of surrounding code, for the reviewer's context."""
    commit_sha: str | None = None

    @model_validator(mode="after")
    def _check_lines(self) -> CodeLocation:
        if (
            self.end_line is not None
            and self.start_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line cannot precede start_line")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class NetworkLocation(BaseModel):
    """Where a finding sits on the network or in an HTTP interface."""

    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    scheme: str | None = None
    method: str | None = None
    path: str | None = None
    parameter: str | None = None
    parameter_location: str | None = None
    """``query``, ``body``, ``header``, ``cookie`` or ``path``."""
    protocol: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class Evidence(BaseModel):
    """Proof that a finding is real.

    Every finding must carry evidence. An engine that cannot substantiate an
    observation should not report it, because an unsubstantiated finding costs
    an analyst more time than it saves.

    Request and response captures are truncated and have credential-shaped
    values redacted before storage, so the platform does not accumulate a
    secondary copy of secrets or session tokens.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    """One sentence stating what was observed. Required."""
    request: str | None = None
    response: str | None = None
    response_status: int | None = None
    matched_value: str | None = None
    """The literal that triggered the rule. Redacted for secret findings."""
    code_snippet: str | None = None
    command: str | None = None
    """The exact check performed, so a reviewer can repeat it."""
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    artifacts: dict[str, Any] = Field(default_factory=dict)
    """Engine-specific structured detail: TLS parameters, manifest entries, ..."""

    @field_validator("request", "response", "code_snippet")
    @classmethod
    def _truncate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        limit = 16_384
        if len(value) > limit:
            return value[:limit] + f"\n… truncated, {len(value) - limit} more bytes"
        return value

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True, mode="json")


class ScanTarget(BaseModel):
    """What an engine was asked to assess."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    """``url``, ``host``, ``repository``, ``directory``, ``file``, ``image``,
    ``manifest``, ``package``, ``cloud_account``, ``kubernetes_manifest``."""
    value: str
    asset_id: str | None = None
    project_id: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover - diagnostics
        return f"{self.kind}:{self.value}"


class ScanFinding(BaseModel):
    """A single normalised security observation.

    ``fingerprint`` identifies this finding *as reported by this engine*, so a
    re-scan updates the existing row rather than inserting a duplicate.

    ``correlation_key`` identifies the underlying defect *independently of the
    engine*, so the same weakness found by SAST, DAST and SCA collapses into
    one managed vulnerability with three corroborating sources instead of three
    separate items to triage. An engine whose findings need a finer identity
    than category-plus-location sets ``correlation_discriminator``.
    """

    model_config = ConfigDict(extra="forbid")

    # --------------------------------------------------------------- identity
    engine: str
    rule_id: str
    """The engine's own stable rule identifier, e.g. ``py.subprocess-shell-true``."""
    category: str
    """A value from the platform's normalised finding taxonomy."""
    title: str = Field(min_length=3, max_length=500)
    description: str = Field(min_length=10)
    severity: Severity
    confidence: Confidence = "medium"

    # ------------------------------------------------------------- substance
    evidence: Evidence
    impact: str | None = None
    remediation: str | None = None
    reproduction: str | None = None
    references: list[str] = Field(default_factory=list)

    # -------------------------------------------------------------- location
    code_location: CodeLocation | None = None
    network_location: NetworkLocation | None = None
    target: ScanTarget | None = None

    # ------------------------------------------------------------- taxonomy
    cve: str | None = None
    cwe: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_version: str | None = None
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    owasp_top10: str | None = None
    owasp_api_top10: str | None = None
    owasp_asvs: list[str] = Field(default_factory=list)
    owasp_masvs: list[str] = Field(default_factory=list)
    mastg_tests: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    capec: list[str] = Field(default_factory=list)

    # ------------------------------------------------------- correlation hint
    correlation_discriminator: str | None = None
    """Extra identity for the underlying defect, supplied by the engine.

    Category plus location is the right identity for most findings: inserting a
    line above a vulnerable call should not present it as a new defect. But some
    categories put several genuinely distinct defects in one place — three
    different credentials committed to one settings file are three things to
    rotate, not one issue — and only the engine knows what distinguishes them.
    It passes that value here (for secrets, the credential's fingerprint) and
    correlation includes it.
    """

    # ------------------------------------------------------------- qualifiers
    is_exploitable: bool = False
    """Only true when exploitation was actually demonstrated, not inferred."""
    exploitability_note: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    # --------------------------------------------------------------- validators
    @field_validator("cve")
    @classmethod
    def _check_cve(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().upper()
        if not _CVE_RE.match(value):
            raise ValueError(f"{value!r} is not a valid CVE identifier (expected CVE-YYYY-NNNN)")
        return value

    @field_validator("cwe")
    @classmethod
    def _check_cwe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().upper()
        if value.isdigit():
            value = f"CWE-{value}"
        if not _CWE_RE.match(value):
            raise ValueError(f"{value!r} is not a valid CWE identifier (expected CWE-NNN)")
        return value

    @field_validator("cvss_vector")
    @classmethod
    def _check_cvss(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().upper()
        if not _CVSS_RE.match(value):
            raise ValueError(f"{value!r} is not a CVSS v3.x or v4.0 vector string")
        return value

    @model_validator(mode="after")
    def _require_a_location(self) -> ScanFinding:
        # A finding with no location cannot be verified or remediated, so one
        # of the location forms is mandatory.
        if self.code_location is None and self.network_location is None and self.target is None:
            raise ValueError(
                "A finding must carry a code location, a network location or a target."
            )
        return self

    @model_validator(mode="after")
    def _exploitability_needs_justification(self) -> ScanFinding:
        if self.is_exploitable and not self.exploitability_note:
            raise ValueError(
                "is_exploitable=True requires exploitability_note describing what was "
                "demonstrated; exploitability is never inferred."
            )
        return self

    @model_validator(mode="after")
    def _derive_cvss_version(self) -> ScanFinding:
        if self.cvss_vector and not self.cvss_version:
            self.cvss_version = "4.0" if self.cvss_vector.startswith("CVSS:4.0") else "3.1"
        return self

    # ------------------------------------------------------------ identifiers
    def fingerprint(self, *, asset_key: str | None = None) -> str:
        """Engine-specific identity of this finding.

        Includes the engine and rule so two engines reporting the same defect
        produce two distinct findings (each is a genuine, separate
        observation), while the same engine re-reporting it on a later scan
        produces the same fingerprint and updates in place.
        """
        parts = [
            self.engine,
            self.rule_id,
            asset_key or (self.target.value if self.target else ""),
            self._location_key(),
        ]
        return _digest(parts)

    def correlation_key(self, *, asset_key: str | None = None) -> str:
        """Engine-independent identity of the underlying defect.

        Deliberately excludes the engine and the rule id. A CVE is the
        strongest signal available, so when one is present it keys the cluster
        directly; otherwise the normalised category plus location is used.
        """
        anchor = self.cve or f"{self.category}|{self.cwe or ''}"
        parts = [
            anchor,
            asset_key or (self.target.value if self.target else ""),
            self._location_key(),
            self.correlation_discriminator or "",
        ]
        return _digest(parts)

    def _location_key(self) -> str:
        """Normalise the location so trivial variation does not split a cluster."""
        if self.code_location is not None:
            # The line number is excluded on purpose: inserting a line above a
            # vulnerable call would otherwise present it as a brand-new
            # finding on the next scan.
            return f"code:{self.code_location.file_path}:{self.code_location.symbol or ''}"
        if self.network_location is not None:
            loc = self.network_location
            # The path is kept but numeric and UUID path segments are
            # generalised, so `/orders/1001` and `/orders/1002` are recognised
            # as the same endpoint rather than thousands of findings.
            path = _generalise_path(loc.path or loc.url or "")
            return (
                f"net:{loc.host or ''}:{loc.port or ''}:{loc.method or ''}"
                f":{path}:{loc.parameter or ''}"
            )
        return f"target:{self.target.kind}:{self.target.value}" if self.target else "unknown"

    def effective_severity(self) -> Severity:
        """Severity, preferring the CVSS-derived rating when a score is present."""
        if self.cvss_score is not None:
            score = self.cvss_score
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0.0:
                return "low"
            return "info"
        return self.severity

    def to_payload(self) -> dict[str, Any]:
        """Flatten to the shape the ingestion layer stores."""
        return {
            "engine": self.engine,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "reproduction": self.reproduction,
            "references": self.references,
            "evidence": self.evidence.as_dict(),
            "location": self._location_payload(),
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "epss_score": self.epss_score,
            "owasp_top10": self.owasp_top10,
            "owasp_api_top10": self.owasp_api_top10,
            "owasp_asvs": self.owasp_asvs,
            "owasp_masvs": self.owasp_masvs,
            "mastg_tests": self.mastg_tests,
            "mitre_techniques": self.mitre_techniques,
            "capec": self.capec,
            "is_exploitable": self.is_exploitable,
            "exploitability_note": self.exploitability_note,
            "raw": self.raw,
        }

    def _location_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if self.code_location is not None:
            payload.update(self.code_location.as_dict())
        if self.network_location is not None:
            payload.update(self.network_location.as_dict())
        if self.target is not None:
            payload["target_kind"] = self.target.kind
            payload["target"] = self.target.value
        return payload


_NUMERIC_SEGMENT = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)"
)
_HASH_SEGMENT = re.compile(r"/[0-9a-fA-F]{32,64}(?=/|$)")


def _generalise_path(path: str) -> str:
    """Replace identifier-shaped path segments with a placeholder.

    Without this, a crawler walking ``/orders/{id}`` reports one finding per
    order and the real issue is buried in thousands of duplicates.
    """
    if "?" in path:
        path = path.split("?", 1)[0]
    path = _UUID_SEGMENT.sub("/{uuid}", path)
    path = _HASH_SEGMENT.sub("/{hash}", path)
    path = _NUMERIC_SEGMENT.sub("/{id}", path)
    return path


def _digest(parts: list[str]) -> str:
    canonical = json.dumps([p or "" for p in parts], separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
