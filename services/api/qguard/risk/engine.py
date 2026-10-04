"""Risk scoring.

A risk score is only useful if the person looking at it can see why it says
what it says, so every component is recorded alongside the result: the raw
inputs, the weight applied, the contribution, and a sentence of explanation.
``Vulnerability.risk_factors`` holds that breakdown, and the API returns it
with the score. Nothing here is hidden or fudged.

The model is a weighted sum of eight factors, each normalised to 0-1, then
scaled to 0-100 and adjusted by multipliers for conditions that genuinely
change exposure (internet reachability, demonstrated exploitation,
compensating controls). Weights are configurable per organization; the
defaults below are the starting point.

Where an input is unknown the factor contributes its *neutral* value and says
so in the breakdown, rather than being silently treated as zero — which would
make an unassessed asset look safe.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.common.enums import (
    OPEN_VULNERABILITY_STATUSES,
    Criticality,
    DataSensitivity,
    Severity,
)
from qguard.common.logging import get_logger
from qguard.models.assets import Asset
from qguard.models.findings import Vulnerability

log = get_logger(__name__)

#: Factor weights. They sum to 1.0 so the weighted score is directly a 0-1
#: value before scaling.
DEFAULT_WEIGHTS: dict[str, float] = {
    "severity": 0.26,
    "exploitability": 0.18,
    "asset_criticality": 0.16,
    "exposure": 0.13,
    "data_sensitivity": 0.10,
    "threat_intelligence": 0.09,
    "corroboration": 0.04,
    "age": 0.04,
}

SEVERITY_SCORES: dict[str, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH: 0.78,
    Severity.MEDIUM: 0.50,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
}

CRITICALITY_SCORES: dict[str, float] = {
    Criticality.CRITICAL: 1.00,
    Criticality.HIGH: 0.75,
    Criticality.MEDIUM: 0.45,
    Criticality.LOW: 0.20,
}

SENSITIVITY_SCORES: dict[str, float] = {
    DataSensitivity.RESTRICTED: 1.00,
    DataSensitivity.CONFIDENTIAL: 0.75,
    DataSensitivity.INTERNAL: 0.45,
    DataSensitivity.PUBLIC: 0.15,
    #: An unclassified asset is treated as mid-sensitivity, not as public.
    #: Assuming "public" would understate risk for every asset nobody has
    #: classified yet, which in most estates is most of them.
    DataSensitivity.UNKNOWN: 0.50,
}

#: Multipliers applied after the weighted sum. Each is bounded so no single
#: condition can dominate the score on its own.
MULTIPLIERS: dict[str, float] = {
    "internet_facing": 1.25,
    "no_authentication_required": 1.15,
    "known_exploited": 1.30,
    "demonstrated_exploitation": 1.20,
    "sla_breached": 1.10,
}

#: Each compensating control reduces the score, with diminishing returns, and
#: the total reduction is floored so controls can never zero out real risk.
COMPENSATING_CONTROL_FACTOR: float = 0.92
MIN_CONTROL_MULTIPLIER: float = 0.70

RECOGNISED_CONTROLS: frozenset[str] = frozenset(
    {
        "waf",
        "mfa",
        "network_segmentation",
        "ip_allowlist",
        "rate_limiting",
        "runtime_protection",
        "egress_filtering",
        "privileged_access_management",
        "monitoring_and_alerting",
        "backup_and_recovery",
    }
)


@dataclass(slots=True)
class Factor:
    """One component of a risk score, with its reasoning attached."""

    key: str
    label: str
    value: float
    weight: float
    explanation: str
    inputs: dict[str, Any] = field(default_factory=dict)
    is_estimated: bool = False
    """True when an input was unknown and a neutral default was used."""

    @property
    def contribution(self) -> float:
        return self.value * self.weight

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": round(self.value, 4),
            "weight": round(self.weight, 4),
            "contribution": round(self.contribution * 100, 2),
            "explanation": self.explanation,
            "inputs": self.inputs,
            "is_estimated": self.is_estimated,
        }


@dataclass(slots=True)
class Multiplier:
    key: str
    label: str
    value: float
    applied: bool
    explanation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": round(self.value, 4),
            "applied": self.applied,
            "explanation": self.explanation,
        }


@dataclass(slots=True)
class RiskAssessment:
    """A risk score and the complete derivation behind it."""

    score: float
    band: str
    factors: list[Factor]
    multipliers: list[Multiplier]
    base_score: float
    model_version: str = "1.0"
    computed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    confidence: str = "high"
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "band": self.band,
            "base_score": round(self.base_score, 2),
            "model_version": self.model_version,
            "computed_at": self.computed_at.isoformat(),
            "confidence": self.confidence,
            "factors": [f.as_dict() for f in self.factors],
            "multipliers": [m.as_dict() for m in self.multipliers],
            "applied_multipliers": [m.key for m in self.multipliers if m.applied],
            "notes": self.notes,
            "calculation": self._calculation_text(),
        }

    def _calculation_text(self) -> str:
        """A one-line, reproducible statement of the arithmetic.

        Written out in full so the number can be checked by hand — a risk score
        nobody can reproduce is a number nobody should act on.
        """
        parts = [
            f"{f.key}({f.value:.2f} x {f.weight:.2f} = {f.contribution * 100:.1f})"
            for f in self.factors
        ]
        text = f"base = {' + '.join(parts)} = {self.base_score:.1f}"

        amplifiers = [m for m in self.multipliers if m.applied and m.value > 1.0]
        reducers = [m for m in self.multipliers if m.applied and m.value < 1.0]
        if amplifiers:
            combined = 1.0
            for m in amplifiers:
                combined *= m.value
            names = ", ".join(m.key for m in amplifiers)
            text += (
                f"; amplified = {self.base_score:.1f} + (100 - {self.base_score:.1f})"
                f" x (1 - 1/{combined:.3f}) [{names}]"
            )
        for m in reducers:
            text += f"; reduced x {m.value:.2f} [{m.key}]"
        return f"{text} = {self.score:.1f}"


def score_band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


def posture_grade(security_score: float) -> str:
    """Map a 0-100 security score to a letter grade using fixed thresholds."""
    if security_score >= 90:
        return "A"
    if security_score >= 80:
        return "B"
    if security_score >= 70:
        return "C"
    if security_score >= 60:
        return "D"
    if security_score >= 50:
        return "E"
    return "F"


class RiskEngine:
    """Computes vulnerability, asset and organization risk."""

    def __init__(self, session: AsyncSession, weights: dict[str, float] | None = None) -> None:
        self.session = session
        self.weights = {**DEFAULT_WEIGHTS, **(weights or {})}
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.001:
            # Normalise rather than refuse, so a tenant tuning one weight does
            # not have to rebalance all eight by hand.
            self.weights = {k: v / total for k, v in self.weights.items()}

    # ------------------------------------------------------ vulnerability risk
    def assess_vulnerability(
        self,
        vulnerability: Vulnerability,
        asset: Asset | None = None,
    ) -> RiskAssessment:
        """Score one vulnerability in the context of the asset it affects."""
        factors: list[Factor] = []
        notes: list[str] = []
        severity = vulnerability.effective_severity

        # ---- 1. Severity --------------------------------------------------
        factors.append(
            Factor(
                key="severity",
                label="Severity",
                value=SEVERITY_SCORES.get(severity, 0.5),
                weight=self.weights["severity"],
                explanation=f"The issue is rated {severity}.",
                inputs={
                    "severity": severity,
                    "cvss_score": float(vulnerability.cvss_score)
                    if vulnerability.cvss_score is not None
                    else None,
                    "overridden": vulnerability.severity_override is not None,
                },
            )
        )

        # ---- 2. Exploitability --------------------------------------------
        if vulnerability.is_exploitable:
            exploit_value, exploit_note = 1.0, ("Exploitation was demonstrated against this asset.")
        elif vulnerability.epss_score is not None:
            exploit_value = min(1.0, float(vulnerability.epss_score) * 2.5)
            exploit_note = (
                f"EPSS puts the probability of exploitation in the next 30 days at "
                f"{float(vulnerability.epss_score):.1%}."
            )
        elif vulnerability.cvss_vector and "/AC:L" in vulnerability.cvss_vector:
            exploit_value, exploit_note = 0.65, ("The CVSS vector reports low attack complexity.")
        else:
            exploit_value, exploit_note = (
                0.40,
                ("No exploitability data is available, so a neutral value is used."),
            )
        factors.append(
            Factor(
                key="exploitability",
                label="Exploitability",
                value=exploit_value,
                weight=self.weights["exploitability"],
                explanation=exploit_note,
                inputs={
                    "is_exploitable": vulnerability.is_exploitable,
                    "epss_score": float(vulnerability.epss_score)
                    if vulnerability.epss_score is not None
                    else None,
                    "cvss_vector": vulnerability.cvss_vector,
                },
                is_estimated=exploit_value == 0.40,
            )
        )

        # ---- 3. Asset criticality -----------------------------------------
        if asset is not None:
            criticality_value = CRITICALITY_SCORES.get(asset.criticality, 0.45)
            criticality_note = (
                f"The affected asset {asset.name!r} is classified {asset.criticality} criticality."
            )
            estimated = False
        else:
            criticality_value, estimated = 0.45, True
            criticality_note = (
                "The affected asset is not recorded, so medium criticality is assumed."
            )
            notes.append(
                "This issue is not linked to an inventoried asset, so asset-derived "
                "factors are estimates. Linking it will sharpen the score."
            )
        factors.append(
            Factor(
                key="asset_criticality",
                label="Asset criticality",
                value=criticality_value,
                weight=self.weights["asset_criticality"],
                explanation=criticality_note,
                inputs={"criticality": asset.criticality if asset else None},
                is_estimated=estimated,
            )
        )

        # ---- 4. Exposure ---------------------------------------------------
        if asset is not None:
            if asset.internet_facing and not asset.requires_authentication:
                exposure_value = 1.00
                exposure_note = "The asset is internet-facing and reachable without authentication."
            elif asset.internet_facing:
                exposure_value = 0.80
                exposure_note = "The asset is internet-facing but requires authentication."
            elif not asset.requires_authentication:
                exposure_value = 0.45
                exposure_note = "The asset is internal but reachable without authentication."
            else:
                exposure_value = 0.25
                exposure_note = "The asset is internal and requires authentication."
            exposure_estimated = False
        else:
            exposure_value, exposure_estimated = 0.50, True
            exposure_note = "Exposure is unknown, so a neutral value is used."
        factors.append(
            Factor(
                key="exposure",
                label="Exposure",
                value=exposure_value,
                weight=self.weights["exposure"],
                explanation=exposure_note,
                inputs={
                    "internet_facing": asset.internet_facing if asset else None,
                    "requires_authentication": asset.requires_authentication if asset else None,
                },
                is_estimated=exposure_estimated,
            )
        )

        # ---- 5. Data sensitivity -------------------------------------------
        sensitivity = asset.data_sensitivity if asset else DataSensitivity.UNKNOWN
        factors.append(
            Factor(
                key="data_sensitivity",
                label="Data sensitivity",
                value=SENSITIVITY_SCORES.get(sensitivity, 0.50),
                weight=self.weights["data_sensitivity"],
                explanation=(
                    f"The asset handles data classified {sensitivity.replace('_', ' ')}."
                    if sensitivity != DataSensitivity.UNKNOWN
                    else (
                        "The asset's data classification is not recorded, so mid "
                        "sensitivity is assumed rather than public."
                    )
                ),
                inputs={"data_sensitivity": sensitivity},
                is_estimated=sensitivity == DataSensitivity.UNKNOWN,
            )
        )

        # ---- 6. Threat intelligence ----------------------------------------
        if vulnerability.is_known_exploited:
            intel_value = 1.00
            intel_note = (
                "This CVE is in the CISA Known Exploited Vulnerabilities catalogue — it is "
                "being exploited in the wild."
            )
        elif vulnerability.epss_score is not None and float(vulnerability.epss_score) > 0.1:
            intel_value = 0.70
            intel_note = (
                f"EPSS is elevated at {float(vulnerability.epss_score):.1%}, indicating "
                "active interest."
            )
        elif vulnerability.cve:
            intel_value = 0.35
            intel_note = "A CVE is assigned but no active exploitation is reported."
        else:
            intel_value = 0.20
            intel_note = "No public CVE, so no external intelligence applies to this issue."
        factors.append(
            Factor(
                key="threat_intelligence",
                label="Threat intelligence",
                value=intel_value,
                weight=self.weights["threat_intelligence"],
                explanation=intel_note,
                inputs={
                    "known_exploited": vulnerability.is_known_exploited,
                    "cve": vulnerability.cve,
                    "epss_score": float(vulnerability.epss_score)
                    if vulnerability.epss_score is not None
                    else None,
                },
            )
        )

        # ---- 7. Corroboration ----------------------------------------------
        confirmations = max(1, vulnerability.confirmation_count)
        corroboration_value = min(1.0, 0.4 + 0.3 * (confirmations - 1))
        factors.append(
            Factor(
                key="corroboration",
                label="Independent corroboration",
                value=corroboration_value,
                weight=self.weights["corroboration"],
                explanation=(
                    f"Confirmed by {confirmations} independent engine(s): "
                    f"{', '.join(vulnerability.source_engines) or 'unknown'}."
                    + (
                        " A single source carries more uncertainty."
                        if confirmations == 1
                        else " Multiple independent detections reduce the chance of a "
                        "false positive."
                    )
                ),
                inputs={
                    "confirmation_count": confirmations,
                    "source_engines": list(vulnerability.source_engines),
                },
            )
        )

        # ---- 8. Age ---------------------------------------------------------
        age_days = max(0, (datetime.now(UTC) - _as_aware(vulnerability.first_seen_at)).days)
        age_value = min(1.0, age_days / 180)
        factors.append(
            Factor(
                key="age",
                label="Age",
                value=age_value,
                weight=self.weights["age"],
                explanation=(
                    f"Open for {age_days} day(s). Unresolved issues accumulate risk because "
                    "the window of opportunity stays open."
                ),
                inputs={"age_days": age_days, "first_seen_at": vulnerability.first_seen_at},
            )
        )

        base_score = sum(f.contribution for f in factors) * 100

        # ---- Multipliers ----------------------------------------------------
        # Amplifying multipliers are applied to the *headroom* between the base
        # score and 100 rather than to the score directly:
        #
        #     amplified = base + (100 - base) * (1 - 1 / M)
        #
        # Plain multiplication saturates: a base of 70 and a base of 94 both
        # clamp to 100 once two or three multipliers stack, which makes a
        # high-severity issue indistinguishable from a critical one that is
        # KEV-listed and demonstrably exploitable — and makes compensating
        # controls invisible. This form approaches 100 asymptotically instead,
        # so the ordering that drives remediation priority survives.
        multipliers = self._build_multipliers(vulnerability, asset)
        amplification = 1.0
        for multiplier in multipliers:
            if multiplier.applied:
                amplification *= multiplier.value

        score = base_score
        if amplification > 1.0:
            score = base_score + (100.0 - base_score) * (1.0 - 1.0 / amplification)

        # Reductions apply to the score directly, so a recorded control always
        # produces a visible decrease.
        control_multiplier, control_note = self._compensating_controls(asset)
        if control_multiplier < 1.0:
            multipliers.append(
                Multiplier(
                    key="compensating_controls",
                    label="Compensating controls",
                    value=control_multiplier,
                    applied=True,
                    explanation=control_note,
                )
            )
            score *= control_multiplier

        score = max(0.0, min(100.0, score))

        estimated_count = sum(1 for f in factors if f.is_estimated)
        confidence = "high" if estimated_count == 0 else "medium" if estimated_count <= 2 else "low"
        if estimated_count:
            notes.append(
                f"{estimated_count} of {len(factors)} factors used a neutral default "
                "because the underlying data is not recorded."
            )

        return RiskAssessment(
            score=score,
            band=score_band(score),
            factors=factors,
            multipliers=multipliers,
            base_score=base_score,
            confidence=confidence,
            notes=notes,
        )

    def _build_multipliers(
        self, vulnerability: Vulnerability, asset: Asset | None
    ) -> list[Multiplier]:
        internet_facing = bool(asset and asset.internet_facing)
        unauthenticated = bool(asset and not asset.requires_authentication)
        return [
            Multiplier(
                key="internet_facing",
                label="Internet-facing asset",
                value=MULTIPLIERS["internet_facing"],
                applied=internet_facing,
                explanation=(
                    "The asset is reachable from the internet, so the attacker population "
                    "is unbounded."
                    if internet_facing
                    else "The asset is not internet-facing."
                ),
            ),
            Multiplier(
                key="no_authentication_required",
                label="No authentication required",
                value=MULTIPLIERS["no_authentication_required"],
                applied=unauthenticated,
                explanation=(
                    "No authentication stands between an attacker and this asset."
                    if unauthenticated
                    else "Authentication is required to reach the asset."
                ),
            ),
            Multiplier(
                key="known_exploited",
                label="Known exploited vulnerability",
                value=MULTIPLIERS["known_exploited"],
                applied=vulnerability.is_known_exploited,
                explanation=(
                    "Listed in the CISA KEV catalogue — exploitation is confirmed in the wild."
                    if vulnerability.is_known_exploited
                    else "Not listed as known-exploited."
                ),
            ),
            Multiplier(
                key="demonstrated_exploitation",
                label="Exploitation demonstrated",
                value=MULTIPLIERS["demonstrated_exploitation"],
                applied=vulnerability.is_exploitable,
                explanation=(
                    "The platform or a tester demonstrated exploitation against this asset."
                    if vulnerability.is_exploitable
                    else "Exploitation has not been demonstrated here."
                ),
            ),
            Multiplier(
                key="sla_breached",
                label="Remediation SLA breached",
                value=MULTIPLIERS["sla_breached"],
                applied=bool(vulnerability.sla_breached),
                explanation=(
                    "The remediation deadline has passed."
                    if vulnerability.sla_breached
                    else "Within the remediation deadline."
                ),
            ),
        ]

    @staticmethod
    def _compensating_controls(asset: Asset | None) -> tuple[float, str]:
        """Reduce the score for recorded mitigations, with a floor.

        Controls reduce risk but never eliminate it: a WAF in front of an
        injection flaw lowers the chance of exploitation without fixing the
        flaw, so the reduction is capped.
        """
        if asset is None or not asset.compensating_controls:
            return 1.0, "No compensating controls are recorded for this asset."
        recognised = [c for c in asset.compensating_controls if c in RECOGNISED_CONTROLS]
        if not recognised:
            return 1.0, (
                "The asset lists controls, but none are recognised by the risk model: "
                f"{', '.join(asset.compensating_controls)}."
            )
        multiplier = max(MIN_CONTROL_MULTIPLIER, COMPENSATING_CONTROL_FACTOR ** len(recognised))
        return multiplier, (
            f"{len(recognised)} compensating control(s) recorded "
            f"({', '.join(recognised)}), reducing the score by "
            f"{(1 - multiplier) * 100:.0f}%. Controls reduce exposure but do not remove "
            "the underlying defect, so the reduction is capped at "
            f"{(1 - MIN_CONTROL_MULTIPLIER) * 100:.0f}%."
        )

    # -------------------------------------------------------------- asset risk
    async def assess_asset(self, org_id: uuid.UUID, asset_id: uuid.UUID) -> dict[str, Any]:
        """Aggregate an asset's open vulnerabilities into a posture score.

        ``security_score`` is deliberately *not* ``100 - risk``: it is driven by
        the worst open issue and the volume of issues, because an asset with one
        critical flaw is not in good shape merely because it has few findings.
        """
        asset = (
            await self.session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
            )
        ).scalar_one_or_none()
        if asset is None:
            return {"error": "The asset was not found."}

        vulnerabilities = list(
            (
                await self.session.execute(
                    select(Vulnerability).where(
                        Vulnerability.org_id == org_id,
                        Vulnerability.asset_id == asset_id,
                        Vulnerability.status.in_(OPEN_VULNERABILITY_STATUSES),
                    )
                )
            )
            .scalars()
            .all()
        )

        if not vulnerabilities:
            assessed = asset.last_assessed_at is not None
            return {
                "asset_id": str(asset_id),
                "risk_score": 0.0 if assessed else None,
                "security_score": 100.0 if assessed else None,
                "posture_grade": "A" if assessed else None,
                # An unassessed asset is reported as unknown, never as clean:
                # claiming a perfect score for something nobody has looked at
                # is exactly the kind of false assurance to avoid.
                "status": "assessed_clean" if assessed else "never_assessed",
                "explanation": (
                    "No open vulnerabilities were found in the most recent assessment."
                    if assessed
                    else (
                        "This asset has never been assessed, so its posture is unknown. "
                        "It is not counted as secure."
                    )
                ),
                "counts": dict.fromkeys(("critical", "high", "medium", "low", "info"), 0),
                "open_vulnerability_count": 0,
            }

        assessments = [(v, self.assess_vulnerability(v, asset)) for v in vulnerabilities]
        scores = sorted((a.score for _, a in assessments), reverse=True)

        # The asset's risk is the worst issue plus a diminishing contribution
        # from the rest, so a long tail of medium issues cannot outrank one
        # critical, while volume still matters.
        risk_score = scores[0]
        for index, score in enumerate(scores[1:], start=1):
            risk_score += score * (0.5**index) * 0.5
        risk_score = min(100.0, risk_score)

        counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
        for vulnerability in vulnerabilities:
            counts[vulnerability.effective_severity] = (
                counts.get(vulnerability.effective_severity, 0) + 1
            )

        penalty = (
            counts["critical"] * 25 + counts["high"] * 12 + counts["medium"] * 4 + counts["low"] * 1
        )
        security_score = max(0.0, 100.0 - min(100.0, penalty))

        return {
            "asset_id": str(asset_id),
            "asset_name": asset.name,
            "risk_score": round(risk_score, 2),
            "security_score": round(security_score, 2),
            "posture_grade": posture_grade(security_score),
            "status": "assessed",
            "counts": counts,
            "open_vulnerability_count": len(vulnerabilities),
            "exploitable_count": sum(1 for v in vulnerabilities if v.is_exploitable),
            "known_exploited_count": sum(1 for v in vulnerabilities if v.is_known_exploited),
            "highest_risk": [
                {
                    "vulnerability_id": str(v.id),
                    "reference": v.reference,
                    "title": v.title,
                    "severity": v.effective_severity,
                    "risk_score": round(a.score, 2),
                    "band": a.band,
                }
                for v, a in sorted(assessments, key=lambda p: -p[1].score)[:5]
            ],
            "explanation": (
                f"Driven by the highest-risk open issue ({scores[0]:.1f}) with a "
                f"diminishing contribution from {len(scores) - 1} further open issue(s). "
                f"The security score deducts {penalty} points for "
                f"{counts['critical']} critical, {counts['high']} high, "
                f"{counts['medium']} medium and {counts['low']} low findings."
            ),
        }

    # --------------------------------------------------------- persistence
    async def recalculate_vulnerability(
        self, org_id: uuid.UUID, vulnerability_id: uuid.UUID
    ) -> RiskAssessment | None:
        vulnerability = (
            await self.session.execute(
                select(Vulnerability).where(
                    Vulnerability.id == vulnerability_id, Vulnerability.org_id == org_id
                )
            )
        ).scalar_one_or_none()
        if vulnerability is None:
            return None
        asset = None
        if vulnerability.asset_id:
            asset = (
                await self.session.execute(select(Asset).where(Asset.id == vulnerability.asset_id))
            ).scalar_one_or_none()

        assessment = self.assess_vulnerability(vulnerability, asset)
        vulnerability.risk_score = assessment.score
        vulnerability.risk_factors = assessment.as_dict()
        vulnerability.risk_calculated_at = assessment.computed_at
        vulnerability.sla_breached = bool(
            vulnerability.due_at and _as_aware(vulnerability.due_at) < datetime.now(UTC)
        )
        return assessment

    async def recalculate_org(self, org_id: uuid.UUID, *, batch_size: int = 500) -> int:
        """Rescore every open vulnerability in an organization.

        Runs as a background job because risk depends on inputs that change
        outside any scan — a reclassified asset, a newly published KEV entry —
        so scores must be refreshed independently of scanning.
        """
        processed = 0
        asset_cache: dict[uuid.UUID, Asset | None] = {}

        while True:
            rows = list(
                (
                    await self.session.execute(
                        select(Vulnerability)
                        .where(
                            Vulnerability.org_id == org_id,
                            Vulnerability.status.in_(OPEN_VULNERABILITY_STATUSES),
                        )
                        .order_by(Vulnerability.id)
                        .offset(processed)
                        .limit(batch_size)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                break

            missing = {v.asset_id for v in rows if v.asset_id and v.asset_id not in asset_cache}
            if missing:
                for asset in (
                    (await self.session.execute(select(Asset).where(Asset.id.in_(missing))))
                    .scalars()
                    .all()
                ):
                    asset_cache[asset.id] = asset
                for asset_id in missing:
                    asset_cache.setdefault(asset_id, None)

            now = datetime.now(UTC)
            for vulnerability in rows:
                asset = asset_cache.get(vulnerability.asset_id) if vulnerability.asset_id else None
                assessment = self.assess_vulnerability(vulnerability, asset)
                vulnerability.risk_score = assessment.score
                vulnerability.risk_factors = assessment.as_dict()
                vulnerability.risk_calculated_at = now
                vulnerability.sla_breached = bool(
                    vulnerability.due_at and _as_aware(vulnerability.due_at) < now
                )
            processed += len(rows)
            await self.session.flush()

        log.info("risk.org_recalculated", org_id=str(org_id), vulnerabilities=processed)
        return processed


def _as_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
