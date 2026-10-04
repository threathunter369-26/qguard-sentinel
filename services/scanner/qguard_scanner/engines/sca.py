"""Software composition analysis.

Inventories dependencies, then checks them against public vulnerability data.
Three behaviours matter:

* **Lockfiles beat manifests.** A manifest states a version *range*; a lockfile
  states what is installed. Matching a CVE against a range produces findings
  that may not apply to the build that ships, so an unpinned requirement is
  recorded as a dependency but reported as unverified rather than matched.

* **An unreachable vulnerability database degrades the run.** If OSV cannot be
  reached, the result is ``degraded`` with that reason — never ``completed``
  with no findings, which would read as "your dependencies are clean" when the
  truth is "nothing was checked".

* **Licence risk is reported separately from vulnerability risk.** A strong
  copyleft licence in a proprietary product is a real problem, but it is a
  legal one, and conflating it with a CVE makes both harder to act on.
"""

from __future__ import annotations

import asyncio
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from qguard_scanner.engines.sca_parsers import (
    MANIFEST_FILES,
    Dependency,
    ParseOutcome,
    parse_file,
)
from qguard_scanner.rules.secret_patterns import SKIP_DIR_NAMES
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import CodeLocation, Evidence, ScanFinding
from qguard_scanner.sdk.registry import register_engine

DEFAULT_OSV_URL = "https://api.osv.dev/v1"

#: OSV accepts up to 1000 queries per batch; 500 keeps request bodies modest.
OSV_BATCH_SIZE = 500

#: Licences that conflict with proprietary distribution. Reported as a licence
#: risk, not a vulnerability — the two need different people to resolve them.
COPYLEFT_LICENSES: dict[str, tuple[str, str]] = {
    "AGPL-3.0": (
        "high",
        "Network copyleft: use over a network triggers the source-disclosure obligation.",
    ),
    "AGPL-3.0-only": ("high", "Network copyleft obligation."),
    "AGPL-3.0-or-later": ("high", "Network copyleft obligation."),
    "GPL-3.0": (
        "high",
        "Strong copyleft: derivative works must be distributed under the GPL.",
    ),
    "GPL-3.0-only": ("high", "Strong copyleft obligation."),
    "GPL-2.0": ("high", "Strong copyleft obligation."),
    "SSPL-1.0": (
        "high",
        "Server Side Public License; generally incompatible with commercial SaaS.",
    ),
    "LGPL-3.0": (
        "medium",
        "Weak copyleft: dynamic linking is usually acceptable, static linking is not.",
    ),
    "LGPL-2.1": ("medium", "Weak copyleft obligation."),
    "MPL-2.0": ("low", "File-level copyleft: modified files must be shared."),
    "EPL-2.0": ("low", "File-level copyleft obligation."),
    "CC-BY-NC-4.0": ("high", "Non-commercial only; prohibits commercial use."),
    "BUSL-1.1": (
        "high",
        "Business Source License: time-delayed open source with usage restrictions.",
    ),
    "Commons-Clause": ("high", "Prohibits selling the software."),
}

OSV_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


@dataclass(slots=True)
class VulnerabilityMatch:
    """One advisory affecting one dependency."""

    dependency: Dependency
    advisory_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str = "medium"
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cve: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published: str | None = None


class OsvClient:
    """Minimal OSV.dev client.

    OSV is used because it aggregates ecosystem-native advisories (GHSA, PYSEC,
    RUSTSEC, GO) as well as CVEs, and because it is queryable without an API
    key — which matters for a platform that must work in an air-gapped
    deployment with the same code path.
    """

    def __init__(self, base_url: str = DEFAULT_OSV_URL, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.requests_sent = 0

    async def query_batch(
        self, dependencies: list[Dependency]
    ) -> tuple[dict[tuple[str, str, str], list[dict[str, Any]]], str | None]:
        """Query OSV for a set of dependencies.

        Returns ``(results, error)``. A non-None error means the lookup did not
        complete and the caller must degrade the run rather than report clean.
        """
        results: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        queries = [
            {
                "package": {"name": d.name, "ecosystem": d.ecosystem},
                "version": d.version,
            }
            for d in dependencies
        ]
        if not queries:
            return results, None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for offset in range(0, len(queries), OSV_BATCH_SIZE):
                    chunk = queries[offset : offset + OSV_BATCH_SIZE]
                    response = await client.post(
                        f"{self.base_url}/querybatch", json={"queries": chunk}
                    )
                    self.requests_sent += 1
                    if response.status_code != 200:
                        return results, (
                            f"OSV returned HTTP {response.status_code} for a batch of "
                            f"{len(chunk)} package queries"
                        )
                    payload = response.json()
                    for dependency, result in zip(
                        dependencies[offset : offset + OSV_BATCH_SIZE],
                        payload.get("results", []),
                        strict=False,
                    ):
                        vulns = result.get("vulns") or []
                        if vulns:
                            results[dependency.key] = vulns
        except (httpx.HTTPError, ValueError) as exc:
            return results, f"{type(exc).__name__}: {exc}"

        return results, None

    async def fetch_details(self, advisory_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch full advisory records. Best effort; failures are tolerated.

        querybatch returns only identifiers, and the finding needs the summary,
        severity and fixed version to be actionable.
        """
        details: dict[str, dict[str, Any]] = {}
        if not advisory_ids:
            return details
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                semaphore = asyncio.Semaphore(8)

                async def fetch(advisory_id: str) -> None:
                    async with semaphore:
                        try:
                            response = await client.get(f"{self.base_url}/vulns/{advisory_id}")
                            self.requests_sent += 1
                            if response.status_code == 200:
                                details[advisory_id] = response.json()
                        except (httpx.HTTPError, ValueError):
                            # A missing detail degrades one finding's richness,
                            # not the run.
                            return

                await asyncio.gather(*(fetch(a) for a in advisory_ids[:300]))
        except Exception:
            return details
        return details


@register_engine
class ScaEngine(SecurityEngine):
    """Software composition analysis across 10 package ecosystems."""

    metadata = EngineMetadata(
        key="sca",
        name="Software Composition Analysis",
        description=(
            "Inventories dependencies from manifests and lockfiles across npm, PyPI, "
            "Maven, Go, crates.io, NuGet, Packagist, RubyGems and more, then matches "
            "them against OSV advisories. Reports licence risk separately from "
            "vulnerability risk."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository", "manifest"),
        capabilities=frozenset({EngineCapability.FILESYSTEM, EngineCapability.INTELLIGENCE}),
        categories=("vulnerable_dependency", "supply_chain", "license_risk"),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        if not await asyncio.to_thread(Path(ctx.target.value).exists):
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        osv_enabled = bool(ctx.option("osv_enabled", True))
        osv_url = str(ctx.option("osv_api_url", DEFAULT_OSV_URL))
        include_dev = bool(ctx.option("include_development", True))

        await ctx.report_progress(3, "locating dependency manifests")
        manifests = await asyncio.to_thread(self._find_manifests, root)
        if not manifests:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No dependency manifest or lockfile was found under {root}. Nothing "
                    "was inventoried, so this result says nothing about dependency risk."
                ),
                stats={
                    "manifests_found": 0,
                    "recognised_filenames": sorted(MANIFEST_FILES),
                },
            )

        outcome = ParseOutcome()
        for path, relative in manifests:
            part = await asyncio.to_thread(parse_file, path, relative)
            outcome.merge(part)

        dependencies = self._deduplicate(outcome.dependencies, include_dev)
        await ctx.report_progress(
            25,
            f"inventoried {len(dependencies)} dependency(ies) from {len(manifests)} manifest(s)",
        )

        findings: list[ScanFinding] = []
        warnings = list(outcome.warnings)
        degraded_reason: str | None = None
        osv_error: str | None = None
        matches: list[VulnerabilityMatch] = []
        client = OsvClient(osv_url)

        # Only pinned versions are queried. Matching an advisory against a
        # version range would produce findings that may not apply to the build.
        pinned = [d for d in dependencies if d.is_pinned]
        unpinned = [d for d in dependencies if not d.is_pinned]

        if not osv_enabled:
            degraded_reason = (
                "Vulnerability lookup is disabled by configuration, so the dependency "
                "inventory was built but no advisories were checked. This is not a "
                "clean result."
            )
        elif not pinned:
            degraded_reason = (
                f"All {len(dependencies)} dependency(ies) came from manifests that "
                "declare version ranges rather than resolved versions, so no advisory "
                "lookup could be performed. Commit a lockfile to make this assessable."
            )
        else:
            await ctx.report_progress(40, f"querying OSV for {len(pinned)} pinned dependency(ies)")
            raw_results, osv_error = await client.query_batch(pinned)
            if osv_error is not None:
                degraded_reason = (
                    f"The OSV vulnerability database could not be reached ({osv_error}), "
                    f"so the {len(pinned)} pinned dependency(ies) in this inventory were "
                    "not checked for known vulnerabilities. The absence of findings here "
                    "does not mean the dependencies are safe."
                )
            else:
                advisory_ids: list[str] = []
                for vulns in raw_results.values():
                    advisory_ids.extend(
                        v["id"] for v in vulns if isinstance(v, dict) and v.get("id")
                    )
                await ctx.report_progress(
                    65, f"fetching details for {len(set(advisory_ids))} advisory(ies)"
                )
                details = await client.fetch_details(sorted(set(advisory_ids)))
                by_key = {d.key: d for d in pinned}
                for key, vulns in raw_results.items():
                    dependency = by_key.get(key)
                    if dependency is None:
                        continue
                    for vuln in vulns:
                        advisory_id = vuln.get("id")
                        if not advisory_id:
                            continue
                        matches.append(
                            self._build_match(
                                dependency, advisory_id, details.get(advisory_id, vuln)
                            )
                        )

        await ctx.report_progress(85, "evaluating licence risk")
        findings.extend(self._vulnerability_findings(matches, ctx))
        findings.extend(self._license_findings(dependencies, ctx))

        if unpinned and osv_enabled and pinned:
            warnings.append(
                f"{len(unpinned)} dependency(ies) were declared as version ranges rather "
                "than resolved versions and were not checked against advisories: "
                + ", ".join(f"{d.ecosystem}:{d.name}" for d in unpinned[:10])
            )

        ecosystems = Counter(d.ecosystem for d in dependencies)
        stats: dict[str, Any] = {
            "manifests_found": len(manifests),
            "lockfiles": outcome.lockfiles_seen,
            "manifests": outcome.manifests_seen,
            "dependencies_total": len(dependencies),
            "dependencies_pinned": len(pinned),
            "dependencies_unpinned": len(unpinned),
            "dependencies_direct": sum(1 for d in dependencies if d.is_direct),
            "ecosystems": dict(ecosystems),
            "advisories_matched": len(matches),
            "unique_advisories": len({m.advisory_id for m in matches}),
            "osv_requests": client.requests_sent,
            "osv_reachable": osv_error is None and osv_enabled,
            "parse_warnings": len(outcome.warnings),
            "sbom": [
                {
                    "purl": d.purl,
                    "ecosystem": d.ecosystem,
                    "name": d.name,
                    "version": d.version,
                    "scope": d.scope,
                    "direct": d.is_direct,
                    "license": d.license,
                }
                for d in dependencies
            ],
        }

        if degraded_reason is not None:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=degraded_reason,
                stats=stats,
                items_examined=len(dependencies),
                requests_sent=client.requests_sent,
                warnings=warnings,
            )
        if outcome.warnings or unpinned:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    "Coverage is incomplete: "
                    + " ".join(warnings[:5])
                    + " Dependencies that could not be resolved are not represented in "
                    "these findings."
                ),
                stats=stats,
                items_examined=len(dependencies),
                requests_sent=client.requests_sent,
                warnings=warnings,
            )

        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=len(dependencies),
            checks_executed=len(pinned),
            requests_sent=client.requests_sent,
            warnings=warnings,
        )

    # ------------------------------------------------------------ collection
    @staticmethod
    def _find_manifests(root: Path) -> list[tuple[Path, str]]:
        if root.is_file():
            return [(root, root.name)]
        found: list[tuple[Path, str]] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                if name in MANIFEST_FILES:
                    path = Path(dirpath) / name
                    try:
                        found.append((path, str(path.relative_to(root))))
                    except ValueError:
                        found.append((path, name))
        return found

    @staticmethod
    def _deduplicate(dependencies: list[Dependency], include_dev: bool) -> list[Dependency]:
        """Collapse duplicates, preferring the pinned record.

        The same package legitimately appears in both a manifest and a
        lockfile; keeping both would double-count it and report the same
        vulnerability twice.
        """
        best: dict[tuple[str, str], Dependency] = {}
        for dependency in dependencies:
            if not include_dev and dependency.scope == "development":
                continue
            identity = (dependency.ecosystem, dependency.name)
            current = best.get(identity)
            if current is None:
                best[identity] = dependency
                continue
            # A pinned record wins outright, because it states what is
            # actually installed. Between two records of equal pinning, prefer
            # the direct one: it is the dependency the team can act on.
            prefer_pinned = dependency.is_pinned and not current.is_pinned
            prefer_direct = (
                dependency.is_pinned == current.is_pinned
                and dependency.is_direct
                and not current.is_direct
            )
            if prefer_pinned or prefer_direct:
                best[identity] = dependency
        return sorted(best.values(), key=lambda d: (d.ecosystem, d.name))

    # --------------------------------------------------------------- matching
    @staticmethod
    def _build_match(
        dependency: Dependency, advisory_id: str, record: dict[str, Any]
    ) -> VulnerabilityMatch:
        aliases = [a for a in (record.get("aliases") or []) if isinstance(a, str)]
        cve = next((a for a in [advisory_id, *aliases] if a.startswith("CVE-")), None)

        severity = "medium"
        cvss_vector = None
        cvss_score = None
        for entry in record.get("severity") or []:
            if entry.get("type") in ("CVSS_V3", "CVSS_V4") and entry.get("score"):
                cvss_vector = str(entry["score"])
        database = record.get("database_specific") or {}
        if isinstance(database.get("severity"), str):
            severity = database["severity"].lower()
            severity = {"moderate": "medium"}.get(severity, severity)
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        cwe_ids = [c for c in (database.get("cwe_ids") or []) if isinstance(c, str)]
        fixed: list[str] = []
        for affected in record.get("affected") or []:
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        fixed.append(str(event["fixed"]))
        references = [
            r["url"]
            for r in (record.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ]

        return VulnerabilityMatch(
            dependency=dependency,
            advisory_id=advisory_id,
            aliases=aliases,
            summary=str(record.get("summary") or "")[:500],
            details=str(record.get("details") or "")[:4000],
            severity=severity,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            cve=cve,
            cwe_ids=cwe_ids,
            fixed_versions=sorted(set(fixed)),
            references=references[:10],
            published=record.get("published"),
        )

    # --------------------------------------------------------------- findings
    @staticmethod
    def _vulnerability_findings(
        matches: list[VulnerabilityMatch], ctx: EngineContext
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for match in matches:
            dependency = match.dependency
            fix_note = (
                f"Upgrade to {', '.join(match.fixed_versions[:3])} or later."
                if match.fixed_versions
                else (
                    "No fixed version is published yet. Assess whether the vulnerable "
                    "code path is reachable from your application, and consider a "
                    "temporary mitigation or an alternative package."
                )
            )
            findings.append(
                ScanFinding(
                    engine="sca",
                    rule_id=f"sca.{match.advisory_id.lower()}",
                    category="vulnerable_dependency",
                    title=(
                        f"{dependency.name} {dependency.version} is affected by "
                        f"{match.cve or match.advisory_id}"
                    ),
                    description=(
                        (
                            match.summary
                            or match.details[:300]
                            or "A known vulnerability affects this dependency."
                        )
                        + f" Reported for {dependency.ecosystem} package "
                        f"{dependency.name} at version {dependency.version}, declared in "
                        f"{dependency.manifest_path}"
                        + (
                            " as a direct dependency."
                            if dependency.is_direct
                            else f" as a transitive dependency (depth {dependency.depth})."
                        )
                    ),
                    severity=match.severity,  # type: ignore[arg-type]
                    confidence="high",
                    cve=match.cve,
                    cwe=match.cwe_ids[0] if match.cwe_ids else None,
                    cvss_vector=match.cvss_vector,
                    cvss_score=match.cvss_score,
                    owasp_top10="A06:2021",
                    owasp_asvs=["V14.2.1"],
                    impact=match.details[:1000] or match.summary,
                    remediation=fix_note,
                    reproduction=(
                        f"Inspect {dependency.manifest_path} for "
                        f"{dependency.name}=={dependency.version} and compare against "
                        f"advisory {match.advisory_id}."
                    ),
                    evidence=Evidence(
                        summary=(f"{match.advisory_id} matches {dependency.purl} (source: OSV)"),
                        artifacts={
                            "advisory_id": match.advisory_id,
                            "aliases": match.aliases,
                            "purl": dependency.purl,
                            "ecosystem": dependency.ecosystem,
                            "installed_version": dependency.version,
                            "fixed_versions": match.fixed_versions,
                            "is_direct": dependency.is_direct,
                            "dependency_scope": dependency.scope,
                            "manifest": dependency.manifest_path,
                            "published": match.published,
                            "data_source": "osv.dev",
                        },
                    ),
                    code_location=CodeLocation(file_path=dependency.manifest_path),
                    # Keyed on the advisory and the exact package version, so the
                    # same CVE in two packages stays two issues while the same
                    # package in two manifests collapses to one.
                    correlation_discriminator=f"{match.advisory_id}:{dependency.purl}",
                    target=ctx.target,
                    references=match.references
                    or [f"https://osv.dev/vulnerability/{match.advisory_id}"],
                    raw={
                        "advisory_id": match.advisory_id,
                        "purl": dependency.purl,
                        "fixed_versions": match.fixed_versions,
                    },
                )
            )
        return findings

    @staticmethod
    def _license_findings(dependencies: list[Dependency], ctx: EngineContext) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        by_license: dict[str, list[Dependency]] = {}
        for dependency in dependencies:
            if not dependency.license:
                continue
            normalised = dependency.license.replace(" OR ", ",").replace(" AND ", ",")
            for token in normalised.split(","):
                key = token.strip()
                if key in COPYLEFT_LICENSES:
                    by_license.setdefault(key, []).append(dependency)

        for license_id, affected in by_license.items():
            severity, reason = COPYLEFT_LICENSES[license_id]
            first = affected[0]
            findings.append(
                ScanFinding(
                    engine="sca",
                    rule_id=f"sca.license.{license_id.lower()}",
                    category="license_risk",
                    title=f"{license_id} licensed dependency in use",
                    description=(
                        f"{len(affected)} dependency(ies) are licensed under "
                        f"{license_id}. {reason} This is a legal and distribution "
                        "concern rather than a security vulnerability, and is reported "
                        "separately so the right people see it."
                    ),
                    severity=severity,  # type: ignore[arg-type]
                    confidence="medium",
                    remediation=(
                        "Confirm with legal counsel whether this licence is compatible "
                        "with how the product is distributed. If it is not, replace the "
                        "dependency or isolate it behind a process boundary."
                    ),
                    reproduction=(
                        f"Review the licence declared for {first.name} in {first.manifest_path}."
                    ),
                    evidence=Evidence(
                        summary=f"{license_id} declared by {len(affected)} dependency(ies)",
                        artifacts={
                            "license": license_id,
                            "packages": [
                                {"purl": d.purl, "manifest": d.manifest_path} for d in affected[:50]
                            ],
                        },
                    ),
                    code_location=CodeLocation(file_path=first.manifest_path),
                    correlation_discriminator=f"license:{license_id}",
                    target=ctx.target,
                    raw={"license": license_id, "package_count": len(affected)},
                )
            )
        return findings
