"""Cryptographic inventory and post-quantum readiness.

Builds an inventory of the cryptography a codebase actually uses, classifies
each primitive by its correct class, and scores how much work a post-quantum
migration needs.

The classification is the point. A readiness report that records ML-KEM as a
signature scheme, or tells a team to replace AES-256, sends them to do the
wrong work — so unknown algorithms are reported as unknown rather than guessed,
and symmetric and hash primitives are reported as Grover-*reduced* rather than
broken.

Key establishment is weighted most heavily because of store-now-decrypt-later:
traffic captured today can be decrypted once the key exchange is broken,
whereas a signature only has to resist forgery while it is still trusted.

Passive: reads files, sends nothing, needs no test authorization.
"""

from __future__ import annotations

import asyncio
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qguard_scanner.rules.crypto_catalog import (
    CODE_CRYPTO_PATTERNS,
    PQCategory,
    QuantumRisk,
    is_hybrid,
    lookup,
)
from qguard_scanner.rules.sast_rules import LANGUAGE_BY_EXTENSION
from qguard_scanner.rules.secret_patterns import SKIP_DIR_NAMES, is_example_path
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import CodeLocation, Evidence, ScanFinding
from qguard_scanner.sdk.registry import register_engine

MAX_FILE_BYTES = 2 * 1024 * 1024

#: Configuration files worth inventorying even though they are not source.
CONFIG_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".conf",
        ".cnf",
        ".ini",
        ".cfg",
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".env",
        ".properties",
        ".xml",
        ".pem",
        ".crt",
        ".tf",
    }
)

#: Weights for the readiness score. Key establishment dominates because of
#: store-now-decrypt-later: a recording made today is decryptable later.
#: Quantum-reduced strength at or above this is considered adequate, so a
#: symmetric or hash primitive at this level is not a migration target.
ADEQUATE_QUANTUM_BITS = 128

READINESS_WEIGHTS: dict[str, float] = {
    "key_establishment": 0.50,
    "signatures": 0.30,
    "symmetric": 0.12,
    "hashes": 0.08,
}


def _NAME_PARTS(components: set[str]) -> set[str]:  # noqa: N802
    """Normalised spellings of hybrid component names.

    `ML-KEM-768` and the `ML-KEM-768` produced from the bare pattern are the
    same primitive, so both spellings have to be recognised when deciding
    which matches a hybrid already accounts for.
    """
    out: set[str] = set()
    for name in components:
        out.add(name)
        out.add(name.replace("-", ""))
        out.add(name.upper())
    return out


@dataclass(slots=True)
class _Usage:
    algorithm: str
    file_path: str
    line_number: int
    line_text: str
    in_example: bool


@dataclass(slots=True)
class _Inventory:
    """Everything found, grouped by the class it belongs to."""

    usages: list[_Usage] = field(default_factory=list)
    files_examined: int = 0
    unreadable: list[str] = field(default_factory=list)

    def merge(self, other: _Inventory) -> None:
        self.usages.extend(other.usages)
        self.files_examined += other.files_examined
        self.unreadable.extend(other.unreadable)


@register_engine
class CryptoEngine(SecurityEngine):
    """Cryptographic inventory and post-quantum readiness scoring."""

    metadata = EngineMetadata(
        key="crypto",
        name="Cryptographic Inventory and Quantum Readiness",
        description=(
            "Inventories the cryptography a codebase uses, classifies every primitive "
            "by its correct class (key encapsulation, signature, key agreement, "
            "symmetric, hash) and scores post-quantum migration readiness. Unknown "
            "algorithms are reported as unknown rather than guessed."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository"),
        capabilities=frozenset({EngineCapability.FILESYSTEM}),
        categories=("cryptographic_failure", "quantum_vulnerable_cryptography"),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        if not await asyncio.to_thread(Path(ctx.target.value).exists):
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        max_files = int(ctx.option("max_files", 20_000))

        await ctx.report_progress(3, f"collecting files under {root}")
        files = await asyncio.to_thread(self._collect, root, max_files)
        if not files:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No source or configuration files were found under {root}, so no "
                    "cryptographic inventory could be built. A readiness score would be "
                    "meaningless and is not reported."
                ),
                stats={"files_found": 0},
            )

        inventory = _Inventory()
        batch = 150
        for offset in range(0, len(files), batch):
            if ctx.is_cancelled():
                break
            chunk = files[offset : offset + batch]
            part = await asyncio.to_thread(self._scan_batch, chunk, root)
            inventory.merge(part)
            await ctx.report_progress(
                min(90, int(100 * (offset + len(chunk)) / len(files))),
                f"inventoried {inventory.files_examined} file(s), "
                f"{len(inventory.usages)} cryptographic use(s)",
            )

        findings, summary = self._assess(inventory, ctx)

        stats: dict[str, Any] = {
            "files_found": len(files),
            "files_examined": inventory.files_examined,
            "unreadable_files": len(inventory.unreadable),
            "crypto_usages": len(inventory.usages),
            **summary,
        }
        warnings: list[str] = []
        if inventory.unreadable:
            warnings.append(
                f"{len(inventory.unreadable)} file(s) could not be read: "
                + "; ".join(inventory.unreadable[:5])
            )

        if not inventory.usages:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    f"{inventory.files_examined} file(s) were examined but no recognised "
                    "cryptographic primitive was found. Either the code delegates "
                    "cryptography entirely to a platform library, or the inventory is "
                    "incomplete — it is reported as unknown rather than as quantum-safe."
                ),
                stats=stats,
                items_examined=inventory.files_examined,
                warnings=warnings,
            )

        if inventory.unreadable:
            return EngineResult.degraded(
                self.key,
                findings,
                reason="Coverage is incomplete: " + " ".join(warnings),
                stats=stats,
                items_examined=inventory.files_examined,
                warnings=warnings,
            )

        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=inventory.files_examined,
            checks_executed=inventory.files_examined * len(CODE_CRYPTO_PATTERNS),
            warnings=warnings,
        )

    # ------------------------------------------------------------ collection
    @staticmethod
    def _collect(root: Path, max_files: int) -> list[Path]:
        if root.is_file():
            return [root]
        collected: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                suffix = Path(name).suffix.lower()
                if suffix not in LANGUAGE_BY_EXTENSION and suffix not in CONFIG_EXTENSIONS:
                    continue
                candidate = Path(dirpath) / name
                if candidate.is_symlink():
                    continue
                collected.append(candidate)
                if len(collected) >= max_files:
                    return collected
        return collected

    @staticmethod
    def _scan_batch(batch: list[Path], root: Path) -> _Inventory:
        inventory = _Inventory()
        for file_path in batch:
            try:
                relative = str(file_path.relative_to(root))
            except ValueError:
                relative = file_path.name
            try:
                if file_path.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                inventory.unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue

            inventory.files_examined += 1
            in_example = is_example_path(relative)
            seen: set[tuple[str, int]] = set()

            for line_number, line in enumerate(text.splitlines(), start=1):
                if len(line) > 2000:
                    continue
                matched: list[str] = []
                for pattern, template, _source in CODE_CRYPTO_PATTERNS:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    algorithm = template
                    if "{0}" in template and match.groups():
                        algorithm = template.format(match.group(1))
                    matched.append(algorithm)

                # A hybrid group name contains its components' names, so
                # `X25519MLKEM768` also matches the bare X25519 and ML-KEM
                # patterns. Recording those separately would count the
                # classical half of a hybrid as a standalone
                # quantum-vulnerable use — reporting a correctly configured
                # hybrid deployment as a finding.
                hybrids = [a for a in matched if is_hybrid(a)[0]]
                if hybrids:
                    components = {c for h in hybrids for c in is_hybrid(h)[1]}
                    spellings = _NAME_PARTS(components)
                    matched = [
                        a
                        for a in matched
                        if is_hybrid(a)[0] or (a not in components and a not in spellings)
                    ]

                for algorithm in matched:
                    key = (algorithm, line_number)
                    if key in seen:
                        continue
                    seen.add(key)
                    inventory.usages.append(
                        _Usage(
                            algorithm=algorithm,
                            file_path=relative,
                            line_number=line_number,
                            line_text=line.strip()[:300],
                            in_example=in_example,
                        )
                    )
        return inventory

    # -------------------------------------------------------------- assessment
    def _assess(
        self, inventory: _Inventory, ctx: EngineContext
    ) -> tuple[list[ScanFinding], dict[str, Any]]:
        """Classify the inventory and build findings plus a readiness summary."""
        by_class: dict[str, Counter[str]] = {
            "key_encapsulation": Counter(),
            "digital_signature": Counter(),
            "key_agreement": Counter(),
            "symmetric_encryption": Counter(),
            "hash": Counter(),
            "unknown": Counter(),
        }
        risk_counts: Counter[str] = Counter()
        hybrid_usages: list[_Usage] = []
        hybrid_components: set[str] = set()
        broken_usages: dict[str, list[_Usage]] = {}
        deprecated_usages: dict[str, list[_Usage]] = {}
        unknown_usages: dict[str, list[_Usage]] = {}

        for usage in inventory.usages:
            hybrid, components = is_hybrid(usage.algorithm)
            if hybrid:
                hybrid_usages.append(usage)
                risk_counts[QuantumRisk.HYBRID] += 1
                # Recorded under the hybrid's own name as key establishment,
                # not split into its parts. Counting the classical half
                # separately would score a correctly configured hybrid as
                # half-unsafe and penalise exactly the configuration the
                # migration guidance recommends.
                by_class["key_encapsulation"][usage.algorithm] += 1
                hybrid_components.update(components)
                continue

            spec = lookup(usage.algorithm)
            if spec is None:
                by_class["unknown"][usage.algorithm] += 1
                risk_counts[QuantumRisk.UNKNOWN] += 1
                unknown_usages.setdefault(usage.algorithm, []).append(usage)
                continue

            by_class[str(spec.pq_category)][spec.name] += 1
            risk_counts[str(spec.quantum_risk)] += 1

            if spec.quantum_risk is QuantumRisk.BROKEN and spec.pq_category in (
                PQCategory.KEY_AGREEMENT,
                PQCategory.DIGITAL_SIGNATURE,
            ):
                broken_usages.setdefault(spec.name, []).append(usage)
            if spec.is_deprecated:
                deprecated_usages.setdefault(spec.name, []).append(usage)

        findings: list[ScanFinding] = []
        for algorithm, usages in broken_usages.items():
            findings.append(self._quantum_finding(algorithm, usages, ctx))
        for algorithm, usages in deprecated_usages.items():
            findings.append(self._deprecated_finding(algorithm, usages, ctx))
        for algorithm, usages in unknown_usages.items():
            if len(usages) >= 1:
                findings.append(self._unknown_finding(algorithm, usages, ctx))

        readiness = self._readiness(by_class, hybrid_usages)
        if readiness["score"] < 100:
            findings.append(self._readiness_finding(readiness, by_class, ctx))

        summary = {
            "inventory_by_class": {k: dict(v) for k, v in by_class.items() if v},
            "quantum_risk_counts": dict(risk_counts),
            "hybrid_usages": len(hybrid_usages),
            "hybrid_components": sorted(hybrid_components),
            "readiness": readiness,
            # Stated explicitly because a KEM-only or signature-only deployment is a
            # common and consequential mistake.
            "has_pq_kem": bool(by_class["key_encapsulation"]),
            "has_pq_signature": any(
                lookup(a) and lookup(a).quantum_risk is QuantumRisk.QUANTUM_SAFE  # type: ignore[union-attr]
                for a in by_class["digital_signature"]
            ),
        }
        return findings, summary

    @staticmethod
    def _readiness(
        by_class: dict[str, Counter[str]], hybrid_usages: list[_Usage]
    ) -> dict[str, Any]:
        """Score migration readiness, showing every component.

        Each class scores the share of its uses that are quantum-safe or
        hybrid. A class with no uses at all is excluded rather than scored as
        perfect, and its absence is stated — an inventory that found no key
        establishment has not demonstrated that key establishment is safe.
        """
        components: dict[str, dict[str, Any]] = {}

        def share(counter: Counter[str], label: str) -> dict[str, Any] | None:
            """Share of a class's uses that are adequate against a quantum adversary.

            Adequacy is not the same as being a PQ algorithm. A symmetric or
            hash primitive is adequate when it retains at least 128 bits of
            strength after Grover's quadratic speed-up — AES-256 and SHA-256
            both do. Treating them as unsafe would score a fully migrated
            codebase as incomplete and send the team to replace primitives
            that do not need replacing.
            """
            if not counter:
                return None
            total = sum(counter.values())
            safe = 0
            inadequate: dict[str, str] = {}
            for algorithm, count in counter.items():
                if is_hybrid(algorithm)[0]:
                    # A classical+PQ hybrid is quantum-safe: breaking it
                    # requires breaking the PQ half.
                    safe += count
                    continue
                spec = lookup(algorithm)
                if spec is None:
                    inadequate[algorithm] = "not in the algorithm catalogue"
                    continue
                if spec.quantum_risk in (QuantumRisk.QUANTUM_SAFE, QuantumRisk.HYBRID):
                    safe += count
                    continue
                if (
                    spec.pq_category
                    in (
                        PQCategory.SYMMETRIC_ENCRYPTION,
                        PQCategory.HASH,
                        PQCategory.MAC,
                        PQCategory.KDF,
                    )
                    and (spec.quantum_bits or 0) >= ADEQUATE_QUANTUM_BITS
                ):
                    safe += count
                    continue
                inadequate[algorithm] = f"{spec.quantum_risk.value}" + (
                    f", {spec.quantum_bits} bit(s) of quantum-reduced strength"
                    if spec.quantum_bits is not None
                    else ""
                )
            return {
                "label": label,
                "total_uses": total,
                "quantum_safe_uses": safe,
                "ratio": round(safe / total, 4),
                "algorithms": dict(counter),
                "inadequate": inadequate,
            }

        key_establishment = Counter(by_class["key_encapsulation"])
        key_establishment.update(by_class["key_agreement"])
        hybrid_count = len(hybrid_usages)

        for key, counter, label in (
            ("key_establishment", key_establishment, "Key establishment"),
            ("signatures", by_class["digital_signature"], "Digital signatures"),
            ("symmetric", by_class["symmetric_encryption"], "Symmetric encryption"),
            ("hashes", by_class["hash"], "Hashing"),
        ):
            result = share(counter, label)
            if result is not None:
                components[key] = result

        if not components:
            return {
                "score": None,
                "maturity": "not_started",
                "components": {},
                "explanation": (
                    "No cryptographic primitives were inventoried, so no readiness score "
                    "is reported. An absent inventory is not evidence of readiness."
                ),
                "hybrid_uses": hybrid_count,
            }

        # Re-normalise the weights across the classes actually present, so an
        # application that does no hashing is not penalised for it.
        active_weight = sum(READINESS_WEIGHTS[k] for k in components)
        score = (
            sum(READINESS_WEIGHTS[k] * components[k]["ratio"] for k in components)
            / active_weight
            * 100
        )

        has_pq_kem = bool(by_class["key_encapsulation"])
        has_pq_signature = any(
            (spec := lookup(a)) is not None and spec.quantum_risk is QuantumRisk.QUANTUM_SAFE
            for a in by_class["digital_signature"]
        )

        notes: list[str] = []

        # A deployment cannot be post-quantum native without both a PQ KEM and
        # a PQ signature scheme: ML-KEM cannot authenticate and ML-DSA cannot
        # establish a secret. An inventory that found only one of the two is
        # capped and the gap is stated, rather than being scored as complete.
        has_key_establishment = "key_establishment" in components
        has_signatures = "signatures" in components
        coverage_gaps: list[str] = []
        if not has_key_establishment:
            coverage_gaps.append(
                "no key establishment primitive was inventoried, so the most important "
                "part of a post-quantum migration is unassessed"
            )
        if not has_signatures:
            coverage_gaps.append(
                "no signature primitive was inventoried, so authentication is unassessed"
            )

        if coverage_gaps:
            # Capped at 60: an inventory missing a whole primitive class has
            # not demonstrated readiness, however good the part it did see.
            capped = min(score, 60.0)
            if capped < score:
                notes.append(
                    f"The score is capped at {capped:.0f} because the inventory is "
                    "incomplete: " + "; ".join(coverage_gaps) + "."
                )
            score = capped

        if score >= 99 and has_key_establishment and has_signatures:
            maturity = "pq_native"
        elif hybrid_count or has_pq_kem or has_pq_signature:
            maturity = "hybrid_rollout"
        elif score > 0:
            maturity = "planning"
        else:
            maturity = "discovery"

        if has_pq_kem and not has_pq_signature:
            notes.append(
                "A post-quantum KEM is in use but no post-quantum signature scheme is. "
                "Confidentiality in transit is addressed while authentication remains "
                "Shor-breakable — ML-KEM cannot sign, so ML-DSA or SLH-DSA is still "
                "needed."
            )
        if has_pq_signature and not has_pq_kem:
            notes.append(
                "A post-quantum signature scheme is in use but no post-quantum KEM is. "
                "Authentication is addressed while key establishment remains "
                "Shor-breakable, which is the more urgent of the two because recorded "
                "traffic can be decrypted later."
            )
        if components.get("symmetric") or components.get("hashes"):
            notes.append(
                "Symmetric and hash primitives at 256-bit strength are Grover-reduced "
                "rather than broken and are not migration targets; they are included in "
                "the inventory for completeness only."
            )

        return {
            "score": round(score, 2),
            "maturity": maturity,
            "components": components,
            "weights": {k: READINESS_WEIGHTS[k] for k in components},
            "hybrid_uses": hybrid_count,
            "has_pq_kem": has_pq_kem,
            "has_pq_signature": has_pq_signature,
            "coverage_gaps": coverage_gaps,
            "notes": notes,
            "explanation": (
                "Weighted across the primitive classes actually present: "
                + "; ".join(
                    f"{c['label']} {c['quantum_safe_uses']}/{c['total_uses']} "
                    f"quantum-safe (weight {READINESS_WEIGHTS[k]:.2f})"
                    for k, c in components.items()
                )
                + ". Key establishment carries the largest weight because recorded "
                "traffic can be decrypted once the key exchange is broken."
            ),
        }

    # ---------------------------------------------------------------- findings
    @staticmethod
    def _quantum_finding(algorithm: str, usages: list[_Usage], ctx: EngineContext) -> ScanFinding:
        spec = lookup(algorithm)
        assert spec is not None
        first = usages[0]
        is_key_exchange = spec.pq_category is PQCategory.KEY_AGREEMENT
        severity = "high" if is_key_exchange else "medium"

        return ScanFinding(
            engine="crypto",
            rule_id=f"crypto.quantum-vulnerable.{algorithm.lower()}",
            category="quantum_vulnerable_cryptography",
            title=f"{algorithm} is quantum-vulnerable ({spec.pq_category.value})",
            description=(
                f"{algorithm} is used in {len(usages)} place(s). {spec.description} "
                f"It is classified as {spec.pq_category.value}, so its replacement must "
                "be a primitive of the same class."
                + (
                    " Key establishment is the migration priority: traffic recorded "
                    "today can be decrypted once this exchange is broken, so the "
                    "exposure is retroactive."
                    if is_key_exchange
                    else " A signature only needs to resist forgery while it is still "
                    "trusted, so the exposure is not retroactive — but long-lived roots "
                    "of trust need the longest lead time to replace."
                )
            ),
            severity=severity,
            confidence="high",
            cwe="CWE-327",
            owasp_top10="A02:2021",
            owasp_asvs=["V6.2.1"],
            impact=(
                "No security against a cryptographically relevant quantum computer. "
                "Increasing the key size does not help, because Shor's algorithm is "
                "polynomial in the key length."
            ),
            remediation=spec.migration
            or "Migrate to a NIST-standardised PQ primitive of the same class.",
            reproduction=(
                f"Review {first.file_path}:{first.line_number} and the "
                f"{len(usages)} recorded use(s) of {algorithm}."
            ),
            evidence=Evidence(
                summary=(
                    f"{algorithm} ({spec.pq_category.value}, quantum risk "
                    f"{spec.quantum_risk.value}) found in {len(usages)} location(s)"
                ),
                code_snippet=first.line_text,
                artifacts={
                    "algorithm": algorithm,
                    "pq_category": spec.pq_category.value,
                    "quantum_risk": spec.quantum_risk.value,
                    "classical_security_bits": spec.classical_bits,
                    "quantum_security_bits": spec.quantum_bits,
                    "locations": [
                        {"file": u.file_path, "line": u.line_number} for u in usages[:25]
                    ],
                    "total_locations": len(usages),
                },
            ),
            code_location=CodeLocation(
                file_path=first.file_path,
                start_line=first.line_number,
                snippet=first.line_text,
            ),
            correlation_discriminator=f"quantum:{algorithm}",
            target=ctx.target,
            references=[
                "https://csrc.nist.gov/projects/post-quantum-cryptography",
                "https://csrc.nist.gov/pubs/ir/8547/ipd",
            ],
            raw={"algorithm": algorithm, "pq_category": spec.pq_category.value},
        )

    @staticmethod
    def _deprecated_finding(
        algorithm: str, usages: list[_Usage], ctx: EngineContext
    ) -> ScanFinding:
        spec = lookup(algorithm)
        assert spec is not None
        first = usages[0]
        return ScanFinding(
            engine="crypto",
            rule_id=f"crypto.deprecated.{algorithm.lower()}",
            category="cryptographic_failure",
            title=f"Deprecated algorithm {algorithm} in use",
            description=(
                f"{algorithm} is used in {len(usages)} place(s). "
                f"{spec.deprecation_reason} This is a present-day weakness, independent "
                "of any quantum consideration."
            ),
            severity="high" if spec.quantum_risk is QuantumRisk.BROKEN else "medium",
            confidence="high",
            cwe="CWE-327",
            owasp_top10="A02:2021",
            impact=spec.description,
            remediation=spec.migration or "Replace with a current algorithm.",
            reproduction=f"Review {first.file_path}:{first.line_number}.",
            evidence=Evidence(
                summary=f"{algorithm} found in {len(usages)} location(s)",
                code_snippet=first.line_text,
                artifacts={
                    "algorithm": algorithm,
                    "deprecation_reason": spec.deprecation_reason,
                    "locations": [
                        {"file": u.file_path, "line": u.line_number} for u in usages[:25]
                    ],
                },
            ),
            code_location=CodeLocation(
                file_path=first.file_path,
                start_line=first.line_number,
                snippet=first.line_text,
            ),
            correlation_discriminator=f"deprecated:{algorithm}",
            target=ctx.target,
            raw={"algorithm": algorithm},
        )

    @staticmethod
    def _unknown_finding(algorithm: str, usages: list[_Usage], ctx: EngineContext) -> ScanFinding:
        first = usages[0]
        return ScanFinding(
            engine="crypto",
            rule_id="crypto.unclassified-primitive",
            category="cryptographic_failure",
            title=f"Unclassified cryptographic primitive: {algorithm}",
            description=(
                f"{algorithm} appears to be cryptographic but is not in the platform's "
                "algorithm catalogue, so its class and quantum exposure are unknown. It "
                "is reported as unknown rather than assumed safe: an inventory gap is "
                "not the same as a clean result, and guessing a class would produce a "
                "migration plan that cannot work."
            ),
            severity="info",
            confidence="low",
            cwe="CWE-1240",
            remediation=(
                "Identify the primitive and its class (key encapsulation, signature, "
                "key agreement, symmetric or hash), then classify its quantum exposure. "
                "Add it to the catalogue so future scans classify it automatically."
            ),
            reproduction=f"Review {first.file_path}:{first.line_number}.",
            evidence=Evidence(
                summary=f"Unrecognised primitive {algorithm} in {len(usages)} location(s)",
                code_snippet=first.line_text,
                artifacts={
                    "algorithm": algorithm,
                    "locations": [
                        {"file": u.file_path, "line": u.line_number} for u in usages[:25]
                    ],
                },
            ),
            code_location=CodeLocation(
                file_path=first.file_path,
                start_line=first.line_number,
                snippet=first.line_text,
            ),
            correlation_discriminator=f"unknown:{algorithm}",
            target=ctx.target,
            raw={"algorithm": algorithm, "classified": False},
        )

    @staticmethod
    def _readiness_finding(
        readiness: dict[str, Any], by_class: dict[str, Counter[str]], ctx: EngineContext
    ) -> ScanFinding:
        score = readiness["score"]
        severity = (
            "info" if score is None else "high" if score < 25 else "medium" if score < 75 else "low"
        )
        return ScanFinding(
            engine="crypto",
            rule_id="crypto.pq-readiness",
            category="quantum_vulnerable_cryptography",
            title=(
                f"Post-quantum readiness: {score:.0f}/100 ({readiness['maturity']})"
                if score is not None
                else "Post-quantum readiness could not be scored"
            ),
            description=(
                readiness["explanation"]
                + (" " + " ".join(readiness.get("notes", [])) if readiness.get("notes") else "")
            ),
            severity=severity,
            confidence="medium",
            cwe="CWE-327",
            impact=(
                "A deployment that has not migrated key establishment is exposed "
                "retroactively: traffic recorded now becomes readable once the exchange "
                "is broken. Signature migration is less urgent but takes longer, because "
                "every verifier must be updated first."
            ),
            remediation=(
                "Address key establishment first by adopting hybrid X25519MLKEM768 in "
                "TLS 1.3, then plan signature migration to ML-DSA (or SLH-DSA for "
                "long-lived roots of trust). Do not spend effort replacing AES-256 or "
                "SHA-256 — both are Grover-reduced rather than broken and remain "
                "adequate."
            ),
            evidence=Evidence(
                summary=(
                    f"Readiness {score}/100, maturity {readiness['maturity']}, "
                    f"{readiness.get('hybrid_uses', 0)} hybrid use(s)"
                ),
                artifacts={
                    "readiness": readiness,
                    "inventory_by_class": {k: dict(v) for k, v in by_class.items() if v},
                },
            ),
            target=ctx.target,
            correlation_discriminator="pq-readiness",
            references=[
                "https://csrc.nist.gov/pubs/ir/8547/ipd",
                "https://csrc.nist.gov/projects/post-quantum-cryptography",
            ],
            raw={"readiness_score": score, "maturity": readiness["maturity"]},
        )
