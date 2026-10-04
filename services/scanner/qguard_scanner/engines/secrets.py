"""Secrets detection engine.

Walks a directory, repository checkout or extracted package and reports
credentials committed into it. Fully offline — no network, no external tool —
so it is a passive engine needing no test authorization.

Design points that matter in practice:

* **The credential is never stored.** A finding carries a short redacted
  preview and an HMAC fingerprint. The fingerprint recognises the same secret
  across files and scans and proves rotation happened, without the platform
  becoming a second copy of the credential store.

* **False positives are actively suppressed.** Placeholders, template
  variables and obvious fixtures are filtered, and a hit in a conventional
  test or example path is reported at reduced severity rather than suppressed —
  a real credential does occasionally get committed to a fixture.

* **Entropy and pattern are separate signals.** A provider-shaped credential
  fires on its own; a shapeless one needs a credential-sounding name *and*
  high entropy, and the finding records which signals fired.
"""

from __future__ import annotations

import asyncio
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qguard_scanner.rules.secret_patterns import (
    ALL_RULES,
    GENERIC_RULE,
    PROVIDER_RULES,
    SKIP_DIR_NAMES,
    SecretRule,
    is_example_path,
    is_placeholder,
    should_skip_file,
)
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import CodeLocation, Evidence, ScanFinding, Severity
from qguard_scanner.sdk.registry import register_engine
from qguard_scanner.sdk.secretutil import (
    DEFAULT_FINGERPRINT_SALT,
    fingerprint,
    redact,
    shannon_entropy,
)

#: Files larger than this are skipped. A credential lives in configuration or
#: source, not in a 10 MB generated file, and reading them all would make the
#: engine unusable on a large repository.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: A single line longer than this is almost certainly minified or generated.
MAX_LINE_LENGTH = 4096

#: Cap on findings per rule, so one bad pattern cannot produce a wall of noise.
MAX_FINDINGS_PER_RULE = 100


#: Severity downgrade applied to a hit found in test or example material.
#: Reduced rather than suppressed: a real credential does sometimes land in
#: a fixture, and silently dropping it would be the worse error.
_REDUCED_SEVERITY: dict[str, Severity] = {
    "critical": "medium",
    "high": "low",
    "medium": "low",
}


#: Hosts whose credentials are unreachable from outside the machine.
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1", "host.docker.internal")


def _is_loopback_credential(line: str) -> bool:
    """Whether a matched line is a connection string pointing at this machine.

    A credential for a loopback address is a development default: it cannot be
    used by anyone who is not already on the host. Treating it with the same
    severity as a live cloud credential makes the severity scale useless.
    """
    lowered = line.lower()
    if "://" not in lowered:
        return False
    after_credentials = lowered.rpartition("@")[2]
    if not after_credentials:
        return False
    return any(after_credentials.startswith(host) for host in _LOOPBACK_HOSTS)


@dataclass(slots=True)
class _Tally:
    """Per-batch counters, merged so coverage can be reported honestly."""

    files_examined: int = 0
    bytes_examined: int = 0
    skipped_binary: int = 0
    skipped_large: int = 0
    skipped_examples: int = 0
    unreadable: list[str] = field(default_factory=list)

    def merge(self, other: _Tally) -> None:
        self.files_examined += other.files_examined
        self.bytes_examined += other.bytes_examined
        self.skipped_binary += other.skipped_binary
        self.skipped_large += other.skipped_large
        self.skipped_examples += other.skipped_examples
        self.unreadable.extend(other.unreadable)


@dataclass(slots=True)
class _Hit:
    rule: SecretRule
    value: str
    file_path: str
    line_number: int
    line_text: str
    entropy: float
    in_example_path: bool


@register_engine
class SecretsEngine(SecurityEngine):
    """Detects committed credentials in source trees and packages."""

    metadata = EngineMetadata(
        key="secrets",
        name="Secrets Detection",
        description=(
            "Finds credentials committed into source, configuration and packaged "
            "artifacts using provider-specific patterns and entropy screening. Stores "
            "only a redacted preview and a keyed fingerprint, never the credential."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository"),
        capabilities=frozenset({EngineCapability.FILESYSTEM}),
        categories=("exposed_secret",),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        path = Path(ctx.target.value)
        exists = await asyncio.to_thread(path.exists)
        if not exists:
            # Reported as a skip with the real reason rather than an empty
            # result, which would read as "no secrets found".
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        """Scan a tree for committed credentials.

        File walking and reading are blocking, so they run in worker threads.
        Doing them on the event loop would stall the worker's other slots and
        its job heartbeat, which the queue reads as a dead worker — the scan
        would be requeued while it was in fact still running.
        """
        salt = str(ctx.option("fingerprint_salt", DEFAULT_FINGERPRINT_SALT))
        max_files = int(ctx.option("max_files", 50_000))
        include_examples = bool(ctx.option("include_example_paths", True))

        # `resolve()` touches the filesystem, so it goes to a thread like the
        # rest of the I/O.
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        await ctx.report_progress(2, f"walking {root}")
        files = await asyncio.to_thread(self._walk, root, max_files)
        if not files:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No files were found under {root}. Coverage is zero, so this result "
                    "does not indicate the absence of secrets."
                ),
                stats={"files_found": 0},
            )

        hits: list[_Hit] = []
        per_rule: Counter[str] = Counter()
        tally = _Tally()
        truncated = False

        # Batched so progress stays live and cancellation is honoured promptly,
        # while each batch's blocking work still happens off the loop.
        batch_size = 200
        for offset in range(0, len(files), batch_size):
            if ctx.is_cancelled():
                break
            batch = files[offset : offset + batch_size]
            batch_hits, batch_tally = await asyncio.to_thread(
                self._scan_batch, batch, root, salt, include_examples
            )
            tally.merge(batch_tally)

            for hit in batch_hits:
                if per_rule[hit.rule.rule_id] >= MAX_FINDINGS_PER_RULE:
                    truncated = True
                    continue
                per_rule[hit.rule.rule_id] += 1
                hits.append(hit)

            await ctx.report_progress(
                min(95, int(100 * (offset + len(batch)) / len(files))),
                f"examined {tally.files_examined} file(s), {len(hits)} candidate secret(s)",
            )

        findings = [self._to_finding(hit, salt, ctx) for hit in hits]

        stats: dict[str, Any] = {
            "files_found": len(files),
            "files_examined": tally.files_examined,
            "bytes_examined": tally.bytes_examined,
            "skipped_binary": tally.skipped_binary,
            "skipped_large": tally.skipped_large,
            "skipped_example_paths": tally.skipped_examples,
            "unreadable_files": len(tally.unreadable),
            "rules_evaluated": len(ALL_RULES),
            "findings_per_rule": dict(per_rule),
            "truncated_rules": [r for r, c in per_rule.items() if c >= MAX_FINDINGS_PER_RULE],
        }
        warnings: list[str] = []
        if tally.unreadable:
            warnings.append(
                f"{len(tally.unreadable)} file(s) could not be read: "
                + "; ".join(tally.unreadable[:5])
            )
        if truncated:
            warnings.append(
                f"Some rules hit the {MAX_FINDINGS_PER_RULE}-finding cap; the affected "
                "files may contain more occurrences of the same pattern."
            )

        if ctx.is_cancelled():
            return EngineResult(
                engine=self.key,
                status=EngineStatus.CANCELLED,
                findings=findings,
                stats=stats,
                items_examined=tally.files_examined,
                checks_executed=tally.files_examined * len(ALL_RULES),
                warnings=warnings,
            )

        if tally.files_examined == 0:
            # Nothing was read, so "no secrets" would be an unfounded claim.
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    f"{len(files)} file(s) were found under {root} but none could be read as "
                    "text. Coverage is zero, so this result does not indicate the absence "
                    "of secrets."
                ),
                stats=stats,
                warnings=warnings,
            )

        if truncated or tally.unreadable:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    "Coverage is incomplete: "
                    + " ".join(warnings)
                    + " Treat the absence of further findings with caution."
                ),
                stats=stats,
                items_examined=tally.files_examined,
                checks_executed=tally.files_examined * len(ALL_RULES),
                warnings=warnings,
            )

        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=tally.files_examined,
            checks_executed=tally.files_examined * len(ALL_RULES),
            warnings=warnings,
        )

    # ------------------------------------------------------------ batch scan
    def _scan_batch(
        self, batch: list[Path], root: Path, salt: str, include_examples: bool
    ) -> tuple[list[_Hit], _Tally]:
        """Read and scan a batch of files. Runs in a worker thread."""
        hits: list[_Hit] = []
        tally = _Tally()

        for file_path in batch:
            try:
                relative = str(file_path.relative_to(root))
            except ValueError:
                relative = file_path.name

            if should_skip_file(relative):
                tally.skipped_binary += 1
                continue
            try:
                size = file_path.stat().st_size
            except OSError as exc:
                tally.unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue
            if size > MAX_FILE_BYTES:
                tally.skipped_large += 1
                continue
            try:
                content = file_path.read_bytes()
            except OSError as exc:
                tally.unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue

            if b"\x00" in content[:8192]:
                # A NUL byte early on means binary; scanning it yields noise.
                tally.skipped_binary += 1
                continue

            in_example = is_example_path(relative)
            if in_example and not include_examples:
                tally.skipped_examples += 1
                continue

            tally.files_examined += 1
            tally.bytes_examined += size
            text = content.decode("utf-8", errors="replace")
            hits.extend(self._scan_text(text, relative, in_example, salt))

        return hits, tally

    # ------------------------------------------------------------- traversal
    @staticmethod
    def _walk(root: Path, max_files: int) -> list[Path]:
        if root.is_file():
            return [root]
        collected: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Pruning in place stops os.walk descending into them at all,
            # which is what keeps a node_modules tree from dominating the run.
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                candidate = Path(dirpath) / name
                if candidate.is_symlink():
                    # A symlink could point outside the target tree; following
                    # it would read files the scan was not pointed at.
                    continue
                collected.append(candidate)
                if len(collected) >= max_files:
                    return collected
        return collected

    # -------------------------------------------------------------- matching
    @staticmethod
    def _scan_text(text: str, relative_path: str, in_example: bool, salt: str) -> list[_Hit]:
        """Match every rule against a file's lines.

        Provider rules run first and the values they claim are recorded. The
        generic entropy rule then runs only on values no provider rule matched,
        so it stays a genuine fallback for credentials with no recognisable
        shape. Without that ordering a Stripe key would be reported twice — once
        correctly as a Stripe key and once as an anonymous high-entropy string —
        and the second report is pure noise for whoever has to triage it.
        """
        hits: list[_Hit] = []
        lines = text.splitlines()

        # (rule_id, fingerprint) pairs already reported, so the same credential
        # repeated on several lines of one file is one thing to rotate.
        seen: set[tuple[str, str]] = set()
        # Fingerprints claimed by a provider rule anywhere in this file.
        claimed: set[str] = set()

        for rule in PROVIDER_RULES:
            for line_number, line in enumerate(lines, start=1):
                if len(line) > MAX_LINE_LENGTH:
                    continue
                for hit in SecretsEngine._match_rule(
                    rule, line, line_number, relative_path, in_example, salt, seen
                ):
                    claimed.add(fingerprint(hit.value, salt))
                    hits.append(hit)

        for line_number, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LENGTH:
                continue
            for hit in SecretsEngine._match_rule(
                GENERIC_RULE, line, line_number, relative_path, in_example, salt, seen
            ):
                if fingerprint(hit.value, salt) in claimed:
                    # A provider rule already identified this value precisely.
                    continue
                hits.append(hit)

        return hits

    @staticmethod
    def _match_rule(
        rule: SecretRule,
        line: str,
        line_number: int,
        relative_path: str,
        in_example: bool,
        salt: str,
        seen: set[tuple[str, str]],
    ) -> list[_Hit]:
        """Apply one rule to one line, filtering placeholders and duplicates."""
        hits: list[_Hit] = []
        for match in rule.pattern.finditer(line):
            group_count = match.lastindex or 0
            value = (
                match.group(rule.secret_group)
                if rule.secret_group and rule.secret_group <= group_count
                else match.group(0)
            )
            if not value:
                continue
            value = value.strip().strip("\"'")
            if is_placeholder(value):
                continue

            entropy = shannon_entropy(value)
            if rule.min_entropy and entropy < rule.min_entropy:
                continue

            key = (rule.rule_id, fingerprint(value, salt))
            if key in seen:
                continue
            seen.add(key)

            hits.append(
                _Hit(
                    rule=rule,
                    value=value,
                    file_path=relative_path,
                    line_number=line_number,
                    line_text=line,
                    entropy=entropy,
                    in_example_path=in_example,
                )
            )
        return hits

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(hit: _Hit, salt: str, ctx: EngineContext) -> ScanFinding:
        rule = hit.rule
        severity = rule.severity
        confidence = rule.confidence
        notes: list[str] = []

        if hit.in_example_path:
            # Reduced, not suppressed: a real credential does sometimes land in
            # a fixture, and silently dropping it would be the worse error.
            severity = _REDUCED_SEVERITY.get(severity, "info")
            confidence = "low"
            notes.append(
                "Found in a path that is conventionally test or example material, so the "
                "severity is reduced. Confirm whether the value is a live credential."
            )

        if _is_loopback_credential(hit.line_text):
            # A credential for a loopback address cannot be used by anyone who
            # is not already on the host, so this is a weak-default finding
            # rather than an exposed-credential one. Still reported: a default
            # that ships is a default that reaches production.
            severity = _REDUCED_SEVERITY.get(severity, "info")
            notes.append(
                "The connection string addresses a loopback host, so the credential is a "
                "local development default rather than one an external attacker could "
                "use. The severity is reduced accordingly. It is still worth removing: a "
                "default that ships is a default that reaches an environment where it "
                "does matter."
            )

        detection_method = "pattern+entropy" if rule.min_entropy > 0 else "pattern"
        if rule.rule_id == "secrets.high-entropy-assignment":
            detection_method = "entropy"
            notes.append(
                f"Detected by entropy ({hit.entropy:.2f} bits/char) on a field named like a "
                "credential, not by a known provider format. Verify before rotating."
            )

        # The redacted line keeps the finding reviewable without reproducing
        # the credential in the evidence record.
        redacted_preview = redact(hit.value)
        redacted_line = hit.line_text.replace(hit.value, redacted_preview)[:500]

        description_parts = [
            f"A value matching {rule.name!r} was found in {hit.file_path} at line "
            f"{hit.line_number}.",
            (
                "The credential itself is not stored by the platform: only this redacted "
                "preview and a keyed fingerprint used to recognise the same secret "
                "elsewhere and to confirm rotation."
            ),
        ]
        description_parts.extend(notes)

        return ScanFinding(
            engine="secrets",
            rule_id=rule.rule_id,
            category="exposed_secret",
            title=f"{rule.name} committed to {Path(hit.file_path).name}",
            description=" ".join(description_parts),
            severity=severity,
            confidence=confidence,
            cwe="CWE-798",
            owasp_top10="A07:2021",
            owasp_asvs=["V2.10", "V6.4"],
            impact=(
                "Anyone with read access to this artifact holds a working credential. For a "
                "repository that includes every past and future collaborator, and the "
                "credential stays valid after the file is deleted — only rotation revokes it."
            ),
            remediation=rule.remediation,
            reproduction=(
                f"Open {hit.file_path} at line {hit.line_number} and inspect the value "
                f"assigned there. Rule: {rule.rule_id}."
            ),
            evidence=Evidence(
                summary=(
                    f"{rule.name} matched at {hit.file_path}:{hit.line_number} "
                    f"(entropy {hit.entropy:.2f} bits/char, detected by {detection_method})"
                ),
                matched_value=redacted_preview,
                code_snippet=redacted_line,
                artifacts={
                    "detection_method": detection_method,
                    "entropy": round(hit.entropy, 3),
                    "secret_length": len(hit.value),
                    "in_example_path": hit.in_example_path,
                    "verifiable": rule.verifiable,
                },
            ),
            code_location=CodeLocation(
                file_path=hit.file_path,
                start_line=hit.line_number,
                snippet=redacted_line,
            ),
            # Each distinct credential is its own defect: three different keys
            # in one settings file are three rotations, not one issue. The
            # keyed fingerprint is what distinguishes them, and it also means
            # the same credential copied into a second file correlates to the
            # one issue it actually is.
            correlation_discriminator=fingerprint(hit.value, salt),
            target=ctx.target,
            references=list(rule.references)
            or [
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
            ],
            raw={
                # Consumed by the ingestion layer to populate `detected_secrets`.
                "secret_type": rule.secret_type,
                "detector": rule.rule_id,
                "detection_method": detection_method,
                "redacted_preview": redacted_preview,
                "secret_fingerprint": fingerprint(hit.value, salt),
                "entropy": round(hit.entropy, 3),
                "exposure": "internal",
                "verifiable": rule.verifiable,
            },
        )
