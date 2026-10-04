"""Mobile application static analysis.

A **passive, sandboxed** engine. It reads a packaged application — an Android
APK or AAB, or an iOS IPA — and never executes it, never installs it, and
never contacts the network. The artifact is attacker-controlled input, so the
engine declares the ``sandbox`` capability: the platform runs it out of the
API process, and the parsers it uses bound every length and offset they read.

What is assessed, and on what evidence:

* **The Android manifest** — decoded from its binary form. Settings such as
  ``android:debuggable``, ``android:allowBackup``, cleartext traffic and
  exported components are facts about the shipped artifact, reported with high
  or confirmed confidence.
* **The network security configuration** — where one is declared and its
  resource can be located, cleartext permission and user-installed trust
  anchors are read from it.
* **The signing block** — which signature schemes are present, since a v1-only
  APK is modifiable while still verifying.
* **The compiled code's tables** — the strings, types and method references in
  ``classes*.dex``. A method reference proves the call site exists; it does not
  prove the call executes, and those findings say so and carry lower
  confidence accordingly.
* **The iOS property list and provisioning profile** — App Transport Security,
  file sharing, custom URL schemes, and the ``get-task-allow`` debugging
  entitlement.
* **Embedded credentials** — the platform's secret rules applied to the
  application's string pool and resources, with the same placeholder filtering
  used elsewhere so a sample key in a bundled test fixture is not reported as
  a live credential.

Where the artifact cannot be fully read — an undecodable manifest, a DEX whose
tables are truncated, a member refused as a decompression bomb — the run is
reported as *degraded* with the specific coverage that is missing. An empty
finding list from a partial read must never read as "nothing wrong here".
"""

from __future__ import annotations

import asyncio
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qguard_scanner.parsers.archive import ArchiveError, SafeArchive
from qguard_scanner.parsers.axml import AxmlDocument, AxmlElement, AxmlError, parse_axml
from qguard_scanner.parsers.dex import DexError, DexFile, merge, parse_dex
from qguard_scanner.rules.mobile_rules import (
    ANDROID_OUTDATED_TARGET_SDK,
    ANDROID_UNSUPPORTED_SDK,
    IOS_UNSUPPORTED_MAJOR,
    MANIFEST_RULES,
    METHOD_RULES,
    STRING_RULES,
    MobileRule,
    permission_risk,
)
from qguard_scanner.rules.secret_patterns import (
    ALL_RULES as SECRET_RULES,
)
from qguard_scanner.rules.secret_patterns import (
    is_placeholder,
)
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import CodeLocation, Evidence, ScanFinding
from qguard_scanner.sdk.registry import register_engine
from qguard_scanner.sdk.secretutil import (
    DEFAULT_FINGERPRINT_SALT,
    fingerprint,
    redact,
)

#: Recognised packaging formats, by file extension.
ANDROID_SUFFIXES = (".apk", ".aab", ".apks")
IOS_SUFFIXES = (".ipa",)

#: Largest artifact the engine will open.
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024

#: Per-member read limits.
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_DEX_BYTES = 48 * 1024 * 1024
MAX_PLIST_BYTES = 4 * 1024 * 1024
MAX_TEXT_RESOURCE_BYTES = 2 * 1024 * 1024

#: Largest number of DEX files read from one artifact. A multi-DEX application
#: rarely exceeds a dozen; a hundred indicates padding.
MAX_DEX_FILES = 24

#: Largest number of bundled text resources read from one artifact.
MAX_TEXT_RESOURCES = 400

#: Native binary limits. A stripped shared library is a few megabytes; the
#: ceiling keeps a padded one from dominating the run.
MAX_NATIVE_BINARY_BYTES = 32 * 1024 * 1024
MAX_NATIVE_BINARIES = 12
MAX_NATIVE_STRINGS = 200_000

#: Shortest string considered for secret matching. Below this a match is noise.
MIN_SECRET_LENGTH = 8

#: Longest string considered. A very long literal is embedded data, not a
#: credential, and scanning it with every rule is wasted work.
MAX_SECRET_CANDIDATE_LENGTH = 4096

#: Components whose export is assessed, with the rule key used for each.
_EXPORTABLE = {
    "activity": "exported_component",
    "activity-alias": "exported_component",
    "service": "exported_component",
    "receiver": "exported_component",
    "provider": "exported_provider",
}

#: Resource paths a network security configuration is conventionally found at.
#: The manifest references it by resource ID, which cannot be resolved without
#: the resource table, so the conventional paths are read instead and the
#: finding states which file was assessed.
_NSC_CANDIDATE_PATHS = (
    "res/xml/network_security_config.xml",
    "res/xml/network_security_configuration.xml",
    "res/xml/nsc.xml",
    "res/xml/networksecurityconfig.xml",
)

_TEXT_RESOURCE_SUFFIXES = (".json", ".xml", ".properties", ".txt", ".js", ".plist", ".yaml", ".yml")


@dataclass(slots=True)
class _Issue:
    """An internal finding, converted to a :class:`ScanFinding` at the end."""

    rule: MobileRule
    summary: str
    location: str
    description_suffix: str = ""
    severity_override: str | None = None
    confidence_override: str | None = None
    discriminator: str | None = None
    matched_value: str | None = None
    snippet: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    title_override: str | None = None


@dataclass(slots=True)
class _ArtifactFacts:
    """Everything read from the artifact, before any check runs."""

    kind: str = "unknown"
    manifest: AxmlDocument | None = None
    dex: DexFile | None = None
    plist: dict[str, Any] = field(default_factory=dict)
    entitlements: dict[str, Any] = field(default_factory=dict)
    nsc: AxmlDocument | None = None
    nsc_path: str | None = None
    signature_schemes: list[str] = field(default_factory=list)
    text_resources: dict[str, str] = field(default_factory=dict)
    coverage_gaps: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


@register_engine
class MobileEngine(SecurityEngine):
    """Static analysis of packaged Android and iOS applications."""

    metadata = EngineMetadata(
        key="mobile",
        name="Mobile application analysis",
        description=(
            "Statically analyses an Android APK/AAB or iOS IPA: manifest and plist "
            "configuration, transport security, component exposure, signing, compiled "
            "code references and embedded credentials. Never executes the artifact."
        ),
        version="1.0.0",
        target_kinds=("mobile_app", "file", "artifact"),
        capabilities=frozenset({EngineCapability.FILESYSTEM, EngineCapability.SANDBOX}),
        categories=(
            "platform_misuse",
            "insecure_storage",
            "insecure_communication",
            "cryptographic_failure",
            "broken_access_control",
            "exposed_secret",
            "code_quality_security",
            "information_disclosure",
            "supply_chain",
            "injection",
            "insecure_deserialization",
            "command_execution",
        ),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        path = self._artifact_path(ctx)
        if path is None:
            return (
                f"The target {ctx.target.value!r} is not a path to a packaged application, "
                "so there was nothing to analyse."
            )
        if not path.is_file():
            return f"{path} does not exist or is not a file, so there was nothing to analyse."
        size = path.stat().st_size
        if size == 0:
            return f"{path} is empty."
        if size > MAX_ARTIFACT_BYTES:
            return (
                f"{path.name} is {size} bytes, beyond this engine's {MAX_ARTIFACT_BYTES}-byte "
                "limit, so it was not opened."
            )
        if path.suffix.lower() not in (*ANDROID_SUFFIXES, *IOS_SUFFIXES):
            return (
                f"{path.name} has the extension {path.suffix!r}, which is not a recognised "
                f"mobile package. Supported: {', '.join((*ANDROID_SUFFIXES, *IOS_SUFFIXES))}."
            )
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        path = self._artifact_path(ctx)
        if path is None:  # pragma: no cover - preflight rejects this first
            return EngineResult.failed(self.key, "No artifact path was resolved.")

        await ctx.report_progress(10, f"reading {path.name}")

        try:
            facts = await asyncio.to_thread(self._read_artifact, path)
        except ArchiveError as exc:
            return EngineResult.failed(
                self.key, f"{path.name} could not be read as an archive: {exc}"
            )

        if facts.kind == "unknown":
            return EngineResult.failed(
                self.key,
                (
                    f"{path.name} is a readable archive but contains neither an Android "
                    "manifest nor an iOS Info.plist, so it is not a packaged mobile "
                    "application this engine can assess."
                ),
                stats=facts.stats,
            )

        await ctx.report_progress(55, f"assessing {facts.kind} application")

        issues: list[_Issue] = []
        if facts.kind == "android":
            issues.extend(self._assess_android(facts))
        else:
            issues.extend(self._assess_ios(facts))
        issues.extend(
            self._assess_embedded_secrets(
                facts, str(ctx.option("fingerprint_salt", DEFAULT_FINGERPRINT_SALT))
            )
        )

        findings = [self._to_finding(issue, path, ctx) for issue in issues]

        common = {
            "stats": facts.stats,
            "items_examined": int(facts.stats.get("members_indexed", 0)),
            "checks_executed": len(MANIFEST_RULES) + len(METHOD_RULES) + len(STRING_RULES),
            "warnings": facts.coverage_gaps[:20],
        }
        if facts.coverage_gaps:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    "parts of the artifact could not be read, so the assessment is "
                    "incomplete: " + "; ".join(facts.coverage_gaps[:4])
                ),
                **common,
            )
        return EngineResult.completed(self.key, findings, **common)

    # ----------------------------------------------------------------- input
    @staticmethod
    def _artifact_path(ctx: EngineContext) -> Path | None:
        raw = ctx.option("artifact_path") or ctx.target.value
        if not raw:
            return None
        path = Path(str(raw))
        if not path.is_absolute() and ctx.workdir is not None:
            path = ctx.workdir / path
        return path

    def _read_artifact(self, path: Path) -> _ArtifactFacts:
        """Read everything the checks need, in one pass over the archive."""
        facts = _ArtifactFacts()
        with SafeArchive.open(path) as archive:
            facts.stats = {
                **archive.stats(),
                "artifact_bytes": path.stat().st_size,
                "artifact_name": path.name,
            }
            facts.stats["members_indexed"] = len(archive.members)
            for refusal in archive.refusals:
                facts.coverage_gaps.append(
                    f"the archive member {refusal.name!r} was not read because {refusal.reason}"
                )
            if archive.truncated:
                facts.coverage_gaps.append(
                    "the archive contains more members than the index limit allows, so the "
                    "remainder was not examined"
                )

            manifest_member = self._android_manifest_member(archive)
            if manifest_member is not None:
                facts.kind = "android"
                self._read_android(archive, manifest_member, facts)
                return facts

            plist_member = self._ios_plist_member(archive)
            if plist_member is not None:
                facts.kind = "ios"
                self._read_ios(archive, plist_member, facts)
                return facts

        return facts

    @staticmethod
    def _android_manifest_member(archive: SafeArchive) -> str | None:
        for candidate in ("AndroidManifest.xml", "base/manifest/AndroidManifest.xml"):
            if archive.has(candidate):
                return candidate
        # A .apks bundle wraps split APKs; the base split carries the manifest.
        manifests = archive.find(suffix="AndroidManifest.xml")
        return manifests[0].name if manifests else None

    @staticmethod
    def _ios_plist_member(archive: SafeArchive) -> str | None:
        candidates = [
            m.name
            for m in archive.find(prefix="Payload/", suffix="Info.plist")
            # The app bundle's own Info.plist sits directly inside the .app,
            # not inside a nested framework or extension bundle.
            if m.name.count("/") == 2
        ]
        if candidates:
            return sorted(candidates, key=len)[0]
        nested = archive.find(prefix="Payload/", suffix="Info.plist")
        return sorted((m.name for m in nested), key=len)[0] if nested else None

    # ------------------------------------------------------------- android IO
    def _read_android(
        self, archive: SafeArchive, manifest_name: str, facts: _ArtifactFacts
    ) -> None:
        try:
            raw = archive.read(manifest_name, limit=MAX_MANIFEST_BYTES)
            facts.manifest = parse_axml(raw)
            facts.stats["manifest_member"] = manifest_name
            if facts.manifest.warnings:
                facts.coverage_gaps.extend(
                    f"the manifest was only partly decoded: {w}" for w in facts.manifest.warnings
                )
        except (ArchiveError, AxmlError) as exc:
            facts.coverage_gaps.append(
                f"the manifest {manifest_name!r} could not be decoded ({exc}), so no "
                "manifest, permission or component check ran"
            )

        for candidate in _NSC_CANDIDATE_PATHS:
            if not archive.has(candidate):
                continue
            try:
                facts.nsc = parse_axml(archive.read(candidate, limit=MAX_MANIFEST_BYTES))
                facts.nsc_path = candidate
            except (ArchiveError, AxmlError) as exc:
                facts.coverage_gaps.append(
                    f"the network security configuration {candidate!r} could not be decoded "
                    f"({exc}), so its cleartext and trust-anchor settings were not assessed"
                )
            break

        dex_members = sorted(
            (m for m in archive.find(suffix=".dex")),
            key=lambda m: m.name,
        )
        facts.stats["dex_members"] = [m.name for m in dex_members]
        if len(dex_members) > MAX_DEX_FILES:
            facts.coverage_gaps.append(
                f"the artifact contains {len(dex_members)} DEX files; only the first "
                f"{MAX_DEX_FILES} were read, so code in the remainder was not assessed"
            )
            dex_members = dex_members[:MAX_DEX_FILES]

        parsed: list[DexFile] = []
        for member in dex_members:
            try:
                parsed.append(parse_dex(archive.read_member(member, limit=MAX_DEX_BYTES)))
            except (ArchiveError, DexError) as exc:
                facts.coverage_gaps.append(
                    f"the compiled code in {member.name!r} could not be read ({exc}), so no "
                    "code-level check covered it"
                )
        if parsed:
            facts.dex = merge(parsed)
            facts.stats["dex"] = facts.dex.stats()
            if facts.dex.truncated:
                facts.coverage_gaps.append(
                    "a DEX file declared more entries than the parser's limit, so part of "
                    "the application's code was not assessed"
                )
        elif dex_members:
            facts.coverage_gaps.append("no DEX file could be parsed, so no code-level check ran")
        else:
            # An AAB stores code as .dex under base/dex/; its absence in an APK
            # means the artifact has no bytecode, which is itself notable.
            facts.coverage_gaps.append(
                "the artifact contains no DEX file, so it carries no Dalvik bytecode and "
                "no code-level check ran"
            )

        facts.signature_schemes = self._signature_schemes(archive)
        facts.stats["signature_schemes"] = facts.signature_schemes
        self._read_text_resources(archive, facts)

    @staticmethod
    def _signature_schemes(archive: SafeArchive) -> list[str]:
        """Which signature schemes the archive carries.

        v1 is visible as JAR signature files under ``META-INF``. v2 and later
        live in the APK Signing Block, which sits between the archive entries
        and the central directory and is therefore not an archive member — its
        presence is detected by reading the block's magic from the file.
        """
        schemes: list[str] = []
        v1 = [
            m.name
            for m in archive.members
            if m.name.startswith("META-INF/")
            and m.name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))
        ]
        if v1:
            schemes.append("v1")

        try:
            with archive.path.open("rb") as handle:
                size = archive.path.stat().st_size
                # The signing block's magic is the 16 bytes immediately before
                # the central directory. Scanning the archive's tail finds it
                # without parsing the whole ZIP structure.
                window = min(size, 128 * 1024)
                handle.seek(size - window)
                tail = handle.read(window)
        except OSError:
            return schemes

        if b"APK Sig Block 42" in tail:
            schemes.append("v2+")
        return schemes

    def _read_text_resources(self, archive: SafeArchive, facts: _ArtifactFacts) -> None:
        """Read bundled text resources, where credentials are frequently left.

        Android and iOS lay their bundles out differently — ``assets/`` and
        ``res/raw/`` against everything inside the ``.app`` directory — so the
        selection is per platform rather than one prefix list that silently
        misses half of one format's resources.
        """
        if facts.kind == "ios":
            interesting = [
                m
                for m in archive.members
                if m.name.lower().endswith(_TEXT_RESOURCE_SUFFIXES)
                and m.name.startswith("Payload/")
                and m.uncompressed_size <= MAX_TEXT_RESOURCE_BYTES
            ]
        else:
            interesting = [
                m
                for m in archive.members
                if m.name.lower().endswith(_TEXT_RESOURCE_SUFFIXES)
                and (
                    m.name.startswith(("assets/", "res/raw/", "res/xml/", "base/assets/"))
                    or m.name.count("/") <= 1
                )
                and m.uncompressed_size <= MAX_TEXT_RESOURCE_BYTES
            ]

        for member in interesting[:MAX_TEXT_RESOURCES]:
            try:
                facts.text_resources[member.name] = archive.read_member(
                    member, limit=MAX_TEXT_RESOURCE_BYTES
                ).decode("utf-8", errors="replace")
            except ArchiveError:
                # Not a coverage gap worth reporting: a single unreadable
                # bundled resource does not change what the checks establish
                # about the application's configuration or code.
                continue
        if len(interesting) > MAX_TEXT_RESOURCES:
            facts.coverage_gaps.append(
                f"the artifact bundles {len(interesting)} text resources; only the first "
                f"{MAX_TEXT_RESOURCES} were read, so literals in the remainder were not "
                "assessed"
            )

        self._read_native_strings(archive, facts)

    def _read_native_strings(self, archive: SafeArchive, facts: _ArtifactFacts) -> None:
        """Extract printable strings from the application's native binaries.

        Native code is where memory-unsafe C functions and iOS Keychain
        accessibility constants are visible, and neither the DEX tables nor a
        property list reaches them. Only the printable runs are extracted —
        the binary is never loaded, parsed as an executable, or run.
        """
        if facts.kind == "ios":
            binaries = [
                m
                for m in archive.members
                if m.name.startswith("Payload/")
                and "." not in m.name.rsplit("/", 1)[-1]
                and m.uncompressed_size <= MAX_NATIVE_BINARY_BYTES
            ]
        else:
            binaries = [
                m
                for m in archive.members
                if m.name.endswith(".so") and m.uncompressed_size <= MAX_NATIVE_BINARY_BYTES
            ]

        for member in binaries[:MAX_NATIVE_BINARIES]:
            try:
                raw = archive.read_member(member, limit=MAX_NATIVE_BINARY_BYTES)
            except ArchiveError as exc:
                facts.coverage_gaps.append(
                    f"the native binary {member.name!r} could not be read ({exc}), so no "
                    "native string check covered it"
                )
                continue
            extracted = self._printable_runs(raw)
            if extracted:
                facts.text_resources[member.name] = "\n".join(extracted)
                facts.stats.setdefault("native_binaries", []).append(
                    {"name": member.name, "strings": len(extracted)}
                )

    @staticmethod
    def _printable_runs(data: bytes, minimum: int = 6) -> list[str]:
        """Printable ASCII runs in a binary, as ``strings`` would find them."""
        runs: list[str] = []
        current = bytearray()
        for byte in data:
            if 0x20 <= byte < 0x7F:
                current.append(byte)
                continue
            if len(current) >= minimum:
                runs.append(current.decode("ascii"))
                if len(runs) >= MAX_NATIVE_STRINGS:
                    return runs
            current.clear()
        if len(current) >= minimum:
            runs.append(current.decode("ascii"))
        return runs

    # ----------------------------------------------------------------- ios IO
    def _read_ios(self, archive: SafeArchive, plist_name: str, facts: _ArtifactFacts) -> None:
        facts.stats["plist_member"] = plist_name
        try:
            raw = archive.read(plist_name, limit=MAX_PLIST_BYTES)
            loaded = plistlib.loads(raw)
            facts.plist = loaded if isinstance(loaded, dict) else {}
            if not isinstance(loaded, dict):
                facts.coverage_gaps.append(
                    f"{plist_name!r} parsed but is not a dictionary, so no plist check ran"
                )
        except (ArchiveError, plistlib.InvalidFileException, ValueError) as exc:
            facts.coverage_gaps.append(
                f"the property list {plist_name!r} could not be parsed ({exc}), so no "
                "transport-security, file-sharing or URL-scheme check ran"
            )

        bundle = plist_name.rsplit("/", 1)[0]
        profile = f"{bundle}/embedded.mobileprovision"
        if archive.has(profile):
            try:
                facts.entitlements = self._parse_mobileprovision(
                    archive.read(profile, limit=MAX_PLIST_BYTES)
                )
                facts.stats["provisioning_profile"] = profile
            except (ArchiveError, ValueError) as exc:
                facts.coverage_gaps.append(
                    f"the provisioning profile {profile!r} could not be parsed ({exc}), so "
                    "the debugging-entitlement check did not run"
                )
        else:
            facts.coverage_gaps.append(
                "the bundle contains no embedded.mobileprovision, so entitlements — "
                "including whether debugging is permitted — were not assessed"
            )

        self._read_text_resources(archive, facts)

    @staticmethod
    def _parse_mobileprovision(data: bytes) -> dict[str, Any]:
        """Extract the plist from a CMS-wrapped provisioning profile.

        The profile is a signed CMS envelope around an XML plist. The plist is
        recovered by locating its boundaries rather than verifying the
        signature: the question here is what the profile grants, and the
        signature's validity is a separate concern from its contents.
        """
        start = data.find(b"<?xml")
        if start == -1:
            raise ValueError("the profile contains no XML plist")
        end = data.find(b"</plist>", start)
        if end == -1:
            raise ValueError("the profile's plist is not terminated")
        loaded = plistlib.loads(data[start : end + len(b"</plist>")])
        if not isinstance(loaded, dict):
            raise ValueError("the profile's plist is not a dictionary")
        entitlements = loaded.get("Entitlements")
        return entitlements if isinstance(entitlements, dict) else loaded

    # ------------------------------------------------------- android checks
    def _assess_android(self, facts: _ArtifactFacts) -> list[_Issue]:
        issues: list[_Issue] = []
        manifest = facts.manifest
        if manifest is not None:
            issues.extend(self._assess_manifest(manifest, facts))
            issues.extend(self._assess_permissions(manifest))
            issues.extend(self._assess_components(manifest))
        issues.extend(self._assess_signing(facts))
        if facts.nsc is not None:
            issues.extend(self._assess_nsc(facts.nsc, facts.nsc_path or "(unknown)"))
        if facts.dex is not None:
            issues.extend(self._assess_dex_methods(facts.dex))
        issues.extend(self._assess_strings(self._string_candidates(facts)))
        return issues

    def _assess_manifest(self, manifest: AxmlDocument, facts: _ArtifactFacts) -> list[_Issue]:
        issues: list[_Issue] = []
        package = self._package_name(manifest)
        application = manifest.root.find("application")

        if application is not None:
            debuggable = application.attribute("debuggable")
            if debuggable is not None and debuggable.as_bool() is True:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["debuggable"],
                        summary='AndroidManifest.xml: android:debuggable="true" on <application>',
                        location="AndroidManifest.xml",
                        discriminator="manifest:debuggable",
                        matched_value="true",
                        artifacts={"package": package},
                    )
                )

            backup = application.attribute("allowBackup")
            min_sdk = self._min_sdk(manifest)
            if backup is None:
                # The platform default is true below API 31. Absent the
                # attribute, the effective value depends on minSdkVersion, so
                # the finding states which case applies rather than assuming.
                if min_sdk is not None and min_sdk < 31:
                    issues.append(
                        _Issue(
                            rule=MANIFEST_RULES["allowBackup"],
                            summary=(
                                "AndroidManifest.xml: android:allowBackup is not set and "
                                f"minSdkVersion is {min_sdk}, so the platform default of "
                                "true applies"
                            ),
                            location="AndroidManifest.xml",
                            description_suffix=(
                                " The attribute is absent from this manifest; the finding "
                                f"follows from the platform default for minSdkVersion "
                                f"{min_sdk}, not from an explicit setting."
                            ),
                            confidence_override="medium",
                            discriminator="manifest:allowBackup",
                            artifacts={"package": package, "explicit": False, "min_sdk": min_sdk},
                        )
                    )
            elif backup.as_bool() is True:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["allowBackup"],
                        summary='AndroidManifest.xml: android:allowBackup="true"',
                        location="AndroidManifest.xml",
                        discriminator="manifest:allowBackup",
                        matched_value="true",
                        artifacts={"package": package, "explicit": True},
                    )
                )

            cleartext = application.attribute("usesCleartextTraffic")
            if cleartext is not None and cleartext.as_bool() is True:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["usesCleartextTraffic"],
                        summary='AndroidManifest.xml: android:usesCleartextTraffic="true"',
                        location="AndroidManifest.xml",
                        discriminator="manifest:cleartextTraffic",
                        matched_value="true",
                        artifacts={"package": package},
                    )
                )

            if application.attribute("backupAgent") is not None:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["backup_agent"],
                        summary=(
                            "AndroidManifest.xml: android:backupAgent="
                            f"{application.get('backupAgent')!r}"
                        ),
                        location="AndroidManifest.xml",
                        discriminator="manifest:backupAgent",
                        matched_value=application.get("backupAgent"),
                        artifacts={"agent": application.get("backupAgent")},
                    )
                )

            nsc_attribute = application.attribute("networkSecurityConfig")
            if nsc_attribute is None:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["no_network_security_config"],
                        summary=(
                            "AndroidManifest.xml: <application> declares no "
                            "android:networkSecurityConfig"
                        ),
                        location="AndroidManifest.xml",
                        discriminator="manifest:no-nsc",
                        artifacts={"package": package},
                    )
                )
            elif facts.nsc is None:
                facts.coverage_gaps.append(
                    "the manifest declares a network security configuration as the resource "
                    f"{nsc_attribute.value}, but no file at the conventional paths "
                    f"({', '.join(_NSC_CANDIDATE_PATHS)}) could be decoded, so its cleartext "
                    "and trust-anchor settings were not assessed"
                )

            if application.attribute("testOnly") is not None and (
                application.get_bool("testOnly") is True
            ):
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["test_only"],
                        summary='AndroidManifest.xml: android:testOnly="true"',
                        location="AndroidManifest.xml",
                        discriminator="manifest:testOnly",
                        matched_value="true",
                    )
                )

        if manifest.root.attribute("sharedUserId") is not None:
            issues.append(
                _Issue(
                    rule=MANIFEST_RULES["shared_user_id"],
                    summary=(
                        "AndroidManifest.xml: android:sharedUserId="
                        f"{manifest.root.get('sharedUserId')!r}"
                    ),
                    location="AndroidManifest.xml",
                    discriminator="manifest:sharedUserId",
                    matched_value=manifest.root.get("sharedUserId"),
                )
            )

        min_sdk = self._min_sdk(manifest)
        if min_sdk is not None and min_sdk <= ANDROID_UNSUPPORTED_SDK:
            issues.append(
                _Issue(
                    rule=MANIFEST_RULES["min_sdk_outdated"],
                    summary=f"AndroidManifest.xml: android:minSdkVersion={min_sdk}",
                    location="AndroidManifest.xml",
                    description_suffix=(
                        f" This artifact declares minSdkVersion {min_sdk}; API level "
                        f"{ANDROID_UNSUPPORTED_SDK} and below no longer receive security fixes."
                    ),
                    discriminator="manifest:minSdk",
                    matched_value=str(min_sdk),
                    artifacts={
                        "min_sdk": min_sdk,
                        "unsupported_at_or_below": ANDROID_UNSUPPORTED_SDK,
                    },
                )
            )

        target_sdk = self._target_sdk(manifest)
        if target_sdk is not None and target_sdk < ANDROID_OUTDATED_TARGET_SDK:
            issues.append(
                _Issue(
                    rule=MANIFEST_RULES["target_sdk_outdated"],
                    summary=f"AndroidManifest.xml: android:targetSdkVersion={target_sdk}",
                    location="AndroidManifest.xml",
                    description_suffix=(
                        f" This artifact targets API level {target_sdk}, below the "
                        f"{ANDROID_OUTDATED_TARGET_SDK} at which the platform applies its "
                        "current defaults."
                    ),
                    discriminator="manifest:targetSdk",
                    matched_value=str(target_sdk),
                    artifacts={"target_sdk": target_sdk},
                )
            )

        for permission in manifest.find_all("permission"):
            level = (permission.get("protectionLevel") or "").lower()
            name = permission.get("name") or "(unnamed)"
            # An unset protectionLevel defaults to normal, which is the weak case.
            if level in ("", "normal", "dangerous") or level.startswith(("normal", "dangerous")):
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["custom_permission_normal"],
                        summary=(
                            f"AndroidManifest.xml: <permission> {name} has protectionLevel "
                            f"{level or 'unset (defaults to normal)'}"
                        ),
                        location="AndroidManifest.xml",
                        discriminator=f"manifest:permission:{name}",
                        matched_value=level or "normal (default)",
                        artifacts={"permission": name, "protection_level": level or "normal"},
                    )
                )

        return issues

    @staticmethod
    def _package_name(manifest: AxmlDocument) -> str | None:
        attribute = manifest.root.attribute("package", namespace=None)
        return attribute.value if attribute is not None else None

    @staticmethod
    def _min_sdk(manifest: AxmlDocument) -> int | None:
        uses_sdk = manifest.root.find("uses-sdk")
        if uses_sdk is not None and (value := uses_sdk.get_int("minSdkVersion")) is not None:
            return value
        return None

    @staticmethod
    def _target_sdk(manifest: AxmlDocument) -> int | None:
        uses_sdk = manifest.root.find("uses-sdk")
        if uses_sdk is not None and (value := uses_sdk.get_int("targetSdkVersion")) is not None:
            return value
        return None

    @staticmethod
    def _assess_permissions(manifest: AxmlDocument) -> list[_Issue]:
        issues: list[_Issue] = []
        requested = [
            name
            for element in manifest.find_all("uses-permission")
            if (name := element.get("name"))
        ]
        requested += [
            name
            for element in manifest.find_all("uses-permission-sdk-23")
            if (name := element.get("name"))
        ]
        for permission in sorted(set(requested)):
            risk = permission_risk(permission)
            if risk is None:
                continue
            short = permission.rsplit(".", 1)[-1]
            issues.append(
                _Issue(
                    rule=MobileRule(
                        rule_id=f"MOB-ANDROID-PERMISSION-{short}",
                        title=f"Application requests {short}",
                        category="platform_misuse",
                        severity=risk.severity,
                        confidence="confirmed",
                        description=(
                            f"The manifest requests `{permission}`. {risk.rationale} "
                            "Holding the permission is not itself a vulnerability — it is "
                            "attack surface, and it determines how much damage any "
                            "compromise of this application can do."
                        ),
                        impact=risk.rationale,
                        remediation=(
                            "Confirm the application's functionality genuinely requires this "
                            "permission. If it does, document why, request it at the point of "
                            "use rather than at install, and handle the data it grants access "
                            "to as sensitive. If it does not, remove it."
                        ),
                        platform="android",
                        cwe="CWE-250",
                        masvs=("MASVS-PLATFORM-1",),
                        mastg=("MASTG-TEST-0029",),
                    ),
                    summary=f'AndroidManifest.xml: <uses-permission android:name="{permission}"/>',
                    location="AndroidManifest.xml",
                    discriminator=f"permission:{permission}",
                    matched_value=permission,
                    artifacts={
                        "permission": permission,
                        "android_dangerous": risk.is_dangerous,
                    },
                )
            )
        return issues

    def _assess_components(self, manifest: AxmlDocument) -> list[_Issue]:
        issues: list[_Issue] = []
        target_sdk = self._target_sdk(manifest)

        for tag, rule_key in _EXPORTABLE.items():
            for component in manifest.find_all(tag):
                name = component.get("name") or "(unnamed)"
                exported_attribute = component.attribute("exported")
                exported = exported_attribute.as_bool() if exported_attribute is not None else None
                has_intent_filter = component.find("intent-filter") is not None

                if exported is None:
                    # From API 31 export must be declared explicitly when an
                    # intent filter is present, so an absent attribute means
                    # not exported. Below that, a filter implies exported.
                    if not has_intent_filter:
                        continue
                    if target_sdk is not None and target_sdk >= 31:
                        continue
                    exported = True
                    target_description = (
                        str(target_sdk) if target_sdk is not None else "an unspecified level"
                    )
                    inference = (
                        " The `android:exported` attribute is absent; the component is "
                        "treated as exported because it declares an intent filter and the "
                        f"application targets API {target_description}, below the 31 at "
                        "which explicit declaration became mandatory."
                    )
                    confidence: str | None = "medium"
                elif not exported:
                    continue
                else:
                    inference = ""
                    confidence = None

                permission = (
                    component.get("permission")
                    or component.get("readPermission")
                    or component.get("writePermission")
                )
                if permission:
                    continue

                extra = inference
                if (
                    tag == "provider"
                    and component.get_bool("grantUriPermissions") is True
                    and component.find("grant-uri-permission") is None
                ):
                    issues.append(
                        _Issue(
                            rule=MANIFEST_RULES["grant_uri_permissions_wildcard"],
                            summary=(
                                f"AndroidManifest.xml: <provider> {name} sets "
                                'android:grantUriPermissions="true" with no '
                                "<grant-uri-permission> restriction"
                            ),
                            location="AndroidManifest.xml",
                            discriminator=f"component:{name}:grant-uri",
                            matched_value=name,
                            artifacts={
                                "component": name,
                                "authorities": component.get("authorities"),
                            },
                        )
                    )

                schemes = [
                    scheme for data in component.find_all("data") if (scheme := data.get("scheme"))
                ]
                if schemes:
                    extra += (
                        " The component is reachable through the URL scheme(s) "
                        f"{', '.join(sorted(set(schemes)))}, so a web page or another "
                        "application can reach it with a chosen URL."
                    )

                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES[rule_key],
                        summary=(
                            f"AndroidManifest.xml: <{tag}> {name} is exported with no "
                            "android:permission"
                        ),
                        location="AndroidManifest.xml",
                        description_suffix=extra,
                        confidence_override=confidence,
                        discriminator=f"component:{tag}:{name}",
                        matched_value=name,
                        artifacts={
                            "component": name,
                            "component_type": tag,
                            "has_intent_filter": has_intent_filter,
                            "authorities": component.get("authorities"),
                            "url_schemes": sorted(set(schemes)),
                            "exported_explicitly": exported_attribute is not None,
                        },
                        title_override=(
                            f"{tag.capitalize()} {name} is exported without permission protection"
                        ),
                    )
                )

        return issues

    @staticmethod
    def _assess_signing(facts: _ArtifactFacts) -> list[_Issue]:
        schemes = facts.signature_schemes
        if not schemes:
            return [
                _Issue(
                    rule=MANIFEST_RULES["unsigned"],
                    summary="no META-INF signature files and no APK Signing Block were found",
                    location=facts.stats.get("artifact_name", "(artifact)"),
                    discriminator="signing:absent",
                    artifacts={"schemes": schemes},
                )
            ]
        if schemes == ["v1"]:
            return [
                _Issue(
                    rule=MANIFEST_RULES["v1_signature_only"],
                    summary=(
                        "META-INF JAR signature files are present but no APK Signing Block "
                        "(v2 or later) was found"
                    ),
                    location=facts.stats.get("artifact_name", "(artifact)"),
                    discriminator="signing:v1-only",
                    artifacts={"schemes": schemes},
                )
            ]
        return []

    @staticmethod
    def _assess_nsc(nsc: AxmlDocument, path: str) -> list[_Issue]:
        issues: list[_Issue] = []

        def scope_of(element: AxmlElement) -> str:
            """Which hosts a configuration element applies to."""
            if element.name == "base-config":
                return "every domain the application contacts"
            domains = [
                text
                for domain in element.find_all("domain")
                # <domain> carries the host as character data, which the
                # decoder does not retain, so the name attribute is used where
                # aapt kept one and the element is named otherwise.
                if (text := domain.get("name") or domain.get("host"))
            ]
            if domains:
                return "the domains " + ", ".join(sorted(set(domains)))
            return f"the domains declared under <{element.name}>"

        for element in (*nsc.find_all("base-config"), *nsc.find_all("domain-config")):
            cleartext = element.attribute("cleartextTrafficPermitted", namespace=None)
            if cleartext is None:
                cleartext = element.attribute("cleartextTrafficPermitted")
            if cleartext is not None and cleartext.as_bool() is True:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["nsc_cleartext_permitted"],
                        summary=(f'{path}: <{element.name} cleartextTrafficPermitted="true">'),
                        location=path,
                        description_suffix=f" This applies to {scope_of(element)}.",
                        discriminator=f"nsc:cleartext:{element.name}",
                        matched_value="true",
                        artifacts={"element": element.name, "file": path},
                    )
                )

        # A user trust anchor inside <debug-overrides> is ignored by the
        # platform in release builds, so only anchors outside it are reported.
        debug_sections = nsc.find_all("debug-overrides")
        debug_certificates = {
            id(certificate)
            for section in debug_sections
            for certificate in section.find_all("certificates")
        }
        for certificate in nsc.find_all("certificates"):
            if id(certificate) in debug_certificates:
                continue
            source = certificate.attribute("src", namespace=None) or certificate.attribute("src")
            if source is not None and source.value.strip().lower() == "user":
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["nsc_user_ca_trusted"],
                        summary=f'{path}: <certificates src="user"/> outside <debug-overrides>',
                        location=path,
                        description_suffix=f" The element appears at {certificate.path()}.",
                        discriminator="nsc:user-ca",
                        matched_value="user",
                        artifacts={"file": path, "path": certificate.path()},
                    )
                )

        return issues

    @staticmethod
    def _assess_dex_methods(dex: DexFile) -> list[_Issue]:
        issues: list[_Issue] = []
        for method_rule in METHOD_RULES:
            matched = [signature for signature in method_rule.signatures if dex.calls(signature)]
            if not matched:
                continue
            if any(dex.calls(signature) for signature in method_rule.negated_by):
                continue
            suffix = f" {method_rule.evidence_note}" if method_rule.evidence_note else ""
            issues.append(
                _Issue(
                    rule=method_rule.rule,
                    summary=("the application's method table references " + ", ".join(matched[:4])),
                    location="classes.dex",
                    description_suffix=suffix,
                    discriminator=f"dex:method:{method_rule.rule.rule_id}",
                    matched_value=matched[0],
                    artifacts={"method_references": matched},
                )
            )
        return issues

    @staticmethod
    def _assess_strings(candidates: list[tuple[str, str]]) -> list[_Issue]:
        """Apply the string rules to the application's literals.

        Takes ``(location, value)`` pairs so a match in ``classes.dex`` and the
        same match in a bundled resource are reported as separate findings —
        they are separate places the defect has to be fixed. Matches are
        grouped per rule and location, so one rule firing on forty literals in
        one file produces one finding listing them rather than forty.
        """
        grouped: dict[tuple[str, str], list[str]] = {}
        for location, value in candidates:
            if not value or len(value) > MAX_SECRET_CANDIDATE_LENGTH:
                continue
            for string_rule in STRING_RULES:
                match = string_rule.pattern.search(value)
                if match is None:
                    continue
                if any(excluded.search(value) for excluded in string_rule.exclude):
                    continue
                captured = match.group(string_rule.value_group) or match.group(0)
                if len(captured) < string_rule.min_length:
                    continue
                examples = grouped.setdefault((string_rule.rule.rule_id, location), [])
                if captured not in examples and len(examples) < 25:
                    examples.append(captured)

        rules_by_id = {r.rule.rule_id: r for r in STRING_RULES}
        issues: list[_Issue] = []
        for (rule_id, location), examples in sorted(grouped.items()):
            string_rule = rules_by_id[rule_id]
            shown = examples[:5]
            more = (
                f" ({len(examples)} distinct matches were found in this file; the first "
                "five are shown.)"
                if len(examples) > len(shown)
                else ""
            )
            issues.append(
                _Issue(
                    rule=string_rule.rule,
                    summary=(
                        f"{location}: {len(examples)} matching literal(s), first: "
                        f"{examples[0][:160]}"
                    ),
                    location=location,
                    description_suffix=(
                        f" Matched in {location}: "
                        + ", ".join(repr(e[:80]) for e in shown)
                        + "."
                        + more
                    ),
                    discriminator=f"string:{rule_id}:{location}",
                    matched_value=examples[0][:200],
                    snippet=examples[0][:400],
                    artifacts={
                        "matches": [e[:200] for e in examples],
                        "match_count": len(examples),
                        "location": location,
                    },
                )
            )
        return issues

    # ----------------------------------------------------------- ios checks
    def _assess_ios(self, facts: _ArtifactFacts) -> list[_Issue]:
        issues: list[_Issue] = []
        plist = facts.plist
        location = str(facts.stats.get("plist_member", "Info.plist"))
        bundle_id = plist.get("CFBundleIdentifier")

        ats = plist.get("NSAppTransportSecurity")
        if not isinstance(ats, dict):
            if plist:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["ios_no_ats_dictionary"],
                        summary=f"{location}: no NSAppTransportSecurity dictionary",
                        location=location,
                        discriminator="plist:no-ats",
                        artifacts={"bundle_id": bundle_id},
                    )
                )
        else:
            if ats.get("NSAllowsArbitraryLoads") is True:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["ios_ats_disabled"],
                        summary=f"{location}: NSAllowsArbitraryLoads = true",
                        location=location,
                        discriminator="plist:ats-disabled",
                        matched_value="NSAllowsArbitraryLoads=true",
                        artifacts={"bundle_id": bundle_id},
                    )
                )
            for key in (
                "NSAllowsArbitraryLoadsInWebContent",
                "NSAllowsArbitraryLoadsForMedia",
                "NSAllowsLocalNetworking",
            ):
                if ats.get(key) is True:
                    issues.append(
                        _Issue(
                            rule=MANIFEST_RULES["ios_ats_exception"],
                            summary=f"{location}: {key} = true",
                            location=location,
                            description_suffix=(
                                f" The exception is the global `{key}` key, which relaxes "
                                "App Transport Security for the whole category it names "
                                "rather than for one domain."
                            ),
                            discriminator=f"plist:ats:{key}",
                            matched_value=f"{key}=true",
                            artifacts={"key": key, "bundle_id": bundle_id},
                            title_override=f"App Transport Security is relaxed by {key}",
                        )
                    )
            exceptions = ats.get("NSExceptionDomains")
            if isinstance(exceptions, dict):
                for domain, settings in exceptions.items():
                    if not isinstance(settings, dict):
                        continue
                    waived = [
                        key
                        for key, value in settings.items()
                        if (
                            key
                            in (
                                "NSExceptionAllowsInsecureHTTPLoads",
                                "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
                                "NSIncludesSubdomains",
                            )
                            and value is True
                        )
                        or (
                            key
                            in (
                                "NSExceptionRequiresForwardSecrecy",
                                "NSThirdPartyExceptionRequiresForwardSecrecy",
                            )
                            and value is False
                        )
                        or (
                            key
                            in (
                                "NSExceptionMinimumTLSVersion",
                                "NSThirdPartyExceptionMinimumTLSVersion",
                            )
                            and str(value) in ("TLSv1.0", "TLSv1.1")
                        )
                    ]
                    if not waived:
                        continue
                    issues.append(
                        _Issue(
                            rule=MANIFEST_RULES["ios_ats_exception"],
                            summary=(
                                f"{location}: NSExceptionDomains[{domain}] waives "
                                f"{', '.join(sorted(waived))}"
                            ),
                            location=location,
                            description_suffix=(
                                f" The exception applies to `{domain}` and waives: "
                                f"{', '.join(sorted(waived))}."
                            ),
                            discriminator=f"plist:ats-exception:{domain}",
                            matched_value=str(domain),
                            artifacts={
                                "domain": domain,
                                "waived": sorted(waived),
                                "settings": {k: str(v) for k, v in settings.items()},
                            },
                            title_override=(
                                f"App Transport Security exception weakens transport security "
                                f"for {domain}"
                            ),
                        )
                    )

        if plist.get("UIFileSharingEnabled") is True:
            issues.append(
                _Issue(
                    rule=MANIFEST_RULES["ios_file_sharing"],
                    summary=f"{location}: UIFileSharingEnabled = true",
                    location=location,
                    discriminator="plist:file-sharing",
                    matched_value="true",
                    artifacts={"bundle_id": bundle_id},
                )
            )

        url_types = plist.get("CFBundleURLTypes")
        if isinstance(url_types, list):
            schemes = [
                str(scheme)
                for entry in url_types
                if isinstance(entry, dict)
                for scheme in (entry.get("CFBundleURLSchemes") or [])
                if isinstance(scheme, str)
            ]
            for scheme in sorted(set(schemes)):
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["ios_custom_url_scheme"],
                        summary=f"{location}: CFBundleURLSchemes includes {scheme!r}",
                        location=location,
                        description_suffix=(
                            f" The registered scheme is `{scheme}://`, so any application or "
                            "web page can open a URL in it and pass data to the handler."
                        ),
                        discriminator=f"plist:url-scheme:{scheme}",
                        matched_value=scheme,
                        artifacts={"scheme": scheme, "bundle_id": bundle_id},
                        title_override=(
                            f"Custom URL scheme {scheme}:// accepts input from any application"
                        ),
                    )
                )

        if facts.entitlements.get("get-task-allow") is True:
            issues.append(
                _Issue(
                    rule=MANIFEST_RULES["ios_get_task_allow"],
                    summary="embedded.mobileprovision: Entitlements.get-task-allow = true",
                    location=str(
                        facts.stats.get("provisioning_profile", "embedded.mobileprovision")
                    ),
                    discriminator="entitlements:get-task-allow",
                    matched_value="true",
                    artifacts={"bundle_id": bundle_id},
                )
            )

        minimum = plist.get("MinimumOSVersion")
        if isinstance(minimum, str):
            try:
                major = int(minimum.split(".")[0])
            except (ValueError, IndexError):
                major = None
            if major is not None and major < IOS_UNSUPPORTED_MAJOR:
                issues.append(
                    _Issue(
                        rule=MANIFEST_RULES["ios_min_os_outdated"],
                        summary=f"{location}: MinimumOSVersion = {minimum}",
                        location=location,
                        description_suffix=(
                            f" This artifact supports iOS {minimum} and above; releases below "
                            f"iOS {IOS_UNSUPPORTED_MAJOR} no longer receive security fixes."
                        ),
                        discriminator="plist:min-os",
                        matched_value=minimum,
                        artifacts={"minimum_os": minimum},
                    )
                )

        # The plist's own string values can carry the same defects as a DEX
        # string pool — a cleartext endpoint or an embedded credential.
        issues.extend(self._assess_strings(self._string_candidates(facts)))
        return issues

    @staticmethod
    def _plist_strings(value: Any, depth: int = 0) -> list[str]:
        """Every string value in a property list, flattened."""
        if depth > 12:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            out: list[str] = []
            for key, nested in value.items():
                if isinstance(key, str):
                    out.append(key)
                out.extend(MobileEngine._plist_strings(nested, depth + 1))
            return out
        if isinstance(value, (list, tuple)):
            out = []
            for item in value:
                out.extend(MobileEngine._plist_strings(item, depth + 1))
            return out
        return []

    # ------------------------------------------------------- string sources
    def _string_candidates(self, facts: _ArtifactFacts) -> list[tuple[str, str]]:
        """Every string literal in the artifact, paired with where it was found.

        Three sources, because a defect is equally real in any of them: the
        compiled code's string pool, the bundled text resources, and — for an
        iOS bundle — the property list's own values.
        """
        candidates: list[tuple[str, str]] = []
        if facts.dex is not None:
            candidates.extend(("classes.dex", value) for value in facts.dex.strings)
        for name, text in facts.text_resources.items():
            candidates.extend((name, line) for line in text.splitlines())
        if facts.plist:
            location = str(facts.stats.get("plist_member", "Info.plist"))
            candidates.extend((location, value) for value in self._plist_strings(facts.plist))
        return candidates

    # ------------------------------------------------------ embedded secrets
    def _assess_embedded_secrets(
        self, facts: _ArtifactFacts, salt: str = DEFAULT_FINGERPRINT_SALT
    ) -> list[_Issue]:
        """Apply the platform's secret rules to the artifact's own strings.

        A mobile application is fully readable by every person who installs it,
        so a credential compiled into one is published, not hidden. The same
        placeholder filtering used by the secrets engine applies here, and the
        value itself is never recorded — only a redacted form and a keyed
        fingerprint, so the finding can be correlated and deduplicated without
        the platform's own database becoming a place credentials are stored.
        """
        candidates = self._string_candidates(facts)
        issues: list[_Issue] = []
        reported: set[tuple[str, str]] = set()

        for location, value in candidates:
            if not value or len(value) < MIN_SECRET_LENGTH:
                continue
            if len(value) > MAX_SECRET_CANDIDATE_LENGTH:
                continue
            for rule in SECRET_RULES:
                match = rule.pattern.search(value)
                if match is None:
                    continue
                try:
                    secret = match.group(rule.secret_group) or match.group(0)
                except (IndexError, re.error):
                    # A rule naming a capture group its pattern does not
                    # define falls back to the whole match rather than losing
                    # the finding.
                    secret = match.group(0)
                if is_placeholder(secret):
                    continue
                secret_fingerprint = fingerprint(secret, salt)
                key = (rule.rule_id, secret_fingerprint)
                if key in reported:
                    continue
                reported.add(key)
                issues.append(
                    _Issue(
                        rule=MobileRule(
                            rule_id=f"MOB-SECRET-{rule.rule_id}",
                            title=f"{rule.name} is embedded in the application",
                            category="exposed_secret",
                            severity=rule.severity,
                            confidence=rule.confidence,
                            description=(
                                f"A value matching {rule.name} is compiled into the shipped "
                                f"artifact, at {location}. A mobile application is "
                                "distributed to every user in full, so a credential inside "
                                "it is public: extracting it needs no exploit, only the "
                                "published package. Removing it in a later release does not "
                                "revoke it."
                            ),
                            impact=(
                                "The credential is available to anyone who downloads the "
                                "application, and can be used directly against whatever it "
                                "authenticates to, with no rate limit and no attribution to "
                                "the attacker."
                            ),
                            remediation=(
                                f"{rule.remediation} Rotate the credential first — it is "
                                "already published — then move the operation it authorises "
                                "behind an authenticated server-side endpoint so the client "
                                "never holds a long-lived secret."
                            ),
                            cwe="CWE-798",
                            masvs=("MASVS-CRYPTO-2",),
                            mastg=("MASTG-TEST-0012",),
                        ),
                        summary=(
                            f"{location}: {rule.secret_type} matching {rule.rule_id} "
                            f"({redact(secret)})"
                        ),
                        location=location,
                        discriminator=f"secret:{rule.rule_id}:{secret_fingerprint[:16]}",
                        # The credential itself is never stored: the redacted
                        # form identifies it to someone who holds it, and the
                        # fingerprint supports correlation without disclosure.
                        matched_value=redact(secret),
                        artifacts={
                            "secret_type": rule.secret_type,
                            "fingerprint": secret_fingerprint,
                            "rule": rule.rule_id,
                            "verifiable": rule.verifiable,
                        },
                    )
                )
                break

        return issues

    # -------------------------------------------------------------- mapping
    @staticmethod
    def _to_finding(issue: _Issue, artifact: Path, ctx: EngineContext) -> ScanFinding:
        rule = issue.rule
        return ScanFinding(
            engine="mobile",
            rule_id=rule.rule_id,
            category=rule.category,
            title=issue.title_override or rule.title,
            description=rule.description + issue.description_suffix,
            severity=(issue.severity_override or rule.severity),
            confidence=(issue.confidence_override or rule.confidence),
            evidence=Evidence(
                summary=issue.summary,
                matched_value=issue.matched_value,
                code_snippet=issue.snippet,
                artifacts={**issue.artifacts, "artifact": artifact.name},
            ),
            impact=rule.impact,
            remediation=rule.remediation,
            references=list(rule.references),
            code_location=CodeLocation(file_path=issue.location),
            target=ctx.target,
            cwe=rule.cwe,
            owasp_masvs=list(rule.masvs),
            mastg_tests=list(rule.mastg),
            correlation_discriminator=issue.discriminator,
        )
