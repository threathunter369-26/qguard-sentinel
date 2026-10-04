"""Mobile application security rules.

Covers the checks a static assessment of a packaged application can make
without a decompiler, mapped to the OWASP Mobile Application Security
Verification Standard (MASVS) and the Mobile Application Security Testing
Guide (MASTG) so findings line up with how mobile work is actually reviewed.

Three rule kinds, each with a different evidential strength, and the
distinction is carried through to the finding's confidence:

* **Manifest and plist rules** evaluate a declared configuration value.
  ``android:debuggable="true"`` is a fact about the shipped artifact, so these
  are high or confirmed confidence.
* **Method-reference rules** fire on a call site present in the application's
  method table. The call exists; whether it executes, and with what arguments,
  is not known from the table, so these are medium confidence and their text
  says what was and was not established.
* **String rules** fire on a literal in the string pool. A literal may be
  dead, or part of a test fixture bundled by accident, so these are the
  weakest and are worded accordingly.

No rule claims exploitation. A finding that a cipher transform string
``AES/ECB/PKCS5Padding`` is present states that the application contains that
transform, which is a real defect worth fixing, and does not assert that a
particular piece of data was decrypted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low", "tentative"]


@dataclass(frozen=True, slots=True)
class MobileRule:
    """One mobile security check."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    impact: str
    remediation: str
    platform: Literal["android", "ios", "both"] = "both"
    cwe: str | None = None
    masvs: tuple[str, ...] = ()
    mastg: tuple[str, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PermissionRisk:
    """What requesting an Android permission exposes."""

    permission: str
    severity: Severity
    rationale: str
    is_dangerous: bool = True
    """Whether Android itself classifies the permission as dangerous."""


@dataclass(frozen=True, slots=True)
class MethodRule:
    """A rule that fires on a method reference in the DEX method table."""

    signatures: tuple[str, ...]
    rule: MobileRule
    #: Method references whose presence makes this finding a false positive —
    #: typically the secure counterpart being used alongside.
    negated_by: tuple[str, ...] = ()
    evidence_note: str = ""


@dataclass(frozen=True, slots=True)
class StringRule:
    """A rule that fires on a string literal in the application."""

    pattern: re.Pattern[str]
    rule: MobileRule
    #: Capture group holding the value shown as evidence. 0 is the whole match.
    value_group: int = 0
    min_length: int = 0
    exclude: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# ------------------------------------------------------------------ manifest
MANIFEST_RULES: dict[str, MobileRule] = {
    "debuggable": MobileRule(
        rule_id="MOB-ANDROID-DEBUGGABLE",
        title="Application is marked debuggable",
        category="platform_misuse",
        severity="critical",
        confidence="confirmed",
        description=(
            'The manifest sets `android:debuggable="true"`. On any device, with no root '
            "and no exploit, this permits attaching a debugger to the running process, "
            "reading and writing its memory, invoking its methods directly, and extracting "
            "everything it holds — session tokens, keys, decrypted data. It also makes the "
            "application's private data directory readable through `run-as`."
        ),
        impact=(
            "Complete loss of client-side confidentiality and integrity for anyone with "
            "physical or ADB access to a device running the app. Any client-side control — "
            "root detection, certificate pinning, licence checks — can be disabled at "
            "runtime."
        ),
        remediation=(
            "Remove `android:debuggable` from the manifest entirely. The build system sets "
            "it for debug builds; hardcoding it ships a debug configuration to production. "
            "Verify with `aapt dump badging` on the release artifact before publishing."
        ),
        platform="android",
        cwe="CWE-489",
        masvs=("MASVS-RESILIENCE-2",),
        mastg=("MASTG-TEST-0024",),
    ),
    "allowBackup": MobileRule(
        rule_id="MOB-ANDROID-ALLOW-BACKUP",
        title="Application data is backed up in cleartext",
        category="insecure_storage",
        severity="medium",
        confidence="high",
        description=(
            "`android:allowBackup` is true (and is the platform default below API 31 when "
            "unset), so the application's private data directory can be copied off the "
            "device with `adb backup` on a debuggable-enabled device, and is included in "
            "cloud backups. Anything the app stores — tokens, cached personal data, local "
            "databases — leaves the device's security boundary."
        ),
        impact=(
            "Credentials and personal data stored locally can be extracted from a device "
            "or recovered from a cloud backup, including onto a different device."
        ),
        remediation=(
            'Set `android:allowBackup="false"`, or keep backups and exclude sensitive '
            "paths with `android:dataExtractionRules` (API 31+) or "
            "`android:fullBackupContent`. Keep secrets in the Keystore, which is never "
            "backed up."
        ),
        platform="android",
        cwe="CWE-530",
        masvs=("MASVS-STORAGE-2",),
        mastg=("MASTG-TEST-0009",),
    ),
    "usesCleartextTraffic": MobileRule(
        rule_id="MOB-ANDROID-CLEARTEXT-TRAFFIC",
        title="Cleartext HTTP traffic is permitted",
        category="insecure_communication",
        severity="high",
        confidence="high",
        description=(
            '`android:usesCleartextTraffic="true"` disables the platform\'s default block '
            "on plain HTTP, so the application may send and receive unencrypted traffic. "
            "On a hostile network — any public Wi-Fi — that traffic is readable and "
            "modifiable, and a modified response is executed by the app as if it were "
            "genuine."
        ),
        impact=(
            "Session tokens and personal data are interceptable, and injected responses can "
            "drive the application's behaviour, which in a WebView extends to script "
            "execution."
        ),
        remediation=(
            "Remove the attribute so the platform default applies, move every endpoint to "
            "HTTPS, and declare any unavoidable exception for a single domain in a network "
            "security configuration rather than globally."
        ),
        platform="android",
        cwe="CWE-319",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0019",),
    ),
    "exported_component": MobileRule(
        rule_id="MOB-ANDROID-EXPORTED-COMPONENT",
        title="Component is exported without permission protection",
        category="broken_access_control",
        severity="high",
        confidence="high",
        description=(
            "The component is exported and declares no `android:permission`, so any other "
            "application on the device can start it or bind to it and supply arbitrary "
            "Intent extras. Whatever the component does on receipt of an Intent, it does on "
            "behalf of an untrusted caller."
        ),
        impact=(
            "Depending on the component: unauthorised actions performed with the app's "
            "identity, access to screens behind authentication, or an Intent redirection "
            "that turns the app into a confused deputy."
        ),
        remediation=(
            'Set `android:exported="false"` unless another application genuinely needs '
            "access. Where it does, require a signature-level permission and validate every "
            "Intent extra as untrusted input."
        ),
        platform="android",
        cwe="CWE-926",
        masvs=("MASVS-PLATFORM-1",),
        mastg=("MASTG-TEST-0029",),
    ),
    "exported_provider": MobileRule(
        rule_id="MOB-ANDROID-EXPORTED-PROVIDER",
        title="Content provider is exported without permission protection",
        category="broken_access_control",
        severity="critical",
        confidence="high",
        description=(
            "The content provider is exported with no read or write permission declared, so "
            "any application on the device can query and modify the data it fronts. A "
            "provider is a direct interface to the app's storage: where it wraps SQLite, an "
            "exported provider frequently permits SQL injection through the selection "
            "argument, and where it serves files, a path traversal through the URI."
        ),
        impact=(
            "Any installed application reads and writes the app's data with no user "
            "interaction and no permission prompt."
        ),
        remediation=(
            'Set `android:exported="false"`. If cross-application access is required, '
            "declare `android:readPermission` and `android:writePermission` at signature "
            "level, use `android:grantUriPermissions` with per-URI grants rather than blanket "
            "access, and parameterise every query."
        ),
        platform="android",
        cwe="CWE-926",
        masvs=("MASVS-PLATFORM-1",),
        mastg=("MASTG-TEST-0029",),
    ),
    "grant_uri_permissions_wildcard": MobileRule(
        rule_id="MOB-ANDROID-GRANT-URI-WILDCARD",
        title="Content provider grants URI permissions for all paths",
        category="broken_access_control",
        severity="high",
        confidence="high",
        description=(
            '`android:grantUriPermissions="true"` with no `<grant-uri-permission>` path '
            "restriction lets the provider hand temporary access to any URI under its "
            "authority. Combined with an Intent the app sends outward, a receiving "
            "application can be granted access to paths the developer never intended to "
            "share."
        ),
        impact=(
            "A malicious or merely careless recipient application gains read or write access "
            "to arbitrary provider paths, including internal files."
        ),
        remediation=(
            "Replace the blanket grant with explicit `<grant-uri-permission>` path or "
            "path-prefix entries covering only what must be shared."
        ),
        platform="android",
        cwe="CWE-926",
        masvs=("MASVS-PLATFORM-1",),
        mastg=("MASTG-TEST-0029",),
    ),
    "custom_permission_normal": MobileRule(
        rule_id="MOB-ANDROID-WEAK-CUSTOM-PERMISSION",
        title="Custom permission uses a weak protection level",
        category="broken_access_control",
        severity="medium",
        confidence="high",
        description=(
            "The application defines a permission at `normal` or `dangerous` protection "
            "level. A `normal` permission is granted to any application that requests it, "
            "without the user being asked; a `dangerous` one is granted on a user prompt "
            "that gives no indication which app is being trusted. Neither restricts access "
            "to the developer's own applications, which is usually the intent."
        ),
        impact=(
            "A component the developer believes is protected is reachable by any application "
            "that declares the permission."
        ),
        remediation=(
            'Use `android:protectionLevel="signature"` so only applications signed with '
            "the same key are granted the permission."
        ),
        platform="android",
        cwe="CWE-280",
        masvs=("MASVS-PLATFORM-1",),
        mastg=("MASTG-TEST-0029",),
    ),
    "shared_user_id": MobileRule(
        rule_id="MOB-ANDROID-SHARED-USER-ID",
        title="Application shares a Linux user ID with other applications",
        category="platform_misuse",
        severity="medium",
        confidence="high",
        description=(
            "`android:sharedUserId` places the application in the same Linux UID as every "
            "other application declaring that ID and signed with the same key. The sandbox "
            "between them disappears: each can read the others' private data directories "
            "directly. The attribute is deprecated precisely because of this, and a "
            "compromise of the weakest application in the group compromises them all."
        ),
        impact=(
            "A vulnerability in any application sharing the UID yields this application's "
            "private data, including its credentials."
        ),
        remediation=(
            "Remove `sharedUserId` and share data through an explicit, permission-protected "
            "content provider or a bound service instead."
        ),
        platform="android",
        cwe="CWE-250",
        masvs=("MASVS-STORAGE-2",),
    ),
    "test_only": MobileRule(
        rule_id="MOB-ANDROID-TEST-ONLY",
        title="Application is marked test-only",
        category="platform_misuse",
        severity="medium",
        confidence="confirmed",
        description=(
            '`android:testOnly="true"` marks the artifact as a test build. Such a build '
            "can be installed with `adb install -t` and, like a debuggable build, is treated "
            "by the platform as a development artifact. Its presence in a release channel "
            "means a non-release build was published."
        ),
        impact=(
            "The published artifact is not the hardened release build, so its other "
            "development-time settings should be assumed present too."
        ),
        remediation="Build and publish a release artifact without the testOnly flag.",
        platform="android",
        cwe="CWE-489",
        masvs=("MASVS-RESILIENCE-2",),
    ),
    "min_sdk_outdated": MobileRule(
        rule_id="MOB-ANDROID-OUTDATED-MIN-SDK",
        title="Application supports Android versions that no longer receive security fixes",
        category="platform_misuse",
        severity="medium",
        confidence="high",
        description=(
            "The declared `minSdkVersion` admits platform versions that Google no longer "
            "patches. On those versions the application inherits unfixed platform "
            "vulnerabilities, and platform defences it relies on — scoped storage, the "
            "cleartext-traffic block, hardware-backed key attestation — are either absent "
            "or weaker."
        ),
        impact=(
            "Platform-level protections the app's threat model assumes are not present on "
            "the oldest supported versions, and known platform exploits remain usable there."
        ),
        remediation=(
            "Raise `minSdkVersion` to a version still receiving security updates, and "
            "confirm which platform defences the application depends on."
        ),
        platform="android",
        cwe="CWE-1104",
        masvs=("MASVS-PLATFORM-3",),
    ),
    "target_sdk_outdated": MobileRule(
        rule_id="MOB-ANDROID-OUTDATED-TARGET-SDK",
        title="Application targets an outdated Android API level",
        category="platform_misuse",
        severity="medium",
        confidence="high",
        description=(
            "`targetSdkVersion` determines which platform behaviour changes apply. A low "
            "target keeps the application in a compatibility mode where newer, stricter "
            "defaults are deliberately not enforced — among them scoped storage, the "
            "cleartext-traffic block, restrictions on implicit-intent matching, and the "
            "requirement to declare component export explicitly."
        ),
        impact=(
            "The application runs without security defaults that the platform applies to "
            "up-to-date applications, so hardening added by the OS does not reach it."
        ),
        remediation=(
            "Raise `targetSdkVersion` to the current platform level and address the "
            "behaviour changes rather than opting out of them."
        ),
        platform="android",
        cwe="CWE-1104",
        masvs=("MASVS-PLATFORM-3",),
    ),
    "backup_agent": MobileRule(
        rule_id="MOB-ANDROID-CUSTOM-BACKUP-AGENT",
        title="Application declares a custom backup agent",
        category="insecure_storage",
        severity="low",
        confidence="high",
        description=(
            "A custom `android:backupAgent` controls exactly what leaves the device during "
            "a backup. That is the right mechanism for excluding secrets, and it is also "
            "where secrets get included by mistake. Review what the agent writes."
        ),
        impact=(
            "If the agent includes credential or key material, that material is copied into "
            "backups and off the device."
        ),
        remediation=(
            "Review the agent's `onFullBackup` and key-value implementation and confirm no "
            "credential, token or key is written. Keep keys in the Keystore."
        ),
        platform="android",
        cwe="CWE-530",
        masvs=("MASVS-STORAGE-2",),
    ),
    "no_network_security_config": MobileRule(
        rule_id="MOB-ANDROID-NO-NETWORK-SECURITY-CONFIG",
        title="No network security configuration is declared",
        category="insecure_communication",
        severity="low",
        confidence="high",
        description=(
            "The application declares no `android:networkSecurityConfig`. The platform "
            "defaults are reasonable from API 28 onward — cleartext blocked, system CAs "
            "trusted — but without a configuration the application also has no certificate "
            "pinning and no explicit trust anchor policy, so any CA in the device's store, "
            "including one added by an attacker with device access or by a corporate MDM, "
            "is trusted for its own endpoints."
        ),
        impact=(
            "Traffic can be intercepted by anyone able to install a trusted CA on the "
            "device, which is the standard setup for mobile traffic interception."
        ),
        remediation=(
            "Add a network security configuration that pins the certificates or public keys "
            "of the application's own endpoints, with a backup pin and a documented rotation "
            "process."
        ),
        platform="android",
        cwe="CWE-295",
        masvs=("MASVS-NETWORK-2",),
        mastg=("MASTG-TEST-0020",),
    ),
    "nsc_cleartext_permitted": MobileRule(
        rule_id="MOB-ANDROID-NSC-CLEARTEXT",
        title="Network security configuration permits cleartext traffic",
        category="insecure_communication",
        severity="high",
        confidence="high",
        description=(
            "The network security configuration sets "
            '`cleartextTrafficPermitted="true"`, re-enabling plain HTTP for the scope it '
            "applies to. Where that scope is `base-config`, it applies to every domain the "
            "application contacts."
        ),
        impact=("Traffic in the affected scope is readable and modifiable on any network path."),
        remediation=(
            'Set `cleartextTrafficPermitted="false"`. If one legacy host genuinely '
            "requires HTTP, scope the exception to that single `domain` entry and record why."
        ),
        platform="android",
        cwe="CWE-319",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0019",),
    ),
    "nsc_user_ca_trusted": MobileRule(
        rule_id="MOB-ANDROID-NSC-USER-CA",
        title="Network security configuration trusts user-installed certificate authorities",
        category="insecure_communication",
        severity="high",
        confidence="high",
        description=(
            'The configuration declares `<certificates src="user" />` outside a '
            "debug-only block, so the application trusts certificate authorities installed "
            "by the device user or an MDM. Installing a CA is the standard way to intercept "
            "mobile traffic, and this makes it work against the production build."
        ),
        impact=(
            "Anyone who can install a certificate on the device — including malware with "
            "user consent, or a hostile network's captive portal flow — can read and modify "
            "the application's TLS traffic."
        ),
        remediation=(
            "Trust only `system` anchors in the production configuration, and move the "
            "`user` anchor into `<debug-overrides>`, which the platform ignores in release "
            "builds."
        ),
        platform="android",
        cwe="CWE-295",
        masvs=("MASVS-NETWORK-2",),
        mastg=("MASTG-TEST-0020",),
    ),
    "v1_signature_only": MobileRule(
        rule_id="MOB-ANDROID-V1-SIGNATURE-ONLY",
        title="Application is signed only with the legacy v1 JAR scheme",
        category="supply_chain",
        severity="high",
        confidence="high",
        description=(
            "The archive carries only a v1 (JAR) signature, with no APK Signature Scheme v2 "
            "block. The v1 scheme signs individual entries rather than the archive, which "
            "leaves unsigned metadata an attacker can modify — the basis of the Janus "
            "vulnerability, where a DEX payload is prepended to a v1-only APK and the "
            "platform accepts the signature while executing the attacker's code."
        ),
        impact=(
            "On affected platform versions, the application can be modified to execute "
            "attacker-supplied code while still verifying as correctly signed."
        ),
        remediation=(
            "Re-sign with APK Signature Scheme v2 or later (`apksigner` does this by "
            "default) and confirm with `apksigner verify --verbose`."
        ),
        platform="android",
        cwe="CWE-347",
        masvs=("MASVS-RESILIENCE-1",),
        mastg=("MASTG-TEST-0037",),
    ),
    "unsigned": MobileRule(
        rule_id="MOB-ANDROID-UNSIGNED",
        title="Application archive carries no signature",
        category="supply_chain",
        severity="high",
        confidence="confirmed",
        description=(
            "The archive contains no signature block of any scheme. An unsigned APK cannot "
            "be installed by the platform, so either this is an intermediate build artifact "
            "rather than a distributable one, or the signature was stripped. Either way its "
            "integrity and origin cannot be verified."
        ),
        impact=(
            "The artifact's origin and integrity are unverifiable, so nothing assessed here "
            "can be attributed to a known publisher."
        ),
        remediation=(
            "Sign the release artifact with the production key and assess the signed "
            "artifact, which is what users will receive."
        ),
        platform="android",
        cwe="CWE-347",
        masvs=("MASVS-RESILIENCE-1",),
        mastg=("MASTG-TEST-0037",),
    ),
    "ios_ats_disabled": MobileRule(
        rule_id="MOB-IOS-ATS-DISABLED",
        title="App Transport Security is disabled globally",
        category="insecure_communication",
        severity="high",
        confidence="confirmed",
        description=(
            "`NSAppTransportSecurity.NSAllowsArbitraryLoads` is true, which switches off App "
            "Transport Security for every connection the application makes. ATS is what "
            "enforces TLS 1.2 or later, forward secrecy and certificate validity on iOS; "
            "with it off, the application may use plain HTTP and weak TLS throughout."
        ),
        impact=(
            "All of the application's traffic may be unencrypted or weakly encrypted, and "
            "is interceptable and modifiable on a hostile network."
        ),
        remediation=(
            "Remove `NSAllowsArbitraryLoads`. Where a specific legacy host must be reached, "
            "add a narrowly scoped `NSExceptionDomains` entry for it and document the reason "
            "and removal plan."
        ),
        platform="ios",
        cwe="CWE-319",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0019",),
    ),
    "ios_ats_exception": MobileRule(
        rule_id="MOB-IOS-ATS-EXCEPTION",
        title="App Transport Security exception weakens transport security for a domain",
        category="insecure_communication",
        severity="medium",
        confidence="high",
        description=(
            "An `NSExceptionDomains` entry relaxes App Transport Security for a specific "
            "domain — permitting cleartext HTTP, a TLS version below 1.2, or connections "
            "without forward secrecy. The exception is narrower than disabling ATS "
            "entirely, but traffic to that domain loses the corresponding protection."
        ),
        impact=(
            "Traffic to the excepted domain is interceptable or downgradeable in proportion "
            "to which protection was waived."
        ),
        remediation=(
            "Fix transport security on the server and remove the exception. Each exception "
            "should carry a documented owner and removal date."
        ),
        platform="ios",
        cwe="CWE-319",
        masvs=("MASVS-NETWORK-1",),
        mastg=("MASTG-TEST-0019",),
    ),
    "ios_get_task_allow": MobileRule(
        rule_id="MOB-IOS-GET-TASK-ALLOW",
        title="Application is signed with debugging entitlements",
        category="platform_misuse",
        severity="critical",
        confidence="confirmed",
        description=(
            "The embedded provisioning profile grants the `get-task-allow` entitlement, "
            "which permits a debugger to attach to the running process. That allows reading "
            "and writing process memory, calling its functions and extracting keys and "
            "tokens from a device with no jailbreak."
        ),
        impact=(
            "Complete loss of client-side confidentiality and integrity for anyone with "
            "access to a device running the app; client-side controls can be disabled at "
            "runtime."
        ),
        remediation=(
            "Build with a distribution provisioning profile, which does not grant "
            "`get-task-allow`, and verify the entitlement is absent from the artifact you "
            "ship."
        ),
        platform="ios",
        cwe="CWE-489",
        masvs=("MASVS-RESILIENCE-2",),
        mastg=("MASTG-TEST-0024",),
    ),
    "ios_file_sharing": MobileRule(
        rule_id="MOB-IOS-FILE-SHARING-ENABLED",
        title="iTunes file sharing is enabled",
        category="insecure_storage",
        severity="medium",
        confidence="high",
        description=(
            "`UIFileSharingEnabled` exposes the application's `Documents` directory through "
            "the Files app and through a connected computer. Anything the application writes "
            "there is readable by the device's user and by any process with access to the "
            "device's filesystem over USB."
        ),
        impact=(
            "Data in `Documents` leaves the application sandbox. Where it includes tokens, "
            "cached personal data or exported databases, those are directly extractable."
        ),
        remediation=(
            "Disable file sharing unless the application's purpose requires it. If it does, "
            "write only user-facing documents to `Documents` and keep everything else in "
            "`Library/Application Support` or the Keychain."
        ),
        platform="ios",
        cwe="CWE-552",
        masvs=("MASVS-STORAGE-1",),
        mastg=("MASTG-TEST-0009",),
    ),
    "ios_custom_url_scheme": MobileRule(
        rule_id="MOB-IOS-CUSTOM-URL-SCHEME",
        title="Custom URL scheme accepts input from any application",
        category="broken_access_control",
        severity="medium",
        confidence="high",
        description=(
            "The application registers a custom URL scheme. Any application on the device, "
            "and any web page the user visits, can open a URL in that scheme and pass data "
            "into the handler. Custom schemes are not exclusive — another application may "
            "register the same one — and they carry no proof of the caller's identity."
        ),
        impact=(
            "Untrusted callers can drive application flows. Where the handler performs an "
            "action or accepts a token, this is an entry point for unauthorised actions or "
            "for an authorisation-code interception attack."
        ),
        remediation=(
            "Prefer Universal Links, which are bound to a verified domain. Where a custom "
            "scheme is required, validate every parameter as untrusted and never perform a "
            "state-changing action without user confirmation."
        ),
        platform="ios",
        cwe="CWE-939",
        masvs=("MASVS-PLATFORM-1",),
        mastg=("MASTG-TEST-0029",),
    ),
    "ios_no_ats_dictionary": MobileRule(
        rule_id="MOB-IOS-NO-ATS-DICTIONARY",
        title="No App Transport Security configuration is declared",
        category="insecure_communication",
        severity="info",
        confidence="high",
        description=(
            "`Info.plist` contains no `NSAppTransportSecurity` dictionary, so the platform "
            "default applies: TLS 1.2 or later with forward secrecy, and cleartext HTTP "
            "blocked. That default is correct, and it is recorded here only to note that "
            "the application also declares no certificate pinning, so any CA trusted by the "
            "device is accepted for its endpoints."
        ),
        impact=(
            "Transport security relies on the device's trust store, so traffic can be "
            "intercepted by anyone able to install a trusted certificate on the device."
        ),
        remediation=(
            "Consider pinning the endpoints' public keys so an added device CA does not "
            "permit interception."
        ),
        platform="ios",
        cwe="CWE-295",
        masvs=("MASVS-NETWORK-2",),
    ),
    "ios_min_os_outdated": MobileRule(
        rule_id="MOB-IOS-OUTDATED-MIN-OS",
        title="Application supports iOS versions that no longer receive security fixes",
        category="platform_misuse",
        severity="medium",
        confidence="high",
        description=(
            "The declared `MinimumOSVersion` admits iOS releases Apple no longer patches. On "
            "those releases the application inherits unfixed platform vulnerabilities and "
            "lacks newer platform defences."
        ),
        impact=(
            "Known platform exploits remain usable on the oldest supported releases, below "
            "the application's own controls."
        ),
        remediation=("Raise `MinimumOSVersion` to a release still receiving security updates."),
        platform="ios",
        cwe="CWE-1104",
        masvs=("MASVS-PLATFORM-3",),
    ),
}


# ---------------------------------------------------------------- permissions
#: Android permissions whose request is worth reporting, with what it exposes.
#: The grant itself is not a vulnerability — it is attack surface, and an
#: application holding a permission it does not need extends the damage of any
#: compromise. Severity reflects what the permission grants access to.
PERMISSION_RISKS: dict[str, PermissionRisk] = {
    "android.permission.READ_SMS": PermissionRisk(
        "android.permission.READ_SMS",
        "high",
        "Reads every SMS on the device, which includes one-time passcodes for the user's "
        "other accounts. A compromise of this application becomes a compromise of any "
        "account using SMS-based second factors.",
    ),
    "android.permission.RECEIVE_SMS": PermissionRisk(
        "android.permission.RECEIVE_SMS",
        "high",
        "Receives incoming SMS as they arrive, including one-time passcodes, before the "
        "user sees them.",
    ),
    "android.permission.SEND_SMS": PermissionRisk(
        "android.permission.SEND_SMS",
        "high",
        "Sends SMS at the user's expense and in the user's name, which is both a direct "
        "financial abuse path and a way to send phishing messages that appear to come from "
        "the device owner.",
    ),
    "android.permission.READ_CONTACTS": PermissionRisk(
        "android.permission.READ_CONTACTS",
        "medium",
        "Reads the full contact list, which is personal data about people who never "
        "installed the application and never consented.",
    ),
    "android.permission.READ_CALL_LOG": PermissionRisk(
        "android.permission.READ_CALL_LOG",
        "high",
        "Reads who the user called and when — metadata that reveals relationships, health "
        "and financial activity without any call content.",
    ),
    "android.permission.ACCESS_FINE_LOCATION": PermissionRisk(
        "android.permission.ACCESS_FINE_LOCATION",
        "medium",
        "Reads precise location. Retained precise location is sufficient to identify a "
        "person's home, workplace and routine.",
    ),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermissionRisk(
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "high",
        "Reads location while the application is not in use, producing a continuous "
        "movement history rather than a point in time.",
    ),
    "android.permission.RECORD_AUDIO": PermissionRisk(
        "android.permission.RECORD_AUDIO",
        "high",
        "Captures audio from the microphone, which includes conversations the user did not "
        "intend for the application.",
    ),
    "android.permission.CAMERA": PermissionRisk(
        "android.permission.CAMERA",
        "medium",
        "Captures images and video from the device cameras.",
    ),
    "android.permission.READ_EXTERNAL_STORAGE": PermissionRisk(
        "android.permission.READ_EXTERNAL_STORAGE",
        "medium",
        "Reads shared storage, which holds documents, photographs and files written by "
        "other applications.",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermissionRisk(
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "medium",
        "Writes to shared storage, where files have no per-application access control and "
        "can be read or replaced by any other application with storage access.",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": PermissionRisk(
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "high",
        "Grants access to the entire shared storage volume, bypassing scoped storage. Very "
        "few applications legitimately need it, and Play Store policy restricts it.",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermissionRisk(
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "high",
        "Prompts the user to install an arbitrary APK. This is the mechanism dropper "
        "malware uses to deliver a second stage, and it turns any code-execution or "
        "content-injection flaw in the application into application installation.",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": PermissionRisk(
        "android.permission.SYSTEM_ALERT_WINDOW",
        "high",
        "Draws windows over other applications. This is the primitive behind tapjacking and "
        "credential-overlay attacks, where a transparent or convincing window captures input "
        "intended for another application.",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermissionRisk(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "critical",
        "An accessibility service can read the content of every screen and inject input "
        "events into any application. It is the most powerful capability available to a "
        "non-system application and is the standard mechanism for Android banking trojans.",
    ),
    "android.permission.BIND_DEVICE_ADMIN": PermissionRisk(
        "android.permission.BIND_DEVICE_ADMIN",
        "high",
        "Device administrator rights permit locking and wiping the device and resisting "
        "uninstallation.",
    ),
    "android.permission.READ_PHONE_STATE": PermissionRisk(
        "android.permission.READ_PHONE_STATE",
        "low",
        "Reads telephony state and, on older platform versions, device identifiers usable "
        "for persistent tracking.",
    ),
    "android.permission.GET_ACCOUNTS": PermissionRisk(
        "android.permission.GET_ACCOUNTS",
        "medium",
        "Lists the accounts configured on the device, which discloses the user's identities "
        "across other services.",
    ),
    "android.permission.QUERY_ALL_PACKAGES": PermissionRisk(
        "android.permission.QUERY_ALL_PACKAGES",
        "low",
        "Enumerates every installed application, a durable fingerprint of the device and "
        "its user, and reconnaissance for targeting other applications.",
        is_dangerous=False,
    ),
    "android.permission.WRITE_SETTINGS": PermissionRisk(
        "android.permission.WRITE_SETTINGS",
        "medium",
        "Modifies system settings, which can be used to weaken the device's configuration.",
        is_dangerous=False,
    ),
    "android.permission.DISABLE_KEYGUARD": PermissionRisk(
        "android.permission.DISABLE_KEYGUARD",
        "medium",
        "Dismisses the lock screen, removing the control that protects everything else on "
        "the device.",
        is_dangerous=False,
    ),
    "android.permission.READ_LOGS": PermissionRisk(
        "android.permission.READ_LOGS",
        "high",
        "Reads the system log, which other applications frequently write sensitive data to. "
        "The platform reserves it for system applications; a request for it indicates an "
        "attempt at cross-application data access.",
        is_dangerous=False,
    ),
}


# --------------------------------------------------------- DEX method rules
def _rule(
    rule_id: str,
    title: str,
    category: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    impact: str,
    remediation: str,
    **kwargs: object,
) -> MobileRule:
    return MobileRule(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        description=description,
        impact=impact,
        remediation=remediation,
        **kwargs,  # type: ignore[arg-type]
    )


METHOD_RULES: tuple[MethodRule, ...] = (
    MethodRule(
        signatures=("Landroid/webkit/WebView;->addJavascriptInterface",),
        rule=_rule(
            "MOB-ANDROID-JAVASCRIPT-INTERFACE",
            "WebView exposes a native object to JavaScript",
            "platform_misuse",
            "high",
            "medium",
            "The application calls `WebView.addJavascriptInterface`, which exposes a Java "
            "object to any JavaScript running in that WebView. Every method annotated "
            "`@JavascriptInterface` on that object becomes callable by page content. If the "
            "WebView ever loads content the application does not fully control — a remote "
            "page, an injected script, a redirect — that content calls into native code "
            "with the application's permissions.",
            "Script in the WebView can invoke the exposed object's methods with the "
            "application's identity and permissions. Where the exposed surface reaches the "
            "filesystem, the network or a reflection helper, this escalates to arbitrary "
            "code execution within the app.",
            "Remove the interface if it is avoidable. Where it is needed, expose the "
            "narrowest possible method set, restrict the WebView to content served over "
            "HTTPS from a domain you control, and never combine the interface with "
            "`setAllowFileAccess` or `setAllowUniversalAccessFromFileURLs`.",
            platform="android",
            cwe="CWE-749",
            masvs=("MASVS-PLATFORM-2",),
            mastg=("MASTG-TEST-0031",),
        ),
        evidence_note=(
            "The call site exists in the application's method table. Which object is "
            "exposed, and what content the WebView loads, requires reading the code."
        ),
    ),
    MethodRule(
        signatures=("Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs",),
        rule=_rule(
            "MOB-ANDROID-WEBVIEW-UNIVERSAL-FILE-ACCESS",
            "WebView grants file URLs access to any origin",
            "platform_misuse",
            "high",
            "medium",
            "`setAllowUniversalAccessFromFileURLs` lets a page loaded from a `file://` URL "
            "make requests to any origin and read the responses, defeating the same-origin "
            "policy. A local HTML file an attacker can influence — one written to shared "
            "storage, or a downloaded attachment — can then read the application's local "
            "files and exfiltrate them.",
            "A local file the attacker controls can read the application's private files "
            "and send their contents to a remote server.",
            "Do not enable universal file access. Load application content from an HTTPS "
            "origin or through `WebViewAssetLoader`, which serves local assets over a "
            "synthetic HTTPS origin and keeps the same-origin policy intact.",
            platform="android",
            cwe="CWE-200",
            masvs=("MASVS-PLATFORM-2",),
            mastg=("MASTG-TEST-0031",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs",
            "Landroid/webkit/WebSettings;->setAllowFileAccess",
        ),
        rule=_rule(
            "MOB-ANDROID-WEBVIEW-FILE-ACCESS",
            "WebView file access is configured explicitly",
            "platform_misuse",
            "medium",
            "low",
            "The application configures WebView file access. Enabling it allows pages in the "
            "WebView to load `file://` URLs, which combined with any content injection "
            "becomes a path to reading the application's private files. The platform "
            "defaults this off from API 30, so an explicit call is usually enabling it.",
            "If enabled, injected or attacker-influenced content in the WebView can read "
            "files from the application's sandbox.",
            "Leave file access disabled and serve local content through "
            "`WebViewAssetLoader`. Confirm from the code whether this call enables or "
            "disables the setting.",
            platform="android",
            cwe="CWE-552",
            masvs=("MASVS-PLATFORM-2",),
            mastg=("MASTG-TEST-0031",),
        ),
        evidence_note=(
            "The method table records the call but not its argument, so whether access is "
            "being enabled or disabled is not established here."
        ),
    ),
    MethodRule(
        signatures=("Landroid/webkit/WebSettings;->setJavaScriptEnabled",),
        rule=_rule(
            "MOB-ANDROID-WEBVIEW-JAVASCRIPT",
            "WebView JavaScript execution is configured",
            "platform_misuse",
            "low",
            "low",
            "The application configures JavaScript execution in a WebView. JavaScript is "
            "required by most legitimate web content, so this is not a defect by itself — it "
            "is recorded because it establishes that script runs in the WebView, which is "
            "what makes the WebView's other settings, and any content injection into it, "
            "consequential.",
            "Enabling script in a WebView that loads content the application does not "
            "control allows that content to act within the WebView's origin and to reach any "
            "exposed JavaScript interface.",
            "Confirm the WebView loads only content from an origin you control over HTTPS, "
            "and review any `addJavascriptInterface` usage alongside this.",
            platform="android",
            cwe="CWE-79",
            masvs=("MASVS-PLATFORM-2",),
            mastg=("MASTG-TEST-0031",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/webkit/WebViewClient;->onReceivedSslError",
            "Landroid/webkit/SslErrorHandler;->proceed",
        ),
        rule=_rule(
            "MOB-ANDROID-WEBVIEW-SSL-ERROR-IGNORED",
            "WebView may proceed past TLS certificate errors",
            "insecure_communication",
            "critical",
            "medium",
            "The application references `SslErrorHandler.proceed`, the call that continues "
            "loading a page after a TLS certificate error. Overriding `onReceivedSslError` "
            "to call `proceed()` accepts any certificate — expired, self-signed, or issued "
            "by an attacker — which removes TLS authentication entirely while leaving the "
            "connection looking encrypted.",
            "An attacker on the network path can present any certificate and read and modify "
            "all traffic in the WebView, including credentials entered into it and any "
            "session token it carries.",
            "Never call `proceed()` in `onReceivedSslError`. Call `cancel()` and surface the "
            "failure. If a development environment needs a self-signed certificate, gate "
            "that on a debug build variant that is not shipped.",
            platform="android",
            cwe="CWE-295",
            masvs=("MASVS-NETWORK-2",),
            mastg=("MASTG-TEST-0020",),
        ),
        evidence_note=(
            "The presence of `proceed` alongside an `onReceivedSslError` override is a "
            "strong indicator; confirm by reading the override's body."
        ),
    ),
    MethodRule(
        signatures=(
            "Ljavax/net/ssl/SSLContext;->init",
            "Ljavax/net/ssl/X509TrustManager;->checkServerTrusted",
        ),
        rule=_rule(
            "MOB-ANDROID-CUSTOM-TRUST-MANAGER",
            "Application configures TLS trust itself",
            "insecure_communication",
            "high",
            "low",
            "The application initialises its own `SSLContext` or implements "
            "`X509TrustManager`, so it decides which certificates to trust rather than "
            "relying on the platform. That is the correct way to implement certificate "
            "pinning — and it is also how trust validation gets disabled, by a "
            "`checkServerTrusted` that returns without checking anything. The two are "
            "indistinguishable from the method table.",
            "If trust validation is weakened or skipped, every TLS connection the "
            "application makes is interceptable while appearing encrypted.",
            "Read the `TrustManager` implementation. If it pins, confirm it validates the "
            "chain and has a backup pin. If it accepts everything, remove it and use the "
            "platform's validation, adding pinning through a network security configuration "
            "or `CertificatePinner` rather than custom code.",
            platform="android",
            cwe="CWE-295",
            masvs=("MASVS-NETWORK-2",),
            mastg=("MASTG-TEST-0020",),
        ),
        evidence_note=(
            "Custom trust configuration is present. Whether it strengthens or weakens "
            "validation cannot be determined from the method table and must be read."
        ),
    ),
    MethodRule(
        signatures=("Ljavax/net/ssl/HostnameVerifier;->verify",),
        rule=_rule(
            "MOB-ANDROID-CUSTOM-HOSTNAME-VERIFIER",
            "Application implements its own TLS hostname verification",
            "insecure_communication",
            "high",
            "low",
            "The application implements `HostnameVerifier`. Hostname verification is what "
            "ties a valid certificate to the host being contacted; a verifier that returns "
            "`true` unconditionally — the most common form of this code — means any "
            "certificate valid for any host is accepted for every host, so a certificate "
            "for a domain the attacker owns works against the application's endpoints.",
            "An attacker with a valid certificate for any domain can intercept the "
            "application's traffic.",
            "Remove the custom verifier and use the platform default. If a specific host "
            "needs an exception, scope it to that host and verify the certificate's "
            "identity rather than returning true.",
            platform="android",
            cwe="CWE-297",
            masvs=("MASVS-NETWORK-2",),
            mastg=("MASTG-TEST-0020",),
        ),
    ),
    MethodRule(
        signatures=("Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start"),
        rule=_rule(
            "MOB-ANDROID-COMMAND-EXECUTION",
            "Application executes operating system commands",
            "command_execution",
            "medium",
            "low",
            "The application spawns operating system processes. On Android this is unusual "
            "in legitimate code and is commonly seen in root detection, in bundled native "
            "tooling, and in malware. Where any part of the command string comes from "
            "outside the application — an Intent extra, a server response, a filename — it "
            "is a command injection.",
            "If any portion of the command is attacker-influenced, the attacker runs "
            "commands with the application's UID and permissions.",
            "Replace process execution with a platform API where one exists. Where it is "
            "genuinely required, build the argument list programmatically rather than as a "
            "shell string, and never interpolate external input.",
            platform="android",
            cwe="CWE-78",
            masvs=("MASVS-CODE-4",),
        ),
    ),
    MethodRule(
        signatures=(
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>",
        ),
        rule=_rule(
            "MOB-ANDROID-DYNAMIC-CODE-LOADING",
            "Application loads code at runtime",
            "supply_chain",
            "high",
            "medium",
            "The application constructs a class loader over a DEX or JAR path, so it "
            "executes code that is not part of the signed artifact. Code loaded this way "
            "bypasses the integrity guarantee of application signing: nothing verifies it, "
            "and store review never saw it. If the source is a downloaded file or writable "
            "storage, an attacker who can replace that file achieves code execution inside "
            "the application.",
            "Code not covered by the application's signature executes with the "
            "application's full permissions. Where the loaded file is downloaded or in "
            "shared storage, this is a direct remote code execution path.",
            "Avoid runtime code loading. Where it is unavoidable, load only from the "
            "application's private, non-writable storage and verify a signature over the "
            "payload before loading it.",
            platform="android",
            cwe="CWE-494",
            masvs=("MASVS-RESILIENCE-3",),
            mastg=("MASTG-TEST-0044",),
        ),
    ),
    MethodRule(
        signatures=(
            "Ljava/util/Random;-><init>",
            "Ljava/util/Random;->nextInt",
            "Ljava/lang/Math;->random",
        ),
        rule=_rule(
            "MOB-ANDROID-WEAK-RANDOM",
            "Application uses a non-cryptographic random number generator",
            "cryptographic_failure",
            "medium",
            "low",
            "`java.util.Random` is a linear congruential generator. Its output is "
            "predictable: observing a small number of values reveals the internal state and "
            "therefore every subsequent and preceding value. Where the output is used for a "
            "token, a password reset code, a nonce or an IV, it is predictable by anyone who "
            "has seen a few of them.",
            "If any security-relevant value comes from this generator, an attacker who "
            "observes a few outputs can predict the rest — forging tokens or recovering "
            "nonces.",
            "Use `java.security.SecureRandom` for anything with a security purpose. "
            "`java.util.Random` is fine for shuffling a playlist and nothing else.",
            platform="android",
            cwe="CWE-338",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
        evidence_note=(
            "The generator is referenced. Whether its output reaches a security-relevant "
            "value requires reading the code."
        ),
    ),
    MethodRule(
        signatures=("Landroid/util/Log;->d", "Landroid/util/Log;->v", "Landroid/util/Log;->i"),
        rule=_rule(
            "MOB-ANDROID-DEBUG-LOGGING",
            "Application contains debug logging calls",
            "information_disclosure",
            "low",
            "low",
            "Debug and verbose logging calls are present in the shipped artifact. Android's "
            "log is per-application from API 16 onward, so this is not the open disclosure it "
            "once was — but the calls still execute in production, their arguments are still "
            "evaluated, and anything they log is visible to a connected developer machine, to "
            "a bug-reporting SDK that captures logs, and to any process able to read logs.",
            "Sensitive values passed to these calls are written to the device log, from "
            "where crash-reporting and diagnostics tooling frequently uploads them.",
            "Strip debug logging from release builds with ProGuard/R8 rules, and check that "
            "no call site passes a token, credential or personal data.",
            platform="android",
            cwe="CWE-532",
            masvs=("MASVS-STORAGE-2",),
            mastg=("MASTG-TEST-0003",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/content/Context;->getExternalFilesDir",
            "Landroid/os/Environment;->getExternalStorageDirectory",
        ),
        rule=_rule(
            "MOB-ANDROID-EXTERNAL-STORAGE-USE",
            "Application writes to external storage",
            "insecure_storage",
            "medium",
            "low",
            "The application uses external storage. Files there have no per-application "
            "access control: on older platform versions any application with the storage "
            "permission can read and modify them, and they survive the application's "
            "uninstallation. Data an application treats as private is not private there.",
            "Data written to external storage is readable, and often writable, by other "
            "applications and by anyone with filesystem access to the device.",
            "Store anything sensitive in the application's internal storage, and keys in the "
            "Keystore. Use external storage only for content the user expects to be shared, "
            "and never trust a file read back from it.",
            platform="android",
            cwe="CWE-312",
            masvs=("MASVS-STORAGE-1",),
            mastg=("MASTG-TEST-0001",),
        ),
    ),
    MethodRule(
        signatures=("Ljava/security/MessageDigest;->getInstance",),
        rule=_rule(
            "MOB-CRYPTO-DIGEST-USE",
            "Application selects a message digest algorithm at runtime",
            "cryptographic_failure",
            "info",
            "low",
            "The application calls `MessageDigest.getInstance`. The algorithm is chosen by "
            "the string argument, which the method table does not record. This is recorded "
            "only to locate hashing for review alongside the algorithm strings found in the "
            "application.",
            "If a broken digest such as MD5 or SHA-1 is selected for a security purpose, "
            "collision attacks against it are practical.",
            "Confirm which algorithm is requested at each call site and use SHA-256 or "
            "stronger. For password storage use a password hash — Argon2id, scrypt or "
            "bcrypt — not a digest.",
            cwe="CWE-328",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/content/Context;->getSharedPreferences",
            "Landroid/content/SharedPreferences;->edit",
        ),
        rule=_rule(
            "MOB-ANDROID-SHARED-PREFERENCES",
            "Application stores data in shared preferences",
            "insecure_storage",
            "info",
            "low",
            "The application uses `SharedPreferences`, which writes an unencrypted XML file "
            "in its private directory. That is adequate for settings and inadequate for "
            "credentials: the file is readable on a rooted or debuggable device, is included "
            "in backups when those are enabled, and persists until the application is "
            "uninstalled.",
            "Any token or credential kept in shared preferences is extractable from a "
            "rooted device, from a backup, or from a debuggable build.",
            "Keep tokens and keys in the Android Keystore, or use `EncryptedSharedPreferences` "
            "with a Keystore-backed master key. Reserve plain preferences for non-sensitive "
            "settings.",
            platform="android",
            cwe="CWE-312",
            masvs=("MASVS-STORAGE-1",),
            mastg=("MASTG-TEST-0001",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
        ),
        rule=_rule(
            "MOB-ANDROID-RAW-SQL",
            "Application executes raw SQL",
            "injection",
            "medium",
            "low",
            "`rawQuery` and `execSQL` take SQL as a string. Where any part of that string is "
            "built from outside the application — an Intent extra, a server response, user "
            "input — the result is SQL injection against the local database. On a device "
            "that matters most where the database holds authorisation state or cached "
            "records for multiple users.",
            "An attacker able to influence the query reads or modifies the whole local "
            "database, regardless of what the application's own logic intended.",
            "Use the parameterised forms — `query()` with `selectionArgs`, or `rawQuery` "
            "with `?` placeholders — and never build SQL by concatenation.",
            platform="android",
            cwe="CWE-89",
            masvs=("MASVS-CODE-4",),
        ),
    ),
    MethodRule(
        signatures=("Ljava/io/ObjectInputStream;->readObject",),
        rule=_rule(
            "MOB-ANDROID-JAVA-DESERIALIZATION",
            "Application deserialises Java objects",
            "insecure_deserialization",
            "high",
            "medium",
            "`ObjectInputStream.readObject` reconstructs arbitrary object graphs from a byte "
            "stream, invoking the deserialised classes' own methods as it goes. If the "
            "stream comes from anywhere outside the application — a file in shared storage, "
            "an Intent extra, a network response — an attacker chooses which classes are "
            "instantiated and can reach code execution through a gadget chain in the "
            "application's dependencies.",
            "Remote or local code execution within the application, depending on the "
            "classes available on its classpath.",
            "Do not deserialise untrusted data with Java serialisation. Use a data format "
            "with an explicit schema — JSON or protobuf into known types — and validate it.",
            platform="android",
            cwe="CWE-502",
            masvs=("MASVS-CODE-4",),
        ),
    ),
    MethodRule(
        signatures=(
            "Landroid/app/PendingIntent;->getActivity",
            "Landroid/app/PendingIntent;->getBroadcast",
            "Landroid/app/PendingIntent;->getService",
        ),
        rule=_rule(
            "MOB-ANDROID-PENDING-INTENT",
            "Application creates PendingIntents",
            "broken_access_control",
            "low",
            "low",
            "A `PendingIntent` is a token that lets another application send an Intent as "
            "this one. Where the wrapped Intent is implicit, or is mutable and lacks an "
            "explicit component, the holder can redirect it — making this application "
            "perform an action the attacker chose, with this application's permissions.",
            "A malicious application holding the token can have this application act on its "
            "behalf, which is a confused-deputy escalation.",
            "Wrap only explicit Intents with an exact component, and pass "
            "`FLAG_IMMUTABLE` unless mutability is genuinely required.",
            platform="android",
            cwe="CWE-927",
            masvs=("MASVS-PLATFORM-1",),
            mastg=("MASTG-TEST-0029",),
        ),
    ),
)


# --------------------------------------------------------- DEX string rules
STRING_RULES: tuple[StringRule, ...] = (
    StringRule(
        pattern=_c(r"\b(DES|DESede|RC2|RC4|Blowfish)\s*/"),
        rule=_rule(
            "MOB-CRYPTO-BROKEN-CIPHER",
            "Application contains a broken cipher transform",
            "cryptographic_failure",
            "high",
            "high",
            "The application contains a cipher transform naming a broken algorithm. DES has "
            "a 56-bit key and is exhaustible in hours; 3DES is limited to 112-bit security "
            "with a practical block-collision attack; RC4 has recoverable keystream biases; "
            "RC2 and Blowfish have 64-bit blocks, which collide after about 32 GB of data "
            "under one key. None of these should encrypt anything that matters.",
            "Data encrypted with these algorithms can be recovered without the key, so "
            "treating it as protected is incorrect.",
            "Use `AES/GCM/NoPadding` with a 256-bit key from the Android Keystore. Re-encrypt "
            "data already stored under a broken algorithm; rotating the code without "
            "re-encrypting leaves the old ciphertext readable.",
            cwe="CWE-327",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
    ),
    StringRule(
        pattern=_c(r"\bAES\s*/\s*ECB\b"),
        rule=_rule(
            "MOB-CRYPTO-ECB-MODE",
            "Application uses AES in ECB mode",
            "cryptographic_failure",
            "high",
            "high",
            "ECB encrypts each block independently, so identical plaintext blocks produce "
            "identical ciphertext blocks. The structure of the plaintext survives "
            "encryption — patterns are visible, blocks can be reordered or replaced "
            "undetected, and equality of plaintexts leaks. The cipher is strong; the mode "
            "defeats it.",
            "Plaintext structure and repetition are disclosed, and an attacker can modify "
            "the ciphertext in meaningful ways without the key.",
            "Use `AES/GCM/NoPadding`, which provides both confidentiality and "
            "authentication, with a unique nonce per encryption.",
            cwe="CWE-327",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
    ),
    StringRule(
        pattern=_c(r"\bAES\s*/\s*CBC\s*/\s*PKCS[57]Padding\b"),
        rule=_rule(
            "MOB-CRYPTO-CBC-UNAUTHENTICATED",
            "Application uses AES-CBC without authentication",
            "cryptographic_failure",
            "medium",
            "medium",
            "`AES/CBC/PKCS5Padding` provides confidentiality but no integrity. An attacker "
            "who can modify ciphertext and observe whether decryption succeeded recovers the "
            "plaintext through a padding-oracle attack, and can also flip chosen bits in the "
            "plaintext by modifying the preceding block.",
            "Ciphertext can be modified and, where decryption outcomes are observable, "
            "decrypted without the key.",
            "Use `AES/GCM/NoPadding`, which authenticates the ciphertext. If CBC must be "
            "kept, apply a separate HMAC over the ciphertext and IV and verify it before "
            "decrypting.",
            cwe="CWE-353",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
    ),
    StringRule(
        pattern=_c(r"^(MD5|MD2|MD4|SHA-?1)$"),
        rule=_rule(
            "MOB-CRYPTO-BROKEN-HASH",
            "Application contains a broken hash algorithm name",
            "cryptographic_failure",
            "medium",
            "medium",
            "The application contains the name of a hash algorithm with practical collision "
            "attacks. MD5 collisions are generated in seconds and SHA-1 collisions have been "
            "demonstrated, so neither can support a signature, a certificate, an integrity "
            "check or a deduplication key where an adversary chooses any input.",
            "Where the digest backs an integrity or authenticity decision, an attacker can "
            "produce a different input with the same digest and have it accepted.",
            "Use SHA-256 or SHA-3 for integrity. For passwords use Argon2id, scrypt or "
            "bcrypt — a fast digest is the wrong primitive regardless of its strength.",
            cwe="CWE-328",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
        exclude=(_c(r"(?i)checksum|etag|cache|dedup"),),
    ),
    StringRule(
        pattern=_c(r"\b(?:AES|DES|DESede|Blowfish)\s*/\s*\w+\s*/\s*NoPadding\b"),
        rule=_rule(
            "MOB-CRYPTO-STATIC-IV-RISK",
            "Application uses a block cipher mode requiring a unique nonce",
            "cryptographic_failure",
            "info",
            "low",
            "The transform requires a per-encryption initialisation vector or nonce that is "
            "never reused under the same key. Reuse is catastrophic in CTR and GCM modes — in "
            "GCM, a repeated nonce discloses the authentication subkey and allows forgery of "
            "arbitrary messages. This is recorded so the IV's provenance is checked; the "
            "transform itself may be entirely correct.",
            "A reused or hardcoded IV breaks confidentiality for the affected mode and, in "
            "GCM, allows an attacker to forge authenticated ciphertext.",
            "Generate the IV with `SecureRandom` for every encryption, store it alongside "
            "the ciphertext, and never derive it from a constant or a counter the attacker "
            "can influence.",
            cwe="CWE-329",
            masvs=("MASVS-CRYPTO-1",),
            mastg=("MASTG-TEST-0014",),
        ),
    ),
    StringRule(
        # The path stops at a quote, bracket, comma or whitespace so the
        # reported value is the URL rather than the rest of the line it sits on.
        pattern=_c(
            r"\bhttp://(?!localhost|127\.0\.0\.1|\[::1\])"
            r"(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?"
            r"(?:/[^\s\"'<>`,;)\]}\\]*)?"
        ),
        rule=_rule(
            "MOB-CLEARTEXT-ENDPOINT",
            "Application contains a cleartext HTTP endpoint",
            "insecure_communication",
            "high",
            "medium",
            "The application embeds a plain `http://` URL for a remote host. Any request to "
            "it is readable and modifiable by anyone on the network path, and a modified "
            "response is processed by the application as genuine. Where the URL fetches "
            "configuration, a script or an update, controlling the response controls the "
            "application's behaviour.",
            "Traffic to this endpoint is interceptable and modifiable. Depending on what the "
            "endpoint returns, that ranges from data disclosure to controlling what the "
            "application does.",
            "Move the endpoint to HTTPS and remove the cleartext URL. Verify no network "
            "security configuration exception keeps the host reachable over HTTP.",
            cwe="CWE-319",
            masvs=("MASVS-NETWORK-1",),
            mastg=("MASTG-TEST-0019",),
        ),
        value_group=0,
        exclude=(
            # URLs that are identifiers rather than endpoints the application
            # fetches over the network: XML namespaces, DTD system identifiers,
            # schema locations and licence references. Reporting these as
            # cleartext endpoints would bury the real ones.
            _c(r"(?i)example\.(com|org|net)|example\.(?:org|com)\.\w+"),
            _c(r"(?i)schemas?[./]|/dtds?/|\.dtd\b|\.xsd\b|xmlns|doctype"),
            _c(r"(?i)\.w3\.org|xmlpull\.org|apache\.org/licenses|/licenses?/|opensource\.org"),
            _c(r"(?i)purl\.org|iptc\.org|ns\.adobe\.com|/TR/|json-schema\.org"),
        ),
    ),
    StringRule(
        pattern=_c(r"\bjdbc:\w+://[^\s\"']+"),
        rule=_rule(
            "MOB-EMBEDDED-DATABASE-URL",
            "Application contains a remote database connection string",
            "exposed_secret",
            "critical",
            "high",
            "The application embeds a JDBC connection string for a remote database. A mobile "
            "application is fully readable by anyone who installs it, so the host, the "
            "database name and any credentials in the string are public. An application that "
            "connects directly to a database also has no server-side authorisation layer: "
            "whatever the connection can do, every user of the app can do.",
            "The database is directly reachable with the embedded credentials by anyone who "
            "extracts them from the application, with no application-level authorisation in "
            "the way.",
            "Remove the direct database connection. Put an authenticated API between the "
            "application and the database, rotate the exposed credentials, and check the "
            "database's logs for access from unexpected addresses.",
            cwe="CWE-798",
            masvs=("MASVS-CRYPTO-2", "MASVS-NETWORK-1"),
            mastg=("MASTG-TEST-0012",),
        ),
    ),
    StringRule(
        pattern=_c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        rule=_rule(
            "MOB-EMBEDDED-PRIVATE-KEY",
            "Application contains a private key",
            "exposed_secret",
            "critical",
            "confirmed",
            "A PEM private key block is embedded in the application. Every copy of the "
            "application contains it, so the key is not secret — it is published. Whatever "
            "the key authenticates or signs can be authenticated or signed by anyone who "
            "installs the app and runs `strings` on it.",
            "The key is compromised for every user of the application. Anything relying on "
            "it for authentication, signing or decryption is forgeable or readable.",
            "Revoke and rotate the key immediately — removing it from a future release does "
            "not un-publish it. Move private key operations server-side, or generate a "
            "per-device key in the Keystore or Keychain, which never leaves the device.",
            cwe="CWE-798",
            masvs=("MASVS-CRYPTO-2",),
            mastg=("MASTG-TEST-0012",),
        ),
    ),
    StringRule(
        pattern=_c(
            r"\b(?:frida|xposed|magisk|supersu|busybox)\b",
        ),
        rule=_rule(
            "MOB-TAMPER-DETECTION-REFERENCE",
            "Application references tampering and instrumentation tools",
            "code_quality_security",
            "info",
            "low",
            "The application contains the names of root, instrumentation or tampering tools, "
            "which indicates it implements detection for them. That is a reasonable defence "
            "in depth. It is recorded so the detection is reviewed rather than relied upon: "
            "every client-side check runs on hardware the attacker controls and can be "
            "patched out, so it must not be the only control protecting anything.",
            "Client-side tampering detection raises the effort of attack; it does not "
            "prevent it. A control that only exists on the client is bypassable.",
            "Keep the detection, and make sure every security decision it feeds is also "
            "enforced server-side. Report detection events to the server rather than only "
            "acting locally.",
            cwe="CWE-693",
            masvs=("MASVS-RESILIENCE-1",),
            mastg=("MASTG-TEST-0046",),
        ),
    ),
    StringRule(
        pattern=_c(
            r"\b(?:0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
        rule=_rule(
            "MOB-INTERNAL-ADDRESS-DISCLOSED",
            "Application contains an internal network address",
            "information_disclosure",
            "low",
            "medium",
            "The application embeds a private-range IP address. In a shipped artifact this "
            "discloses part of the publisher's internal network layout, and it indicates "
            "development or staging configuration reaching production. A build that still "
            "points at an internal address may also still carry its other non-production "
            "settings.",
            "Internal addressing is disclosed to anyone who inspects the application, which "
            "assists reconnaissance against the publisher's network.",
            "Remove internal addresses from release builds and keep environment "
            "configuration out of the artifact. Check whether other development settings "
            "shipped alongside it.",
            cwe="CWE-200",
            masvs=("MASVS-CODE-2",),
        ),
        exclude=(_c(r"(?i)(?:^|\W)(?:0\.0\.0\.0/0|255\.255|subnet|netmask|example)"),),
    ),
    StringRule(
        pattern=_c(r"\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b"),
        rule=_rule(
            "MOB-IOS-KEYCHAIN-ALWAYS-ACCESSIBLE",
            "Keychain item is accessible without the device being unlocked",
            "insecure_storage",
            "high",
            "high",
            "`kSecAttrAccessibleAlways` stores a Keychain item so it is readable whether or "
            "not the device is unlocked. The passcode then protects nothing for that item: "
            "it can be read from a locked device and is included in unencrypted backups. "
            "Apple deprecated the attribute for this reason.",
            "The stored secret is extractable from a locked device and from backups, "
            "defeating the device passcode as a control over it.",
            "Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, or "
            "`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` where background access is "
            "genuinely required. The `ThisDeviceOnly` variants also keep the item out of "
            "backups.",
            platform="ios",
            cwe="CWE-312",
            masvs=("MASVS-STORAGE-1",),
            mastg=("MASTG-TEST-0011",),
        ),
    ),
    StringRule(
        pattern=_c(r"\b(?:strcpy|strcat|sprintf|gets|memcpy|alloca)\b"),
        rule=_rule(
            "MOB-NATIVE-UNSAFE-FUNCTION",
            "Native code references a memory-unsafe C function",
            "code_quality_security",
            "medium",
            "low",
            "The application's native code references a C function with no bounds checking. "
            "`strcpy`, `strcat`, `sprintf` and `gets` write until a terminator regardless of "
            "the destination's size, so a longer-than-expected input overflows the buffer. "
            "In native mobile code that means memory corruption and, commonly, code "
            "execution — below the managed runtime's protections.",
            "An input longer than the destination buffer corrupts memory. In native code "
            "this is routinely exploitable for code execution within the application.",
            "Replace with the bounded variants (`strlcpy`, `snprintf`) or, better, with "
            "memory-safe code. Build native libraries with stack protection, FORTIFY_SOURCE "
            "and PIE, and fuzz the parsers that handle external input.",
            cwe="CWE-120",
            masvs=("MASVS-CODE-4",),
        ),
    ),
)


#: Android API levels with no vendor security support, used by the SDK-version
#: checks. Updated as platform support windows move.
ANDROID_UNSUPPORTED_SDK = 24
"""minSdkVersion at or below this admits platform versions with no security fixes."""

ANDROID_OUTDATED_TARGET_SDK = 30
"""targetSdkVersion below this keeps the app out of several platform defences."""

IOS_UNSUPPORTED_MAJOR = 14
"""MinimumOSVersion below this admits releases with no security fixes."""


def permission_risk(permission: str) -> PermissionRisk | None:
    """The catalogued risk of an Android permission, or ``None`` if uncatalogued."""
    return PERMISSION_RISKS.get(permission)


def manifest_rule(key: str) -> MobileRule:
    """A manifest rule by key. Raises ``KeyError`` for an unknown key."""
    return MANIFEST_RULES[key]


__all__ = [
    "ANDROID_OUTDATED_TARGET_SDK",
    "ANDROID_UNSUPPORTED_SDK",
    "IOS_UNSUPPORTED_MAJOR",
    "MANIFEST_RULES",
    "METHOD_RULES",
    "PERMISSION_RISKS",
    "STRING_RULES",
    "MethodRule",
    "MobileRule",
    "PermissionRisk",
    "StringRule",
    "manifest_rule",
    "permission_risk",
]
