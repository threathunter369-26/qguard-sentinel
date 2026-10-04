"""Static analysis rule packs.

Two tiers, deliberately labelled differently because they carry different
certainty:

* **AST rules** (Python) are evaluated against the parsed syntax tree, so the
  analyser knows what a call actually is and which argument is which. A rule
  can require that an argument is a literal, or that it is interpolated from a
  variable, which is the difference between a real defect and a false alarm.

* **Pattern rules** (every other language) are regular expressions with
  surrounding context checks. They are reported at lower confidence because a
  regex cannot see scope or data flow, and the finding says so rather than
  implying certainty the method does not have.

Every rule carries CWE, OWASP and remediation metadata so the compliance
mapping layer has data to work with and never has to special-case a scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low", "tentative"]


@dataclass(frozen=True, slots=True)
class SastRule:
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str
    cwe: str
    remediation: str
    languages: tuple[str, ...]
    owasp_top10: str | None = None
    owasp_asvs: tuple[str, ...] = ()
    owasp_masvs: tuple[str, ...] = ()
    """Mobile control references, for rules that apply to app code."""
    references: tuple[str, ...] = ()
    #: For pattern rules: the expression to search for.
    pattern: re.Pattern[str] | None = None
    #: Lines matching this are not reported — used for the safe form of an API.
    negative_pattern: re.Pattern[str] | None = None
    #: A comment marker that suppresses the rule on that line.
    allow_suppression: bool = True


def _re(pattern: str, *, ignore_case: bool = False) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE if ignore_case else 0)


FIX_PARAMETERISE = (
    "Use parameterised queries or an ORM binding so the value is sent separately from "
    "the statement. String concatenation puts the value inside the statement, where the "
    "database cannot tell data from code."
)
FIX_NO_SHELL = (
    "Pass the command and its arguments as a list and leave shell interpretation off. "
    "With a shell, any metacharacter in the input becomes a command."
)

# ---------------------------------------------------------------------------
# Python AST rules. `node_kind` and `check` are interpreted by the analyser.
# ---------------------------------------------------------------------------
PYTHON_AST_RULES: tuple[SastRule, ...] = (
    SastRule(
        rule_id="py.eval-exec",
        name="Dynamic code execution",
        description=(
            "eval() or exec() executes its argument as Python. If any part of that "
            "argument can be influenced by a request, a file or an environment "
            "variable, the caller controls the process."
        ),
        severity="critical",
        confidence="high",
        category="command_execution",
        cwe="CWE-95",
        owasp_top10="A03:2021",
        owasp_asvs=("V5.2.4",),
        remediation=(
            "Remove the dynamic evaluation. For data, use json.loads or "
            "ast.literal_eval; for dispatch, use an explicit mapping of permitted "
            "operations."
        ),
        languages=("python",),
        references=("https://cwe.mitre.org/data/definitions/95.html",),
    ),
    SastRule(
        rule_id="py.subprocess-shell-true",
        name="Shell command execution",
        description=(
            "A subprocess was started with shell=True. The argument is interpreted by "
            "a shell, so a semicolon, backtick or $() in any interpolated value runs "
            "as a separate command."
        ),
        severity="high",
        confidence="high",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        owasp_asvs=("V5.3.8",),
        remediation=FIX_NO_SHELL,
        languages=("python",),
    ),
    SastRule(
        rule_id="py.os-system",
        name="os.system command execution",
        description=(
            "os.system() passes its whole argument to a shell and offers no way to "
            "separate arguments from the command."
        ),
        severity="high",
        confidence="high",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        remediation=FIX_NO_SHELL,
        languages=("python",),
    ),
    SastRule(
        rule_id="py.pickle-load",
        name="Unsafe deserialization",
        description=(
            "pickle, marshal and shelve reconstruct arbitrary Python objects, which "
            "means deserialising untrusted data executes whatever the data says. This "
            "is remote code execution, not a parsing bug."
        ),
        severity="critical",
        confidence="high",
        category="insecure_deserialization",
        cwe="CWE-502",
        owasp_top10="A08:2021",
        owasp_asvs=("V5.5.1",),
        remediation=(
            "Use a data-only format such as JSON. If pickle is unavoidable, restrict "
            "it to data the application itself produced and authenticate it with an "
            "HMAC before loading."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.yaml-unsafe-load",
        name="Unsafe YAML load",
        description=(
            "yaml.load() without SafeLoader can instantiate arbitrary Python objects "
            "through YAML tags, which makes loading untrusted YAML equivalent to "
            "running it."
        ),
        severity="high",
        confidence="high",
        category="insecure_deserialization",
        cwe="CWE-502",
        owasp_top10="A08:2021",
        remediation="Use yaml.safe_load(), or yaml.load(data, Loader=yaml.SafeLoader).",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.sql-string-building",
        name="SQL built by string formatting",
        description=(
            "A SQL statement was assembled with an f-string, % formatting, .format() "
            "or concatenation. Any interpolated value becomes part of the statement."
        ),
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        owasp_asvs=("V5.3.4",),
        remediation=FIX_PARAMETERISE,
        languages=("python",),
    ),
    SastRule(
        rule_id="py.weak-hash",
        name="Weak hash algorithm",
        description=(
            "MD5 and SHA-1 have practical collision attacks and must not be used "
            "where collision resistance matters — signatures, integrity checks or "
            "deduplication of security-relevant data."
        ),
        severity="medium",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-327",
        owasp_top10="A02:2021",
        owasp_asvs=("V6.2.5",),
        remediation=(
            "Use SHA-256 or SHA-3. For password storage use Argon2id, scrypt or "
            "bcrypt — a fast hash is the wrong primitive for passwords regardless of "
            "its collision resistance."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.insecure-random",
        name="Non-cryptographic randomness in a security context",
        description=(
            "The `random` module is a deterministic Mersenne Twister. Its output is "
            "predictable from a few observed values, so it must not generate tokens, "
            "passwords, salts, nonces or session identifiers."
        ),
        severity="medium",
        confidence="medium",
        category="cryptographic_failure",
        cwe="CWE-338",
        owasp_top10="A02:2021",
        owasp_asvs=("V6.3.1",),
        remediation="Use the `secrets` module, or os.urandom(), for any security value.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.tls-verification-disabled",
        name="TLS certificate verification disabled",
        description=(
            "verify=False, or an unverified SSL context, accepts any certificate. The "
            "connection is still encrypted but no longer authenticated, so a network "
            "attacker can read and alter it."
        ),
        severity="high",
        confidence="high",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        owasp_asvs=("V9.2.1",),
        remediation=(
            "Leave verification on. For an internal certificate authority, point the "
            "client at its CA bundle rather than turning verification off."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.weak-cipher",
        name="Weak or broken cipher",
        description=(
            "DES, 3DES, RC4, Blowfish and ECB mode are broken or offer inadequate "
            "security. ECB in particular leaks plaintext structure because identical "
            "blocks encrypt identically."
        ),
        severity="high",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-327",
        owasp_top10="A02:2021",
        remediation="Use AES-256-GCM, or ChaCha20-Poly1305. Both authenticate as well as encrypt.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.path-traversal",
        name="Path built from unvalidated input",
        description=(
            "A filesystem path was joined with a value that may contain '..' or an "
            "absolute path, letting a caller reach files outside the intended "
            "directory."
        ),
        severity="high",
        confidence="low",
        category="path_traversal",
        cwe="CWE-22",
        owasp_top10="A01:2021",
        owasp_asvs=("V12.3.1",),
        remediation=(
            "Resolve the joined path and confirm it is still inside the intended "
            "directory before opening it: compare "
            "Path(base, user).resolve().is_relative_to(Path(base).resolve())."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.assert-for-security",
        name="assert used for a security check",
        description=(
            "assert statements are removed entirely when Python runs with -O. A "
            "security check written as an assert silently disappears in an optimised "
            "deployment."
        ),
        severity="medium",
        confidence="medium",
        category="broken_access_control",
        cwe="CWE-617",
        owasp_top10="A01:2021",
        remediation="Replace the assert with an explicit if and raise a permission error.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.flask-debug",
        name="Debug mode enabled",
        description=(
            "Flask's debug mode exposes the Werkzeug interactive debugger, which "
            "offers a Python console to anyone who can reach an error page."
        ),
        severity="critical",
        confidence="high",
        category="security_misconfiguration",
        cwe="CWE-489",
        owasp_top10="A05:2021",
        remediation="Drive debug from configuration and keep it off outside local development.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.bind-all-interfaces",
        name="Service bound to all interfaces",
        description=(
            "Binding to 0.0.0.0 exposes the service on every network the host is "
            "attached to, which in a flat network means far more than intended."
        ),
        severity="low",
        confidence="medium",
        category="network_exposure",
        cwe="CWE-1327",
        owasp_top10="A05:2021",
        remediation=(
            "Bind to a specific interface, or keep 0.0.0.0 only where a container "
            "network namespace already provides the boundary."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.xml-unsafe-parse",
        name="XML parsed without entity protections",
        description=(
            "The stdlib XML parsers resolve external entities and are vulnerable to "
            "XXE file disclosure and to the 'billion laughs' expansion attack."
        ),
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-611",
        owasp_top10="A05:2021",
        owasp_asvs=("V5.5.2",),
        remediation="Parse untrusted XML with defusedxml, which disables entity "
        "resolution and expansion.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.jwt-verification-disabled",
        name="JWT signature verification disabled",
        description=(
            "Decoding a JWT with verify_signature disabled accepts any token, "
            "including one an attacker wrote. The claims become attacker-controlled "
            "input."
        ),
        severity="critical",
        confidence="high",
        category="broken_authentication",
        cwe="CWE-347",
        owasp_top10="A07:2021",
        owasp_asvs=("V3.5.3",),
        remediation=(
            "Verify the signature with an explicit algorithm allow-list. Never accept "
            "the algorithm from the token header."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.hardcoded-crypto-key",
        name="Hardcoded cryptographic key or IV",
        description=(
            "A key or initialisation vector was given as a literal. A key in source "
            "is readable by everyone with repository access, and a fixed IV destroys "
            "the semantic security of CBC and CTR modes."
        ),
        severity="high",
        confidence="medium",
        category="cryptographic_failure",
        cwe="CWE-321",
        owasp_top10="A02:2021",
        remediation=(
            "Load keys from a secrets manager or a key management service, and "
            "generate a fresh random IV or nonce for every encryption."
        ),
        languages=("python",),
    ),
    SastRule(
        rule_id="py.tempfile-insecure",
        name="Insecure temporary file creation",
        description=(
            "tempfile.mktemp() and predictable paths under /tmp are vulnerable to a "
            "symlink race: an attacker creates the path first and redirects the write."
        ),
        severity="medium",
        confidence="high",
        category="file_handling",
        cwe="CWE-377",
        remediation="Use tempfile.NamedTemporaryFile or tempfile.mkstemp, which create "
        "the file atomically.",
        languages=("python",),
    ),
    SastRule(
        rule_id="py.ssrf-request",
        name="Outbound request to a caller-controlled URL",
        description=(
            "An HTTP request target is built from a variable. If a caller influences "
            "it, the application can be made to reach internal services and cloud "
            "metadata endpoints on the attacker's behalf."
        ),
        severity="high",
        confidence="low",
        category="ssrf",
        cwe="CWE-918",
        owasp_top10="A10:2021",
        owasp_asvs=("V12.6.1",),
        remediation=(
            "Validate the destination against an allow-list, resolve it and reject "
            "private, loopback and link-local addresses before connecting. Re-check "
            "on every redirect."
        ),
        languages=("python",),
    ),
)

# ---------------------------------------------------------------------------
# Pattern rules for languages without a bundled AST analyser.
# ---------------------------------------------------------------------------
PATTERN_RULES: tuple[SastRule, ...] = (
    # ----------------------------------------------------- JavaScript / TypeScript
    SastRule(
        rule_id="js.eval",
        name="Dynamic code execution",
        description=(
            "eval(), new Function() and setTimeout with a string argument execute "
            "their input as JavaScript."
        ),
        severity="high",
        confidence="medium",
        category="command_execution",
        cwe="CWE-95",
        owasp_top10="A03:2021",
        remediation="Remove the dynamic evaluation; use JSON.parse for data and an "
        "explicit dispatch map for behaviour.",
        languages=("javascript", "typescript"),
        pattern=_re(r"\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"])"),
    ),
    SastRule(
        rule_id="js.inner-html",
        name="HTML sink assigned a dynamic value",
        description=(
            "innerHTML, outerHTML, document.write and insertAdjacentHTML parse their "
            "input as markup, so an interpolated value can introduce script."
        ),
        severity="high",
        confidence="low",
        category="cross_site_scripting",
        cwe="CWE-79",
        owasp_top10="A03:2021",
        owasp_asvs=("V5.3.3",),
        remediation=(
            "Assign to textContent, or sanitise with a library such as DOMPurify. In "
            "React, avoid dangerouslySetInnerHTML."
        ),
        languages=("javascript", "typescript"),
        pattern=_re(
            r"\.(?:innerHTML|outerHTML)\s*=\s*(?!['\"`]\s*['\"`])"
            r"|document\.write(?:ln)?\s*\("
            r"|insertAdjacentHTML\s*\("
            r"|dangerouslySetInnerHTML"
        ),
        negative_pattern=_re(r"DOMPurify|sanitiz|escapeHtml|textContent"),
    ),
    SastRule(
        rule_id="js.child-process-exec",
        name="Shell command execution",
        description=(
            "child_process.exec() and execSync() run their argument through a shell, "
            "so metacharacters in an interpolated value become commands."
        ),
        severity="high",
        confidence="medium",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        remediation="Use execFile or spawn with an argument array and no shell.",
        languages=("javascript", "typescript"),
        pattern=_re(
            r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`'\"].*\$\{|\bexec(?:Sync)?\s*\([^)]*\+"
        ),
    ),
    SastRule(
        rule_id="js.sql-template",
        name="SQL built by string interpolation",
        description="A SQL statement was assembled with a template literal or concatenation.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation=FIX_PARAMETERISE,
        languages=("javascript", "typescript"),
        pattern=_re(
            r"(?i)\b(?:query|execute|raw)\s*\(\s*[`'\"](?:[^`'\"]*)"
            r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`'\"]*(?:\$\{|\"\s*\+|'\s*\+)"
        ),
    ),
    SastRule(
        rule_id="js.tls-verification-disabled",
        name="TLS certificate verification disabled",
        description=(
            "rejectUnauthorized: false, or NODE_TLS_REJECT_UNAUTHORIZED=0, accepts any "
            "certificate, leaving the connection encrypted but unauthenticated."
        ),
        severity="high",
        confidence="high",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        remediation="Keep verification on and supply the internal CA bundle instead.",
        languages=("javascript", "typescript"),
        pattern=_re(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
    ),
    SastRule(
        rule_id="js.weak-hash",
        name="Weak hash algorithm",
        description="MD5 or SHA-1 used via createHash.",
        severity="medium",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-327",
        owasp_top10="A02:2021",
        remediation="Use sha256. For passwords use argon2, scrypt or bcrypt.",
        languages=("javascript", "typescript"),
        pattern=_re(r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]", ignore_case=True),
    ),
    SastRule(
        rule_id="js.insecure-random",
        name="Math.random() in a security context",
        description=(
            "Math.random() is not cryptographically secure and must not produce "
            "tokens, identifiers or keys."
        ),
        severity="medium",
        confidence="low",
        category="cryptographic_failure",
        cwe="CWE-338",
        owasp_top10="A02:2021",
        remediation="Use crypto.randomBytes() or crypto.randomUUID().",
        languages=("javascript", "typescript"),
        pattern=_re(
            r"(?i)(?:token|secret|key|password|nonce|salt|session|otp|uuid|id)\s*"
            r"[:=][^;\n]*Math\.random\s*\("
        ),
    ),
    SastRule(
        rule_id="js.jwt-none-algorithm",
        name="JWT verification weakened",
        description=(
            "Accepting the 'none' algorithm, or omitting an algorithm allow-list, lets "
            "an attacker present an unsigned token."
        ),
        severity="critical",
        confidence="medium",
        category="broken_authentication",
        cwe="CWE-347",
        owasp_top10="A07:2021",
        remediation="Pass an explicit algorithms allow-list to jwt.verify().",
        languages=("javascript", "typescript"),
        pattern=_re(r"(?i)algorithms?\s*:\s*\[?\s*['\"]none['\"]|\balgorithm\s*:\s*['\"]none['\"]"),
    ),
    SastRule(
        rule_id="js.cors-wildcard-credentials",
        name="Permissive CORS with credentials",
        description=(
            "Reflecting any origin while allowing credentials lets any site make "
            "authenticated requests on a user's behalf and read the response."
        ),
        severity="high",
        confidence="medium",
        category="security_misconfiguration",
        cwe="CWE-942",
        owasp_top10="A05:2021",
        remediation="Use an explicit origin allow-list whenever credentials are permitted.",
        languages=("javascript", "typescript"),
        pattern=_re(
            r"(?i)origin\s*:\s*(?:true|['\"]\*['\"]|function)[^}]{0,200}credentials\s*:\s*true"
            r"|credentials\s*:\s*true[^}]{0,200}origin\s*:\s*(?:true|['\"]\*['\"])"
        ),
    ),
    # ------------------------------------------------------------------ Java / Kotlin
    SastRule(
        rule_id="java.sql-concatenation",
        name="SQL built by concatenation",
        description="A JDBC statement was assembled by concatenating a variable.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation="Use PreparedStatement with bound parameters.",
        languages=("java", "kotlin"),
        pattern=_re(
            r"(?i)(?:executeQuery|executeUpdate|createQuery|execute)\s*\(\s*"
            r"[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\+"
        ),
    ),
    SastRule(
        rule_id="java.deserialization",
        name="Java native deserialization",
        description=(
            "ObjectInputStream.readObject() reconstructs arbitrary objects and is a "
            "well-established remote code execution vector when the stream is "
            "untrusted."
        ),
        severity="critical",
        confidence="medium",
        category="insecure_deserialization",
        cwe="CWE-502",
        owasp_top10="A08:2021",
        remediation="Use a data-only format. If native serialization is unavoidable, "
        "apply a strict class allow-list via ObjectInputFilter.",
        languages=("java", "kotlin"),
        pattern=_re(r"\bObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
    ),
    SastRule(
        rule_id="java.weak-crypto",
        name="Weak cipher or hash",
        description="DES, 3DES, RC4, ECB mode, MD5 or SHA-1 requested by name.",
        severity="high",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-327",
        owasp_top10="A02:2021",
        remediation="Use AES/GCM/NoPadding and SHA-256 or stronger.",
        languages=("java", "kotlin"),
        pattern=_re(
            r"(?i)(?:Cipher|MessageDigest|KeyGenerator)\.getInstance\s*\(\s*"
            r"[\"'](?:DES|DESede|RC4|RC2|Blowfish|MD5|SHA-?1|AES/ECB|.*?/ECB/)"
        ),
    ),
    SastRule(
        rule_id="java.trust-all-certificates",
        name="All TLS certificates trusted",
        description=(
            "A TrustManager that accepts every certificate, or a hostname verifier "
            "that always returns true, removes server authentication."
        ),
        severity="high",
        confidence="high",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        remediation="Use the platform trust store, or pin the internal CA explicitly.",
        languages=("java", "kotlin"),
        pattern=_re(
            r"(?s)checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}"
            r"|ALLOW_ALL_HOSTNAME_VERIFIER"
            r"|verify\s*\([^)]*\)\s*\{\s*return\s+true\s*;\s*\}"
        ),
    ),
    SastRule(
        rule_id="java.xxe",
        name="XML parsed without entity protections",
        description="An XML parser was created without disabling external entities.",
        severity="high",
        confidence="low",
        category="injection",
        cwe="CWE-611",
        owasp_top10="A05:2021",
        remediation=(
            "Set FEATURE_SECURE_PROCESSING and disable external general and parameter "
            "entities and the external DTD feature."
        ),
        languages=("java", "kotlin"),
        pattern=_re(
            r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\("
        ),
        negative_pattern=_re(
            r"(?:setFeature|setProperty|setExpandEntityReferences|"
            r"XMLConstants\.FEATURE_SECURE_PROCESSING|disallow-doctype-decl)"
        ),
    ),
    # ------------------------------------------------------------------------- Go
    SastRule(
        rule_id="go.sql-concatenation",
        name="SQL built by formatting",
        description="A query was assembled with Sprintf or concatenation.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation="Pass placeholders and arguments to Query/Exec instead.",
        languages=("go",),
        pattern=_re(
            r"(?i)(?:db|tx|conn)\.(?:Query|QueryRow|Exec)\w*\s*\(\s*"
            r"(?:fmt\.Sprintf|[\"`][^\"`]*[\"`]\s*\+)"
        ),
    ),
    SastRule(
        rule_id="go.command-execution",
        name="Shell command execution",
        description="exec.Command invoking a shell with a constructed argument.",
        severity="high",
        confidence="medium",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        remediation="Invoke the binary directly with an argument slice and no shell.",
        languages=("go",),
        pattern=_re(
            r"exec\.Command(?:Context)?\s*\(\s*[\"'](?:/bin/)?(?:ba)?sh[\"']\s*,\s*[\"']-c[\"']"
        ),
    ),
    SastRule(
        rule_id="go.tls-verification-disabled",
        name="TLS certificate verification disabled",
        description="InsecureSkipVerify: true disables server authentication.",
        severity="high",
        confidence="high",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        remediation="Leave verification on and set RootCAs for an internal authority.",
        languages=("go",),
        pattern=_re(r"InsecureSkipVerify\s*:\s*true"),
    ),
    SastRule(
        rule_id="go.weak-crypto",
        name="Weak cipher or hash",
        description="crypto/md5, crypto/sha1, crypto/des or crypto/rc4 imported.",
        severity="medium",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-327",
        owasp_top10="A02:2021",
        remediation="Use crypto/sha256 and crypto/aes with GCM.",
        languages=("go",),
        pattern=_re(r"[\"']crypto/(?:md5|sha1|des|rc4)[\"']"),
    ),
    # ------------------------------------------------------------------------ PHP
    SastRule(
        rule_id="php.sql-interpolation",
        name="SQL built by interpolation",
        description="A query string interpolates a variable directly.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation="Use PDO prepared statements with bound parameters.",
        languages=("php",),
        pattern=_re(
            r"(?i)(?:mysqli?_query|->query|->exec)\s*\(\s*[\"'][^\"']*"
            r"(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*\$"
        ),
    ),
    SastRule(
        rule_id="php.command-execution",
        name="Shell command execution",
        description="system, exec, shell_exec, passthru or backticks with a variable.",
        severity="critical",
        confidence="medium",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        remediation="Avoid shell execution; if unavoidable, use escapeshellarg on every argument.",
        languages=("php",),
        pattern=_re(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$"),
    ),
    SastRule(
        rule_id="php.unserialize",
        name="Unsafe deserialization",
        description="unserialize() on request data permits object injection.",
        severity="critical",
        confidence="medium",
        category="insecure_deserialization",
        cwe="CWE-502",
        owasp_top10="A08:2021",
        remediation="Use json_decode, or pass allowed_classes to unserialize.",
        languages=("php",),
        pattern=_re(r"unserialize\s*\(\s*\$(?:_GET|_POST|_COOKIE|_REQUEST)"),
    ),
    # ------------------------------------------------------------------------- C#
    SastRule(
        rule_id="csharp.sql-concatenation",
        name="SQL built by concatenation",
        description="A SqlCommand was assembled by concatenating a variable.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation="Use SqlParameter bindings or an ORM.",
        languages=("csharp",),
        pattern=_re(
            r"(?i)new\s+SqlCommand\s*\(\s*[\"$][^\"]*"
            r"(?:SELECT|INSERT|UPDATE|DELETE)[^\"]*(?:\"\s*\+|\{)"
        ),
    ),
    SastRule(
        rule_id="csharp.tls-verification-disabled",
        name="TLS certificate validation bypassed",
        description="A certificate validation callback that always returns true.",
        severity="high",
        confidence="high",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        remediation="Validate the chain, or pin the internal CA.",
        languages=("csharp",),
        pattern=_re(
            r"(?i)ServerCertificateValidationCallback\s*(?:\+?=)\s*"
            r"(?:delegate|\([^)]*\)\s*=>\s*true|.*?=>\s*true)"
        ),
    ),
    # ------------------------------------------------------------------------ Ruby
    SastRule(
        rule_id="ruby.command-execution",
        name="Shell command execution",
        description="Backticks, system() or %x with an interpolated value.",
        severity="high",
        confidence="medium",
        category="command_execution",
        cwe="CWE-78",
        owasp_top10="A03:2021",
        remediation="Use system with an argument array, which bypasses the shell.",
        languages=("ruby",),
        pattern=_re(r"(?:`[^`]*#\{|%x\{[^}]*#\{|system\s*\(\s*[\"'][^\"']*#\{)"),
    ),
    SastRule(
        rule_id="ruby.sql-interpolation",
        name="SQL built by interpolation",
        description="An ActiveRecord condition interpolates a value.",
        severity="high",
        confidence="medium",
        category="injection",
        cwe="CWE-89",
        owasp_top10="A03:2021",
        remediation="Use the array or hash condition form so values are bound.",
        languages=("ruby",),
        pattern=_re(r"(?i)\.(?:where|find_by_sql|exec_query)\s*\(\s*[\"'][^\"']*#\{"),
    ),
    # -------------------------------------------------------------- Swift / Obj-C
    SastRule(
        rule_id="swift.tls-verification-disabled",
        name="TLS certificate validation bypassed",
        description=(
            "An authentication challenge handled by trusting the server's own "
            "credential accepts any certificate."
        ),
        severity="high",
        confidence="medium",
        category="insecure_communication",
        cwe="CWE-295",
        owasp_top10="A02:2021",
        remediation="Evaluate the trust object, or pin the expected certificate.",
        languages=("swift", "objectivec"),
        pattern=_re(
            r"URLCredential\s*\(\s*trust:\s*challenge\.protectionSpace\.serverTrust"
            r"|allowsAnyHTTPSCertificate"
        ),
    ),
    SastRule(
        rule_id="swift.insecure-storage",
        name="Sensitive value in UserDefaults",
        description=(
            "UserDefaults is an unencrypted plist. Credentials and tokens stored "
            "there are readable from a device backup or a jailbroken device."
        ),
        severity="medium",
        confidence="low",
        category="insecure_storage",
        cwe="CWE-922",
        owasp_masvs=("MASVS-STORAGE-1",),
        remediation="Store secrets in the Keychain with an appropriate accessibility class.",
        languages=("swift", "objectivec"),
        pattern=_re(
            r"(?i)UserDefaults[^\n]{0,80}\.set\s*\([^)]*"
            r"(?:password|token|secret|key|credential|pin)"
        ),
    ),
    # ----------------------------------------------------------------------- C/C++
    SastRule(
        rule_id="c.unsafe-string-function",
        name="Unbounded string function",
        description=(
            "strcpy, strcat, sprintf and gets perform no bounds checking and overflow "
            "the destination when the source is longer."
        ),
        severity="high",
        confidence="medium",
        category="code_quality_security",
        cwe="CWE-120",
        remediation="Use the bounded forms (strncpy, snprintf, strlcpy) and check the result.",
        languages=("c", "cpp"),
        pattern=_re(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets)\s*\("),
    ),
    SastRule(
        rule_id="c.system-call",
        name="Shell command execution",
        description="system() or popen() passes its argument to a shell.",
        severity="high",
        confidence="medium",
        category="command_execution",
        cwe="CWE-78",
        remediation="Use execve with an explicit argument vector.",
        languages=("c", "cpp"),
        pattern=_re(r"\b(?:system|popen)\s*\("),
    ),
    # ----------------------------------------------------------- Infrastructure
    SastRule(
        rule_id="tf.public-ingress",
        name="Security group open to the internet",
        description=(
            "An ingress rule allows 0.0.0.0/0. Combined with an administrative port "
            "this exposes the service to the entire internet."
        ),
        severity="high",
        confidence="medium",
        category="cloud_misconfiguration",
        cwe="CWE-284",
        owasp_top10="A01:2021",
        remediation="Restrict the CIDR to known networks, or front the service with a "
        "bastion or load balancer.",
        languages=("terraform",),
        pattern=_re(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"'),
    ),
    SastRule(
        rule_id="tf.unencrypted-storage",
        name="Storage encryption disabled",
        description="A storage resource explicitly disables encryption at rest.",
        severity="high",
        confidence="high",
        category="cryptographic_failure",
        cwe="CWE-311",
        owasp_top10="A02:2021",
        remediation="Enable encryption at rest with a customer-managed key where policy "
        "requires it.",
        languages=("terraform",),
        pattern=_re(r"(?i)(?:encrypted|storage_encrypted|encryption_enabled)\s*=\s*false"),
    ),
)

#: File extension to language.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".php": "php",
    ".phtml": "php",
    ".cs": "csharp",
    ".rb": "ruby",
    ".rake": "ruby",
    ".swift": "swift",
    ".m": "objectivec",
    ".mm": "objectivec",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
}

SUPPORTED_LANGUAGES: tuple[str, ...] = tuple(sorted(set(LANGUAGE_BY_EXTENSION.values())))

PATTERN_RULES_BY_LANGUAGE: dict[str, list[SastRule]] = {}
for _rule in PATTERN_RULES:
    for _language in _rule.languages:
        PATTERN_RULES_BY_LANGUAGE.setdefault(_language, []).append(_rule)

ALL_RULES: tuple[SastRule, ...] = (*PYTHON_AST_RULES, *PATTERN_RULES)
RULES_BY_ID: dict[str, SastRule] = {r.rule_id: r for r in ALL_RULES}

#: Comment markers that suppress a finding on the line they appear on. Honoured
#: so a reviewed and accepted construct does not reappear on every scan, which
#: is how a finding list becomes something people stop reading.
SUPPRESSION_PATTERN = _re(r"(?i)(?:#|//|/\*|--)\s*(?:qguard|nosec|noqa|nosemgrep|codeql)\s*[:\s]?")


#: A rule identifier inside a suppression comment, e.g. `py.eval-exec`.
_RULE_ID_IN_COMMENT = re.compile(r"\b[a-z]{1,10}\.[a-z0-9]+(?:-[a-z0-9]+)*\b")


def is_suppressed(line: str, rule_id: str) -> bool:
    """Whether a line carries a suppression comment covering this rule.

    A marker with no rule identifier after it suppresses every rule on the
    line, whether or not it is followed by a written justification — and a
    justification is what a good suppression looks like, so
    ``# nosec reviewed: input is a fixed allow-list`` must suppress exactly as
    ``# nosec`` does. A marker that names rule identifiers suppresses only
    those, so a line can acknowledge one finding while remaining open to
    others.

    Suppressions are counted and surfaced in the engine's statistics, so they
    reduce noise without silently reducing visible coverage.
    """
    match = SUPPRESSION_PATTERN.search(line)
    if not match:
        return False
    tail = line[match.end() :].strip()
    named = _RULE_ID_IN_COMMENT.findall(tail)
    if not named:
        # Bare marker, or marker plus prose: suppresses every rule here.
        return True
    short = rule_id.split(".", 1)[-1]
    return any(name in (rule_id, short) for name in named)
