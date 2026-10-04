"""Static application security testing engine.

Python is analysed through its real syntax tree: the analyser knows what a call
is, which argument is which, and whether a value is a literal or interpolated.
That distinction is what separates a finding from noise — ``subprocess.run(cmd,
shell=True)`` where ``cmd`` is a module constant is very different from the same
call where ``cmd`` is an f-string built from a request parameter, and only the
second is worth waking somebody for.

Other languages are matched with pattern rules and surrounding-context checks,
and are reported at the confidence a regular expression actually warrants. The
finding states which method found it, so a reviewer knows how much to trust it.

Passive: reads files, sends nothing, needs no test authorization.
"""

from __future__ import annotations

import ast
import asyncio
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from qguard_scanner.rules.sast_rules import (
    LANGUAGE_BY_EXTENSION,
    PATTERN_RULES_BY_LANGUAGE,
    RULES_BY_ID,
    SastRule,
    is_suppressed,
)
from qguard_scanner.rules.secret_patterns import SKIP_DIR_NAMES
from qguard_scanner.sdk.engine import (
    EngineCapability,
    EngineContext,
    EngineMetadata,
    EngineResult,
    EngineStatus,
    SecurityEngine,
)
from qguard_scanner.sdk.finding import CodeLocation, Evidence, ScanFinding
from qguard_scanner.sdk.registry import register_engine

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_LENGTH = 2000
MAX_FINDINGS_PER_RULE = 200

#: Names whose value is likely to originate outside the process. Used to decide
#: whether an interpolated value is plausibly attacker-influenced, which raises
#: a finding's confidence from "this construct is risky" to "this construct is
#: risky *and* reachable".
TAINT_HINTS: frozenset[str] = frozenset(
    {
        "request",
        "req",
        "params",
        "query",
        "form",
        "body",
        "json",
        "data",
        "args",
        "kwargs",
        "input",
        "payload",
        "headers",
        "cookies",
        "argv",
        "environ",
        "getenv",
        "stdin",
        "user_input",
        "user_data",
        "untrusted",
        "external",
        "remote",
        "client",
        "post",
        "get",
        "path_param",
        "query_param",
        "upload",
        "filename",
        "url",
        "uri",
        "host",
        "target",
    }
)

#: Hash algorithms with practical collision attacks.
WEAK_HASHES: frozenset[str] = frozenset({"md5", "sha1", "md4", "sha", "ripemd160"})

#: Ciphers and modes that are broken or inadequate.
WEAK_CIPHERS: frozenset[str] = frozenset(
    {"des", "tripledes", "des3", "rc2", "rc4", "arc4", "blowfish", "idea", "cast5", "seed"}
)

SQL_KEYWORDS: tuple[str, ...] = (
    "select ",
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "alter ",
    "union ",
    "where ",
    "from ",
    "into ",
    "values ",
    "create table",
)


@dataclass(slots=True)
class _Issue:
    """One detected problem, before it becomes a finding."""

    rule: SastRule
    file_path: str
    line_number: int
    end_line: int | None
    line_text: str
    symbol: str | None
    detail: str
    detection: str
    confidence_override: str | None = None
    severity_override: str | None = None
    tainted: bool = False
    evidence_extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class _Tally:
    files_examined: int = 0
    files_by_language: Counter[str] = field(default_factory=Counter)
    parse_failures: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    suppressed: int = 0
    skipped_large: int = 0
    lines_examined: int = 0

    def merge(self, other: _Tally) -> None:
        self.files_examined += other.files_examined
        self.files_by_language.update(other.files_by_language)
        self.parse_failures.extend(other.parse_failures)
        self.unreadable.extend(other.unreadable)
        self.suppressed += other.suppressed
        self.skipped_large += other.skipped_large
        self.lines_examined += other.lines_examined


class PythonSecurityVisitor(ast.NodeVisitor):
    """Walks a Python syntax tree looking for the AST rules.

    Carries a light notion of taint: it records which local names were assigned
    from something that looks externally influenced, so a rule can distinguish
    a risky construct from a risky construct that is actually reachable.
    """

    def __init__(self, file_path: str, source_lines: list[str]) -> None:
        self.file_path = file_path
        self.lines = source_lines
        self.issues: list[_Issue] = []
        self.suppressed = 0
        self._scope: list[str] = []
        self._tainted_names: set[str] = set()

    # -------------------------------------------------------------- helpers
    def _line(self, node: ast.AST) -> str:
        index = getattr(node, "lineno", 0) - 1
        return self.lines[index] if 0 <= index < len(self.lines) else ""

    def _symbol(self) -> str | None:
        return ".".join(self._scope) if self._scope else None

    def _add(
        self,
        rule_id: str,
        node: ast.AST,
        detail: str,
        *,
        tainted: bool = False,
        confidence: str | None = None,
        severity: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        rule = RULES_BY_ID.get(rule_id)
        if rule is None:  # pragma: no cover - guards a typo in a rule id
            return
        line = self._line(node)
        if is_suppressed(line, rule_id):
            self.suppressed += 1
            return
        self.issues.append(
            _Issue(
                rule=rule,
                file_path=self.file_path,
                line_number=getattr(node, "lineno", 0),
                end_line=getattr(node, "end_lineno", None),
                line_text=line,
                symbol=self._symbol(),
                detail=detail,
                detection="ast",
                confidence_override=confidence,
                severity_override=severity,
                tainted=tainted,
                evidence_extra=extra or {},
            )
        )

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        """Dotted name of a call target, e.g. ``subprocess.run``."""
        parts: list[str] = []
        current: ast.AST = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _keyword(node: ast.Call, name: str) -> ast.expr | None:
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    @staticmethod
    def _is_true(value: ast.expr | None) -> bool:
        return isinstance(value, ast.Constant) and value.value is True

    @staticmethod
    def _is_false(value: ast.expr | None) -> bool:
        return isinstance(value, ast.Constant) and value.value is False

    @staticmethod
    def _literal_str(value: ast.expr | None) -> str | None:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
        return None

    def _names_in(self, node: ast.AST) -> set[str]:
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def _looks_tainted(self, node: ast.AST | None) -> bool:
        """Whether an expression plausibly carries externally-influenced data."""
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return False
        names = self._names_in(node)
        if names & self._tainted_names:
            return True
        lowered = {n.lower() for n in names}
        if lowered & TAINT_HINTS:
            return True
        # `request.args.get(...)`, `os.environ[...]`, `sys.argv[1]`
        for sub in ast.walk(node):
            if isinstance(sub, ast.Attribute) and sub.attr.lower() in TAINT_HINTS:
                return True
            if isinstance(sub, ast.Call):
                called = self._call_name(sub).lower()
                if any(hint in called for hint in ("getenv", "input", "argv", "recv")):
                    return True
        return False

    @staticmethod
    def _is_dynamic_string(node: ast.AST | None) -> bool:
        """Whether a string expression is built at runtime rather than fixed."""
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("format", "join"):
                return True
        return False

    # --------------------------------------------------------------- scopes
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope.append(node.name)
        # Parameters named like request data are treated as tainted inside the
        # function, which is how a handler's input reaches the rules.
        entering = {
            arg.arg
            for arg in (*node.args.args, *node.args.kwonlyargs)
            if arg.arg.lower() in TAINT_HINTS
        }
        self._tainted_names |= entering
        self.generic_visit(node)
        self._tainted_names -= entering
        self._scope.pop()

    # ast.NodeVisitor dispatches on the exact node class name, so the
    # CamelCase spelling is required by the API.
    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        # Propagate taint through simple assignments.
        if self._looks_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_names.add(target.id)

        self._check_hardcoded_crypto(node)
        self._check_sql_assignment(node)
        self._check_bind_all(node)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        text = ast.unparse(node.test).lower() if hasattr(ast, "unparse") else ""
        if any(
            token in text
            for token in (
                "is_admin",
                "is_staff",
                "is_superuser",
                "has_perm",
                "permission",
                "authoriz",
                "authentic",
                "is_owner",
                "can_",
                "role",
                "token",
                "current_user",
            )
        ):
            self._add(
                "py.assert-for-security",
                node,
                (
                    f"The assertion `{ast.unparse(node.test)[:120]}` appears to enforce an "
                    "access-control decision. Assertions are stripped under python -O, so "
                    "this check would not run in an optimised deployment."
                ),
            )
        self.generic_visit(node)

    # ---------------------------------------------------------------- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node)
        lowered = name.lower()

        self._check_dynamic_execution(node, name, lowered)
        self._check_process_execution(node, name, lowered)
        self._check_deserialization(node, name, lowered)
        self._check_yaml(node, name, lowered)
        self._check_hashes(node, name, lowered)
        self._check_random(node, name, lowered)
        self._check_tls(node, name, lowered)
        self._check_ciphers(node, name, lowered)
        self._check_sql_call(node, name, lowered)
        self._check_path_traversal(node, name, lowered)
        self._check_flask_debug(node, name, lowered)
        self._check_xml(node, name, lowered)
        self._check_jwt(node, name, lowered)
        self._check_tempfile(node, name, lowered)
        self._check_ssrf(node, name, lowered)
        self.generic_visit(node)

    # ----------------------------------------------------------- individual
    def _check_dynamic_execution(self, node: ast.Call, name: str, lowered: str) -> None:
        if lowered not in ("eval", "exec", "compile", "builtins.eval", "builtins.exec"):
            return
        argument = node.args[0] if node.args else None
        tainted = self._looks_tainted(argument)
        dynamic = self._is_dynamic_string(argument) or not isinstance(argument, ast.Constant)
        if not dynamic:
            # eval on a fixed literal is a code-quality problem, not a
            # vulnerability, and reporting it as critical would be wrong.
            return
        self._add(
            "py.eval-exec",
            node,
            (
                f"{name}() is called with a runtime-constructed argument"
                + (
                    " that appears to derive from external input, so the caller "
                    "plausibly controls what executes."
                    if tainted
                    else ", so whatever reaches it will be executed as Python."
                )
            ),
            tainted=tainted,
            confidence="high" if tainted else "medium",
        )

    def _check_process_execution(self, node: ast.Call, name: str, lowered: str) -> None:
        if lowered in ("os.system", "os.popen", "commands.getoutput"):
            argument = node.args[0] if node.args else None
            tainted = self._looks_tainted(argument)
            self._add(
                "py.os-system",
                node,
                (
                    f"{name}() passes its entire argument to a shell"
                    + (" and the argument appears to include external input." if tainted else ".")
                ),
                tainted=tainted,
                confidence="high" if tainted else "medium",
                severity="critical" if tainted else "high",
            )
            return

        if lowered.startswith(("subprocess.", "asyncio.create_subprocess")) or lowered in (
            "popen",
            "run",
            "call",
            "check_output",
            "check_call",
        ):
            shell = self._keyword(node, "shell")
            if not self._is_true(shell):
                return
            argument = node.args[0] if node.args else None
            tainted = self._looks_tainted(argument)
            dynamic = self._is_dynamic_string(argument)
            self._add(
                "py.subprocess-shell-true",
                node,
                (
                    f"{name}() was called with shell=True"
                    + (
                        " and a command string built at runtime from what looks like "
                        "external input, so shell metacharacters in that input would "
                        "run as separate commands."
                        if tainted
                        else (
                            " and a command string built at runtime, so any "
                            "metacharacter in the interpolated value is interpreted by "
                            "the shell."
                            if dynamic
                            else " with a fixed command. The shell is unnecessary here "
                            "and removing it eliminates the risk entirely."
                        )
                    )
                ),
                tainted=tainted,
                confidence="high" if (tainted or dynamic) else "low",
                severity="critical" if tainted else ("high" if dynamic else "low"),
            )

    def _check_deserialization(self, node: ast.Call, name: str, lowered: str) -> None:
        unsafe = (
            "pickle.load",
            "pickle.loads",
            "cpickle.load",
            "cpickle.loads",
            "_pickle.load",
            "_pickle.loads",
            "marshal.load",
            "marshal.loads",
            "shelve.open",
            "dill.load",
            "dill.loads",
            "jsonpickle.decode",
        )
        if lowered in unsafe:
            argument = node.args[0] if node.args else None
            tainted = self._looks_tainted(argument)
            self._add(
                "py.pickle-load",
                node,
                (
                    f"{name}() reconstructs arbitrary Python objects"
                    + (
                        " from data that appears to come from outside the application, "
                        "which is remote code execution rather than a parsing issue."
                        if tainted
                        else ". If the input is ever attacker-influenced this is remote "
                        "code execution."
                    )
                ),
                tainted=tainted,
                confidence="high" if tainted else "medium",
            )

    def _check_yaml(self, node: ast.Call, name: str, lowered: str) -> None:
        if lowered not in ("yaml.load", "yaml.load_all", "yaml.full_load"):
            return
        loader = self._keyword(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
        if loader is not None:
            loader_name = ast.unparse(loader) if hasattr(ast, "unparse") else ""
            if "safe" in loader_name.lower() or "BaseLoader" in loader_name:
                return
        self._add(
            "py.yaml-unsafe-load",
            node,
            (
                f"{name}() was called without a safe loader, so YAML tags in the input "
                "can instantiate arbitrary Python objects."
            ),
            tainted=self._looks_tainted(node.args[0] if node.args else None),
        )

    def _check_hashes(self, node: ast.Call, name: str, lowered: str) -> None:
        algorithm: str | None = None
        if lowered in ("hashlib.md5", "hashlib.sha1"):
            algorithm = lowered.rsplit(".", 1)[-1]
        elif lowered in ("hashlib.new",) and node.args:
            algorithm = (self._literal_str(node.args[0]) or "").lower() or None
        if algorithm is None or algorithm not in WEAK_HASHES:
            return
        # `usedforsecurity=False` is the documented way to say this hash is a
        # checksum, not a security control. Respecting it avoids arguing with a
        # developer who already made the distinction explicit.
        if self._is_false(self._keyword(node, "usedforsecurity")):
            return
        line = self._line(node).lower()
        non_security = any(
            token in line for token in ("etag", "cache", "checksum", "dedup", "fingerprint")
        )
        self._add(
            "py.weak-hash",
            node,
            (
                f"{algorithm.upper()} is used here. It has practical collision attacks, so "
                "it must not back a signature, integrity check or any other security "
                "decision."
                + (
                    " The surrounding code suggests a non-security use; if so, pass "
                    "usedforsecurity=False to make that explicit."
                    if non_security
                    else ""
                )
            ),
            confidence="low" if non_security else "high",
            severity="low" if non_security else "medium",
            extra={"algorithm": algorithm},
        )

    def _check_random(self, node: ast.Call, name: str, lowered: str) -> None:
        if not lowered.startswith("random."):
            return
        if lowered.startswith("random.systemrandom"):
            return
        line = self._line(node).lower()
        security_context = any(
            token in line
            for token in (
                "token",
                "secret",
                "password",
                "passwd",
                "key",
                "nonce",
                "salt",
                "session",
                "otp",
                "code",
                "csrf",
                "iv",
                "auth",
            )
        )
        if not security_context:
            # Random numbers have plenty of legitimate non-security uses;
            # flagging all of them would bury the ones that matter.
            return
        self._add(
            "py.insecure-random",
            node,
            (
                f"{name}() is a deterministic Mersenne Twister and its output is "
                "predictable from a few observed values. The surrounding code suggests a "
                "security value is being generated."
            ),
            confidence="medium",
        )

    def _check_tls(self, node: ast.Call, name: str, lowered: str) -> None:
        if self._is_false(self._keyword(node, "verify")):
            self._add(
                "py.tls-verification-disabled",
                node,
                (
                    f"{name}() passes verify=False, so any certificate is accepted. The "
                    "connection is encrypted but not authenticated, which leaves it open "
                    "to interception."
                ),
            )
        if lowered in ("ssl._create_unverified_context", "ssl.create_default_context") and (
            lowered.endswith("_create_unverified_context")
        ):
            self._add(
                "py.tls-verification-disabled",
                node,
                "An unverified SSL context performs no certificate or hostname checks.",
            )

    def _check_ciphers(self, node: ast.Call, name: str, lowered: str) -> None:
        last = lowered.rsplit(".", 1)[-1]
        if last in WEAK_CIPHERS or any(f".{c}." in lowered for c in WEAK_CIPHERS):
            self._add(
                "py.weak-cipher",
                node,
                f"{name} selects a cipher that is broken or offers inadequate security.",
                extra={"cipher": last},
            )
            return
        if "modes.ecb" in lowered or last == "ecb":
            self._add(
                "py.weak-cipher",
                node,
                (
                    "ECB mode encrypts identical plaintext blocks to identical ciphertext "
                    "blocks, so it leaks the structure of the data."
                ),
                extra={"mode": "ECB"},
            )

    def _check_sql_call(self, node: ast.Call, name: str, lowered: str) -> None:
        last = lowered.rsplit(".", 1)[-1]
        if last not in ("execute", "executemany", "executescript", "raw", "text", "query"):
            return
        argument = node.args[0] if node.args else None
        if argument is None or not self._is_dynamic_string(argument):
            return
        rendered = (ast.unparse(argument) if hasattr(ast, "unparse") else "").lower()
        if not any(keyword in rendered for keyword in SQL_KEYWORDS):
            return
        tainted = self._looks_tainted(argument)
        self._add(
            "py.sql-string-building",
            node,
            (
                f"The statement passed to {name}() is assembled at runtime"
                + (
                    " from what appears to be external input, so the interpolated value "
                    "becomes part of the SQL rather than a parameter."
                    if tainted
                    else ", so any interpolated value becomes part of the SQL."
                )
            ),
            tainted=tainted,
            confidence="high" if tainted else "medium",
            severity="critical" if tainted else "high",
        )

    def _check_sql_assignment(self, node: ast.Assign) -> None:
        if not self._is_dynamic_string(node.value):
            return
        rendered = (ast.unparse(node.value) if hasattr(ast, "unparse") else "").lower()
        if not any(keyword in rendered for keyword in SQL_KEYWORDS):
            return
        tainted = self._looks_tainted(node.value)
        self._add(
            "py.sql-string-building",
            node,
            (
                "A SQL statement is built by string formatting here"
                + (
                    " from what appears to be external input."
                    if tainted
                    else ", so any interpolated value becomes part of the statement."
                )
            ),
            tainted=tainted,
            confidence="medium" if tainted else "low",
            severity="high" if tainted else "medium",
        )

    def _check_path_traversal(self, node: ast.Call, name: str, lowered: str) -> None:
        if lowered not in ("os.path.join", "open", "pathlib.path", "path"):
            return
        tainted_arg = next((a for a in node.args if self._looks_tainted(a)), None)
        if tainted_arg is None:
            return
        line = self._line(node)
        if any(
            guard in line
            for guard in ("is_relative_to", "realpath", "resolve()", "secure_filename", "basename")
        ):
            return
        self._add(
            "py.path-traversal",
            node,
            (
                f"{name}() builds a path from a value that appears to come from outside "
                "the application. Without a containment check, '..' segments or an "
                "absolute path reach files outside the intended directory."
            ),
            tainted=True,
            confidence="low",
        )

    def _check_flask_debug(self, node: ast.Call, name: str, lowered: str) -> None:
        if not lowered.endswith(".run") and lowered != "run":
            return
        if self._is_true(self._keyword(node, "debug")):
            self._add(
                "py.flask-debug",
                node,
                (
                    "debug=True enables the Werkzeug interactive debugger, which offers a "
                    "Python console to anyone able to trigger an error page."
                ),
            )

    def _check_bind_all(self, node: ast.Assign) -> None:
        for sub in ast.walk(node.value):
            # The literal address is the thing being detected, not a binding.
            if isinstance(sub, ast.Constant) and sub.value in ("0.0.0.0", "::"):  # noqa: S104
                self._add(
                    "py.bind-all-interfaces",
                    node,
                    (
                        f"The address {sub.value!r} binds every interface on the host. "
                        "Inside a container this is often intentional; on a shared host it "
                        "exposes far more than intended."
                    ),
                    confidence="low",
                )
                return

    def _check_xml(self, node: ast.Call, name: str, lowered: str) -> None:
        unsafe = (
            "xml.etree.elementtree.parse",
            "xml.etree.elementtree.fromstring",
            "elementtree.parse",
            "elementtree.fromstring",
            "et.parse",
            "et.fromstring",
            "xml.dom.minidom.parse",
            "xml.dom.minidom.parsestring",
            "xml.sax.parse",
            "lxml.etree.parse",
            "lxml.etree.fromstring",
        )
        if lowered in unsafe or (lowered.endswith((".parse", ".fromstring")) and "xml" in lowered):
            self._add(
                "py.xml-unsafe-parse",
                node,
                (
                    f"{name}() resolves external entities by default, which permits XXE "
                    "file disclosure and entity-expansion denial of service."
                ),
                tainted=self._looks_tainted(node.args[0] if node.args else None),
                confidence="medium",
            )

    def _check_jwt(self, node: ast.Call, name: str, lowered: str) -> None:
        if "jwt" not in lowered or "decode" not in lowered:
            return
        options = self._keyword(node, "options")
        verify = self._keyword(node, "verify")
        disabled = self._is_false(verify)
        if isinstance(options, ast.Dict):
            for key, value in zip(options.keys, options.values, strict=False):
                key_name = self._literal_str(key) or ""
                if key_name in ("verify_signature", "verify_exp", "verify_aud") and (
                    self._is_false(value)
                ):
                    disabled = True
        if disabled:
            self._add(
                "py.jwt-verification-disabled",
                node,
                (
                    f"{name}() is called with verification disabled, so a token an "
                    "attacker wrote is accepted and its claims become attacker-controlled "
                    "input."
                ),
            )

    def _check_tempfile(self, node: ast.Call, name: str, lowered: str) -> None:
        if lowered in ("tempfile.mktemp", "os.tmpnam", "os.tempnam"):
            self._add(
                "py.tempfile-insecure",
                node,
                (
                    f"{name}() returns a name without creating the file, leaving a window "
                    "in which an attacker can create it first as a symlink."
                ),
            )

    def _check_ssrf(self, node: ast.Call, name: str, lowered: str) -> None:
        http_calls = (
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.head",
            "requests.patch",
            "requests.request",
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "urllib.request.urlopen",
            "urlopen",
            "aiohttp.clientsession.get",
            "session.get",
            "client.get",
        )
        if lowered not in http_calls:
            return
        url_arg = node.args[0] if node.args else self._keyword(node, "url")
        if url_arg is None or isinstance(url_arg, ast.Constant):
            return
        if not self._looks_tainted(url_arg):
            return
        line = self._line(node)
        if any(
            guard in line for guard in ("allowlist", "allow_list", "validate_url", "is_safe_url")
        ):
            return
        self._add(
            "py.ssrf-request",
            node,
            (
                f"{name}() requests a URL built from what appears to be external input. "
                "Without validation the application can be made to reach internal "
                "services and cloud metadata endpoints on the caller's behalf."
            ),
            tainted=True,
            confidence="low",
        )

    def _check_hardcoded_crypto(self, node: ast.Assign) -> None:
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            lowered = target.id.lower()
            if not any(
                token in lowered for token in ("_key", "key_", "secret_key", "iv", "nonce", "salt")
            ):
                continue
            value = node.value
            literal = None
            if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
                literal = value.value
            if literal is None or len(literal) < 8:
                continue
            self._add(
                "py.hardcoded-crypto-key",
                node,
                (
                    f"{target.id} is assigned a literal value. A key in source is readable "
                    "by anyone with repository access, and a fixed IV or nonce removes the "
                    "semantic security of CBC and CTR modes."
                ),
                confidence="medium",
                extra={"name": target.id, "length": len(literal)},
            )


@register_engine
class SastEngine(SecurityEngine):
    """Static analysis across 17 languages."""

    metadata = EngineMetadata(
        key="sast",
        name="Static Application Security Testing",
        description=(
            "Analyses source code for vulnerable patterns. Python is analysed through "
            "its syntax tree with light taint tracking; 16 other languages are covered "
            "by context-aware pattern rules reported at appropriate confidence."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository"),
        capabilities=frozenset({EngineCapability.FILESYSTEM}),
        categories=(
            "injection",
            "command_execution",
            "cross_site_scripting",
            "insecure_deserialization",
            "path_traversal",
            "cryptographic_failure",
            "broken_authentication",
            "broken_access_control",
            "ssrf",
            "security_misconfiguration",
            "insecure_communication",
            "file_handling",
            "code_quality_security",
            "cloud_misconfiguration",
            "network_exposure",
        ),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        exists = await asyncio.to_thread(Path(ctx.target.value).exists)
        if not exists:
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        max_files = int(ctx.option("max_files", 20_000))
        languages = ctx.option("languages")
        selected = set(languages) if languages else None

        await ctx.report_progress(2, f"collecting source files under {root}")
        files = await asyncio.to_thread(self._collect, root, max_files, selected)
        if not files:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No files in a supported language were found under {root}. Coverage "
                    "is zero, so this result says nothing about the code's security."
                ),
                stats={
                    "files_found": 0,
                    "supported_languages": sorted(set(LANGUAGE_BY_EXTENSION.values())),
                },
            )

        issues: list[_Issue] = []
        per_rule: Counter[str] = Counter()
        tally = _Tally()
        truncated = False

        batch_size = 100
        for offset in range(0, len(files), batch_size):
            if ctx.is_cancelled():
                break
            batch = files[offset : offset + batch_size]
            batch_issues, batch_tally = await asyncio.to_thread(self._analyze_batch, batch, root)
            tally.merge(batch_tally)
            for issue in batch_issues:
                if per_rule[issue.rule.rule_id] >= MAX_FINDINGS_PER_RULE:
                    truncated = True
                    continue
                per_rule[issue.rule.rule_id] += 1
                issues.append(issue)
            await ctx.report_progress(
                min(95, int(100 * (offset + len(batch)) / len(files))),
                f"analysed {tally.files_examined} file(s), {len(issues)} issue(s)",
            )

        findings = [self._to_finding(issue, ctx) for issue in issues]
        stats: dict[str, Any] = {
            "files_found": len(files),
            "files_examined": tally.files_examined,
            "lines_examined": tally.lines_examined,
            "files_by_language": dict(tally.files_by_language),
            "parse_failures": len(tally.parse_failures),
            "unreadable_files": len(tally.unreadable),
            "suppressed_findings": tally.suppressed,
            "rules_evaluated": len(RULES_BY_ID),
            "findings_per_rule": dict(per_rule),
            "tainted_findings": sum(1 for i in issues if i.tainted),
        }
        warnings: list[str] = []
        if tally.parse_failures:
            warnings.append(
                f"{len(tally.parse_failures)} Python file(s) could not be parsed, so they "
                "received pattern analysis only: " + "; ".join(tally.parse_failures[:5])
            )
        if tally.unreadable:
            warnings.append(
                f"{len(tally.unreadable)} file(s) could not be read: "
                + "; ".join(tally.unreadable[:5])
            )
        if tally.suppressed:
            warnings.append(
                f"{tally.suppressed} finding(s) were suppressed by in-code comments. "
                "Suppressions are counted here so they stay visible."
            )
        if truncated:
            warnings.append(
                f"Some rules reached the {MAX_FINDINGS_PER_RULE}-finding cap, so the same "
                "pattern may occur in more places."
            )

        if ctx.is_cancelled():
            return EngineResult(
                engine=self.key,
                status=EngineStatus.CANCELLED,
                findings=findings,
                stats=stats,
                items_examined=tally.files_examined,
                warnings=warnings,
            )

        if tally.parse_failures or tally.unreadable or truncated:
            return EngineResult.degraded(
                self.key,
                findings,
                reason="Coverage is incomplete: " + " ".join(warnings),
                stats=stats,
                items_examined=tally.files_examined,
                checks_executed=tally.files_examined * len(RULES_BY_ID),
                warnings=warnings,
            )

        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=tally.files_examined,
            checks_executed=tally.files_examined * len(RULES_BY_ID),
            warnings=warnings,
        )

    # ------------------------------------------------------------ collection
    @staticmethod
    def _collect(root: Path, max_files: int, languages: set[str] | None) -> list[Path]:
        if root.is_file():
            return [root]
        collected: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                language = LANGUAGE_BY_EXTENSION.get(Path(name).suffix.lower())
                if language is None or (languages and language not in languages):
                    continue
                candidate = Path(dirpath) / name
                if candidate.is_symlink():
                    continue
                collected.append(candidate)
                if len(collected) >= max_files:
                    return collected
        return collected

    # -------------------------------------------------------------- analysis
    def _analyze_batch(self, batch: list[Path], root: Path) -> tuple[list[_Issue], _Tally]:
        issues: list[_Issue] = []
        tally = _Tally()

        for file_path in batch:
            try:
                relative = str(file_path.relative_to(root))
            except ValueError:
                relative = file_path.name
            language = LANGUAGE_BY_EXTENSION.get(file_path.suffix.lower())
            if language is None:
                continue
            try:
                if file_path.stat().st_size > MAX_FILE_BYTES:
                    tally.skipped_large += 1
                    continue
                source = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                tally.unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue

            tally.files_examined += 1
            tally.files_by_language[language] += 1
            lines = source.splitlines()
            tally.lines_examined += len(lines)

            if language == "python":
                try:
                    tree = ast.parse(source, filename=relative)
                except SyntaxError as exc:
                    # A file that will not parse gets pattern analysis instead,
                    # and the gap is reported rather than hidden.
                    tally.parse_failures.append(f"{relative}: line {exc.lineno}: {exc.msg}")
                else:
                    visitor = PythonSecurityVisitor(relative, lines)
                    visitor.visit(tree)
                    issues.extend(visitor.issues)
                    tally.suppressed += visitor.suppressed

            pattern_issues, suppressed = self._pattern_scan(lines, relative, language)
            issues.extend(pattern_issues)
            tally.suppressed += suppressed

        return issues, tally

    @staticmethod
    def _pattern_scan(lines: list[str], relative: str, language: str) -> tuple[list[_Issue], int]:
        rules = PATTERN_RULES_BY_LANGUAGE.get(language, [])
        if not rules:
            return [], 0
        issues: list[_Issue] = []
        suppressed = 0
        for index, line in enumerate(lines):
            if len(line) > MAX_LINE_LENGTH:
                continue
            for rule in rules:
                if rule.pattern is None or not rule.pattern.search(line):
                    continue
                # The negative pattern is checked against the matched line only.
                # A sanitiser called on a different line does not protect this
                # one, and widening the window to catch that case suppressed the
                # genuine findings sitting next to a safe example. A regular
                # expression cannot follow the value, so these rules declare low
                # confidence and the finding says the result needs confirming in
                # context — that is the honest trade rather than silently
                # dropping real findings.
                if rule.negative_pattern is not None and rule.negative_pattern.search(line):
                    continue
                if is_suppressed(line, rule.rule_id):
                    suppressed += 1
                    continue
                issues.append(
                    _Issue(
                        rule=rule,
                        file_path=relative,
                        line_number=index + 1,
                        end_line=None,
                        line_text=line,
                        symbol=None,
                        detail=rule.description,
                        detection="pattern",
                    )
                )
        return issues, suppressed

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(issue: _Issue, ctx: EngineContext) -> ScanFinding:
        rule = issue.rule
        severity = issue.severity_override or rule.severity
        confidence = issue.confidence_override or rule.confidence

        method_note = (
            "Found by analysing the file's syntax tree, so the construct and its "
            "arguments were identified precisely."
            if issue.detection == "ast"
            else (
                "Found by pattern matching with surrounding-context checks. A regular "
                "expression cannot see scope or data flow, so confirm the finding in "
                "context before acting on it."
            )
        )
        taint_note = (
            " A value reaching this point appears to originate outside the application, "
            "which is what makes the construct reachable rather than merely risky."
            if issue.tainted
            else ""
        )

        return ScanFinding(
            engine="sast",
            rule_id=rule.rule_id,
            category=rule.category,
            title=f"{rule.name} in {Path(issue.file_path).name}",
            description=f"{issue.detail} {method_note}{taint_note}",
            severity=severity,  # type: ignore[arg-type]
            confidence=confidence,  # type: ignore[arg-type]
            cwe=rule.cwe,
            owasp_top10=rule.owasp_top10,
            owasp_asvs=list(rule.owasp_asvs),
            owasp_masvs=list(rule.owasp_masvs),
            impact=rule.description,
            remediation=rule.remediation,
            reproduction=(
                f"Open {issue.file_path} at line {issue.line_number}"
                + (f" in {issue.symbol}" if issue.symbol else "")
                + f" and review the construct flagged by {rule.rule_id}."
            ),
            evidence=Evidence(
                summary=(
                    f"{rule.name} at {issue.file_path}:{issue.line_number} "
                    f"(detected by {issue.detection}"
                    + (", externally-influenced input" if issue.tainted else "")
                    + ")"
                ),
                code_snippet=issue.line_text.strip()[:500],
                artifacts={
                    "detection_method": issue.detection,
                    "tainted_input": issue.tainted,
                    "enclosing_symbol": issue.symbol,
                    "language": rule.languages[0] if rule.languages else None,
                    **issue.evidence_extra,
                },
            ),
            code_location=CodeLocation(
                file_path=issue.file_path,
                start_line=issue.line_number,
                end_line=issue.end_line,
                symbol=issue.symbol,
                snippet=issue.line_text.strip()[:500],
            ),
            target=ctx.target,
            references=list(rule.references)
            or [f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html"],
            raw={"rule_id": rule.rule_id, "detection": issue.detection},
        )
