"""Container image and Dockerfile analysis.

Analyses Dockerfiles, Compose files and image configuration JSON for the
misconfigurations that actually lead to container escapes and lateral movement:
running as root, mounting the Docker socket, privileged mode, dropped isolation
namespaces, secrets baked into layers, and unpinned base images.

Passive: reads files, pulls nothing, needs no test authorization. Analysing a
*registry* image would be an active operation and is deliberately not done
here — the engine works on what is in the repository, which is where the
problem can actually be fixed.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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

DOCKERFILE_NAMES = re.compile(r"(?i)^(?:dockerfile|containerfile)(?:\..+)?$|\.dockerfile$")
COMPOSE_NAMES = re.compile(r"(?i)^(?:docker-)?compose(?:\.[\w.-]+)?\.ya?ml$")

#: Package managers whose cache must be cleaned in the same layer, or it ships
#: in the image.
PACKAGE_MANAGER_CLEANUP: dict[str, str] = {
    "apt-get install": "rm -rf /var/lib/apt/lists/*",
    "apk add": "--no-cache",
    "yum install": "yum clean all",
    "dnf install": "dnf clean all",
    "pip install": "--no-cache-dir",
}

#: Linux capabilities that effectively grant host access.
DANGEROUS_CAPABILITIES: dict[str, str] = {
    "SYS_ADMIN": "Permits mount operations and is close to full root on the host.",
    "SYS_PTRACE": "Permits inspecting and modifying other processes.",
    "SYS_MODULE": "Permits loading kernel modules — a direct path to host compromise.",
    "NET_ADMIN": "Permits reconfiguring host networking.",
    "DAC_READ_SEARCH": "Bypasses file read permission checks (CVE-2014-9322 class).",
    "SYS_RAWIO": "Permits raw I/O port and memory access.",
    "BPF": "Permits loading BPF programs.",
    "ALL": "Grants every capability, which is equivalent to privileged mode.",
}


@dataclass(slots=True)
class _Issue:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe: str
    remediation: str
    file_path: str
    line_number: int | None = None
    snippet: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    discriminator: str | None = None


@register_engine
class ContainerEngine(SecurityEngine):
    """Dockerfile, Compose and image-configuration analysis."""

    metadata = EngineMetadata(
        key="container",
        name="Container Security",
        description=(
            "Analyses Dockerfiles, Compose files and image configuration for root "
            "execution, privilege escalation paths, Docker socket exposure, secrets "
            "baked into layers and unpinned base images."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository", "image"),
        capabilities=frozenset({EngineCapability.FILESYSTEM}),
        categories=("container_security", "security_misconfiguration", "exposed_secret"),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        if not await asyncio.to_thread(Path(ctx.target.value).exists):
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        await ctx.report_progress(5, "locating container definitions")
        targets = await asyncio.to_thread(self._collect, root)

        if not targets:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No Dockerfile, Compose file or image configuration was found under "
                    f"{root}. Nothing was analysed, so this result says nothing about "
                    "container security."
                ),
                stats={"definitions_found": 0},
            )

        issues: list[_Issue] = []
        unreadable: list[str] = []
        counts = {"dockerfile": 0, "compose": 0, "image_config": 0}

        for index, (path, relative, kind) in enumerate(targets, start=1):
            try:
                raw = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
            except OSError as exc:
                unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue
            counts[kind] += 1
            if kind == "dockerfile":
                issues.extend(self._analyze_dockerfile(raw, relative))
            elif kind == "compose":
                issues.extend(self._analyze_compose(raw, relative))
            else:
                issues.extend(self._analyze_image_config(raw, relative))
            await ctx.report_progress(
                min(95, int(100 * index / len(targets))),
                f"analysed {index}/{len(targets)} definition(s)",
            )

        findings = [self._to_finding(i, ctx) for i in issues]
        stats: dict[str, Any] = {
            "definitions_found": len(targets),
            **{f"{k}_count": v for k, v in counts.items()},
            "unreadable_files": len(unreadable),
            "issues": len(issues),
        }
        warnings = (
            [f"{len(unreadable)} file(s) could not be read: " + "; ".join(unreadable[:5])]
            if unreadable
            else []
        )
        if unreadable:
            return EngineResult.degraded(
                self.key,
                findings,
                reason="Coverage is incomplete: " + warnings[0],
                stats=stats,
                items_examined=sum(counts.values()),
                warnings=warnings,
            )
        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=sum(counts.values()),
            checks_executed=sum(counts.values()) * 14,
        )

    # ------------------------------------------------------------ collection
    @staticmethod
    def _collect(root: Path) -> list[tuple[Path, str, str]]:
        if root.is_file():
            kind = (
                "dockerfile"
                if DOCKERFILE_NAMES.match(root.name)
                else "compose"
                if COMPOSE_NAMES.match(root.name)
                else "image_config"
            )
            return [(root, root.name, kind)]
        found: list[tuple[Path, str, str]] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                path = Path(dirpath) / name
                try:
                    relative = str(path.relative_to(root))
                except ValueError:
                    relative = name
                if DOCKERFILE_NAMES.match(name):
                    found.append((path, relative, "dockerfile"))
                elif COMPOSE_NAMES.match(name):
                    found.append((path, relative, "compose"))
        return found

    # ------------------------------------------------------------ dockerfile
    def _analyze_dockerfile(self, raw: str, relative: str) -> list[_Issue]:
        issues: list[_Issue] = []
        lines = raw.splitlines()

        # Join continuation lines so a multi-line RUN is analysed as one command.
        logical: list[tuple[int, str]] = []
        buffer = ""
        start_line = 1
        for number, line in enumerate(lines, start=1):
            stripped = line.rstrip()
            if not buffer:
                start_line = number
            if stripped.endswith("\\"):
                buffer += stripped[:-1] + " "
                continue
            logical.append((start_line, (buffer + stripped).strip()))
            buffer = ""
        if buffer:
            logical.append((start_line, buffer.strip()))

        last_user: str | None = None
        user_line: int | None = None
        has_healthcheck = False
        stages: list[str] = []

        for number, instruction in logical:
            if not instruction or instruction.startswith("#"):
                continue
            verb, _, remainder = instruction.partition(" ")
            verb = verb.upper()
            remainder = remainder.strip()

            if verb == "FROM":
                stages.append(remainder)
                issues.extend(self._check_base_image(remainder, relative, number))
            elif verb == "USER":
                last_user = remainder.split()[0] if remainder else None
                user_line = number
            elif verb == "HEALTHCHECK":
                has_healthcheck = True
            elif verb == "RUN":
                issues.extend(self._check_run(remainder, relative, number))
            elif verb in ("ENV", "ARG"):
                issues.extend(self._check_env(verb, remainder, relative, number))
            elif verb == "ADD":
                issues.extend(self._check_add(remainder, relative, number))
            elif verb == "EXPOSE":
                issues.extend(self._check_expose(remainder, relative, number))
            elif verb == "COPY":
                issues.extend(self._check_copy(remainder, relative, number))

        # A missing or root USER in the final stage means the container runs as
        # root, which turns any in-container code execution into root access to
        # the container's filesystem and whatever is mounted into it.
        if last_user is None or last_user in ("root", "0"):
            issues.append(
                _Issue(
                    rule_id="container.runs-as-root",
                    title="Container runs as root",
                    description=(
                        "The image does not switch to an unprivileged user before its "
                        "entrypoint"
                        + (
                            f" (USER is set to {last_user!r} on line {user_line})."
                            if last_user
                            else ", so it inherits root from the base image."
                        )
                        + " Any code execution inside the container is then root inside "
                        "the container, which widens a web-application flaw into full "
                        "control of the container's filesystem and any mounted volume."
                    ),
                    severity="high",
                    confidence="high",
                    category="container_security",
                    cwe="CWE-250",
                    remediation=(
                        "Create a non-root user in the image and add `USER <name>` before "
                        "the entrypoint. Where the process must bind a privileged port, "
                        "prefer a high port plus a service mapping over running as root."
                    ),
                    file_path=relative,
                    line_number=user_line,
                    artifacts={"declared_user": last_user, "stages": len(stages)},
                    discriminator="runs-as-root",
                )
            )

        if not has_healthcheck:
            issues.append(
                _Issue(
                    rule_id="container.no-healthcheck",
                    title="No HEALTHCHECK defined",
                    description=(
                        "Without a health check the orchestrator cannot distinguish a "
                        "running container from a working one, so a compromised or hung "
                        "process keeps receiving traffic."
                    ),
                    severity="low",
                    confidence="high",
                    category="security_misconfiguration",
                    cwe="CWE-1059",
                    remediation="Add a HEALTHCHECK, or define a readiness probe in the "
                    "orchestrator.",
                    file_path=relative,
                    discriminator="no-healthcheck",
                )
            )
        return issues

    @staticmethod
    def _check_base_image(reference: str, relative: str, number: int) -> list[_Issue]:
        issues: list[_Issue] = []
        image = reference.split(" AS ")[0].split(" as ")[0].strip()
        if not image or image.startswith("$"):
            return issues

        if "@sha256:" in image:
            return issues  # pinned by digest: reproducible and tamper-evident

        tag = image.rpartition(":")[2] if ":" in image.rpartition("/")[2] else ""
        if not tag or tag == "latest":
            issues.append(
                _Issue(
                    rule_id="container.unpinned-base-image",
                    title=f"Base image {image} is not pinned",
                    description=(
                        f"The base image {image!r} uses "
                        + ("the `latest` tag" if tag == "latest" else "no tag")
                        + ", so the contents of a build are not reproducible and a "
                        "rebuild can silently pull different — possibly compromised — "
                        "code. A digest pin is also what makes a supply-chain "
                        "substitution detectable."
                    ),
                    severity="medium",
                    confidence="high",
                    category="supply_chain",
                    cwe="CWE-1104",
                    remediation=(
                        "Pin by digest (`image@sha256:...`) so the exact bytes are fixed, "
                        "and update it deliberately through a dependency process."
                    ),
                    file_path=relative,
                    line_number=number,
                    snippet=f"FROM {reference}",
                    artifacts={"image": image, "tag": tag or None},
                    discriminator=f"unpinned:{image}",
                )
            )
        return issues

    @staticmethod
    def _check_run(command: str, relative: str, number: int) -> list[_Issue]:
        issues: list[_Issue] = []
        lowered = command.lower()

        if re.search(r"curl[^|]*\|\s*(?:ba)?sh|wget[^|]*\|\s*(?:ba)?sh", lowered):
            issues.append(
                _Issue(
                    rule_id="container.curl-pipe-shell",
                    title="Remote script piped to a shell during build",
                    description=(
                        "The build downloads a script and executes it immediately. "
                        "Whatever the server returns at build time runs with build "
                        "privileges, and nothing verifies that it is what was expected."
                    ),
                    severity="high",
                    confidence="high",
                    category="supply_chain",
                    cwe="CWE-494",
                    remediation=(
                        "Download to a file, verify a published checksum or signature, "
                        "then execute. Better still, install from a package repository "
                        "with signature verification."
                    ),
                    file_path=relative,
                    line_number=number,
                    snippet=command[:300],
                    discriminator="curl-pipe-shell",
                )
            )

        if re.search(r"\b(?:--no-check-certificate|--insecure|-k\b|verify=False)", command):
            issues.append(
                _Issue(
                    rule_id="container.build-tls-disabled",
                    title="TLS verification disabled during build",
                    description=(
                        "A build step disables certificate verification, so the "
                        "downloaded artifact is unauthenticated and can be substituted "
                        "by anyone on the network path."
                    ),
                    severity="high",
                    confidence="high",
                    category="supply_chain",
                    cwe="CWE-295",
                    remediation="Keep verification on and add the internal CA to the "
                    "build image if needed.",
                    file_path=relative,
                    line_number=number,
                    snippet=command[:300],
                    discriminator="build-tls-disabled",
                )
            )

        if re.search(r"\bsudo\b|\bchmod\s+(?:-R\s+)?0?777\b", command):
            issues.append(
                _Issue(
                    rule_id="container.overly-permissive-build",
                    title="Overly permissive build step",
                    description=(
                        "The build uses sudo or sets world-writable permissions. "
                        "World-writable paths let any process in the container modify "
                        "them, which turns a low-privilege foothold into persistence."
                    ),
                    severity="medium",
                    confidence="medium",
                    category="container_security",
                    cwe="CWE-732",
                    remediation="Set the narrowest permissions that work, and avoid sudo "
                    "in an image that already builds as root.",
                    file_path=relative,
                    line_number=number,
                    snippet=command[:300],
                    discriminator="permissive-build",
                )
            )

        for install, cleanup in PACKAGE_MANAGER_CLEANUP.items():
            if install in lowered and cleanup.lower() not in lowered:
                issues.append(
                    _Issue(
                        rule_id="container.package-cache-retained",
                        title=f"Package cache retained after `{install}`",
                        description=(
                            f"`{install}` is used without `{cleanup}` in the same layer, "
                            "so the package index and cached archives ship inside the "
                            "image. Beyond size, that leaves package metadata and "
                            "sometimes credentials from private repositories in a layer."
                        ),
                        severity="low",
                        confidence="medium",
                        category="container_security",
                        cwe="CWE-1104",
                        remediation=f"Add `{cleanup}` to the same RUN instruction.",
                        file_path=relative,
                        line_number=number,
                        snippet=command[:300],
                        discriminator=f"cache:{install}",
                    )
                )
        return issues

    @staticmethod
    def _check_env(verb: str, remainder: str, relative: str, number: int) -> list[_Issue]:
        # A value set with ENV or ARG is recorded in the image's layer history
        # and visible to anyone who can pull it, so `docker history` discloses it
        # even if a later layer unsets the variable.
        secretish = re.compile(
            r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|"
            r"PRIVATE_KEY|CREDENTIAL|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(\S+)"
        )
        issues: list[_Issue] = []
        for match in secretish.finditer(remainder):
            name, value = match.group(1), match.group(2).strip("\"'")
            if not value or value.startswith("$") or len(value) < 6:
                continue
            issues.append(
                _Issue(
                    rule_id="container.secret-in-image-layer",
                    title=f"Credential-named {verb} value baked into the image",
                    description=(
                        f"{verb} sets {name} to a literal value. Values set this way are "
                        "recorded in the image's layer history and are readable with "
                        "`docker history` by anyone who can pull the image — including "
                        "after a later layer unsets the variable."
                    ),
                    severity="high",
                    confidence="medium",
                    category="exposed_secret",
                    cwe="CWE-522",
                    remediation=(
                        "Inject the value at run time from a secrets manager or an "
                        "orchestrator secret. For build-time credentials use BuildKit "
                        "secret mounts, which are not persisted into a layer."
                    ),
                    file_path=relative,
                    line_number=number,
                    snippet=f"{verb} {name}=«redacted»",
                    artifacts={"variable": name, "instruction": verb},
                    discriminator=f"layer-secret:{name}",
                )
            )
        return issues

    @staticmethod
    def _check_add(remainder: str, relative: str, number: int) -> list[_Issue]:
        if re.match(r"(?i)^(?:--\S+\s+)*(?:https?|git)://", remainder):
            return [
                _Issue(
                    rule_id="container.add-remote-url",
                    title="ADD used to fetch a remote URL",
                    description=(
                        "ADD with a URL downloads over the network during build without "
                        "verifying a checksum, and it auto-extracts archives — which has "
                        "its own path-traversal history. The fetched content is "
                        "unauthenticated."
                    ),
                    severity="medium",
                    confidence="high",
                    category="supply_chain",
                    cwe="CWE-494",
                    remediation=(
                        "Use RUN with an explicit download, checksum verification and "
                        "extraction, or COPY a vendored artifact."
                    ),
                    file_path=relative,
                    line_number=number,
                    snippet=f"ADD {remainder[:200]}",
                    discriminator="add-remote",
                )
            ]
        return []

    @staticmethod
    def _check_expose(remainder: str, relative: str, number: int) -> list[_Issue]:
        issues: list[_Issue] = []
        sensitive = {
            "22": "SSH",
            "23": "telnet",
            "3306": "MySQL",
            "5432": "PostgreSQL",
            "6379": "Redis",
            "27017": "MongoDB",
            "9200": "Elasticsearch",
            "2375": "the Docker daemon API, unauthenticated",
            "2376": "the Docker daemon API",
            "5984": "CouchDB",
            "11211": "memcached",
            "9000": "an admin interface",
        }
        for token in remainder.split():
            port = token.split("/")[0]
            if port in sensitive:
                issues.append(
                    _Issue(
                        rule_id="container.sensitive-port-exposed",
                        title=f"Sensitive port {port} exposed",
                        description=(
                            f"Port {port} ({sensitive[port]}) is declared as exposed. "
                            "Administrative and datastore ports should not be reachable "
                            "from outside the pod or service boundary."
                        ),
                        severity="critical" if port in ("2375", "23") else "medium",
                        confidence="medium",
                        category="network_exposure",
                        cwe="CWE-668",
                        remediation=(
                            "Remove the EXPOSE declaration and reach the service over an "
                            "internal network only. Never expose the Docker daemon API."
                        ),
                        file_path=relative,
                        line_number=number,
                        snippet=f"EXPOSE {remainder[:100]}",
                        artifacts={"port": port, "service": sensitive[port]},
                        discriminator=f"port:{port}",
                    )
                )
        return issues

    @staticmethod
    def _check_copy(remainder: str, relative: str, number: int) -> list[_Issue]:
        # Copying the whole build context pulls in .git, .env and local
        # credentials unless a .dockerignore excludes them.
        tokens = shlex.split(remainder) if remainder else []
        sources = [t for t in tokens if not t.startswith("--")][:-1]
        if any(s in (".", "./") for s in sources):
            return [
                _Issue(
                    rule_id="container.copy-entire-context",
                    title="Entire build context copied into the image",
                    description=(
                        "`COPY . ` copies everything in the build context, which "
                        "routinely includes `.git`, `.env` files and local credentials. "
                        "A `.dockerignore` is the only thing preventing that, and it is "
                        "easy to forget."
                    ),
                    severity="medium",
                    confidence="low",
                    category="exposed_secret",
                    cwe="CWE-527",
                    remediation=(
                        "Copy only what the image needs, and maintain a .dockerignore "
                        "that excludes .git, .env, credentials and build caches."
                    ),
                    file_path=relative,
                    line_number=number,
                    snippet=f"COPY {remainder[:160]}",
                    discriminator="copy-context",
                )
            ]
        return []

    # --------------------------------------------------------------- compose
    def _analyze_compose(self, raw: str, relative: str) -> list[_Issue]:
        issues: list[_Issue] = []
        try:
            document = yaml.safe_load(raw) or {}
        except yaml.YAMLError as exc:
            return [
                _Issue(
                    rule_id="container.compose-unparseable",
                    title="Compose file could not be parsed",
                    description=(
                        f"The Compose file could not be parsed ({exc}), so its service "
                        "definitions were not analysed. This is a coverage gap, not a "
                        "clean result."
                    ),
                    severity="info",
                    confidence="high",
                    category="security_misconfiguration",
                    cwe="CWE-1059",
                    remediation="Fix the YAML so the file can be assessed.",
                    file_path=relative,
                    discriminator="compose-unparseable",
                )
            ]
        if not isinstance(document, dict):
            return issues

        for name, service in (document.get("services") or {}).items():
            if not isinstance(service, dict):
                continue
            issues.extend(self._check_service(name, service, relative))
        return issues

    @staticmethod
    def _check_service(name: str, service: dict[str, Any], relative: str) -> list[_Issue]:
        issues: list[_Issue] = []

        if service.get("privileged") is True:
            issues.append(
                _Issue(
                    rule_id="container.privileged-mode",
                    title=f"Service {name!r} runs privileged",
                    description=(
                        f"`privileged: true` on service {name!r} disables almost every "
                        "container isolation mechanism: the container gets all "
                        "capabilities and access to host devices. Code execution in it "
                        "is effectively code execution on the host."
                    ),
                    severity="critical",
                    confidence="high",
                    category="container_security",
                    cwe="CWE-250",
                    remediation=(
                        "Remove privileged mode and grant only the specific capabilities "
                        "the workload needs via `cap_add`."
                    ),
                    file_path=relative,
                    artifacts={"service": name},
                    discriminator=f"privileged:{name}",
                )
            )

        volumes = service.get("volumes") or []
        for volume in volumes:
            text = volume if isinstance(volume, str) else str(volume.get("source", ""))
            if "/var/run/docker.sock" in text:
                issues.append(
                    _Issue(
                        rule_id="container.docker-socket-mounted",
                        title=f"Docker socket mounted into {name!r}",
                        description=(
                            "The Docker socket is mounted into the container. Anything "
                            "that can write to it can start a new privileged container "
                            "mounting the host filesystem, so this is equivalent to "
                            "giving the container root on the host."
                        ),
                        severity="critical",
                        confidence="high",
                        category="container_security",
                        cwe="CWE-250",
                        remediation=(
                            "Remove the mount. Where Docker access is genuinely required, "
                            "use a socket proxy restricted to the specific API calls "
                            "needed, or a rootless daemon."
                        ),
                        file_path=relative,
                        artifacts={"service": name, "mount": text},
                        discriminator=f"docker-socket:{name}",
                    )
                )
            elif re.match(r"^/(?:etc|proc|sys|boot|root|var/lib)(?:/|:)", text):
                issues.append(
                    _Issue(
                        rule_id="container.sensitive-host-path-mounted",
                        title=f"Sensitive host path mounted into {name!r}",
                        description=(
                            f"The host path in {text!r} is mounted into the container. "
                            "Mounting /etc, /proc, /sys or /root exposes host "
                            "configuration and credentials, and a writable mount permits "
                            "host modification."
                        ),
                        severity="high",
                        confidence="medium",
                        category="container_security",
                        cwe="CWE-668",
                        remediation=(
                            "Mount only the specific files required, read-only, or pass "
                            "the data in by another route."
                        ),
                        file_path=relative,
                        artifacts={"service": name, "mount": text},
                        discriminator=f"host-mount:{name}:{text}",
                    )
                )

        for capability in service.get("cap_add") or []:
            key = str(capability).upper().removeprefix("CAP_")
            if key in DANGEROUS_CAPABILITIES:
                issues.append(
                    _Issue(
                        rule_id="container.dangerous-capability",
                        title=f"Capability {key} granted to {name!r}",
                        description=(
                            f"{key} is added to service {name!r}. {DANGEROUS_CAPABILITIES[key]}"
                        ),
                        severity="high" if key != "ALL" else "critical",
                        confidence="high",
                        category="container_security",
                        cwe="CWE-250",
                        remediation=(
                            "Remove the capability. If the workload truly needs it, "
                            "isolate that workload and document the exception."
                        ),
                        file_path=relative,
                        artifacts={"service": name, "capability": key},
                        discriminator=f"capability:{name}:{key}",
                    )
                )

        for namespace, label in (
            ("network_mode", "host networking"),
            ("pid", "the host PID namespace"),
            ("ipc", "the host IPC namespace"),
        ):
            if str(service.get(namespace, "")).lower() == "host":
                issues.append(
                    _Issue(
                        rule_id=f"container.host-{namespace}",
                        title=f"Service {name!r} shares {label}",
                        description=(
                            f"Service {name!r} uses {label}, which removes that isolation "
                            "boundary. With host networking the container reaches every "
                            "service bound to the host, including ones that assume "
                            "localhost means trusted."
                        ),
                        severity="high",
                        confidence="high",
                        category="container_security",
                        cwe="CWE-668",
                        remediation=f"Remove the host {namespace} setting and use a "
                        "dedicated namespace.",
                        file_path=relative,
                        artifacts={"service": name, "setting": namespace},
                        discriminator=f"host-ns:{name}:{namespace}",
                    )
                )

        environment = service.get("environment")
        pairs: list[str] = []
        if isinstance(environment, dict):
            pairs = [f"{k}={v}" for k, v in environment.items()]
        elif isinstance(environment, list):
            pairs = [str(e) for e in environment]
        for pair in pairs:
            match = re.match(
                r"(?i)^([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)[A-Z0-9_]*)=(.+)$",
                pair,
            )
            if match and not match.group(2).startswith("$"):
                issues.append(
                    _Issue(
                        rule_id="container.secret-in-compose",
                        title=f"Credential literal in {name!r} environment",
                        description=(
                            f"{match.group(1)} is set to a literal value in the Compose "
                            "file, so the credential is committed to the repository and "
                            "visible to every process that can read the container's "
                            "environment."
                        ),
                        severity="high",
                        confidence="medium",
                        category="exposed_secret",
                        cwe="CWE-798",
                        remediation=(
                            "Reference an environment variable or a Compose secret "
                            "instead of a literal, and rotate the committed value."
                        ),
                        file_path=relative,
                        snippet=f"{match.group(1)}=«redacted»",
                        artifacts={"service": name, "variable": match.group(1)},
                        discriminator=f"compose-secret:{name}:{match.group(1)}",
                    )
                )

        if service.get("read_only") is not True and not service.get("privileged"):
            issues.append(
                _Issue(
                    rule_id="container.writable-root-filesystem",
                    title=f"Service {name!r} has a writable root filesystem",
                    description=(
                        "The container's root filesystem is writable, so an attacker who "
                        "achieves code execution can drop tools and establish "
                        "persistence inside the image."
                    ),
                    severity="low",
                    confidence="medium",
                    category="container_security",
                    cwe="CWE-732",
                    remediation=(
                        "Set `read_only: true` and mount a tmpfs for the specific paths "
                        "the application must write."
                    ),
                    file_path=relative,
                    artifacts={"service": name},
                    discriminator=f"writable-root:{name}",
                )
            )
        return issues

    # --------------------------------------------------------- image config
    def _analyze_image_config(self, raw: str, relative: str) -> list[_Issue]:
        try:
            config = json.loads(raw)
        except ValueError:
            return []
        issues: list[_Issue] = []
        container_config = (
            config.get("config") or config.get("Config") or config.get("container_config") or {}
        )
        user = str(container_config.get("User") or "").strip()
        if not user or user in ("root", "0", "0:0"):
            issues.append(
                _Issue(
                    rule_id="container.runs-as-root",
                    title="Image configuration runs as root",
                    description=(
                        "The image configuration declares no unprivileged user, so the "
                        "entrypoint runs as root."
                    ),
                    severity="high",
                    confidence="high",
                    category="container_security",
                    cwe="CWE-250",
                    remediation="Rebuild the image with a non-root USER.",
                    file_path=relative,
                    artifacts={"declared_user": user or None},
                    discriminator="runs-as-root",
                )
            )
        for variable in container_config.get("Env") or []:
            if re.match(
                r"(?i)^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)[A-Z0-9_]*=.+",
                str(variable),
            ):
                name = str(variable).split("=", 1)[0]
                issues.append(
                    _Issue(
                        rule_id="container.secret-in-image-layer",
                        title=f"Credential-named variable {name} in image configuration",
                        description=(
                            f"{name} carries a value in the image's own configuration, so "
                            "anyone able to pull the image can read it."
                        ),
                        severity="high",
                        confidence="medium",
                        category="exposed_secret",
                        cwe="CWE-522",
                        remediation="Rebuild without the value and inject it at run time.",
                        file_path=relative,
                        artifacts={"variable": name},
                        discriminator=f"layer-secret:{name}",
                    )
                )
        return issues

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(issue: _Issue, ctx: EngineContext) -> ScanFinding:
        return ScanFinding(
            engine="container",
            rule_id=issue.rule_id,
            category=issue.category,
            title=issue.title,
            description=issue.description,
            severity=issue.severity,
            confidence=issue.confidence,
            cwe=issue.cwe,
            owasp_top10="A05:2021",
            remediation=issue.remediation,
            reproduction=(
                f"Review {issue.file_path}"
                + (f" at line {issue.line_number}" if issue.line_number else "")
                + f" against rule {issue.rule_id}."
            ),
            evidence=Evidence(
                summary=f"{issue.title} in {issue.file_path}",
                code_snippet=issue.snippet,
                artifacts=issue.artifacts,
            ),
            code_location=CodeLocation(
                file_path=issue.file_path,
                start_line=issue.line_number,
                snippet=issue.snippet,
            ),
            correlation_discriminator=issue.discriminator,
            target=ctx.target,
            references=[
                "https://docs.docker.com/develop/security-best-practices/",
                f"https://cwe.mitre.org/data/definitions/{issue.cwe.split('-')[-1]}.html",
            ],
            raw={"rule_id": issue.rule_id, **issue.artifacts},
        )
