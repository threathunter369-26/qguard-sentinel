"""Kubernetes manifest analysis.

Evaluates workload, RBAC and network-policy manifests against the Pod Security
Standards and the RBAC patterns that actually enable cluster takeover.

Pod security and RBAC are treated as equally important, because in practice the
cluster compromises that matter come from an over-broad Role far more often
than from a container setting — a ServiceAccount with ``secrets: list`` at
cluster scope can read every credential in the cluster, and that is a one-line
manifest change nobody reviews.

Passive: reads manifests, contacts no cluster, needs no test authorization.
"""

from __future__ import annotations

import asyncio
import os
import re
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

WORKLOAD_KINDS: frozenset[str] = frozenset(
    {
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
        "ReplicationController",
    }
)
RBAC_KINDS: frozenset[str] = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})

#: Verbs that permit modification or disclosure.
WRITE_VERBS: frozenset[str] = frozenset(
    {"create", "update", "patch", "delete", "deletecollection", "*"}
)
READ_VERBS: frozenset[str] = frozenset({"get", "list", "watch", "*"})

#: Resources whose disclosure or modification escalates privilege.
SENSITIVE_RESOURCES: dict[str, str] = {
    "secrets": "Reading secrets discloses every credential stored in scope.",
    "serviceaccounts/token": "Minting a ServiceAccount token impersonates that account.",
    "pods/exec": "Executing in a pod gives code execution with that pod's identity.",
    "pods/attach": "Attaching to a pod gives access to its process.",
    "pods/portforward": "Port-forwarding reaches services that are otherwise unreachable.",
    "nodes/proxy": "Proxying to the kubelet permits running commands on the node.",
    "clusterrolebindings": "Creating a binding grants any role to any subject.",
    "rolebindings": "Creating a binding grants roles within the namespace.",
    "clusterroles": "Creating a role defines new permissions.",
    "validatingwebhookconfigurations": "A webhook can intercept and alter any API request.",
    "mutatingwebhookconfigurations": "A mutating webhook can inject into any workload.",
    "persistentvolumes": "A hostPath volume reaches the node filesystem.",
    "certificatesigningrequests/approval": "Approving a CSR issues a cluster credential.",
}

DANGEROUS_CAPABILITIES: dict[str, str] = {
    "SYS_ADMIN": "Close to full root on the node.",
    "SYS_MODULE": "Loading a kernel module compromises the node.",
    "SYS_PTRACE": "Inspecting other processes, including on the host PID namespace.",
    "NET_ADMIN": "Reconfiguring node networking.",
    "NET_RAW": "Raw sockets enable ARP and DNS spoofing on the pod network.",
    "DAC_READ_SEARCH": "Bypasses file read permissions.",
    "SYS_RAWIO": "Raw device access.",
    "ALL": "Every capability — equivalent to privileged.",
}

SENSITIVE_HOST_PATHS = re.compile(
    r"^/(?:$|etc|var/run|var/lib|proc|sys|root|boot|dev|home|usr/bin|usr/sbin)"
)


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
    resource: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    discriminator: str | None = None


@register_engine
class KubernetesEngine(SecurityEngine):
    """Pod security, RBAC and network policy analysis."""

    metadata = EngineMetadata(
        key="kubernetes",
        name="Kubernetes Security",
        description=(
            "Evaluates Kubernetes manifests against the Pod Security Standards and "
            "analyses RBAC for the over-broad grants that enable cluster takeover, "
            "plus service exposure and network policy coverage."
        ),
        version="1.0.0",
        target_kinds=("directory", "file", "repository", "kubernetes_manifest"),
        capabilities=frozenset({EngineCapability.FILESYSTEM}),
        categories=(
            "kubernetes_security",
            "broken_access_control",
            "security_misconfiguration",
            "network_exposure",
            "exposed_secret",
        ),
    )

    async def preflight(self, ctx: EngineContext) -> str | None:
        if not await asyncio.to_thread(Path(ctx.target.value).exists):
            return f"The path {ctx.target.value!r} does not exist or is not readable."
        return None

    async def analyze(self, ctx: EngineContext) -> EngineResult:
        root = await asyncio.to_thread(lambda: Path(ctx.target.value).resolve())
        await ctx.report_progress(5, "locating Kubernetes manifests")
        candidates = await asyncio.to_thread(self._collect, root)

        if not candidates:
            return EngineResult.degraded(
                self.key,
                [],
                reason=(
                    f"No YAML manifests were found under {root}, so nothing was "
                    "analysed. This result says nothing about the cluster's security."
                ),
                stats={"files_found": 0},
            )

        issues: list[_Issue] = []
        parse_failures: list[str] = []
        unreadable: list[str] = []
        kinds: dict[str, int] = {}
        documents_examined = 0
        workloads_seen = 0
        namespaces_with_policy: set[str] = set()
        namespaces_with_workload: set[str] = set()

        for index, (path, relative) in enumerate(candidates, start=1):
            try:
                raw = await asyncio.to_thread(path.read_text, encoding="utf-8", errors="replace")
            except OSError as exc:
                unreadable.append(f"{relative}: {exc.strerror or exc}")
                continue
            try:
                documents = list(yaml.safe_load_all(raw))
            except yaml.YAMLError as exc:
                parse_failures.append(f"{relative}: {exc}")
                continue

            for document in documents:
                if not isinstance(document, dict) or "kind" not in document:
                    continue
                documents_examined += 1
                kind = str(document.get("kind"))
                kinds[kind] = kinds.get(kind, 0) + 1
                namespace = (document.get("metadata") or {}).get("namespace") or "default"

                if kind in WORKLOAD_KINDS:
                    workloads_seen += 1
                    namespaces_with_workload.add(namespace)
                    issues.extend(self._check_workload(document, relative))
                elif kind in RBAC_KINDS:
                    issues.extend(self._check_rbac(document, relative))
                elif kind == "Service":
                    issues.extend(self._check_service(document, relative))
                elif kind == "NetworkPolicy":
                    namespaces_with_policy.add(namespace)
                elif kind == "Secret":
                    issues.extend(self._check_secret(document, relative))
                elif kind == "Ingress":
                    issues.extend(self._check_ingress(document, relative))

            await ctx.report_progress(
                min(92, int(100 * index / len(candidates))),
                f"analysed {index}/{len(candidates)} file(s), {documents_examined} manifest(s)",
            )

        # A namespace running workloads with no NetworkPolicy allows every pod
        # to reach every other pod, which is what turns one compromised pod into
        # lateral movement across the cluster.
        for namespace in sorted(namespaces_with_workload - namespaces_with_policy):
            issues.append(
                _Issue(
                    rule_id="k8s.no-network-policy",
                    title=f"Namespace {namespace!r} has no NetworkPolicy",
                    description=(
                        f"Workloads were found in namespace {namespace!r} but no "
                        "NetworkPolicy selects them. Kubernetes defaults to allowing all "
                        "pod-to-pod traffic, so one compromised pod can reach every "
                        "other service in the namespace — and usually the cluster."
                    ),
                    severity="medium",
                    confidence="medium",
                    category="network_exposure",
                    cwe="CWE-923",
                    remediation=(
                        "Apply a default-deny NetworkPolicy for the namespace, then add "
                        "explicit allow rules for the traffic each workload needs."
                    ),
                    file_path="(namespace-wide)",
                    resource=f"Namespace/{namespace}",
                    artifacts={"namespace": namespace},
                    discriminator=f"no-netpol:{namespace}",
                )
            )

        findings = [self._to_finding(i, ctx) for i in issues]
        stats: dict[str, Any] = {
            "files_found": len(candidates),
            "documents_examined": documents_examined,
            "kinds": kinds,
            "workloads": workloads_seen,
            "namespaces_with_workloads": sorted(namespaces_with_workload),
            "namespaces_with_network_policy": sorted(namespaces_with_policy),
            "parse_failures": len(parse_failures),
            "unreadable_files": len(unreadable),
        }
        warnings: list[str] = []
        if parse_failures:
            warnings.append(
                f"{len(parse_failures)} file(s) could not be parsed as YAML: "
                + "; ".join(parse_failures[:5])
            )
        if unreadable:
            warnings.append(
                f"{len(unreadable)} file(s) could not be read: " + "; ".join(unreadable[:5])
            )

        if documents_examined == 0:
            return EngineResult.degraded(
                self.key,
                findings,
                reason=(
                    f"{len(candidates)} YAML file(s) were read but none contained a "
                    "Kubernetes manifest, so nothing was assessed."
                ),
                stats=stats,
                warnings=warnings,
            )
        if warnings:
            return EngineResult.degraded(
                self.key,
                findings,
                reason="Coverage is incomplete: " + " ".join(warnings),
                stats=stats,
                items_examined=documents_examined,
                warnings=warnings,
            )
        return EngineResult.completed(
            self.key,
            findings,
            stats=stats,
            items_examined=documents_examined,
            checks_executed=documents_examined * 18,
        )

    # ------------------------------------------------------------ collection
    @staticmethod
    def _collect(root: Path) -> list[tuple[Path, str]]:
        if root.is_file():
            return [(root, root.name)]
        found: list[tuple[Path, str]] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
            for name in filenames:
                if not name.lower().endswith((".yaml", ".yml")):
                    continue
                path = Path(dirpath) / name
                try:
                    found.append((path, str(path.relative_to(root))))
                except ValueError:
                    found.append((path, name))
        return found

    # -------------------------------------------------------------- workloads
    def _check_workload(self, document: dict[str, Any], relative: str) -> list[_Issue]:
        kind = str(document.get("kind"))
        name = (document.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (document.get("metadata") or {}).get("namespace", "default")
        resource = f"{kind}/{namespace}/{name}"

        spec = self._pod_spec(document)
        if spec is None:
            return []

        issues: list[_Issue] = []
        pod_security = spec.get("securityContext") or {}

        for namespace_field, label in (
            ("hostNetwork", "the node's network namespace"),
            ("hostPID", "the node's PID namespace"),
            ("hostIPC", "the node's IPC namespace"),
        ):
            if spec.get(namespace_field) is True:
                issues.append(
                    _Issue(
                        rule_id=f"k8s.{namespace_field.lower()}",
                        title=f"{resource} shares {label}",
                        description=(
                            f"{namespace_field} is enabled, so the pod shares {label} "
                            "with the node. With hostNetwork the pod reaches every "
                            "service bound on the node — including ones that treat "
                            "localhost as trusted — and NetworkPolicies no longer apply "
                            "to it."
                        ),
                        severity="high",
                        confidence="high",
                        category="kubernetes_security",
                        cwe="CWE-668",
                        remediation=f"Remove {namespace_field} and use the pod network.",
                        file_path=relative,
                        resource=resource,
                        artifacts={"setting": namespace_field},
                        discriminator=f"{namespace_field}:{resource}",
                    )
                )

        if spec.get("automountServiceAccountToken") is not False:
            issues.append(
                _Issue(
                    rule_id="k8s.automount-service-account-token",
                    title=f"{resource} automounts its ServiceAccount token",
                    description=(
                        "The ServiceAccount token is mounted into the pod even though "
                        "most workloads never call the Kubernetes API. Any code "
                        "execution in the pod then gets a cluster credential for free, "
                        "which is the usual first step from application compromise to "
                        "cluster compromise."
                    ),
                    severity="medium",
                    confidence="medium",
                    category="kubernetes_security",
                    cwe="CWE-522",
                    remediation=(
                        "Set `automountServiceAccountToken: false` unless the workload "
                        "genuinely calls the API, and give it a dedicated ServiceAccount "
                        "with minimal RBAC when it does."
                    ),
                    file_path=relative,
                    resource=resource,
                    discriminator=f"automount:{resource}",
                )
            )

        for volume in spec.get("volumes") or []:
            host_path = (volume or {}).get("hostPath") or {}
            path_value = str(host_path.get("path", ""))
            if not path_value:
                continue
            severity = "critical" if path_value in ("/", "/etc", "/var/run") else "high"
            if "/var/run/docker.sock" in path_value or "containerd.sock" in path_value:
                severity = "critical"
            issues.append(
                _Issue(
                    rule_id="k8s.host-path-volume",
                    title=f"{resource} mounts host path {path_value}",
                    description=(
                        f"The pod mounts the node path {path_value!r}. A hostPath volume "
                        "crosses the container boundary: a sensitive path discloses node "
                        "configuration and credentials, and a container-runtime socket "
                        "is equivalent to root on the node."
                    ),
                    severity=severity if SENSITIVE_HOST_PATHS.match(path_value) else "medium",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-668",
                    remediation=(
                        "Remove the hostPath volume. Use a PersistentVolumeClaim, a "
                        "ConfigMap or a projected volume instead. Where a node path is "
                        "unavoidable, mount the narrowest path read-only and restrict the "
                        "workload with a policy."
                    ),
                    file_path=relative,
                    resource=resource,
                    artifacts={"host_path": path_value},
                    discriminator=f"hostpath:{resource}:{path_value}",
                )
            )

        containers = [
            *(spec.get("containers") or []),
            *(spec.get("initContainers") or []),
            *(spec.get("ephemeralContainers") or []),
        ]
        for container in containers:
            issues.extend(self._check_container(container, pod_security, resource, relative))
        return issues

    @staticmethod
    def _pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
        spec = document.get("spec") or {}
        if document.get("kind") == "Pod":
            return spec
        if document.get("kind") == "CronJob":
            spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        template = (spec.get("template") or {}).get("spec")
        return template if isinstance(template, dict) else None

    def _check_container(
        self,
        container: dict[str, Any],
        pod_security: dict[str, Any],
        resource: str,
        relative: str,
    ) -> list[_Issue]:
        issues: list[_Issue] = []
        name = container.get("name", "<unnamed>")
        security = container.get("securityContext") or {}
        label = f"{resource}[{name}]"

        def effective(key: str) -> Any:
            # A container-level setting overrides the pod-level default.
            return security.get(key, pod_security.get(key))

        if security.get("privileged") is True:
            issues.append(
                _Issue(
                    rule_id="k8s.privileged-container",
                    title=f"{label} runs privileged",
                    description=(
                        "privileged: true disables almost every isolation mechanism: the "
                        "container receives all capabilities and access to host devices. "
                        "Code execution in it is effectively code execution on the node."
                    ),
                    severity="critical",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-250",
                    remediation=(
                        "Remove privileged mode and add only the specific capabilities "
                        "the workload needs."
                    ),
                    file_path=relative,
                    resource=label,
                    discriminator=f"privileged:{label}",
                )
            )

        if security.get("allowPrivilegeEscalation") is not False:
            issues.append(
                _Issue(
                    rule_id="k8s.privilege-escalation-allowed",
                    title=f"{label} permits privilege escalation",
                    description=(
                        "allowPrivilegeEscalation is not set to false, so a setuid binary "
                        "inside the container can gain privileges beyond those the "
                        "container started with — defeating a non-root user setting."
                    ),
                    severity="medium",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-250",
                    remediation="Set `allowPrivilegeEscalation: false`.",
                    file_path=relative,
                    resource=label,
                    discriminator=f"privesc:{label}",
                )
            )

        run_as_non_root = effective("runAsNonRoot")
        run_as_user = effective("runAsUser")
        if run_as_non_root is not True and run_as_user in (None, 0):
            issues.append(
                _Issue(
                    rule_id="k8s.runs-as-root",
                    title=f"{label} runs as root",
                    description=(
                        "Neither runAsNonRoot nor a non-zero runAsUser is set, so the "
                        "container runs as root. Combined with a writable filesystem or a "
                        "hostPath mount this is the difference between a contained "
                        "application bug and a node compromise."
                    ),
                    severity="high",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-250",
                    remediation=(
                        "Set `runAsNonRoot: true` and an explicit non-zero `runAsUser`, "
                        "and build the image with a matching user."
                    ),
                    file_path=relative,
                    resource=label,
                    artifacts={"run_as_user": run_as_user},
                    discriminator=f"root:{label}",
                )
            )

        if effective("readOnlyRootFilesystem") is not True:
            issues.append(
                _Issue(
                    rule_id="k8s.writable-root-filesystem",
                    title=f"{label} has a writable root filesystem",
                    description=(
                        "readOnlyRootFilesystem is not enabled, so an attacker with code "
                        "execution can write tools into the container and persist."
                    ),
                    severity="low",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-732",
                    remediation=(
                        "Set `readOnlyRootFilesystem: true` and mount an emptyDir for "
                        "paths the application must write."
                    ),
                    file_path=relative,
                    resource=label,
                    discriminator=f"writable-root:{label}",
                )
            )

        capabilities = security.get("capabilities") or {}
        for capability in capabilities.get("add") or []:
            key = str(capability).upper().removeprefix("CAP_")
            if key in DANGEROUS_CAPABILITIES:
                issues.append(
                    _Issue(
                        rule_id="k8s.dangerous-capability",
                        title=f"{label} is granted {key}",
                        description=(
                            f"The capability {key} is added. {DANGEROUS_CAPABILITIES[key]}"
                        ),
                        severity="critical" if key == "ALL" else "high",
                        confidence="high",
                        category="kubernetes_security",
                        cwe="CWE-250",
                        remediation=(
                            "Remove the capability, and drop ALL then add back only what "
                            "is strictly required."
                        ),
                        file_path=relative,
                        resource=label,
                        artifacts={"capability": key},
                        discriminator=f"cap:{label}:{key}",
                    )
                )
        if "ALL" not in {str(c).upper() for c in (capabilities.get("drop") or [])}:
            issues.append(
                _Issue(
                    rule_id="k8s.capabilities-not-dropped",
                    title=f"{label} does not drop all capabilities",
                    description=(
                        "The container keeps the default capability set, which includes "
                        "NET_RAW — enough to spoof ARP and DNS on the pod network and "
                        "intercept other pods' traffic."
                    ),
                    severity="medium",
                    confidence="high",
                    category="kubernetes_security",
                    cwe="CWE-250",
                    remediation='Set `capabilities.drop: ["ALL"]` and add back only '
                    "what is required.",
                    file_path=relative,
                    resource=label,
                    discriminator=f"caps-not-dropped:{label}",
                )
            )

        resources = container.get("resources") or {}
        if not (resources.get("limits") or {}).get("memory"):
            issues.append(
                _Issue(
                    rule_id="k8s.no-resource-limits",
                    title=f"{label} has no memory limit",
                    description=(
                        "Without a memory limit one workload can consume the node's "
                        "memory and evict its neighbours, which makes a single "
                        "application bug a cluster-wide availability incident."
                    ),
                    severity="low",
                    confidence="high",
                    category="denial_of_service_risk",
                    cwe="CWE-770",
                    remediation="Set memory and CPU requests and limits for every container.",
                    file_path=relative,
                    resource=label,
                    discriminator=f"no-limits:{label}",
                )
            )

        image = str(container.get("image", ""))
        if (
            image
            and "@sha256:" not in image
            and (image.endswith(":latest") or ":" not in image.rpartition("/")[2])
        ):
            issues.append(
                _Issue(
                    rule_id="k8s.unpinned-image",
                    title=f"{label} uses an unpinned image",
                    description=(
                        f"The image {image!r} is not pinned to a digest, so what runs is "
                        "whatever the registry serves at pull time. That is both "
                        "non-reproducible and a supply-chain substitution risk."
                    ),
                    severity="medium",
                    confidence="high",
                    category="supply_chain",
                    cwe="CWE-1104",
                    remediation="Pin the image by digest and update it deliberately.",
                    file_path=relative,
                    resource=label,
                    artifacts={"image": image},
                    discriminator=f"unpinned:{image}",
                )
            )

        for variable in container.get("env") or []:
            variable_name = str((variable or {}).get("name", ""))
            value = (variable or {}).get("value")
            if value and re.match(
                r"(?i)^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)[A-Z0-9_]*$",
                variable_name,
            ):
                issues.append(
                    _Issue(
                        rule_id="k8s.secret-in-env-literal",
                        title=f"{label} sets {variable_name} to a literal value",
                        description=(
                            f"{variable_name} is given a literal value in the manifest, "
                            "so the credential is committed to source control and visible "
                            "to anyone who can read the pod spec — which is a much wider "
                            "group than those who can read a Secret."
                        ),
                        severity="high",
                        confidence="medium",
                        category="exposed_secret",
                        cwe="CWE-798",
                        remediation=(
                            "Reference a Secret via `valueFrom.secretKeyRef`, or better, "
                            "mount it from an external secrets manager. Rotate the "
                            "committed value."
                        ),
                        file_path=relative,
                        resource=label,
                        artifacts={"variable": variable_name},
                        discriminator=f"env-secret:{label}:{variable_name}",
                    )
                )
        return issues

    # ------------------------------------------------------------------- RBAC
    def _check_rbac(self, document: dict[str, Any], relative: str) -> list[_Issue]:
        kind = str(document.get("kind"))
        name = (document.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (document.get("metadata") or {}).get("namespace", "")
        resource = f"{kind}/{namespace + '/' if namespace else ''}{name}"
        issues: list[_Issue] = []
        is_cluster_scoped = kind.startswith("Cluster")

        if kind in ("RoleBinding", "ClusterRoleBinding"):
            role_ref = document.get("roleRef") or {}
            if str(role_ref.get("name")) == "cluster-admin":
                subjects = [
                    f"{s.get('kind')}/{s.get('name')}" for s in (document.get("subjects") or [])
                ]
                issues.append(
                    _Issue(
                        rule_id="k8s.cluster-admin-binding",
                        title=f"{resource} grants cluster-admin",
                        description=(
                            "This binding grants cluster-admin to "
                            f"{', '.join(subjects) or 'its subjects'}. "
                            "cluster-admin permits every action on every resource, "
                            "including reading all secrets and creating privileged "
                            "workloads on any node."
                        ),
                        severity="critical",
                        confidence="high",
                        category="broken_access_control",
                        cwe="CWE-269",
                        remediation=(
                            "Replace cluster-admin with a role scoped to the specific "
                            "resources and verbs the subject needs."
                        ),
                        file_path=relative,
                        resource=resource,
                        artifacts={"subjects": subjects},
                        discriminator=f"cluster-admin:{resource}",
                    )
                )
            for subject in document.get("subjects") or []:
                subject_name = str((subject or {}).get("name", ""))
                if subject_name in ("system:anonymous", "system:unauthenticated"):
                    issues.append(
                        _Issue(
                            rule_id="k8s.anonymous-rbac-binding",
                            title=f"{resource} grants permissions to anonymous users",
                            description=(
                                f"The binding includes {subject_name!r}, so unauthenticated "
                                "callers receive the bound role. Anyone who can reach the "
                                "API server gets those permissions."
                            ),
                            severity="critical",
                            confidence="high",
                            category="broken_access_control",
                            cwe="CWE-306",
                            remediation="Remove the anonymous subject from the binding.",
                            file_path=relative,
                            resource=resource,
                            discriminator=f"anon-binding:{resource}",
                        )
                    )
            return issues

        for rule in document.get("rules") or []:
            verbs = {str(v).lower() for v in (rule.get("verbs") or [])}
            resources = {str(r).lower() for r in (rule.get("resources") or [])}
            api_groups = {str(g) for g in (rule.get("apiGroups") or [])}

            if "*" in verbs and "*" in resources:
                issues.append(
                    _Issue(
                        rule_id="k8s.wildcard-rbac-rule",
                        title=f"{resource} grants all verbs on all resources",
                        description=(
                            'A rule grants `verbs: ["*"]` on `resources: ["*"]`. At '
                            + (
                                "cluster scope this is cluster-admin by another name."
                                if is_cluster_scoped
                                else "namespace scope this grants full control of the "
                                "namespace, including reading its secrets."
                            )
                        ),
                        severity="critical" if is_cluster_scoped else "high",
                        confidence="high",
                        category="broken_access_control",
                        cwe="CWE-269",
                        remediation=(
                            "Enumerate the specific resources and verbs required. A "
                            "wildcard rule also silently grants access to resources added "
                            "by future CRDs."
                        ),
                        file_path=relative,
                        resource=resource,
                        artifacts={"api_groups": sorted(api_groups)},
                        discriminator=f"wildcard:{resource}",
                    )
                )
                continue

            for sensitive, why in SENSITIVE_RESOURCES.items():
                if sensitive not in resources and "*" not in resources:
                    continue
                granted = sorted(verbs & (READ_VERBS | WRITE_VERBS))
                if not granted:
                    continue
                is_write = bool(verbs & WRITE_VERBS)
                issues.append(
                    _Issue(
                        rule_id="k8s.sensitive-rbac-grant",
                        title=(
                            f"{resource} grants {'write' if is_write else 'read'} access "
                            f"to {sensitive}"
                        ),
                        description=(
                            f"The role grants {', '.join(granted)} on {sensitive!r}"
                            + (" at cluster scope" if is_cluster_scoped else "")
                            + f". {why}"
                            + (
                                " At cluster scope this reaches every namespace."
                                if is_cluster_scoped
                                else ""
                            )
                        ),
                        severity=(
                            "critical"
                            if is_cluster_scoped and (is_write or sensitive == "secrets")
                            else "high"
                        ),
                        confidence="high",
                        category="broken_access_control",
                        cwe="CWE-269",
                        remediation=(
                            "Narrow the rule with `resourceNames` to the specific objects "
                            "needed, reduce the verbs, and prefer a namespaced Role over "
                            "a ClusterRole."
                        ),
                        file_path=relative,
                        resource=resource,
                        artifacts={
                            "sensitive_resource": sensitive,
                            "verbs": granted,
                            "cluster_scoped": is_cluster_scoped,
                        },
                        discriminator=f"rbac:{resource}:{sensitive}",
                    )
                )

            if "escalate" in verbs or "bind" in verbs or "impersonate" in verbs:
                issues.append(
                    _Issue(
                        rule_id="k8s.rbac-escalation-verb",
                        title=f"{resource} grants an escalation verb",
                        description=(
                            "The role grants `escalate`, `bind` or `impersonate`. These "
                            "exist specifically to bypass the normal RBAC restriction "
                            "that a subject cannot grant permissions it does not hold, "
                            "so they are a direct path to full cluster access."
                        ),
                        severity="critical",
                        confidence="high",
                        category="broken_access_control",
                        cwe="CWE-269",
                        remediation="Remove the verb. There is rarely a legitimate reason "
                        "for a workload to hold it.",
                        file_path=relative,
                        resource=resource,
                        artifacts={"verbs": sorted(verbs)},
                        discriminator=f"escalate:{resource}",
                    )
                )
        return issues

    # ---------------------------------------------------------------- others
    @staticmethod
    def _check_service(document: dict[str, Any], relative: str) -> list[_Issue]:
        spec = document.get("spec") or {}
        name = (document.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (document.get("metadata") or {}).get("namespace", "default")
        resource = f"Service/{namespace}/{name}"
        service_type = str(spec.get("type", "ClusterIP"))
        issues: list[_Issue] = []

        if service_type in ("LoadBalancer", "NodePort"):
            ports = [
                str(p.get("port") or p.get("targetPort") or "") for p in (spec.get("ports") or [])
            ]
            sensitive = {"22", "3306", "5432", "6379", "27017", "9200", "2375", "11211"}
            exposed_sensitive = sorted(set(ports) & sensitive)
            issues.append(
                _Issue(
                    rule_id="k8s.externally-exposed-service",
                    title=f"{resource} is exposed externally via {service_type}",
                    description=(
                        f"The service is of type {service_type}, which publishes it "
                        "outside the cluster"
                        + (
                            f". Ports {', '.join(exposed_sensitive)} are datastore or "
                            "administrative ports and should never be reachable from "
                            "outside."
                            if exposed_sensitive
                            else ". Confirm this exposure is intended."
                        )
                    ),
                    severity="critical" if exposed_sensitive else "medium",
                    confidence="high" if exposed_sensitive else "low",
                    category="network_exposure",
                    cwe="CWE-668",
                    remediation=(
                        "Use ClusterIP with an Ingress that terminates TLS and "
                        "authenticates, and never publish a datastore port externally."
                    ),
                    file_path=relative,
                    resource=resource,
                    artifacts={
                        "service_type": service_type,
                        "ports": ports,
                        "sensitive_ports": exposed_sensitive,
                    },
                    discriminator=f"exposed:{resource}",
                )
            )
        return issues

    @staticmethod
    def _check_secret(document: dict[str, Any], relative: str) -> list[_Issue]:
        name = (document.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (document.get("metadata") or {}).get("namespace", "default")
        data = document.get("data") or document.get("stringData") or {}
        if not data:
            return []
        return [
            _Issue(
                rule_id="k8s.secret-committed-to-manifest",
                title=f"Secret/{namespace}/{name} contains committed data",
                description=(
                    f"The Secret manifest carries {len(data)} value(s) in source "
                    "control. Kubernetes Secrets are base64-encoded, not encrypted, so a "
                    "committed Secret is a committed credential — and base64 is not a "
                    "protection."
                ),
                severity="high",
                confidence="high",
                category="exposed_secret",
                cwe="CWE-798",
                remediation=(
                    "Remove the values from source control and rotate them. Supply "
                    "Secrets from an external manager (External Secrets Operator, Vault, "
                    "or a cloud secrets service), or encrypt them at rest in the "
                    "repository with Sealed Secrets or SOPS."
                ),
                file_path=relative,
                resource=f"Secret/{namespace}/{name}",
                artifacts={"key_count": len(data), "keys": sorted(data)[:20]},
                discriminator=f"committed-secret:{namespace}/{name}",
            )
        ]

    @staticmethod
    def _check_ingress(document: dict[str, Any], relative: str) -> list[_Issue]:
        spec = document.get("spec") or {}
        name = (document.get("metadata") or {}).get("name", "<unnamed>")
        namespace = (document.get("metadata") or {}).get("namespace", "default")
        resource = f"Ingress/{namespace}/{name}"
        if not spec.get("tls"):
            return [
                _Issue(
                    rule_id="k8s.ingress-without-tls",
                    title=f"{resource} has no TLS configuration",
                    description=(
                        "The Ingress declares no TLS block, so traffic to it is "
                        "unencrypted. Credentials and session cookies sent over it are "
                        "readable by anyone on the network path."
                    ),
                    severity="high",
                    confidence="medium",
                    category="insecure_communication",
                    cwe="CWE-319",
                    remediation=(
                        "Add a TLS block with a certificate, and redirect HTTP to HTTPS "
                        "at the controller."
                    ),
                    file_path=relative,
                    resource=resource,
                    discriminator=f"ingress-no-tls:{resource}",
                )
            ]
        return []

    # --------------------------------------------------------------- findings
    @staticmethod
    def _to_finding(issue: _Issue, ctx: EngineContext) -> ScanFinding:
        return ScanFinding(
            engine="kubernetes",
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
                f"Inspect {issue.resource} in {issue.file_path} against rule {issue.rule_id}."
            ),
            evidence=Evidence(
                summary=f"{issue.title} ({issue.resource})",
                artifacts={"resource": issue.resource, **issue.artifacts},
            ),
            code_location=CodeLocation(file_path=issue.file_path, symbol=issue.resource),
            correlation_discriminator=issue.discriminator,
            target=ctx.target,
            references=[
                "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
                f"https://cwe.mitre.org/data/definitions/{issue.cwe.split('-')[-1]}.html",
            ],
            raw={"rule_id": issue.rule_id, "resource": issue.resource},
        )
