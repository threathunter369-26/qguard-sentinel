"""The platform's permission vocabulary and built-in roles.

Permissions are fine-grained and named ``<resource>:<action>``. Roles are
bundles of permissions; a user holds roles, optionally narrowed to a team or a
project. Nothing in the platform checks a role name directly — every guard
checks a permission — so a tenant can define its own roles without the
authorization logic changing.

The catalogue is code, not data, because it is a property of the software
version. The role→permission grants are rows, because they are a property of
the tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    key: str
    resource: str
    action: str
    description: str
    #: Sensitive permissions always produce an audit event when exercised,
    #: regardless of any audit sampling.
    sensitive: bool = False


def _p(resource: str, action: str, description: str, *, sensitive: bool = False) -> PermissionSpec:
    return PermissionSpec(
        key=f"{resource}:{action}",
        resource=resource,
        action=action,
        description=description,
        sensitive=sensitive,
    )


PERMISSIONS: Final[tuple[PermissionSpec, ...]] = (
    # ------------------------------------------------------------ organization
    _p("organization", "read", "View organization settings and metadata."),
    _p("organization", "update", "Change organization settings.", sensitive=True),
    _p("organization", "manage_retention", "Change data retention policy.", sensitive=True),
    # -------------------------------------------------------------------- users
    _p("user", "read", "View user accounts."),
    _p("user", "create", "Invite or create user accounts.", sensitive=True),
    _p("user", "update", "Modify user accounts."),
    _p("user", "disable", "Disable or suspend a user account.", sensitive=True),
    _p("user", "manage_roles", "Grant or revoke roles.", sensitive=True),
    _p("user", "manage_api_keys", "Create or revoke API keys.", sensitive=True),
    _p("user", "impersonate", "Act on behalf of another user.", sensitive=True),
    # -------------------------------------------------------- teams and projects
    _p("team", "read", "View teams and their membership."),
    _p("team", "manage", "Create, modify or delete teams."),
    _p("project", "read", "View projects."),
    _p("project", "create", "Create projects."),
    _p("project", "update", "Modify projects."),
    _p("project", "delete", "Delete projects.", sensitive=True),
    _p("project", "manage_members", "Change project membership."),
    # ------------------------------------------------------------------- assets
    _p("asset", "read", "View the asset inventory."),
    _p("asset", "create", "Add assets to the inventory."),
    _p("asset", "update", "Modify assets."),
    _p("asset", "delete", "Remove assets.", sensitive=True),
    _p("asset", "import", "Bulk-import assets."),
    # ------------------------------------------------------ test authorizations
    _p("authorization", "read", "View test authorizations and their scope."),
    _p("authorization", "create", "Draft a test authorization."),
    _p(
        "authorization",
        "approve",
        "Approve a test authorization, permitting active testing of its scope.",
        sensitive=True,
    ),
    _p("authorization", "revoke", "Revoke a test authorization.", sensitive=True),
    # -------------------------------------------------------------------- scans
    _p("scan", "read", "View scans and their results."),
    _p("scan", "run_passive", "Run passive assessments that send no traffic to a target."),
    _p(
        "scan",
        "run_active",
        "Run active assessments against authorized targets.",
        sensitive=True,
    ),
    _p(
        "scan",
        "run_intrusive",
        "Run checks that modify state or are noticeably disruptive.",
        sensitive=True,
    ),
    _p("scan", "cancel", "Cancel a running scan."),
    _p("scan", "manage_profiles", "Create or modify scan profiles."),
    _p("scan", "manage_schedules", "Create or modify scan schedules."),
    _p("scan", "import_results", "Import results from a third-party scanner."),
    # ---------------------------------------------------- findings and vulns
    _p("finding", "read", "View findings."),
    _p("finding", "create", "Record a finding manually."),
    _p("finding", "update", "Modify a finding."),
    _p("vulnerability", "read", "View vulnerabilities."),
    _p("vulnerability", "update", "Modify vulnerability details and ownership."),
    _p("vulnerability", "change_status", "Change a vulnerability's lifecycle status."),
    _p(
        "vulnerability",
        "accept_risk",
        "Accept the risk of an unresolved vulnerability.",
        sensitive=True,
    ),
    _p(
        "vulnerability",
        "override_severity",
        "Override an engine-assigned severity.",
        sensitive=True,
    ),
    _p("vulnerability", "verify", "Verify that a remediation is effective."),
    # ------------------------------------------------------------------ secrets
    _p("secret", "read", "View detected secrets in redacted form."),
    _p(
        "secret",
        "validate",
        "Check whether a detected credential is still live.",
        sensitive=True,
    ),
    _p("secret", "record_rotation", "Record that a credential has been rotated."),
    # ------------------------------------------------------------------- crypto
    _p("crypto", "read", "View the cryptographic inventory and quantum readiness."),
    _p("crypto", "assess", "Run cryptographic and post-quantum assessments."),
    # ------------------------------------------------------------------- mobile
    _p("mobile", "read", "View mobile application analyses."),
    _p("mobile", "upload", "Upload a mobile application package for analysis."),
    # ---------------------------------------------------------------------- api
    _p("api_security", "read", "View the API inventory and endpoint assessments."),
    _p("api_security", "import_spec", "Import an API specification."),
    # ------------------------------------------------------------------ pentest
    _p("engagement", "read", "View penetration testing engagements."),
    _p("engagement", "create", "Create engagements."),
    _p("engagement", "update", "Modify engagements."),
    _p("engagement", "manage_scope", "Change an engagement's target scope.", sensitive=True),
    _p("engagement", "close", "Close an engagement."),
    # --------------------------------------------------------------------- DFIR
    _p("case", "read", "View forensic cases assigned to you."),
    _p("case", "read_all", "View every forensic case in the organization.", sensitive=True),
    _p("case", "create", "Open a forensic case."),
    _p("case", "update", "Modify a forensic case."),
    _p("case", "close", "Close a forensic case."),
    _p("evidence", "read", "View evidence metadata."),
    _p("evidence", "upload", "Ingest evidence."),
    _p("evidence", "download", "Download evidence content.", sensitive=True),
    _p("evidence", "export", "Export evidence out of the platform.", sensitive=True),
    _p("evidence", "transfer_custody", "Transfer custody of evidence.", sensitive=True),
    _p("evidence", "verify", "Verify evidence integrity."),
    _p("evidence", "seal", "Seal evidence against further modification.", sensitive=True),
    _p("evidence", "dispose", "Dispose of evidence.", sensitive=True),
    # ---------------------------------------------------------------- incidents
    _p("incident", "read", "View incidents."),
    _p("incident", "declare", "Declare an incident.", sensitive=True),
    _p("incident", "update", "Update an incident."),
    _p("incident", "change_phase", "Advance an incident's response phase."),
    _p("incident", "close", "Close an incident.", sensitive=True),
    _p("incident", "manage_tasks", "Create and assign response tasks."),
    _p("incident", "communicate", "Record external stakeholder communications."),
    # ------------------------------------------------------- threat intelligence
    _p("threat_intel", "read", "View threat intelligence."),
    _p("threat_intel", "create", "Record indicators, actors and campaigns."),
    _p("threat_intel", "update", "Modify threat intelligence."),
    _p("threat_intel", "manage_feeds", "Configure intelligence feeds.", sensitive=True),
    # --------------------------------------------------------------------- risk
    _p("risk", "read", "View risk scores and posture."),
    _p("risk", "recalculate", "Trigger a risk recalculation."),
    _p("risk", "manage_model", "Change risk model weights.", sensitive=True),
    # --------------------------------------------------------------- compliance
    _p("compliance", "read", "View compliance assessments and control mappings."),
    _p("compliance", "assess", "Run a compliance assessment."),
    _p("compliance", "attest", "Record a manual control attestation.", sensitive=True),
    _p("compliance", "manage_mappings", "Modify finding-to-control mappings.", sensitive=True),
    # ------------------------------------------------------------------ reports
    _p("report", "read", "View generated reports."),
    _p("report", "generate", "Generate reports."),
    _p("report", "download", "Download report files."),
    _p("report", "manage_templates", "Create or modify report templates."),
    # -------------------------------------------------------------------- audit
    _p("audit", "read", "Read the audit trail.", sensitive=True),
    _p("audit", "verify", "Verify audit trail integrity."),
    _p("audit", "export", "Export the audit trail.", sensitive=True),
    # ------------------------------------------------------------------ platform
    _p("job", "read", "View background jobs."),
    _p("job", "manage", "Retry or cancel background jobs."),
    _p("notification", "manage_channels", "Configure notification channels."),
    _p("cloud", "read", "View cloud inventory and posture."),
    _p("cloud", "manage_accounts", "Connect or remove cloud accounts.", sensitive=True),
    _p("cloud", "assess", "Run cloud posture assessments."),
    _p("container", "read", "View container and Kubernetes inventory."),
    _p("container", "assess", "Run container and Kubernetes assessments."),
)

PERMISSIONS_BY_KEY: Final[dict[str, PermissionSpec]] = {p.key: p for p in PERMISSIONS}
ALL_PERMISSION_KEYS: Final[frozenset[str]] = frozenset(PERMISSIONS_BY_KEY)
SENSITIVE_PERMISSION_KEYS: Final[frozenset[str]] = frozenset(
    p.key for p in PERMISSIONS if p.sensitive
)


def permissions_for_resources(*resources: str) -> list[str]:
    return [p.key for p in PERMISSIONS if p.resource in resources]


def read_only_permissions() -> list[str]:
    """Every ``:read``-style permission, excluding sensitive ones.

    Used to build the auditor role: broad visibility, but evidence download
    and the audit trail still require their own explicit grant.
    """
    return [p.key for p in PERMISSIONS if p.action in {"read", "verify"} and not p.sensitive]


@dataclass(frozen=True, slots=True)
class RoleSpec:
    key: str
    name: str
    description: str
    #: Higher rank may manage lower-ranked roles. A holder can never grant a
    #: role at or above their own rank, which is what stops privilege
    #: escalation through the role-assignment endpoint.
    rank: int
    permissions: frozenset[str] = field(default_factory=frozenset)


def _role(key: str, name: str, description: str, rank: int, perms: list[str]) -> RoleSpec:
    unknown = set(perms) - ALL_PERMISSION_KEYS
    if unknown:
        raise ValueError(f"Role {key!r} references unknown permissions: {sorted(unknown)}")
    return RoleSpec(
        key=key, name=name, description=description, rank=rank, permissions=frozenset(perms)
    )


_SECURITY_ENGINEER_PERMS = [
    *read_only_permissions(),
    "asset:create",
    "asset:update",
    "asset:import",
    "authorization:create",
    "scan:run_passive",
    "scan:run_active",
    "scan:cancel",
    "scan:manage_profiles",
    "scan:manage_schedules",
    "scan:import_results",
    "finding:create",
    "finding:update",
    "vulnerability:update",
    "vulnerability:change_status",
    "vulnerability:verify",
    "secret:record_rotation",
    "crypto:assess",
    "mobile:upload",
    "api_security:import_spec",
    "container:assess",
    "cloud:assess",
    "risk:recalculate",
    "compliance:assess",
    "report:generate",
    "report:download",
    "threat_intel:create",
    "job:read",
    "job:manage",
]

_ANALYST_PERMS = [
    *read_only_permissions(),
    "scan:run_passive",
    "finding:create",
    "finding:update",
    "vulnerability:update",
    "vulnerability:change_status",
    "threat_intel:create",
    "threat_intel:update",
    "report:generate",
    "report:download",
    "job:read",
]

_INCIDENT_RESPONDER_PERMS = [
    *read_only_permissions(),
    "incident:declare",
    "incident:update",
    "incident:change_phase",
    "incident:manage_tasks",
    "incident:communicate",
    "case:create",
    "case:update",
    "evidence:upload",
    "evidence:verify",
    "threat_intel:create",
    "threat_intel:update",
    "report:generate",
    "report:download",
    "scan:run_passive",
]

_DFIR_INVESTIGATOR_PERMS = [
    *read_only_permissions(),
    "case:create",
    "case:update",
    "case:close",
    "case:read_all",
    "evidence:upload",
    "evidence:download",
    "evidence:verify",
    "evidence:transfer_custody",
    "evidence:seal",
    "incident:update",
    "incident:manage_tasks",
    "threat_intel:create",
    "threat_intel:update",
    "report:generate",
    "report:download",
]

_PENTESTER_PERMS = [
    *read_only_permissions(),
    "engagement:create",
    "engagement:update",
    "engagement:close",
    "authorization:create",
    "scan:run_passive",
    "scan:run_active",
    "scan:run_intrusive",
    "scan:cancel",
    "finding:create",
    "finding:update",
    "vulnerability:update",
    "vulnerability:change_status",
    "vulnerability:verify",
    "evidence:upload",
    "asset:create",
    "asset:update",
    "report:generate",
    "report:download",
    "mobile:upload",
    "api_security:import_spec",
]

_DEVSECOPS_PERMS = [
    *read_only_permissions(),
    "scan:run_passive",
    "scan:import_results",
    "asset:create",
    "asset:update",
    "vulnerability:update",
    "vulnerability:change_status",
    "secret:record_rotation",
    "container:assess",
    "api_security:import_spec",
    "report:generate",
    "report:download",
    "job:read",
]

_COMPLIANCE_PERMS = [
    *read_only_permissions(),
    "compliance:assess",
    "compliance:attest",
    "report:generate",
    "report:download",
    "audit:read",
    "audit:export",
]

_AUDITOR_PERMS = [*read_only_permissions(), "audit:read", "report:read", "report:download"]

_MANAGER_PERMS = [
    *_SECURITY_ENGINEER_PERMS,
    "authorization:approve",
    "authorization:revoke",
    "vulnerability:accept_risk",
    "vulnerability:override_severity",
    "project:create",
    "project:update",
    "project:manage_members",
    "team:manage",
    "engagement:create",
    "engagement:update",
    "engagement:manage_scope",
    "engagement:close",
    "incident:declare",
    "incident:close",
    "evidence:download",
    "secret:validate",
    "audit:read",
    "risk:manage_model",
    "report:manage_templates",
    "scan:run_intrusive",
]

SYSTEM_ROLES: Final[tuple[RoleSpec, ...]] = (
    _role(
        "platform_admin",
        "Platform Administrator",
        "Full administrative control, including user management and every "
        "sensitive capability. Intended for a small number of operators.",
        100,
        sorted(ALL_PERMISSION_KEYS - {"user:impersonate"}),
    ),
    _role(
        "security_manager",
        "Security Manager",
        "Leads the security function: approves test authorizations, accepts "
        "risk and owns the vulnerability management programme.",
        80,
        sorted(set(_MANAGER_PERMS)),
    ),
    _role(
        "security_engineer",
        "Security Engineer",
        "Runs assessments, triages findings and drives remediation. Can test "
        "actively within an approved authorization but cannot approve one.",
        60,
        sorted(set(_SECURITY_ENGINEER_PERMS)),
    ),
    _role(
        "penetration_tester",
        "Penetration Tester",
        "Runs engagements and intrusive testing strictly inside an approved "
        "scope, and documents findings with evidence.",
        60,
        sorted(set(_PENTESTER_PERMS)),
    ),
    _role(
        "dfir_investigator",
        "DFIR Investigator",
        "Conducts forensic investigations: ingests evidence, holds custody and builds timelines.",
        60,
        sorted(set(_DFIR_INVESTIGATOR_PERMS)),
    ),
    _role(
        "incident_responder",
        "Incident Responder",
        "Declares and drives incidents through the response lifecycle.",
        55,
        sorted(set(_INCIDENT_RESPONDER_PERMS)),
    ),
    _role(
        "security_analyst",
        "Security Analyst",
        "Triages findings and threat intelligence. Passive assessment only.",
        40,
        sorted(set(_ANALYST_PERMS)),
    ),
    _role(
        "devsecops_engineer",
        "DevSecOps Engineer",
        "Integrates security into delivery pipelines: imports scanner results "
        "and tracks remediation for owned services.",
        40,
        sorted(set(_DEVSECOPS_PERMS)),
    ),
    _role(
        "compliance_officer",
        "Compliance Officer",
        "Runs compliance assessments, attests controls and reads the audit trail.",
        40,
        sorted(set(_COMPLIANCE_PERMS)),
    ),
    _role(
        "auditor",
        "Auditor (read-only)",
        "Read-only visibility for assurance purposes. Cannot change any "
        "record, run any assessment or download evidence.",
        20,
        sorted(set(_AUDITOR_PERMS)),
    ),
)

SYSTEM_ROLES_BY_KEY: Final[dict[str, RoleSpec]] = {r.key: r for r in SYSTEM_ROLES}


class Perm:
    """Permission key constants, so guards never carry a bare string literal."""

    ORG_READ = "organization:read"
    ORG_UPDATE = "organization:update"
    ORG_MANAGE_RETENTION = "organization:manage_retention"

    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DISABLE = "user:disable"
    USER_MANAGE_ROLES = "user:manage_roles"
    USER_MANAGE_API_KEYS = "user:manage_api_keys"

    TEAM_READ = "team:read"
    TEAM_MANAGE = "team:manage"
    PROJECT_READ = "project:read"
    PROJECT_CREATE = "project:create"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    PROJECT_MANAGE_MEMBERS = "project:manage_members"

    ASSET_READ = "asset:read"
    ASSET_CREATE = "asset:create"
    ASSET_UPDATE = "asset:update"
    ASSET_DELETE = "asset:delete"
    ASSET_IMPORT = "asset:import"

    AUTHORIZATION_READ = "authorization:read"
    AUTHORIZATION_CREATE = "authorization:create"
    AUTHORIZATION_APPROVE = "authorization:approve"
    AUTHORIZATION_REVOKE = "authorization:revoke"

    SCAN_READ = "scan:read"
    SCAN_RUN_PASSIVE = "scan:run_passive"
    SCAN_RUN_ACTIVE = "scan:run_active"
    SCAN_RUN_INTRUSIVE = "scan:run_intrusive"
    SCAN_CANCEL = "scan:cancel"
    SCAN_MANAGE_PROFILES = "scan:manage_profiles"
    SCAN_MANAGE_SCHEDULES = "scan:manage_schedules"
    SCAN_IMPORT_RESULTS = "scan:import_results"

    FINDING_READ = "finding:read"
    FINDING_CREATE = "finding:create"
    FINDING_UPDATE = "finding:update"
    VULN_READ = "vulnerability:read"
    VULN_UPDATE = "vulnerability:update"
    VULN_CHANGE_STATUS = "vulnerability:change_status"
    VULN_ACCEPT_RISK = "vulnerability:accept_risk"
    VULN_OVERRIDE_SEVERITY = "vulnerability:override_severity"
    VULN_VERIFY = "vulnerability:verify"

    SECRET_READ = "secret:read"
    SECRET_VALIDATE = "secret:validate"
    SECRET_RECORD_ROTATION = "secret:record_rotation"

    CRYPTO_READ = "crypto:read"
    CRYPTO_ASSESS = "crypto:assess"
    MOBILE_READ = "mobile:read"
    MOBILE_UPLOAD = "mobile:upload"
    API_SECURITY_READ = "api_security:read"
    API_SECURITY_IMPORT_SPEC = "api_security:import_spec"

    ENGAGEMENT_READ = "engagement:read"
    ENGAGEMENT_CREATE = "engagement:create"
    ENGAGEMENT_UPDATE = "engagement:update"
    ENGAGEMENT_MANAGE_SCOPE = "engagement:manage_scope"
    ENGAGEMENT_CLOSE = "engagement:close"

    CASE_READ = "case:read"
    CASE_READ_ALL = "case:read_all"
    CASE_CREATE = "case:create"
    CASE_UPDATE = "case:update"
    CASE_CLOSE = "case:close"

    EVIDENCE_READ = "evidence:read"
    EVIDENCE_UPLOAD = "evidence:upload"
    EVIDENCE_DOWNLOAD = "evidence:download"
    EVIDENCE_EXPORT = "evidence:export"
    EVIDENCE_TRANSFER_CUSTODY = "evidence:transfer_custody"
    EVIDENCE_VERIFY = "evidence:verify"
    EVIDENCE_SEAL = "evidence:seal"
    EVIDENCE_DISPOSE = "evidence:dispose"

    INCIDENT_READ = "incident:read"
    INCIDENT_DECLARE = "incident:declare"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_CHANGE_PHASE = "incident:change_phase"
    INCIDENT_CLOSE = "incident:close"
    INCIDENT_MANAGE_TASKS = "incident:manage_tasks"
    INCIDENT_COMMUNICATE = "incident:communicate"

    THREAT_INTEL_READ = "threat_intel:read"
    THREAT_INTEL_CREATE = "threat_intel:create"
    THREAT_INTEL_UPDATE = "threat_intel:update"
    THREAT_INTEL_MANAGE_FEEDS = "threat_intel:manage_feeds"

    RISK_READ = "risk:read"
    RISK_RECALCULATE = "risk:recalculate"
    RISK_MANAGE_MODEL = "risk:manage_model"

    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_ASSESS = "compliance:assess"
    COMPLIANCE_ATTEST = "compliance:attest"
    COMPLIANCE_MANAGE_MAPPINGS = "compliance:manage_mappings"

    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    REPORT_DOWNLOAD = "report:download"
    REPORT_MANAGE_TEMPLATES = "report:manage_templates"

    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    AUDIT_EXPORT = "audit:export"

    JOB_READ = "job:read"
    JOB_MANAGE = "job:manage"
    NOTIFICATION_MANAGE_CHANNELS = "notification:manage_channels"
    CLOUD_READ = "cloud:read"
    CLOUD_MANAGE_ACCOUNTS = "cloud:manage_accounts"
    CLOUD_ASSESS = "cloud:assess"
    CONTAINER_READ = "container:read"
    CONTAINER_ASSESS = "container:assess"
