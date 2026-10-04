"""SQLAlchemy models — the single source of truth for the platform schema.

Every model is imported here so ``Base.metadata`` is complete for Alembic
autogeneration and for test schema creation. Models are grouped by domain but
share one metadata object, because correlation across domains (a finding
evidencing a compliance control, an incident tracing back to a vulnerability)
is the point of the platform.
"""

from __future__ import annotations

from qguard.common.database import Base
from qguard.models.api_security import ApiEndpoint, ApiSpecification
from qguard.models.assets import (
    Asset,
    AssetAssessment,
    AssetRelationship,
    Dependency,
)
from qguard.models.audit import (
    CRITICAL_AUDIT_ACTIONS,
    AuditAction,
    AuditLogEntry,
    Notification,
    NotificationChannel,
    RetentionPolicy,
    SecurityEvent,
)
from qguard.models.compliance import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ControlAssessment,
    ControlMapping,
)
from qguard.models.cryptography import CryptoInventoryItem, PQCReadinessAssessment
from qguard.models.dfir import (
    Case,
    CaseMember,
    CaseNote,
    ChainOfCustodyEntry,
    Evidence,
    EvidenceAccessLog,
    ForensicArtifact,
    TimelineEvent,
)
from qguard.models.findings import (
    CVERecord,
    DetectedSecret,
    Finding,
    FindingComment,
    LicenseFinding,
    Vulnerability,
    VulnerabilityEvent,
)
from qguard.models.identity import (
    ApiKey,
    Organization,
    Permission,
    Project,
    ProjectMember,
    Role,
    RolePermission,
    Team,
    TeamMember,
    User,
    UserRole,
    UserSession,
)
from qguard.models.incidents import (
    Incident,
    IncidentAsset,
    IncidentResponder,
    IncidentTask,
    IncidentUpdate,
)
from qguard.models.infrastructure import (
    CloudAccount,
    CloudResource,
    ContainerImage,
    KubernetesResource,
)
from qguard.models.mobile import MobileApplication
from qguard.models.pentest import (
    Engagement,
    EngagementPhase,
    EngagementTarget,
    PentestNote,
    Retest,
)
from qguard.models.reports import Report, ReportTemplate
from qguard.models.risk import RiskSnapshot
from qguard.models.scanning import (
    Job,
    Scan,
    ScanEngineRun,
    ScanMetric,
    ScanProfile,
    ScanSchedule,
    TestAuthorization,
)
from qguard.models.threat_intel import (
    IOC,
    Campaign,
    IOCMatch,
    MitreTechnique,
    ThreatActor,
    ThreatFeed,
)

#: Tables that carry ``org_id`` and therefore receive a row level security
#: policy. Checked by a test so a new tenant-scoped table cannot be added
#: without a policy.
TENANT_SCOPED_TABLES: tuple[str, ...] = tuple(
    sorted(
        table.name
        for table in Base.metadata.sorted_tables
        if "org_id" in table.columns and not table.columns["org_id"].nullable
    )
)

#: Tables deliberately *not* tenant-scoped, with the reason.
GLOBAL_TABLES: dict[str, str] = {
    "organizations": "The tenant root itself.",
    "permissions": "Permission vocabulary is a property of the software version.",
    "roles": "System roles are global; tenant roles carry a nullable org_id.",
    "role_permissions": "Child of roles.",
    "cve_records": "Public vulnerability intelligence, cached for offline use.",
    "mitre_techniques": "Public MITRE ATT&CK reference data.",
    "compliance_frameworks": "Public standards catalogue.",
    "compliance_controls": "Public standards catalogue.",
    "control_mappings": "Reusable finding-to-control mappings shipped with the platform.",
    "report_templates": "System templates are global; tenant templates carry a nullable org_id.",
    "audit_log": "Tenant-filtered by a nullable org_id so pre-auth events are still recorded.",
}

__all__ = [
    "CRITICAL_AUDIT_ACTIONS",
    "GLOBAL_TABLES",
    "IOC",
    "TENANT_SCOPED_TABLES",
    "ApiEndpoint",
    "ApiKey",
    "ApiSpecification",
    "Asset",
    "AssetAssessment",
    "AssetRelationship",
    "AuditAction",
    "AuditLogEntry",
    "Base",
    "CVERecord",
    "Campaign",
    "Case",
    "CaseMember",
    "CaseNote",
    "ChainOfCustodyEntry",
    "CloudAccount",
    "CloudResource",
    "ComplianceAssessment",
    "ComplianceControl",
    "ComplianceFramework",
    "ContainerImage",
    "ControlAssessment",
    "ControlMapping",
    "CryptoInventoryItem",
    "Dependency",
    "DetectedSecret",
    "Engagement",
    "EngagementPhase",
    "EngagementTarget",
    "Evidence",
    "EvidenceAccessLog",
    "Finding",
    "FindingComment",
    "ForensicArtifact",
    "IOCMatch",
    "Incident",
    "IncidentAsset",
    "IncidentResponder",
    "IncidentTask",
    "IncidentUpdate",
    "Job",
    "KubernetesResource",
    "LicenseFinding",
    "MitreTechnique",
    "MobileApplication",
    "Notification",
    "NotificationChannel",
    "Organization",
    "PQCReadinessAssessment",
    "PentestNote",
    "Permission",
    "Project",
    "ProjectMember",
    "Report",
    "ReportTemplate",
    "RetentionPolicy",
    "Retest",
    "RiskSnapshot",
    "Role",
    "RolePermission",
    "Scan",
    "ScanEngineRun",
    "ScanMetric",
    "ScanProfile",
    "ScanSchedule",
    "SecurityEvent",
    "Team",
    "TeamMember",
    "TestAuthorization",
    "ThreatActor",
    "ThreatFeed",
    "TimelineEvent",
    "User",
    "UserRole",
    "UserSession",
    "Vulnerability",
    "VulnerabilityEvent",
]
