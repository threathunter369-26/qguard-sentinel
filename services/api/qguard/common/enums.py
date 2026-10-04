"""Domain enumerations.

These are stored as constrained VARCHARs rather than native PostgreSQL enums so
that adding a value is an ordinary, non-locking migration. Every enum inherits
from :class:`StrEnum` so values serialise naturally through Pydantic and JSON.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity. Ordered via :data:`SEVERITY_ORDER`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


#: Sort key helper — higher is worse.
def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(str(value or "").lower(), 0)


def severity_from_cvss(score: float | None) -> Severity:
    """Map a CVSS v3.x base score onto the qualitative rating defined by FIRST."""
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    WEB_APPLICATION = "web_application"
    API = "api"
    MOBILE_APPLICATION = "mobile_application"
    SERVER = "server"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER_IMAGE = "container_image"
    KUBERNETES_RESOURCE = "kubernetes_resource"
    CERTIFICATE = "certificate"
    CRYPTOGRAPHIC_KEY = "cryptographic_key"
    REPOSITORY = "repository"
    DEPENDENCY = "dependency"
    ENDPOINT = "endpoint"
    NETWORK_RANGE = "network_range"
    WORKSTATION = "workstation"
    OTHER = "other"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    DR = "disaster_recovery"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataSensitivity(StrEnum):
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class AssetRelation(StrEnum):
    HOSTS = "hosts"
    RESOLVES_TO = "resolves_to"
    DEPENDS_ON = "depends_on"
    PART_OF = "part_of"
    EXPOSES = "exposes"
    CONNECTS_TO = "connects_to"
    BUILT_FROM = "built_from"
    SECURED_BY = "secured_by"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"  # some engines failed — surfaced, never hidden
    FAILED = "failed"
    CANCELLED = "cancelled"


class EngineRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"  # produced results but an input was unavailable
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    UNAUTHORIZED = "unauthorized"  # blocked by scope authorization


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobKind(StrEnum):
    SCAN = "scan"
    SAST_ANALYSIS = "sast_analysis"
    SCA_ANALYSIS = "sca_analysis"
    SECRETS_ANALYSIS = "secrets_analysis"
    MOBILE_ANALYSIS = "mobile_analysis"
    WEB_ASSESSMENT = "web_assessment"
    API_ASSESSMENT = "api_assessment"
    CONTAINER_ANALYSIS = "container_analysis"
    KUBERNETES_ANALYSIS = "kubernetes_analysis"
    CLOUD_ASSESSMENT = "cloud_assessment"
    CRYPTO_ASSESSMENT = "crypto_assessment"
    NETWORK_ASSESSMENT = "network_assessment"
    EVIDENCE_PROCESSING = "evidence_processing"
    REPORT_GENERATION = "report_generation"
    THREAT_INTEL_INGEST = "threat_intel_ingest"
    CORRELATION = "correlation"
    RISK_RECALCULATION = "risk_recalculation"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    RETENTION_SWEEP = "retention_sweep"


class FindingStatus(StrEnum):
    """Per-observation state. Lifecycle state lives on the Vulnerability."""

    NEW = "new"
    ACTIVE = "active"
    REGRESSED = "regressed"
    ABSENT = "absent"  # not seen in the latest scan of the same asset+engine


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    REOPENED = "reopened"


#: Statuses that still count toward open risk on dashboards and risk scoring.
OPEN_VULNERABILITY_STATUSES: tuple[str, ...] = (
    VulnerabilityStatus.OPEN,
    VulnerabilityStatus.CONFIRMED,
    VulnerabilityStatus.IN_PROGRESS,
    VulnerabilityStatus.REOPENED,
)

#: Statuses that represent a closed item (no longer contributing to risk).
CLOSED_VULNERABILITY_STATUSES: tuple[str, ...] = (
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.ACCEPTED_RISK,
    VulnerabilityStatus.RESOLVED,
    VulnerabilityStatus.VERIFIED,
)

#: Legal status transitions. Enforced server-side by the vulnerability service.
VULNERABILITY_TRANSITIONS: dict[str, tuple[str, ...]] = {
    VulnerabilityStatus.OPEN: (
        VulnerabilityStatus.CONFIRMED,
        VulnerabilityStatus.FALSE_POSITIVE,
        VulnerabilityStatus.ACCEPTED_RISK,
        VulnerabilityStatus.IN_PROGRESS,
        VulnerabilityStatus.RESOLVED,
    ),
    VulnerabilityStatus.CONFIRMED: (
        VulnerabilityStatus.IN_PROGRESS,
        VulnerabilityStatus.ACCEPTED_RISK,
        VulnerabilityStatus.RESOLVED,
        VulnerabilityStatus.FALSE_POSITIVE,
    ),
    VulnerabilityStatus.IN_PROGRESS: (
        VulnerabilityStatus.RESOLVED,
        VulnerabilityStatus.ACCEPTED_RISK,
        VulnerabilityStatus.CONFIRMED,
    ),
    VulnerabilityStatus.RESOLVED: (
        VulnerabilityStatus.VERIFIED,
        VulnerabilityStatus.REOPENED,
    ),
    VulnerabilityStatus.VERIFIED: (VulnerabilityStatus.REOPENED,),
    VulnerabilityStatus.REOPENED: (
        VulnerabilityStatus.CONFIRMED,
        VulnerabilityStatus.IN_PROGRESS,
        VulnerabilityStatus.RESOLVED,
        VulnerabilityStatus.FALSE_POSITIVE,
        VulnerabilityStatus.ACCEPTED_RISK,
    ),
    VulnerabilityStatus.FALSE_POSITIVE: (VulnerabilityStatus.REOPENED,),
    VulnerabilityStatus.ACCEPTED_RISK: (
        VulnerabilityStatus.REOPENED,
        VulnerabilityStatus.IN_PROGRESS,
    ),
}


class FindingCategory(StrEnum):
    """Normalised finding taxonomy shared by every engine.

    Engines must map their native categories onto this list so correlation,
    compliance mapping and reporting work identically across sources.
    """

    INJECTION = "injection"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    BROKEN_AUTHENTICATION = "broken_authentication"
    SESSION_MANAGEMENT = "session_management"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    CRYPTOGRAPHIC_FAILURE = "cryptographic_failure"
    QUANTUM_VULNERABLE_CRYPTOGRAPHY = "quantum_vulnerable_cryptography"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    EXPOSED_SECRET = "exposed_secret"
    SSRF = "ssrf"
    CSRF = "csrf"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_EXECUTION = "command_execution"
    FILE_HANDLING = "file_handling"
    INPUT_VALIDATION = "input_validation"
    API_SECURITY = "api_security"
    INSECURE_STORAGE = "insecure_storage"
    INSECURE_COMMUNICATION = "insecure_communication"
    PLATFORM_MISUSE = "platform_misuse"
    CODE_QUALITY_SECURITY = "code_quality_security"
    SUPPLY_CHAIN = "supply_chain"
    CONTAINER_SECURITY = "container_security"
    KUBERNETES_SECURITY = "kubernetes_security"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    NETWORK_EXPOSURE = "network_exposure"
    CERTIFICATE_ISSUE = "certificate_issue"
    DNS_SECURITY = "dns_security"
    LICENSE_RISK = "license_risk"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE_RISK = "denial_of_service_risk"
    LOGGING_AND_MONITORING = "logging_and_monitoring"
    OTHER = "other"


class EngineKey(StrEnum):
    """Stable identifiers for scanner engines."""

    SECRETS = "secrets"
    SAST = "sast"
    SCA = "sca"
    WEB = "web"
    API = "api"
    MOBILE = "mobile"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    CRYPTO = "crypto"
    NETWORK = "network"
    CERTIFICATE = "certificate"
    CONFIGURATION = "configuration"
    MANUAL = "manual"  # analyst-entered finding (pentest workspace)
    IMPORT = "import"  # third-party scanner import


class ScanType(StrEnum):
    WEB_APPLICATION = "web_application"
    API = "api"
    MOBILE = "mobile"
    SOURCE_CODE = "source_code"
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    NETWORK = "network"
    CRYPTOGRAPHY = "cryptography"
    FULL_ASSESSMENT = "full_assessment"


class PQCategory(StrEnum):
    """Post-quantum cryptographic primitive classes.

    Kept strictly separated so a KEM is never reported as a signature scheme and
    vice versa. ML-KEM is key encapsulation only; ML-DSA and SLH-DSA are
    signature schemes only.
    """

    KEY_ENCAPSULATION = "key_encapsulation"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_AGREEMENT = "key_agreement"
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    UNKNOWN = "unknown"


class QuantumRisk(StrEnum):
    """Exposure of a primitive to a cryptographically relevant quantum computer."""

    BROKEN = "broken"  # Shor-breakable: RSA, ECC, DH, DSA
    REDUCED = "reduced"  # Grover-reduced symmetric strength
    QUANTUM_SAFE = "quantum_safe"  # NIST PQC standard or adequate symmetric margin
    HYBRID = "hybrid"  # classical + PQ composite
    UNKNOWN = "unknown"


class CryptoAssetKind(StrEnum):
    CERTIFICATE = "certificate"
    TLS_CONFIGURATION = "tls_configuration"
    SSH_CONFIGURATION = "ssh_configuration"
    KEY = "key"
    CODE_USAGE = "code_usage"
    JWT_CONFIGURATION = "jwt_configuration"
    HASH_USAGE = "hash_usage"
    RANDOMNESS = "randomness"


class CasePriority(StrEnum):
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    ON_HOLD = "on_hold"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseType(StrEnum):
    INCIDENT_INVESTIGATION = "incident_investigation"
    MALWARE_ANALYSIS = "malware_analysis"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    FRAUD = "fraud"
    PHISHING = "phishing"
    POLICY_VIOLATION = "policy_violation"
    THREAT_HUNT = "threat_hunt"
    OTHER = "other"


class IncidentPhase(StrEnum):
    """NIST SP 800-61 aligned response lifecycle."""

    DETECTION = "detection"
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"
    CLOSED = "closed"


INCIDENT_PHASE_ORDER: tuple[str, ...] = (
    IncidentPhase.DETECTION,
    IncidentPhase.TRIAGE,
    IncidentPhase.INVESTIGATION,
    IncidentPhase.CONTAINMENT,
    IncidentPhase.ERADICATION,
    IncidentPhase.RECOVERY,
    IncidentPhase.LESSONS_LEARNED,
    IncidentPhase.CLOSED,
)


class IncidentStatus(StrEnum):
    OPEN = "open"
    MONITORING = "monitoring"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_ALARM = "false_alarm"


class IncidentCategory(StrEnum):
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    WEB_COMPROMISE = "web_compromise"
    SUPPLY_CHAIN = "supply_chain"
    INSIDER = "insider"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    CLOUD_COMPROMISE = "cloud_compromise"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class TaskStatus(StrEnum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    CANCELLED = "cancelled"


class EvidenceStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    AVAILABLE = "available"
    QUARANTINED = "quarantined"
    FAILED = "failed"
    SEALED = "sealed"
    DISPOSED = "disposed"


class CustodyAction(StrEnum):
    COLLECTED = "collected"
    RECEIVED = "received"
    TRANSFERRED = "transferred"
    ACCESSED = "accessed"
    ANALYZED = "analyzed"
    EXPORTED = "exported"
    VERIFIED = "verified"
    SEALED = "sealed"
    DISPOSED = "disposed"


class EvidenceSourceType(StrEnum):
    FILE = "file"
    DISK_IMAGE = "disk_image"
    MEMORY_CAPTURE = "memory_capture"
    LOG = "log"
    NETWORK_CAPTURE = "network_capture"
    BROWSER_ARTIFACT = "browser_artifact"
    SYSTEM_ARTIFACT = "system_artifact"
    MOBILE_ARTIFACT = "mobile_artifact"
    CLOUD_ARTIFACT = "cloud_artifact"
    AUTHENTICATION_LOG = "authentication_log"
    EMAIL = "email"
    SCREENSHOT = "screenshot"
    MOBILE_PACKAGE = "mobile_package"
    SOURCE_ARCHIVE = "source_archive"
    OTHER = "other"


class ArtifactType(StrEnum):
    BROWSER_HISTORY = "browser_history"
    BROWSER_DOWNLOAD = "browser_download"
    BROWSER_COOKIE = "browser_cookie"
    AUTH_EVENT = "auth_event"
    PROCESS_EXECUTION = "process_execution"
    PERSISTENCE = "persistence"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_METADATA = "file_metadata"
    EMAIL_HEADER = "email_header"
    REGISTRY_KEY = "registry_key"
    SCHEDULED_TASK = "scheduled_task"
    USER_ACCOUNT = "user_account"
    CLOUD_API_CALL = "cloud_api_call"
    IOC_HIT = "ioc_hit"
    LOG_RECORD = "log_record"
    STRING_MATCH = "string_match"
    OTHER = "other"


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"
    REGISTRY_KEY = "registry_key"
    USER_AGENT = "user_agent"
    ASN = "asn"
    MUTEX = "mutex"
    JA3 = "ja3"
    BITCOIN_ADDRESS = "bitcoin_address"
    CVE = "cve"
    YARA_RULE = "yara_rule"


class TLP(StrEnum):
    """Traffic Light Protocol 2.0 sharing designations."""

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber_strict"
    RED = "red"


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    SCOPING = "scoping"
    APPROVED = "approved"
    ACTIVE = "active"
    TESTING_COMPLETE = "testing_complete"
    REPORTING = "reporting"
    RETEST = "retest"
    CLOSED = "closed"
    CANCELLED = "cancelled"


class EngagementType(StrEnum):
    WEB_APPLICATION = "web_application"
    MOBILE_APPLICATION = "mobile_application"
    API = "api"
    NETWORK_INTERNAL = "network_internal"
    NETWORK_EXTERNAL = "network_external"
    CLOUD = "cloud"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"
    CODE_REVIEW = "code_review"
    CONFIGURATION_REVIEW = "configuration_review"


class PentestPhase(StrEnum):
    """PTES-aligned engagement phases."""

    PRE_ENGAGEMENT = "pre_engagement"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    REPORTING = "reporting"
    RETEST = "retest"


class AuthorizationStatus(StrEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REJECTED = "rejected"


class ReportKind(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    VULNERABILITY = "vulnerability"
    PENETRATION_TEST = "penetration_test"
    MOBILE_SECURITY = "mobile_security"
    WEB_SECURITY = "web_security"
    API_SECURITY = "api_security"
    DFIR = "dfir"
    INCIDENT = "incident"
    COMPLIANCE = "compliance"
    CRYPTOGRAPHIC_ASSESSMENT = "cryptographic_assessment"
    QUANTUM_READINESS = "quantum_readiness"
    ASSET_INVENTORY = "asset_inventory"
    SCAN_SUMMARY = "scan_summary"


class ReportFormat(StrEnum):
    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class ReportStatus(StrEnum):
    QUEUED = "queued"
    GENERATING = "generating"
    AVAILABLE = "available"
    FAILED = "failed"
    EXPIRED = "expired"


class ControlAssessmentStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class MappingSourceType(StrEnum):
    """What a compliance control mapping is keyed on."""

    CWE = "cwe"
    CVE = "cve"
    OWASP_TOP10 = "owasp_top10"
    OWASP_ASVS = "owasp_asvs"
    OWASP_MASVS = "owasp_masvs"
    OWASP_API_TOP10 = "owasp_api_top10"
    FINDING_CATEGORY = "finding_category"
    MITRE_ATTACK = "mitre_attack"
    CAPEC = "capec"
    ENGINE = "engine"


class UserStatus(StrEnum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    DISABLED = "disabled"


class ScopeType(StrEnum):
    """Scope at which a role assignment applies."""

    ORGANIZATION = "organization"
    TEAM = "team"
    PROJECT = "project"


class TeamKind(StrEnum):
    SECURITY_ENGINEERING = "security_engineering"
    SOC = "soc"
    DFIR = "dfir"
    DEVELOPMENT = "development"
    RED_TEAM = "red_team"
    COMPLIANCE = "compliance"
    PLATFORM = "platform"
    OTHER = "other"


class ProjectKind(StrEnum):
    WEB_APPLICATIONS = "web_applications"
    MOBILE_APPLICATIONS = "mobile_applications"
    APIS = "apis"
    INFRASTRUCTURE = "infrastructure"
    CLOUD = "cloud"
    SOURCE_CODE = "source_code"
    MIXED = "mixed"


class AuditResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class ActorType(StrEnum):
    USER = "user"
    API_KEY = "api_key"
    SYSTEM = "system"
    WORKER = "worker"
    ANONYMOUS = "anonymous"


class SecurityEventKind(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    ENGINE_FAILED = "engine_failed"
    CRITICAL_FINDING = "critical_finding"
    VULNERABILITY_REOPENED = "vulnerability_reopened"
    INCIDENT_DECLARED = "incident_declared"
    INCIDENT_ESCALATED = "incident_escalated"
    EVIDENCE_UPLOADED = "evidence_uploaded"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"
    IOC_MATCH = "ioc_match"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    SCOPE_VIOLATION_BLOCKED = "scope_violation_blocked"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"
    PERMISSION_CHANGED = "permission_changed"
    AUDIT_CHAIN_BROKEN = "audit_chain_broken"


class NotificationChannelKind(StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    IN_APP = "in_app"


class LicenseRisk(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


class SecretValidationStatus(StrEnum):
    UNVERIFIED = "unverified"
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    ROTATED = "rotated"
    NOT_APPLICABLE = "not_applicable"


class MobilePlatform(StrEnum):
    ANDROID = "android"
    IOS = "ios"


class CloudProvider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    OTHER = "other"
