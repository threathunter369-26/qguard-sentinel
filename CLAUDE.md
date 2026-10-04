# Qguard Sentinel
## Enterprise Cybersecurity Assessment, VAPT, DFIR & Incident Response Platform

> **Mission:** Build a secure, evidence-driven, enterprise-grade cybersecurity platform for authorized security assessment, vulnerability management, penetration testing, digital forensics, incident response, threat intelligence, cryptographic analysis, and security operations.

---

# 1. ROLE OF THIS FILE

This `CLAUDE.md` is the primary engineering contract for **Qguard Sentinel**.

Claude Code MUST read and follow this document before:

- Creating files
- Modifying architecture
- Adding dependencies
- Implementing features
- Modifying database schemas
- Creating scanners
- Modifying authentication
- Changing authorization
- Creating APIs
- Modifying security logic
- Changing deployment configuration
- Refactoring existing modules

This document takes precedence over convenience, shortcuts, or assumptions.

When repository-specific documentation conflicts with this file:

1. Preserve security invariants.
2. Preserve data integrity.
3. Preserve existing production behavior.
4. Prefer the more restrictive security interpretation.
5. Explain the conflict before making destructive architectural changes.

---

# 2. PRODUCT IDENTITY

## Product

**Qguard Sentinel™**

## Product Description

Qguard Sentinel is an enterprise cybersecurity platform designed to centralize:

- Vulnerability Assessment
- Penetration Testing
- Web Application Security
- API Security
- Mobile Application Security
- SAST
- DAST
- SCA
- Secrets Detection
- Infrastructure Security
- Cloud Security
- Container Security
- Cryptographic Security
- Post-Quantum Cryptography Readiness
- Attack Surface Management
- Vulnerability Management
- Risk Management
- Threat Intelligence
- Digital Forensics
- Incident Response
- Evidence Management
- Security Case Management
- Compliance Mapping
- Security Reporting

## Product Philosophy

Qguard Sentinel must not become a collection of disconnected scanners.

It must operate as a:

> **Unified Security Intelligence, Assessment, Investigation and Response Platform.**

The platform should progressively correlate:

```text
Assets
   ↓
Discovery
   ↓
Security Telemetry
   ↓
Findings
   ↓
Vulnerabilities
   ↓
Risk
   ↓
Threat Intelligence
   ↓
Incidents
   ↓
Evidence
   ↓
Investigation
   ↓
Remediation
   ↓
Verification
   ↓
Reporting
```

---

# 3. CORE ENGINEERING PRINCIPLES

Every implementation MUST follow these principles.

## 3.1 Security First

Security is not an optional feature.

Every feature must consider:

- Authentication
- Authorization
- Input validation
- Output encoding
- Data protection
- Secrets handling
- Logging
- Auditability
- Tenant isolation
- Abuse prevention
- Failure handling

---

## 3.2 Evidence Over Assumptions

Never claim a security condition without supporting evidence.

Bad:

```text
Cloudflare is secure.
```

Good:

```text
TLS 1.3 observed.
HSTS header observed.
Certificate valid until YYYY-MM-DD.
```

Findings must distinguish:

```text
Observed
Verified
Inferred
Not Tested
Unknown
Failed
```

Do not convert "unknown" into "secure."

---

## 3.3 No Fake Security Data

NEVER introduce:

- Random security scores
- Fake vulnerabilities
- Fake scan results
- Random charts
- Hardcoded production metrics
- Artificial scanner success
- Synthetic timestamps
- Fake remediation statistics

Development fixtures are allowed only when explicitly marked as:

```text
DEVELOPMENT / TEST DATA
```

Production dashboards must use real persisted data.

---

# 4. AUTHORIZED SECURITY TESTING ONLY

Qguard Sentinel is intended for authorized defensive security operations.

Security testing functionality must be designed around:

- Explicit targets
- Authorized scopes
- Engagements
- Rules of engagement
- Target ownership
- Scope restrictions
- Rate limits
- Safe defaults
- Audit trails

Never design features that intentionally bypass authorization controls or silently expand testing scope.

Every scanner should understand:

```text
Engagement
Target
Scope
Authorization
Testing Policy
Rate Limit
Execution Mode
```

---

# 5. TECHNOLOGY STACK

## Frontend

Use:

- Next.js
- React
- TypeScript
- Tailwind CSS
- Modern CSS
- shadcn/ui or equivalent component architecture

Use:

- Next.js App Router
- Server Components where appropriate
- Client Components only when required
- Strong TypeScript typing

Avoid unnecessary client-side state.

---

# 6. BACKEND

Use:

- Python
- FastAPI
- Pydantic
- AsyncIO
- PostgreSQL
- Supabase

Backend responsibilities include:

- Authentication integration
- Authorization
- Security APIs
- Scanner orchestration
- Finding normalization
- Risk calculation
- Evidence management
- Case management
- Reporting
- Audit logging
- Background jobs

Do not put security-sensitive business logic exclusively inside React.

---

# 7. DATABASE

Primary database:

**PostgreSQL**

Use Supabase where appropriate for:

- Authentication
- PostgreSQL
- Storage
- Realtime
- Row Level Security

Database requirements:

- Foreign keys
- Constraints
- Indexes
- Transactions
- Migration scripts
- Audit fields
- Soft deletion where appropriate
- Immutable records where required
- Tenant isolation

Never solve relational consistency purely in frontend code.

---

# 8. AUTHENTICATION

Use Supabase Authentication.

Support architecture for:

- Email/password
- OAuth where required
- MFA
- Session management
- Password recovery
- Account recovery
- Session revocation

Never store plaintext passwords.

Never expose:

- Service-role keys
- Database credentials
- Private keys
- API secrets

to browser clients.

---

# 9. AUTHORIZATION / RBAC

Implement server-side authorization.

Example roles:

```text
SUPER_ADMIN
SECURITY_ADMIN
SECURITY_ENGINEER
PENTESTER
SOC_ANALYST
DFIR_ANALYST
INCIDENT_RESPONDER
SECURITY_AUDITOR
REPORT_VIEWER
READ_ONLY
```

Permissions should be granular.

Example:

```text
assets.read
assets.create
assets.update
assets.delete

scans.create
scans.cancel
scans.read

findings.read
findings.update
findings.assign
findings.resolve

evidence.read
evidence.upload
evidence.export

cases.create
cases.update
cases.close

reports.generate
reports.export

administration.manage
```

Never trust a role supplied by the frontend.

---

# 10. MULTI-TENANCY

Design for secure multi-tenancy.

Every tenant-owned record must have:

```text
organization_id
```

where applicable.

Tenant isolation must be enforced at:

1. Database layer
2. API layer
3. Service layer
4. Frontend routing/data layer

Never rely exclusively on UI filtering.

A user must never be able to access another organization's:

- Assets
- Findings
- Scans
- Evidence
- Incidents
- Cases
- Reports
- Intelligence
- Audit records

---

# 11. ARCHITECTURE

Recommended structure:

```text
qguard-sentinel/
│
├── apps/
│   └── web/
│
├── services/
│   ├── api/
│   ├── scanner/
│   ├── workers/
│   ├── dfir/
│   ├── intelligence/
│   └── reporting/
│
├── packages/
│   ├── ui/
│   ├── types/
│   ├── security-models/
│   ├── scanner-sdk/
│   └── config/
│
├── database/
│   ├── migrations/
│   ├── seeds/
│   └── schemas/
│
├── infrastructure/
│   ├── docker/
│   ├── deployment/
│   └── monitoring/
│
├── tests/
│
├── docs/
│
├── scripts/
│
├── CLAUDE.md
├── AGENTS.md
├── README.md
└── .env.example
```

Claude may adapt this structure if the repository already has a superior architecture.

Do not reorganize the entire repository without first understanding the current architecture.

---

# 12. FRONTEND ARCHITECTURE

Use feature-oriented organization.

Example:

```text
src/
├── app/
├── components/
├── features/
│   ├── dashboard/
│   ├── assets/
│   ├── vulnerabilities/
│   ├── scanners/
│   ├── pentest/
│   ├── dfir/
│   ├── incidents/
│   ├── evidence/
│   ├── intelligence/
│   ├── crypto/
│   └── compliance/
├── lib/
├── hooks/
├── types/
└── config/
```

Do not create massive components.

Prefer:

```text
Page
 ↓
Feature Container
 ↓
Feature Components
 ↓
Hooks
 ↓
API Client
 ↓
Backend
```

---

# 13. UI/UX STANDARD

Qguard Sentinel must look like a premium enterprise cybersecurity platform.

Design goals:

- Professional
- Technical
- Modern
- Clean
- High information density
- Excellent visual hierarchy
- Accessible
- Responsive
- Fast

Avoid:

- Excessive gradients
- Generic SaaS appearance
- Excessive animations
- Unnecessary glassmorphism
- Fake cyberpunk effects
- Decorative dashboards that hide important data

Visual hierarchy must prioritize:

```text
Critical Security Information
        ↓
Risk
        ↓
Findings
        ↓
Evidence
        ↓
Recommended Actions
```

---

# 14. GLOBAL NAVIGATION

Primary navigation:

```text
Overview

Assets
Attack Surface
Scanners

Web Security
API Security
Mobile Security
SAST
DAST
SCA
Secrets

Infrastructure
Cloud Security
Container Security

Cryptography
Quantum Security

Vulnerabilities
Risk Management
Penetration Testing

DFIR
Incidents
Cases
Evidence
Timeline

Threat Intelligence

Compliance

Reports

Administration
```

Navigation can evolve as the platform grows.

---

# 15. DESIGN SYSTEM

Create reusable components:

```text
SecurityScore
RiskBadge
SeverityBadge
FindingCard
AssetCard
ScanStatus
ScannerStatus
EvidenceCard
Timeline
FindingTable
AssetTable
RiskHeatmap
AttackSurfaceGraph
SecurityMetric
Chart
FilterBar
Search
Pagination
EmptyState
ErrorState
LoadingState
```

Never recreate the same UI pattern independently across modules.

---

# 16. ACCESSIBILITY

Follow modern accessibility standards.

At minimum:

- Keyboard navigation
- Semantic HTML
- ARIA where necessary
- Sufficient contrast
- Visible focus states
- Screen-reader compatibility
- Accessible dialogs
- Accessible tables
- Accessible charts with textual summaries

---

# 17. ASSET INVENTORY

Asset types:

```text
DOMAIN
SUBDOMAIN
URL
IP_ADDRESS
WEB_APPLICATION
API
MOBILE_APPLICATION
SERVER
DATABASE
CLOUD_RESOURCE
CONTAINER
KUBERNETES_RESOURCE
REPOSITORY
CERTIFICATE
CRYPTOGRAPHIC_KEY
ENDPOINT
SERVICE
```

Asset model should support:

```text
id
organization_id
name
type
environment
criticality
owner
technology
location
status
tags
created_at
updated_at
last_seen_at
```

---

# 18. SCANNER ARCHITECTURE

All scanners MUST be modular.

Use:

```text
Scanner Orchestrator
        │
        ├── Discovery
        ├── Web
        ├── API
        ├── Mobile
        ├── SAST
        ├── DAST
        ├── SCA
        ├── Secrets
        ├── Infrastructure
        ├── Cloud
        ├── Container
        ├── Crypto
        └── Configuration
```

Every scanner must produce a normalized result.

---

# 19. NORMALIZED FINDING MODEL

All security engines should converge on a common model.

Example:

```typescript
interface SecurityFinding {
  id: string;
  organizationId: string;
  assetId: string;
  scannerId: string;

  title: string;
  description: string;

  category: string;
  severity: Severity;

  cve?: string;
  cwe?: string;
  cvss?: number;

  evidence?: EvidenceReference[];

  status: FindingStatus;

  firstSeenAt: string;
  lastSeenAt: string;

  remediation?: Remediation;

  confidence: FindingConfidence;
}
```

Possible confidence:

```text
LOW
MEDIUM
HIGH
CONFIRMED
```

---

# 20. FINDING DEDUPLICATION

This is a critical requirement.

Multiple scanners may detect the same underlying issue.

Do not automatically create independent findings for every scanner result.

Use correlation keys such as:

```text
organization
asset
endpoint
vulnerability class
CVE/CWE
location
technology
evidence fingerprint
```

Maintain:

```text
Raw Scanner Finding
        ↓
Normalization
        ↓
Correlation
        ↓
Deduplication
        ↓
Canonical Finding
```

The system must retain scanner provenance.

---

# 21. WEB SECURITY

Support authorized assessment of:

- Domains
- Subdomains
- URLs
- HTTP services
- TLS
- Certificates
- Security headers
- Cookies
- Authentication
- Authorization
- Session management
- Input validation
- Injection classes
- XSS
- SSRF
- CSRF
- Access-control weaknesses
- Misconfiguration
- API exposure
- Sensitive information exposure

Map findings where possible to:

- OWASP
- CWE
- CVE
- CVSS

---

# 22. MOBILE SECURITY

Support:

- APK
- AAB
- IPA architecture
- Android manifest
- Permissions
- Components
- Signing
- Certificates
- Network security configuration
- Embedded secrets
- URLs
- API endpoints
- Cryptography
- Local storage
- Debug configuration
- Exported components
- Dependencies

Map findings to:

- OWASP MASVS
- OWASP MASTG

---

# 23. API SECURITY

Support:

- REST
- GraphQL
- WebSocket assessment architecture
- OpenAPI import
- Endpoint inventory
- Authentication
- Authorization
- Input validation
- Rate limiting
- Schema validation
- Sensitive data exposure

---

# 24. SAST

Support languages through pluggable analyzers.

Initial architecture should support:

```text
JavaScript
TypeScript
Python
Java
Kotlin
Swift
Go
C
C++
C#
PHP
```

Findings should include:

```text
Repository
File
Line
Column
Code Context
Rule
Severity
CWE
Remediation
```

---

# 25. SCA

Analyze:

- Direct dependencies
- Transitive dependencies
- Package versions
- Known vulnerabilities
- License information
- Dependency health
- Supply-chain risks

Support ecosystem-specific manifests.

---

# 26. SECRET DETECTION

Detect:

- API keys
- Tokens
- Passwords
- Private keys
- Cloud credentials
- Database credentials
- JWT secrets
- Certificates

Never display complete secrets unnecessarily.

Use redaction:

```text
sk_live_****************1234
```

---

# 27. CRYPTOGRAPHIC SECURITY

Maintain an explicit cryptographic inventory.

Track:

```text
Algorithm
Key Size
Protocol
Usage
Asset
Certificate
Library
Location
Risk
```

Correctly distinguish:

### KEM

```text
ML-KEM
```

### Digital Signatures

```text
ML-DSA
SLH-DSA
Ed25519
ECDSA
RSA-PSS
```

### Symmetric

```text
AES-256-GCM
```

### Hashing

```text
SHA-256
SHA-384
SHA-512
SHA-3
```

Never misclassify algorithms.

---

# 28. POST-QUANTUM SECURITY

Provide a dedicated quantum readiness engine.

Track:

```text
Classical Algorithm
Hybrid Algorithm
PQC Algorithm
Asset
Protocol
Certificate
Key
Migration Status
Risk
```

Support architecture for:

```text
ML-KEM-768
ML-KEM-1024
ML-DSA-65
ML-DSA-87
SLH-DSA
X25519 + ML-KEM
```

Do not assume PQC deployment merely because a library supports a PQC algorithm.

Require observable evidence.

---

# 29. VULNERABILITY MANAGEMENT

Statuses:

```text
OPEN
CONFIRMED
FALSE_POSITIVE
ACCEPTED_RISK
IN_PROGRESS
RESOLVED
VERIFIED
REOPENED
```

Every vulnerability should support:

- Assignment
- Comments
- Evidence
- Remediation
- SLA
- Verification
- History

---

# 30. RISK ENGINE

Risk must be explainable.

Potential factors:

```text
Severity
Exploitability
Asset Criticality
Exposure
Business Impact
Data Sensitivity
Authentication Requirement
Threat Intelligence
Exploit Availability
Compensating Controls
```

Never create opaque scores.

Always provide the contributing factors.

---

# 31. PENETRATION TESTING

Support:

```text
Engagement
Scope
Rules of Engagement
Targets
Testing Phases
Findings
Evidence
Notes
POCs
Remediation
Retesting
Final Report
```

Never allow testing to silently exceed engagement scope.

---

# 32. DFIR

DFIR must be evidence-centric.

Support:

- Evidence acquisition
- Evidence hashing
- Chain of custody
- Artifact analysis
- Timeline
- IOC extraction
- File analysis
- Memory analysis architecture
- Disk image analysis architecture
- Network capture analysis
- Log analysis
- Mobile artifacts

---

# 33. CHAIN OF CUSTODY

Evidence records should include:

```text
Evidence ID
Case ID
SHA-256
SHA-512 where required
Collected At
Collected By
Source
Original Name
Size
MIME Type
Custodian
Access History
Integrity Status
```

Evidence should be immutable wherever practical.

Never silently modify original evidence.

---

# 34. INCIDENT RESPONSE

Incident lifecycle:

```text
DETECTED
↓
TRIAGED
↓
INVESTIGATING
↓
CONTAINMENT
↓
ERADICATION
↓
RECOVERY
↓
CLOSED
```

Support:

- Severity
- Timeline
- Assets
- IOCs
- Evidence
- Investigators
- Tasks
- Communications
- Root cause
- Remediation

---

# 35. THREAT INTELLIGENCE

Support:

```text
IP
DOMAIN
URL
HASH
EMAIL
MALWARE
THREAT ACTOR
CAMPAIGN
TECHNIQUE
```

Map to:

- MITRE ATT&CK
- CVE
- CWE
- CAPEC

External intelligence sources must be adapter-based.

---

# 36. COMPLIANCE

Build reusable control mappings.

Support architecture for:

```text
OWASP
ASVS
MASVS
MASTG
CWE
CVE
CVSS
MITRE ATT&CK
NIST CSF
NIST 800-53
NIST 800-61
NIST SSDF
CIS Controls
ISO 27001
```

Do not hardcode compliance logic into individual scanners.

---

# 37. REPORTING

Reports must be generated from persisted data.

Never fabricate report statistics.

Supported formats:

```text
PDF
DOCX
JSON
CSV
```

Report types:

```text
Executive
Technical
Vulnerability
Pentest
Web
Mobile
API
DFIR
Incident
Compliance
Cryptographic
Quantum Readiness
```

---

# 38. REAL-TIME ARCHITECTURE

Use:

- WebSockets
- SSE
- Event-driven processing

for:

- Scan progress
- Job status
- Finding updates
- Incident changes
- Evidence processing
- Report generation

Avoid unnecessary polling.

---

# 39. BACKGROUND JOBS

Long-running operations must never block HTTP requests.

Examples:

```text
Scan
SAST
DAST
Mobile analysis
Evidence processing
Report generation
Threat feed ingestion
Risk recalculation
Correlation
```

Job lifecycle:

```text
QUEUED
RUNNING
COMPLETED
FAILED
CANCELLED
```

Failures must be visible.

Never convert failures into successful results.

---

# 40. ERROR HANDLING

Never swallow exceptions.

Bad:

```python
try:
    scan()
except:
    pass
```

Good:

```python
try:
    scan()
except Exception as exc:
    logger.exception("Scanner execution failed")
    raise
```

Frontend must distinguish:

```text
Loading
Success
Empty
Partial
Failed
Unauthorized
Forbidden
```

Do not show empty data as "secure."

---

# 41. LOGGING

Use structured logging.

Every security operation should provide enough context for investigation.

Avoid logging:

- Passwords
- Tokens
- API keys
- Private keys
- Full session cookies
- Sensitive evidence

Use correlation IDs:

```text
request_id
scan_id
job_id
finding_id
case_id
incident_id
```

---

# 42. AUDIT LOGGING

Audit important actions:

```text
LOGIN
LOGOUT
ASSET_CREATED
ASSET_UPDATED
ASSET_DELETED
SCAN_STARTED
SCAN_COMPLETED
SCAN_FAILED
FINDING_CREATED
FINDING_UPDATED
FINDING_RESOLVED
EVIDENCE_UPLOADED
EVIDENCE_ACCESSED
CASE_CREATED
CASE_UPDATED
REPORT_GENERATED
REPORT_EXPORTED
PERMISSION_CHANGED
```

Audit logs must be protected against unauthorized modification.

---

# 43. FILE UPLOAD SECURITY

Never trust uploaded files.

Validate:

- MIME
- Extension
- Size
- Hash
- Content type
- Storage location

Use isolated processing environments for potentially malicious artifacts.

Never execute uploaded content inside the main API process.

---

# 44. SSRF PROTECTION

Any feature that fetches remote URLs must implement SSRF protection.

Protect against:

```text
127.0.0.1
localhost
Private IPv4
Private IPv6
Link-local
Cloud metadata endpoints
Internal DNS
DNS rebinding
Redirect-based SSRF
```

Do not assume URL validation alone is sufficient.

---

# 45. COMMAND EXECUTION

Security scanners may require external tools.

Never directly interpolate user-controlled strings into shell commands.

Prefer:

```python
subprocess.run(
    [binary, argument1, argument2],
    shell=False
)
```

Use:

- Allowlisted binaries
- Argument validation
- Execution timeouts
- Resource limits
- Sandboxing
- Separate worker processes

---

# 46. SCANNER SAFETY

Scanner execution must support:

```text
Authorization
Scope
Rate Limit
Timeout
Concurrency
User Agent
Network Policy
Execution Mode
```

Potential modes:

```text
PASSIVE
SAFE
ACTIVE
CONTROLLED
```

Default to the safest appropriate mode.

---

# 47. DATABASE SAFETY

Never:

- Drop production tables casually
- Rewrite migrations destructively
- Delete user data without authorization
- Disable RLS to "fix" a query
- Expose service-role credentials

Before destructive schema changes:

1. Inspect dependencies.
2. Create migration.
3. Validate affected data.
4. Test migration.
5. Provide rollback strategy.

---

# 48. ENVIRONMENT MANAGEMENT

Required:

```text
.env.example
.env.local
.env.production
```

Never commit real secrets.

Environment variables must be validated at application startup.

Example:

```text
DATABASE_URL
SUPABASE_URL
SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY
```

Service-role credentials must remain server-side.

---

# 49. DEPENDENCY MANAGEMENT

Before adding a dependency:

1. Determine whether existing dependencies already provide the functionality.
2. Verify maintenance status.
3. Check licensing.
4. Check known vulnerabilities.
5. Evaluate bundle/runtime impact.
6. Document why it is required.

Do not add packages unnecessarily.

---

# 50. TESTING REQUIREMENTS

Every meaningful feature should have appropriate tests.

## Frontend

- Unit
- Component
- Integration
- E2E

## Backend

- Unit
- API
- Database
- Authentication
- Authorization

## Security

Test:

```text
IDOR
Authentication bypass
Authorization bypass
SQL Injection
XSS
CSRF
SSRF
Path Traversal
Command Injection
File Upload
Rate Limiting
Tenant Isolation
```

---

# 51. E2E VERIFICATION

Before declaring a feature complete:

```text
Build
↓
Lint
↓
Type Check
↓
Unit Tests
↓
Integration Tests
↓
E2E
↓
Security Validation
↓
Production Build
```

Never claim success without verification.

---

# 52. NO FALSE COMPLETION

Do not say:

```text
Implemented successfully.
```

unless the implementation has actually been verified.

If blocked:

```text
BLOCKED
```

Explain:

- What failed
- Why
- What was attempted
- What remains

---

# 53. DEVELOPMENT WORKFLOW

For every substantial task:

## Step 1 — Understand

Inspect:

- Repository
- Existing architecture
- Relevant components
- Database
- APIs
- Tests
- Environment

## Step 2 — Plan

Identify:

- Files affected
- Dependencies
- Risks
- Migration requirements
- Testing requirements

## Step 3 — Implement

Make the smallest coherent change.

## Step 4 — Verify

Run:

- Typecheck
- Lint
- Tests
- Build
- Relevant security checks

## Step 5 — Review

Check:

- Security
- Performance
- UX
- Data integrity
- Regression risk

---

# 54. CHANGE DISCIPLINE

Do not rewrite large sections of the application unnecessarily.

Prefer:

```text
Small
Focused
Tested
Reversible
```

changes.

Before refactoring, determine:

- Why the refactor is necessary.
- What depends on the existing behavior.
- Whether the refactor changes public APIs.
- Whether migration is required.

---

# 55. SOURCE OF TRUTH

Every important domain must have one canonical source.

Examples:

```text
Assets → Asset service
Findings → Finding service
Risk → Risk engine
Evidence → Evidence service
Incidents → Incident service
Cases → Case service
Reports → Reporting service
```

Do not independently calculate the same security metric in multiple frontend components.

---

# 56. SECURITY METRICS

Metrics must be reproducible.

Example:

```text
Critical Vulnerabilities
=
COUNT(canonical_findings WHERE severity = CRITICAL AND status != RESOLVED)
```

Not:

```text
Math.random()
```

Every major metric should have a documented definition.

---

# 57. DATA LINEAGE

Important security metrics should be traceable:

```text
Dashboard Metric
      ↓
Query
      ↓
Canonical Data
      ↓
Finding
      ↓
Evidence
      ↓
Scanner Result
      ↓
Source
```

The user should be able to drill down from a metric to the underlying evidence where appropriate.

---

# 58. SECURITY FINDING STATES

Do not confuse:

```text
Not Tested
```

with:

```text
Secure
```

Use explicit states:

```text
NOT_TESTED
TESTING
OBSERVED
CONFIRMED
NOT_APPLICABLE
FAILED
ERROR
UNKNOWN
```

---

# 59. PARTIAL SCAN RESULTS

If some scanners succeed and others fail:

Do not mark the entire assessment as successful.

Example:

```text
Assessment: PARTIAL

Web Scanner: Completed
TLS Scanner: Completed
Certificate Scanner: Failed
DNS Scanner: Not Executed
```

This distinction is critical.

---

# 60. SCAN HISTORY

Maintain historical scans.

Support:

- Comparison
- Trend analysis
- Regression detection
- New findings
- Resolved findings
- Reopened findings
- Risk changes

Example:

```text
Previous Scan
      ↓
Current Scan
      ↓
Diff Engine
      ↓
New / Resolved / Changed / Persistent
```

---

# 61. PERFORMANCE

Design for:

```text
Thousands of users
Hundreds of thousands of assets
Millions of findings
Large repositories
Large mobile binaries
Large evidence collections
Concurrent scans
```

Use:

- Pagination
- Indexes
- Caching
- Background processing
- Streaming
- Async operations
- Query optimization

Never load millions of rows into a browser.

---

# 62. OBSERVABILITY

Production architecture should support:

```text
Logs
Metrics
Traces
Health Checks
Job Monitoring
Scanner Monitoring
Database Monitoring
```

Use correlation IDs throughout the system.

---

# 63. HEALTH CHECKS

Provide endpoints such as:

```text
/health
/health/live
/health/ready
```

Health checks should distinguish:

```text
Application
Database
Queue
Storage
External Dependencies
```

---

# 64. DEPLOYMENT

Architecture must support:

```text
Development
Staging
Production
```

Never assume localhost-only deployment.

Configuration must be environment-specific.

---

# 65. CI/CD

CI should run:

```text
Install
Lint
Typecheck
Unit Tests
Integration Tests
Security Checks
Build
E2E
```

Production deployments should require successful verification.

---

# 66. DOCUMENTATION

Maintain:

```text
README.md
ARCHITECTURE.md
SECURITY.md
DATABASE.md
API.md
DEPLOYMENT.md
DFIR.md
SCANNER_ARCHITECTURE.md
THREAT_MODEL.md
```

Documentation must reflect actual implementation.

---

# 67. THREAT MODELING

For major features, consider:

```text
Assets
Trust Boundaries
Threat Actors
Attack Surface
Threats
Mitigations
Residual Risk
```

Prioritize:

- Authentication
- Evidence
- Scanner execution
- File uploads
- Remote network access
- Secrets
- Multi-tenancy
- Administrative functions

---

# 68. SECURE DEFAULTS

Defaults must favor security.

Examples:

```text
Authentication → Required
Authorization → Deny by default
Scanner → Safe mode
File upload → Restricted
Network access → Restricted
Logging → Enabled
Audit → Enabled
TLS → Required
Sensitive data → Redacted
```

---

# 69. UI DATA INTEGRITY

Never display:

```text
100% Secure
```

unless that exact statement is technically justified.

Prefer:

```text
Assessment Coverage: 84%
14 Assets Not Yet Assessed
3 Scanner Errors
```

The UI should communicate uncertainty honestly.

---

# 70. AI FEATURES

If AI is introduced later:

AI must not become the authoritative source of security truth.

AI may:

- Summarize
- Correlate
- Explain
- Recommend
- Prioritize
- Generate reports
- Assist investigations

AI must not fabricate:

- Evidence
- Vulnerabilities
- IOC data
- Scan results
- Compliance status
- Security metrics

AI-generated content should be clearly distinguishable from verified security telemetry.

---

# 71. AI SECURITY

AI integrations must consider:

- Prompt injection
- Data exfiltration
- Sensitive context leakage
- Tool abuse
- Excessive permissions
- Untrusted documents
- Malicious evidence
- Retrieval poisoning

AI tools should use least privilege.

---

# 72. DFIR DATA PROTECTION

Forensic data may contain extremely sensitive information.

Apply:

- Strict authorization
- Encryption
- Access auditing
- Evidence integrity
- Retention controls
- Secure deletion policies
- Export controls

Never expose evidence globally by default.

---

# 73. PENTEST DATA PROTECTION

Penetration-testing artifacts may contain:

- Credentials
- Tokens
- Exploit evidence
- Sensitive endpoints
- Internal IPs
- Application secrets

Treat them as sensitive security data.

---

# 74. MOBILE ARTIFACT PROTECTION

Mobile application uploads must be isolated and access-controlled.

Do not expose uploaded:

- APKs
- AABs
- IPAs
- Decompiled source
- Credentials
- Certificates

through predictable public URLs.

---

# 75. DATABASE MIGRATION RULE

Every schema change must have a migration.

Never manually modify production schemas without a migration record.

Migrations must be:

- Repeatable
- Reviewable
- Tested
- Versioned

---

# 76. GIT DISCIPLINE

Use meaningful commits.

Examples:

```text
feat(scanner): add certificate assessment engine
fix(auth): enforce organization authorization
feat(dfir): add evidence chain of custody
fix(findings): deduplicate scanner results
refactor(risk): centralize risk calculation
```

Never commit:

- Secrets
- Tokens
- Credentials
- Large binaries
- Production evidence
- Local databases

---

# 77. BRANCHING

Use feature branches for significant work.

Example:

```text
main
develop
feature/web-scanner
feature/dfir-evidence
feature/mobile-analysis
fix/finding-deduplication
```

Never perform destructive experiments directly on production branches.

---

# 78. CODE QUALITY

Prefer:

- Strong typing
- Small functions
- Clear names
- Explicit errors
- Testable services
- Dependency injection where appropriate
- Separation of concerns

Avoid:

- God classes
- God components
- Massive API routes
- Hidden global state
- Circular dependencies
- Copy/paste implementations

---

# 79. FRONTEND STATE

Use server state and local state appropriately.

Avoid storing sensitive security data unnecessarily in:

```text
localStorage
sessionStorage
browser URLs
client-side logs
```

---

# 80. SECRETS

Never expose secrets in:

- Source code
- Git
- Client bundles
- Logs
- Error messages
- URLs
- Screenshots
- Reports unless explicitly required

---

# 81. API SECURITY

Every API endpoint must answer:

```text
Who is calling?
Are they authenticated?
Are they authorized?
Which organization do they belong to?
Which resource are they accessing?
Is the operation allowed?
```

Never rely on:

```text
if user.role == "admin"
```

alone.

Resource ownership must also be validated.

---

# 82. RESOURCE OWNERSHIP

For every resource:

```text
Request
 ↓
Authenticated User
 ↓
Organization
 ↓
Resource Ownership
 ↓
Permission
 ↓
Action
```

---

# 83. RATE LIMITING

Apply rate limits to:

- Authentication
- Password reset
- Scan creation
- Scanner APIs
- Evidence upload
- Report generation
- Expensive operations

Limits should be configurable.

---

# 84. AUDITABLE SCANNING

Every scan must record:

```text
Scan ID
User
Organization
Target
Scope
Scanner Version
Configuration
Start Time
End Time
Status
Findings
Errors
```

---

# 85. SCANNER VERSIONING

Scanner engines must be versioned.

Example:

```text
web-scanner@1.4.2
crypto-scanner@2.0.1
mobile-scanner@1.1.0
```

This enables reproducibility.

---

# 86. FINDING REPRODUCIBILITY

A finding should retain enough information to understand:

```text
What was detected?
Where?
When?
By which scanner?
Using which scanner version?
Against which asset?
With which configuration?
What evidence supported it?
```

---

# 87. REPORT REPRODUCIBILITY

Reports should reference:

```text
Assessment ID
Scan IDs
Finding IDs
Report generation timestamp
Report version
```

---

# 88. SECURITY TOOL INTEGRATION

External security tools must be integrated through adapters.

Never tightly couple the entire application to a single scanner.

Example:

```text
ScannerAdapter
    ├── ToolAAdapter
    ├── ToolBAdapter
    └── InternalScannerAdapter
```

Normalize outputs into Qguard Sentinel's internal schema.

---

# 89. TOOL FAILURE

External tool failure must never produce a fake successful scan.

Example:

```text
Scanner: FAILED
Tool: <tool>
Exit Code: <code>
Error: <message>
```

---

# 90. NETWORK SAFETY

Network scanners must enforce:

- Scope
- Rate limits
- Timeouts
- Concurrency limits
- Network restrictions
- Logging

Never assume an IP address is authorized merely because it is reachable.

---

# 91. PRODUCTION RULE

Before production:

```text
No debug mode
No development credentials
No mock findings
No test accounts
No unsecured admin endpoints
No exposed secrets
No permissive CORS
No disabled RLS
No unsafe defaults
```

---

# 92. BACKUP & RECOVERY

Design for:

- Database backups
- Evidence backups
- Configuration backups
- Disaster recovery
- Restore testing

Critical evidence must have appropriate redundancy.

---

# 93. DATA RETENTION

Different data classes may require different retention:

```text
Audit Logs
Evidence
Findings
Reports
Incidents
Scanner Results
Threat Intelligence
```

Retention policies must be configurable.

---

# 94. DELETE OPERATIONS

Destructive operations require:

- Authorization
- Confirmation
- Audit event

For critical evidence:

Prefer immutable/retention-controlled behavior over immediate deletion.

---

# 95. SECURITY REVIEW CHECKLIST

Before merging a significant security feature:

```text
[ ] Authentication verified
[ ] Authorization verified
[ ] Tenant isolation verified
[ ] Input validation verified
[ ] Output handling verified
[ ] Secrets handling reviewed
[ ] Logging reviewed
[ ] Audit logging implemented
[ ] Error handling verified
[ ] Rate limiting considered
[ ] SSRF considered
[ ] File upload security considered
[ ] Command execution security considered
[ ] Database queries reviewed
[ ] Tests added
[ ] Documentation updated
```

---

# 96. FEATURE COMPLETION CHECKLIST

A feature is NOT complete until:

```text
[ ] Architecture reviewed
[ ] Database changes implemented
[ ] API implemented
[ ] Authorization implemented
[ ] UI implemented
[ ] Loading states implemented
[ ] Empty states implemented
[ ] Error states implemented
[ ] Audit events implemented
[ ] Tests implemented
[ ] Security reviewed
[ ] Typecheck passes
[ ] Lint passes
[ ] Build passes
[ ] E2E verified
[ ] Documentation updated
```

---

# 97. DEBUGGING PROCEDURE

When something fails:

1. Reproduce.
2. Capture the exact error.
3. Identify the responsible layer.
4. Inspect logs.
5. Inspect network requests.
6. Inspect database state.
7. Determine root cause.
8. Implement the smallest safe fix.
9. Add regression coverage.
10. Re-run verification.

Never hide symptoms with UI workarounds.

---

# 98. WHEN REQUIREMENTS ARE AMBIGUOUS

Do not invent critical security behavior.

If ambiguity affects:

- Authentication
- Authorization
- Data integrity
- Evidence
- Scanner scope
- Destructive operations
- Cryptography
- Tenant isolation

stop and clarify.

For low-risk UI decisions, use established project conventions.

---

# 99. NO ARCHITECTURAL DRIFT

Before creating a new service, database table, scanner, or abstraction ask:

```text
Does an existing component already solve this?
```

If yes:

Reuse or extend it.

If no:

Create a clearly defined new component.

---

# 100. NO DUPLICATE SECURITY ENGINES

Before implementing a new scanner:

Search the repository for:

```text
scanner
engine
finding
assessment
crypto
vulnerability
risk
```

Determine whether equivalent functionality already exists.

Do not create parallel implementations accidentally.

---

# 101. SECURITY DATA CONTRACTS

Changes to shared models require special care.

When changing:

```text
Finding
Asset
Scan
Evidence
Incident
Case
Risk
```

inspect:

- Backend
- Frontend
- Database
- Reports
- Tests
- Integrations

before modifying the contract.

---

# 102. BACKWARD COMPATIBILITY

Prefer backward-compatible changes.

When breaking an API:

1. Document the breaking change.
2. Version the API.
3. Update consumers.
4. Add migration strategy.
5. Test old/new behavior where necessary.

---

# 103. PERFORMANCE REGRESSION

When changing:

- Queries
- Scanners
- Dashboards
- Finding correlation
- Reports

consider performance impact.

Do not fix correctness by introducing unacceptable performance degradation.

---

# 104. OBSERVABILITY OF SCANNERS

Each scanner should expose:

```text
Status
Version
Last Run
Execution Count
Success Count
Failure Count
Average Duration
Current Job
```

Scanner failures should be operationally visible.

---

# 105. SECURITY DASHBOARD TRUTH MODEL

Dashboard metrics should be derived from canonical services.

Example:

```text
Finding Service
       ↓
Risk Engine
       ↓
Dashboard
       ↓
Reports
```

Not:

```text
Scanner A → Dashboard
Scanner B → Dashboard
Scanner C → Dashboard
```

This prevents contradictory metrics.

---

# 106. CRITICAL SECURITY RULE

Never make the dashboard appear healthier than the underlying evidence indicates.

If data is missing:

```text
Data unavailable
```

If scanning failed:

```text
Assessment incomplete
```

If an asset was not tested:

```text
Not assessed
```

Never silently substitute:

```text
Secure
```

---

# 107. AI / AUTOMATION SAFETY

Automated remediation must be:

- Explicit
- Authorized
- Auditable
- Reversible where possible
- Scoped

Never automatically modify production security controls without appropriate authorization.

---

# 108. REMEDIATION

Each finding may provide:

```text
Explanation
Impact
Recommended Fix
References
Verification Method
```

Do not claim remediation is complete until verification confirms it.

Lifecycle:

```text
Detected
↓
Remediated
↓
Retested
↓
Verified
```

---

# 109. SECURITY SCORE

If security scoring is used:

The formula must be documented.

Users should be able to understand:

```text
Score
↓
Factors
↓
Findings
↓
Assets
↓
Evidence
```

Avoid opaque "AI-generated" scores.

---

# 110. ENTERPRISE UX

Every major module must support:

```text
Search
Filter
Sort
Pagination
Export
Bulk Actions
Details
History
Audit
```

where appropriate.

---

# 111. RESPONSIVE DESIGN

Support:

```text
Desktop
Laptop
Tablet
Mobile
```

Desktop is the primary security operations environment.

Do not sacrifice desktop information density to create a mobile layout.

---

# 112. DARK/LIGHT MODE

Support:

```text
Dark
Light
System
```

Security severity must not rely solely on color.

Example:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Use text/icons in addition to color.

---

# 113. PERFORMANCE UX

Every long-running operation needs:

```text
Progress
Current Stage
Elapsed Time
Status
Errors
Cancel
```

Never leave users staring at an unexplained spinner.

---

# 114. FINAL DEVELOPMENT COMMANDMENT

Before writing code, understand the system.

Before changing architecture, understand dependencies.

Before changing security logic, understand the threat model.

Before changing data, understand ownership.

Before claiming success, verify.

Before declaring a finding, require evidence.

Before declaring security, verify coverage.

Before deploying, test.

---

# 115. MASTER QUALITY GATE

Qguard Sentinel is considered production-ready only when:

```text
Security
        +
Correctness
        +
Evidence
        +
Data Integrity
        +
Observability
        +
Performance
        +
Scalability
        +
Usability
        +
Testing
        +
Documentation
```

meet enterprise requirements.

The objective is not to produce the largest number of features.

The objective is to produce a **trustworthy cybersecurity platform whose results security professionals can rely upon.**

---

# 116. FINAL PRINCIPLE

## Qguard Sentinel must always prefer:

**Truth over appearance.**

**Evidence over assumptions.**

**Security over convenience.**

**Correctness over speed.**

**Traceability over opacity.**

**Modularity over technical debt.**

**Verification over claims.**

**User control over automation.**

**Defensive security over uncontrolled exploitation.**

Build accordingly.