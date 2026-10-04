# Qguard Sentinel
# AGENTS.md

## AI AGENT OPERATING, DEVELOPMENT & VERIFICATION PROTOCOL

---

# 1. PURPOSE

This document defines how AI coding agents must operate when developing, modifying, debugging, testing, reviewing, or deploying **Qguard Sentinel**.

Qguard Sentinel is an enterprise cybersecurity platform covering:

- Vulnerability Assessment
- Penetration Testing
- Web Security
- API Security
- Mobile Security
- SAST
- DAST
- SCA
- Secrets Detection
- Infrastructure Security
- Cloud Security
- Container Security
- Cryptographic Security
- Post-Quantum Cryptography Assessment
- Attack Surface Management
- Vulnerability Management
- Risk Management
- Threat Intelligence
- Digital Forensics
- Incident Response
- Evidence Management
- Compliance
- Security Reporting

The agent must treat this repository as a **security-critical application**.

Do not optimize for merely producing code.

Optimize for:

> **Correctness + Security + Evidence + Maintainability + Verification**

---

# 2. AUTHORITY HIERARCHY

When operating inside the repository, follow this priority:

```text
System Instructions
        ↓
Developer Instructions
        ↓
CLAUDE.md
        ↓
AGENTS.md
        ↓
Repository Documentation
        ↓
Feature Documentation
        ↓
User Task
        ↓
Agent Assumptions
```

Never override a higher-level security requirement because a lower-level task appears to request it.

If requirements conflict:

1. Preserve security.
2. Preserve data integrity.
3. Preserve tenant isolation.
4. Preserve existing production functionality.
5. Ask for clarification when the conflict materially affects security or architecture.

---

# 3. CORE AGENT PRINCIPLES

The agent MUST follow these principles.

## 3.1 Inspect Before Modifying

Never immediately start editing files.

First understand:

- Repository structure
- Application architecture
- Existing implementation
- Dependencies
- Database schema
- API structure
- Authentication
- Authorization
- Existing tests
- Existing scanner engines
- Existing shared components

---

## 3.2 Reuse Before Creating

Before creating a:

- Component
- Hook
- Service
- API
- Scanner
- Database table
- Utility
- Type
- Security engine

search the repository for an existing implementation.

Prefer:

```text
Reuse
↓
Extend
↓
Refactor
↓
Create New
```

Do not create duplicate functionality.

---

# 4. REQUIRED WORKFLOW

Every meaningful task must follow:

```text
UNDERSTAND
    ↓
INSPECT
    ↓
PLAN
    ↓
IMPLEMENT
    ↓
TEST
    ↓
SECURITY REVIEW
    ↓
BUILD
    ↓
E2E VERIFY
    ↓
FINAL REVIEW
    ↓
REPORT
```

Never skip verification simply because the change appears small.

---

# 5. PHASE 1 — UNDERSTAND

Before implementation, determine:

### What is being requested?

Identify:

- User objective
- Functional requirements
- Security requirements
- UI requirements
- API requirements
- Data requirements
- Integration requirements

Determine whether the task changes:

```text
Frontend
Backend
Database
Authentication
Authorization
Scanner logic
DFIR
Reporting
Deployment
Infrastructure
```

---

# 6. PHASE 2 — REPOSITORY INSPECTION

Inspect the relevant repository structure.

Look for:

```text
package.json
pyproject.toml
requirements.txt
docker-compose.yml
Dockerfile
.env.example
next.config.*
tsconfig.json
tailwind.config.*
supabase/
migrations/
src/
app/
components/
services/
tests/
docs/
```

Also inspect:

- Existing routes
- Existing API clients
- Database models
- Existing hooks
- Existing scanners
- Existing security utilities
- Existing tests

Do not assume the repository structure from documentation alone.

---

# 7. PHASE 3 — DEPENDENCY ANALYSIS

Before adding dependencies:

1. Search existing dependencies.
2. Determine whether the functionality already exists.
3. Check package compatibility.
4. Check maintenance status.
5. Check security implications.
6. Evaluate bundle/runtime impact.

Do not install dependencies simply because they are convenient.

---

# 8. PHASE 4 — ARCHITECTURAL IMPACT

Before changing architecture, identify:

```text
Affected Components
Affected Services
Affected APIs
Affected Database Tables
Affected Types
Affected Tests
Affected Reports
Affected Security Controls
```

For significant changes, create a short implementation plan.

Example:

```text
1. Add database migration
2. Add backend service
3. Add API endpoint
4. Add frontend hook
5. Add UI
6. Add tests
7. Run security verification
8. Run E2E
```

---

# 9. PHASE 5 — IMPLEMENTATION

Implement the smallest complete solution.

Do not:

- Rewrite unrelated modules
- Rename unrelated files
- Replace frameworks unnecessarily
- Perform broad refactors
- Remove functionality without authorization
- Introduce temporary hacks

Unless the task specifically requires a broader architectural change.

---

# 10. CHANGE BOUNDARIES

Stay within the requested scope.

If you discover an unrelated problem:

```text
DO NOT silently modify it.
```

Instead:

```text
Document:
- Location
- Problem
- Security impact
- Recommended follow-up
```

Only fix it if it blocks the requested feature or creates a serious security risk.

---

# 11. SECURITY-CRITICAL CHANGES

The following require additional review:

- Authentication
- Authorization
- RLS
- Tenant isolation
- Evidence
- Cryptography
- Scanner execution
- Command execution
- File uploads
- Network access
- Secrets
- Admin functionality
- Database migrations
- Data deletion
- Export functionality

Never treat these as ordinary UI changes.

---

# 12. AUTHORIZATION VERIFICATION

For every protected backend endpoint verify:

```text
Authentication
     ↓
User
     ↓
Organization
     ↓
Resource Ownership
     ↓
Permission
     ↓
Action
```

Never trust:

```text
userId
organizationId
role
assetId
caseId
findingId
```

provided directly by the client.

Validate ownership server-side.

---

# 13. TENANT ISOLATION

Whenever modifying database queries, ask:

> Can this query accidentally return another organization's data?

Check:

- SELECT
- INSERT
- UPDATE
- DELETE
- RPC
- Storage
- Realtime
- Reports
- Search
- Export

Tenant isolation must be preserved.

---

# 14. DATABASE CHANGES

Never modify production schemas manually.

Create migrations.

Before a migration:

1. Inspect current schema.
2. Identify dependencies.
3. Determine migration impact.
4. Create migration.
5. Test migration.
6. Verify rollback/recovery strategy where applicable.

Never casually:

```sql
DROP TABLE
TRUNCATE
DROP COLUMN
```

without explicit authorization and impact analysis.

---

# 15. FRONTEND DEVELOPMENT

Before modifying a page:

Inspect:

- Existing layout
- Navigation
- Components
- Data hooks
- API calls
- Loading states
- Error states
- Permissions

Do not create a second implementation of an existing pattern.

---

# 16. UI STATE REQUIREMENTS

Every data-driven page should account for:

```text
Loading
Success
Empty
Partial
Error
Unauthorized
Forbidden
```

Never represent:

```text
No Data
```

as:

```text
Secure
```

---

# 17. DASHBOARD INTEGRITY

Never fabricate:

- Counts
- Charts
- Scores
- Vulnerabilities
- Scan results
- Risk metrics
- Trends
- Security posture

If data is unavailable:

```text
Data unavailable
```

If assessment is incomplete:

```text
Assessment incomplete
```

If a scanner failed:

```text
Scanner failed
```

---

# 18. SECURITY FINDINGS

Every finding should have provenance.

Verify:

```text
Asset
Scanner
Scanner Version
Timestamp
Evidence
Confidence
Severity
Status
```

Do not create a confirmed vulnerability from an unverified observation unless the detection rule explicitly supports that classification.

---

# 19. FINDING DEDUPLICATION

Before adding a new finding pipeline:

Inspect existing:

- Finding normalization
- Correlation
- Deduplication
- Fingerprinting

Avoid duplicate vulnerabilities caused by multiple scanners.

Preferred flow:

```text
Raw Finding
     ↓
Normalize
     ↓
Fingerprint
     ↓
Correlate
     ↓
Canonical Finding
     ↓
Risk Engine
```

---

# 20. SCANNER DEVELOPMENT

Every scanner must define:

```text
Purpose
Input
Scope
Authorization
Execution Mode
Timeout
Rate Limit
Output
Evidence
Failure State
Version
```

Scanner output must be normalized.

---

# 21. SCANNER FAILURE RULE

Never convert:

```text
FAILED
```

into:

```text
PASSED
```

Never convert:

```text
NOT TESTED
```

into:

```text
SECURE
```

Never hide scanner errors.

---

# 22. PARTIAL RESULTS

If an assessment is incomplete:

Example:

```text
Web Scanner ........ COMPLETED
TLS Scanner ........ COMPLETED
Certificate Scanner  FAILED
DNS Scanner ........ NOT EXECUTED
```

Overall result:

```text
PARTIAL
```

Not:

```text
SECURE
```

---

# 23. SCANNER SCOPE

Before executing a scanner verify:

```text
Target
Scope
Authorization
Testing Policy
```

Never silently expand scope.

If scope is ambiguous and the action could affect external systems:

STOP and request clarification.

---

# 24. COMMAND EXECUTION

When invoking security tools:

Prefer argument arrays.

Example:

```python
subprocess.run(
    [binary, arg1, arg2],
    shell=False,
    timeout=timeout
)
```

Never construct shell commands from untrusted user input.

Use:

- Allowlisted binaries
- Validated arguments
- Timeouts
- Resource limits
- Isolated workers
- Logging

---

# 25. FILE PROCESSING

Never trust uploaded files.

Validate:

```text
Size
MIME
Extension
Hash
Content
Origin
```

Potentially malicious files must be processed in isolated environments.

Never execute uploaded files inside the primary API process.

---

# 26. SSRF

Any feature that fetches a remote URL must consider:

- Loopback
- Private IPs
- Link-local addresses
- Cloud metadata services
- Internal DNS
- IPv6 private ranges
- DNS rebinding
- Redirects

SSRF protection must be enforced server-side.

---

# 27. SECRETS

Never expose secrets.

Do not place credentials in:

- Source code
- Git
- Frontend bundles
- Logs
- URLs
- Error messages

Never expose Supabase service-role credentials to the browser.

---

# 28. CRYPTOGRAPHY

When modifying cryptographic functionality:

STOP and inspect the existing crypto architecture.

Do not invent cryptographic algorithms.

Prefer established libraries and standards.

Clearly distinguish:

```text
KEM
Signature
Symmetric Encryption
Hash
KDF
Protocol
Certificate
Key Management
```

Do not classify ML-KEM as a signature algorithm.

Do not classify ML-DSA as an encryption algorithm.

---

# 29. DFIR RULES

For forensic functionality:

Evidence integrity takes priority over convenience.

Every evidence object should have:

```text
Hash
Timestamp
Source
Collector
Case
Custodian
Access History
```

Never silently modify original evidence.

---

# 30. CHAIN OF CUSTODY

When implementing evidence access or transfer:

Record:

```text
Who
What
When
Why
From
To
Action
Hash
```

Examples:

```text
COLLECTED
IMPORTED
ACCESSED
COPIED
EXPORTED
ANALYZED
SEALED
RELEASED
```

---

# 31. INCIDENT RESPONSE

Incident workflows should preserve history.

Do not overwrite important incident state without creating an audit trail.

Prefer:

```text
Event History
```

over silently mutating historical records.

---

# 32. AI FEATURES

AI-generated content must never become authoritative security evidence.

AI may:

- Summarize
- Explain
- Correlate
- Recommend
- Classify
- Generate drafts

AI must not fabricate:

- Findings
- Evidence
- Threat intelligence
- Vulnerabilities
- Compliance results
- Security metrics

AI-generated recommendations should be distinguishable from verified telemetry.

---

# 33. TESTING STRATEGY

After implementation, determine the appropriate tests.

Minimum:

```text
Typecheck
Lint
Unit Tests
```

For API/database changes:

```text
Integration Tests
```

For user workflows:

```text
E2E Tests
```

For security-sensitive functionality:

```text
Security Tests
```

---

# 34. REQUIRED VERIFICATION

Before declaring completion:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

Use the repository's actual scripts when they differ.

For Python:

```bash
ruff check .
pytest
```

or the project's configured equivalents.

Never invent commands.

First inspect `package.json`, `pyproject.toml`, Makefiles, or other project configuration.

---

# 35. E2E VERIFICATION

When a browser-accessible feature changes:

Verify:

1. Application starts.
2. Page loads.
3. Authentication works.
4. Relevant UI renders.
5. API requests succeed.
6. Data appears correctly.
7. Loading states work.
8. Error states work.
9. No unexpected console errors.
10. No obvious broken interactions.

---

# 36. VISUAL VERIFICATION

For significant UI changes inspect:

- Layout
- Spacing
- Typography
- Responsive behavior
- Tables
- Charts
- Dialogs
- Navigation
- Empty states
- Error states
- Dark/light mode

Do not assume the UI is correct merely because TypeScript compiles.

---

# 37. REGRESSION TESTING

After changing shared components or services, test dependent functionality.

Examples:

Changing:

```text
Finding model
```

requires checking:

```text
Dashboard
Findings
Risk
Reports
Scanner results
Exports
```

Changing:

```text
Authentication
```

requires checking:

```text
Login
Logout
Protected routes
API authorization
User profile
RBAC
Tenant isolation
```

---

# 38. BUILD VERIFICATION

A successful build is necessary but insufficient.

Verify:

```text
Build
Runtime
API
Database
Authentication
Critical UI
```

---

# 39. ERROR INVESTIGATION

When something fails:

```text
1. Reproduce
2. Capture exact error
3. Identify layer
4. Inspect logs
5. Inspect network
6. Inspect database state
7. Identify root cause
8. Fix
9. Add regression test
10. Re-run verification
```

Do not mask errors.

---

# 40. NO WORKAROUNDS THAT HIDE ROOT CAUSES

Bad:

```text
if error:
    return []
```

when the underlying operation failed.

Instead:

```text
Expose the failure state.
```

The user must know that data could not be retrieved.

---

# 41. PERFORMANCE VERIFICATION

For large data operations check:

- Query performance
- Pagination
- Indexes
- Memory usage
- API response size
- Browser rendering
- Scanner concurrency
- Background job behavior

Never load an entire large dataset into the browser unnecessarily.

---

# 42. LOGGING VERIFICATION

Ensure important failures produce useful structured logs.

Logs should contain relevant:

```text
request_id
job_id
scan_id
asset_id
finding_id
case_id
```

but must not contain secrets.

---

# 43. SECURITY REVIEW

After implementation ask:

### Authentication

- Can unauthenticated users access this?
- Should they?

### Authorization

- Can another user access this?
- Can another tenant access this?

### Input

- Is user input validated?

### Output

- Could sensitive information leak?

### Database

- Are queries scoped correctly?

### Files

- Can malicious files be uploaded?

### Network

- Could this create SSRF?

### Commands

- Could this create command injection?

### Secrets

- Could credentials leak?

### Audit

- Is the action auditable?

---

# 44. FINAL DIFF REVIEW

Before completion inspect the final changes.

Check:

```text
New Files
Modified Files
Deleted Files
Database Changes
Dependencies
Environment Variables
Tests
Documentation
```

Remove:

- Debug logs
- Temporary code
- TODO hacks
- Commented-out experiments
- Test credentials
- Unused imports
- Unused dependencies

---

# 45. GIT DIFF REVIEW

Always inspect the effective diff for meaningful changes.

Look for:

```text
Unexpected changes
Large unrelated modifications
Secret exposure
Generated files
Accidental deletions
Debug code
```

---

# 46. DOCUMENTATION UPDATE

If implementation changes architecture, update relevant documentation.

At minimum consider:

```text
README
ARCHITECTURE
API
DATABASE
SECURITY
SCANNER_ARCHITECTURE
DFIR
DEPLOYMENT
```

Do not allow documentation to describe behavior that no longer exists.

---

# 47. COMPLETION CRITERIA

A task is complete only when:

```text
[ ] Requirement understood
[ ] Repository inspected
[ ] Architecture reviewed
[ ] Existing functionality reused
[ ] Implementation completed
[ ] Authentication reviewed
[ ] Authorization reviewed
[ ] Tenant isolation reviewed
[ ] Database reviewed
[ ] Error states implemented
[ ] Tests added
[ ] Lint passed
[ ] Typecheck passed
[ ] Build passed
[ ] E2E verified where applicable
[ ] Security review completed
[ ] Documentation updated where necessary
[ ] Final diff reviewed
```

---

# 48. REPORTING FORMAT

At the end of every significant task, provide a concise report.

Use:

```text
## Implementation Summary

Implemented:
- ...

Modified:
- ...

Added:
- ...

Database:
- ...

Security:
- ...

Tests:
- ...

Verification:
- ...

Known Issues:
- ...

Recommended Follow-up:
- ...
```

Never claim a test passed unless it actually ran successfully.

---

# 49. BLOCKED STATE

If implementation cannot safely continue:

```text
STATUS: BLOCKED
```

Explain:

```text
Blocker:
Reason:
Evidence:
What was attempted:
What is required:
```

Do not fabricate completion.

---

# 50. UNKNOWN STATE

When information is unavailable:

Use:

```text
UNKNOWN
```

Do not infer:

```text
SECURE
```

from lack of evidence.

---

# 51. PRODUCTION SAFETY

Never execute destructive operations against production unless explicitly authorized.

Examples:

```text
Database deletion
Data migration
Evidence deletion
Production scanner execution
Mass remediation
Credential rotation
Infrastructure modification
```

require explicit authorization and appropriate safeguards.

---

# 52. NO SILENT DESTRUCTIVE ACTIONS

Never:

- Delete user data
- Delete evidence
- Drop tables
- Reset databases
- Remove authentication
- Disable RLS
- Disable security controls
- Remove audit logging

without explicit authorization.

---

# 53. NO FAKE IMPLEMENTATION

Do not create buttons that appear functional but do nothing.

Do not create:

```text
"Scan"
```

that merely changes UI state.

Do not create:

```text
"Generate Report"
```

that produces fake data.

Do not create:

```text
"Remediate"
```

that does not actually perform or queue the operation.

If functionality is not implemented:

```text
Mark it as unavailable or incomplete.
```

---

# 54. NO MOCK DATA IN PRODUCTION FLOWS

Development mock data must be isolated.

Never allow:

```text
mock findings
mock scanner results
mock risk scores
```

to leak into production paths.

---

# 55. SECURITY TOOL EXECUTION MODEL

Prefer:

```text
Web/API
   ↓
Job Queue
   ↓
Worker
   ↓
Sandboxed Scanner
   ↓
Raw Result
   ↓
Normalizer
   ↓
Correlation
   ↓
Finding Store
   ↓
Risk Engine
   ↓
Dashboard
```

Do not execute expensive or potentially dangerous tools directly inside HTTP request handlers.

---

# 56. SCANNER JOB LIFECYCLE

Every scanner job should expose:

```text
CREATED
QUEUED
RUNNING
PROCESSING
COMPLETED
FAILED
CANCELLED
```

Where possible, record:

```text
started_at
completed_at
duration
error
scanner_version
```

---

# 57. SCANNER OBSERVABILITY

Track:

```text
Execution count
Success count
Failure count
Average runtime
Current status
Last execution
Last error
```

This allows administrators to determine whether the platform itself is functioning correctly.

---

# 58. DATA CONSISTENCY

If two parts of the UI show different values for the same metric:

Do not patch the UI independently.

Find the source-of-truth problem.

Correct the underlying service/query/model.

---

# 59. SECURITY SCORE CONSISTENCY

Risk/security scores must be calculated centrally.

Do not independently calculate:

```text
Dashboard Score
Asset Score
Report Score
Executive Score
```

unless they intentionally represent different documented metrics.

---

# 60. REPORT DATA CONSISTENCY

Reports must consume the same canonical security data as the dashboard.

Avoid:

```text
Dashboard → Query A
Report → Query B
```

when both represent the same metric.

Prefer:

```text
Canonical Security Service
       ├── Dashboard
       ├── Reports
       ├── API
       └── Analytics
```

---

# 61. API CONTRACTS

When changing API responses:

Inspect:

```text
Frontend consumers
Other services
Tests
Reports
Integrations
```

Do not casually remove or rename fields.

---

# 62. TYPE SAFETY

Avoid:

```typescript
any
```

unless genuinely unavoidable.

Prefer:

```typescript
unknown
```

with validation.

Shared security data models must remain strongly typed.

---

# 63. PYTHON TYPE SAFETY

Use:

- Pydantic models
- Type hints
- Explicit return types
- Validation

Avoid dynamically structured dictionaries where a typed model is appropriate.

---

# 64. DATABASE QUERY SAFETY

Use parameterized queries.

Never construct SQL with string interpolation from user input.

Validate:

- Filters
- Sort fields
- Pagination
- Search values

Allowlist dynamic SQL identifiers where necessary.

---

# 65. SEARCH SECURITY

Search endpoints must enforce:

- Authentication
- Tenant scope
- Permission
- Query limits
- Pagination

Never expose global search across organizations.

---

# 66. EXPORT SECURITY

Exports may contain highly sensitive data.

Every export must enforce:

```text
Authorization
Tenant Scope
Data Scope
Audit Logging
```

Avoid generating publicly accessible files.

---

# 67. REPORT SECURITY

Reports may contain:

- Vulnerabilities
- Internal infrastructure
- Credentials
- Security architecture
- Evidence

Treat reports as sensitive information.

---

# 68. NOTIFICATIONS

Notifications must not leak secrets.

Avoid including:

```text
Passwords
Tokens
Private keys
Full exploit evidence
Sensitive forensic content
```

in email/push notifications.

---

# 69. OBSERVABILITY WITHOUT DATA LEAKAGE

Logs and telemetry must never become a secondary data-exfiltration channel.

Redact sensitive values.

---

# 70. SECURITY REGRESSION PROTECTION

Whenever fixing a security bug:

Add a regression test demonstrating:

```text
Before → Vulnerable
After → Protected
```

where practical.

---

# 71. VULNERABILITY FIXES

When fixing a vulnerability:

1. Reproduce.
2. Confirm root cause.
3. Implement fix.
4. Add regression test.
5. Test adjacent flows.
6. Verify no bypass remains.

---

# 72. PENTEST FINDINGS

Do not confuse:

```text
Potential
```

with:

```text
Confirmed
```

unless evidence supports confirmation.

---

# 73. DFIR FINDINGS

Forensic conclusions should preserve:

```text
Observed Evidence
Analysis
Inference
Confidence
```

Do not present an inference as directly observed fact.

---

# 74. THREAT INTELLIGENCE

External intelligence must preserve provenance.

Track:

```text
Source
Collection Time
Indicator
Confidence
Expiration
Context
```

Do not treat third-party intelligence as unquestionable truth.

---

# 75. COMPLIANCE

Compliance mappings must be evidence-driven.

Do not mark:

```text
COMPLIANT
```

simply because a feature exists.

Use:

```text
IMPLEMENTED
PARTIALLY_IMPLEMENTED
NOT_IMPLEMENTED
NOT_ASSESSED
```

where appropriate.

---

# 76. QUANTUM SECURITY

Quantum-readiness conclusions must be based on observed cryptographic inventory and documented assumptions.

Do not claim:

```text
Quantum Safe
```

without sufficient evidence.

Distinguish:

```text
PQC Capable
PQC Enabled
Hybrid Enabled
PQC Verified
Classical Only
Unknown
```

---

# 77. RELEASE GATE

Before release:

```text
Build
✓

Tests
✓

Security Review
✓

Database Migration
✓

E2E
✓

Deployment Configuration
✓

Documentation
✓
```

If any critical gate fails:

```text
RELEASE BLOCKED
```

---

# 78. INCIDENT / SECURITY BUG MODE

If a serious security issue is discovered during development:

Prioritize:

```text
Containment
↓
Evidence Preservation
↓
Root Cause
↓
Fix
↓
Regression Test
↓
Verification
```

Do not conceal the issue simply to complete the requested feature.

---

# 79. AGENT BEHAVIOR

The agent should be:

- Precise
- Conservative with security
- Evidence-driven
- Explicit about uncertainty
- Efficient
- Modular
- Test-oriented
- Transparent about failures

The agent should NOT:

- Pretend success
- Invent data
- Invent tests
- Hide failures
- Make destructive changes silently
- Disable security controls for convenience
- Create fake implementations
- Assume authorization

---

# 80. WHEN TO STOP AND ASK

Stop and request clarification when:

- Authorization is unclear.
- A destructive operation is requested without sufficient scope.
- Production data may be affected.
- Tenant isolation is uncertain.
- A security boundary must be weakened.
- Evidence may be destroyed.
- Cryptographic behavior is ambiguous.
- A scanner may exceed authorized scope.
- Requirements conflict materially.

Do not ask unnecessary questions for straightforward implementation details.

---

# 81. FINAL AGENT CHECK

Before saying:

```text
DONE
```

verify:

```text
Requirement implemented
        +
Correct architecture
        +
Correct data
        +
Secure authorization
        +
Tests passing
        +
Build passing
        +
E2E verified
        +
No obvious regressions
        +
Documentation synchronized
```

Only then report completion.

---

# 82. FINAL RESPONSE FORMAT

For substantial work, end with:

```text
## Qguard Sentinel Implementation Report

### Status
COMPLETED / PARTIAL / BLOCKED

### Implemented
- ...

### Files Changed
- ...

### Database Changes
- ...

### Security Changes
- ...

### Tests Executed
- ...

### Verification
- Lint: PASS/FAIL
- Typecheck: PASS/FAIL
- Unit Tests: PASS/FAIL
- Integration Tests: PASS/FAIL
- Build: PASS/FAIL
- E2E: PASS/FAIL

### Known Issues
- ...

### Follow-up
- ...
```

Never report PASS without actually executing the relevant verification.

---

# 83. THE QGUARD SENTINEL AGENT PRINCIPLE

The agent must remember:

> **You are not merely writing software. You are engineering a security platform.**

Therefore:

**Inspect before changing.**

**Understand before implementing.**

**Verify before claiming.**

**Preserve evidence.**

**Protect data.**

**Respect authorization boundaries.**

**Never fabricate security results.**

**Never hide failures.**

**Never trade security for convenience.**

**Build for the next security engineer who will have to trust your work.**

---

# END OF AGENTS.md