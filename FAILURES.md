# QGuard Helix - FAILURES.md

Status: ACTIVE INVESTIGATIONS
Last Updated: {{timestamp}}

---

# PURPOSE

This document tracks:

* Open failures
* Active investigations
* Unresolved defects
* Architectural weaknesses
* Recurring operational issues

A failure remains in this file until:

* Root cause is identified
* Fix is implemented
* Verification passes
* Evidence is collected

Only then may it be closed.

---

# FAILURE LIFECYCLE

OPEN
→ INVESTIGATING
→ ROOT CAUSE IDENTIFIED
→ FIX IN PROGRESS
→ FIX IMPLEMENTED
→ VERIFIED
→ CLOSED

Never close a failure without evidence.

---

# FAILURE SEVERITY

P0 - Critical

* Security compromise
* Data loss
* System outage
* Authentication failure

---

P1 - High

* Major feature broken
* Incorrect security posture
* Incorrect migration guidance

---

P2 - Medium

* Incorrect telemetry
* Dashboard inconsistencies
* Performance degradation

---

P3 - Low

* Cosmetic issues
* Minor UX issues
* Non-critical warnings

---

# DISCOVERY FAILURES

## FAILURE-DISC-001

Severity:
P1

Status:
OPEN

Module:
Discovery

Issue:

Duplicate vulnerabilities appear across discovery modules.

Observed In:

* PQC Scanner
* Crypto Exposure
* Assets & CBOM

Impact:

Inflated vulnerability counts.

Possible Causes:

* Missing deduplication
* Duplicate asset correlation
* Multiple scanner sources

Investigation Owner:

Discovery Engineer

Evidence:

Pending

Created:

2026-XX-XX

---

## FAILURE-DISC-002

Severity:
P1

Status:
OPEN

Module:
Discovery

Issue:

Asset counts differ between pages.

Impact:

Inconsistent readiness calculations.

Possible Causes:

* Different query sources
* Aggregation mismatch
* Caching issue

Investigation Owner:

Database Reviewer

Evidence:

Pending

---

## FAILURE-DISC-003

Severity:
P1

Status:
OPEN

Module:
Discovery

Issue:

Discovery findings may not always map to evidence.

Impact:

Reduced confidence.

Investigation Owner:

Security Auditor

Evidence:

Pending

---

# TELEMETRY FAILURES

## FAILURE-TEL-001

Severity:
P1

Status:
OPEN

Module:
Telemetry

Issue:

KPI cards display inconsistent values.

Impact:

Operational confusion.

Possible Causes:

* Multiple data sources
* Unsynchronized SSE streams
* Stale cache

Investigation Owner:

Telemetry Validator

Evidence:

Pending

---

## FAILURE-TEL-002

Severity:
P1

Status:
OPEN

Module:
Telemetry

Issue:

Dashboard values cannot always be traced to backend sources.

Impact:

Loss of trust.

Investigation Owner:

API Reviewer

Evidence:

Pending

---

## FAILURE-TEL-003

Severity:
P2

Status:
OPEN

Module:
Telemetry

Issue:

Freshness indicators missing.

Impact:

Users cannot determine data age.

Investigation Owner:

Frontend Engineer

Evidence:

Pending

---

# PQAUTH FAILURES

## FAILURE-PQAUTH-001

Severity:
P1

Status:
OPEN

Issue:

Identity migration readiness may not reflect actual asset state.

Impact:

Incorrect migration guidance.

Investigation Owner:

PQAuth Architect

Evidence:

Pending

---

## FAILURE-PQAUTH-002

Severity:
P1

Status:
OPEN

Issue:

JWT telemetry requires validation against backend evidence.

Impact:

Potential mismatch.

Investigation Owner:

Telemetry Validator

Evidence:

Pending

---

# TRUST FABRIC FAILURES

## FAILURE-TRUST-001

Severity:
P1

Status:
OPEN

Issue:

Trust relationships may be incomplete.

Impact:

Incorrect blast radius calculations.

Investigation Owner:

Trust Engineer

Evidence:

Pending

---

## FAILURE-TRUST-002

Severity:
P2

Status:
OPEN

Issue:

Certificate ownership mapping incomplete.

Impact:

Delayed remediation.

Investigation Owner:

Discovery Engineer

Evidence:

Pending

---

# QKMS FAILURES

## FAILURE-QKMS-001

Severity:
P1

Status:
OPEN

Issue:

Key ownership visibility incomplete.

Impact:

Lifecycle management risk.

Investigation Owner:

QKMS Engineer

Evidence:

Pending

---

# QUANTUM VAULT FAILURES

## FAILURE-VAULT-001

Severity:
P0

Status:
OPEN

Issue:

Recovery workflow requires enterprise validation.

Impact:

Potential recovery failure.

Investigation Owner:

Security Auditor

Evidence:

Pending

---

## FAILURE-VAULT-002

Severity:
P1

Status:
OPEN

Issue:

Recovery key lifecycle requires review.

Impact:

Recovery architecture uncertainty.

Investigation Owner:

Vault Engineer

Evidence:

Pending

---

# AGENT FAILURES

## FAILURE-AGENT-001

Severity:
P1

Status:
OPEN

Issue:

Agents may report completion without evidence.

Impact:

False positive success reports.

Investigation Owner:

Code Reviewer

Evidence:

Pending

---

## FAILURE-AGENT-002

Severity:
P1

Status:
OPEN

Issue:

Agents may bypass verification workflows.

Impact:

Quality degradation.

Investigation Owner:

Security Auditor

Evidence:

Pending

---

# ARCHITECTURE FAILURES

## FAILURE-ARCH-001

Severity:
P1

Status:
OPEN

Issue:

Potential duplication between modules.

Impact:

Maintenance complexity.

Investigation Owner:

Architecture Reviewer

Evidence:

Pending

---

## FAILURE-ARCH-002

Severity:
P1

Status:
OPEN

Issue:

Source-of-truth ownership unclear for some KPIs.

Impact:

Conflicting metrics.

Investigation Owner:

Telemetry Validator

Evidence:

Pending

---

# PRODUCTION FAILURES

## FAILURE-PROD-001

Severity:
P0

Status:
OPEN

Issue:

Mock data may still exist in production paths.

Impact:

False visibility.

Investigation Owner:

Security Auditor

Evidence:

Pending

---

## FAILURE-PROD-002

Severity:
P1

Status:
OPEN

Issue:

Evidence collection not enforced platform-wide.

Impact:

Verification gaps.

Investigation Owner:

Compliance Reviewer

Evidence:

Pending

---

# RECURRING FAILURE TRACKER

Failures occurring more than once:

| Failure ID | Occurrences | Status |
| ---------- | ----------- | ------ |
| None       | 0           | N/A    |

---

# ESCALATION RULES

Immediately Escalate:

* Same failure twice
* Security findings
* Data integrity issues
* Production incidents
* Authentication failures

---

# CLOSURE REQUIREMENTS

A failure may only be closed when:

1. Root cause documented
2. Fix implemented
3. Verification passed
4. Evidence collected
5. Reviewer approved

Required Evidence:

* Test Results
* Screenshots
* Logs
* API Validation
* Database Validation
* Security Review

---

# CLOSED FAILURES

Move completed failures here.

Maintain:

* Root Cause
* Fix
* Evidence
* Lessons Learned

Never delete closed failures.

They become future lessons.

---

END OF DOCUMENT
