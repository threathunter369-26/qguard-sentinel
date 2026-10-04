# QGuard Helix - STATE.md

Last Updated: {{timestamp}}

---

# PROJECT OVERVIEW

Project Name:
QGuard Helix™

Mission:
Discover, assess, orchestrate, and secure enterprise cryptographic infrastructures against current and future quantum threats.

Platform Vision:
Provide organizations with a unified Quantum Cyber Defense platform capable of:

* Discovering cryptographic assets
* Mapping trust relationships
* Assessing quantum risk exposure
* Simulating PQC migrations
* Executing remediation workflows
* Monitoring runtime cryptographic telemetry
* Maintaining crypto agility

---

# CURRENT DEVELOPMENT PHASE

Current Phase:

[ ] Foundation
[ ] Discovery
[ ] Intelligence
[ ] Migration
[ ] Trust Fabric
[ ] PQAuth
[ ] QKMS
[ ] Quantum Vault
[ ] Compliance
[ ] Production Hardening

Active Module:

Discovery

Current Goal:

Verify and harden all Discovery module telemetry, APIs, dashboards, KPI cards, charts, and SSE streams using real asset intelligence.

---

# VERIFIED FACTS

Only place confirmed information here.

## Architecture

Verified:

* Frontend uses React + Vite + TypeScript
* Backend uses Express API
* Supabase handles Auth
* Supabase handles Database
* Supabase handles Storage
* Supabase handles Realtime
* SSE used for live telemetry updates

## Cryptographic Standards

Verified:

* ML-KEM (FIPS 203)
* ML-DSA (FIPS 204)
* SLH-DSA (FIPS 205)
* AES-256-GCM
* SHA3-256
* HKDF-SHA3-256

## Security Standards

Verified:

* NIST PQC Standards
* CNSA 2.0 Guidance
* NIST CSF
* ISO 27001
* SOC2
* PCI DSS

---

# ACTIVE MODULE STATUS

## OVERVIEW

Status:
IN PROGRESS

Verification:
PENDING

Issues:

* KPI synchronization validation pending
* Real telemetry validation pending

---

## DISCOVERY

Status:
ACTIVE

Submodules:

* PQC Scanner
* CBOM Explorer
* Crypto Exposure
* Assets & CBOM
* Shadow Crypto
* Harvest Now Decrypt Later

Verification Status:

[ ] APIs Verified
[ ] SSE Verified
[ ] Charts Verified
[ ] KPI Cards Verified
[ ] Supabase Queries Verified
[ ] Real Data Verified
[ ] UI Reviewed

---

## INTELLIGENCE

Status:
PLANNED

Submodules:

* Drift Detection
* Vulnerabilities
* Runtime Crypto Intelligence
* Behavioral Analytics
* Telemetry Correlation
* Quantum Risk Scoring

---

## PQAUTH

Status:
IN DEVELOPMENT

Submodules:

* Identity Discovery
* Trust Graph
* JWT Intelligence
* Digital Twin
* Runtime Identity Telemetry

---

## TRUST FABRIC

Status:
PLANNED

Submodules:

* Trust State Discovery
* Trust Chain Analyzer
* Vendor Trust Analysis
* Dependency Mapping

---

## QKMS

Status:
PLANNED

Submodules:

* Key Inventory
* Key Lifecycle
* Rotation Engine
* PQC Readiness

---

## QUANTUM VAULT

Status:
ACTIVE

Submodules:

* Quantum-Safe Encryption
* Recovery Key System
* Secure Sync
* Vault Explorer
* 3D Quantum Vault

---

# OPEN FAILURES

Document all unresolved issues.

---

## Failure ID: F-001

Module:
Discovery

Issue:
Duplicate vulnerabilities displayed across pages.

Status:
Open

Hypothesis:
Assets not being deduplicated before aggregation.

Next Action:
Verify asset correlation pipeline.

---

## Failure ID: F-002

Module:
Telemetry

Issue:
KPI values inconsistent between modules.

Status:
Open

Hypothesis:
Different data sources feeding cards.

Next Action:
Trace SSE source and API responses.

---

# LESSONS LEARNED

## Discovery

* Never display mock telemetry in production dashboards.
* All KPI cards must map to a verified backend source.
* Asset counts should originate from a single authoritative source.

## Migration

* Migration plans must be based on discovered assets.
* Never estimate readiness without evidence.

## Telemetry

* SSE streams require health validation.
* Dashboard cards must fail safely if telemetry is unavailable.

---

# KNOWN FAILURE MODES

## Discovery

Failure Mode:
Duplicate asset records.

Mitigation:
Deduplicate using asset fingerprint.

---

Failure Mode:
Telemetry drift.

Mitigation:
Cross-check API against SSE feed.

---

Failure Mode:
Stale KPI cards.

Mitigation:
Implement freshness timestamps.

---

# ARCHITECTURAL DECISIONS

Decision ID:
AD-001

Decision:
React + Vite selected as frontend architecture.

Reason:
Performance and maintainability.

Status:
Accepted

---

Decision ID:
AD-002

Decision:
Supabase selected for backend services.

Reason:
Unified auth, database, storage, and realtime.

Status:
Accepted

---

# ANTI-PATTERNS

NEVER:

* Use fake telemetry in production
* Display placeholder KPI values
* Create charts without verified data
* Mark verification complete without evidence
* Remove validation checks to pass verification
* Hardcode readiness scores
* Bypass security review
* Ignore failed telemetry streams

---

# AGENT DIRECTIVES

All agents MUST:

1. Read STATE.md before starting.
2. Read applicable Skill files.
3. Verify before claiming success.
4. Record failures.
5. Record verified facts.
6. Record lessons learned.
7. Update progress before exiting.

---

# LOOP RULES

Stop Conditions:

ALL GREEN

OR

5 cycles completed

OR

Same failure twice consecutively

OR

Regression detected

Never declare success without verifier evidence.

---

# NEXT PRIORITIES

Priority 1

Discovery Verification

* APIs
* KPI Cards
* SSE Streams
* Charts
* Telemetry

Priority 2

PQAuth Hardening

Priority 3

Trust Fabric Development

Priority 4

QKMS Implementation

Priority 5

Production Readiness Review

---

# SESSION HANDOFF

Last Completed:

---

Current Work:

---

Next Action:

---

Blocked By:

---

Owner:

---

Timestamp:

---
