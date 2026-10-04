# QGuard Helix - VERIFIED_FACTS.md

Status: AUTHORITATIVE
Last Updated: {{timestamp}}

---

# PURPOSE

This document contains verified facts about QGuard Helix.

Everything in this file must be:

* Verified
* Reproducible
* Evidence-backed

Nothing in this file should be speculative.

If uncertain:

DO NOT ADD IT.

---

# VERIFICATION REQUIREMENTS

A fact may only be added if one or more of the following exists:

* Source code inspection
* API validation
* Database validation
* Telemetry validation
* Configuration validation
* Security review
* Documentation review
* Direct testing
* Evidence report

Every fact should include evidence.

---

# PLATFORM FACTS

## PF-001

Fact:

QGuard Helix is built using React, Vite, and TypeScript.

Verified By:

Architecture Review

Evidence:

src/main.tsx
src/App.tsx

Status:

VERIFIED

---

## PF-002

Fact:

QGuard Helix uses an Express backend API.

Verified By:

Architecture Review

Evidence:

src/api-server/

Status:

VERIFIED

---

## PF-003

Fact:

Supabase is the primary platform backend service.

Responsibilities:

* Authentication
* PostgreSQL Database
* Storage
* Realtime

Status:

VERIFIED

---

# AUTHENTICATION FACTS

## AUTH-001

Fact:

Authentication is handled by Supabase Auth.

Status:

VERIFIED

---

## AUTH-002

Fact:

Authentication tokens use JWT.

Status:

VERIFIED

---

## AUTH-003

Fact:

Database access is protected through RLS policies.

Status:

VERIFIED

---

# DATABASE FACTS

## DB-001

Fact:

Supabase PostgreSQL is the authoritative database.

Status:

VERIFIED

---

## DB-002

Fact:

Frontend dashboards are not authoritative.

Database is authoritative.

Status:

VERIFIED

---

## DB-003

Fact:

All production KPIs must originate from backend-controlled sources.

Status:

VERIFIED

---

# TELEMETRY FACTS

## TEL-001

Fact:

Telemetry should flow through backend services before dashboard display.

Status:

VERIFIED

---

## TEL-002

Fact:

Telemetry without evidence is not considered valid.

Status:

VERIFIED

---

## TEL-003

Fact:

Dashboard values must be traceable to a source.

Status:

VERIFIED

---

# DISCOVERY FACTS

## DISC-001

Fact:

Discovery is responsible for identifying cryptographic assets.

Status:

VERIFIED

---

## DISC-002

Fact:

Discovery findings require evidence.

Status:

VERIFIED

---

## DISC-003

Fact:

Discovery must not generate synthetic findings.

Status:

VERIFIED

---

# CBOM FACTS

## CBOM-001

Fact:

CBOM stands for Cryptography Bill of Materials.

Status:

VERIFIED

---

## CBOM-002

Fact:

CBOM inventories cryptographic algorithms, keys, certificates, libraries, and dependencies.

Status:

VERIFIED

---

# PQC FACTS

## PQC-001

Fact:

ML-KEM is NIST's standardized key encapsulation mechanism.

Reference:

FIPS 203

Status:

VERIFIED

---

## PQC-002

Fact:

ML-DSA is NIST's standardized digital signature algorithm.

Reference:

FIPS 204

Status:

VERIFIED

---

## PQC-003

Fact:

SLH-DSA is NIST's standardized stateless hash-based signature algorithm.

Reference:

FIPS 205

Status:

VERIFIED

---

## PQC-004

Fact:

AES-256-GCM remains quantum-resistant against known quantum attacks.

Status:

VERIFIED

---

## PQC-005

Fact:

SHA3-256 is approved for quantum-safe architectures.

Status:

VERIFIED

---

# QUANTUM VAULT FACTS

## VAULT-001

Fact:

Quantum Vault uses client-side encryption.

Status:

VERIFIED

---

## VAULT-002

Fact:

Server-side components must not possess plaintext user encryption keys.

Status:

VERIFIED

---

## VAULT-003

Fact:

Recovery keys should never be transmitted to the server.

Status:

VERIFIED

---

# SECURITY FACTS

## SEC-001

Fact:

Private keys must never be stored in plaintext.

Status:

VERIFIED

---

## SEC-002

Fact:

Recovery keys must never be logged.

Status:

VERIFIED

---

## SEC-003

Fact:

Mock telemetry must never be displayed as production telemetry.

Status:

VERIFIED

---

## SEC-004

Fact:

Verification evidence is required before feature completion.

Status:

VERIFIED

---

# TRUST FABRIC FACTS

## TRUST-001

Fact:

Trust Fabric maps relationships between identities, certificates, workloads, systems, and services.

Status:

VERIFIED

---

## TRUST-002

Fact:

Trust relationships can impact migration blast radius.

Status:

VERIFIED

---

# MIGRATION FACTS

## MIG-001

Fact:

Migration readiness must be based on discovered assets.

Status:

VERIFIED

---

## MIG-002

Fact:

Migration planning without asset discovery is incomplete.

Status:

VERIFIED

---

# AGENT FACTS

## AGENT-001

Fact:

Agents are builders.

Status:

VERIFIED

---

## AGENT-002

Fact:

Verifiers are responsible for validation.

Status:

VERIFIED

---

## AGENT-003

Fact:

Builders must not approve their own work.

Status:

VERIFIED

---

# EVIDENCE FACTS

## EVID-001

Fact:

No feature is considered complete without evidence.

Status:

VERIFIED

---

## EVID-002

Fact:

Verification requires documented proof.

Status:

VERIFIED

---

# KNOWN VERIFIED DATA SOURCES

Approved Sources:

* Supabase Database
* Express API
* Scanner Telemetry
* SSE Streams
* Audit Logs
* Migration Logs
* Verification Reports

Unapproved Sources:

* Mock Data
* Placeholder Data
* Estimated Values
* AI Assumptions

---

# FACT ADDITION RULES

Before adding a new fact:

1. Verify it.
2. Collect evidence.
3. Document source.
4. Confirm reproducibility.
5. Add fact.

If evidence is missing:

DO NOT ADD.

---

# FACT REMOVAL RULES

A fact may be removed only if:

* Evidence is proven incorrect
* Architecture changed
* Technology replaced
* Verification failed

Document removal in DECISIONS.md

---

END OF DOCUMENT
