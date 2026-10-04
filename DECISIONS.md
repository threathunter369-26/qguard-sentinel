# QGuard Helix - DECISIONS.md

Status: AUTHORITATIVE
Last Updated: {{timestamp}}

---

# PURPOSE

This document records significant architectural, security, operational, and product decisions.

Purpose:

* Preserve reasoning
* Prevent repeated debates
* Maintain architectural consistency
* Explain why decisions were made

This document records:

* What was decided
* Why it was decided
* Alternatives considered
* Expected impact

---

# DECISION STATUS

PROPOSED

Decision under review.

---

ACCEPTED

Decision approved and active.

---

SUPERSEDED

Replaced by a newer decision.

---

REJECTED

Decision evaluated and rejected.

---

# DECISION TEMPLATE

Decision ID

Title

Date

Status

Context

Decision

Alternatives Considered

Rationale

Expected Impact

Risks

Evidence

---

# ARCHITECTURE DECISIONS

## AD-001

Title

Frontend Architecture

Date

2026-XX-XX

Status

ACCEPTED

Decision

Use React + Vite + TypeScript.

Alternatives Considered

* Next.js
* Angular
* Vue

Rationale

* Fast development
* Excellent TypeScript support
* Lightweight deployment model
* Strong ecosystem

Expected Impact

Improved maintainability.

---

## AD-002

Title

Backend Architecture

Date

2026-XX-XX

Status

ACCEPTED

Decision

Use Express API backend.

Alternatives Considered

* Fastify
* NestJS
* Hono

Rationale

* Simplicity
* Mature ecosystem
* Easy integration

Expected Impact

Rapid feature delivery.

---

## AD-003

Title

Primary Backend Platform

Status

ACCEPTED

Decision

Use Supabase.

Alternatives Considered

* Firebase
* Appwrite
* Custom PostgreSQL

Rationale

Unified:

* Auth
* Database
* Storage
* Realtime

Expected Impact

Reduced operational complexity.

---

# TELEMETRY DECISIONS

## TD-001

Title

Realtime Communication Standard

Status

ACCEPTED

Decision

Use Server-Sent Events (SSE).

Alternatives Considered

* Polling
* WebSockets

Rationale

* Simpler implementation
* Lower overhead
* Excellent for telemetry

Expected Impact

Reliable real-time dashboards.

---

## TD-002

Title

Telemetry Source Of Truth

Status

ACCEPTED

Decision

Backend services own telemetry calculations.

Rationale

Frontend should display telemetry, not generate it.

Expected Impact

Consistent metrics.

---

# SECURITY DECISIONS

## SEC-001

Title

Zero Trust Architecture

Status

ACCEPTED

Decision

Apply zero-trust principles across QGuard Helix.

Rationale

Every component must verify trust.

Expected Impact

Improved security posture.

---

## SEC-002

Title

Evidence First Validation

Status

ACCEPTED

Decision

No feature may be considered complete without evidence.

Rationale

Evidence prevents false-positive completion.

Expected Impact

Higher quality.

---

## SEC-003

Title

Verification Separation

Status

ACCEPTED

Decision

Builders cannot approve their own work.

Rationale

Independent verification improves reliability.

Expected Impact

Reduced defects.

---

# PQC DECISIONS

## PQC-001

Title

Primary PQC KEM

Status

ACCEPTED

Decision

Use ML-KEM.

References

FIPS 203

Alternatives Considered

* HQC
* BIKE

Rationale

NIST standardized.

Expected Impact

Alignment with industry standards.

---

## PQC-002

Title

Primary PQC Signature

Status

ACCEPTED

Decision

Use ML-DSA.

References

FIPS 204

Expected Impact

Standards compliance.

---

## PQC-003

Title

Hash-Based Signature Support

Status

ACCEPTED

Decision

Support SLH-DSA.

References

FIPS 205

Expected Impact

Additional cryptographic resilience.

---

## PQC-004

Title

Hybrid Cryptography Strategy

Status

ACCEPTED

Decision

Support hybrid deployments.

Examples

* X25519 + ML-KEM
* Classical PKI + PQC

Rationale

Industry migration will be gradual.

Expected Impact

Real-world interoperability.

---

# DISCOVERY DECISIONS

## DISC-001

Title

Evidence-Based Discovery

Status

ACCEPTED

Decision

All discovery findings require evidence.

Rationale

Discovery without evidence reduces trust.

Expected Impact

Higher confidence findings.

---

## DISC-002

Title

CBOM Requirement

Status

ACCEPTED

Decision

Cryptography Bill of Materials is mandatory.

Rationale

Organizations cannot migrate what they cannot inventory.

Expected Impact

Improved migration planning.

---

# MIGRATION DECISIONS

## MIG-001

Title

Discovery Before Migration

Status

ACCEPTED

Decision

Migration planning requires discovery.

Rationale

Unknown assets create migration risk.

Expected Impact

More accurate plans.

---

## MIG-002

Title

Rollback Requirement

Status

ACCEPTED

Decision

Every migration workflow requires rollback validation.

Expected Impact

Reduced operational risk.

---

## MIG-003

Title

Trust Analysis Requirement

Status

ACCEPTED

Decision

Trust Fabric analysis required before major migrations.

Expected Impact

Reduced blast radius.

---

# TRUST FABRIC DECISIONS

## TRUST-001

Title

Trust Graph Architecture

Status

ACCEPTED

Decision

Model trust relationships as a graph.

Rationale

Trust relationships are interconnected.

Expected Impact

Better dependency visibility.

---

## TRUST-002

Title

Certificate Ownership Tracking

Status

ACCEPTED

Decision

Track ownership for certificates and trust assets.

Expected Impact

Faster remediation.

---

# QUANTUM VAULT DECISIONS

## VAULT-001

Title

Client-Side Encryption

Status

ACCEPTED

Decision

Encrypt data before transmission.

Rationale

Zero-knowledge architecture.

Expected Impact

Maximum confidentiality.

---

## VAULT-002

Title

Recovery Key Architecture

Status

ACCEPTED

Decision

Recovery keys remain user-controlled.

Rationale

Server must not possess recovery secrets.

Expected Impact

Zero-knowledge recovery.

---

## VAULT-003

Title

Enterprise Cryptographic Stack

Status

ACCEPTED

Decision

Adopt:

* ML-KEM
* AES-256-GCM
* HKDF-SHA3-256
* SHA3-256

Expected Impact

Quantum-resistant encryption architecture.

---

# AGENT DEV KIT DECISIONS

## AGENT-001

Title

Memory Layer

Status

ACCEPTED

Decision

Introduce memory layer.

Structure

memory/

* STATE.md
* ARCHITECTURE.md
* VERIFIED_FACTS.md
* LESSONS.md
* FAILURES.md
* DECISIONS.md

Rationale

Enable compounding knowledge.

Expected Impact

Reduced repeated mistakes.

---

## AGENT-002

Title

Loop-Based Development

Status

ACCEPTED

Decision

Adopt build → verify → review loop.

Expected Impact

Improved quality.

---

## AGENT-003

Title

Stop Rules

Status

ACCEPTED

Decision

Stop when:

* All Green
* Five Cycles
* Same Failure Twice
* Regression Detected

Expected Impact

Reduced wasted effort.

---

# SUPERSEDED DECISIONS

Move retired decisions here.

Never delete historical decisions.

---

# REJECTED DECISIONS

Document rejected decisions.

Include:

* Why rejected
* Risks
* Alternatives

Historical context is valuable.

---

# DECISION REVIEW RULES

Quarterly Review:

* Validate assumptions
* Confirm relevance
* Mark obsolete decisions
* Record replacements

---

# AGENT RULES

Agents may:

* Propose decisions

Agents may NOT:

* Approve decisions

Approval required from:

* Architect
* Reviewer
* Auditor

Before status becomes ACCEPTED.

---

END OF DOCUMENT
