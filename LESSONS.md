# QGuard Helix - LESSONS.md

Status: COMPOUNDING KNOWLEDGE
Last Updated: {{timestamp}}

---

# PURPOSE

This document captures lessons learned from:

* Development
* Security Reviews
* Discovery Operations
* PQC Assessments
* Telemetry Validation
* Migration Projects
* Production Issues
* Agent Loops

The goal is simple:

Never pay twice for the same mistake.

---

# LESSON FORMAT

Every lesson should contain:

Lesson

Why It Happened

Impact

Prevention

Date

Evidence

---

# DISCOVERY LESSONS

## LESSON-DISC-001

Lesson

Asset inventories should have one authoritative source.

Why It Happened

Different dashboards calculated asset counts independently.

Impact

Inconsistent KPI values across modules.

Prevention

All asset counts must originate from a canonical backend service.

Date

2026-XX-XX

---

## LESSON-DISC-002

Lesson

Duplicate vulnerabilities create false risk inflation.

Why It Happened

Multiple scanners reported the same finding.

Impact

Risk scores became inaccurate.

Prevention

Deduplicate findings before scoring.

Date

2026-XX-XX

---

## LESSON-DISC-003

Lesson

Discovery findings without evidence lose credibility.

Why It Happened

A finding was displayed without traceable evidence.

Impact

Users could not verify results.

Prevention

Every finding must include supporting evidence.

Date

2026-XX-XX

---

# TELEMETRY LESSONS

## LESSON-TEL-001

Lesson

Real-time telemetry must be traceable.

Why It Happened

Metrics appeared on dashboards without a documented source.

Impact

Users questioned data accuracy.

Prevention

Every metric must map to:

* API
* Query
* SSE Stream
* Evidence Source

Date

2026-XX-XX

---

## LESSON-TEL-002

Lesson

Mock telemetry becomes technical debt.

Why It Happened

Placeholder data remained after development.

Impact

False operational visibility.

Prevention

Remove all placeholder telemetry before production.

Date

2026-XX-XX

---

## LESSON-TEL-003

Lesson

Freshness indicators are mandatory.

Why It Happened

Users could not determine whether data was current.

Impact

Reduced trust.

Prevention

Display timestamps and update status.

Date

2026-XX-XX

---

# SECURITY LESSONS

## LESSON-SEC-001

Lesson

Client-side calculations should never determine security posture.

Why It Happened

Frontend attempted to calculate risk scores.

Impact

Results could be manipulated.

Prevention

Risk calculations must occur on backend systems.

Date

2026-XX-XX

---

## LESSON-SEC-002

Lesson

Security findings require validation.

Why It Happened

Scanner output was trusted without verification.

Impact

False positives.

Prevention

Require validation workflows.

Date

2026-XX-XX

---

## LESSON-SEC-003

Lesson

Zero-trust applies internally as well.

Why It Happened

An internal service was trusted without verification.

Impact

Potential trust boundary violation.

Prevention

Validate all service interactions.

Date

2026-XX-XX

---

# PQC LESSONS

## LESSON-PQC-001

Lesson

PQC readiness cannot be estimated.

Why It Happened

Readiness scoring was attempted without asset evidence.

Impact

Misleading migration guidance.

Prevention

Readiness must be based on discovered assets.

Date

2026-XX-XX

---

## LESSON-PQC-002

Lesson

Algorithm inventories are required before migration planning.

Why It Happened

Migration planning started before crypto discovery.

Impact

Incomplete migration plans.

Prevention

Discovery must precede migration.

Date

2026-XX-XX

---

## LESSON-PQC-003

Lesson

Hybrid cryptography will exist for years.

Why It Happened

Initial planning assumed immediate PQC replacement.

Impact

Unrealistic migration timelines.

Prevention

Support hybrid deployments.

Date

2026-XX-XX

---

# MIGRATION LESSONS

## LESSON-MIG-001

Lesson

Migration plans without rollback plans are incomplete.

Why It Happened

Focus was placed solely on migration execution.

Impact

Increased operational risk.

Prevention

Every migration requires rollback validation.

Date

2026-XX-XX

---

## LESSON-MIG-002

Lesson

Blast radius analysis must happen before execution.

Why It Happened

Dependency mapping was skipped.

Impact

Unexpected service impact.

Prevention

Perform dependency analysis first.

Date

2026-XX-XX

---

## LESSON-MIG-003

Lesson

Trust relationships affect migration complexity.

Why It Happened

Certificate dependencies were underestimated.

Impact

Migration delays.

Prevention

Use Trust Fabric analysis before migration.

Date

2026-XX-XX

---

# TRUST FABRIC LESSONS

## LESSON-TRUST-001

Lesson

Most organizations underestimate trust complexity.

Why It Happened

Hidden trust relationships were discovered late.

Impact

Unexpected migration dependencies.

Prevention

Map trust relationships early.

Date

2026-XX-XX

---

## LESSON-TRUST-002

Lesson

Certificate ownership is often unclear.

Why It Happened

No ownership tracking existed.

Impact

Remediation delays.

Prevention

Track ownership continuously.

Date

2026-XX-XX

---

# QUANTUM VAULT LESSONS

## LESSON-VAULT-001

Lesson

Recovery mechanisms are just as important as encryption.

Why It Happened

Initial focus was encryption strength.

Impact

Risk of permanent data loss.

Prevention

Design recovery architecture early.

Date

2026-XX-XX

---

## LESSON-VAULT-002

Lesson

Users lose devices more often than encryption fails.

Why It Happened

Real-world usage patterns.

Impact

Recovery becomes critical.

Prevention

Provide secure recovery workflows.

Date

2026-XX-XX

---

# UI/UX LESSONS

## LESSON-UX-001

Lesson

Users need actionable guidance.

Why It Happened

Dashboards displayed problems but not solutions.

Impact

Users became overwhelmed.

Prevention

Every page should answer:

1. What is affected?
2. Why is it risky?
3. What should I do?
4. Has it been fixed?

Date

2026-XX-XX

---

## LESSON-UX-002

Lesson

More data does not mean more clarity.

Why It Happened

Pages became overloaded with metrics.

Impact

Reduced usability.

Prevention

Prioritize important information first.

Date

2026-XX-XX

---

# AGENT LESSONS

## LESSON-AGENT-001

Lesson

Builders should never approve their own work.

Impact

Verification quality improves significantly.

Prevention

Use independent reviewers.

Date

2026-XX-XX

---

## LESSON-AGENT-002

Lesson

Evidence is more valuable than confidence.

Why It Happened

Agents reported success without proof.

Impact

False completion reports.

Prevention

Require evidence for every completion.

Date

2026-XX-XX

---

## LESSON-AGENT-003

Lesson

Repeated failures indicate a flawed approach.

Why It Happened

Loops continued without progress.

Impact

Token waste.

Prevention

Stop after the same failure occurs twice.

Date

2026-XX-XX

---

# PRODUCTION LESSONS

## LESSON-PROD-001

Lesson

Production data must always override assumptions.

Prevention

Verify against real telemetry.

---

## LESSON-PROD-002

Lesson

Every dashboard must have an evidence trail.

Prevention

Require traceability.

---

## LESSON-PROD-003

Lesson

Trust is built through accuracy.

Prevention

Never display unverified information.

---

# LESSON ADDITION RULES

Before adding a lesson:

1. Confirm event occurred.
2. Identify root cause.
3. Determine impact.
4. Define prevention.
5. Document evidence.

---

# LESSON REVIEW RULES

Monthly Review:

* Remove duplicates
* Merge related lessons
* Update prevention guidance
* Promote recurring lessons into Skills

---

# PROMOTION RULE

If a lesson repeats three times:

Promote it into:

* Skill
* Verification Rule
* Architecture Rule
* Security Standard

The goal is to prevent recurrence.

---

END OF DOCUMENT
