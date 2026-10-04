# QGuard Helix - ARCHITECTURE.md

Version: 1.0
Status: AUTHORITATIVE
Last Updated: {{timestamp}}

---

# PURPOSE

This document defines the official architecture of QGuard Helix.

All agents MUST read this document before making architectural decisions.

Agents MUST NOT:

* Invent new architectures
* Introduce duplicate patterns
* Create conflicting data flows
* Bypass security boundaries
* Ignore documented standards

If implementation conflicts with this document:

STOP

Review architecture first.

---

# PLATFORM OVERVIEW

QGuard Helix is a Quantum Cyber Defense Platform designed to:

* Discover cryptographic assets
* Map trust relationships
* Assess quantum readiness
* Simulate PQC migrations
* Orchestrate remediation
* Monitor runtime cryptography
* Maintain crypto agility

Primary Objective:

Help organizations prepare for and migrate toward post-quantum cryptography.

---

# HIGH LEVEL ARCHITECTURE

┌──────────────────────────┐
│ React + Vite Frontend    │
└────────────┬─────────────┘
│
▼
┌──────────────────────────┐
│ Express API Layer        │
└────────────┬─────────────┘
│
┌───────────┼─────────────┐
▼           ▼             ▼

Supabase   Scanner      Telemetry
Database   Agents       Services

▼           ▼             ▼

Discovery  Analysis    Realtime SSE

▼           ▼             ▼

Migration  Remediation  Dashboards

---

# RUNTIME BOUNDARIES

Frontend

Location:

src/

Responsibilities:

* User Interface
* Dashboards
* Visualization
* Workflow Management
* Telemetry Display

Frontend MUST NOT:

* Perform privileged actions
* Access service secrets
* Execute remediation logic
* Bypass API layer

---

Backend

Location:

src/api-server/

Responsibilities:

* Business Logic
* Secure Operations
* Orchestration
* Telemetry Aggregation
* Asset Correlation
* Policy Enforcement

Backend owns:

* Remediation
* Asset Processing
* Risk Calculations
* Migration Planning
* Security Validation

---

# AUTHORITY MODEL

Single Source Of Truth

Frontend:
Display Only

Backend:
Authority

Database:
Persistence

Telemetry:
Evidence

Never calculate critical security posture exclusively in the browser.

All authoritative calculations must originate from backend services.

---

# DATA FLOW

Discovery

Scanner
→ Asset Inventory
→ CBOM
→ Crypto Analysis
→ Risk Engine
→ Database
→ SSE
→ Dashboard

---

Migration

Assets
→ Readiness Analysis
→ Migration Planner
→ Orchestrator
→ Validation
→ Telemetry
→ Dashboard

---

Runtime Intelligence

Assets
→ Telemetry Collection
→ Correlation Engine
→ Risk Engine
→ Alert Engine
→ Dashboard

---

# DATABASE ARCHITECTURE

Primary Database:

Supabase PostgreSQL

Responsibilities:

* Tenants
* Assets
* Discoveries
* Telemetry
* Risk Scores
* Migrations
* Audit Events
* Compliance Evidence

Database is authoritative.

Dashboards must never become authoritative.

---

# AUTHENTICATION

Provider:

Supabase Auth

Authentication:

JWT

Authorization:

RBAC

Future:

ABAC

Authentication Flow:

User
→ Login
→ JWT
→ Express API
→ Supabase RLS
→ Data Access

---

# REALTIME ARCHITECTURE

Primary Mechanism:

Server Sent Events (SSE)

Purpose:

* Asset Updates
* Migration Progress
* Risk Updates
* Telemetry Streams
* Agent Activity

Requirements:

* Automatic reconnect
* Health monitoring
* Backpressure handling
* Stream validation

Polling should be avoided where SSE exists.

---

# SCANNER ARCHITECTURE

Scanner Responsibilities

* TLS Discovery
* Certificate Discovery
* Cryptographic Inventory
* PQC Assessment
* CBOM Generation
* Shadow Crypto Detection

Scanner Output

Assets
Evidence
Findings
Telemetry

Scanners never modify assets directly.

Remediation agents perform changes.

---

# REMEDIATION ARCHITECTURE

Operator Patchers

Responsibilities:

* TLS Updates
* Certificate Replacement
* Crypto Upgrades
* PQC Migration
* Configuration Remediation

Supported Targets:

* Local Assets
* Cloud Assets
* Kubernetes
* Containers
* Web Applications
* APIs
* SaaS Services
* Infrastructure

All remediation must generate evidence.

---

# DISCOVERY MODULE

Components

* PQC Scanner
* CBOM Explorer
* Crypto Exposure
* Assets & CBOM
* Shadow Crypto
* Harvest Now Decrypt Later

Discovery produces:

Evidence

Discovery never assumes.

All findings require evidence.

---

# INTELLIGENCE MODULE

Components

* Drift Detection
* Vulnerabilities
* Runtime Crypto Intelligence
* Behavioral Analytics
* Telemetry Correlation
* Quantum Risk Scoring

Intelligence consumes:

Discovery Data

Intelligence never invents findings.

---

# PQAUTH MODULE

Components

* Identity Discovery
* Trust Graph
* JWT Intelligence
* Identity Digital Twin
* Runtime Identity Telemetry

Purpose:

Identity migration to PQC.

---

# TRUST FABRIC MODULE

Components

* Trust-State Discovery
* Dependency Mapping
* Trust Chain Analysis
* Vendor Trust Analysis

Purpose:

Map trust relationships across infrastructure.

---

# QKMS MODULE

Components

* Key Inventory
* Key Governance
* Key Rotation
* PQC Readiness

Purpose:

Manage cryptographic lifecycle.

---

# QUANTUM VAULT

Architecture

Client Side Encryption

Primary Algorithms

* ML-KEM
* AES-256-GCM
* HKDF-SHA3-256
* SHA3-256

Future Support

* ML-DSA
* SLH-DSA

Server never owns user keys.

Zero Knowledge principle applies.

---

# CRYPTOGRAPHIC STANDARDS

Approved Algorithms

Key Encapsulation

* ML-KEM-768
* ML-KEM-1024

Signatures

* ML-DSA
* SLH-DSA

Symmetric

* AES-256-GCM

Hashing

* SHA3-256
* SHA3-512

KDF

* HKDF-SHA3-256

Disallowed For New Deployments

* SHA1
* MD5
* RC4
* DES
* 3DES

---

# SECURITY BOUNDARIES

Never Store

* Plaintext Keys
* Recovery Keys
* Private Keys
* Secrets

Never Trust

* Client Calculations
* Browser Risk Scores
* Mock Telemetry

Always Verify

* APIs
* SSE Streams
* Database Results
* Asset Ownership

---

# OBSERVABILITY

All systems should emit telemetry.

Required

* Health
* Latency
* Errors
* Security Events
* Discovery Events
* Migration Events

No silent failures.

---

# EVIDENCE FIRST RULE

No feature is complete without evidence.

Evidence Examples

* API Validation
* Telemetry Validation
* Database Validation
* Security Validation
* Migration Validation

Evidence must be stored.

---

# VERIFICATION FIRST RULE

Every implementation requires:

Builder
→ Reviewer
→ Auditor
→ Validator

No direct promotion to completed status.

---

# AGENT RULES

All Agents Must:

Read

* STATE.md
* ARCHITECTURE.md
* VERIFIED_FACTS.md
* LESSONS.md

Before Starting

Write

* New Facts
* New Failures
* New Decisions
* New Lessons

Before Exiting

---

# SUCCESS CRITERIA

QGuard Helix succeeds when:

* Discovery is evidence-based
* Telemetry is real-time
* Migration is measurable
* Trust relationships are visible
* Cryptographic assets are inventoried
* PQC readiness is verifiable
* Every dashboard reflects real data
* Every finding is backed by evidence

END OF DOCUMENT
