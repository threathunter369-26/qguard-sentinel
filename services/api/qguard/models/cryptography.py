"""Cryptographic inventory and post-quantum readiness.

The taxonomy here is deliberately strict. ML-KEM is a **key encapsulation
mechanism** and can never be recorded as a signature algorithm; ML-DSA and
SLH-DSA are **signature schemes** and can never be recorded as KEMs or
encryption algorithms. The database enforces this with a CHECK constraint, so
no engine, importer or manual entry can produce a miscategorised record.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import (
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import PQCategory, QuantumRisk


class CryptoInventoryItem(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """One discovered cryptographic primitive, configuration or certificate."""

    __tablename__ = "crypto_inventory"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL")
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    """Canonical algorithm name, e.g. ``RSA``, ``ECDSA``, ``ML-KEM-768``, ``AES-256-GCM``."""
    algorithm_family: Mapped[str | None] = mapped_column(String(48), index=True)
    pq_category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=PQCategory.UNKNOWN,
        index=True,
        server_default="'unknown'",
    )
    """Primitive class. Strictly separates KEMs from signatures from symmetric ciphers."""
    quantum_risk: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=QuantumRisk.UNKNOWN,
        index=True,
        server_default="'unknown'",
    )
    is_post_quantum: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    is_hybrid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """True for composites such as X25519+ML-KEM-768 in TLS 1.3 key exchange."""
    hybrid_components: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list, server_default="{}"
    )
    nist_security_category: Mapped[int | None] = mapped_column(Integer)
    """NIST PQC security category 1-5, for standardised PQ algorithms only."""

    key_size_bits: Mapped[int | None] = mapped_column(Integer)
    curve: Mapped[str | None] = mapped_column(String(48))
    effective_security_bits: Mapped[int | None] = mapped_column(Integer)
    """Classical security level, used to flag under-strength keys."""
    usage: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    """``key_exchange``, ``signature``, ``encryption``, ``integrity``, ``authentication``."""
    protocol: Mapped[str | None] = mapped_column(String(48))
    protocol_versions: Mapped[list[str]] = mapped_column(
        ARRAY(String(24)), nullable=False, default=list, server_default="{}"
    )
    is_deprecated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    deprecation_reason: Mapped[str | None] = mapped_column(Text)

    # Certificate-specific fields.
    subject: Mapped[str | None] = mapped_column(String(600))
    issuer: Mapped[str | None] = mapped_column(String(600))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    not_valid_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_valid_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    is_self_signed: Mapped[bool | None] = mapped_column(Boolean)
    is_ca: Mapped[bool | None] = mapped_column(Boolean)
    san_entries: Mapped[list[str]] = mapped_column(
        ARRAY(String(320)), nullable=False, default=list, server_default="{}"
    )
    signature_algorithm: Mapped[str | None] = mapped_column(String(80))

    source: Mapped[str] = mapped_column(
        String(48), nullable=False, default="crypto", server_default="'crypto'"
    )
    location: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    migration_recommendation: Mapped[str | None] = mapped_column(Text)
    migration_priority: Mapped[str | None] = mapped_column(String(16))
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint", name="uq_crypto_inventory_org_fingerprint"),
        Index("ix_crypto_inventory_org_quantum", "org_id", "quantum_risk"),
        Index("ix_crypto_inventory_org_pq", "org_id", "is_post_quantum", "pq_category"),
        Index("ix_crypto_inventory_expiry", "org_id", "not_valid_after"),
        CheckConstraint(
            "kind IN ('certificate','tls_configuration','ssh_configuration','key',"
            "'code_usage','jwt_configuration','hash_usage','randomness')",
            name="crypto_kind_valid",
        ),
        CheckConstraint(
            "pq_category IN ('key_encapsulation','digital_signature','key_agreement',"
            "'symmetric_encryption','hash','mac','kdf','unknown')",
            name="pq_category_valid",
        ),
        CheckConstraint(
            "quantum_risk IN ('broken','reduced','quantum_safe','hybrid','unknown')",
            name="quantum_risk_valid",
        ),
        # ML-KEM is key encapsulation, full stop.
        CheckConstraint(
            "algorithm NOT LIKE 'ML-KEM%' OR pq_category = 'key_encapsulation'",
            name="ml_kem_is_key_encapsulation",
        ),
        # ML-DSA and SLH-DSA are signature schemes, full stop.
        CheckConstraint(
            "(algorithm NOT LIKE 'ML-DSA%' AND algorithm NOT LIKE 'SLH-DSA%') "
            "OR pq_category = 'digital_signature'",
            name="ml_dsa_and_slh_dsa_are_signatures",
        ),
        # Anything claiming PQ status must declare a NIST category, and anything
        # that is post-quantum cannot simultaneously be Shor-broken.
        CheckConstraint(
            "NOT is_post_quantum OR quantum_risk IN ('quantum_safe','hybrid')",
            name="post_quantum_not_broken",
        ),
        CheckConstraint(
            "nist_security_category IS NULL OR nist_security_category BETWEEN 1 AND 5",
            name="nist_category_range",
        ),
    )


class PQCReadinessAssessment(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A scored snapshot of post-quantum migration readiness.

    Every component of the score is stored so the number can be explained,
    reproduced and compared against a later assessment.
    """

    __tablename__ = "pqc_readiness_assessments"

    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))

    readiness_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    """0-100. 100 means no quantum-broken primitive remains in scope."""
    maturity_level: Mapped[str] = mapped_column(String(32), nullable=False)
    """``not_started``, ``discovery``, ``planning``, ``hybrid_rollout``, ``pq_native``."""

    total_primitives: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    quantum_broken_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    quantum_reduced_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    quantum_safe_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    hybrid_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    kem_inventory: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    signature_inventory: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    symmetric_inventory: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    hash_inventory: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    score_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    migration_plan: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    highest_risk_items: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    __table_args__ = (
        Index("ix_pqc_assessments_org_time", "org_id", "assessed_at"),
        CheckConstraint("readiness_score >= 0 AND readiness_score <= 100", name="pqc_score_range"),
        CheckConstraint(
            "maturity_level IN ('not_started','discovery','planning','hybrid_rollout','pq_native')",
            name="pqc_maturity_valid",
        ),
    )
