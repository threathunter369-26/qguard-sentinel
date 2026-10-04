"""Mobile application packages and their static analysis results."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


class MobileApplication(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """An uploaded APK, AAB or IPA and everything extracted from it.

    Uploaded packages are untrusted input. They are hashed, stored outside the
    web root and parsed in a sandboxed worker — never unpacked or executed
    inside the API process.
    """

    __tablename__ = "mobile_applications"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL")
    )
    """The stored package, tracked under the same integrity controls as evidence."""

    platform: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    package_format: Mapped[str] = mapped_column(String(8), nullable=False)
    """``apk``, ``aab`` or ``ipa``."""
    package_name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    app_name: Mapped[str | None] = mapped_column(String(300))
    version_name: Mapped[str | None] = mapped_column(String(80))
    version_code: Mapped[str | None] = mapped_column(String(40))
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)

    min_sdk_version: Mapped[str | None] = mapped_column(String(16))
    target_sdk_version: Mapped[str | None] = mapped_column(String(16))
    compile_sdk_version: Mapped[str | None] = mapped_column(String(16))
    minimum_os_version: Mapped[str | None] = mapped_column(String(16))

    is_debuggable: Mapped[bool | None] = mapped_column(Boolean)
    allows_backup: Mapped[bool | None] = mapped_column(Boolean)
    allows_cleartext_traffic: Mapped[bool | None] = mapped_column(Boolean)
    uses_certificate_pinning: Mapped[bool | None] = mapped_column(Boolean)
    has_network_security_config: Mapped[bool | None] = mapped_column(Boolean)
    network_security_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    ats_configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """iOS App Transport Security settings from ``Info.plist``."""

    signing: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Certificate subject, issuer, algorithm, key size, validity, v1/v2/v3 scheme."""
    permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default="{}"
    )
    dangerous_permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default="{}"
    )
    custom_permissions: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default="{}"
    )
    exported_components: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Activities, services, receivers and providers reachable by other apps."""
    manifest: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    info_plist: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    url_schemes: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default="{}"
    )
    discovered_endpoints: Mapped[list[str]] = mapped_column(
        ARRAY(String(2048)), nullable=False, default=list, server_default="{}"
    )
    third_party_sdks: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    native_libraries: Mapped[list[str]] = mapped_column(
        ARRAY(String(300)), nullable=False, default=list, server_default="{}"
    )
    crypto_usage: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    dex_count: Mapped[int | None] = mapped_column(Integer)
    file_count: Mapped[int | None] = mapped_column(Integer)
    analysis_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    masvs_coverage: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Per-MASVS-control results, so report mapping is data rather than hardcoded."""

    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analysis_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending", server_default="'pending'"
    )
    analysis_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("org_id", "file_sha256", name="uq_mobile_applications_org_sha256"),
        Index("ix_mobile_applications_org_package", "org_id", "package_name"),
        CheckConstraint("platform IN ('android','ios')", name="mobile_platform_valid"),
        CheckConstraint("package_format IN ('apk','aab','ipa')", name="mobile_format_valid"),
        CheckConstraint(
            "analysis_status IN ('pending','processing','completed','failed')",
            name="mobile_analysis_status_valid",
        ),
    )
