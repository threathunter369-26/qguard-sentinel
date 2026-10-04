"""Container, Kubernetes and cloud inventory.

Cloud support is adapter-shaped: a :class:`CloudAccount` names a provider and
holds an encrypted credential reference, and a provider adapter performs the
collection. AWS, Azure and GCP are added by registering adapters, so the rest
of the platform stays provider-agnostic.
"""

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
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)


class ContainerImage(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A container image analysed by the container engine."""

    __tablename__ = "container_images"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    registry_host: Mapped[str | None] = mapped_column(String(300))
    repository: Mapped[str] = mapped_column(String(400), nullable=False, index=True)
    tag: Mapped[str | None] = mapped_column(String(160))
    digest: Mapped[str | None] = mapped_column(String(160), index=True)
    image_reference: Mapped[str] = mapped_column(String(800), nullable=False)

    base_image: Mapped[str | None] = mapped_column(String(400))
    os_family: Mapped[str | None] = mapped_column(String(80))
    os_version: Mapped[str | None] = mapped_column(String(80))
    architecture: Mapped[str | None] = mapped_column(String(32))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    layer_count: Mapped[int | None] = mapped_column(Integer)
    created_at_source: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    runs_as_root: Mapped[bool | None] = mapped_column(Boolean)
    declared_user: Mapped[str | None] = mapped_column(String(120))
    has_healthcheck: Mapped[bool | None] = mapped_column(Boolean)
    exposed_ports: Mapped[list[str]] = mapped_column(
        ARRAY(String(24)), nullable=False, default=list, server_default="{}"
    )
    environment_keys: Mapped[list[str]] = mapped_column(
        ARRAY(String(200)), nullable=False, default=list, server_default="{}"
    )
    """Environment variable *names* only. Values may hold credentials, so they
    are examined by the secrets engine and never stored here."""
    entrypoint: Mapped[list[str]] = mapped_column(
        ARRAY(String(600)), nullable=False, default=list, server_default="{}"
    )
    labels: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    dockerfile_path: Mapped[str | None] = mapped_column(String(1024))
    dockerfile_sha256: Mapped[str | None] = mapped_column(String(64))
    package_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    analysis_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("org_id", "image_reference", name="uq_container_images_org_reference"),
        Index("ix_container_images_org_repo", "org_id", "repository"),
    )


class KubernetesResource(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A Kubernetes object assessed from a manifest or a cluster inventory."""

    __tablename__ = "kubernetes_resources"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    cluster_name: Mapped[str | None] = mapped_column(String(240), index=True)
    namespace: Mapped[str | None] = mapped_column(String(240), index=True)
    api_version: Mapped[str | None] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    source_path: Mapped[str | None] = mapped_column(String(1024))

    # Pod security posture, extracted so queries do not have to walk the spec.
    runs_privileged: Mapped[bool | None] = mapped_column(Boolean, index=True)
    allows_privilege_escalation: Mapped[bool | None] = mapped_column(Boolean)
    runs_as_root: Mapped[bool | None] = mapped_column(Boolean)
    read_only_root_filesystem: Mapped[bool | None] = mapped_column(Boolean)
    host_network: Mapped[bool | None] = mapped_column(Boolean)
    host_pid: Mapped[bool | None] = mapped_column(Boolean)
    host_ipc: Mapped[bool | None] = mapped_column(Boolean)
    added_capabilities: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    has_resource_limits: Mapped[bool | None] = mapped_column(Boolean)
    service_account_name: Mapped[str | None] = mapped_column(String(240))
    automount_service_account_token: Mapped[bool | None] = mapped_column(Boolean)

    # RBAC posture for Role/ClusterRole/Binding objects.
    rbac_rules: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    grants_wildcard_permissions: Mapped[bool | None] = mapped_column(Boolean, index=True)
    grants_cluster_admin: Mapped[bool | None] = mapped_column(Boolean, index=True)

    is_internet_exposed: Mapped[bool | None] = mapped_column(Boolean, index=True)
    service_type: Mapped[str | None] = mapped_column(String(48))
    has_network_policy: Mapped[bool | None] = mapped_column(Boolean)
    images: Mapped[list[str]] = mapped_column(
        ARRAY(String(800)), nullable=False, default=list, server_default="{}"
    )
    labels: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    spec_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "cluster_name",
            "namespace",
            "kind",
            "name",
            name="uq_kubernetes_resources_identity",
        ),
        Index("ix_kubernetes_resources_org_kind", "org_id", "kind"),
    )


class CloudAccount(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """A connected cloud account or subscription.

    Credentials are stored encrypted and are expected to grant read-only
    security-audit access. The adapter interface keeps provider specifics out
    of the rest of the platform.
    """

    __tablename__ = "cloud_accounts"

    provider: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    account_identifier: Mapped[str] = mapped_column(String(240), nullable=False)
    """AWS account id, Azure subscription id or GCP project id."""
    default_region: Mapped[str | None] = mapped_column(String(64))
    regions: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list, server_default="{}"
    )
    credential_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="none", server_default="'none'"
    )
    """``none``, ``role_assumption``, ``workload_identity`` or ``static_key``."""
    credentials_encrypted: Mapped[str | None] = mapped_column(Text)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    environment: Mapped[str | None] = mapped_column(String(32))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_status: Mapped[str | None] = mapped_column(String(24))
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    resource_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id", "provider", "account_identifier", name="uq_cloud_accounts_identity"
        ),
        CheckConstraint("provider IN ('aws','azure','gcp','other')", name="cloud_provider_valid"),
        CheckConstraint(
            "credential_mode IN ('none','role_assumption','workload_identity','static_key')",
            name="cloud_credential_mode_valid",
        ),
    )


class CloudResource(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A discovered cloud resource and its security-relevant configuration."""

    __tablename__ = "cloud_resources"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(600), nullable=False)
    name: Mapped[str | None] = mapped_column(String(400))
    region: Mapped[str | None] = mapped_column(String(64))

    is_public: Mapped[bool | None] = mapped_column(Boolean, index=True)
    encryption_at_rest: Mapped[bool | None] = mapped_column(Boolean)
    encryption_in_transit: Mapped[bool | None] = mapped_column(Boolean)
    logging_enabled: Mapped[bool | None] = mapped_column(Boolean)
    mfa_required: Mapped[bool | None] = mapped_column(Boolean)
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    tags: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "cloud_account_id", "resource_id", name="uq_cloud_resources_account_resource"
        ),
        Index("ix_cloud_resources_org_type", "org_id", "resource_type"),
        Index("ix_cloud_resources_public", "org_id", "is_public"),
    )
