"""Request and response shapes for the asset inventory."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any

from fastapi import Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from qguard.api.schemas import CountByKey, SeverityCounts
from qguard.common.enums import (
    AssetRelation,
    AssetType,
    Confidence,
    Criticality,
    DataSensitivity,
    Environment,
)

#: Asset types whose identifier must parse as a network address.
_IP_TYPES = {AssetType.IP_ADDRESS}
_CIDR_TYPES = {AssetType.NETWORK_RANGE}


class AssetBase(BaseModel):
    """Fields a caller may set on an asset."""

    name: str = Field(min_length=1, max_length=500)
    asset_type: AssetType
    identifier: str = Field(
        min_length=1,
        max_length=1000,
        description=(
            "The value that identifies this asset uniquely for its type — a hostname, a "
            "URL, an IP address, a repository path, an image reference. Together with "
            "`asset_type` it is the asset's identity, so the same thing discovered twice "
            "becomes one asset."
        ),
    )
    description: str | None = None
    project_id: uuid.UUID | None = None
    owner_user_id: uuid.UUID | None = None
    owning_team_id: uuid.UUID | None = None
    parent_asset_id: uuid.UUID | None = None

    environment: Environment = Environment.UNKNOWN
    criticality: Criticality = Criticality.MEDIUM
    business_value: str | None = Field(
        default=None,
        description="What breaks, and for whom, if this asset is compromised or unavailable.",
    )
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    internet_facing: bool = False
    requires_authentication: bool = True
    compensating_controls: list[str] = Field(
        default_factory=list,
        description=(
            "Controls that reduce the exploitability of findings on this asset — a WAF, "
            "network segmentation, an allow-list. Recorded because they lower the risk "
            "score, and the score shows which ones were credited."
        ),
    )

    hostname: str | None = Field(default=None, max_length=500)
    domain: str | None = Field(default=None, max_length=500)
    ip_address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    url: str | None = Field(default=None, max_length=2000)
    operating_system: str | None = Field(default=None, max_length=200)
    technology: dict[str, Any] = Field(default_factory=dict)

    cloud_provider: str | None = Field(default=None, max_length=50)
    cloud_account_id: str | None = Field(default=None, max_length=200)
    cloud_region: str | None = Field(default=None, max_length=100)

    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tags", "compensating_controls")
    @classmethod
    def _clean_list(cls, value: list[str]) -> list[str]:
        """Normalise and deduplicate, so filtering by tag is predictable."""
        seen: list[str] = []
        for item in value:
            cleaned = item.strip().lower()
            if cleaned and cleaned not in seen:
                seen.append(cleaned)
        if len(seen) > 50:
            raise ValueError("At most 50 entries are allowed.")
        return seen

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid IP address.") from exc

    @model_validator(mode="after")
    def _identifier_matches_type(self) -> AssetBase:
        """Check the identifier is plausible for the declared type.

        An IP asset whose identifier is a hostname would never match a scan
        target, so the asset would silently accumulate no findings. Rejecting
        it at the boundary is better than an inventory that looks populated
        and correlates nothing.
        """
        identifier = self.identifier.strip()
        if self.asset_type in _IP_TYPES:
            try:
                ipaddress.ip_address(identifier)
            except ValueError as exc:
                raise ValueError(
                    f"An asset of type {self.asset_type.value!r} needs an IP address as its "
                    f"identifier; {identifier!r} is not one."
                ) from exc
        elif self.asset_type in _CIDR_TYPES:
            try:
                ipaddress.ip_network(identifier, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"An asset of type {self.asset_type.value!r} needs a CIDR range as its "
                    f"identifier; {identifier!r} is not one."
                ) from exc
        elif self.asset_type in (AssetType.URL, AssetType.WEB_APPLICATION) and "://" not in (
            identifier
        ):
            raise ValueError(
                f"An asset of type {self.asset_type.value!r} needs a full URL including the "
                f"scheme as its identifier; {identifier!r} has none."
            )
        return self


class AssetCreate(AssetBase):
    """A new asset, entered manually or imported."""

    discovery_source: str = Field(
        default="manual",
        max_length=50,
        description="How the platform learned about this asset. Retained for provenance.",
    )


class AssetUpdate(BaseModel):
    """A partial update. Only the fields present are changed."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=500)
    description: str | None = None
    project_id: uuid.UUID | None = None
    owner_user_id: uuid.UUID | None = None
    owning_team_id: uuid.UUID | None = None
    parent_asset_id: uuid.UUID | None = None
    environment: Environment | None = None
    criticality: Criticality | None = None
    business_value: str | None = None
    data_sensitivity: DataSensitivity | None = None
    internet_facing: bool | None = None
    requires_authentication: bool | None = None
    compensating_controls: list[str] | None = None
    hostname: str | None = None
    domain: str | None = None
    ip_address: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    url: str | None = None
    operating_system: str | None = None
    technology: dict[str, Any] | None = None
    cloud_provider: str | None = None
    cloud_account_id: str | None = None
    cloud_region: str | None = None
    tags: list[str] | None = None
    attributes: dict[str, Any] | None = None
    is_active: bool | None = None

    @field_validator("tags", "compensating_controls")
    @classmethod
    def _clean_list(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        seen: list[str] = []
        for item in value:
            cleaned = item.strip().lower()
            if cleaned and cleaned not in seen:
                seen.append(cleaned)
        return seen

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid IP address.") from exc

    def changes(self) -> dict[str, Any]:
        """The fields the caller actually supplied."""
        return self.model_dump(exclude_unset=True)


class AssetSummary(BaseModel):
    """An asset as it appears in a list.

    Deliberately narrower than the full resource: a list of 200 assets should
    not carry 200 technology dictionaries. ``open_vulnerability_count`` and
    ``risk_score`` are included because a table without them forces a
    follow-up request per row.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    asset_type: AssetType
    identifier: str
    environment: Environment
    criticality: Criticality
    data_sensitivity: DataSensitivity
    internet_facing: bool
    tags: list[str]
    risk_score: Decimal | None
    security_score: Decimal | None
    last_assessed_at: datetime | None
    discovery_source: str
    first_seen_at: datetime
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetSummary):
    """The full asset, with its security posture attached."""

    description: str | None
    project_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    owning_team_id: uuid.UUID | None
    parent_asset_id: uuid.UUID | None
    business_value: str | None
    requires_authentication: bool
    compensating_controls: list[str]
    hostname: str | None
    domain: str | None
    ip_address: str | None
    port: int | None
    url: str | None
    operating_system: str | None
    technology: dict[str, Any]
    cloud_provider: str | None
    cloud_account_id: str | None
    cloud_region: str | None
    attributes: dict[str, Any]
    last_scan_id: uuid.UUID | None

    #: Derived, not stored. Counted from the vulnerability table at read time
    #: so it cannot drift out of date the way a cached counter does.
    open_vulnerabilities: SeverityCounts = Field(default_factory=SeverityCounts)
    open_vulnerability_count: int = 0
    scan_count: int = 0
    last_scan_status: str | None = None
    has_active_authorization: bool = False


class AssetRelationshipCreate(BaseModel):
    """A directed relationship between two assets."""

    target_asset_id: uuid.UUID
    relation: AssetRelation
    confidence: Confidence = Confidence.HIGH
    attributes: dict[str, Any] = Field(default_factory=dict)


class AssetRelationshipRead(BaseModel):
    """A relationship, with both ends resolved enough to render a graph."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relation: AssetRelation
    confidence: Confidence
    discovered_by: str | None
    attributes: dict[str, Any]
    created_at: datetime

    source_name: str | None = None
    target_name: str | None = None
    target_asset_type: AssetType | None = None
    target_criticality: Criticality | None = None


class AssetFilters(BaseModel):
    """Query parameters for the asset list."""

    search: Annotated[
        str | None, Query(description="Substring match on name, identifier, hostname or URL.")
    ] = None
    asset_type: Annotated[list[AssetType] | None, Query(description="Restrict to these types.")] = (
        None
    )
    environment: Annotated[list[Environment] | None, Query()] = None
    criticality: Annotated[list[Criticality] | None, Query()] = None
    data_sensitivity: Annotated[list[DataSensitivity] | None, Query()] = None
    internet_facing: Annotated[bool | None, Query()] = None
    project_id: Annotated[uuid.UUID | None, Query()] = None
    owner_user_id: Annotated[uuid.UUID | None, Query()] = None
    parent_asset_id: Annotated[uuid.UUID | None, Query()] = None
    tags: Annotated[list[str] | None, Query(description="Match assets carrying any of these.")] = (
        None
    )
    discovery_source: Annotated[list[str] | None, Query()] = None
    cloud_provider: Annotated[str | None, Query()] = None
    is_active: Annotated[bool | None, Query(description="Defaults to active assets only.")] = True
    never_assessed: Annotated[
        bool | None,
        Query(
            description=(
                "Only assets that have never been assessed. These are the inventory's blind "
                "spots: an asset with no findings may be clean or may simply never have been "
                "looked at, and the two are not the same."
            )
        ),
    ] = None
    has_open_vulnerabilities: Annotated[bool | None, Query()] = None


class AssetInventorySummary(BaseModel):
    """Counts across the inventory, for the asset page's header.

    Every number here is counted from the database on request. None is
    cached, estimated or seeded.
    """

    total: int
    active: int
    inactive: int
    internet_facing: int
    never_assessed: int
    assessed_in_last_30_days: int
    with_open_critical_or_high: int
    by_type: list[CountByKey]
    by_environment: list[CountByKey]
    by_criticality: list[CountByKey]
    by_discovery_source: list[CountByKey]


class AssetImportRequest(BaseModel):
    """A batch of assets from a discovery source or inventory export.

    ``assets`` is deliberately typed as raw objects rather than as
    :class:`AssetCreate`. Each entry is validated individually inside the
    handler, so one malformed row is reported in ``rejections`` and the rest
    of the batch still lands. Typing the list as a validated model would make
    Pydantic reject the whole request on the first bad entry — which, for an
    inventory import, means a single typo in a 900-asset export leaves the
    entire inventory unupdated and nothing recorded about why.
    """

    assets: list[dict[str, Any]] = Field(
        min_length=1,
        max_length=1000,
        description=(
            "Asset objects with the same fields as the create endpoint. Each is validated "
            "on its own; see `rejections` in the response for any that failed."
        ),
    )
    discovery_source: str = Field(
        default="import",
        max_length=50,
        description="Applied to every asset in the batch that does not set its own.",
    )
    update_existing: bool = Field(
        default=True,
        description=(
            "When true, an asset whose identity already exists has its descriptive fields "
            "refreshed. Business context set by a person — criticality, data sensitivity, "
            "ownership — is never overwritten by an import, because an automated source "
            "does not know it."
        ),
    )
    strict: bool = Field(
        default=False,
        description=(
            "When true, the whole batch is rejected if any entry is invalid, and nothing "
            "is written. Use it for a source that should be internally consistent, where a "
            "partial import would be harder to reason about than none."
        ),
    )


class AssetImportRejection(BaseModel):
    """One entry the import could not accept, and why."""

    index: int = Field(description="Position in the submitted array, so the source can be fixed.")
    identifier: str | None = None
    reason: str
    field_errors: list[dict[str, str]] = Field(default_factory=list)


class AssetImportResult(BaseModel):
    """What an import actually did, per outcome.

    The counts sum to the number of entries submitted. An entry that could not
    be accepted appears in ``rejections`` with its position and reason, rather
    than being dropped — an import that silently discards rows produces an
    inventory with a hole in it, and nobody finds out until something
    unassessed is compromised.
    """

    submitted: int
    created: int
    updated: int
    unchanged: int
    rejected: int
    rejections: list[AssetImportRejection] = Field(default_factory=list)
    created_ids: list[uuid.UUID] = Field(default_factory=list)


__all__ = [
    "AssetBase",
    "AssetCreate",
    "AssetDetail",
    "AssetFilters",
    "AssetImportRejection",
    "AssetImportRequest",
    "AssetImportResult",
    "AssetInventorySummary",
    "AssetRelationshipCreate",
    "AssetRelationshipRead",
    "AssetSummary",
    "AssetUpdate",
]
