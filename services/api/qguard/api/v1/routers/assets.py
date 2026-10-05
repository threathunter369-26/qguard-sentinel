"""Asset inventory endpoints.

Every collection here pages, and every number returned is counted from the
database on request. Nothing is cached, estimated, or seeded.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from qguard.api.deps import (
    AuditDep,
    CurrentPrincipal,
    DbSession,
    OrgId,
    require_permission,
)
from qguard.api.query import apply_sort, paginate
from qguard.api.schemas import Acknowledgement, Page, Pagination, SortOrder
from qguard.assets.schemas import (
    AssetCreate,
    AssetDetail,
    AssetFilters,
    AssetImportRequest,
    AssetImportResult,
    AssetInventorySummary,
    AssetRelationshipCreate,
    AssetRelationshipRead,
    AssetSummary,
    AssetUpdate,
)
from qguard.assets.service import AssetService, RelatedAsset
from qguard.auth.permissions import Perm
from qguard.models.assets import Asset

router = APIRouter(prefix="/assets", tags=["assets"])

#: Sort names this collection publishes, mapped to the columns behind them.
#: A name not in this mapping is rejected rather than ignored.
SORTABLE = {
    "name": Asset.name,
    "asset_type": Asset.asset_type,
    "criticality": Asset.criticality,
    "environment": Asset.environment,
    "risk_score": Asset.risk_score,
    "security_score": Asset.security_score,
    "last_assessed_at": Asset.last_assessed_at,
    "first_seen_at": Asset.first_seen_at,
    "created_at": Asset.created_at,
    "updated_at": Asset.updated_at,
}


def get_asset_service(session: DbSession, audit: AuditDep) -> AssetService:
    return AssetService(session, audit)


ServiceDep = Annotated[AssetService, Depends(get_asset_service)]
FiltersDep = Annotated[AssetFilters, Depends()]
PaginationDep = Annotated[Pagination, Depends()]
SortDep = Annotated[SortOrder, Depends()]


def _relationship_read(related: RelatedAsset) -> AssetRelationshipRead:
    row = AssetRelationshipRead.model_validate(related.relationship)
    row.source_name = related.source_name
    row.target_name = related.target_name
    row.target_asset_type = related.target_asset_type  # type: ignore[assignment]
    row.target_criticality = related.target_criticality  # type: ignore[assignment]
    return row


@router.get(
    "",
    summary="List assets",
    response_model=Page[AssetSummary],
    dependencies=[Depends(require_permission(Perm.ASSET_READ))],
)
async def list_assets(
    session: DbSession,
    service: ServiceDep,
    org_id: OrgId,
    filters: FiltersDep,
    pagination: PaginationDep,
    sort: SortDep,
) -> Page[AssetSummary]:
    """Page through the inventory.

    ``total`` is a counted value, so a client can distinguish "no assets match"
    from "first page of many".
    """
    stmt = apply_sort(
        service.list_query(org_id, filters),
        sort,
        allowed=SORTABLE,
        default=Asset.created_at,
        tiebreaker=Asset.id,
    )
    return await paginate(session, stmt, pagination, serialize=AssetSummary.model_validate)


@router.get(
    "/summary",
    summary="Inventory counts",
    response_model=AssetInventorySummary,
    dependencies=[Depends(require_permission(Perm.ASSET_READ))],
)
async def inventory_summary(
    service: ServiceDep,
    org_id: OrgId,
    filters: FiltersDep,
) -> AssetInventorySummary:
    """Counts across the inventory, honouring the same filters as the list.

    Takes the filters so the header numbers describe exactly the rows shown in
    the table beneath them. A summary computed from an unfiltered query is the
    usual reason a count and a table disagree.
    """
    return await service.inventory_summary(org_id, filters)


@router.post(
    "",
    summary="Add an asset",
    status_code=status.HTTP_201_CREATED,
    response_model=AssetDetail,
    dependencies=[Depends(require_permission(Perm.ASSET_CREATE))],
)
async def create_asset(
    payload: AssetCreate,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> AssetDetail:
    asset = await service.create(principal, payload)
    return await _detail(service, asset)


@router.post(
    "/import",
    summary="Import a batch of assets",
    response_model=AssetImportResult,
    dependencies=[Depends(require_permission(Perm.ASSET_IMPORT))],
)
async def import_assets(
    payload: AssetImportRequest,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> AssetImportResult:
    """Import assets from a discovery source or inventory export.

    Each entry is reported as created, updated, unchanged or rejected, and a
    rejection carries its reason. An import that silently dropped entries would
    leave a hole in the inventory that nobody notices until something
    unassessed is compromised.

    Business context a person has set — criticality, data sensitivity,
    ownership, compensating controls — is never overwritten by an import,
    because the automated source does not know it.
    """
    return await service.import_batch(principal, payload)


@router.get(
    "/{asset_id}",
    summary="Get an asset with its security posture",
    response_model=AssetDetail,
    dependencies=[Depends(require_permission(Perm.ASSET_READ))],
)
async def get_asset(
    asset_id: uuid.UUID,
    service: ServiceDep,
    org_id: OrgId,
) -> AssetDetail:
    asset = await service.get(org_id, asset_id)
    return await _detail(service, asset)


@router.patch(
    "/{asset_id}",
    summary="Update an asset",
    response_model=AssetDetail,
    dependencies=[Depends(require_permission(Perm.ASSET_UPDATE))],
)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> AssetDetail:
    """Apply a partial update.

    The audit entry records the before and after of every field that changed,
    because criticality and data sensitivity feed the risk score and a silent
    change to them silently changes every score derived from them.
    """
    asset = await service.update(principal, asset_id, payload)
    return await _detail(service, asset)


@router.delete(
    "/{asset_id}",
    summary="Retire an asset",
    response_model=Acknowledgement,
    dependencies=[Depends(require_permission(Perm.ASSET_DELETE))],
)
async def retire_asset(
    asset_id: uuid.UUID,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> Acknowledgement:
    """Remove an asset from the active inventory.

    The record is retained rather than deleted: findings, scans and evidence
    reference it, and a security record whose subject has vanished cannot be
    audited. The asset stops being scanned and leaves the active inventory.
    """
    asset = await service.soft_delete(principal, asset_id)
    return Acknowledgement(
        message=(
            f"{asset.name} was retired. Its findings, scans and evidence are retained and "
            "remain queryable."
        ),
        affected=1,
    )


@router.get(
    "/{asset_id}/relationships",
    summary="List an asset's relationships",
    response_model=list[AssetRelationshipRead],
    dependencies=[Depends(require_permission(Perm.ASSET_READ))],
)
async def list_relationships(
    asset_id: uuid.UUID,
    service: ServiceDep,
    org_id: OrgId,
    both_directions: Annotated[
        bool,
        Query(
            description=(
                "Include relationships pointing at this asset as well as from it. "
                "'What depends on this' is as important as 'what this depends on'."
            )
        ),
    ] = True,
) -> list[AssetRelationshipRead]:
    await service.get(org_id, asset_id)
    rows = await service.relationships(org_id, asset_id, both_directions=both_directions)
    return [_relationship_read(row) for row in rows]


@router.post(
    "/{asset_id}/relationships",
    summary="Relate this asset to another",
    status_code=status.HTTP_201_CREATED,
    response_model=AssetRelationshipRead,
    dependencies=[Depends(require_permission(Perm.ASSET_UPDATE))],
)
async def add_relationship(
    asset_id: uuid.UUID,
    payload: AssetRelationshipCreate,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> AssetRelationshipRead:
    relationship = await service.add_relationship(principal, asset_id, payload)
    return AssetRelationshipRead.model_validate(relationship)


@router.delete(
    "/{asset_id}/relationships/{relationship_id}",
    summary="Remove a relationship",
    response_model=Acknowledgement,
    dependencies=[Depends(require_permission(Perm.ASSET_UPDATE))],
)
async def remove_relationship(
    asset_id: uuid.UUID,
    relationship_id: uuid.UUID,
    service: ServiceDep,
    principal: CurrentPrincipal,
) -> Acknowledgement:
    await service.remove_relationship(principal, asset_id, relationship_id)
    return Acknowledgement(message="The relationship was removed.", affected=1)


@router.get(
    "/{asset_id}/dependents",
    summary="What else is affected if this asset is compromised",
    dependencies=[Depends(require_permission(Perm.ASSET_READ))],
)
async def asset_dependents(
    asset_id: uuid.UUID,
    service: ServiceDep,
    org_id: OrgId,
    max_depth: Annotated[int, Query(ge=1, le=6)] = 3,
) -> dict[str, object]:
    """Walk the dependency graph outward from this asset.

    Answers the question a critical finding raises: what else is reachable
    from here. The traversal is bounded in depth and tracks visited nodes,
    because an inventory graph built from discovery data contains cycles.
    """
    asset = await service.get(org_id, asset_id)
    dependents = await service.dependents(org_id, asset_id, max_depth=max_depth)
    return {
        "asset_id": str(asset.id),
        "name": asset.name,
        "max_depth": max_depth,
        "dependent_count": len(dependents),
        "dependents": dependents,
    }


# --------------------------------------------------------------------- helpers
async def _detail(service: AssetService, asset: Asset) -> AssetDetail:
    """Attach the asset's counted security posture to the response."""
    posture = await service.posture(asset.org_id, asset.id)
    detail = AssetDetail.model_validate(asset)
    detail.open_vulnerabilities = posture.open_vulnerabilities
    detail.open_vulnerability_count = posture.open_vulnerability_count
    detail.scan_count = posture.scan_count
    detail.last_scan_status = posture.last_scan_status
    detail.has_active_authorization = posture.has_active_authorization
    return detail


__all__ = ["router"]
