"""Asset inventory operations.

Identity is the central concern. ``(org_id, asset_type, identifier)`` is
unique, so the same host reported by a network scan, a cloud inventory import
and a person typing it in resolves to one asset and its findings aggregate.
:meth:`AssetService.upsert` is how every automated source enters the
inventory, and it is deliberately conservative about what it overwrites:
business context — criticality, data sensitivity, ownership, compensating
controls — is set by people who know the system, and a discovery scan does
not know it. An import that clobbered those fields would quietly destroy the
inputs the risk model depends on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import Select, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.api.query import (
    apply_array_overlap,
    apply_in,
    apply_search,
    group_count,
)
from qguard.api.schemas import CountByKey, SeverityCounts
from qguard.assets.schemas import (
    AssetCreate,
    AssetFilters,
    AssetImportRejection,
    AssetImportRequest,
    AssetImportResult,
    AssetInventorySummary,
    AssetRelationshipCreate,
    AssetUpdate,
)
from qguard.audit.service import AuditService
from qguard.auth.principal import Principal
from qguard.common.enums import (
    OPEN_VULNERABILITY_STATUSES,
    AssetRelation,
    AuthorizationStatus,
)
from qguard.common.errors import ConflictError, NotFoundError, ValidationError
from qguard.common.logging import get_logger
from qguard.models.assets import Asset, AssetRelationship
from qguard.models.audit import AuditAction
from qguard.models.findings import Vulnerability
from qguard.models.scanning import Scan, TestAuthorization

log = get_logger(__name__)

#: Fields an automated source may refresh on an asset it rediscovers. Anything
#: not listed here is left alone, because a scanner does not know it.
_IMPORT_REFRESHABLE = frozenset(
    {
        "name",
        "description",
        "hostname",
        "domain",
        "ip_address",
        "port",
        "url",
        "operating_system",
        "technology",
        "cloud_provider",
        "cloud_account_id",
        "cloud_region",
        "attributes",
    }
)

#: Fields only a person (or an explicit update) may change. Listed explicitly
#: so the rule is reviewable rather than implied by what the import happens
#: to send.
_HUMAN_OWNED = frozenset(
    {
        "criticality",
        "data_sensitivity",
        "environment",
        "business_value",
        "owner_user_id",
        "owning_team_id",
        "compensating_controls",
        "requires_authentication",
        "tags",
    }
)


@dataclass(slots=True)
class RelatedAsset:
    """A relationship with the far end resolved enough to render a graph node."""

    relationship: AssetRelationship
    source_name: str | None
    target_name: str | None
    target_asset_type: str | None
    target_criticality: str | None


@dataclass(slots=True)
class AssetPosture:
    """An asset's security state, counted at read time."""

    open_vulnerabilities: SeverityCounts = field(default_factory=SeverityCounts)
    open_vulnerability_count: int = 0
    scan_count: int = 0
    last_scan_status: str | None = None
    has_active_authorization: bool = False


class AssetService:
    """Reads and writes the asset inventory."""

    def __init__(self, session: AsyncSession, audit: AuditService | None = None) -> None:
        self.session = session
        self.audit = audit

    # ------------------------------------------------------------------ reads
    def list_query(self, org_id: uuid.UUID, filters: AssetFilters) -> Select[Any]:
        """Build the filtered asset query.

        Returned rather than executed so the caller can reuse the same
        statement for the page, the total and any breakdown — which is what
        keeps a table and the chart beside it describing the same rows.
        """
        stmt = select(Asset).where(Asset.org_id == org_id, Asset.deleted_at.is_(None))

        if filters.is_active is not None:
            stmt = stmt.where(Asset.is_active.is_(filters.is_active))
        stmt = apply_search(
            stmt,
            filters.search,
            (Asset.name, Asset.identifier, Asset.hostname, Asset.url),
        )
        stmt = apply_in(stmt, Asset.asset_type, filters.asset_type)
        stmt = apply_in(stmt, Asset.environment, filters.environment)
        stmt = apply_in(stmt, Asset.criticality, filters.criticality)
        stmt = apply_in(stmt, Asset.data_sensitivity, filters.data_sensitivity)
        stmt = apply_in(stmt, Asset.discovery_source, filters.discovery_source)
        stmt = apply_array_overlap(stmt, Asset.tags, filters.tags)

        if filters.internet_facing is not None:
            stmt = stmt.where(Asset.internet_facing.is_(filters.internet_facing))
        if filters.project_id is not None:
            stmt = stmt.where(Asset.project_id == filters.project_id)
        if filters.owner_user_id is not None:
            stmt = stmt.where(Asset.owner_user_id == filters.owner_user_id)
        if filters.parent_asset_id is not None:
            stmt = stmt.where(Asset.parent_asset_id == filters.parent_asset_id)
        if filters.cloud_provider:
            stmt = stmt.where(Asset.cloud_provider == filters.cloud_provider)
        if filters.never_assessed:
            stmt = stmt.where(Asset.last_assessed_at.is_(None))

        if filters.has_open_vulnerabilities is not None:
            open_assets = (
                select(Vulnerability.asset_id)
                .where(
                    Vulnerability.org_id == org_id,
                    Vulnerability.status.in_(list(OPEN_VULNERABILITY_STATUSES)),
                    Vulnerability.asset_id.is_not(None),
                )
                .distinct()
            )
            if filters.has_open_vulnerabilities:
                stmt = stmt.where(Asset.id.in_(open_assets))
            else:
                stmt = stmt.where(Asset.id.not_in(open_assets))

        return stmt

    async def get(self, org_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
        asset = await self.session.scalar(
            select(Asset).where(
                Asset.id == asset_id,
                Asset.org_id == org_id,
                Asset.deleted_at.is_(None),
            )
        )
        if asset is None:
            raise NotFoundError(f"No asset {asset_id} exists in this organization.")
        return asset

    async def posture(self, org_id: uuid.UUID, asset_id: uuid.UUID) -> AssetPosture:
        """Count an asset's current security state.

        Counted on request rather than stored. A denormalised counter on the
        asset row would be wrong between a scan finishing and the counter
        being updated, and a dashboard reading a stale counter is worse than
        one that waits for a query.
        """
        severity_rows = (
            await self.session.execute(
                select(Vulnerability.severity, func.count())
                .where(
                    Vulnerability.org_id == org_id,
                    Vulnerability.asset_id == asset_id,
                    Vulnerability.status.in_(list(OPEN_VULNERABILITY_STATUSES)),
                )
                .group_by(Vulnerability.severity)
            )
        ).all()
        counts = SeverityCounts.from_rows([(str(s), int(c)) for s, c in severity_rows])

        # ``asset_ids`` is a uuid[] on the scan, so membership is an array
        # containment test (``@>``) rather than a join.
        covers_asset = Scan.asset_ids.contains([asset_id])
        scan_count = int(
            await self.session.scalar(
                select(func.count(Scan.id)).where(Scan.org_id == org_id, covers_asset)
            )
            or 0
        )
        last_scan_status = await self.session.scalar(
            select(Scan.status)
            .where(Scan.org_id == org_id, covers_asset)
            .order_by(Scan.queued_at.desc())
            .limit(1)
        )

        # An asset is "authorized" only while an approved authorization is
        # inside its validity window. An expired one grants nothing, and the
        # UI must not show a stale green badge against it.
        now = datetime.now(UTC)
        authorized = await self.session.scalar(
            select(func.count(TestAuthorization.id)).where(
                TestAuthorization.org_id == org_id,
                TestAuthorization.status == AuthorizationStatus.ACTIVE,
                TestAuthorization.approved_at.is_not(None),
                TestAuthorization.revoked_at.is_(None),
                (TestAuthorization.valid_from.is_(None)) | (TestAuthorization.valid_from <= now),
                (TestAuthorization.valid_until.is_(None)) | (TestAuthorization.valid_until >= now),
            )
        )

        return AssetPosture(
            open_vulnerabilities=counts,
            open_vulnerability_count=counts.total,
            scan_count=scan_count,
            last_scan_status=str(last_scan_status) if last_scan_status else None,
            has_active_authorization=bool(authorized),
        )

    async def inventory_summary(
        self, org_id: uuid.UUID, filters: AssetFilters
    ) -> AssetInventorySummary:
        """Counts across the inventory, every one from a live query."""
        base = self.list_query(org_id, filters)

        async def count_where(*conditions: Any) -> int:
            stmt = base.order_by(None)
            for condition in conditions:
                stmt = stmt.where(condition)
            value = await self.session.scalar(select(func.count()).select_from(stmt.subquery()))
            return int(value or 0)

        total = await count_where()
        thirty_days_ago = datetime.now(UTC) - timedelta(days=30)

        critical_or_high = (
            select(Vulnerability.asset_id)
            .where(
                Vulnerability.org_id == org_id,
                Vulnerability.status.in_(list(OPEN_VULNERABILITY_STATUSES)),
                Vulnerability.severity.in_(["critical", "high"]),
                Vulnerability.asset_id.is_not(None),
            )
            .distinct()
        )

        return AssetInventorySummary(
            total=total,
            active=await count_where(Asset.is_active.is_(True)),
            inactive=await count_where(Asset.is_active.is_(False)),
            internet_facing=await count_where(Asset.internet_facing.is_(True)),
            never_assessed=await count_where(Asset.last_assessed_at.is_(None)),
            assessed_in_last_30_days=await count_where(Asset.last_assessed_at >= thirty_days_ago),
            with_open_critical_or_high=await count_where(Asset.id.in_(critical_or_high)),
            by_type=await self._breakdown(base, Asset.asset_type),
            by_environment=await self._breakdown(base, Asset.environment),
            by_criticality=await self._breakdown(base, Asset.criticality),
            by_discovery_source=await self._breakdown(base, Asset.discovery_source),
        )

    async def _breakdown(self, stmt: Select[Any], column: Any) -> list[CountByKey]:
        rows = await group_count(self.session, stmt, column)
        return [CountByKey(key=key, count=count) for key, count in rows]

    # ----------------------------------------------------------------- writes
    async def create(self, principal: Principal, payload: AssetCreate) -> Asset:
        """Add an asset, refusing a duplicate identity."""
        org_id = self._require_org(principal)
        existing = await self.session.scalar(
            select(Asset.id).where(
                Asset.org_id == org_id,
                Asset.asset_type == payload.asset_type,
                Asset.identifier == payload.identifier,
                Asset.deleted_at.is_(None),
            )
        )
        if existing is not None:
            raise ConflictError(
                f"An asset of type {payload.asset_type.value!r} with the identifier "
                f"{payload.identifier!r} already exists.",
                details={"asset_id": str(existing)},
            )

        asset = Asset(
            org_id=org_id,
            created_by=principal.user_id,
            updated_by=principal.user_id,
            first_seen_at=datetime.now(UTC),
            **payload.model_dump(),
        )
        self.session.add(asset)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            # The unique index is the real arbiter: two concurrent creates can
            # both pass the check above.
            raise ConflictError(
                f"An asset of type {payload.asset_type.value!r} with the identifier "
                f"{payload.identifier!r} already exists."
            ) from exc

        await self._audit(
            principal,
            AuditAction.ASSET_ADDED,
            asset,
            {"asset_type": str(asset.asset_type), "identifier": asset.identifier},
        )
        return asset

    async def update(
        self, principal: Principal, asset_id: uuid.UUID, payload: AssetUpdate
    ) -> Asset:
        """Apply a partial update, recording exactly what changed."""
        org_id = self._require_org(principal)
        asset = await self.get(org_id, asset_id)
        changes = payload.changes()
        if not changes:
            raise ValidationError("The request contained no fields to update.")

        if "parent_asset_id" in changes and changes["parent_asset_id"] is not None:
            await self._check_parent(org_id, asset_id, changes["parent_asset_id"])

        applied: dict[str, dict[str, Any]] = {}
        for key, value in changes.items():
            before = getattr(asset, key)
            if before == value:
                continue
            setattr(asset, key, value)
            applied[key] = {"from": _audit_value(before), "to": _audit_value(value)}

        if not applied:
            return asset

        asset.updated_by = principal.user_id
        await self.session.flush()
        await self._audit(
            principal,
            AuditAction.ASSET_UPDATED,
            asset,
            {"fields_changed": sorted(applied)},
            before={key: change["from"] for key, change in applied.items()},
            after={key: change["to"] for key, change in applied.items()},
        )
        return asset

    async def soft_delete(self, principal: Principal, asset_id: uuid.UUID) -> Asset:
        """Retire an asset without destroying its history.

        A soft delete, because findings, scans and evidence reference the
        asset and a security record that loses its subject is not auditable.
        The asset leaves the active inventory and stops being scanned.
        """
        org_id = self._require_org(principal)
        asset = await self.get(org_id, asset_id)
        asset.deleted_at = datetime.now(UTC)
        asset.is_active = False
        asset.updated_by = principal.user_id
        await self.session.flush()
        await self._audit(
            principal,
            AuditAction.ASSET_REMOVED,
            asset,
            {"identifier": asset.identifier, "retained": "findings, scans and evidence"},
        )
        return asset

    async def upsert(
        self,
        org_id: uuid.UUID,
        payload: AssetCreate,
        *,
        actor_user_id: uuid.UUID | None = None,
        update_existing: bool = True,
    ) -> tuple[Asset, str]:
        """Create or refresh an asset by identity.

        Returns the asset and one of ``created``, ``updated`` or
        ``unchanged``. Only the descriptive fields are refreshed: business
        context is left as a person set it, because the automated source that
        rediscovered the asset does not know it.
        """
        asset = await self.session.scalar(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.asset_type == payload.asset_type,
                Asset.identifier == payload.identifier,
            )
        )
        if asset is None:
            asset = Asset(
                org_id=org_id,
                created_by=actor_user_id,
                updated_by=actor_user_id,
                first_seen_at=datetime.now(UTC),
                **payload.model_dump(),
            )
            self.session.add(asset)
            await self.session.flush()
            return asset, "created"

        if asset.deleted_at is not None:
            # A rediscovered asset is back in the inventory: it evidently
            # still exists, and leaving it retired would hide its findings.
            asset.deleted_at = None
            asset.is_active = True

        if not update_existing:
            return asset, "unchanged"

        changed = False
        for key, value in payload.model_dump().items():
            if key not in _IMPORT_REFRESHABLE:
                continue
            if value in (None, {}, []) or getattr(asset, key) == value:
                continue
            setattr(asset, key, value)
            changed = True

        if changed:
            asset.updated_by = actor_user_id
            await self.session.flush()
        return asset, "updated" if changed else "unchanged"

    async def import_batch(
        self, principal: Principal, payload: AssetImportRequest
    ) -> AssetImportResult:
        """Import a batch, validating and reporting each entry on its own.

        Entries arrive as raw objects and are validated one at a time, so a
        malformed row is reported with its position and reason while the rest
        of the batch still lands. Validating the whole list up front would
        reject a 900-asset export over a single typo, leaving the inventory
        unchanged and nothing recorded about why — which is exactly the silent
        gap this endpoint exists to avoid.

        ``strict`` reverses that for a source that should be internally
        consistent: any invalid entry refuses the whole batch and writes
        nothing.
        """
        org_id = self._require_org(principal)
        result = AssetImportResult(
            submitted=len(payload.assets), created=0, updated=0, unchanged=0, rejected=0
        )

        # Validation first, so ``strict`` can refuse before anything is written.
        validated: list[tuple[int, AssetCreate]] = []
        for index, raw in enumerate(payload.assets):
            try:
                entry = AssetCreate.model_validate(raw)
            except PydanticValidationError as exc:
                result.rejected += 1
                result.rejections.append(
                    AssetImportRejection(
                        index=index,
                        identifier=_entry_identifier(raw),
                        reason="The entry is not a valid asset.",
                        field_errors=[
                            {
                                "field": ".".join(str(part) for part in error["loc"]) or "(body)",
                                "message": str(error["msg"]),
                            }
                            for error in exc.errors()[:10]
                        ],
                    )
                )
                continue
            if entry.discovery_source == "manual":
                entry = entry.model_copy(update={"discovery_source": payload.discovery_source})
            validated.append((index, entry))

        if payload.strict and result.rejections:
            raise ValidationError(
                f"{result.rejected} of {len(payload.assets)} entries are invalid and the "
                "request asked for strict handling, so nothing was imported.",
                details={"rejections": [r.model_dump(mode="json") for r in result.rejections[:50]]},
            )

        for index, entry in validated:
            # A savepoint per entry: one failing insert must not abandon the
            # work already done, and the enclosing request transaction stays
            # usable either way.
            savepoint = await self.session.begin_nested()
            try:
                asset, outcome = await self.upsert(
                    org_id,
                    entry,
                    actor_user_id=principal.user_id,
                    update_existing=payload.update_existing,
                )
            except (IntegrityError, ValueError) as exc:
                await savepoint.rollback()
                result.rejected += 1
                result.rejections.append(
                    AssetImportRejection(
                        index=index,
                        identifier=entry.identifier,
                        reason=str(exc)[:500],
                    )
                )
                continue
            await savepoint.commit()

            if outcome == "created":
                result.created += 1
                result.created_ids.append(asset.id)
            elif outcome == "updated":
                result.updated += 1
            else:
                result.unchanged += 1

        await self._audit_event(
            principal,
            AuditAction.ASSET_IMPORTED,
            {
                "source": payload.discovery_source,
                "submitted": result.submitted,
                "created": result.created,
                "updated": result.updated,
                "unchanged": result.unchanged,
                "rejected": result.rejected,
                # The reasons go in the audit entry too: an import that lost a
                # tenth of its input is a coverage gap, and the record of why
                # should outlive the HTTP response.
                "rejection_reasons": [r.reason for r in result.rejections[:20]],
            },
        )
        return result

    # ---------------------------------------------------------- relationships
    async def relationships(
        self, org_id: uuid.UUID, asset_id: uuid.UUID, *, both_directions: bool = True
    ) -> list[RelatedAsset]:
        """Relationships touching an asset, with the far end's name resolved.

        Both directions by default: "what depends on this" is as important as
        "what this depends on", and a graph drawn from one direction only
        hides the blast radius.
        """
        source = Asset.__table__.alias("source_asset")
        target = Asset.__table__.alias("target_asset")
        stmt = (
            select(
                AssetRelationship,
                source.c.name,
                target.c.name,
                target.c.asset_type,
                target.c.criticality,
            )
            .join(source, source.c.id == AssetRelationship.source_asset_id)
            .join(target, target.c.id == AssetRelationship.target_asset_id)
            .where(AssetRelationship.org_id == org_id)
        )
        if both_directions:
            stmt = stmt.where(
                (AssetRelationship.source_asset_id == asset_id)
                | (AssetRelationship.target_asset_id == asset_id)
            )
        else:
            stmt = stmt.where(AssetRelationship.source_asset_id == asset_id)
        rows = await self.session.execute(stmt.order_by(AssetRelationship.created_at.desc()))
        return [
            RelatedAsset(
                relationship=relationship,
                source_name=source_name,
                target_name=target_name,
                target_asset_type=str(target_type) if target_type else None,
                target_criticality=str(target_criticality) if target_criticality else None,
            )
            for relationship, source_name, target_name, target_type, target_criticality in (
                rows.all()
            )
        ]

    async def add_relationship(
        self,
        principal: Principal,
        asset_id: uuid.UUID,
        payload: AssetRelationshipCreate,
    ) -> AssetRelationship:
        """Link two assets, refusing a self-link or a cross-tenant target."""
        org_id = self._require_org(principal)
        if asset_id == payload.target_asset_id:
            raise ValidationError("An asset cannot be related to itself.")

        await self.get(org_id, asset_id)
        await self.get(org_id, payload.target_asset_id)

        existing = await self.session.scalar(
            select(AssetRelationship).where(
                AssetRelationship.org_id == org_id,
                AssetRelationship.source_asset_id == asset_id,
                AssetRelationship.target_asset_id == payload.target_asset_id,
                AssetRelationship.relation == payload.relation,
            )
        )
        if existing is not None:
            raise ConflictError(
                f"A {payload.relation.value!r} relationship between these assets already exists.",
                details={"relationship_id": str(existing.id)},
            )

        relationship = AssetRelationship(
            org_id=org_id,
            source_asset_id=asset_id,
            target_asset_id=payload.target_asset_id,
            relation=payload.relation,
            confidence=payload.confidence,
            discovered_by="manual",
            attributes=payload.attributes,
        )
        self.session.add(relationship)
        await self.session.flush()
        await self._audit_event(
            principal,
            AuditAction.ASSET_RELATIONSHIP_ADDED,
            {
                "asset_id": str(asset_id),
                "relationship": payload.relation.value,
                "target_asset_id": str(payload.target_asset_id),
                "confidence": payload.confidence.value,
            },
        )
        return relationship

    async def remove_relationship(
        self, principal: Principal, asset_id: uuid.UUID, relationship_id: uuid.UUID
    ) -> None:
        org_id = self._require_org(principal)
        relationship = await self.session.scalar(
            select(AssetRelationship).where(
                AssetRelationship.id == relationship_id,
                AssetRelationship.org_id == org_id,
            )
        )
        if relationship is None:
            raise NotFoundError(f"No relationship {relationship_id} exists in this organization.")
        if asset_id not in (relationship.source_asset_id, relationship.target_asset_id):
            raise ValidationError(
                "That relationship does not involve the asset it was requested under."
            )
        await self.session.delete(relationship)
        await self.session.flush()
        await self._audit_event(
            principal,
            AuditAction.ASSET_RELATIONSHIP_REMOVED,
            {"asset_id": str(asset_id), "relationship_id": str(relationship_id)},
        )

    async def dependents(
        self, org_id: uuid.UUID, asset_id: uuid.UUID, *, max_depth: int = 3
    ) -> list[dict[str, Any]]:
        """Assets that depend on this one, breadth first to a bounded depth.

        Answers "what else is affected" for an asset with an open critical
        finding. Depth is bounded and visited nodes are tracked, because an
        inventory graph built from discovery data contains cycles.
        """
        if max_depth < 1 or max_depth > 6:
            raise ValidationError("max_depth must be between 1 and 6.")

        seen: set[uuid.UUID] = {asset_id}
        frontier = [asset_id]
        out: list[dict[str, Any]] = []

        for depth in range(1, max_depth + 1):
            if not frontier:
                break
            rows = (
                await self.session.execute(
                    select(
                        AssetRelationship.source_asset_id,
                        AssetRelationship.relation,
                        Asset.id,
                        Asset.name,
                        Asset.asset_type,
                        Asset.criticality,
                        Asset.environment,
                    )
                    .join(Asset, Asset.id == AssetRelationship.source_asset_id)
                    .where(
                        AssetRelationship.org_id == org_id,
                        AssetRelationship.target_asset_id.in_(frontier),
                        AssetRelationship.relation.in_(
                            [AssetRelation.DEPENDS_ON, AssetRelation.PART_OF]
                        ),
                        Asset.deleted_at.is_(None),
                    )
                )
            ).all()

            next_frontier: list[uuid.UUID] = []
            for _source_id, relation, dep_id, name, asset_type, criticality, environment in rows:
                if dep_id in seen:
                    continue
                seen.add(dep_id)
                next_frontier.append(dep_id)
                out.append(
                    {
                        "asset_id": str(dep_id),
                        "name": name,
                        "asset_type": str(asset_type),
                        "criticality": str(criticality),
                        "environment": str(environment),
                        "relation": str(relation),
                        "depth": depth,
                    }
                )
            frontier = next_frontier

        return out

    # --------------------------------------------------------------- internals
    async def _check_parent(
        self, org_id: uuid.UUID, asset_id: uuid.UUID, parent_id: uuid.UUID
    ) -> None:
        """Refuse a parent that would create a cycle in the hierarchy."""
        if parent_id == asset_id:
            raise ValidationError("An asset cannot be its own parent.")
        await self.get(org_id, parent_id)

        current: uuid.UUID | None = parent_id
        seen: set[uuid.UUID] = set()
        while current is not None:
            if current == asset_id:
                raise ValidationError("That parent would create a cycle in the asset hierarchy.")
            if current in seen:
                break
            seen.add(current)
            current = await self.session.scalar(
                select(Asset.parent_asset_id).where(Asset.id == current, Asset.org_id == org_id)
            )

    @staticmethod
    def _require_org(principal: Principal) -> uuid.UUID:
        if principal.org_id is None:
            raise ValidationError(
                "This operation needs an organization context, and the caller has none."
            )
        return principal.org_id

    async def _audit(
        self,
        principal: Principal,
        action: str,
        asset: Asset,
        metadata: dict[str, Any],
        *,
        before: dict[str, Any] | None = None,
        after: dict[str, Any] | None = None,
    ) -> None:
        if self.audit is None:
            return
        await self.audit.record(
            action=action,
            org_id=asset.org_id,
            actor=principal,
            resource_type="asset",
            resource_id=asset.id,
            resource_label=asset.name,
            before=before,
            after=after,
            metadata=metadata,
        )

    async def _audit_event(
        self, principal: Principal, action: str, metadata: dict[str, Any]
    ) -> None:
        if self.audit is None:
            return
        await self.audit.record(
            action=action,
            org_id=principal.org_id,
            actor=principal,
            resource_type="asset",
            metadata=metadata,
        )


def _entry_identifier(raw: dict[str, Any]) -> str | None:
    """The identifier of a rejected entry, if it supplied a usable one.

    Reported so the source system can locate the offending row by value as
    well as by position.
    """
    value = raw.get("identifier")
    return value[:200] if isinstance(value, str) else None


def _audit_value(value: Any) -> Any:
    """Render a value for the audit trail without losing its meaning."""
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, dict, str, int, float, bool)) or value is None:
        return value
    return str(value)


__all__ = ["AssetPosture", "AssetService", "RelatedAsset"]
