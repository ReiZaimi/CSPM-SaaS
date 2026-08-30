"""Rebuilding the asset graph from what the last scan stored.

Computed on read rather than persisted, and that is a deliberate limit rather
than a shortcut. Attack paths are a pure function of the assets and edges
already in the database, so storing them would mean keeping a derived table in
step with its inputs -- and a stale path is worse than no path, because it
describes a route somebody may already have closed.

What is genuinely lost is history: "did a new attack path appear this week" is
a question about change over time, and this cannot answer it. That wants an
``attack_paths`` table written per scan, which is worth building once paths are
being acted on rather than looked at (ARCHITECTURE_REVIEW.md section 8).
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import RelationshipType
from app.domain.resource import CloudResource
from app.graph import AssetGraph
from app.models.resource import ResourceRecord, ResourceRelationship


async def load_graph(session: AsyncSession, organization_id: UUID) -> AssetGraph:
    """Every asset this organization holds, and the edges between them.

    Two queries whatever the size of the tenant. The edges are stored by
    database id and the graph works in provider ids -- the ones a customer can
    paste into a portal -- so the mapping happens here rather than leaking a
    surrogate key into something a person reads.
    """
    records = list(
        (
            await session.execute(
                select(ResourceRecord).where(
                    ResourceRecord.organization_id == organization_id
                )
            )
        )
        .scalars()
        .all()
    )

    by_id = {record.id: record.provider_resource_id for record in records}
    edges = (
        (
            await session.execute(
                select(ResourceRelationship).where(
                    ResourceRelationship.organization_id == organization_id
                )
            )
        )
        .scalars()
        .all()
    )

    resources = [
        CloudResource(
            provider_resource_id=record.provider_resource_id,
            resource_type=record.resource_type,
            name=record.name,
            provider=record.provider,
            region=record.region,
            environment=record.environment,
            criticality=record.criticality,
            data_sensitivity=record.data_sensitivity,
            public_exposure=record.public_exposure,
            metadata=record.resource_metadata or {},
        )
        for record in records
    ]

    relationships = [
        (
            by_id[edge.source_resource_id],
            RelationshipType(edge.relationship_type),
            by_id[edge.target_resource_id],
        )
        for edge in edges
        # An edge whose endpoints are not both still present. The resource was
        # deleted and the edge outlived it; following one would describe a route
        # through something that is gone.
        if edge.source_resource_id in by_id and edge.target_resource_id in by_id
    ]

    return AssetGraph.build(resources, relationships)
