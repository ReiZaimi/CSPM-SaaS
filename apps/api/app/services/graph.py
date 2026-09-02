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

**Assets that are still there.** An asset a scan looked for and did not find
keeps its row -- deliberately, so its findings stay history and so an asset that
vanishes for a week and returns is one asset rather than two -- and the graph
must not keep it. A route through something that no longer exists is not a
weaker claim than a real one, it is a false one, and it was being served on the
attack-paths page while the scanner's own graph, built from one scan's state,
never contained it. Two views of one tenant disagreeing, with the wrong one
facing the customer.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import RelationshipType
from app.domain.resource import CloudResource
from app.graph import AssetGraph, Path
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
                    ResourceRecord.organization_id == organization_id,
                    # Present, as of the last scan that covered it.
                    ResourceRecord.absent_since.is_(None),
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
        # An edge whose endpoints are not both still present -- because the
        # resource was deleted outright and the edge outlived it, or because it
        # is absent and was filtered above. Following one would describe a route
        # through something that is gone.
        if edge.source_resource_id in by_id and edge.target_resource_id in by_id
    ]

    return AssetGraph.build(resources, relationships)


def serialize_path(path: Path) -> dict:
    step = path.cheapest_break()
    return {
        "entry": {
            "id": path.entry.provider_resource_id,
            "name": path.entry.name,
            "resource_type": path.entry.resource_type.value,
            "public_exposure": path.entry.public_exposure.value,
        },
        "target": {
            "id": path.target.provider_resource_id,
            "name": path.target.name,
            "resource_type": path.target.resource_type.value,
            "data_sensitivity": path.target.data_sensitivity.value,
        },
        "hops": path.hops,
        # The route in plain language, hop by hop. A path that only named its
        # endpoints would be an alarm; naming the route is what makes it a
        # thing somebody can go and cut.
        "steps": [
            {
                "source": s.source.name,
                "source_id": s.source.provider_resource_id,
                "relationship": s.relationship.value,
                "target": s.target.name,
                "target_id": s.target.provider_resource_id,
                "description": s.describe(),
            }
            for s in path.steps
        ],
        # Where to cut it. Containment cannot be removed -- a storage account
        # has to live somewhere -- so this is always a capability hop, and the
        # earliest one closes the way in rather than containing what somebody
        # reaches once inside.
        "cheapest_break": (
            {
                "description": step.describe(),
                "relationship": step.relationship.value,
                "source_id": step.source.provider_resource_id,
                "target_id": step.target.provider_resource_id,
            }
            if step
            else None
        ),
    }
