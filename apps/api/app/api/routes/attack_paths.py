"""Routes from somewhere an attacker could start to something worth taking.

The findings list answers "what is wrong". This answers "what is wrong
*together*" -- and the two are different questions with different first
actions. Five findings across a jump box, an identity and a storage account
rank by severity and get worked top-down; the same five as one path rank by how
few hops separate the internet from customer data, and name the one change that
severs it.
"""

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
from app.graph import Path
from app.services import graph as graph_service

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


def _serialize(path: Path) -> dict:
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


@router.get("")
async def list_attack_paths(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=50, le=200),
) -> dict:
    """Every route from an exposed asset to a sensitive one, shortest first.

    Built from the assets and edges the last scan stored rather than from a
    table of its own: a path is a pure function of those, and a stored one
    could describe a route the customer has already closed.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.attack_paths()

    return envelope(
        [_serialize(path) for path in paths[:limit]],
        {
            "total": len(paths),
            # Both counts are the honest denominator for an empty answer. No
            # paths because nothing is exposed is a different thing from no
            # paths because nothing was classified as sensitive, and a customer
            # reading "0" deserves to know which.
            "entry_points": len(graph.entry_points()),
            "sensitive_targets": len(graph.sensitive_targets()),
        },
    )


@router.get("/blast-radius/{resource_id:path}")
async def blast_radius(
    resource_id: str, session: DbSession, tenant: Tenant
) -> dict:
    """What one identity or asset can act on.

    The question a customer actually asks about an over-privileged principal:
    never "is this role too broad" in the abstract, but "what would go with it".
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    if resource_id not in graph.nodes:
        raise NotFound("No such asset in this organization")

    reached = graph.blast_radius(resource_id)
    return envelope(
        [
            {
                "id": resource.provider_resource_id,
                "name": resource.name,
                "resource_type": resource.resource_type.value,
                "data_sensitivity": resource.data_sensitivity.value,
            }
            for resource in reached
        ],
        {"total": len(reached)},
    )
