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
from app.services import graph as graph_service
from app.services.graph import serialize_path

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


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
        [serialize_path(path) for path in paths[:limit]],
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
