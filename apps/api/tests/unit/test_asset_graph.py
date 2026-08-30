"""The asset graph, and the sentence no rule can produce.

Rules are local by design: each looks at one resource and decides. One can say
a virtual machine is reachable from the internet; another can say an identity
holds Contributor over a subscription. Neither can say they are the same
machine -- and that sentence is the product:

    an internet-facing host runs as an identity that can act across the
    subscription the customer's data sits in

Pure tests: a graph is built from resources and edges and asked questions. No
database, no Azure, no scan.
"""

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph

SUB = "/subscriptions/sub-1"
GROUP = f"{SUB}/resourceGroups/prod"
VM = f"{GROUP}/providers/Microsoft.Compute/virtualMachines/jump-01"
IDENTITY = "/principals/mi-jump-01"
STORAGE = f"{GROUP}/providers/Microsoft.Storage/storageAccounts/customerdata"
QUIET_VM = f"{GROUP}/providers/Microsoft.Compute/virtualMachines/batch-07"


def node(
    resource_id: str,
    kind: ResourceType,
    *,
    name: str = "",
    exposure: Level = Level.LOW,
    sensitivity: Level = Level.LOW,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=name or resource_id.rsplit("/", 1)[-1],
        public_exposure=exposure,
        data_sensitivity=sensitivity,
    )


def environment() -> AssetGraph:
    """The shape the whole exercise is for.

    An internet-facing jump box, running as a managed identity, which holds a
    role over the subscription that contains the customer data.
    """
    return AssetGraph.build(
        [
            node(SUB, ResourceType.SUBSCRIPTION),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
            node(QUIET_VM, ResourceType.VIRTUAL_MACHINE),
        ],
        [
            (SUB, RelationshipType.CONTAINS, GROUP),
            (GROUP, RelationshipType.CONTAINS, VM),
            (GROUP, RelationshipType.CONTAINS, STORAGE),
            (GROUP, RelationshipType.CONTAINS, QUIET_VM),
            (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, SUB),
        ],
    )


# ----------------------------------------------------------------- the point
def test_the_path_no_rule_could_find() -> None:
    """Five findings on five resources are five rows. This is one fact."""
    paths = environment().attack_paths()

    assert paths, "an internet-facing host reaching customer data is a path"
    reached = {p.target.provider_resource_id for p in paths}
    assert STORAGE in reached


def test_the_path_says_how_it_got_there() -> None:
    """"This storage account is reachable" is an alarm. Naming the route is a
    thing somebody can act on, and it names every place they could cut it."""
    path = next(
        p for p in environment().attack_paths()
        if p.target.provider_resource_id == STORAGE
    )

    assert path.entry.provider_resource_id == VM
    assert path.describe() == [
        "jump-01 runs as mi-jump-01",
        "mi-jump-01 can act over sub-1",
        "sub-1 contains prod",
        "prod contains customerdata",
    ]


def test_the_cheapest_break_is_a_capability_hop() -> None:
    """Containment cannot be removed -- a storage account has to live
    somewhere. Detaching the identity or removing the role severs the route,
    and the earliest of those closes the way in rather than containing what
    somebody reaches once inside.
    """
    path = next(
        p for p in environment().attack_paths()
        if p.target.provider_resource_id == STORAGE
    )
    step = path.cheapest_break()

    assert step is not None
    assert step.relationship == RelationshipType.HAS_IDENTITY
    assert step.source.provider_resource_id == VM


# --------------------------------------------------------------- what it is not
def test_an_unexposed_host_is_not_an_entry_point() -> None:
    """Otherwise every asset in the tenant is the start of an attack path, and
    the answer stops meaning anything."""
    entries = {e.provider_resource_id for e in environment().entry_points()}

    assert VM in entries
    assert QUIET_VM not in entries


def test_unknown_exposure_is_not_treated_as_exposed() -> None:
    """The gap-into-alarm mistake, which is the one worth guarding.

    UNKNOWN means CloudGuard could not work the exposure out. Treating that as
    internet-facing would manufacture attack paths out of failed collection --
    the same overclaim as a PASS nobody earned, pointed the other way.
    """
    graph = AssetGraph.build(
        [node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.UNKNOWN)], []
    )
    assert graph.entry_points() == []


def test_unknown_sensitivity_is_not_treated_as_sensitive() -> None:
    """The mirror image. An asset CloudGuard could not classify is not thereby
    the customer's crown jewels."""
    graph = AssetGraph.build(
        [node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.UNKNOWN)], []
    )
    assert graph.sensitive_targets() == []


def test_structural_edges_are_not_routes() -> None:
    """An NSG protecting a VM is a fact about the VM's configuration, not a way
    to get anywhere from the NSG. Walking it would produce something that reads
    as an attack path and describes nothing an attacker could do.
    """
    nsg = f"{GROUP}/providers/Microsoft.Network/networkSecurityGroups/nsg-1"
    graph = AssetGraph.build(
        [
            node(nsg, ResourceType.NETWORK_SECURITY_GROUP, exposure=Level.CRITICAL),
            node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
        ],
        [(nsg, RelationshipType.PROTECTS, STORAGE)],
    )

    assert graph.attack_paths() == []


def test_an_edge_to_something_never_seen_is_dropped() -> None:
    """A dangling edge is not a shorter path -- it is a path through an asset
    CloudGuard never collected, and following one would describe reach it
    cannot support."""
    graph = AssetGraph.build(
        [node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL)],
        [(VM, RelationshipType.HAS_IDENTITY, "/principals/never-collected")],
    )

    assert graph.reachable_from(VM) == {}


def test_a_tenant_with_nothing_sensitive_has_no_paths() -> None:
    """Not an empty answer for lack of looking: there is genuinely nowhere a
    path could end that would cost the customer anything."""
    graph = AssetGraph.build(
        [
            node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
        ],
        [(VM, RelationshipType.HAS_IDENTITY, IDENTITY)],
    )
    assert graph.attack_paths() == []


# ------------------------------------------------------------- blast radius
def test_blast_radius_answers_what_would_go_with_it() -> None:
    """The question a customer actually asks about an over-privileged identity:
    never "is this role too broad" in the abstract, but "what goes if this is
    taken"."""
    reached = {
        r.provider_resource_id for r in environment().blast_radius(IDENTITY)
    }

    assert reached == {VM, STORAGE, QUIET_VM}


def test_blast_radius_reports_assets_not_scopes() -> None:
    """A subscription is where the reach lands; the resources beneath it are
    what the reach is of. Listing both would count the same authority twice."""
    reached = {
        r.resource_type for r in environment().blast_radius(IDENTITY)
    }

    assert ResourceType.SUBSCRIPTION not in reached
    assert ResourceType.RESOURCE_GROUP not in reached


def test_an_identity_nobody_granted_anything_reaches_nothing() -> None:
    graph = AssetGraph.build(
        [node(IDENTITY, ResourceType.SERVICE_PRINCIPAL)], []
    )
    assert graph.blast_radius(IDENTITY) == []


# -------------------------------------------------------------------- bounds
def test_traversal_records_the_shortest_route() -> None:
    """A shorter path is a smaller thing to explain and usually a cheaper thing
    to break, so it is the one worth keeping when two exist."""
    direct = f"{GROUP}/providers/Microsoft.Storage/storageAccounts/direct"
    graph = AssetGraph.build(
        [
            node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(direct, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
        ],
        [
            (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, direct),
        ],
    )

    path = graph.attack_paths()[0]
    assert path.hops == 2


def test_a_long_containment_chain_does_not_run_away() -> None:
    """Every real path this graph expresses is three or four hops. A longer one
    is a containment chain being walked for its own sake."""
    ids = [f"{SUB}/level/{n}" for n in range(12)]
    graph = AssetGraph.build(
        [node(i, ResourceType.RESOURCE_GROUP) for i in ids],
        [
            (ids[n], RelationshipType.CONTAINS, ids[n + 1])
            for n in range(len(ids) - 1)
        ],
    )

    assert len(graph.reachable_from(ids[0], max_depth=3)) == 3


# --------------------------------------------------------------- round trip
def test_the_graph_survives_being_keyed_by_surrogate_ids() -> None:
    """Edges are stored by database id; the graph works in provider ids.

    That translation is where a round trip actually breaks, and it breaks
    quietly: a mapping that dropped an endpoint would leave a path silently
    short rather than raising, and a shorter path reads as a *better* answer.

    This mimics exactly what ``services/graph.load_graph`` does, without
    needing PostgreSQL to do it.
    """
    import uuid as uuidlib

    resources = [
        node(SUB, ResourceType.SUBSCRIPTION),
        node(GROUP, ResourceType.RESOURCE_GROUP),
        node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
        node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
        node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
    ]
    provider_edges = [
        (SUB, RelationshipType.CONTAINS, GROUP),
        (GROUP, RelationshipType.CONTAINS, STORAGE),
        (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
        (IDENTITY, RelationshipType.GRANTS_ROLE, SUB),
    ]

    # Store: every asset gets a surrogate key, and edges are written against it.
    surrogate = {r.provider_resource_id: uuidlib.uuid4() for r in resources}
    stored = [
        (surrogate[s], relationship, surrogate[t]) for s, relationship, t in provider_edges
    ]

    # Load: the surrogate keys come back and have to become provider ids again.
    by_id = {value: key for key, value in surrogate.items()}
    rebuilt = AssetGraph.build(
        resources,
        [(by_id[s], relationship, by_id[t]) for s, relationship, t in stored],
    )

    paths = rebuilt.attack_paths()
    assert len(paths) == 1
    assert paths[0].target.provider_resource_id == STORAGE
    assert paths[0].hops == 4


def test_an_edge_whose_endpoint_was_deleted_is_dropped_on_load() -> None:
    """A resource can go while an edge naming it lingers. Following one would
    describe a route through an asset that no longer exists."""
    import uuid as uuidlib

    live = uuidlib.uuid4()
    gone = uuidlib.uuid4()
    by_id = {live: VM}

    relationships = [
        (by_id[s], relationship, by_id[t])
        for s, relationship, t in [(live, RelationshipType.HAS_IDENTITY, gone)]
        if s in by_id and t in by_id
    ]
    assert relationships == []


# ------------------------------------------------------- privilege escalation
def escalating_environment() -> AssetGraph:
    """The same shape, with the identity able to hand out roles.

    Both edges between the identity and the subscription, because they are
    different claims about the same pair: one says what the principal may do
    today, the other says the ceiling is whatever it chooses to give itself.
    """
    graph = environment()
    graph._out.setdefault(IDENTITY, []).append(
        (RelationshipType.CAN_GRANT_ROLES, SUB)
    )
    return graph


def test_a_chain_ends_at_the_scope_that_could_be_taken() -> None:
    """Not at the identity. "This VM runs as something that can grant itself
    Owner" is alarming; naming what it can do that over is what makes it
    actionable."""
    chains = escalating_environment().escalation_chains()

    assert len(chains) == 1
    chain = chains[0]
    assert chain.entry.provider_resource_id == VM
    assert chain.target.provider_resource_id == SUB
    assert chain.describe()[-1] == "mi-jump-01 can grant itself any role over sub-1"


def test_an_identity_that_only_holds_a_role_is_no_chain() -> None:
    """Holding Contributor is reach. Being able to assign roles is reach with no
    ceiling, and only the second is what this template is about."""
    assert environment().escalation_chains() == []


def test_an_unreachable_administrator_is_not_a_chain() -> None:
    """Over-privileged, certainly. But there is no route from outside to them
    here, and reporting one would invent the half that makes it urgent."""
    graph = AssetGraph.build(
        [
            node(SUB, ResourceType.SUBSCRIPTION),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
        ],
        [(IDENTITY, RelationshipType.CAN_GRANT_ROLES, SUB)],
    )
    assert graph.escalation_chains() == []


def test_the_break_to_make_is_the_escalating_assignment_when_it_is_first() -> None:
    chain = escalating_environment().escalation_chains()[0]
    step = chain.cheapest_break()

    assert step is not None
    # The earliest capability hop: detaching the identity from the host closes
    # the way in, which beats arguing about the role afterwards.
    assert step.relationship is RelationshipType.HAS_IDENTITY


def test_a_scope_reports_what_it_holds() -> None:
    """What an escalation over it would be an escalation to. Scopes themselves
    are excluded, the same way a folder is not a file."""
    held = {r.provider_resource_id for r in environment().contained_by(SUB)}

    assert held == {VM, STORAGE, QUIET_VM}
