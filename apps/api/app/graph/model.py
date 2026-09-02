"""The graph, and the two questions worth asking of it.

Built per scan from the same normalized state the rule engine sees, so a path
and a finding are always statements about one reading of one environment. A
graph assembled from a different scan's edges would let CloudGuard describe a
route through an environment nobody looked at in one go.
"""

from collections import deque
from dataclasses import dataclass, field

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource

# Exposure at or above which a node is somewhere an attacker could start.
#
# A predicate over an attribute the normalizer already computes, rather than an
# edge from a synthetic INTERNET node. UNKNOWN is deliberately *not* an entry
# point: it means CloudGuard could not work the exposure out, and treating that
# as "reachable from the internet" would manufacture attack paths out of gaps in
# collection -- the same overclaim as a PASS nobody earned, pointed the other
# way.
ENTRY_EXPOSURE = {Level.HIGH, Level.CRITICAL}

# Sensitivity at or above which reaching a node actually costs the customer
# something. UNKNOWN is excluded for the mirror-image reason.
SENSITIVE_DATA = {Level.HIGH, Level.CRITICAL}

# How far a path may run before it stops being a description of anything.
# Every real Azure path this graph can express is three or four hops -- host,
# identity, scope, resource -- and a longer one is a containment chain being
# walked for its own sake.
MAX_DEPTH = 6


@dataclass(frozen=True)
class PathStep:
    """One hop, and why it exists."""

    source: CloudResource
    relationship: RelationshipType
    target: CloudResource

    def describe(self) -> str:
        verb = {
            RelationshipType.HAS_IDENTITY: "runs as",
            RelationshipType.GRANTS_ROLE: "can act over",
            RelationshipType.CAN_GRANT_ROLES: "can grant itself any role over",
            RelationshipType.CONTAINS: "contains",
        }.get(self.relationship, self.relationship.value)
        return f"{self.source.name} {verb} {self.target.name}"


@dataclass(frozen=True)
class Path:
    """A route from somewhere an attacker could start to something worth taking.

    Carries the whole route rather than its endpoints. "This storage account is
    reachable" is an alarm; "it is reachable *because* this internet-facing VM
    runs as an identity holding Contributor over the subscription" is a thing
    somebody can go and fix, and it names three places they could cut it.
    """

    entry: CloudResource
    target: CloudResource
    steps: tuple[PathStep, ...]

    @property
    def hops(self) -> int:
        return len(self.steps)

    def describe(self) -> list[str]:
        return [step.describe() for step in self.steps]

    def node_ids(self) -> frozenset[str]:
        """Every asset on the route, endpoints included."""
        ids = {self.entry.provider_resource_id, self.target.provider_resource_id}
        for step in self.steps:
            ids.add(step.source.provider_resource_id)
            ids.add(step.target.provider_resource_id)
        return frozenset(ids)

    def cheapest_break(self) -> PathStep | None:
        """The hop to cut first.

        The capability hops, in preference to the structural ones: removing a
        role assignment or detaching an identity severs the route, while
        "contains" describes where a resource lives and cannot be removed at
        all. Among those, the earliest -- closing the way in beats containing
        what someone reaches once inside.
        """
        for step in self.steps:
            if step.relationship in {
                RelationshipType.HAS_IDENTITY,
                RelationshipType.GRANTS_ROLE,
                RelationshipType.CAN_GRANT_ROLES,
            }:
                return step
        return None


@dataclass(frozen=True)
class ChokePoint:
    """One removable link, and the routes that stop existing without it.

    The question the attack-path list cannot answer however carefully it is
    sorted. Fifty routes are fifty things to read; "remove this one role
    assignment and thirty-seven of them close" is one thing to do, and it is
    frequently not the fix any single route would have suggested on its own --
    the shared hop is usually in the middle, while each route's own cheapest
    break is at its start.
    """

    step: PathStep
    #: Routes that no longer exist once this link is gone. The real answer.
    severed: tuple[Path, ...]
    #: Routes this link sits on, which is larger whenever another way round
    #: exists. Kept because the gap between the two is the interesting part:
    #: a link on twenty routes that closes three is a link with alternates.
    on_routes: int

    @property
    def severs(self) -> int:
        return len(self.severed)

    def describe(self) -> str:
        return self.step.describe()


@dataclass
class AssetGraph:
    """Assets and the edges between them, for one scan.

    Directed. ``CONTAINS`` runs from the container downward and
    ``GRANTS_ROLE`` from the principal to the scope, so following edges forward
    is following reach -- which is what makes a traversal from an entry point
    mean what it looks like it means.
    """

    nodes: dict[str, CloudResource] = field(default_factory=dict)
    _out: dict[str, list[tuple[RelationshipType, str]]] = field(
        default_factory=dict, repr=False
    )

    @classmethod
    def build(
        cls,
        resources: list[CloudResource],
        relationships: list[tuple[str, RelationshipType, str]],
    ) -> "AssetGraph":
        graph = cls(nodes={r.provider_resource_id: r for r in resources})
        for source, relationship, target in relationships:
            # Both ends have to be nodes. A dangling edge is not a shorter path,
            # it is a path through something CloudGuard never saw -- and a
            # traversal that followed one would describe reach it cannot
            # support.
            if source in graph.nodes and target in graph.nodes:
                graph._out.setdefault(source, []).append((relationship, target))
        return graph

    # ---------------------------------------------------------------- queries
    def entry_points(self) -> list[CloudResource]:
        """Assets an attacker could plausibly start from."""
        return [
            node for node in self.nodes.values() if node.public_exposure in ENTRY_EXPOSURE
        ]

    def sensitive_targets(self) -> list[CloudResource]:
        """Assets where reaching them costs the customer something."""
        return [
            node for node in self.nodes.values() if node.data_sensitivity in SENSITIVE_DATA
        ]

    def reachable_from(self, start: str, max_depth: int = MAX_DEPTH) -> dict[str, Path]:
        """Everything reachable from one node, with the route to each.

        Breadth-first, so the route recorded for a node is the shortest one --
        which is also the most useful, because a shorter path is a smaller thing
        to explain and usually a cheaper thing to break.

        Only capability edges are followed. An NSG protecting a VM is a fact
        about the VM's configuration, not a way to get anywhere from the NSG,
        and walking it would produce routes that read as attack paths while
        describing nothing an attacker could do.
        """
        if start not in self.nodes:
            return {}

        found: dict[str, Path] = {}
        queue: deque[tuple[str, tuple[PathStep, ...]]] = deque([(start, ())])
        seen = {start}

        while queue:
            current, steps = queue.popleft()
            if len(steps) >= max_depth:
                continue

            for relationship, target in self._out.get(current, []):
                if not relationship.is_capability or target in seen:
                    continue
                seen.add(target)
                route = (
                    *steps,
                    PathStep(self.nodes[current], relationship, self.nodes[target]),
                )
                found[target] = Path(
                    entry=self.nodes[start], target=self.nodes[target], steps=route
                )
                queue.append((target, route))

        return found

    def attack_paths(self, max_depth: int = MAX_DEPTH) -> list[Path]:
        """Routes from somewhere an attacker could start to something worth taking.

        The question no rule can answer, and the reason the graph exists. Sorted
        shortest-first: a two-hop path is both more likely and easier to
        explain than a five-hop one, and a list that buried it under longer
        routes would be a worse answer to the same question.
        """
        targets = {t.provider_resource_id for t in self.sensitive_targets()}
        if not targets:
            return []

        paths: list[Path] = []
        for entry in self.entry_points():
            reachable = self.reachable_from(entry.provider_resource_id, max_depth)
            for target_id, path in reachable.items():
                if target_id in targets and target_id != entry.provider_resource_id:
                    paths.append(path)

        return sorted(paths, key=lambda p: (p.hops, p.target.name))

    def paths_through(
        self, resource_id: str, max_depth: int = MAX_DEPTH
    ) -> list[Path]:
        """The attack paths this asset is part of, wherever on them it sits.

        Wherever on them, deliberately. A storage account at the end of a route
        and the jump box at the start of it are on the same route, and a person
        looking at one finding on either asset is looking at the same problem --
        so membership is asked of the whole route rather than of its endpoints.
        """
        return [
            path
            for path in self.attack_paths(max_depth)
            if resource_id in path.node_ids()
        ]

    def escalation_chains(self, max_depth: int = MAX_DEPTH) -> list[Path]:
        """Routes from somewhere an attacker could start to an identity that can
        grant itself more.

        A different question from :meth:`attack_paths`, not a variation on it.
        That one asks what an attacker reaches; this asks what they could be
        *given* once they arrive -- and the answer changes the shape of the
        problem, because a principal that may write role assignments over a
        scope has an effective permission of "whatever exists", regardless of
        the role it currently holds. Fixing the reachable asset does not shrink
        that; only the assignment does.

        The route ends at the scope rather than at the identity, because the
        scope is the size of the answer. "This VM runs as an identity that can
        grant itself Owner" is alarming; naming the subscription it can do that
        over is what makes it actionable.

        Requires an entry point, deliberately. A directory administrator who can
        hand out roles is over-privileged and is not a *chain* -- there is no
        route from outside to them here, and reporting one would be inventing
        the half of the story that makes it urgent.
        """
        chains: list[Path] = []
        for entry in self.entry_points():
            reachable = self.reachable_from(entry.provider_resource_id, max_depth)
            for node_id, path in reachable.items():
                for relationship, scope_id in self._out.get(node_id, []):
                    if relationship is not RelationshipType.CAN_GRANT_ROLES:
                        continue
                    if scope_id not in self.nodes:
                        continue
                    hop = PathStep(
                        self.nodes[node_id],
                        RelationshipType.CAN_GRANT_ROLES,
                        self.nodes[scope_id],
                    )
                    chains.append(
                        Path(
                            entry=entry,
                            target=self.nodes[scope_id],
                            steps=(*path.steps, hop),
                        )
                    )

        # Shortest first, and by scope name for stability. A two-hop chain -- an
        # exposed host whose own identity can grant roles -- is both likelier and
        # cheaper to explain than one that arrives through three intermediaries.
        return sorted(chains, key=lambda p: (p.hops, p.target.name))

    def choke_points(
        self, *, limit: int = 5, max_depth: int = MAX_DEPTH
    ) -> list["ChokePoint"]:
        """The links worth cutting first, ranked by how much closes with them.

        Two passes, because the cheap answer is the wrong one. Counting how many
        routes a link sits on takes one walk and *overstates*: a link on twenty
        routes closes only the ones with no way round, and reporting the
        containment as though it were the severance would promise a customer a
        result they will not get. So the leading candidates are then checked by
        removing the link and re-asking the whole question -- the only way to
        know that a route is gone rather than merely re-routed.

        Verified for the top few rather than for every candidate, because each
        check is a full re-traversal. The ordering that selects them is
        containment, which is an upper bound on severance, so a link that could
        sever more than a checked one is always itself checked first.

        Structural links are not candidates. A storage account has to live
        somewhere, so ``CONTAINS`` cannot be removed and offering it would be a
        recommendation nobody can take -- the same reason
        :meth:`Path.cheapest_break` skips it.

        Attack paths only. Escalation chains answer a different question, and a
        single count covering both would make "routes" mean two things in one
        sentence.
        """
        paths = self.attack_paths(max_depth)
        if not paths:
            return []

        # Every removable hop, and the routes it sits on. Every hop rather than
        # each route's own cheapest break: the link several routes share is
        # usually in the middle, and looking only at the breaks would rank the
        # entry points -- which are the answer for one route each.
        containment: dict[tuple[str, str, str], list[Path]] = {}
        steps: dict[tuple[str, str, str], PathStep] = {}
        for path in paths:
            for step in path.steps:
                if step.relationship is RelationshipType.CONTAINS:
                    continue
                key = (
                    step.source.provider_resource_id,
                    step.relationship.value,
                    step.target.provider_resource_id,
                )
                containment.setdefault(key, []).append(path)
                steps.setdefault(key, step)

        reachable_now = {
            (p.entry.provider_resource_id, p.target.provider_resource_id) for p in paths
        }
        ranked = sorted(
            containment.items(),
            key=lambda item: (-len(item[1]), steps[item[0]].describe()),
        )

        found: list[ChokePoint] = []
        for key, on in ranked[:limit]:
            still = {
                (p.entry.provider_resource_id, p.target.provider_resource_id)
                for p in self._without(key).attack_paths(max_depth)
            }
            gone = reachable_now - still
            if not gone:
                # Every route through it has another way round. Cutting it
                # changes nothing a customer would see, so it is not offered.
                continue
            found.append(
                ChokePoint(
                    step=steps[key],
                    severed=tuple(
                        p
                        for p in paths
                        if (p.entry.provider_resource_id, p.target.provider_resource_id)
                        in gone
                    ),
                    on_routes=len(on),
                )
            )

        return sorted(found, key=lambda c: (-c.severs, c.describe()))

    def _without(self, edge: tuple[str, str, str]) -> "AssetGraph":
        """This graph with one link removed, for asking what it was holding up.

        A shallow copy: the nodes are shared, because nothing here mutates them
        and copying an estate's worth of resources per candidate would make the
        analysis cost more than the answer is worth.
        """
        source, relationship, target = edge
        pruned = AssetGraph(nodes=self.nodes)
        for node, outgoing in self._out.items():
            kept = [
                (rel, other)
                for rel, other in outgoing
                if not (node == source and rel.value == relationship and other == target)
            ]
            if kept:
                pruned._out[node] = kept
        return pruned

    def contained_by(self, scope_id: str, max_depth: int = MAX_DEPTH) -> list[CloudResource]:
        """Everything that sits under a scope.

        What an escalation at that scope would be an escalation *over*.

        Containment only, unlike :meth:`blast_radius`, and the difference is the
        point rather than an optimization. Reach spreads through identities --
        a host under this subscription runs as a principal, and that principal
        is reachable from here -- but a managed identity is not something the
        subscription *holds*. Counting it would answer "what could be taken from
        here" while being asked "what is in here", and the two diverge exactly
        where the answer matters.
        """
        structural = {ResourceType.SUBSCRIPTION, ResourceType.RESOURCE_GROUP}
        held: list[CloudResource] = []
        queue: deque[tuple[str, int]] = deque([(scope_id, 0)])
        seen = {scope_id}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for relationship, target in self._out.get(current, []):
                if relationship is not RelationshipType.CONTAINS or target in seen:
                    continue
                seen.add(target)
                node = self.nodes[target]
                if node.resource_type not in structural:
                    held.append(node)
                queue.append((target, depth + 1))
        return held

    def blast_radius(self, principal_id: str, max_depth: int = MAX_DEPTH) -> list[CloudResource]:
        """What one identity can act on.

        Answers the question a customer asks about an over-privileged
        principal, which is never "is this role too broad" in the abstract but
        "what would go if this were taken". Scopes are excluded from the answer
        for the same reason a folder is not a file: a subscription is where the
        reach lands, and the resources beneath it are what the reach is *of*.
        """
        structural = {ResourceType.SUBSCRIPTION, ResourceType.RESOURCE_GROUP}
        return [
            path.target
            for path in self.reachable_from(principal_id, max_depth).values()
            if path.target.resource_type not in structural
        ]
