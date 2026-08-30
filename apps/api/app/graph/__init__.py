"""The asset graph.

Rules are deliberately local: each one looks at a resource, decides, and says
so. That is what makes them testable and explainable, and it is also what they
cannot do. A rule can tell you a virtual machine is reachable from the
internet. Another can tell you an identity holds Contributor over a
subscription. Neither can tell you they are the same machine, and that sentence
is the whole product:

    an internet-facing host runs as an identity that can act across the
    subscription your customer data sits in

Nothing in a per-resource verdict composes into that. It is a property of how
the environment is wired, so it needs the wiring as a first-class thing.

**In memory, from PostgreSQL.** The edges live in ``resource_relationships``
and are read back per scan; traversal happens here, over dictionaries. An SME
tenant is 10^3 to 10^5 nodes, which is a dict -- and a graph database would buy
interactive multi-hop queries over millions of nodes across tenants, bought
with a second stateful system that has no row-level security and needs its own
tenancy story. The trade is revisited when a customer's graph stops fitting in
a worker, not before (ARCHITECTURE_REVIEW.md section 8).

**No synthetic nodes.** There is no ``INTERNET`` node and no ``SENSITIVE_DATA``
node. Both are tempting -- the drawings in every CSPM deck have them -- and
both would be CloudGuard inventing vertices it cannot point at anything real
for. Exposure and sensitivity are already *attributes* the normalizer computes
per asset, so an entry point is a predicate over nodes rather than an edge from
a fiction.
"""

from app.graph.model import AssetGraph, Path, PathStep

__all__ = ["AssetGraph", "Path", "PathStep"]
