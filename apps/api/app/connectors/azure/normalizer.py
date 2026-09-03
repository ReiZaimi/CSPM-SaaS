"""Normalization: raw Azure JSON -> cloud-neutral ``CloudResource`` objects.

This module is the only place in CloudGuard that knows what an ARM payload looks
like. Everything downstream — rules, findings, risk, UI — sees the neutral
shape. A pure function with no I/O, so it is directly testable against recorded
Azure responses.

Asset context — criticality, data sensitivity, environment — is no longer
inferred here. It moved to :mod:`app.context`, because none of it was ever
Azure-specific: tag vocabularies and the rule that a database holds data by
definition are the same facts under any provider, and a second connector would
have written its own slightly different copy. What stays here is exposure,
which is read off the configuration in the capture rather than inferred from
labels — a public IP is attached or it is not.
"""

import re
from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import Any

from app.connectors.base import NormalizedState, RawSnapshot
from app.context import AssetContext, infer
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource


def _context(item: dict[str, Any], resource_type: ResourceType) -> AssetContext:
    """What the capture says this asset is worth, and on whose authority.

    One call per resource rather than three, and the source travels with each
    value: a CRITICAL read off a tag and a CRITICAL guessed from a resource name
    multiply a finding identically, and only one of them is worth arguing with.
    """
    return infer(
        tags=item.get("tags"),
        name=str(item.get("name", "")),
        resource_type=resource_type,
    )


def _graph_time(raw: Any) -> datetime | None:
    """One of Graph's timestamps, or None if it is not one.

    Tolerant of the fractional second because Graph is not consistent about it:
    the same field comes back as ``...T12:00:00Z`` from one endpoint and
    ``...T12:00:00.1234567Z`` from another, and ``fromisoformat`` accepts at
    most six digits. A credential whose expiry could not be parsed is treated as
    an expiry CloudGuard does not know rather than as one that has not passed.
    """
    if not raw:
        return None
    # The fraction is the part that actually breaks: Graph writes up to seven
    # digits and fromisoformat parses at most six. The trailing Z is spelled
    # out alongside it because the two are one normalization, not because
    # anything here refuses a Z.
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6], str(raw).strip())
    text = text.replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _days_between(earlier: datetime, later: datetime) -> int:
    """Whole days from ``earlier`` to ``later``, truncated downwards.

    Truncation is the safe direction for both readers: a credential that
    expired six hours ago reports -1 day remaining rather than 0, and an
    account last seen 89.9 days ago reports 89 rather than 90 -- so a threshold
    is crossed when it has genuinely been crossed.
    """
    return (later - earlier).days


def _resource_group_of(resource_id: str) -> str | None:
    """The resource group an ARM id names, if it names one.

    Parsed rather than collected: an ARM id spells out its own subscription and
    resource group, and asking Azure for something the id already states would
    be a round trip to confirm a substring.

    Case-insensitive on the segment name because ARM is: ``/resourcegroups/``
    and ``/resourceGroups/`` are the same path, and a customer whose ids arrive
    in the other casing would otherwise get a graph with no containment in it
    at all.
    """
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _principal_node(principal_id: str, known: set[str]) -> str:
    """The node id for a principal, preferring one the directory already named.

    An administrator who also holds a subscription role is one person. Minting
    a second node for the same GUID would split their reach across two nodes
    and hide exactly the case worth seeing: a privileged directory account that
    is *also* privileged over the infrastructure.
    """
    directory_node = f"/users/{principal_id}"
    if directory_node in known:
        return directory_node
    return f"/principals/{principal_id}"


def _role_summary(definition: dict[str, Any] | None) -> str:
    """A role's name, or the honest absence of one.

    An assignment names a definition by GUID. Without the definition, "this
    principal holds 8e3af657-a8ff-443c-a75c-2fe8c4bcb635 over your subscription"
    is true and useless, so an unresolved role says so rather than showing the
    GUID as though it were a name.
    """
    if not definition:
        return "Unknown role"
    return str(_first(definition, "properties", "roleName", default="Unknown role"))


# The action that turns access into more access. A principal that may write role
# assignments over a scope can give itself anything at that scope, so its
# effective permission is not the role it holds but the highest role that
# exists.
ROLE_ASSIGNMENT_WRITE = "Microsoft.Authorization/roleAssignments/write"


def _action_matches(pattern: str, action: str) -> bool:
    """Whether an ARM action pattern covers a specific action.

    ARM patterns are segment-wise globs -- ``*``, ``Microsoft.Authorization/*``,
    ``Microsoft.Authorization/*/Write`` -- and matching them by equality would
    miss every built-in role, since the interesting ones are written with
    wildcards. Case-insensitive because ARM is: ``/Write`` and ``/write`` are the
    same action, and Azure's own definitions use both.
    """
    return fnmatch(action.lower(), pattern.lower())


def _grants_role_assignment(definition: dict[str, Any] | None) -> bool:
    """Whether this role definition lets its holder hand out roles.

    The distinction that makes this worth computing rather than pattern-matching
    on role names: **Owner and Contributor both carry ``actions: ["*"]``**, and
    only Contributor excludes ``Microsoft.Authorization/*/Write`` in its
    ``notActions``. Reading the name would call every Contributor an escalation
    path, on nearly every subscription in existence, which is the kind of false
    alarm that gets a whole feature switched off.

    Custom roles are the reason this is read from the definition at all. A
    tenant's own role granting exactly this one action is invisible to any list
    of well-known role names, and is precisely the thing worth finding.
    """
    if not definition:
        return False
    for permission in _first(definition, "properties", "permissions", default=[]) or []:
        actions = permission.get("actions") or []
        not_actions = permission.get("notActions") or []
        if not any(_action_matches(p, ROLE_ASSIGNMENT_WRITE) for p in actions):
            continue
        if any(_action_matches(p, ROLE_ASSIGNMENT_WRITE) for p in not_actions):
            continue
        return True
    return False


def _first(value: Any, *path: str, default: Any = None) -> Any:
    node = value
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


class AzureNormalizer:
    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        # Keyed by evidence key, not category: that is what rules declare.
        state = NormalizedState(collection_errors=dict(snapshot.gaps))
        data = snapshot.data

        diagnostics = data.get("diagnostic_settings", {}) or {}
        assessments = self._assessments_by_resource(data)

        # Index NIC -> public IP and NIC -> NSG before walking VMs, so a VM's
        # exposure can be resolved by following its interfaces.
        nics = {n["id"]: n for n in data.get("network_interfaces", []) if n.get("id")}
        public_ips = {p["id"]: p for p in data.get("public_ip_addresses", []) if p.get("id")}

        state.resources.extend(self._normalize_nsgs(data, diagnostics))
        state.resources.extend(self._normalize_storage(data, diagnostics))
        state.resources.extend(self._normalize_databases(data, diagnostics))
        state.resources.extend(self._normalize_key_vaults(data, diagnostics))

        vms, vm_edges = self._normalize_vms(data, nics, public_ips)
        state.resources.extend(vms)
        state.relationships.extend(vm_edges)

        state.resources.extend(self._normalize_users(data, snapshot.collected_at))
        state.resources.extend(
            self._normalize_applications(data, snapshot.collected_at)
        )

        # Everything else the subscription holds. Added after the service
        # listings and filtered against them, because the inventory covers the
        # same storage accounts and virtual machines those listings already
        # produced in far more detail -- and two rows for one asset would be an
        # inventory that miscounts and a graph with the same thing in it twice.
        state.resources.extend(self._normalize_inventory(data, state.resources))

        # --- the graph ------------------------------------------------------
        # Everything above describes assets one at a time. What follows says how
        # they relate, which is a different kind of fact and the only kind that
        # composes into a path: a rule can tell you a VM is internet-facing and
        # that an identity is over-privileged, and no rule can tell you they are
        # the same VM.
        scopes, scope_edges = self._normalize_scopes(
            snapshot, state.resources, diagnostics
        )
        state.resources.extend(scopes)
        state.relationships.extend(scope_edges)

        principals, identity_edges = self._normalize_authorization(
            data, state.resources
        )
        state.resources.extend(principals)
        state.relationships.extend(identity_edges)

        # Defences, which are not assets and are not findings. Kept out of
        # ``resources`` deliberately: a Conditional Access policy is not a thing
        # anybody secures, has no exposure and no data sensitivity, and putting
        # it in the asset list would inflate every inventory count with rows a
        # customer never asked to own (``rules/controls.py``).
        state.controls = self._normalize_controls(data)

        # Defender's findings, attached last so every asset exists to attach
        # them to. Written onto the resources rather than kept beside them,
        # because what makes them worth reading is the asset they are about --
        # a critical vulnerability is one sentence on a development box and a
        # different one on an internet-facing machine holding an identity that
        # can act across the subscription, and only the asset knows which.
        self._attach_assessments(state.resources, assessments)
        return state

    # --------------------------------------------------------------- posture
    def _assessments_by_resource(
        self, data: dict[str, Any]
    ) -> dict[str, list[dict[str, Any]]]:
        """Defender's unhealthy findings, indexed by the resource they are about.

        Only the unhealthy ones are kept. A healthy assessment says Defender
        looked and was satisfied, which is Defender's verdict rather than
        CloudGuard's evidence -- and carrying several hundred of them per
        subscription into every snapshot would store a great deal to say
        nothing. What a rule needs is what is wrong and how bad Microsoft
        thinks it is.

        ``NotApplicable`` is dropped for the same reason and a stronger one: it
        frequently means the assessment could not run, and reading it as a pass
        would be exactly the overclaim this engine refuses everywhere else.
        """
        by_resource: dict[str, list[dict[str, Any]]] = {}

        for assessment in data.get("security_assessments", []) or []:
            props = assessment.get("properties", {}) or {}
            status = (props.get("status", {}) or {}).get("code")
            if str(status).lower() != "unhealthy":
                continue

            target = _first(props, "resourceDetails", "Id") or _first(
                props, "resourceDetails", "id"
            )
            if not target:
                continue

            metadata = props.get("metadata", {}) or {}
            by_resource.setdefault(str(target).lower(), []).append(
                {
                    # The stable identifier. ``displayName`` is what a person
                    # reads and what Microsoft rewords; the name is the GUID a
                    # rule can match on years later.
                    "assessment_id": assessment.get("name"),
                    "title": props.get("displayName") or metadata.get("displayName"),
                    # Microsoft's severity, kept under their name rather than
                    # mapped onto CloudGuard's. The two scales were tuned by
                    # different people for different purposes, and silently
                    # equating them would put somebody else's judgement inside
                    # this product's risk formula.
                    "provider_severity": metadata.get("severity"),
                    "categories": metadata.get("categories") or [],
                    "cause": (props.get("status", {}) or {}).get("cause"),
                    "description": (props.get("status", {}) or {}).get("description"),
                }
            )
        return by_resource

    def _attach_assessments(
        self,
        resources: list[CloudResource],
        assessments: dict[str, list[dict[str, Any]]],
    ) -> None:
        """Put each asset's findings on the asset.

        Matched case-insensitively because ARM ids are: Defender reports a
        resource group as ``resourceGroups`` and the resource listing may
        return ``resourcegroups``, and a case-sensitive join would silently
        attach nothing at all -- which reads as an estate with no findings.

        Absent entirely rather than an empty list where nothing matched, so a
        rule can tell "Defender assessed this and found nothing unhealthy" from
        "no assessment reached this asset". Only the second is UNKNOWN.
        """
        answered = bool(assessments)
        for resource in resources:
            key = resource.provider_resource_id.lower()
            if key in assessments:
                resource.metadata["security_assessments"] = assessments[key]
            elif answered:
                # Defender answered for this subscription and said nothing
                # about this asset. That is a reading, and an empty one.
                resource.metadata["security_assessments"] = []

    # ------------------------------------------------------------- inventory
    def _normalize_inventory(
        self, data: dict[str, Any], modelled: list[CloudResource]
    ) -> list[CloudResource]:
        """The resources CloudGuard does not check, said out loud.

        For a long time this payload was collected on every scan, stored in
        every snapshot, and read by nothing -- while the asset list showed only
        the ten-odd types the connector models in detail. A customer with a
        subscription full of App Services and Cosmos accounts saw a tidy
        inventory of storage and virtual machines and no indication that most of
        what they own was missing from it. Silence read as coverage, which is
        the one inference this product exists to prevent.

        These carry ``ResourceType.UNKNOWN`` and that is the load-bearing part.
        No rule's ``applies_to`` names it, so none of them is ever judged, and
        none can quietly become a PASS: they are counted, listed, and reported
        as unchecked. The Azure type is kept in metadata, which is what turns
        "23 resources are unchecked" into "23, and here is what they are".

        Nothing is invented about them. Resource Graph's projection excludes
        ``properties`` deliberately, so there is no configuration here to judge
        even if a rule wanted to -- context comes from tags alone, the same way
        it does for a modelled asset.
        """
        known = {resource.provider_resource_id for resource in modelled}
        resources: list[CloudResource] = []

        for row in data.get("resources", []):
            resource_id = row.get("id")
            if not resource_id or resource_id in known:
                continue
            # Guards a duplicate inside the payload itself. Resource Graph pages
            # a stable ordered query, and a repeated row would otherwise become
            # a repeated asset.
            known.add(resource_id)

            azure_type = str(row.get("type") or "").strip()
            context = _context(row, ResourceType.UNKNOWN)

            resources.append(
                CloudResource(
                    provider_resource_id=resource_id,
                    resource_type=ResourceType.UNKNOWN,
                    name=row.get("name") or "unnamed",
                    provider=Provider.AZURE,
                    region=row.get("location"),
                    **context.fields(),
                    # Not UNKNOWN-as-caution and not LOW-as-reassurance. Exposure
                    # is something CloudGuard establishes by looking at a
                    # resource's configuration, and there is no configuration
                    # here -- so it stays the honest absence, which the risk
                    # engine already treats as "not established" rather than
                    # "safe".
                    public_exposure=Level.UNKNOWN,
                    metadata={
                        # The real type, which is the whole content of the
                        # finding this asset represents: CloudGuard has no rule
                        # for a Microsoft.Web/sites and the customer should know
                        # that rather than infer it from an absence.
                        "azure_type": azure_type,
                        "kind": row.get("kind"),
                        "sku": row.get("sku"),
                        "managed_by": row.get("managedBy"),
                        # True for every one of these by construction, and
                        # recorded rather than derived so a consumer does not
                        # have to know that UNKNOWN means unchecked.
                        "unchecked": True,
                        "tags": row.get("tags") or {},
                    },
                )
            )
        return resources

    # ------------------------------------------------------------ containment
    def _normalize_scopes(
        self,
        snapshot: RawSnapshot,
        resources: list[CloudResource],
        diagnostics: dict[str, Any],
    ) -> tuple[list[CloudResource], list[tuple[str, RelationshipType, str]]]:
        """The subscription and resource groups every asset sits inside.

        Derived from the resource ids rather than collected, because the id is
        authoritative about this and nothing else needs asking: an ARM id spells
        out its own subscription and resource group.

        These exist so a role assignment has somewhere to point. "Contributor
        over the subscription" is only a fact about blast radius if the
        subscription is a node with things underneath it -- otherwise it is a
        string in a payload.
        """
        subscription_id = snapshot.subscription_id
        if not subscription_id:
            return [], []

        subscription_node = f"/subscriptions/{subscription_id}"
        nodes = [
            CloudResource(
                provider_resource_id=subscription_node,
                resource_type=ResourceType.SUBSCRIPTION,
                name=subscription_id,
                provider=Provider.AZURE,
                # A subscription is exactly as exposed and as sensitive as
                # whatever it contains, and the graph is what works that out.
                # Claiming a level here would double-count it.
                metadata={
                    "subscription_id": subscription_id,
                    # Where the activity log goes, if anywhere. Carried on the
                    # subscription rather than derived per resource, because
                    # the activity log is one record of what was done across
                    # the whole subscription -- not a property of anything
                    # inside it.
                    "diagnostic_settings": self._diagnostics_for(
                        subscription_node, diagnostics
                    ),
                },
            )
        ]
        edges: list[tuple[str, RelationshipType, str]] = []
        groups: dict[str, str] = {}

        for resource in resources:
            group = _resource_group_of(resource.provider_resource_id)
            if group is None:
                # No resource group in the id. Either a directory asset -- a
                # user does not live in a resource group -- or something scoped
                # directly to the subscription, which is contained by it.
                if resource.provider_resource_id.startswith(f"{subscription_node}/"):
                    edges.append(
                        (
                            subscription_node,
                            RelationshipType.CONTAINS,
                            resource.provider_resource_id,
                        )
                    )
                continue

            group_node = f"{subscription_node}/resourceGroups/{group}"
            if group_node not in groups:
                groups[group_node] = group
                nodes.append(
                    CloudResource(
                        provider_resource_id=group_node,
                        resource_type=ResourceType.RESOURCE_GROUP,
                        name=group,
                        provider=Provider.AZURE,
                    )
                )
                edges.append(
                    (subscription_node, RelationshipType.CONTAINS, group_node)
                )
            edges.append(
                (group_node, RelationshipType.CONTAINS, resource.provider_resource_id)
            )

        return nodes, edges

    # ----------------------------------------------------------- authorization
    def _normalize_authorization(
        self, data: dict[str, Any], resources: list[CloudResource]
    ) -> tuple[list[CloudResource], list[tuple[str, RelationshipType, str]]]:
        """Which identities hold which roles, and which resources run as them.

        Two edges, and between them the hop that turns a foothold into a blast
        radius. ``HAS_IDENTITY`` says a workload runs as a principal;
        ``GRANTS_ROLE`` says that principal may act over a scope. Neither is
        interesting alone, and together they answer the question no rule can:
        if this internet-facing thing were taken, what else would go with it.

        Principals already in the directory keep their existing node -- an
        administrator with a subscription role is one person, not a user and a
        principal that happen to share a GUID.
        """
        assignments = data.get("role_assignments", []) or []
        definitions = {
            definition["id"]: definition
            for definition in (data.get("role_definitions", []) or [])
            if definition.get("id")
        }
        by_id = {r.provider_resource_id: r for r in resources}
        known = set(by_id)

        nodes: dict[str, CloudResource] = {}
        edges: list[tuple[str, RelationshipType, str]] = []

        for assignment in assignments:
            props = assignment.get("properties", {}) or {}
            principal_id = props.get("principalId")
            scope = props.get("scope")
            if not principal_id or not scope:
                continue

            definition = definitions.get(props.get("roleDefinitionId", ""))
            role = _role_summary(definition)
            escalates = _grants_role_assignment(definition)
            principal_node = _principal_node(principal_id, known)

            if principal_node not in known and principal_node not in nodes:
                nodes[principal_node] = CloudResource(
                    provider_resource_id=principal_node,
                    resource_type=ResourceType.SERVICE_PRINCIPAL,
                    name=props.get("principalType") or "Principal",
                    provider=Provider.AZURE,
                    metadata={
                        "principal_id": principal_id,
                        "principal_type": props.get("principalType"),
                    },
                )

            # Only where the scope is something we hold. An assignment above the
            # subscription -- at a management group CloudGuard cannot see -- is
            # real and is not a reach we can describe, and inventing an edge to
            # a node that does not exist would be describing it anyway.
            if scope in known or scope in nodes:
                edges.append((principal_node, RelationshipType.GRANTS_ROLE, scope))
                # Beside it, never instead of it. The reach is the same pair of
                # nodes; this says the reach has no ceiling, because the holder
                # can grant itself whatever it does not already have.
                if escalates:
                    edges.append(
                        (principal_node, RelationshipType.CAN_GRANT_ROLES, scope)
                    )

            # Recorded on whichever node holds this principal -- one minted
            # here, or the directory user the ``known`` lookup found.
            #
            # It used to be recorded only on the minted ones, on the grounds
            # that a traversal reads the edges anyway. That is true of a
            # traversal and false of a rule: an edge says a principal reaches a
            # scope and cannot say *as what*, so "this person holds Owner over
            # your subscription" was a fact CloudGuard collected, drew a line
            # for, and then could not state. The directory node is the one case
            # where it matters most, because a named human with Owner is worse
            # than an unnamed principal with it, not better.
            existing = nodes.get(principal_node) or by_id.get(principal_node)
            if existing is not None:
                roles = list(existing.metadata.get("roles", []))
                roles.append(
                    {"role": role, "scope": scope, "grants_role_assignment": escalates}
                )
                existing.metadata["roles"] = roles

        # Resources that run as an identity. The first hop of the path.
        for vm in data.get("virtual_machines", []):
            identity = vm.get("identity") or {}
            principal_id = identity.get("principalId")
            if not principal_id or not vm.get("id"):
                continue
            principal_node = _principal_node(principal_id, known)
            if principal_node not in known and principal_node not in nodes:
                nodes[principal_node] = CloudResource(
                    provider_resource_id=principal_node,
                    resource_type=ResourceType.SERVICE_PRINCIPAL,
                    name="Managed identity",
                    provider=Provider.AZURE,
                    metadata={
                        "principal_id": principal_id,
                        "principal_type": "ManagedIdentity",
                    },
                )
            edges.append((vm["id"], RelationshipType.HAS_IDENTITY, principal_node))

        return list(nodes.values()), edges

    # -------------------------------------------------------------------- NSG
    def _normalize_nsgs(
        self, data: dict[str, Any], diagnostics: dict[str, Any]
    ) -> list[CloudResource]:
        resources = []
        for nsg in data.get("network_security_groups", []):
            props = nsg.get("properties", {}) or {}
            rules = [
                self._normalize_security_rule(r)
                for r in (props.get("securityRules") or [])
            ]
            context = _context(nsg, ResourceType.NETWORK_SECURITY_GROUP)
            resources.append(
                CloudResource(
                    provider_resource_id=nsg["id"],
                    resource_type=ResourceType.NETWORK_SECURITY_GROUP,
                    name=nsg.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=nsg.get("location"),
                    **context.fields(),
                    public_exposure=self._nsg_exposure(rules),
                    metadata={
                        "security_rules": rules,
                        "default_security_rules": len(props.get("defaultSecurityRules") or []),
                        "diagnostic_settings": self._diagnostics_for(nsg["id"], diagnostics),
                        "attached_subnets": [
                            s.get("id") for s in (props.get("subnets") or [])
                        ],
                        "attached_interfaces": [
                            n.get("id") for n in (props.get("networkInterfaces") or [])
                        ],
                        "tags": nsg.get("tags") or {},
                    },
                )
            )
        return resources

    def _normalize_security_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        """Flatten an ARM security rule into the shape rules read.

        Azure expresses source and ports in singular *or* plural fields
        depending on how the rule was created; both are folded together here so
        no rule has to know that.
        """
        props = rule.get("properties", {}) or {}

        source = props.get("sourceAddressPrefix")
        if not source:
            prefixes = props.get("sourceAddressPrefixes") or []
            source = prefixes[0] if len(prefixes) == 1 else ",".join(prefixes)

        ports = props.get("destinationPortRanges") or []
        if not ports and props.get("destinationPortRange"):
            ports = [props["destinationPortRange"]]

        return {
            "name": rule.get("name"),
            "direction": props.get("direction"),
            "access": props.get("access"),
            "protocol": props.get("protocol"),
            "source": source,
            "source_prefixes": props.get("sourceAddressPrefixes") or [],
            "destination_ports": [str(p) for p in ports],
            "priority": props.get("priority"),
            "description": props.get("description"),
        }

    def _nsg_exposure(self, rules: list[dict[str, Any]]) -> Level:
        """How exposed is whatever this NSG guards?

        Feeds the risk score directly, which is why an open administrative port
        outranks an open web port.
        """
        from app.rules.azure.network.exposure import _is_public, _port_matches

        inbound_allow = [
            r
            for r in rules
            if str(r.get("direction", "")).lower() == "inbound"
            and str(r.get("access", "")).lower() == "allow"
        ]
        public = [r for r in inbound_allow if _is_public(r.get("source"))]
        if not public:
            return Level.LOW

        for rule in public:
            ports = rule.get("destination_ports", [])
            if any(str(p).strip() == "*" for p in ports):
                return Level.CRITICAL
            if any(_port_matches(p, 3389) or _port_matches(p, 22) for p in ports):
                return Level.CRITICAL
        return Level.HIGH

    # ---------------------------------------------------------------- storage
    def _normalize_storage(
        self, data: dict[str, Any], diagnostics: dict[str, Any]
    ) -> list[CloudResource]:
        resources = []
        for account in data.get("storage_accounts", []):
            props = account.get("properties", {}) or {}
            network_acls = props.get("networkAcls", {}) or {}
            context = _context(account, ResourceType.STORAGE_ACCOUNT)

            allow_public = props.get("allowBlobPublicAccess")
            default_action = network_acls.get("defaultAction")

            resources.append(
                CloudResource(
                    provider_resource_id=account["id"],
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    name=account.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=account.get("location"),
                    **context.fields(),
                    public_exposure=(
                        Level.CRITICAL
                        if allow_public is True
                        else Level.HIGH
                        if str(default_action).lower() == "allow"
                        else Level.LOW
                        if allow_public is False
                        else Level.UNKNOWN
                    ),
                    metadata={
                        "allow_blob_public_access": allow_public,
                        "network_default_action": default_action,
                        "public_network_access": props.get("publicNetworkAccess"),
                        "https_traffic_only": props.get("supportsHttpsTrafficOnly"),
                        "min_tls_version": props.get("minimumTlsVersion"),
                        "allow_shared_key_access": props.get("allowSharedKeyAccess"),
                        "infrastructure_encryption": _first(
                            props, "encryption", "requireInfrastructureEncryption"
                        ),
                        "ip_rules": network_acls.get("ipRules") or [],
                        "virtual_network_rules": network_acls.get("virtualNetworkRules") or [],
                        "public_containers": [],
                        "diagnostic_settings": self._diagnostics_for(account["id"], diagnostics),
                        "tags": account.get("tags") or {},
                    },
                )
            )
        return resources

    # ---------------------------------------------------------------- secrets
    def _normalize_key_vaults(
        self, data: dict[str, Any], diagnostics: dict[str, Any]
    ) -> list[CloudResource]:
        """Vault configuration. Never vault contents."""
        resources = []
        for vault in data.get("key_vaults", []):
            props = vault.get("properties", {}) or {}
            network_acls = props.get("networkAcls", {}) or {}
            context = _context(vault, ResourceType.KEY_VAULT)

            public_access = props.get("publicNetworkAccess")
            default_action = network_acls.get("defaultAction")

            resources.append(
                CloudResource(
                    provider_resource_id=vault["id"],
                    resource_type=ResourceType.KEY_VAULT,
                    name=vault.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=vault.get("location"),
                    # Sensitivity comes from the context engine's type floor
                    # rather than from anything set here: a vault holds the
                    # credentials to everything else, tagged or not.
                    **context.fields(),
                    public_exposure=(
                        Level.HIGH
                        if str(public_access).lower() == "enabled"
                        and str(default_action).lower() != "deny"
                        else Level.LOW
                        if str(public_access).lower() == "disabled"
                        or str(default_action).lower() == "deny"
                        else Level.UNKNOWN
                    ),
                    metadata={
                        "purge_protection": props.get("enablePurgeProtection"),
                        "soft_delete": props.get("enableSoftDelete"),
                        "soft_delete_retention_days": props.get(
                            "softDeleteRetentionInDays"
                        ),
                        "public_network_access": public_access,
                        "network_default_action": default_action,
                        "ip_rules": network_acls.get("ipRules") or [],
                        "virtual_network_rules": network_acls.get("virtualNetworkRules")
                        or [],
                        "rbac_authorization": props.get("enableRbacAuthorization"),
                        "access_policy_count": len(props.get("accessPolicies") or []),
                        "diagnostic_settings": self._diagnostics_for(
                            vault["id"], diagnostics
                        ),
                        "tags": vault.get("tags") or {},
                    },
                )
            )
        return resources

    # --------------------------------------------------------------- database
    def _normalize_databases(
        self, data: dict[str, Any], diagnostics: dict[str, Any]
    ) -> list[CloudResource]:
        resources = []
        auditing = data.get("sql_auditing", {}) or {}

        for server in data.get("sql_servers", []):
            props = server.get("properties", {}) or {}
            context = _context(server, ResourceType.SQL_SERVER)
            firewall_rules = self._firewall_rules(server)

            resources.append(
                CloudResource(
                    provider_resource_id=server["id"],
                    resource_type=ResourceType.SQL_SERVER,
                    name=server.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=server.get("location"),
                    **context.fields(),
                    public_exposure=self._database_exposure(props, firewall_rules),
                    metadata={
                        "public_network_access": props.get("publicNetworkAccess"),
                        "firewall_rules": firewall_rules,
                        "private_endpoints": [
                            _first(pe, "properties", "privateEndpoint", "id")
                            for pe in (props.get("privateEndpointConnections") or [])
                        ],
                        "version": props.get("version"),
                        "administrator_login": props.get("administratorLogin"),
                        "minimal_tls_version": props.get("minimalTlsVersion"),
                        "auditing": self._auditing(server["id"], auditing),
                        "diagnostic_settings": self._diagnostics_for(server["id"], diagnostics),
                        "tags": server.get("tags") or {},
                    },
                )
            )

        for server in data.get("postgresql_servers", []):
            props = server.get("properties", {}) or {}
            context = _context(server, ResourceType.POSTGRESQL_SERVER)
            network = props.get("network", {}) or {}
            public_access = network.get("publicNetworkAccess") or props.get(
                "publicNetworkAccess"
            )

            resources.append(
                CloudResource(
                    provider_resource_id=server["id"],
                    resource_type=ResourceType.POSTGRESQL_SERVER,
                    name=server.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=server.get("location"),
                    **context.fields(),
                    public_exposure=(
                        Level.HIGH
                        if str(public_access).lower() == "enabled"
                        else Level.LOW
                        if public_access
                        else Level.UNKNOWN
                    ),
                    metadata={
                        "public_network_access": public_access,
                        "firewall_rules": [],
                        "private_endpoints": (
                            [network.get("delegatedSubnetResourceId")]
                            if network.get("delegatedSubnetResourceId")
                            else []
                        ),
                        "version": props.get("version"),
                        "diagnostic_settings": self._diagnostics_for(server["id"], diagnostics),
                        "tags": server.get("tags") or {},
                    },
                )
            )

        return resources

    def _firewall_rules(self, server: dict[str, Any]) -> list[dict[str, Any]] | None:
        """None (not []) when the call failed -- the difference between "no
        rules" and "we could not read the rules"."""
        if "_firewall_rules_error" in server:
            return None
        raw = server.get("_firewall_rules")
        if raw is None:
            return None
        return [
            {
                "name": r.get("name"),
                "start_ip_address": _first(r, "properties", "startIpAddress"),
                "end_ip_address": _first(r, "properties", "endIpAddress"),
            }
            for r in raw
        ]

    def _auditing(
        self, server_id: str, auditing: dict[str, Any]
    ) -> dict[str, Any] | None:
        """What this server records about who queried it.

        Read from its own task's output rather than off the server, because it
        is its own evidence key: a rule that judges the audit trail depends on
        this and a rule that judges reachability does not.

        None (not a dict of falsey values) when the call failed or was never
        made, which is the same distinction ``_firewall_rules`` draws: a server
        whose auditing setting could not be read is not a server without
        auditing, and only one of those is a finding.
        """
        raw = auditing.get(server_id)
        if not isinstance(raw, dict):
            # Absent, or the string 'error: ...' the collector records per
            # server it could not read.
            return None
        props = raw.get("properties", {}) or {}
        return {
            "state": props.get("state"),
            "retention_days": props.get("retentionDays"),
            # Where the records go. A server auditing to nowhere keeps nothing,
            # so the destination is part of the answer rather than detail.
            "storage_endpoint": props.get("storageEndpoint"),
            "log_analytics_enabled": props.get("isAzureMonitorTargetEnabled"),
            "audit_actions": props.get("auditActionsAndGroups") or [],
        }

    def _database_exposure(
        self, props: dict[str, Any], firewall_rules: list[dict[str, Any]] | None
    ) -> Level:
        public = str(props.get("publicNetworkAccess", "")).lower()
        if public == "disabled":
            return Level.LOW
        if firewall_rules is None:
            return Level.UNKNOWN
        for rule in firewall_rules:
            if (rule.get("start_ip_address"), rule.get("end_ip_address")) == (
                "0.0.0.0",
                "255.255.255.255",
            ):
                return Level.CRITICAL
        return Level.HIGH if public == "enabled" else Level.UNKNOWN

    # ---------------------------------------------------------------- compute
    def _normalize_vms(
        self,
        data: dict[str, Any],
        nics: dict[str, Any],
        public_ips: dict[str, Any],
    ) -> tuple[list[CloudResource], list[tuple[str, RelationshipType, str]]]:
        resources: list[CloudResource] = []
        edges: list[tuple[str, RelationshipType, str]] = []

        for vm in data.get("virtual_machines", []):
            props = vm.get("properties", {}) or {}
            context = _context(vm, ResourceType.VIRTUAL_MACHINE)

            attached_nic_ids = [
                nic.get("id")
                for nic in _first(props, "networkProfile", "networkInterfaces", default=[]) or []
                if nic.get("id")
            ]

            vm_public_ips: list[str] = []
            guarding_nsgs: set[str] = set()
            resolved_any_nic = False

            for nic_id in attached_nic_ids:
                nic = nics.get(nic_id)
                if nic is None:
                    continue
                resolved_any_nic = True
                nic_props = nic.get("properties", {}) or {}

                nsg_id = _first(nic_props, "networkSecurityGroup", "id")
                if nsg_id:
                    guarding_nsgs.add(nsg_id)

                for ip_config in nic_props.get("ipConfigurations") or []:
                    ip_props = ip_config.get("properties", {}) or {}
                    # A subnet-level NSG guards the VM just as a NIC-level one does.
                    subnet_nsg = _first(
                        ip_props, "subnet", "properties", "networkSecurityGroup", "id"
                    )
                    if subnet_nsg:
                        guarding_nsgs.add(subnet_nsg)

                    pip_id = _first(ip_props, "publicIPAddress", "id")
                    if pip_id:
                        pip = public_ips.get(pip_id)
                        address = _first(pip or {}, "properties", "ipAddress")
                        vm_public_ips.append(address or pip_id)

            # Edges point NSG -> VM, the direction the relationship actually
            # runs. The rule engine derives the reverse index itself.
            for nsg_id in guarding_nsgs:
                edges.append((nsg_id, RelationshipType.PROTECTS, vm["id"]))

            has_public_ip: bool | None = bool(vm_public_ips)
            if attached_nic_ids and not resolved_any_nic:
                # The VM references NICs we never collected -- we genuinely do
                # not know whether it is exposed.
                has_public_ip = None

            resources.append(
                CloudResource(
                    provider_resource_id=vm["id"],
                    resource_type=ResourceType.VIRTUAL_MACHINE,
                    name=vm.get("name", "unnamed"),
                    provider=Provider.AZURE,
                    region=vm.get("location"),
                    **context.fields(),
                    public_exposure=(
                        Level.UNKNOWN
                        if has_public_ip is None
                        else Level.HIGH
                        if has_public_ip
                        else Level.LOW
                    ),
                    metadata={
                        "has_public_ip": has_public_ip,
                        "public_ips": vm_public_ips,
                        "os_type": _first(props, "storageProfile", "osDisk", "osType"),
                        "vm_size": _first(props, "hardwareProfile", "vmSize"),
                        "network_interfaces": attached_nic_ids,
                        "guarding_nsgs": sorted(guarding_nsgs),
                        "tags": vm.get("tags") or {},
                    },
                )
            )

        return resources, edges

    # --------------------------------------------------------------- identity
    def _normalize_users(
        self, data: dict[str, Any], collected_at: datetime
    ) -> list[CloudResource]:
        role_map = data.get("user_role_map", {}) or {}
        auth_methods = data.get("authentication_methods", {}) or {}
        sign_in = data.get("user_sign_in_activity", {}) or {}
        resources = []

        for user in data.get("users", []):
            user_id = user.get("id")
            if not user_id:
                continue

            roles = role_map.get(user_id, [])
            methods_raw = auth_methods.get(user_id, "__absent__")

            metadata: dict[str, Any] = {
                "user_principal_name": user.get("userPrincipalName"),
                "account_enabled": user.get("accountEnabled"),
                "directory_roles": roles,
            }
            metadata.update(
                self._sign_in_state(user, sign_in, collected_at)
            )
            # Only set mfa_methods when we actually read them. Absent means the
            # rule reports UNKNOWN; empty list means "read it, found nothing".
            if methods_raw != "__absent__" and methods_raw is not None:
                metadata["mfa_methods"] = [
                    self._method_name(m) for m in methods_raw
                ]

            resources.append(
                CloudResource(
                    provider_resource_id=f"/users/{user_id}",
                    resource_type=ResourceType.USER,
                    name=user.get("displayName") or user.get("userPrincipalName") or user_id,
                    provider=Provider.AZURE,
                    criticality=Level.CRITICAL if roles else Level.MEDIUM,
                    data_sensitivity=Level.HIGH if roles else Level.MEDIUM,
                    public_exposure=Level.HIGH,  # identity is internet-reachable by design
                    metadata=metadata,
                )
            )
        return resources

    @staticmethod
    def _sign_in_state(
        user: dict[str, Any],
        sign_in: dict[str, Any],
        collected_at: datetime,
    ) -> dict[str, Any]:
        """What this capture knows about when the account was last used.

        Three states, and keeping them apart is the whole job:

        * The read did not cover this account -- nothing is set, and a rule
          asking about dormancy reports UNKNOWN for it.
        * It covered the account and Entra holds no activity -- the account has
          never signed in, which is the strongest form of dormant rather than a
          missing reading.
        * It covered the account and holds a date -- the age is measured from
          the moment of capture, so a replay of this snapshot reaches the same
          verdict a year later.

        Interactive and non-interactive sign-ins are both read, and the more
        recent one wins. A service account that authenticates nightly has no
        interactive sign-in at all, and judging it on that alone would report
        the tenant's busiest credentials as its most dormant.
        """
        user_id = str(user.get("id"))
        if user_id not in sign_in:
            return {}

        activity = sign_in.get(user_id) or {}
        moments = [
            _graph_time(activity.get(field))
            for field in (
                "lastSignInDateTime",
                "lastNonInteractiveSignInDateTime",
                "lastSuccessfulSignInDateTime",
            )
        ]
        seen = [m for m in moments if m is not None]

        state: dict[str, Any] = {"sign_in_activity_read": True}
        created = _graph_time(user.get("createdDateTime"))
        if created is not None:
            # How long the account has existed, so a rule can tell an account
            # nobody uses from one nobody has had time to use yet.
            state["account_age_days"] = _days_between(created, collected_at)

        if not seen:
            state["last_sign_in"] = None
            state["days_since_sign_in"] = None
            return state

        last = max(seen)
        state["last_sign_in"] = last.isoformat()
        state["days_since_sign_in"] = _days_between(last, collected_at)
        return state

    # ----------------------------------------------------------- applications
    def _normalize_applications(
        self, data: dict[str, Any], collected_at: datetime
    ) -> list[CloudResource]:
        """Application registrations, reduced to when their credentials stop.

        The registration is the asset rather than each credential, because the
        registration is what a customer owns, names and rotates -- a finding
        per secret would report one application with four expired secrets as
        four problems with one fix.

        Public exposure is HIGH for the same reason a directory user's is:
        these credentials are presented to a token endpoint on the internet,
        and no network control stands in front of that.
        """
        resources = []

        for app in data.get("application_credentials", []):
            app_object_id = app.get("id")
            if not app_object_id:
                continue

            credentials = [
                credential
                for kind, field in (
                    ("secret", "passwordCredentials"),
                    ("certificate", "keyCredentials"),
                )
                for credential in self._credentials_of(app, kind, field, collected_at)
            ]

            resources.append(
                CloudResource(
                    provider_resource_id=f"/applications/{app_object_id}",
                    resource_type=ResourceType.APPLICATION,
                    name=app.get("displayName") or str(app_object_id),
                    provider=Provider.AZURE,
                    # An application registration holds no data and runs in no
                    # environment, so there is nothing here for the context
                    # engine to read and nothing a tag could say. What it is
                    # worth depends entirely on what its service principal has
                    # been granted, which the authorization graph answers and
                    # this object does not.
                    criticality=Level.UNKNOWN,
                    data_sensitivity=Level.UNKNOWN,
                    public_exposure=Level.HIGH,
                    metadata={
                        "app_id": app.get("appId"),
                        "credentials": credentials,
                        "credential_count": len(credentials),
                    },
                )
            )
        return resources

    @staticmethod
    def _credentials_of(
        app: dict[str, Any], kind: str, field: str, collected_at: datetime
    ) -> list[dict[str, Any]]:
        """One application's secrets or certificates, dated against the capture.

        ``days_remaining`` is None when Graph gave an expiry this cannot read,
        which is deliberately not zero: an unparseable date is a credential
        CloudGuard knows nothing about, and reporting it as expired would be a
        finding invented out of a parsing failure.
        """
        found = []
        for credential in app.get(field) or []:
            expires = _graph_time(credential.get("endDateTime"))
            found.append(
                {
                    "kind": kind,
                    "key_id": credential.get("keyId"),
                    "display_name": credential.get("displayName"),
                    "end_date": expires.isoformat() if expires else None,
                    "days_remaining": (
                        _days_between(collected_at, expires)
                        if expires is not None
                        else None
                    ),
                }
            )
        return found

    # ------------------------------------------------------ compensating controls
    def _normalize_controls(self, data: dict[str, Any]) -> dict[str, Any]:
        """Tenant defences, reduced to what a rule can actually reason about.

        Only what is *established* survives this. A policy CloudGuard cannot
        fully resolve -- scoped to an application rather than to all of them,
        granting something other than multi-factor, excluding a group whose
        membership never arrived -- is dropped rather than reported weakly,
        because the one thing these are used for is lowering a finding's score
        and a half-understood policy is not grounds for that.
        """
        controls: dict[str, Any] = {}

        defaults = data.get("security_defaults")
        if isinstance(defaults, dict) and defaults.get("isEnabled") is not None:
            controls["security_defaults_enabled"] = bool(defaults.get("isEnabled"))

        policies = data.get("conditional_access_policies")
        if policies is not None:
            controls["mfa_policies"] = self._mfa_policies(
                policies, data.get("directory_roles") or [], data.get("group_members")
            )
        return controls

    @staticmethod
    def _requires_mfa(policy: dict[str, Any]) -> bool:
        """Whether satisfying this policy necessarily means a second factor.

        ``OR`` across several controls does not: a policy granting "MFA or a
        compliant device" lets a stolen password through on a machine the
        attacker has enrolled, and reading it as multi-factor would be
        CloudGuard vouching for a requirement the tenant did not make.

        ``authenticationStrength`` is not read as MFA either. Most strengths are
        multi-factor and a custom one need not be, and the difference is not
        established from the policy object alone.
        """
        grant = policy.get("grantControls") or {}
        built_in = [str(c).lower() for c in (grant.get("builtInControls") or [])]
        if "mfa" not in built_in:
            return False
        if len(built_in) == 1:
            return True
        return str(grant.get("operator", "")).upper() == "AND"

    def _mfa_policies(
        self,
        policies: list[dict[str, Any]],
        directory_roles: list[dict[str, Any]],
        group_members: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Enforced policies that require a second factor of everyone they cover.

        Directory roles are matched by name rather than by id, because that is
        what the role map holds -- and the template id each name corresponds to
        is read from this tenant's own directory rather than from a table of
        GUIDs written from memory. The same discipline ``rbac.py`` applies to
        ARM action strings: an identifier that looks right and is not is
        indistinguishable from one that is, until a customer is affected.
        """
        by_template = {
            str(role.get("roleTemplateId")): str(role.get("displayName", ""))
            for role in directory_roles
            if role.get("roleTemplateId") and role.get("displayName")
        }
        members = group_members or {}

        resolved: list[dict[str, Any]] = []
        for policy in policies:
            if str(policy.get("state", "")).lower() != "enabled":
                continue
            if not self._requires_mfa(policy):
                continue

            conditions = policy.get("conditions") or {}
            applications = conditions.get("applications") or {}
            included_apps = [
                str(a).lower() for a in (applications.get("includeApplications") or [])
            ]
            if "all" not in included_apps:
                # Scoped to particular applications. It may well protect the
                # thing that matters and CloudGuard cannot tell which
                # applications an attacker would use, so it makes no claim.
                continue

            users = conditions.get("users") or {}
            included = [str(u).lower() for u in (users.get("includeUsers") or [])]
            include_groups = [str(g) for g in (users.get("includeGroups") or [])]
            exclude_groups = [str(g) for g in (users.get("excludeGroups") or [])]

            # A group whose membership never arrived leaves the policy's reach
            # unknown in the direction that matters: an unread *exclusion* could
            # contain the very account being judged.
            if any(group not in members for group in exclude_groups):
                continue

            excluded_users = {
                str(u) for u in (users.get("excludeUsers") or []) if u
            }
            for group in exclude_groups:
                excluded_users.update(str(m) for m in members.get(group, []))

            included_users = {str(u) for u in (users.get("includeUsers") or []) if u}
            for group in include_groups:
                included_users.update(str(m) for m in members.get(group, []))

            resolved.append(
                {
                    "id": policy.get("id"),
                    "name": policy.get("displayName") or "Conditional Access policy",
                    "all_users": "all" in included,
                    "role_names": sorted(
                        {
                            by_template[str(r)]
                            for r in (users.get("includeRoles") or [])
                            if str(r) in by_template
                        }
                    ),
                    "user_ids": sorted(included_users),
                    "excluded_role_names": sorted(
                        {
                            by_template[str(r)]
                            for r in (users.get("excludeRoles") or [])
                            if str(r) in by_template
                        }
                    ),
                    "excluded_user_ids": sorted(excluded_users),
                }
            )
        return resolved

    def _method_name(self, method: dict[str, Any]) -> str:
        """Graph returns the method type in @odata.type, e.g.
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'."""
        odata = str(method.get("@odata.type", ""))
        name = odata.rsplit(".", 1)[-1].replace("AuthenticationMethod", "")
        return name or "unknown"

    def _diagnostics_for(
        self, resource_id: str, diagnostics: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        entry = diagnostics.get(resource_id)
        if entry is None or isinstance(entry, str):
            # Absent, or the string 'error: ...' recorded by the collector.
            return None
        return [
            {
                "name": d.get("name"),
                "workspace_id": _first(d, "properties", "workspaceId"),
                "storage_account_id": _first(d, "properties", "storageAccountId"),
                "event_hub_id": _first(d, "properties", "eventHubAuthorizationRuleId"),
            }
            for d in entry
        ]
