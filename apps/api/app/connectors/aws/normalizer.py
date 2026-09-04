"""AWS payloads -> cloud-neutral resources. A pure function of the snapshot.

Nothing here calls AWS, reads a clock or touches a database. The whole point of
storing the provider's own JSON verbatim is that this can be run again, years
later, against a capture nobody can re-take.

Two things it does that the Azure normalizer does not have to.

**It unwraps regional blocks.** A regional key holds
``[{"region": ..., "items": [...]}, ...]`` rather than a flat list, and the
region travels with each resource -- which is where it belongs, because several
AWS identifiers do not carry one and a normalizer forced to recover it from an
ARN would recover nothing for those.

**It maps onto Azure-flavoured type names**, and that is deliberate rather than
lazy. ``ResourceType`` members are neutral concepts under Azure's vocabulary
(``MULTI_CLOUD.md`` §6): an S3 bucket and a storage account are the same kind of
thing to every rule that reads criticality, exposure or sensitivity. Renaming
them is a decision worth making once, against both providers, rather than
inside the change that adds the second.

.. warning::

   The response shapes below come from the published API reference and have not
   been checked against a live account.
"""

from typing import Any

from app.connectors.aws.evidence import AwsEvidence
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.core.logging import get_logger
from app.domain.resource import CloudResource

log = get_logger(__name__)

# Ports whose exposure to the whole internet is a finding rather than a
# configuration choice. Read by the normalizer only to set ``public_exposure``;
# the rules make their own judgements from the raw rules on the group.
ADMIN_PORTS = frozenset({22, 3389})


def regional_items(
    data: dict[str, Any], key: AwsEvidence
) -> list[tuple[str | None, dict[str, Any]]]:
    """Every item under a key, paired with the region it was read in.

    Handles both shapes so one function serves the whole normalizer: a regional
    key holds blocks, a global one holds a plain list. A capture is stored
    verbatim and its shape is a fact about how it was collected, so the
    normalizer accommodates it rather than a migration rewriting old captures.
    """
    payload = data.get(key.value) or []
    if not isinstance(payload, list):
        return []

    pairs: list[tuple[str | None, dict[str, Any]]] = []
    for entry in payload:
        if isinstance(entry, dict) and "items" in entry and "region" in entry:
            region = entry.get("region")
            for item in entry.get("items") or []:
                if isinstance(item, dict):
                    pairs.append((region, item))
        elif isinstance(entry, dict):
            pairs.append((None, entry))
    return pairs


class AwsNormalizer:
    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        state = NormalizedState(collection_errors=dict(snapshot.gaps))
        data = snapshot.data
        account_id = snapshot.subscription_id or ""

        if account_id:
            state.resources.append(self._account(account_id, snapshot.tenant_id))

        state.resources.extend(self._buckets(data))
        state.resources.extend(self._instances(data))
        state.resources.extend(self._security_groups(data))
        state.resources.extend(
            self._simple(data, AwsEvidence.VPCS, "VpcId", ResourceType.VIRTUAL_NETWORK)
        )
        state.resources.extend(
            self._simple(data, AwsEvidence.SUBNETS, "SubnetId", ResourceType.SUBNET)
        )
        state.resources.extend(self._network_interfaces(data))
        state.resources.extend(self._elastic_ips(data))
        state.resources.extend(self._databases(data))
        state.resources.extend(self._keys(data))
        state.resources.extend(self._users(data))
        state.resources.extend(self._roles(data))

        state.relationships.extend(self._relationships(data, account_id))
        state.controls.update(self._controls(data))
        return state

    # ------------------------------------------------------------- the account

    def _account(self, account_id: str, organization_id: str) -> CloudResource:
        """The account itself, which is the AWS analogue of a subscription.

        Present so findings that are about the account rather than about a
        resource in it -- no password policy, root keys still active -- have
        something to attach to.
        """
        return CloudResource(
            provider_resource_id=f"arn:aws:organizations::{account_id}:account",
            resource_type=ResourceType.SUBSCRIPTION,
            name=account_id,
            provider=Provider.AWS,
            metadata={"account_id": account_id, "organization_id": organization_id},
        )

    # ------------------------------------------------------------- storage

    def _buckets(self, data: dict[str, Any]) -> list[CloudResource]:
        """S3 buckets, with the three per-bucket settings folded back on.

        Folded here rather than left to each rule, because all three are keyed
        by bucket name and a rule joining them itself would join them slightly
        differently each time. A setting that could not be read is absent rather
        than false -- which is what lets a rule tell "no block configured" from
        "we could not ask".
        """
        access = self._by_bucket(data, AwsEvidence.S3_PUBLIC_ACCESS_BLOCK)
        policy = self._by_bucket(data, AwsEvidence.S3_BUCKET_POLICY_STATUS)
        encryption = self._by_bucket(data, AwsEvidence.S3_ENCRYPTION)

        resources: list[CloudResource] = []
        for _, bucket in regional_items(data, AwsEvidence.S3_BUCKETS):
            name = str(bucket.get("Name") or "")
            if not name:
                continue
            region = str(bucket.get("Region") or "") or None
            metadata: dict[str, Any] = dict(bucket)
            if name in access:
                metadata["PublicAccessBlock"] = access[name]
            if name in policy:
                metadata["PolicyStatus"] = policy[name]
            if name in encryption:
                metadata["Encryption"] = encryption[name]

            resources.append(
                CloudResource(
                    provider_resource_id=f"arn:aws:s3:::{name}",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    name=name,
                    provider=Provider.AWS,
                    region=region,
                    public_exposure=self._bucket_exposure(metadata),
                    metadata=metadata,
                )
            )
        return resources

    @staticmethod
    def _by_bucket(data: dict[str, Any], key: AwsEvidence) -> dict[str, Any]:
        """One per-bucket reading, indexed by bucket name.

        ``Configuration`` is ``None`` where the setting is simply not set, which
        is a real answer AWS gives as an error code. Kept as ``None`` rather
        than dropped, so a rule can tell it apart from a bucket the reading
        never covered.
        """
        found: dict[str, Any] = {}
        for _, row in regional_items(data, key):
            name = row.get("Bucket")
            if name:
                found[str(name)] = row.get("Configuration")
        return found

    @staticmethod
    def _bucket_exposure(metadata: dict[str, Any]) -> Level:
        """Read off the configuration in the capture, never guessed.

        Two independent ways a bucket is reachable, and a block on one does not
        cover the other: the account-level public access block, and a bucket
        policy that grants a wildcard principal. ``UNKNOWN`` when neither was
        read, because "we did not look" and "it is private" are different
        sentences.
        """
        block = metadata.get("PublicAccessBlock")
        status = metadata.get("PolicyStatus")
        if "PublicAccessBlock" not in metadata and "PolicyStatus" not in metadata:
            return Level.UNKNOWN

        if isinstance(status, dict) and (status.get("PolicyStatus") or {}).get(
            "IsPublic"
        ):
            return Level.HIGH

        settings = (block or {}).get("PublicAccessBlockConfiguration") or {}
        if settings and all(
            settings.get(flag)
            for flag in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        ):
            return Level.LOW
        if not settings:
            return Level.MEDIUM
        return Level.MEDIUM

    # ------------------------------------------------------------- compute

    def _instances(self, data: dict[str, Any]) -> list[CloudResource]:
        resources: list[CloudResource] = []
        for region, instance in regional_items(data, AwsEvidence.EC2_INSTANCES):
            instance_id = str(instance.get("InstanceId") or "")
            if not instance_id:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=instance_id,
                    resource_type=ResourceType.VIRTUAL_MACHINE,
                    name=self._tag(instance, "Name") or instance_id,
                    provider=Provider.AWS,
                    region=region,
                    public_exposure=(
                        Level.HIGH if instance.get("PublicIpAddress") else Level.LOW
                    ),
                    metadata=dict(instance),
                )
            )
        return resources

    # ------------------------------------------------------------- network

    def _security_groups(self, data: dict[str, Any]) -> list[CloudResource]:
        resources: list[CloudResource] = []
        for region, group in regional_items(data, AwsEvidence.SECURITY_GROUPS):
            group_id = str(group.get("GroupId") or "")
            if not group_id:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=group_id,
                    resource_type=ResourceType.NETWORK_SECURITY_GROUP,
                    name=str(group.get("GroupName") or group_id),
                    provider=Provider.AWS,
                    region=region,
                    public_exposure=self._group_exposure(group),
                    metadata=dict(group),
                )
            )
        return resources

    @staticmethod
    def _group_exposure(group: dict[str, Any]) -> Level:
        for permission in group.get("IpPermissions") or []:
            open_to_world = any(
                str(entry.get("CidrIp")) == "0.0.0.0/0"
                for entry in permission.get("IpRanges") or []
            ) or any(
                str(entry.get("CidrIpv6")) == "::/0"
                for entry in permission.get("Ipv6Ranges") or []
            )
            if not open_to_world:
                continue
            start = permission.get("FromPort")
            end = permission.get("ToPort")
            if start is None or end is None:
                # All protocols, which covers every port there is.
                return Level.HIGH
            if any(port in ADMIN_PORTS for port in range(int(start), int(end) + 1)):
                return Level.HIGH
            return Level.MEDIUM
        return Level.LOW

    def _network_interfaces(self, data: dict[str, Any]) -> list[CloudResource]:
        resources: list[CloudResource] = []
        for region, interface in regional_items(data, AwsEvidence.NETWORK_INTERFACES):
            interface_id = str(interface.get("NetworkInterfaceId") or "")
            if not interface_id:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=interface_id,
                    resource_type=ResourceType.NETWORK_INTERFACE,
                    name=interface_id,
                    provider=Provider.AWS,
                    region=region,
                    metadata=dict(interface),
                )
            )
        return resources

    def _elastic_ips(self, data: dict[str, Any]) -> list[CloudResource]:
        resources: list[CloudResource] = []
        for region, address in regional_items(data, AwsEvidence.ELASTIC_IPS):
            allocation = str(
                address.get("AllocationId") or address.get("PublicIp") or ""
            )
            if not allocation:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=allocation,
                    resource_type=ResourceType.PUBLIC_IP,
                    name=str(address.get("PublicIp") or allocation),
                    provider=Provider.AWS,
                    region=region,
                    public_exposure=Level.HIGH,
                    metadata=dict(address),
                )
            )
        return resources

    def _simple(
        self,
        data: dict[str, Any],
        key: AwsEvidence,
        id_field: str,
        resource_type: ResourceType,
    ) -> list[CloudResource]:
        """A listing whose items need nothing but an id and a type."""
        resources: list[CloudResource] = []
        for region, item in regional_items(data, key):
            identifier = str(item.get(id_field) or "")
            if not identifier:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=identifier,
                    resource_type=resource_type,
                    name=self._tag(item, "Name") or identifier,
                    provider=Provider.AWS,
                    region=region,
                    metadata=dict(item),
                )
            )
        return resources

    # ------------------------------------------------------------- database

    def _databases(self, data: dict[str, Any]) -> list[CloudResource]:
        """RDS instances, typed by the engine they run.

        PostgreSQL gets its own type because CloudGuard already has one and the
        remediation differs; everything else maps onto ``SQL_SERVER``, which is
        the neutral "a managed relational database" of the existing vocabulary.
        """
        resources: list[CloudResource] = []
        for region, instance in regional_items(data, AwsEvidence.RDS_INSTANCES):
            arn = str(instance.get("DBInstanceArn") or "")
            identifier = str(instance.get("DBInstanceIdentifier") or "")
            if not arn and not identifier:
                continue
            engine = str(instance.get("Engine") or "").lower()
            resources.append(
                CloudResource(
                    provider_resource_id=arn or identifier,
                    resource_type=(
                        ResourceType.POSTGRESQL_SERVER
                        if "postgres" in engine
                        else ResourceType.SQL_SERVER
                    ),
                    name=identifier or arn,
                    provider=Provider.AWS,
                    region=region,
                    public_exposure=(
                        Level.HIGH if instance.get("PubliclyAccessible") else Level.LOW
                    ),
                    metadata=dict(instance),
                )
            )
        return resources

    # ------------------------------------------------------------- secrets

    def _keys(self, data: dict[str, Any]) -> list[CloudResource]:
        """KMS keys as assets. Their material is not modelled and never will be.

        The same position the Azure connector takes on a key vault: CloudGuard
        holds no permission that could read what a key protects, so a key is
        something it knows exists in the sense that a vault exists.
        """
        resources: list[CloudResource] = []
        for region, key in regional_items(data, AwsEvidence.KMS_KEYS):
            arn = str(key.get("Arn") or key.get("KeyId") or "")
            if not arn:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=arn,
                    resource_type=ResourceType.KEY_VAULT,
                    name=str(key.get("Description") or key.get("KeyId") or arn),
                    provider=Provider.AWS,
                    region=region,
                    metadata=dict(key),
                )
            )
        return resources

    # ------------------------------------------------------------- identity

    def _users(self, data: dict[str, Any]) -> list[CloudResource]:
        """IAM users, with their credential-report row folded on.

        The report is where the facts a rule actually needs live -- MFA, key
        age, last use -- and none of them appear in ``ListUsers``. Joined on the
        ARN, which the report carries and which is unambiguous; a user with no
        row is a user the report did not cover, and the absence is left visible
        rather than filled with a default.
        """
        report = {
            str(row.get("arn") or ""): row
            for _, row in regional_items(data, AwsEvidence.IAM_CREDENTIAL_REPORT)
        }
        resources: list[CloudResource] = []
        for _, user in regional_items(data, AwsEvidence.IAM_USERS):
            arn = str(user.get("Arn") or "")
            if not arn:
                continue
            metadata = dict(user)
            if arn in report:
                metadata["CredentialReport"] = report[arn]
            resources.append(
                CloudResource(
                    provider_resource_id=arn,
                    resource_type=ResourceType.USER,
                    name=str(user.get("UserName") or arn),
                    provider=Provider.AWS,
                    metadata=metadata,
                )
            )
        return resources

    def _roles(self, data: dict[str, Any]) -> list[CloudResource]:
        """IAM roles, as workload identities rather than people.

        ``SERVICE_PRINCIPAL`` because the remediation differs entirely from a
        user's: a person gets MFA, a workload identity gets a narrower policy.
        """
        resources: list[CloudResource] = []
        for _, role in regional_items(data, AwsEvidence.IAM_ROLES):
            arn = str(role.get("Arn") or "")
            if not arn:
                continue
            resources.append(
                CloudResource(
                    provider_resource_id=arn,
                    resource_type=ResourceType.SERVICE_PRINCIPAL,
                    name=str(role.get("RoleName") or arn),
                    provider=Provider.AWS,
                    metadata=dict(role),
                )
            )
        return resources

    # -------------------------------------------------------- relationships

    def _relationships(
        self, data: dict[str, Any], account_id: str
    ) -> list[tuple[str, RelationshipType, str]]:
        """The edges that compose into a path, and the structural ones that do not.

        ``PROTECTS`` and ``ATTACHED_TO`` describe how the estate is put together.
        ``HAS_IDENTITY`` is the one that matters for an attack path: it is the
        first hop from a compromised instance to everything its role is allowed
        to do, which is why it is a capability edge and the others are not.
        """
        edges: list[tuple[str, RelationshipType, str]] = []

        for _, instance in regional_items(data, AwsEvidence.EC2_INSTANCES):
            instance_id = str(instance.get("InstanceId") or "")
            if not instance_id:
                continue
            for group in instance.get("SecurityGroups") or []:
                group_id = str(group.get("GroupId") or "")
                if group_id:
                    edges.append((group_id, RelationshipType.PROTECTS, instance_id))

            profile = (instance.get("IamInstanceProfile") or {}).get("Arn")
            if profile:
                # The instance profile's ARN, not the role's -- they differ by
                # one path segment and only the role exists as a resource. The
                # graph resolves what it can and drops what it cannot, which is
                # better than inventing a role ARN from a naming convention that
                # holds only most of the time.
                edges.append(
                    (instance_id, RelationshipType.HAS_IDENTITY, str(profile))
                )

        for _, interface in regional_items(data, AwsEvidence.NETWORK_INTERFACES):
            interface_id = str(interface.get("NetworkInterfaceId") or "")
            attachment = (interface.get("Attachment") or {}).get("InstanceId")
            if interface_id and attachment:
                edges.append(
                    (interface_id, RelationshipType.ATTACHED_TO, str(attachment))
                )

        for _, subnet in regional_items(data, AwsEvidence.SUBNETS):
            subnet_id = str(subnet.get("SubnetId") or "")
            vpc_id = str(subnet.get("VpcId") or "")
            if subnet_id and vpc_id:
                edges.append((vpc_id, RelationshipType.CONTAINS, subnet_id))

        return edges

    # ------------------------------------------------------------- controls

    def _controls(self, data: dict[str, Any]) -> dict[str, Any]:
        """Account-level state that is not an asset.

        Nobody secures a password policy; it is a defence that lowers what a
        weak credential is worth. Kept out of ``resources`` for exactly the
        reason the Azure controls are: none of these is a thing anybody secures.
        """
        policies = [
            row
            for _, row in regional_items(data, AwsEvidence.ACCOUNT_PASSWORD_POLICY)
        ]
        summaries = [
            row for _, row in regional_items(data, AwsEvidence.ACCOUNT_SUMMARY)
        ]
        detectors = regional_items(data, AwsEvidence.GUARDDUTY_DETECTORS)
        trails = regional_items(data, AwsEvidence.CLOUDTRAIL_TRAILS)

        return {
            "password_policy": policies[0] if policies else None,
            "account_summary": summaries[0] if summaries else None,
            "guardduty_regions": sorted(
                {
                    region
                    for region, detector in detectors
                    if region and detector.get("Status") == "ENABLED"
                }
            ),
            "cloudtrail_regions": sorted({region for region, _ in trails if region}),
            "ebs_encryption_by_default": {
                region: bool(row.get("EbsEncryptionByDefault"))
                for region, row in regional_items(
                    data, AwsEvidence.EBS_ENCRYPTION_DEFAULT
                )
                if region
            },
        }

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _tag(item: dict[str, Any], key: str) -> str | None:
        for tag in item.get("Tags") or []:
            if str(tag.get("Key")) == key:
                return str(tag.get("Value"))
        return None
