"""AWS's collection plans: what to gather, where, and what each piece needs.

Two plans, as on Azure, because a scan reads two different things. The
**account** plan reads one AWS account -- its IAM, its buckets, and every
regional service in every region that account has enabled. The **organization**
plan reads the trust boundary once for the whole scan, which on AWS means the
account list and nothing else: IAM is per account, unlike an Entra directory,
so identity belongs to the account plan rather than above it.

The fan-out is the part with no Azure equivalent. ``ec2:DescribeRegions`` is
read first, before the plan exists, because the plan's *shape* depends on the
answer -- one task per (listing x region). When that read fails the regional
tasks are still emitted, exactly one per key with no region, each depending on
the region listing; the executor then records them SKIPPED. That is the case
worth being careful about: a key with no reading at all produces no gap, so a
rule would see no error, evaluate against nothing, and PASS. The skipped tasks
are what stop a failed region listing from being read as an empty estate.

Every task declares the actions it needs, and ``iam.py`` is checked against
those declarations in both directions.

.. warning::

   Nothing here has been run against a live AWS account. Operation names,
   response keys and pagination shapes come from the published API reference;
   ``docs/AWS_INTEGRATION.md`` §1 is the checklist that makes them verified.
"""

import asyncio
import csv
import io
import json
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from aiobotocore.session import AioSession

from app.connectors.aws.auth import RoleAssumer
from app.connectors.aws.client import AwsApiError, AwsClient
from app.connectors.aws.evidence import AwsEvidence
from app.connectors.collection import CollectionTask, TaskData
from app.connectors.evidence import EvidenceCategory, ProviderEndpoint
from app.core.logging import get_logger

log = get_logger(__name__)

# How many per-resource detail calls one task runs at once. Buckets are the
# case that needs it: three calls per bucket, and an account with four hundred
# buckets would otherwise make twelve hundred sequential round trips.
DETAIL_CONCURRENCY = 8

# How many tasks the executor may have in flight across the whole run. Azure
# needed no ceiling because a wave was eleven listings; a regional fan-out puts
# one listing per region in a wave, and AWS throttles per region per service --
# so a wave that opened every region at once would be shaped to be throttled.
MAX_CONCURRENT_TASKS = 12

# The API contract each reading is taken under, recorded on the evidence row.
# ``api_version`` is botocore's service model date rather than a URL parameter,
# which is the same fact in AWS's vocabulary: it is what decides the response
# shape, so a field absent from a stored capture can be told apart from a field
# the contract never returned.
def endpoint(service: str, operation: str, api_version: str) -> ProviderEndpoint:
    return ProviderEndpoint(f"{service}:{operation}", api_version)


# Which evidence keys an action serves. Declared beside the tasks rather than
# parsed out of them, so ``iam.py`` can answer "which checks does an older
# policy lose" without constructing a builder.
ACTION_KEYS: dict[str, tuple[AwsEvidence, ...]] = {
    "ec2:DescribeRegions": (AwsEvidence.ENABLED_REGIONS,),
    "organizations:ListAccounts": (AwsEvidence.ORGANIZATION_ACCOUNTS,),
    "iam:ListUsers": (AwsEvidence.IAM_USERS,),
    "iam:ListRoles": (AwsEvidence.IAM_ROLES,),
    "iam:ListPolicies": (AwsEvidence.IAM_POLICIES,),
    "iam:GenerateCredentialReport": (AwsEvidence.IAM_CREDENTIAL_REPORT,),
    "iam:GetCredentialReport": (AwsEvidence.IAM_CREDENTIAL_REPORT,),
    "iam:GetAccountPasswordPolicy": (AwsEvidence.ACCOUNT_PASSWORD_POLICY,),
    "iam:GetAccountSummary": (AwsEvidence.ACCOUNT_SUMMARY,),
    "s3:ListAllMyBuckets": (AwsEvidence.S3_BUCKETS,),
    "s3:GetBucketLocation": (AwsEvidence.S3_BUCKETS,),
    "s3:GetBucketPublicAccessBlock": (AwsEvidence.S3_PUBLIC_ACCESS_BLOCK,),
    "s3:GetBucketPolicyStatus": (AwsEvidence.S3_BUCKET_POLICY_STATUS,),
    "s3:GetEncryptionConfiguration": (AwsEvidence.S3_ENCRYPTION,),
    "ec2:GetEbsEncryptionByDefault": (AwsEvidence.EBS_ENCRYPTION_DEFAULT,),
    "ec2:DescribeSecurityGroups": (AwsEvidence.SECURITY_GROUPS,),
    "ec2:DescribeVpcs": (AwsEvidence.VPCS,),
    "ec2:DescribeSubnets": (AwsEvidence.SUBNETS,),
    "ec2:DescribeNetworkInterfaces": (AwsEvidence.NETWORK_INTERFACES,),
    "ec2:DescribeAddresses": (AwsEvidence.ELASTIC_IPS,),
    "ec2:DescribeInstances": (AwsEvidence.EC2_INSTANCES,),
    "rds:DescribeDBInstances": (AwsEvidence.RDS_INSTANCES,),
    "kms:ListKeys": (AwsEvidence.KMS_KEYS,),
    "kms:DescribeKey": (AwsEvidence.KMS_KEYS,),
    "cloudtrail:DescribeTrails": (AwsEvidence.CLOUDTRAIL_TRAILS,),
    "config:DescribeConfigurationRecorders": (AwsEvidence.CONFIG_RECORDERS,),
    "guardduty:ListDetectors": (AwsEvidence.GUARDDUTY_DETECTORS,),
    "guardduty:GetDetector": (AwsEvidence.GUARDDUTY_DETECTORS,),
    "iam:GetPolicyVersion": (AwsEvidence.IAM_POLICY_DOCUMENTS,),
    "iam:ListInstanceProfiles": (AwsEvidence.IAM_INSTANCE_PROFILES,),
    "iam:ListServerCertificates": (AwsEvidence.IAM_SERVER_CERTIFICATES,),
    "s3:GetBucketPolicy": (AwsEvidence.S3_BUCKET_POLICY,),
    "s3:GetBucketLogging": (AwsEvidence.S3_BUCKET_LOGGING,),
    "kms:GetKeyRotationStatus": (AwsEvidence.KMS_KEYS,),
    "ec2:DescribeFlowLogs": (AwsEvidence.VPC_FLOW_LOGS,),
    "ec2:DescribeNetworkAcls": (AwsEvidence.NETWORK_ACLS,),
    "access-analyzer:ListAnalyzers": (AwsEvidence.ACCESS_ANALYZERS,),
    "securityhub:DescribeHub": (AwsEvidence.SECURITYHUB_STATUS,),
    "config:DescribeConfigurationRecorderStatus": (AwsEvidence.CONFIG_RECORDERS,),
    "logs:DescribeMetricFilters": (AwsEvidence.LOG_METRIC_FILTERS,),
    "cloudwatch:DescribeAlarms": (AwsEvidence.CLOUDWATCH_ALARMS,),
}


def categories_for_actions(actions: Iterable[str]) -> frozenset[EvidenceCategory]:
    """Which collection categories a set of actions serves.

    Used to turn "your stack is missing these three actions" into "these
    categories report UNKNOWN until you redeploy", which is the sentence a
    customer can act on.
    """
    return frozenset(
        key.category
        for action in actions
        for key in ACTION_KEYS.get(action, ())
    )


class AwsPlanBuilder:
    """Builds the collection tasks for one AWS account, or for its organization.

    Holds the assumed session and the account id; every task opens its own
    service client over that session, so a truncated listing stays attributable
    to the task that truncated.
    """

    def __init__(
        self,
        assumer: RoleAssumer,
        account_id: str | None = None,
        *,
        session: AioSession | None = None,
        home_region: str = "us-east-1",
    ) -> None:
        self.assumer = assumer
        self.account_id = account_id
        self.session = session
        # Where the global services are called. IAM, S3's bucket list, STS and
        # Organizations answer the same thing wherever they are asked; one has
        # to be named, and this is the one AWS documents as their home.
        self.home_region = home_region

    def client(self, service: str, region: str | None = None) -> AwsClient:
        return AwsClient(
            self.assumer, service, region or self.home_region, session=self.session
        )

    # ------------------------------------------------------------- the plans

    async def build_account_plan(self) -> list[CollectionTask]:
        """Everything read against one account, fanned out over its regions.

        Async, unlike Azure's builder, and that is the region dimension showing
        through: the plan's *shape* is a function of an answer only the account
        can give, so the region listing happens before there is a plan rather
        than inside it.
        """
        regions, problem = await self._enabled_regions()

        tasks: list[CollectionTask] = [self._region_task(regions, problem)]
        tasks += self._global_tasks()

        if problem is not None:
            # One task per regional key, with no region, each blocked on the
            # listing that failed. The executor records them SKIPPED -- which is
            # the whole point: a key with no reading at all raises no gap, so a
            # rule would evaluate against nothing and PASS.
            tasks += [self._blocked_task(key) for key in _REGIONAL_TASK_KEYS]
        else:
            for region in regions:
                tasks += self._regional_tasks(region)
        return tasks

    def build_directory_plan(self) -> list[CollectionTask]:
        """The organization, read once for the whole scan.

        One task, and that is not an oversight. AWS's trust boundary holds the
        account list and nothing else CloudGuard reads: IAM is per account,
        unlike an Entra directory, so every identity listing belongs to the
        account plan.
        """
        return [
            CollectionTask(
                key=AwsEvidence.ORGANIZATION_ACCOUNTS,
                run=self._organization_accounts,
                actions=("organizations:ListAccounts",),
                endpoints=(endpoint("organizations", "ListAccounts", "2016-11-28"),),
            )
        ]

    # ------------------------------------------------------------- the regions

    async def _enabled_regions(self) -> tuple[list[str], str | None]:
        """Which regions this account can be read in, or why that is unknown.

        ``AllRegions=False`` is the default and the one that matters: it returns
        only the regions the account has enabled, so a scan does not spend a
        listing per service on seventeen regions the customer switched off.
        """
        try:
            async with self.client("ec2") as ec2:
                response = await ec2.call("describe_regions", AllRegions=False)
        except AwsApiError as error:
            log.warning(
                "aws.region_listing_failed",
                account_id=self.account_id,
                code=error.code,
                error=str(error),
            )
            return [], str(error) or error.code
        except Exception as exc:
            return [], str(exc) or type(exc).__name__

        regions = sorted(
            str(r.get("RegionName"))
            for r in response.get("Regions") or []
            if r.get("RegionName")
        )
        if not regions:
            return [], "the account reported no enabled regions"
        return regions, None

    def _region_task(
        self, regions: list[str], problem: str | None
    ) -> CollectionTask:
        """The region listing, recorded as the reading it was.

        The call has already been made -- the plan's shape depended on it -- so
        this replays the outcome rather than repeating the call. Recorded as a
        task all the same, because every regional task depends on it and a
        dependency the coverage report has never heard of cannot block anything.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            if problem is not None:
                raise AwsApiError(problem, operation="describe_regions")
            return TaskData({AwsEvidence.ENABLED_REGIONS.value: list(regions)})

        return CollectionTask(
            key=AwsEvidence.ENABLED_REGIONS,
            run=run,
            actions=("ec2:DescribeRegions",),
            endpoints=(endpoint("ec2", "DescribeRegions", "2016-11-15"),),
        )

    def _blocked_task(self, key: AwsEvidence) -> CollectionTask:
        """A regional key that cannot be read because the region list is not.

        Never actually runs -- the executor skips it, because its dependency
        produced no usable data. It exists so the key appears in the coverage
        report at all.
        """

        async def run(collected: dict[str, Any]) -> TaskData:  # pragma: no cover
            raise AwsApiError("the enabled regions could not be listed")

        return CollectionTask(
            key=key,
            run=run,
            depends_on=(AwsEvidence.ENABLED_REGIONS,),
        )

    # ------------------------------------------------------------ global tasks

    def _global_tasks(self) -> list[CollectionTask]:
        return [
            CollectionTask(
                key=AwsEvidence.IAM_USERS,
                run=self._iam_users,
                actions=("iam:ListUsers",),
                endpoints=(endpoint("iam", "ListUsers", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_ROLES,
                run=self._iam_roles,
                actions=("iam:ListRoles",),
                endpoints=(endpoint("iam", "ListRoles", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_POLICIES,
                run=self._iam_policies,
                actions=("iam:ListPolicies",),
                endpoints=(endpoint("iam", "ListPolicies", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_CREDENTIAL_REPORT,
                run=self._credential_report,
                actions=("iam:GenerateCredentialReport", "iam:GetCredentialReport"),
                endpoints=(endpoint("iam", "GetCredentialReport", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.ACCOUNT_PASSWORD_POLICY,
                run=self._password_policy,
                actions=("iam:GetAccountPasswordPolicy",),
                endpoints=(
                    endpoint("iam", "GetAccountPasswordPolicy", "2010-05-08"),
                ),
            ),
            CollectionTask(
                key=AwsEvidence.ACCOUNT_SUMMARY,
                run=self._account_summary,
                actions=("iam:GetAccountSummary",),
                endpoints=(endpoint("iam", "GetAccountSummary", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.S3_BUCKETS,
                run=self._s3_buckets,
                actions=("s3:ListAllMyBuckets", "s3:GetBucketLocation"),
                endpoints=(
                    endpoint("s3", "ListBuckets", "2006-03-01"),
                    endpoint("s3", "GetBucketLocation", "2006-03-01"),
                ),
            ),
            CollectionTask(
                key=AwsEvidence.S3_PUBLIC_ACCESS_BLOCK,
                run=self._s3_public_access,
                depends_on=(AwsEvidence.S3_BUCKETS,),
                actions=("s3:GetBucketPublicAccessBlock",),
                endpoints=(
                    endpoint("s3", "GetPublicAccessBlock", "2006-03-01"),
                ),
            ),
            CollectionTask(
                key=AwsEvidence.S3_BUCKET_POLICY_STATUS,
                run=self._s3_policy_status,
                depends_on=(AwsEvidence.S3_BUCKETS,),
                actions=("s3:GetBucketPolicyStatus",),
                endpoints=(endpoint("s3", "GetBucketPolicyStatus", "2006-03-01"),),
            ),
            CollectionTask(
                key=AwsEvidence.S3_ENCRYPTION,
                run=self._s3_encryption,
                depends_on=(AwsEvidence.S3_BUCKETS,),
                actions=("s3:GetEncryptionConfiguration",),
                endpoints=(endpoint("s3", "GetBucketEncryption", "2006-03-01"),),
            ),
            CollectionTask(
                key=AwsEvidence.S3_BUCKET_POLICY,
                run=self._s3_bucket_policy,
                depends_on=(AwsEvidence.S3_BUCKETS,),
                actions=("s3:GetBucketPolicy",),
                endpoints=(endpoint("s3", "GetBucketPolicy", "2006-03-01"),),
            ),
            CollectionTask(
                key=AwsEvidence.S3_BUCKET_LOGGING,
                run=self._s3_bucket_logging,
                depends_on=(AwsEvidence.S3_BUCKETS,),
                actions=("s3:GetBucketLogging",),
                endpoints=(endpoint("s3", "GetBucketLogging", "2006-03-01"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_POLICY_DOCUMENTS,
                run=self._iam_policy_documents,
                depends_on=(AwsEvidence.IAM_POLICIES,),
                actions=("iam:GetPolicyVersion",),
                endpoints=(endpoint("iam", "GetPolicyVersion", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_INSTANCE_PROFILES,
                run=self._iam_instance_profiles,
                actions=("iam:ListInstanceProfiles",),
                endpoints=(endpoint("iam", "ListInstanceProfiles", "2010-05-08"),),
            ),
            CollectionTask(
                key=AwsEvidence.IAM_SERVER_CERTIFICATES,
                run=self._iam_server_certificates,
                actions=("iam:ListServerCertificates",),
                endpoints=(
                    endpoint("iam", "ListServerCertificates", "2010-05-08"),
                ),
            ),
        ]

    # ---------------------------------------------------------- regional tasks

    def _regional_tasks(self, region: str) -> list[CollectionTask]:
        listings: list[tuple[AwsEvidence, str, str, str, str, str]] = [
            (
                AwsEvidence.SECURITY_GROUPS,
                "ec2",
                "describe_security_groups",
                "SecurityGroups",
                "ec2:DescribeSecurityGroups",
                "2016-11-15",
            ),
            (
                AwsEvidence.VPCS,
                "ec2",
                "describe_vpcs",
                "Vpcs",
                "ec2:DescribeVpcs",
                "2016-11-15",
            ),
            (
                AwsEvidence.SUBNETS,
                "ec2",
                "describe_subnets",
                "Subnets",
                "ec2:DescribeSubnets",
                "2016-11-15",
            ),
            (
                AwsEvidence.NETWORK_INTERFACES,
                "ec2",
                "describe_network_interfaces",
                "NetworkInterfaces",
                "ec2:DescribeNetworkInterfaces",
                "2016-11-15",
            ),
            (
                AwsEvidence.ELASTIC_IPS,
                "ec2",
                "describe_addresses",
                "Addresses",
                "ec2:DescribeAddresses",
                "2016-11-15",
            ),
            (
                AwsEvidence.RDS_INSTANCES,
                "rds",
                "describe_db_instances",
                "DBInstances",
                "rds:DescribeDBInstances",
                "2014-10-31",
            ),
            (
                AwsEvidence.CLOUDTRAIL_TRAILS,
                "cloudtrail",
                "describe_trails",
                "trailList",
                "cloudtrail:DescribeTrails",
                "2013-11-01",
            ),
            (
                AwsEvidence.NETWORK_ACLS,
                "ec2",
                "describe_network_acls",
                "NetworkAcls",
                "ec2:DescribeNetworkAcls",
                "2016-11-15",
            ),
            (
                AwsEvidence.VPC_FLOW_LOGS,
                "ec2",
                "describe_flow_logs",
                "FlowLogs",
                "ec2:DescribeFlowLogs",
                "2016-11-15",
            ),
            # Every filter in the region, not only the ones on a trail's log
            # group. Which log group matters is the *rule's* question, and a
            # collector that decided it here would have to know what the rules
            # are looking for -- and would collect nothing for an account whose
            # trail listing failed.
            (
                AwsEvidence.LOG_METRIC_FILTERS,
                "logs",
                "describe_metric_filters",
                "metricFilters",
                "logs:DescribeMetricFilters",
                "2014-03-28",
            ),
            (
                AwsEvidence.CLOUDWATCH_ALARMS,
                "cloudwatch",
                "describe_alarms",
                "MetricAlarms",
                "cloudwatch:DescribeAlarms",
                "2010-08-01",
            ),
        ]

        tasks = [
            self._listing_task(key, service, operation, result_key, action, api, region)
            for key, service, operation, result_key, action, api in listings
        ]
        tasks.append(self._config_recorders_task(region))
        tasks.append(self._instances_task(region))
        tasks.append(self._securityhub_task(region))
        tasks.append(self._access_analyzer_task(region))
        tasks.append(self._ebs_default_task(region))
        tasks.append(self._kms_task(region))
        tasks.append(self._guardduty_task(region))
        return tasks

    def _listing_task(
        self,
        key: AwsEvidence,
        service: str,
        operation: str,
        result_key: str,
        action: str,
        api_version: str,
        region: str,
    ) -> CollectionTask:
        """One paginated listing in one region.

        ``describe_trails`` and ``describe_configuration_recorders`` have no
        paginator in botocore, so they fall back to a single call -- which is
        correct rather than a compromise: neither response is paginated.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client(service, region) as client:
                if client.can_paginate(operation):
                    items = await client.paginate(operation, result_key)
                else:
                    response = await client.call(operation)
                    items = list(response.get(result_key) or [])
                return TaskData(
                    {key.value: items},
                    partial_reason=(
                        f"{operation} stopped at the page cap"
                        if client.truncated
                        else None
                    ),
                )

        return CollectionTask(
            key=key,
            run=run,
            region=region,
            actions=(action,),
            endpoints=(endpoint(service, operation, api_version),),
        )

    def _instances_task(self, region: str) -> CollectionTask:
        """EC2 instances, flattened out of the reservations they arrive in.

        ``DescribeInstances`` answers reservations, each holding instances, and
        a reservation is an artefact of how they were launched rather than
        anything a rule judges. Flattened here so the normalizer reads a list of
        instances -- the reservation id stays on each one, which is where it is
        actually useful.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("ec2", region) as ec2:
                reservations = await ec2.paginate(
                    "describe_instances", "Reservations"
                )
                instances = [
                    {**instance, "ReservationId": reservation.get("ReservationId")}
                    for reservation in reservations
                    for instance in reservation.get("Instances") or []
                ]
                return TaskData(
                    {AwsEvidence.EC2_INSTANCES.value: instances},
                    partial_reason=(
                        "describe_instances stopped at the page cap"
                        if ec2.truncated
                        else None
                    ),
                )

        return CollectionTask(
            key=AwsEvidence.EC2_INSTANCES,
            run=run,
            region=region,
            actions=("ec2:DescribeInstances",),
            endpoints=(endpoint("ec2", "DescribeInstances", "2016-11-15"),),
        )

    def _ebs_default_task(self, region: str) -> CollectionTask:
        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("ec2", region) as ec2:
                response = await ec2.call("get_ebs_encryption_by_default")
                return TaskData(
                    {AwsEvidence.EBS_ENCRYPTION_DEFAULT.value: [response]}
                )

        return CollectionTask(
            key=AwsEvidence.EBS_ENCRYPTION_DEFAULT,
            run=run,
            region=region,
            actions=("ec2:GetEbsEncryptionByDefault",),
            endpoints=(endpoint("ec2", "GetEbsEncryptionByDefault", "2016-11-15"),),
        )

    def _kms_task(self, region: str) -> CollectionTask:
        """Key metadata, never key material.

        ``DescribeKey`` returns rotation state, origin and whether the key is
        pending deletion. It returns nothing that could decrypt anything, and
        ``kms:Decrypt`` is not in the policy and never will be.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("kms", region) as kms:
                listed = await kms.paginate("list_keys", "Keys")
                async def describe(entry: dict[str, Any]) -> dict[str, Any] | None:
                    key_id = str(entry.get("KeyId"))
                    found = await kms.optional("describe_key", KeyId=key_id)
                    if not found:
                        return None
                    metadata = dict(found.get("KeyMetadata") or {})
                    # Rotation is a separate call and only means anything for a
                    # key AWS does not manage: asking about an AWS-managed key
                    # answers ``UnsupportedOperationException``, which is not a
                    # finding and not a gap.
                    if metadata.get("KeyManager") == "CUSTOMER":
                        rotation = await kms.optional(
                            "get_key_rotation_status", KeyId=key_id
                        )
                        metadata["KeyRotationEnabled"] = (
                            None if rotation is None
                            else bool(rotation.get("KeyRotationEnabled"))
                        )
                    return metadata

                described = await _fan_out(listed, describe)
                keys = [result for result in described if result]
                return TaskData(
                    {AwsEvidence.KMS_KEYS.value: keys},
                    partial_reason=(
                        "list_keys stopped at the page cap" if kms.truncated else None
                    ),
                )

        return CollectionTask(
            key=AwsEvidence.KMS_KEYS,
            run=run,
            region=region,
            actions=("kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"),
            endpoints=(
                endpoint("kms", "ListKeys", "2014-11-01"),
                endpoint("kms", "DescribeKey", "2014-11-01"),
                endpoint("kms", "GetKeyRotationStatus", "2014-11-01"),
            ),
        )

    def _config_recorders_task(self, region: str) -> CollectionTask:
        """Whether AWS Config exists here, and whether it is actually recording.

        Two calls in one task, unlike the split this connector usually prefers.
        The recorder's *existence* and its *status* are granted by the same
        managed policy and refused together, so separating them would buy a
        finer gap that cannot occur -- and a recorder that exists and is stopped
        is the finding, which needs both halves to see.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("config", region) as config:
                listed = await config.call("describe_configuration_recorders")
                status = await config.optional(
                    "describe_configuration_recorder_status"
                )
                by_name = {
                    str(entry.get("name")): entry
                    for entry in (status or {}).get("ConfigurationRecordersStatus")
                    or []
                }
                recorders = [
                    {**recorder, "Status": by_name.get(str(recorder.get("name")))}
                    for recorder in listed.get("ConfigurationRecorders") or []
                ]
                return TaskData({AwsEvidence.CONFIG_RECORDERS.value: recorders})

        return CollectionTask(
            key=AwsEvidence.CONFIG_RECORDERS,
            run=run,
            region=region,
            actions=(
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
            ),
            endpoints=(
                endpoint("config", "DescribeConfigurationRecorders", "2014-11-12"),
                endpoint(
                    "config", "DescribeConfigurationRecorderStatus", "2014-11-12"
                ),
            ),
        )

    def _securityhub_task(self, region: str) -> CollectionTask:
        """Whether Security Hub is switched on here.

        The hub rather than its findings. CloudGuard reaches its own verdicts
        and does not re-report somebody else's -- but a region with no hub has
        nobody aggregating at all, and that is a fact about the account rather
        than a conclusion of theirs.

        A region where it is off answers ``InvalidAccessException``, which the
        client already treats as an answer rather than a gap.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("securityhub", region) as hub:
                found = await hub.optional("describe_hub")
                return TaskData(
                    {AwsEvidence.SECURITYHUB_STATUS.value: [found] if found else []}
                )

        return CollectionTask(
            key=AwsEvidence.SECURITYHUB_STATUS,
            run=run,
            region=region,
            actions=("securityhub:DescribeHub",),
            endpoints=(endpoint("securityhub", "DescribeHub", "2018-10-26"),),
        )

    def _access_analyzer_task(self, region: str) -> CollectionTask:
        """Whether anything watches for resources shared outside the account."""

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("accessanalyzer", region) as analyzer:
                listed = await analyzer.call("list_analyzers")
                return TaskData(
                    {
                        AwsEvidence.ACCESS_ANALYZERS.value: list(
                            listed.get("analyzers") or []
                        )
                    }
                )

        return CollectionTask(
            key=AwsEvidence.ACCESS_ANALYZERS,
            run=run,
            region=region,
            actions=("access-analyzer:ListAnalyzers",),
            endpoints=(endpoint("accessanalyzer", "ListAnalyzers", "2019-11-01"),),
        )

    def _guardduty_task(self, region: str) -> CollectionTask:
        """What the customer's own detector has concluded, where there is one.

        A region with GuardDuty switched off has an answer -- no detector -- and
        it is not a gap. Recorded as an empty list rather than a failure, so the
        rule that reads it can say "GuardDuty is not enabled here", which is the
        finding, instead of reporting UNKNOWN over a question it can answer.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            async with self.client("guardduty", region) as guardduty:
                listed = await guardduty.call("list_detectors")
                detectors = []
                for detector_id in listed.get("DetectorIds") or []:
                    detail = await guardduty.optional(
                        "get_detector", DetectorId=detector_id
                    )
                    if detail is not None:
                        detectors.append({**detail, "DetectorId": detector_id})
                return TaskData({AwsEvidence.GUARDDUTY_DETECTORS.value: detectors})

        return CollectionTask(
            key=AwsEvidence.GUARDDUTY_DETECTORS,
            run=run,
            region=region,
            actions=("guardduty:ListDetectors", "guardduty:GetDetector"),
            endpoints=(
                endpoint("guardduty", "ListDetectors", "2017-11-28"),
                endpoint("guardduty", "GetDetector", "2017-11-28"),
            ),
        )

    # ------------------------------------------------------------ global reads

    async def _organization_accounts(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("organizations") as organizations:
            accounts = await organizations.paginate("list_accounts", "Accounts")
            return TaskData(
                {AwsEvidence.ORGANIZATION_ACCOUNTS.value: accounts},
                partial_reason=(
                    "list_accounts stopped at the page cap"
                    if organizations.truncated
                    else None
                ),
            )

    async def _iam_users(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("iam") as iam:
            users = await iam.paginate("list_users", "Users")
            return TaskData(
                {AwsEvidence.IAM_USERS.value: users},
                partial_reason=(
                    "list_users stopped at the page cap" if iam.truncated else None
                ),
            )

    async def _iam_roles(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("iam") as iam:
            roles = await iam.paginate("list_roles", "Roles")
            return TaskData(
                {AwsEvidence.IAM_ROLES.value: roles},
                partial_reason=(
                    "list_roles stopped at the page cap" if iam.truncated else None
                ),
            )

    async def _iam_policies(self, collected: dict[str, Any]) -> TaskData:
        """Customer-managed policies only.

        ``Scope="Local"`` excludes AWS's own hundreds, which no rule judges and
        which would be the same payload in every account CloudGuard ever reads.
        ``OnlyAttached`` is deliberately *not* set: a policy granting ``*:*`` and
        attached to nothing today is attached to something tomorrow.
        """
        async with self.client("iam") as iam:
            policies = await iam.paginate("list_policies", "Policies", Scope="Local")
            return TaskData(
                {AwsEvidence.IAM_POLICIES.value: policies},
                partial_reason=(
                    "list_policies stopped at the page cap" if iam.truncated else None
                ),
            )

    async def _credential_report(self, collected: dict[str, Any]) -> TaskData:
        """IAM's report on every credential in the account, parsed into rows.

        Generated asynchronously: the first ``GetCredentialReport`` answers
        ``ReportNotPresent`` and starts the generation, so the call is retried
        rather than treated as an answer. ``GenerateCredentialReport`` is a write
        in IAM's vocabulary and creates nothing -- it compiles a report about
        state that already exists -- which is why it is the one non-``Get``
        action in the policy and why it is called out there.

        Stored as parsed rows rather than the raw CSV, because a base64 blob in
        the capture is not something anybody can read back in two years.
        """
        async with self.client("iam") as iam:
            await iam.optional("generate_credential_report")
            report = None
            for _ in range(6):
                report = await iam.optional("get_credential_report")
                if report is not None:
                    break
                await asyncio.sleep(2)
            if report is None:
                return TaskData(
                    {AwsEvidence.IAM_CREDENTIAL_REPORT.value: []},
                    partial_reason="IAM did not produce a credential report in time",
                )
            content = report.get("Content") or b""
            text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
            rows = list(csv.DictReader(io.StringIO(text)))
            return TaskData({AwsEvidence.IAM_CREDENTIAL_REPORT.value: rows})

    async def _password_policy(self, collected: dict[str, Any]) -> TaskData:
        """The account's password policy, or the fact that it has none.

        ``NoSuchEntity`` means no policy is set, which is the finding rather
        than a failed read -- an empty list says so without costing the rule its
        verdict.
        """
        async with self.client("iam") as iam:
            response = await iam.optional("get_account_password_policy")
            policy = (response or {}).get("PasswordPolicy")
            return TaskData(
                {AwsEvidence.ACCOUNT_PASSWORD_POLICY.value: [policy] if policy else []}
            )

    async def _account_summary(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("iam") as iam:
            response = await iam.call("get_account_summary")
            return TaskData(
                {AwsEvidence.ACCOUNT_SUMMARY.value: [response.get("SummaryMap") or {}]}
            )

    async def _iam_policy_documents(self, collected: dict[str, Any]) -> TaskData:
        """What each customer-managed policy actually grants.

        ``ListPolicies`` answers metadata, so a check asking "does this grant
        everything" has nothing to read without this. Only the *default*
        version, which is the one in force -- an older version that granted more
        is history rather than access.

        AWS returns the document URL-encoded, and it is decoded here so the
        stored reading is JSON somebody can read back in two years rather than a
        percent-escaped string.
        """
        from urllib.parse import unquote

        policies = collected.get(AwsEvidence.IAM_POLICIES.value) or []

        async def read(policy: dict[str, Any]) -> dict[str, Any] | None:
            arn = str(policy.get("Arn") or "")
            version = str(policy.get("DefaultVersionId") or "")
            if not arn or not version:
                return None
            async with self.client("iam") as iam:
                found = await iam.optional(
                    "get_policy_version", PolicyArn=arn, VersionId=version
                )
            if found is None:
                return None
            document = (found.get("PolicyVersion") or {}).get("Document")
            if isinstance(document, str):
                try:
                    document = json.loads(unquote(document))
                except ValueError:
                    document = None
            return {
                "Arn": arn,
                "PolicyName": policy.get("PolicyName"),
                "VersionId": version,
                "AttachmentCount": policy.get("AttachmentCount"),
                "Document": document,
            }

        rows = await _fan_out(policies, read)
        return TaskData(
            {AwsEvidence.IAM_POLICY_DOCUMENTS.value: [row for row in rows if row]}
        )

    async def _iam_instance_profiles(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("iam") as iam:
            profiles = await iam.paginate(
                "list_instance_profiles", "InstanceProfiles"
            )
            return TaskData(
                {AwsEvidence.IAM_INSTANCE_PROFILES.value: profiles},
                partial_reason=(
                    "list_instance_profiles stopped at the page cap"
                    if iam.truncated
                    else None
                ),
            )

    async def _iam_server_certificates(self, collected: dict[str, Any]) -> TaskData:
        async with self.client("iam") as iam:
            certificates = await iam.paginate(
                "list_server_certificates", "ServerCertificateMetadataList"
            )
            return TaskData(
                {AwsEvidence.IAM_SERVER_CERTIFICATES.value: certificates},
                partial_reason=(
                    "list_server_certificates stopped at the page cap"
                    if iam.truncated
                    else None
                ),
            )

    async def _s3_bucket_policy(self, collected: dict[str, Any]) -> TaskData:
        """Each bucket's policy document, parsed.

        A bucket with no policy answers ``NoSuchBucketPolicy``, which the client
        treats as an answer -- and it *is* one: no policy means no policy
        denying plaintext HTTP, which is the finding.
        """
        rows = await self._per_bucket(
            collected, AwsEvidence.S3_BUCKET_POLICY, "get_bucket_policy"
        )
        parsed = []
        for row in rows.data[AwsEvidence.S3_BUCKET_POLICY.value]:
            document = (row.get("Configuration") or {}).get("Policy")
            if isinstance(document, str):
                try:
                    document = json.loads(document)
                except ValueError:
                    document = None
            parsed.append({**row, "Document": document})
        return TaskData({AwsEvidence.S3_BUCKET_POLICY.value: parsed})

    async def _s3_bucket_logging(self, collected: dict[str, Any]) -> TaskData:
        return await self._per_bucket(
            collected, AwsEvidence.S3_BUCKET_LOGGING, "get_bucket_logging"
        )

    async def _s3_buckets(self, collected: dict[str, Any]) -> TaskData:
        """Every bucket, each carrying the region it actually lives in.

        The bucket list is global and the per-bucket calls are not: they have to
        be made against the bucket's own region or they answer
        ``PermanentRedirect``. ``GetBucketLocation`` answers ``None`` for
        us-east-1, which is a documented quirk rather than a missing value.
        """
        async with self.client("s3") as s3:
            listed = await s3.call("list_buckets")
            buckets = list(listed.get("Buckets") or [])

            async def locate(bucket: dict[str, Any]) -> dict[str, Any]:
                where = await s3.optional(
                    "get_bucket_location", Bucket=str(bucket.get("Name"))
                )
                constraint = (where or {}).get("LocationConstraint")
                return {**bucket, "Region": constraint or "us-east-1"}

            located = await _fan_out(buckets, locate)
            return TaskData(
                {AwsEvidence.S3_BUCKETS.value: [b for b in located if b]}
            )

    async def _s3_public_access(self, collected: dict[str, Any]) -> TaskData:
        return await self._per_bucket(
            collected,
            AwsEvidence.S3_PUBLIC_ACCESS_BLOCK,
            "get_public_access_block",
        )

    async def _s3_policy_status(self, collected: dict[str, Any]) -> TaskData:
        return await self._per_bucket(
            collected, AwsEvidence.S3_BUCKET_POLICY_STATUS, "get_bucket_policy_status"
        )

    async def _s3_encryption(self, collected: dict[str, Any]) -> TaskData:
        return await self._per_bucket(
            collected, AwsEvidence.S3_ENCRYPTION, "get_bucket_encryption"
        )

    async def _per_bucket(
        self, collected: dict[str, Any], key: AwsEvidence, operation: str
    ) -> TaskData:
        """One per-bucket setting, read in each bucket's own region.

        A bucket with the setting unset answers with an error code rather than
        an empty document -- ``NoSuchPublicAccessBlockConfiguration``,
        ``NoSuchBucketPolicy``, ``ServerSideEncryptionConfigurationNotFoundError``
        -- and every one of those *is* the finding. Recorded as a row with the
        setting absent, which is the honest reading and the one the rule needs;
        treating it as a failed call would degrade the rule that was about to
        raise it.
        """
        buckets = collected.get(AwsEvidence.S3_BUCKETS.value) or []

        async def read(bucket: dict[str, Any]) -> dict[str, Any]:
            name = str(bucket.get("Name"))
            region = str(bucket.get("Region") or self.home_region)
            async with self.client("s3", region) as s3:
                found = await s3.optional(operation, Bucket=name)
            return {"Bucket": name, "Region": region, "Configuration": found}

        rows = await _fan_out(buckets, read)
        return TaskData({key.value: [row for row in rows if row]})


async def _fan_out(
    items: list[dict[str, Any]],
    call: Callable[[dict[str, Any]], Awaitable[Any]],
) -> list[Any]:
    """Run one call per item, a bounded number at a time.

    Bounded because an account with four hundred buckets would otherwise open
    four hundred concurrent calls to one service and be throttled for it -- and
    a throttled detail call costs the whole task, not just the item.
    """
    gate = asyncio.Semaphore(DETAIL_CONCURRENCY)

    async def one(item: dict[str, Any]) -> Any:
        async with gate:
            return await call(item)

    return list(await asyncio.gather(*(one(item) for item in items)))


# Regional keys as the plan actually emits them. Derived from the tasks rather
# than listed twice: a key that is regional in ``evidence.py`` and has no
# regional task would otherwise be skipped for a region list nothing was going
# to read.
_REGIONAL_TASK_KEYS: tuple[AwsEvidence, ...] = (
    AwsEvidence.SECURITY_GROUPS,
    AwsEvidence.VPCS,
    AwsEvidence.SUBNETS,
    AwsEvidence.NETWORK_INTERFACES,
    AwsEvidence.ELASTIC_IPS,
    AwsEvidence.RDS_INSTANCES,
    AwsEvidence.CLOUDTRAIL_TRAILS,
    AwsEvidence.CONFIG_RECORDERS,
    AwsEvidence.NETWORK_ACLS,
    AwsEvidence.VPC_FLOW_LOGS,
    AwsEvidence.LOG_METRIC_FILTERS,
    AwsEvidence.CLOUDWATCH_ALARMS,
    AwsEvidence.SECURITYHUB_STATUS,
    AwsEvidence.ACCESS_ANALYZERS,
    AwsEvidence.EC2_INSTANCES,
    AwsEvidence.EBS_ENCRYPTION_DEFAULT,
    AwsEvidence.KMS_KEYS,
    AwsEvidence.GUARDDUTY_DETECTORS,
)
