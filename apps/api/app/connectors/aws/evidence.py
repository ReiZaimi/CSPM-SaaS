"""Every unit of evidence CloudGuard collects from AWS.

One member per collection task, the same discipline Azure's keys follow: the
task declares which key it produces, the rule declares which it needs, and the
coverage report is keyed by the same values -- so "this rule lost its verdict
because that listing failed" is one lookup rather than three strings agreeing by
hand.

**The region is not part of the key**, and this is the decision the whole AWS
connector rests on. A rule depends on evidence, and a rule has no business
knowing which regions a customer has enabled: asking for the security groups is
asking about the estate, not about eu-west-1. A key read in seventeen regions is
seventeen *readings*, scoped by region in the coverage report and in the
``evidence`` table, aggregated back to one verdict before any rule sees it
(``DECISIONS.md`` §69).

:attr:`AwsEvidence.regional` says which keys work that way. The global ones are
global in AWS's own terms rather than in ours -- IAM, S3's bucket list,
Organizations and STS are single-endpoint services, and asking them once per
region would return the same answer seventeen times.
"""

from datetime import timedelta

from app.connectors.evidence import EvidenceCategory, EvidenceKey


class AwsEvidence(EvidenceKey):
    """The keys. Values match the snapshot's own payload keys, deliberately.

    A snapshot holds ``{"s3_buckets": [...]}``, so keeping the key equal to the
    payload name means the evidence a rule asks for and the data it then reads
    are named the same thing in both places.
    """

    # --- the account itself, and where it can be read ----------------------
    #
    # Which regions this account has enabled. A task like any other, and every
    # regional task depends on it -- so an account that cannot answer it
    # collects nothing regional rather than guessing at a region list and
    # reporting the estate as empty.
    ENABLED_REGIONS = "enabled_regions"
    # The accounts in the customer's organization, read once per scan against
    # the management account. The AWS analogue of Azure's directory read.
    ORGANIZATION_ACCOUNTS = "organization_accounts"

    # --- identity: global, and read once for the whole account -------------
    IAM_USERS = "iam_users"
    IAM_ROLES = "iam_roles"
    IAM_POLICIES = "iam_policies"
    # IAM's own report on every credential in the account: when each password
    # and access key was last used, whether MFA is on, whether the root account
    # still has keys. One call rather than four per user, and the only place
    # some of those facts exist at all.
    #
    # Generated asynchronously by IAM: the first request returns 404 with
    # ``ReportNotPresent`` and starts the generation, so the collector asks
    # again rather than treating the first answer as the answer.
    IAM_CREDENTIAL_REPORT = "iam_credential_report"
    ACCOUNT_PASSWORD_POLICY = "account_password_policy"
    # Whether the account's root user has MFA, and how many keys it holds.
    # Separate from the credential report because it is a separate call and
    # separately deniable -- and because the root account is the one identity
    # whose compromise is unrecoverable.
    ACCOUNT_SUMMARY = "account_summary"

    # --- storage: the bucket list is global, its settings are per bucket ---
    S3_BUCKETS = "s3_buckets"
    # Whether each bucket blocks public access, at the bucket level. Its own key
    # rather than a field on the listing, because it is a separate call per
    # bucket and refused separately: a role that can list buckets and not read
    # their access blocks has read the listing perfectly well, and the public
    # -access rule going UNKNOWN is the honest outcome for that one check.
    S3_PUBLIC_ACCESS_BLOCK = "s3_public_access_block"
    S3_ENCRYPTION = "s3_encryption"
    # The bucket policy, which is the other half of "is this public": a bucket
    # can block public ACLs and still carry a policy granting ``*``.
    S3_BUCKET_POLICY_STATUS = "s3_bucket_policy_status"

    # --- account-wide settings that happen to be regional ------------------
    # Whether new EBS volumes are encrypted by default. Regional, and one of
    # the few settings where a single unset region is a real finding rather
    # than a rounding error.
    EBS_ENCRYPTION_DEFAULT = "ebs_encryption_default"

    # --- network: regional -------------------------------------------------
    SECURITY_GROUPS = "security_groups"
    VPCS = "vpcs"
    SUBNETS = "subnets"
    NETWORK_INTERFACES = "network_interfaces"
    ELASTIC_IPS = "elastic_ips"

    # --- compute: regional -------------------------------------------------
    EC2_INSTANCES = "ec2_instances"

    # --- database: regional ------------------------------------------------
    RDS_INSTANCES = "rds_instances"

    # --- secrets: regional -------------------------------------------------
    # The key's configuration -- rotation, policy, state. Never its material:
    # ``kms:Decrypt`` is not requested and never will be, exactly as the Azure
    # connector reads a vault's configuration and none of its contents.
    KMS_KEYS = "kms_keys"

    # --- logging -----------------------------------------------------------
    # Trails are listed per region but a multi-region trail is returned by every
    # region it covers, which is precisely what the rule needs to see: "is there
    # a trail covering this region" cannot be answered from one region's list.
    CLOUDTRAIL_TRAILS = "cloudtrail_trails"
    CONFIG_RECORDERS = "config_recorders"

    # --- posture: somebody else's conclusions, read as evidence ------------
    GUARDDUTY_DETECTORS = "guardduty_detectors"

    @property
    def category(self) -> EvidenceCategory:
        return _CATEGORIES[self]

    @property
    def regional(self) -> bool:
        """Whether this listing must be read once per enabled region.

        The line is AWS's, not ours: IAM, S3's bucket list, Organizations and
        STS answer from one endpoint for the whole account, and asking them per
        region would return the same answer seventeen times and pay for it
        seventeen times.
        """
        return self in _REGIONAL

    @property
    def reuse_window(self) -> timedelta | None:
        """Never, for every AWS key, and structurally so.

        A carried reading is held under one entry per evidence key
        (``CollectionPlan.carried``), which cannot hold seventeen regions of one
        key without silently keeping whichever was written last. A regional key
        must therefore never declare a window, and ``test_aws_evidence`` pins
        that. The global keys decline one for the ordinary reason: a customer
        who fixes something and asks CloudGuard to check is owed an answer about
        the account as it is now.
        """
        return None


_CATEGORIES: dict[AwsEvidence, EvidenceCategory] = {
    AwsEvidence.ENABLED_REGIONS: EvidenceCategory.RESOURCES,
    AwsEvidence.ORGANIZATION_ACCOUNTS: EvidenceCategory.RESOURCES,
    AwsEvidence.IAM_USERS: EvidenceCategory.IDENTITY,
    AwsEvidence.IAM_ROLES: EvidenceCategory.IDENTITY,
    AwsEvidence.IAM_POLICIES: EvidenceCategory.AUTHORIZATION,
    AwsEvidence.IAM_CREDENTIAL_REPORT: EvidenceCategory.IDENTITY,
    AwsEvidence.ACCOUNT_PASSWORD_POLICY: EvidenceCategory.IDENTITY,
    AwsEvidence.ACCOUNT_SUMMARY: EvidenceCategory.IDENTITY,
    AwsEvidence.S3_BUCKETS: EvidenceCategory.STORAGE,
    AwsEvidence.S3_PUBLIC_ACCESS_BLOCK: EvidenceCategory.STORAGE,
    AwsEvidence.S3_ENCRYPTION: EvidenceCategory.STORAGE,
    AwsEvidence.S3_BUCKET_POLICY_STATUS: EvidenceCategory.STORAGE,
    AwsEvidence.EBS_ENCRYPTION_DEFAULT: EvidenceCategory.COMPUTE,
    AwsEvidence.SECURITY_GROUPS: EvidenceCategory.NETWORK,
    AwsEvidence.VPCS: EvidenceCategory.NETWORK,
    AwsEvidence.SUBNETS: EvidenceCategory.NETWORK,
    AwsEvidence.NETWORK_INTERFACES: EvidenceCategory.NETWORK,
    AwsEvidence.ELASTIC_IPS: EvidenceCategory.NETWORK,
    AwsEvidence.EC2_INSTANCES: EvidenceCategory.COMPUTE,
    AwsEvidence.RDS_INSTANCES: EvidenceCategory.DATABASE,
    AwsEvidence.KMS_KEYS: EvidenceCategory.SECRETS,
    AwsEvidence.CLOUDTRAIL_TRAILS: EvidenceCategory.LOGGING,
    AwsEvidence.CONFIG_RECORDERS: EvidenceCategory.LOGGING,
    AwsEvidence.GUARDDUTY_DETECTORS: EvidenceCategory.POSTURE,
}

# Enumerated rather than compared at call time: a key added without a category
# would otherwise fail as a KeyError inside a running scan, on the one path
# whose job is to be reliable when everything else is not.
_missing = set(AwsEvidence) - set(_CATEGORIES)
if _missing:  # pragma: no cover - import-time guard
    raise RuntimeError(
        "AwsEvidence members with no category: " + ", ".join(sorted(_missing))
    )


_REGIONAL: frozenset[AwsEvidence] = frozenset(
    {
        AwsEvidence.EBS_ENCRYPTION_DEFAULT,
        AwsEvidence.SECURITY_GROUPS,
        AwsEvidence.VPCS,
        AwsEvidence.SUBNETS,
        AwsEvidence.NETWORK_INTERFACES,
        AwsEvidence.ELASTIC_IPS,
        AwsEvidence.EC2_INSTANCES,
        AwsEvidence.RDS_INSTANCES,
        AwsEvidence.KMS_KEYS,
        AwsEvidence.CLOUDTRAIL_TRAILS,
        AwsEvidence.CONFIG_RECORDERS,
        AwsEvidence.GUARDDUTY_DETECTORS,
    }
)


# Evidence CloudGuard collects because the product needs it, not because a rule
# judges it. Every other key is named by some rule's ``requires_evidence``;
# these are named by none, and would be dropped the moment a plan is derived
# from the rule set rather than written out by hand.
#
# The region list is the load-bearing one: every regional task depends on it, so
# without it a plan derived from the rules would collect nothing regional at
# all. The rest are the asset inventory and the graph's identity edges -- the
# things the *product* is built from rather than judged from.
BASELINE_EVIDENCE: frozenset[AwsEvidence] = frozenset(
    {
        AwsEvidence.ENABLED_REGIONS,
        AwsEvidence.ORGANIZATION_ACCOUNTS,
        AwsEvidence.VPCS,
        AwsEvidence.SUBNETS,
        AwsEvidence.NETWORK_INTERFACES,
        AwsEvidence.ELASTIC_IPS,
        AwsEvidence.IAM_ROLES,
        AwsEvidence.IAM_POLICIES,
    }
)


def keys_in(category: EvidenceCategory) -> frozenset[AwsEvidence]:
    """Every key that belongs to one category.

    Used where a category-level fact has to be applied to the keys underneath
    it -- a grant that covers no storage action costs every storage key, and the
    rules that lose a verdict do so one key at a time.
    """
    return frozenset(key for key, value in _CATEGORIES.items() if value is category)
