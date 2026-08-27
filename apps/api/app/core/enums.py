"""Cloud-neutral domain vocabulary.

These names are shared by the database, the rule engine, the risk engine and
the API. Nothing here is Azure-specific -- adding an AWS connector later must
not require touching this file (ARCHITECTURE.md section 6).
"""

from enum import StrEnum


class Provider(StrEnum):
    AZURE = "azure"
    AWS = "aws"  # extension point only -- no connector in v0.1
    GCP = "gcp"  # extension point only -- no connector in v0.1


class Role(StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    IT_ADMIN = "IT_ADMIN"
    VIEWER = "VIEWER"
    ADVISOR = "ADVISOR"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Level(StrEnum):
    """Scale shared by criticality, data sensitivity and internet exposure.

    UNKNOWN is a first-class value, not a missing one: the risk engine scores it
    cautiously rather than optimistically (RISK_ENGINE.md section 1).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class RuleState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RuleScope(StrEnum):
    PER_RESOURCE = "per_resource"
    AGGREGATE = "aggregate"


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    DISCOVERING = "DISCOVERING"
    NORMALIZING = "NORMALIZING"
    EVALUATING = "EVALUATING"
    CALCULATING_RISK = "CALCULATING_RISK"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in {
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.PARTIAL,
            ScanStatus.CANCELLED,
        }


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    @property
    def is_open(self) -> bool:
        """Statuses that still count against the org security score."""
        return self in {FindingStatus.OPEN, FindingStatus.IN_PROGRESS}


class RiskStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"


class RemediationStatus(StrEnum):
    TODO = "TODO"
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"
    CANCELLED = "CANCELLED"


class Priority(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConnectionScope(StrEnum):
    """How much of a customer's cloud one connection covers.

    The choice is a real trade between coverage and least privilege, and it is
    the customer's to make: TENANT_ROOT sees every subscription that exists now
    or later and needs a correspondingly broad grant, while SUBSCRIPTION is the
    narrowest thing that works. CloudGuard does not pick for them.
    """

    TENANT_ROOT = "TENANT_ROOT"
    MANAGEMENT_GROUP = "MANAGEMENT_GROUP"
    SUBSCRIPTION = "SUBSCRIPTION"


class PermissionMode(StrEnum):
    """Which RBAC role the customer grants.

    READER is Azure's built-in ``*/read`` -- one line to grant, and it never
    needs revisiting. CUSTOM_ROLE is the exact list of actions CloudGuard's
    collector performs, which is far narrower but has to be redeployed whenever
    a new rule reads a new resource type (app/connectors/azure/rbac.py).
    """

    READER = "READER"
    CUSTOM_ROLE = "CUSTOM_ROLE"


class ConsentStatus(StrEnum):
    PENDING = "PENDING"
    GRANTED = "GRANTED"
    REVOKED = "REVOKED"


class CloudAccountStatus(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class ExceptionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ResourceType(StrEnum):
    """Normalized, cloud-neutral resource types.

    The Azure normalizer maps ARM type strings onto these; an AWS normalizer
    would map its own. Rules declare ``applies_to`` in these terms so rule code
    never sees a provider-specific type string.
    """

    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    VIRTUAL_MACHINE = "virtual_machine"
    NETWORK_SECURITY_GROUP = "network_security_group"
    NETWORK_INTERFACE = "network_interface"
    PUBLIC_IP = "public_ip"
    VIRTUAL_NETWORK = "virtual_network"
    SUBNET = "subnet"
    STORAGE_ACCOUNT = "storage_account"
    SQL_SERVER = "sql_server"
    SQL_DATABASE = "sql_database"
    POSTGRESQL_SERVER = "postgresql_server"
    USER = "user"
    ROLE_ASSIGNMENT = "role_assignment"
    DIAGNOSTIC_SETTING = "diagnostic_setting"
    UNKNOWN = "unknown"


class RelationshipType(StrEnum):
    ATTACHED_TO = "attached_to"
    CONTAINS = "contains"
    PROTECTS = "protects"
    ASSIGNED_TO = "assigned_to"
