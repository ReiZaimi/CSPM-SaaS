"""Whether a database encrypts what it stores.

One rule, and it exists against the reasoning recorded in ``RULE_ENGINE.md``:
transparent data encryption has been on by default for Azure SQL since 2017, so
this check passes for very nearly every customer and costs a permission and a
per-database fan-out to say so. That trade was declined once and is being made
deliberately now -- a control an auditor asks about by name is worth evidence
even when the evidence is usually a pass, and the compliance view is where that
difference shows up.

What it must not do is claim a pass it did not earn. A database whose encryption
state could not be read is UNKNOWN, and a server whose database listing failed
takes no verdict at all: the permissions behind both arrive in role v6, so on
any connection that has not redeployed this is precisely what a customer sees.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureDatabaseEncryptionRule(SecurityRule):
    rule_id = "AZ-DB-006"
    name = "Database is not encrypted at rest"
    description = (
        "A database on this SQL server has transparent data encryption turned off, so its "
        "files, its backups and its transaction log are stored unencrypted. Anyone who "
        "obtains a copy -- a restored backup, an exported file, storage reached by another "
        "route -- reads the data without needing the database or a credential for it."
    )
    category = "database"
    severity = Severity.HIGH
    # Two rather than higher: getting at the files is a step of its own, and an
    # attacker who already has them has usually reached further than this. What
    # this changes is whether that step ends in readable data.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.SQL_TDE,)
    estimated_effort_minutes = 30
    rationale = (
        "Encryption at rest is the control that survives the loss of the storage rather "
        "than the loss of the database. It is also the one every regulator and framework "
        "asks about by name, which is why an unencrypted database is expensive out of "
        "proportion to how often it is exploited."
    )
    remediation = (
        "Turn transparent data encryption on for the database.\n\n"
        "Azure Portal: SQL database > Security > Data Encryption > Transparent data "
        "encryption: On.\n\n"
        "Azure CLI:\n"
        "  az sql db tde set --resource-group <rg> --server <server> \\\n"
        "    --database <database> --status Enabled\n\n"
        "It is on by default for databases created since 2017, so a database without it "
        "was either created earlier or had it turned off deliberately -- worth asking which "
        "before turning it back on, in case something depends on the answer. Encryption is "
        "transparent to applications: no connection string or query changes."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="databases",
                comparison=Comparison.NONE_MATCHING,
                equals=None,
                describes="No database on this server has encryption at rest disabled",
                example={"database": "<name>", "state": "Disabled"},
            ),
        ),
        cli=(
            "az sql db tde set --resource-group <rg> --server <server> "
            "--database <database> --status Enabled",
        ),
        policy_resource_type="Microsoft.Sql/servers/databases/transparentDataEncryption",
        # Audit rather than Deny: encryption is a child resource created with
        # the database, and denying its creation is how a deployment fails
        # rather than how a database ends up encrypted.
        policy_effect="Audit",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.1.1", "4.1.2"],
        "ISO_27001": ["A.8.24", "A.5.10"],
        "NIST_CSF": ["PR.DS-1"],
        "GDPR": ["32(1)(a)", "5(1)(f)"],
        "NIST_800_53": ["SC-28", "SC-12"],
        "SOC2": ["CC6.1", "CC6.7"],
        "PCI_DSS_4": ["3.5.1", "3.6.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Encryption state unavailable: {failure}")

        databases = resource.get("databases")
        if databases is None:
            # The server was listed and its databases were not. A role
            # predating v6 produces exactly this, and reading it as "no
            # databases, therefore nothing unencrypted" would be a pass built
            # on a call that was refused.
            return RuleResult.unknown(
                "This server's databases could not be listed, so their "
                "encryption state is not known"
            )

        if not databases:
            return RuleResult.passed({"database_count": 0})

        unencrypted: list[dict[str, Any]] = []
        unreadable: list[str] = []
        for database in databases:
            state = database.get("state")
            name = str(database.get("database") or "unnamed")
            if state is None:
                unreadable.append(name)
                continue
            if str(state).lower() != "enabled":
                unencrypted.append({"database": name, "state": state})

        if unencrypted:
            return RuleResult.failed(
                evidence={
                    "database_count": len(databases),
                    "unencrypted": unencrypted,
                    # Carried on the failure too: a server with one unencrypted
                    # database and three unreadable ones is worse than the
                    # finding alone says, and hiding that behind the failure
                    # would be the same overclaim pointed the other way.
                    "unreadable": unreadable,
                },
                message=(
                    f"{len(unencrypted)} database(s) on {resource.name} store their "
                    "data unencrypted: "
                    + ", ".join(sorted(str(d["database"]) for d in unencrypted))
                ),
            )

        if unreadable:
            return RuleResult.unknown(
                f"The encryption state of {len(unreadable)} database(s) on "
                f"{resource.name} could not be read"
            )

        return RuleResult.passed(
            {"database_count": len(databases), "all_encrypted": True}
        )
