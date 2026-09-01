"""Remediation as data.

The prose stays where it is -- ``SecurityRule.remediation`` is what somebody
reads at two in the morning, and it is snapshot-copied onto every finding so
old findings keep the guidance they were raised with. What lives here is the
half a machine can act on: what must become true, and the artifacts generated
from that one statement.
"""

from app.remediation.spec import (
    Comparison,
    ExpectedState,
    RemediationSpec,
    azure_policy,
    terraform_hints,
)

__all__ = [
    "Comparison",
    "ExpectedState",
    "RemediationSpec",
    "azure_policy",
    "terraform_hints",
]
