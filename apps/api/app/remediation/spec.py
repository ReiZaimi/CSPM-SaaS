"""Remediation as data: what must become true, and the artifacts that make it so.

A rule's remediation was a paragraph of prose. Good prose -- portal clicks and a
CLI command -- and unusable by anything except a person reading it. Three things
were therefore impossible.

**Saying what "fixed" means.** A verification records that a customer claims a
fix and waits for the rule to pass, which is the right test and a poor
explanation: the customer is told CloudGuard will check, not what it will check
for. An expected state says it in the terms of the setting itself.

**Preventing the next one.** The fix closes today's finding. A policy that
refuses the misconfiguration closes the whole class of it, and the policy is
derivable from the same statement of what must be true -- the ``rbac.py``
pattern applied a second time: one declaration, several generated artifacts,
tests holding them to each other.

**Being honest about what cannot be automated.** Not every check has an ARM
policy behind it. Whether an administrator has MFA is a directory setting, not a
resource property, and no ``policyRule`` can express it. A generator that
invented one would produce a deployment that fails atomically -- the exact
failure mode ``rbac.py`` records for a permission string nobody verified. So a
policy is declared where one genuinely exists and omitted where it does not, and
the API says which.

The strings that reach Azure -- policy aliases -- carry the same rule as the
RBAC actions do: verified before they are written down, because an alias that
looks plausible and is not real fails the customer's deployment rather than
producing a warning.
"""

from dataclasses import dataclass
from typing import Any, Final

# Distinguishes "Terraform spells this the same way" from "Terraform spells it
# ``false``". ``None`` cannot serve, because a Terraform argument genuinely set
# to null is a thing somebody might mean.
UNSET: Final = object()


@dataclass(frozen=True)
class ExpectedState:
    """One thing that must be true for this finding to be fixed.

    Three names for one setting, because the setting genuinely has three: the
    field the normalizer produced and the rule reads, the ARM alias a policy
    matches on, and the Terraform argument that sets it. Writing them together
    is what lets one declaration generate the artifacts and lets a test prove
    the rule agrees with its own remediation.
    """

    # The key on the normalized asset, exactly as the rule reads it with
    # ``resource.get(...)``. This is the half a test can check against the rule.
    field: str
    # What it has to be: the value the CLI sets, Terraform writes and the
    # customer is told to configure.
    equals: Any
    # The sentence a customer reads. Written in the provider's own vocabulary,
    # because that is what they will be looking at in the portal.
    describes: str
    # Other values the rule also accepts. TLS 1.3 satisfies a rule asking for
    # 1.2, and a policy pinned to equality would refuse an account configured
    # *better* than asked -- a change-control incident rather than a bug
    # report. A floor is expressed here rather than discovered after
    # deployment.
    also_accepts: tuple[Any, ...] = ()
    # The alias an Azure Policy condition matches on. ``None`` where no alias
    # exists, which is not a gap to fill in later with a guess: an alias that is
    # not real fails the customer's policy deployment outright.
    arm_alias: str | None = None
    # The argument on the corresponding Terraform resource. A hint for whoever
    # manages this in code -- deliberately an attribute rather than a whole
    # resource block, because a generated block missing the arguments Terraform
    # requires would not apply, and one that guessed at them would apply
    # something nobody asked for.
    terraform_attribute: str | None = None
    # What Terraform calls the value, where that differs from what ARM calls it.
    # It often does: ARM says ``publicNetworkAccess: "Disabled"`` and the
    # provider says ``public_network_access_enabled = false``. Emitting the ARM
    # spelling into HCL would produce a line that does not mean what it says.
    terraform_value: Any = UNSET


@dataclass(frozen=True)
class RemediationSpec:
    """The machine-readable half of a rule's remediation.

    Sits beside ``SecurityRule.remediation`` rather than replacing it. The prose
    is what somebody reads at two in the morning and it is snapshot-copied onto
    every finding so old findings keep the guidance they were raised with; this
    is what the product can act on.
    """

    # What must be true afterwards. The order is the order a customer would
    # change them in.
    expected: tuple[ExpectedState, ...]
    # Commands that make it so, with placeholders left as ``<angle brackets>``
    # -- a command carrying a made-up resource name is a command somebody runs.
    cli: tuple[str, ...] = ()
    # The Azure Policy resource type this would be enforced on. Present only
    # where every expected state carries an alias; a policy that enforced half
    # a rule would report compliance the rule does not.
    policy_resource_type: str | None = None
    # Deny rather than Audit where the setting can be refused outright at
    # creation. Audit where refusing it would break a deployment that has other
    # legitimate reasons to set it.
    policy_effect: str = "Deny"
    notes: str = ""

    @property
    def enforceable(self) -> bool:
        """Whether a preventive policy can be generated at all.

        Requires an alias for *every* expected state, not any of them. A policy
        covering one of two conditions would pass an asset that still fails the
        rule, and a customer who deployed it would believe the class was closed.
        """
        return bool(
            self.policy_resource_type
            and self.expected
            and all(state.arm_alias for state in self.expected)
        )


def azure_policy(rule_id: str, name: str, spec: RemediationSpec) -> dict[str, Any] | None:
    """An Azure Policy definition that refuses the misconfiguration.

    Generated from the expected states rather than written per rule, so a rule
    whose expected state changes cannot keep a policy that enforces the old one.

    Returns ``None`` where the rule is not enforceable by policy. That is the
    honest answer for a directory setting or a diagnostic configuration, and it
    is better than a definition that deploys and checks nothing.

    The condition is the *negation* of the expected state -- policy matches what
    it refuses -- which is why this is generated rather than declared: getting
    the polarity backwards by hand produces a policy that denies every compliant
    resource, and that is a change control incident rather than a bug report.
    """
    if not spec.enforceable:
        return None

    conditions = [_condition(state) for state in spec.expected]
    match: dict[str, Any] = {
        "allOf": [
            {"field": "type", "equals": spec.policy_resource_type},
            # Any one expected state unmet is a resource this policy refuses.
            {"anyOf": conditions} if len(conditions) > 1 else conditions[0],
        ]
    }
    return {
        "properties": {
            "displayName": f"CloudGuard {rule_id}: {name}",
            "policyType": "Custom",
            "mode": "Indexed",
            "description": (
                f"Generated from CloudGuard rule {rule_id}. Refuses resources that "
                "would raise this finding."
            ),
            "metadata": {"category": "Security", "cloudguard_rule": rule_id},
            "parameters": {},
            "policyRule": {"if": match, "then": {"effect": spec.policy_effect}},
        }
    }


def _condition(state: ExpectedState) -> dict[str, Any]:
    """The policy condition that matches a resource this rule would fail.

    Negated, because a policy matches what it refuses. Getting that polarity
    backwards by hand produces a definition that denies every compliant
    resource, which is why it is generated in one place rather than written per
    rule.
    """
    accepted = [state.equals, *state.also_accepts]
    if len(accepted) == 1:
        return {"field": state.arm_alias, "notEquals": _policy_value(state.equals)}
    return {"field": state.arm_alias, "notIn": [_policy_value(v) for v in accepted]}


def terraform_hints(spec: RemediationSpec) -> list[dict[str, str]]:
    """The arguments to set, for a customer who manages this in code.

    Attributes rather than a resource block, deliberately. A generated block
    would be missing every argument Terraform requires and could not be applied;
    one that filled them in would be proposing infrastructure nobody asked for.
    What a customer with existing HCL needs is the line to change.
    """
    return [
        {
            "attribute": state.terraform_attribute,
            "value": _hcl_value(
                state.equals
                if state.terraform_value is UNSET
                else state.terraform_value
            ),
            "describes": state.describes,
        }
        for state in spec.expected
        if state.terraform_attribute
    ]


def _policy_value(value: Any) -> Any:
    """Policy conditions compare against strings, including for booleans."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _hcl_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)

