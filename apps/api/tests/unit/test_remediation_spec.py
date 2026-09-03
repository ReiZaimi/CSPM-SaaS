"""Remediation as data, and the rule agreeing with its own remediation.

This is the `rbac.py` pattern applied a second time: one declaration, several
generated artifacts, and tests holding them to each other in both directions.
There it was permissions -- every collector call has an action and every action
has a call. Here it is settings: every expected state is a field the rule
actually reads, and satisfying the declaration actually makes the rule pass.

Without the second half the declaration is documentation, and documentation
drifts. A rule whose check moved on while its remediation stayed put tells a
customer to change something that no longer closes the finding, which is worse
than telling them nothing: they do the work and the finding stays open.
"""

import pytest

from app.core.enums import Level, RuleState
from app.domain.resource import CloudResource
from app.remediation import (
    Comparison,
    RemediationSpec,
    azure_policy,
    terraform_hints,
)
from app.remediation.spec import ExpectedState
from app.rules.base import RuleContext
from app.rules.registry import RULE_REGISTRY

DECLARED = [rule for rule in RULE_REGISTRY if rule.remediation_spec is not None]
# Rules whose expectation can be turned into an asset, which is what makes the
# agreement checkable. The rest are not a loophole -- see the test below.
CHECKABLE = [rule for rule in DECLARED if rule.remediation_spec.expected]
UNCHECKABLE = [rule for rule in DECLARED if not rule.remediation_spec.expected]


def resource_meeting(rule, satisfied: bool) -> CloudResource:
    """An asset built from the rule's own declaration.

    Every expected state set to what it asks for, or -- when ``satisfied`` is
    false -- to something it plainly is not. Built from the declaration rather
    than by hand, which is the whole point: a rule whose check drifts away from
    its remediation fails here rather than in a customer's inbox.

    The collection comparisons are why a declaration carries a witness. "No
    inbound rule allows 3389 from anywhere" cannot be turned into an asset the
    rule should fail unless the declaration says what such a rule looks like,
    and a declaration that says so is one a customer can read too.
    """
    # ``applies_when`` may name a classification the asset carries as a field
    # rather than as metadata. AZ-DB-002 expects private connectivity *of a
    # database holding sensitive data*, and sensitivity is what the normalizer
    # computed about the asset, not a key inside it -- so a builder that could
    # only write metadata would hand every such rule an asset it declines to
    # judge, and the agreement below would pass by never being tested.
    classification = {"criticality": Level.MEDIUM, "data_sensitivity": Level.MEDIUM}
    metadata = {}
    for key, value in rule.remediation_spec.applies_when.items():
        if key in classification:
            classification[key] = value
        else:
            metadata[key] = value

    for state in rule.remediation_spec.expected:
        metadata[state.field] = _value_for(state, satisfied)
    return CloudResource(
        provider_resource_id="/x/asset",
        resource_type=rule.applies_to[0],
        name="asset",
        metadata=metadata,
        **classification,
    )


def _value_for(state, satisfied: bool):
    if state.comparison is Comparison.NONE_MATCHING:
        assert state.example, "a NONE_MATCHING state needs the shape it forbids"
        return [] if satisfied else [state.example]
    if state.comparison is Comparison.NOT_EMPTY:
        assert state.example, "a NOT_EMPTY state needs an entry that satisfies it"
        return [state.example] if satisfied else []
    return state.equals if satisfied else _violation(state.equals)


def _violation(value: object) -> object:
    if isinstance(value, bool):
        return not value
    if value == "Deny":
        return "Allow"
    if value == "Disabled":
        return "Enabled"
    if value == "TLS1_2":
        return "TLS1_0"
    raise AssertionError(f"no violation defined for {value!r}")


def evaluate(rule, resource: CloudResource) -> RuleState:
    context = RuleContext(resources=[resource])
    result = rule.evaluate(resource, context)
    results = result if isinstance(result, list) else [result]
    return results[0].state


# ------------------------------------------- the rule and its remediation agree
@pytest.mark.parametrize("rule", CHECKABLE, ids=lambda r: r.rule_id)
def test_meeting_the_expected_state_makes_the_rule_pass(rule) -> None:
    """The claim a remediation makes, checked against the check itself.

    If this fails, the rule is asking for something its remediation does not
    describe -- and a customer who does exactly what they were told would be
    told they had not fixed it.
    """
    assert evaluate(rule, resource_meeting(rule, satisfied=True)) is RuleState.PASS


@pytest.mark.parametrize("rule", CHECKABLE, ids=lambda r: r.rule_id)
def test_violating_the_expected_state_makes_the_rule_fail(rule) -> None:
    """The other direction. A declaration nothing can violate would pass the
    test above while describing nothing the rule cares about."""
    assert evaluate(rule, resource_meeting(rule, satisfied=False)) is RuleState.FAIL


@pytest.mark.parametrize("rule", DECLARED, ids=lambda r: r.rule_id)
def test_a_declared_rule_says_something_in_words_too(rule) -> None:
    """The prose is not replaced by the data. It is what somebody reads at two
    in the morning, and it is what a finding snapshot-copies."""
    assert rule.remediation
    assert all(state.describes for state in rule.remediation_spec.expected)


@pytest.mark.parametrize("rule", UNCHECKABLE, ids=lambda r: r.rule_id)
def test_an_expectation_nobody_can_state_has_to_say_why(rule) -> None:
    """The one thing that stops "no expected state" becoming a way out.

    Two rules genuinely have none: one judges a ratio across the whole
    directory, and one is about a relationship between a machine and the
    security groups that govern it. Neither is a setting on an asset. But an
    empty declaration is also exactly what a rule looks like when somebody could
    not be bothered, and those must not be indistinguishable -- so an empty one
    owes a reason and something a customer can still do.
    """
    spec = rule.remediation_spec
    assert spec.notes, "an empty expectation must explain itself"
    assert spec.cli, "and still say what to run"
    assert spec.enforceable is False


def test_every_rule_now_carries_a_declaration() -> None:
    """Both directions of the same discipline as ``rbac.py``: no rule ships
    without a machine-readable remediation, and none carries one that says
    nothing without saying why."""
    undeclared = [
        rule.rule_id for rule in RULE_REGISTRY if rule.remediation_spec is None
    ]
    assert not undeclared, f"rules with no remediation declaration: {undeclared}"


# ------------------------------------------------------------ generated policy
def test_a_policy_matches_what_it_refuses_rather_than_what_it_wants() -> None:
    """Polarity is why this is generated rather than written per rule: inverted
    by hand, a policy denies every compliant resource, which is a change-control
    incident rather than a bug report."""
    spec = RemediationSpec(
        expected=(
            ExpectedState(
                field="allow_blob_public_access",
                equals=False,
                describes="Anonymous access is off",
                arm_alias="Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
            ),
        ),
        policy_resource_type="Microsoft.Storage/storageAccounts",
    )
    policy = azure_policy("AZ-TEST-001", "Test", spec)

    assert policy is not None
    condition = policy["properties"]["policyRule"]["if"]["allOf"][1]
    assert condition["notEquals"] == "false"
    assert policy["properties"]["policyRule"]["then"]["effect"] == "Deny"


def test_a_floor_is_expressed_as_a_set_rather_than_an_equality() -> None:
    """TLS 1.3 satisfies a rule asking for 1.2. A policy pinned to equality
    would refuse an account configured better than asked."""
    spec = RemediationSpec(
        expected=(
            ExpectedState(
                field="min_tls_version",
                equals="TLS1_2",
                describes="TLS 1.2 or higher",
                also_accepts=("TLS1_3",),
                arm_alias="Microsoft.Storage/storageAccounts/minimumTlsVersion",
            ),
        ),
        policy_resource_type="Microsoft.Storage/storageAccounts",
    )
    condition = azure_policy("AZ-TEST-002", "Test", spec)["properties"]["policyRule"][
        "if"
    ]["allOf"][1]

    assert condition["notIn"] == ["TLS1_2", "TLS1_3"]


def test_several_expected_states_are_refused_if_any_one_is_unmet() -> None:
    """``anyOf``, not ``allOf``. A resource has to satisfy every expected state
    to be compliant, so failing any single one is what the policy refuses."""
    spec = RemediationSpec(
        expected=(
            ExpectedState("a", False, "A is off", arm_alias="Provider/type/a"),
            ExpectedState("b", "Deny", "B denies", arm_alias="Provider/type/b"),
        ),
        policy_resource_type="Provider/type",
    )
    built = azure_policy("AZ-TEST-003", "Test", spec)

    assert built is not None
    assert len(built["properties"]["policyRule"]["if"]["allOf"][1]["anyOf"]) == 2


def test_a_rule_no_policy_can_enforce_generates_none() -> None:
    """Whether an administrator has MFA is a directory setting, not a resource
    property. A definition invented for it would deploy and check nothing."""
    spec = RemediationSpec(
        expected=(ExpectedState("mfa_methods", True, "MFA is registered"),),
    )
    assert spec.enforceable is False
    assert azure_policy("AZ-ID-001", "MFA", spec) is None


def test_half_a_rule_is_not_enforceable() -> None:
    """A policy covering one of two conditions would pass an asset that still
    fails the rule, and the customer would believe the class was closed."""
    spec = RemediationSpec(
        expected=(
            ExpectedState("a", False, "A is off", arm_alias="Provider/type/a"),
            ExpectedState("b", "Deny", "B denies"),
        ),
        policy_resource_type="Provider/type",
    )
    assert spec.enforceable is False
    assert azure_policy("AZ-TEST-004", "Test", spec) is None


# --------------------------------------------------------- generated terraform
def test_terraform_takes_the_providers_own_spelling() -> None:
    """ARM disables; the provider un-enables. Emitting the ARM spelling into HCL
    produces a line that does not mean what it says."""
    spec = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="Public network access is disabled",
                terraform_attribute="public_network_access_enabled",
                terraform_value=False,
            ),
        )
    )
    assert terraform_hints(spec) == [
        {
            "attribute": "public_network_access_enabled",
            "value": "false",
            "describes": "Public network access is disabled",
        }
    ]


def test_a_state_with_no_terraform_argument_is_left_out() -> None:
    spec = RemediationSpec(expected=(ExpectedState("a", False, "A is off"),))
    assert terraform_hints(spec) == []
