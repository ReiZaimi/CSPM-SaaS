"""Defences that lower a finding's score without resolving it.

Three properties carry the whole feature, and each is the product refusing a
temptation the category is full of:

* a control never turns FAIL into PASS,
* only prevention counts -- detection changes who finds out, not what an
  attacker must have,
* a control CloudGuard could not fully read is absent, and lowers nothing.
"""

from typing import ClassVar

from app.connectors.azure.normalizer import AzureNormalizer
from app.core.enums import Level, Provider, ResourceType, RuleState, Severity
from app.domain.resource import CloudResource
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.controls import Control
from tests.conftest import make_context

GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def admin(user_id: str = "u1") -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=f"/users/{user_id}",
        resource_type=ResourceType.USER,
        name="Ada Admin",
        criticality=Level.CRITICAL,
        data_sensitivity=Level.HIGH,
        public_exposure=Level.HIGH,
        metadata={
            "user_principal_name": "ada@contoso.com",
            "account_enabled": True,
            "directory_roles": ["Global Administrator"],
            "mfa_methods": ["password"],
        },
    )


def policy(**overrides: object) -> dict:
    base: dict = {
        "id": "p1",
        "displayName": "Require MFA for admins",
        "state": "enabled",
        "conditions": {
            "applications": {"includeApplications": ["All"]},
            "users": {"includeRoles": [GLOBAL_ADMIN_TEMPLATE]},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }
    base.update(overrides)
    return base


def normalized(**payload: object) -> dict:
    """Controls as the normalizer produces them from a directory capture."""
    data: dict = {
        "directory_roles": [
            {
                "id": "role-object-id",
                "displayName": "Global Administrator",
                "roleTemplateId": GLOBAL_ADMIN_TEMPLATE,
            }
        ]
    }
    data.update(payload)
    return AzureNormalizer()._normalize_controls(data)


# ------------------------------------------------------------ the arithmetic
class _Rule(SecurityRule):
    rule_id = "TEST-002"
    name = "Test"
    description = ""
    category = "test"
    severity = Severity.HIGH
    exploitability = 5
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult:
        return RuleResult.failed()


def control(value: int, name: str = "A control") -> Control:
    return Control(id=f"test.{value}", name=name, detail="", exploitability=value)


def test_a_control_lowers_the_score() -> None:
    rule = _Rule()
    assert rule.effective_exploitability(RuleResult.failed(controls=(control(3),))) == 3


def test_several_controls_compose_to_the_strongest() -> None:
    """No control has to know the others exist."""
    rule = _Rule()
    result = RuleResult.failed(controls=(control(4), control(2), control(3)))

    assert rule.effective_exploitability(result) == 2


def test_a_control_can_never_raise_a_finding() -> None:
    """A defence that made a problem worse would be a contradiction in terms."""
    rule = _Rule()
    assert rule.effective_exploitability(RuleResult.failed(controls=(control(9),))) == 5


def test_a_control_composes_with_an_instance_step_down() -> None:
    rule = _Rule()
    result = RuleResult.failed(exploitability=4, controls=(control(2),))

    assert rule.effective_exploitability(result) == 2


# ------------------------------------------------------- what counts as one
class TestWhatTheNormalizerAccepts:
    def test_security_defaults_are_read_as_a_control(self) -> None:
        assert normalized(security_defaults={"isEnabled": True}) == {
            "security_defaults_enabled": True
        }

    def test_security_defaults_that_were_never_read_are_absent(self) -> None:
        """Not False. "We could not look" and "it is off" are different, and
        only one of them is a claim."""
        assert "security_defaults_enabled" not in normalized()

    def test_an_enforced_policy_requiring_mfa_is_kept(self) -> None:
        controls = normalized(conditional_access_policies=[policy()])

        assert controls["mfa_policies"][0]["role_names"] == ["Global Administrator"]

    def test_a_report_only_policy_grants_nothing(self) -> None:
        """It logs what would have happened. Nobody is challenged."""
        controls = normalized(
            conditional_access_policies=[
                policy(state="enabledForReportingButNotEnforced")
            ]
        )

        assert controls["mfa_policies"] == []

    def test_mfa_or_something_else_is_not_multi_factor(self) -> None:
        """"MFA or a compliant device" lets a stolen password through on a
        machine the attacker enrolled."""
        controls = normalized(
            conditional_access_policies=[
                policy(
                    grantControls={
                        "operator": "OR",
                        "builtInControls": ["mfa", "compliantDevice"],
                    }
                )
            ]
        )

        assert controls["mfa_policies"] == []

    def test_mfa_and_something_else_still_requires_mfa(self) -> None:
        controls = normalized(
            conditional_access_policies=[
                policy(
                    grantControls={
                        "operator": "AND",
                        "builtInControls": ["mfa", "compliantDevice"],
                    }
                )
            ]
        )

        assert len(controls["mfa_policies"]) == 1

    def test_a_policy_scoped_to_some_applications_makes_no_claim(self) -> None:
        """CloudGuard cannot tell which application an attacker would use."""
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["797f4846-ba00"]},
                        "users": {"includeRoles": [GLOBAL_ADMIN_TEMPLATE]},
                    }
                )
            ]
        )

        assert controls["mfa_policies"] == []

    def test_an_unread_exclusion_group_discards_the_policy(self) -> None:
        """The group that could not be read might be the one holding the
        account being judged. Every real tenant excludes a break-glass group,
        so this is the case that decides whether the feature is honest."""
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {
                            "includeRoles": [GLOBAL_ADMIN_TEMPLATE],
                            "excludeGroups": ["g-breakglass"],
                        },
                    }
                )
            ],
            group_members={},
        )

        assert controls["mfa_policies"] == []

    def test_a_read_exclusion_group_expands_to_its_members(self) -> None:
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {
                            "includeRoles": [GLOBAL_ADMIN_TEMPLATE],
                            "excludeGroups": ["g-breakglass"],
                        },
                    }
                )
            ],
            group_members={"g-breakglass": ["u9"]},
        )

        assert controls["mfa_policies"][0]["excluded_user_ids"] == ["u9"]

    def test_a_role_id_this_tenant_never_named_is_dropped(self) -> None:
        """Template ids are resolved from the tenant's own directory rather than
        from a table of GUIDs written from memory -- the discipline rbac.py
        applies to ARM action strings."""
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {"includeRoles": ["00000000-0000-0000-0000-000000000000"]},
                    }
                )
            ]
        )

        assert controls["mfa_policies"][0]["role_names"] == []


# ------------------------------------------------------------- AZ-ID-001
class TestMfaRuleWithControls:
    rule = AzureMfaRule()

    def test_it_is_still_a_finding(self) -> None:
        """The account has no second factor registered. A policy demanding one
        locks it out of its own tenant at the next challenge, which is a real
        operational problem rather than a fixed one."""
        user = admin()
        result = self.rule.evaluate(
            user, make_context(user, controls={"security_defaults_enabled": True})
        )

        assert result.state == RuleState.FAIL

    def test_security_defaults_lower_what_it_is_scored_at(self) -> None:
        user = admin()
        result = self.rule.evaluate(
            user, make_context(user, controls={"security_defaults_enabled": True})
        )

        assert self.rule.effective_exploitability(result) == 3
        assert self.rule.effective_exploitability(result) < self.rule.exploitability
        assert "Security defaults" in result.message

    def test_no_control_leaves_the_rule_tag(self) -> None:
        user = admin()
        result = self.rule.evaluate(user, make_context(user))

        assert result.controls == ()
        assert self.rule.effective_exploitability(result) == self.rule.exploitability

    def test_a_policy_covering_this_role_applies(self) -> None:
        user = admin()
        controls = normalized(conditional_access_policies=[policy()])
        result = self.rule.evaluate(user, make_context(user, controls=controls))

        assert self.rule.effective_exploitability(result) == 3
        assert result.controls[0].id == "entra.conditional_access.p1"

    def test_a_policy_excluding_this_account_does_not(self) -> None:
        user = admin("u9")
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {
                            "includeRoles": [GLOBAL_ADMIN_TEMPLATE],
                            "excludeGroups": ["g-breakglass"],
                        },
                    }
                )
            ],
            group_members={"g-breakglass": ["u9"]},
        )
        result = self.rule.evaluate(user, make_context(user, controls=controls))

        assert result.controls == ()
        assert self.rule.effective_exploitability(result) == self.rule.exploitability

    def test_a_policy_covering_a_role_this_account_does_not_hold(self) -> None:
        user = admin()
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {"includeRoles": ["some-other-template"]},
                    }
                )
            ]
        )
        result = self.rule.evaluate(user, make_context(user, controls=controls))

        assert result.controls == ()

    def test_all_users_covers_everyone(self) -> None:
        user = admin()
        controls = normalized(
            conditional_access_policies=[
                policy(
                    conditions={
                        "applications": {"includeApplications": ["All"]},
                        "users": {"includeUsers": ["All"]},
                    }
                )
            ]
        )
        result = self.rule.evaluate(user, make_context(user, controls=controls))

        assert self.rule.effective_exploitability(result) == 3
