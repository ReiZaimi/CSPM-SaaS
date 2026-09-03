"""The identity rules, from the tenant's own settings down to one account."""

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.identity.mfa import (
    AzureLegacyAuthenticationRule,
    AzureMfaRule,
    AzureTenantMfaEnforcementRule,
    AzureUserWithoutMfaRule,
)
from app.rules.azure.identity.privileged import (
    AzureDisabledPrivilegedUserRule,
    AzureGuestPrivilegedUserRule,
    AzurePrivilegedUserRule,
)
from tests.conftest import make_context, resource_from


class TestMfaRule:
    rule = AzureMfaRule()

    def test_privileged_user_without_mfa_fails(self) -> None:
        user = resource_from("vulnerable", "user_admin_no_mfa")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.FAIL
        assert result.evidence["mfa_registered"] is False
        assert "Global Administrator" in result.evidence["privileged_roles"]

    def test_privileged_user_with_mfa_passes(self) -> None:
        user = resource_from("secure", "user_admin_with_mfa")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.PASS

    def test_password_alone_is_not_mfa(self) -> None:
        """A registered 'password' method must not read as a second factor."""
        user = resource_from("vulnerable", "user_admin_no_mfa")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.FAIL

    def test_non_privileged_user_is_not_applicable(self) -> None:
        user = resource_from("secure", "user_standard")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.NOT_APPLICABLE

    def test_disabled_admin_is_not_applicable(self) -> None:
        user = resource_from("secure", "user_admin_disabled")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.NOT_APPLICABLE

    def test_unknown_when_auth_methods_unreadable(self) -> None:
        """Missing UserAuthenticationMethod.Read.All consent is a coverage gap,
        not a clean bill of health."""
        user = resource_from("unknown", "user_admin_mfa_unreadable")
        result = self.rule.evaluate(user, make_context(user))
        assert result.state == RuleState.UNKNOWN
        assert "UserAuthenticationMethod" in result.message

    def test_unknown_when_identity_collection_failed(self) -> None:
        user = resource_from("vulnerable", "user_admin_no_mfa")
        ctx = make_context(user, collection_errors={AzureEvidence.USERS: "Graph 403"})
        assert self.rule.evaluate(user, ctx).state == RuleState.UNKNOWN


class TestPrivilegedUserRule:
    rule = AzurePrivilegedUserRule()

    def _admins(self, count: int) -> list:
        base = resource_from("vulnerable", "user_admin_no_mfa")
        from dataclasses import replace

        return [
            replace(base, provider_resource_id=f"/users/admin-{i}", name=f"Admin {i}")
            for i in range(count)
        ]

    def _standard(self, count: int) -> list:
        base = resource_from("secure", "user_standard")
        from dataclasses import replace

        return [
            replace(base, provider_resource_id=f"/users/user-{i}", name=f"User {i}")
            for i in range(count)
        ]

    def test_excessive_privileged_users_fails(self) -> None:
        # 6 admins out of 20 accounts = 30%, over both thresholds.
        ctx = make_context(*self._admins(6), *self._standard(14))
        result = self.rule.evaluate(None, ctx)
        assert result.state == RuleState.FAIL
        assert result.evidence["privileged_user_count"] == 6

    def test_small_team_with_few_admins_passes(self) -> None:
        """Two admins in a two-person company is not a finding."""
        ctx = make_context(*self._admins(2), *self._standard(3))
        assert self.rule.evaluate(None, ctx).state == RuleState.PASS

    def test_large_org_under_ratio_passes(self) -> None:
        # 6 admins out of 100 = 6%, over the floor but well under the ratio.
        ctx = make_context(*self._admins(6), *self._standard(94))
        assert self.rule.evaluate(None, ctx).state == RuleState.PASS

    def test_disabled_admins_are_excluded(self) -> None:
        disabled = resource_from("secure", "user_admin_disabled")
        ctx = make_context(disabled, *self._standard(4))
        result = self.rule.evaluate(None, ctx)
        assert result.state == RuleState.PASS
        assert result.evidence["privileged_user_count"] == 0

    def test_unknown_when_no_users_collected(self) -> None:
        assert self.rule.evaluate(None, make_context()).state == RuleState.UNKNOWN

    def test_unknown_when_identity_collection_failed(self) -> None:
        ctx = make_context(
            *self._admins(6),
            collection_errors={AzureEvidence.USERS: "Graph timeout"},
        )
        assert self.rule.evaluate(None, ctx).state == RuleState.UNKNOWN


# ------------------------------------------------ the accounts nobody calls admin
def user(
    *,
    roles: list[str] | None = None,
    mfa: list[str] | None = None,
    enabled: bool | None = True,
    user_type: str | None = "Member",
    name: str = "Person",
) -> CloudResource:
    metadata: dict = {"user_principal_name": "person@contoso.onmicrosoft.com"}
    if roles is not None:
        metadata["directory_roles"] = roles
    if mfa is not None:
        metadata["mfa_methods"] = mfa
    if enabled is not None:
        metadata["account_enabled"] = enabled
    if user_type is not None:
        metadata["user_type"] = user_type
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/users/u1",
        resource_type=ResourceType.USER,
        name=name,
        metadata=metadata,
    )


class TestOrdinaryAccountsWithoutMfa:
    """AZ-ID-004. AZ-ID-001 asks this of administrators at Critical; every
    other account is one password away from being inside the directory, which
    is a smaller blast radius and the same front door."""

    rule = AzureUserWithoutMfaRule()

    def test_a_password_only_account_fails(self) -> None:
        person = user(roles=[], mfa=["password"])
        result = self.rule.evaluate(person, make_context(person))
        assert result.state == RuleState.FAIL
        assert result.evidence["mfa_registered"] is False

    def test_a_registered_second_factor_passes(self) -> None:
        person = user(roles=[], mfa=["microsoftAuthenticator"])
        assert (
            self.rule.evaluate(person, make_context(person)).state is RuleState.PASS
        )

    def test_an_administrator_belongs_to_the_critical_rule(self) -> None:
        """Not a pass: a scope statement. Reporting both would raise two
        findings for one missing second factor."""
        admin = user(roles=["Global Administrator"], mfa=[])
        assert (
            self.rule.evaluate(admin, make_context(admin)).state
            is RuleState.NOT_APPLICABLE
        )

    def test_a_disabled_account_is_not_judged(self) -> None:
        person = user(roles=[], mfa=[], enabled=False)
        assert (
            self.rule.evaluate(person, make_context(person)).state
            is RuleState.NOT_APPLICABLE
        )

    def test_unread_authentication_methods_are_unknown(self) -> None:
        """Reading them needs a Graph permission that may not be consented.
        That is a coverage gap, not a clean account."""
        person = user(roles=[], mfa=None)
        assert (
            self.rule.evaluate(person, make_context(person)).state is RuleState.UNKNOWN
        )

    def test_security_defaults_lower_the_score_without_clearing_the_finding(
        self,
    ) -> None:
        """A tenant-wide requirement means the password alone no longer signs
        in -- and the account still has nothing registered, so it is still a
        finding, scored lower."""
        person = user(roles=[], mfa=[])
        context = make_context(person, controls={"security_defaults_enabled": True})
        result = self.rule.evaluate(person, context)
        assert result.state == RuleState.FAIL
        assert result.controls


class TestWhetherAnythingEnforcesMfa:
    """AZ-ID-005. Per-account registration covers whoever opted in; the
    accounts that did not are the ones an attacker will find."""

    rule = AzureTenantMfaEnforcementRule()

    def test_security_defaults_are_enough(self) -> None:
        context = make_context(controls={"security_defaults_enabled": True})
        assert self.rule.evaluate(None, context).state is RuleState.PASS

    def test_a_policy_covering_every_account_is_enough(self) -> None:
        context = make_context(
            controls={
                "security_defaults_enabled": False,
                "mfa_policies": [{"name": "Require MFA", "all_users": True}],
            }
        )
        assert self.rule.evaluate(None, context).state is RuleState.PASS

    def test_policies_covering_only_some_accounts_fail(self) -> None:
        """The case that reads as covered on a screen and is not: three
        policies, each protecting one group, and everybody else signing in with
        a password."""
        context = make_context(
            controls={
                "security_defaults_enabled": False,
                "mfa_policies": [
                    {"name": "Admins", "all_users": False},
                    {"name": "Finance", "all_users": False},
                ],
            }
        )
        result = self.rule.evaluate(None, context)
        assert result.state == RuleState.FAIL
        assert result.evidence["policies_covering_some_users"] == ["Admins", "Finance"]

    def test_nothing_at_all_fails(self) -> None:
        context = make_context(
            controls={"security_defaults_enabled": False, "mfa_policies": []}
        )
        assert self.rule.evaluate(None, context).state is RuleState.FAIL

    def test_a_tenant_whose_policies_were_never_read_is_unknown(self) -> None:
        """Absent is not off. A tenant CloudGuard could not read is one it
        cannot speak for."""
        assert self.rule.evaluate(None, make_context()).state is RuleState.UNKNOWN


class TestLegacyAuthentication:
    """AZ-ID-006. The protocols that cannot present a second factor, and
    therefore bypass every policy demanding one."""

    rule = AzureLegacyAuthenticationRule()

    def test_an_unblocked_tenant_fails(self) -> None:
        context = make_context(
            controls={
                "security_defaults_enabled": False,
                "legacy_authentication_blocked": False,
            }
        )
        assert self.rule.evaluate(None, context).state is RuleState.FAIL

    def test_a_blocking_policy_passes(self) -> None:
        context = make_context(
            controls={
                "security_defaults_enabled": False,
                "legacy_authentication_blocked": True,
            }
        )
        result = self.rule.evaluate(None, context)
        assert result.state == RuleState.PASS
        assert result.evidence["via"] == "conditional_access"

    def test_security_defaults_block_it_as_part_of_the_same_switch(self) -> None:
        context = make_context(
            controls={
                "security_defaults_enabled": True,
                "legacy_authentication_blocked": False,
            }
        )
        result = self.rule.evaluate(None, context)
        assert result.state == RuleState.PASS
        assert result.evidence["via"] == "security_defaults"

    def test_a_tenant_whose_policies_were_never_read_is_unknown(self) -> None:
        assert self.rule.evaluate(None, make_context()).state is RuleState.UNKNOWN


class TestGuestsHoldingPrivilege:
    """AZ-ID-011. Privilege granted to an identity you do not control is
    privilege you cannot withdraw at the speed of an incident."""

    rule = AzureGuestPrivilegedUserRule()

    def test_a_privileged_guest_fails(self) -> None:
        guest = user(roles=["Global Administrator"], user_type="Guest")
        result = self.rule.evaluate(guest, make_context(guest))
        assert result.state == RuleState.FAIL
        assert result.evidence["user_type"] == "Guest"

    def test_a_privileged_member_passes(self) -> None:
        member = user(roles=["Global Administrator"], user_type="Member")
        assert (
            self.rule.evaluate(member, make_context(member)).state is RuleState.PASS
        )

    def test_an_ordinary_guest_is_out_of_scope(self) -> None:
        """Guests are how organizations work with each other. The finding is
        the privilege, not the guest."""
        guest = user(roles=[], user_type="Guest")
        assert (
            self.rule.evaluate(guest, make_context(guest)).state
            is RuleState.NOT_APPLICABLE
        )

    def test_an_unreported_user_type_is_unknown(self) -> None:
        """Guessing "Member" because most accounts are one would be a pass
        nobody earned."""
        unknown = user(roles=["Global Administrator"], user_type=None)
        assert (
            self.rule.evaluate(unknown, make_context(unknown)).state
            is RuleState.UNKNOWN
        )


class TestDisabledAccountsHoldingPrivilege:
    """AZ-ID-012. Disabling stops sign-in; it does not remove privilege, and
    re-enabling is one checkbox."""

    rule = AzureDisabledPrivilegedUserRule()

    def test_a_disabled_administrator_fails(self) -> None:
        leaver = user(roles=["Global Administrator"], enabled=False)
        result = self.rule.evaluate(leaver, make_context(leaver))
        assert result.state == RuleState.FAIL
        assert result.evidence["account_enabled"] is False

    def test_an_enabled_administrator_is_not_this_finding(self) -> None:
        """AZ-ID-001 and AZ-ID-002 judge those. This one is about offboarding
        that stopped halfway."""
        admin = user(roles=["Global Administrator"], enabled=True)
        assert self.rule.evaluate(admin, make_context(admin)).state is RuleState.PASS

    def test_a_disabled_ordinary_account_is_out_of_scope(self) -> None:
        leaver = user(roles=[], enabled=False)
        assert (
            self.rule.evaluate(leaver, make_context(leaver)).state
            is RuleState.NOT_APPLICABLE
        )

    def test_an_unreported_account_state_is_unknown(self) -> None:
        admin = user(roles=["Global Administrator"], enabled=None)
        assert (
            self.rule.evaluate(admin, make_context(admin)).state is RuleState.UNKNOWN
        )
