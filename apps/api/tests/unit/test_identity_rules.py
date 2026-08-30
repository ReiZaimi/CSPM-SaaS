"""AZ-ID-001 / AZ-ID-002."""

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import RuleState
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.azure.identity.privileged import AzurePrivilegedUserRule
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
