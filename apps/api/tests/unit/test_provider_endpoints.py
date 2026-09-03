"""Every declared endpoint is one the collector actually calls.

The declaration exists so a stored reading can say what it was a reading *of*,
months later, without anyone reading today's collector to find out. That is only
worth anything if the two cannot drift, and nothing about a wrong string here
would ever fail at runtime: a task carrying the wrong api-version collects
perfectly well and lies quietly in the evidence row.

The same reasoning ``rbac.py`` records about ARM actions, applied to the calls
rather than to the permissions. An action nothing calls has never been checked
against Azure by anything; an endpoint nothing calls is the same, and the
consequence is worse, because this one is shown to a customer as the answer to
"how do you know".
"""

import re
from pathlib import Path

import httpx

from app.connectors.azure import plan as plan_module
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.evidence import ProviderEndpoint

CLIENT = (Path(plan_module.__file__).parent / "client.py").read_text()

DECLARED: list[tuple[str, ProviderEndpoint]] = [
    (name, value)
    for name, value in vars(plan_module).items()
    if isinstance(value, ProviderEndpoint)
]


def test_there_are_endpoints_to_check() -> None:
    """A guard on the guard. If the declarations move, this file must not go on
    passing by finding nothing to look at."""
    assert len(DECLARED) >= 15


def test_every_declared_api_version_appears_in_the_client() -> None:
    """The half that matters.

    A response's shape is a function of its api-version, so a declaration that
    drifted would answer "which contract did you read this under" with a
    contract nobody used -- and the ambiguity this whole column exists to remove
    would come back, now wearing a precise-looking string.
    """
    for name, endpoint in DECLARED:
        if endpoint.api_version.startswith("v"):
            # Microsoft Graph versions in the path, so the client carries it in
            # its base URL rather than in a query parameter.
            assert endpoint.api_version in CLIENT, (
                f"{name} declares Graph {endpoint.api_version}, "
                "which the client does not use"
            )
            continue
        assert f"api-version={endpoint.api_version}" in CLIENT, (
            f"{name} declares api-version={endpoint.api_version}, "
            "which no call in client.py asks for"
        )


def test_every_declared_path_matches_a_call() -> None:
    """The path is a template, so it is checked by its distinctive tail.

    Compared on the last two segments rather than in full: the client builds a
    URL from an f-string with the subscription interpolated, and matching the
    whole thing would only prove that this test and that f-string were written
    by the same person on the same day.
    """
    for name, endpoint in DECLARED:
        tail = endpoint.path.rstrip("/").split("/")[-1]
        if tail.startswith("{"):
            # A template whose last segment is a placeholder -- there are none
            # today, and one appearing should be looked at rather than skipped
            # silently.
            raise AssertionError(f"{name} ends in a placeholder: {endpoint.path}")
        assert re.search(rf"/{re.escape(tail)}\b", CLIENT), (
            f"{name} declares a path ending /{tail}, which client.py never calls"
        )


# Client methods that are not part of any collection task, and so produce no
# evidence row to attach a contract to. Named rather than inferred, because
# "this call records no provenance" is a claim worth making explicitly:
#
#   list_subscriptions / list_resources  -- connection validation and
#     subscription discovery. Both run before a scan exists, prove the grant
#     works, and store nothing a rule ever reads.
#   list_role_assignments_at_scope       -- confirms a tenant-scoped grant above
#     any subscription, for the same reason.
#   get_organization / list_group_members / list_role_members /
#   list_authentication_methods / list_sql_firewall_rules
#     -- second calls inside a task whose own endpoint is declared, or
#     declared as a second endpoint on it.
OUTSIDE_COLLECTION = {
    "list_subscriptions",
    "list_resources",
    "list_role_assignments_at_scope",
    "get_organization",
}


def test_every_collecting_client_method_has_a_declared_contract() -> None:
    """The direction that catches a silent gap.

    A collector call nobody declared produces evidence whose provenance is
    blank -- indistinguishable from a reading taken before this column existed.
    Checked against the client's own listing methods rather than a hand-kept
    list, so a new one is caught the day it is added and has to be either
    declared or explicitly named as collecting nothing.
    """
    methods = re.findall(
        r"async def (list_\w+|get_\w+)\(.*?\n(.*?)(?=\n    async def |\nclass )",
        CLIENT,
        re.S,
    )
    declared_versions = {e.api_version for _name, e in DECLARED}

    undeclared = []
    for name, body in methods:
        if name in OUTSIDE_COLLECTION:
            continue
        used = re.findall(r"api-version=([0-9][\w.-]*)", body)
        if used and not set(used) & declared_versions:
            undeclared.append((name, used))

    assert not undeclared, (
        "these client calls collect under an api-version no task declares, so a "
        f"reading taken through them records no contract: {undeclared}"
    )


def test_a_task_declaring_several_calls_records_all_of_them() -> None:
    """A reading that made two calls is not a reading that made one.

    The SQL task lists servers and then each server's firewall rules, and the
    conditional-access task reads policies and then the groups they name. A
    record naming only the first would describe a narrower read than the one
    that happened.
    """
    assert len(plan_module.SQL_FIREWALL_ENDPOINT.path) > 0
    sql_endpoints = (
        plan_module.SQL_SERVERS_ENDPOINT,
        plan_module.SQL_FIREWALL_ENDPOINT,
    )
    assert len({e.api_version for e in sql_endpoints}) == 1, (
        "both SQL calls go to the same api-version; if that changes the "
        "declaration has to say so"
    )


def test_describe_reads_as_the_call_that_was_made() -> None:
    endpoint = ProviderEndpoint("https://example.test/things", "2023-01-01")
    assert endpoint.describe() == "https://example.test/things?api-version=2023-01-01"


class _Tokens:
    """Only ever held, never called: the plan is built here, not run."""

    def arm_token(self) -> str:  # pragma: no cover - not reached
        return "token"

    def graph_token(self) -> str:  # pragma: no cover - not reached
        return "token"


def _plan() -> list:
    builder = AzurePlanBuilder(
        tokens=_Tokens(),  # type: ignore[arg-type]
        subscription_id="00000000-0000-0000-0000-000000000000",
        http_client=httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200))
        ),
    )
    return builder.build_account_plan() + builder.build_directory_plan()


def test_every_collection_task_declares_what_it_calls() -> None:
    """Asserted against a real plan rather than a recorded fixture.

    The integration suite replays a recording, and a recording can only echo
    what was written into it -- so a task's declared endpoints have to be
    checked where the tasks are actually built. The same reason ``permissions``
    is asserted in the unit suite rather than beside the pipeline.
    """
    undeclared = [t.key.value for t in _plan() if not t.endpoints]
    assert not undeclared, (
        "these tasks produce an evidence row recording no contract, which reads "
        f"as a gap in CloudGuard's history rather than as one: {undeclared}"
    )


def test_a_task_reading_several_things_declares_all_of_them() -> None:
    """A record naming one call describes a narrower read than the one made.

    The SQL listing makes two: the servers, then each server's firewall rules.
    Its auditing settings are a third call and a *different* reading, because a
    role predating v4 answers that one with a 403 while these two succeed -- so
    it carries its own key and its own declared contract.
    """
    by_key = {t.key.value: t for t in _plan()}
    assert {e.path.rsplit("/", 1)[-1] for e in by_key["sql_servers"].endpoints} == {
        "servers",
        "firewallRules",
    }
    assert {e.path.rsplit("/", 1)[-1] for e in by_key["sql_auditing"].endpoints} == {
        "default"
    }
    assert len(by_key["user_role_map"].endpoints) == 2
