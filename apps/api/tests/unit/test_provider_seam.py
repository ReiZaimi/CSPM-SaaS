"""Whether "provider-neutral above the connector" is true, or only intended.

`ARCHITECTURE.md` §6 and the connector docstring both claim that everything
above `CloudConnector` speaks in `CloudResource` and never in one cloud's terms,
so adding a second provider means writing a connector rather than reshaping the
core. That claim was **false in three places** when this test was written, and
each had the same shape: something neutral reaching sideways into
`connectors/azure` because Azure was the only answer it could need.

* the scan pipeline imported Azure's evidence-key enum to work out which keys a
  permission category holds, so a second connector's categories would have
  degraded nothing;
* the permissions endpoint returned Azure's grants for every provider, so the
  first AWS customer would have been told CloudGuard wanted admin consent;
* the change-event service hard-coded ARM operation names and the `az` command.

None of those would have been noticed by a test of behaviour, because with one
provider they all give the right answer. They are only wrong on the day somebody
starts step 2 of `MULTI_CLOUD.md` §8 -- which is the day this test exists for.
"""

import ast
import pathlib

import pytest

from app.connectors.registry import (
    CONNECTORS,
    ONBOARDING,
    get_connector_class,
    get_onboarding,
)
from app.core.enums import Provider

APP = pathlib.Path(__file__).resolve().parents[2] / "app"

# Modules allowed to name a provider, and why.
#
# The registry maps providers to implementations, so naming them is its whole
# job. `connectors/<provider>/` and `rules/<provider>/` are the provider halves
# by construction. Everything else is meant to be neutral.
ALLOWED_PREFIXES = (
    "connectors/azure/",
    "rules/azure/",
    "connectors/aws/",
    "rules/aws/",
    # The two registries. Mapping a provider to its implementation is the whole
    # job of one and half the job of the other, so naming providers there is the
    # design rather than a leak from it.
    "connectors/registry.py",
    "rules/registry.py",
)

# Nothing is exempt any more.
#
# ``services/cloud_connections.py`` was, by schedule rather than by accident:
# ``MULTI_CLOUD.md`` §8 step 5 put the onboarding split *after* a second
# connector, because it is a refactor whose right shape is knowable from two
# examples and guessable from one. AWS is that second example, and the split
# happened -- consent URLs, the deployable artefact, the probe and the account
# listing now sit behind ``ProviderOnboarding``.
#
# Kept as an empty set rather than deleted, so a future exception has to be
# written down beside a reason instead of quietly appearing in the allow-list
# above.
SCHEDULED_EXCEPTIONS: set[str] = set()


def neutral_modules() -> list[pathlib.Path]:
    return [
        path
        for path in APP.rglob("*.py")
        if not any(str(path.relative_to(APP)).startswith(p) for p in ALLOWED_PREFIXES)
    ]


def provider_imports(path: pathlib.Path) -> list[str]:
    """Imports of a provider package, found in the syntax rather than the text.

    A docstring mentioning Azure is fine and unavoidable -- the product only
    supports one cloud today, and explaining a decision usually means naming it.
    An *import* is the thing that makes neutral code depend on one provider, and
    it is what a second connector would have to break.
    """
    tree = ast.parse(path.read_text())
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
        elif isinstance(node, ast.Import):
            module = node.names[0].name
        else:
            continue
        for provider in Provider:
            connector = f"connectors.{provider.value}"
            rules = f"rules.{provider.value}"
            if module.startswith(f"app.{connector}") or module.startswith(f"app.{rules}"):
                found.append(module)
    return found


def test_nothing_neutral_imports_a_provider_package() -> None:
    """The seam, checked rather than asserted in a docstring.

    The registries are exempt by design and nothing else is: the onboarding
    service was the last scheduled exception and no longer needs one. Anything
    appearing here is a place a second connector would have to be threaded
    through by hand, found now rather than during a migration.
    """
    leaks = {
        name: imports
        for path in neutral_modules()
        if (name := str(path.relative_to(APP))) not in SCHEDULED_EXCEPTIONS
        and (imports := provider_imports(path))
    }
    assert not leaks, (
        "these modules are meant to be provider-neutral and import a provider "
        f"package: {leaks}"
    )


def test_every_registered_provider_answers_the_questions_asked_of_a_class() -> None:
    """The three questions asked of a provider without a connection to it.

    Each was previously answered by importing Azure directly. A registered
    connector that could not answer them would be one the neutral code has to
    special-case, which is the seam leaking again in a different direction.
    """
    for provider, implementation in CONNECTORS.items():
        assert implementation.required_permissions(), provider
        assert implementation.baseline_evidence(), provider
        # Every provider has *some* category it collects under; which ones is
        # its own business.
        assert any(
            implementation.evidence_keys_in(category)
            for category in {key.category for key in implementation.baseline_evidence()}
        ), provider


def test_an_unimplemented_provider_is_refused_rather_than_defaulted() -> None:
    """AWS is in the ``Provider`` enum as an extension point. Returning Azure's
    connector for it would be the worst possible answer: a scan that appears to
    work and reads the wrong cloud."""
    from app.core.errors import NotConfigured

    with pytest.raises(NotConfigured):
        get_connector_class(Provider.AWS)
    with pytest.raises(NotConfigured):
        get_connector_class(Provider.GCP)


def test_every_registered_provider_can_onboard_a_customer() -> None:
    """Onboarding is now a seam too, and a seam is only real if something asks.

    The abstract methods make an incomplete implementation fail at construction
    rather than at the moment a customer presses a button, which is the whole
    reason they are abstract: a provider missing ``probe`` would have verified
    every connection to it by not checking.
    """
    for provider in ONBOARDING:
        onboarding = get_onboarding(provider)
        assert onboarding.provider == provider
        assert onboarding.root_scope
        assert onboarding.grant_version()
        assert onboarding.initial_status_detail


def test_a_provider_with_no_onboarding_is_refused_rather_than_defaulted() -> None:
    """The same rule the connector registry follows, for the same reason.

    Handing back Azure's flow for AWS would send a customer to a Microsoft
    consent screen for an Amazon account.
    """
    from app.core.errors import NotConfigured

    with pytest.raises(NotConfigured):
        get_onboarding(Provider.GCP)
