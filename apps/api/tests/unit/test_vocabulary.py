"""What each cloud calls the things a customer reads about.

The columns keep Azure's names on purpose: renaming them would make every stored
capture unreplayable (`DECISIONS.md` §70). What a *customer* reads is a
different question, and telling an AWS customer "this subscription is no longer
connected" is a product that has not noticed which cloud it is looking at.

These pin the split. Identifiers stay Azure-flavoured; sentences do not.
"""

import pytest

from app.core.enums import Provider, ScanStepKind
from app.core.vocabulary import words
from app.models.scan import ScanStep


def test_each_cloud_gets_its_own_nouns() -> None:
    assert words(Provider.AZURE).account == "subscription"
    assert words(Provider.AWS).account == "account"
    assert words(Provider.AZURE).directory == "tenant directory"
    assert words(Provider.AWS).directory == "organization"


def test_the_artefact_and_the_console_are_named_too() -> None:
    """"Check that the deployment succeeded in Azure Portal" is the wrong pair
    of nouns for somebody who ran a CloudFormation stack -- and it is shown at
    the moment they are most likely to be confused about which step they are
    on."""
    assert words(Provider.AWS).artifact == "scanner stack"
    assert words(Provider.AWS).console == "the AWS console"
    assert words(Provider.AZURE).artifact == "scanner role"


@pytest.mark.parametrize("provider", [None, "gcp", "nonsense"])
def test_an_unknown_provider_reads_slightly_wrong_rather_than_breaking(
    provider: object,
) -> None:
    """A missing noun is a sentence problem, not a security decision.

    Raising here would take down the page a customer is trying to read in order
    to avoid saying "subscription" once.
    """
    assert words(provider).account == "subscription"  # type: ignore[arg-type]


def test_a_collect_step_describes_itself_in_its_own_cloud_s_words() -> None:
    directory = ScanStep(kind=ScanStepKind.COLLECT, cloud_account_id=None)
    assert directory.describe(Provider.AWS) == "the organization"
    assert directory.describe(Provider.AZURE) == "the tenant directory"


def test_a_step_with_no_provider_keeps_the_words_it_always_had() -> None:
    """The log line calls it this way, and a log line is read by us rather than
    by a customer -- threading a provider through it would cost a query per
    step to change a word nobody outside is reading."""
    directory = ScanStep(kind=ScanStepKind.COLLECT, cloud_account_id=None)
    assert directory.describe() == "the tenant directory"


def test_a_non_collect_step_names_its_kind_whatever_the_cloud() -> None:
    """ANALYZE is ANALYZE in both clouds. A vocabulary that reworded it would be
    translating something that was never provider-shaped."""
    step = ScanStep(kind=ScanStepKind.ANALYZE)
    assert step.describe(Provider.AWS) == "analyze"
    assert step.describe(Provider.AZURE) == "analyze"
