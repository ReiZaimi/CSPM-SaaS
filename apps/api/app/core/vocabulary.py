"""What each cloud calls the things a customer reads about.

The columns are neutral and named after Azure's words, deliberately and for a
reason that has not changed: renaming them would make every stored capture
unreplayable (``DECISIONS.md`` §70). What a *customer* reads is a different
question, and the answer to that one is not negotiable — a CSPM telling an AWS
customer "this subscription is no longer connected" is a product that has not
noticed which cloud it is looking at.

So the identifiers stay Azure-flavoured and the sentences do not. This module is
the one place that knows the difference, and it holds nouns rather than
sentences: a sentence per provider would be two sentences to keep in step, and
the half nobody was looking at would drift.

Deliberately not on ``ProviderOnboarding``. These words are needed by the
scanner, the findings routes and the scan model — none of which is onboarding,
and all of which would otherwise import a connector to ask what a word is.
"""

from dataclasses import dataclass

from app.core.enums import Provider


@dataclass(frozen=True)
class Words:
    """One cloud's nouns, in the forms a sentence needs them."""

    #: The unit a scan reads: a subscription, an account, later a project.
    account: str
    accounts: str
    #: The trust boundary above it.
    boundary: str
    #: What the boundary's own reading is *of* — the directory on Azure, the
    #: organization on AWS. Distinct from ``boundary`` because a sentence says
    #: "read the tenant directory" and "read the organization", not "read the
    #: tenant organization".
    directory: str
    #: What the customer deploys to grant access, for the sentences that name it.
    artifact: str
    #: Where they deploy it.
    console: str


AZURE = Words(
    account="subscription",
    accounts="subscriptions",
    boundary="tenant",
    directory="tenant directory",
    artifact="scanner role",
    console="Azure Portal",
)

AWS = Words(
    account="account",
    accounts="accounts",
    boundary="organization",
    directory="organization",
    artifact="scanner stack",
    console="the AWS console",
)

# A provider with no entry gets Azure's words rather than an exception. This is
# a sentence, not a security decision: a missing noun should read slightly wrong
# rather than break the page a customer is trying to read.
_WORDS: dict[Provider, Words] = {Provider.AZURE: AZURE, Provider.AWS: AWS}


def words(provider: Provider | str | None) -> Words:
    """The nouns for one cloud."""
    if provider is None:
        return AZURE
    try:
        return _WORDS.get(Provider(provider), AZURE)
    except ValueError:
        return AZURE
