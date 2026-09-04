"""AWS's evidence keys, and the two invariants that are easy to break quietly.

Both failures here are silent. A key with no category raises a ``KeyError``
inside a running scan, on the one path whose job is to be reliable when
everything else is not. A regional key with a reuse window loses sixteen of
seventeen regions to a mapping that can only hold one reading per key, and the
scan reports the survivor as though it were the estate.
"""

from app.connectors.aws.evidence import (
    BASELINE_EVIDENCE,
    AwsEvidence,
    keys_in,
)
from app.connectors.aws.plan import _REGIONAL_TASK_KEYS, ACTION_KEYS
from app.connectors.evidence import EvidenceCategory


def test_every_key_belongs_to_a_category() -> None:
    """Enumerated at import, so this is a second lock on the same door.

    Worth keeping both: the import guard fails the process, which is right in
    production and unhelpfully late in review.
    """
    for key in AwsEvidence:
        assert isinstance(key.category, EvidenceCategory)


def test_no_key_may_be_carried_forward_between_scans() -> None:
    """A regional key structurally cannot be, and a global one has no reason to.

    ``CollectionPlan.carried`` holds one reading per evidence key, so a
    seventeen-region key with a window would keep whichever region was written
    last and present it as all of them. The global keys decline for the ordinary
    reason: a customer who fixes something and asks CloudGuard to check is owed
    an answer about the account as it is now.
    """
    for key in AwsEvidence:
        assert key.reuse_window is None, key


def test_the_keys_declared_regional_are_the_ones_the_plan_fans_out() -> None:
    """Two lists that must agree, and nothing else makes them.

    A key regional in the enum with no regional task would be skipped for a
    region listing nothing was going to use; a key with a regional task and not
    declared regional would read as global to anything asking the enum.
    """
    declared = {key for key in AwsEvidence if key.regional}
    assert declared == set(_REGIONAL_TASK_KEYS)


def test_every_key_is_produced_by_something() -> None:
    """A key nothing collects is a rule that can never degrade.

    That is the exact drift ``requires_evidence`` exists to prevent one layer
    up: a rule naming evidence no task produces reports PASS over data that
    never arrived.
    """
    produced = {key for keys in ACTION_KEYS.values() for key in keys}
    assert set(AwsEvidence) == produced


def test_the_baseline_is_what_no_rule_names() -> None:
    """Collected because the product needs it, not because a rule judges it.

    The region list is the load-bearing entry: every regional task depends on
    it, so a plan derived purely from the rule set would collect nothing
    regional at all.
    """
    assert AwsEvidence.ENABLED_REGIONS in BASELINE_EVIDENCE
    assert set(AwsEvidence) >= BASELINE_EVIDENCE


def test_a_category_lookup_covers_its_keys_and_no_others() -> None:
    """A grant that covers no storage action costs every storage key.

    Which keys belong to a category is a provider's own answer -- AWS has no
    directory category at all -- so the pipeline asks the connector rather than
    an enum it happens to know.
    """
    storage = keys_in(EvidenceCategory.STORAGE)
    assert AwsEvidence.S3_BUCKETS in storage
    assert AwsEvidence.SECURITY_GROUPS not in storage
    assert all(key.category is EvidenceCategory.STORAGE for key in storage)
