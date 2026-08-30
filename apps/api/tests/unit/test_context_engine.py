"""What an asset is worth, and on whose authority.

Context is the multiplier the risk engine turns a finding into a risk with, so
every case here is really a case about ranking. Two properties carry the weight:
a declaration can raise a value but never lower one, and every value says where
it came from -- because "CRITICAL" invites the question "says who?" and until
this module there was nowhere the answer existed.
"""

from app.context import ContextDeclaration, infer, resolve, resolve_resource
from app.context.engine import AssetContext
from app.core.enums import ContextSource, Level, ResourceType
from app.domain.resource import CloudResource


def vm(**tags: str) -> AssetContext:
    return infer(tags=tags, name="vm-01", resource_type=ResourceType.VIRTUAL_MACHINE)


# ------------------------------------------------------------------ inference
def test_nothing_known_stays_unknown_and_says_so() -> None:
    """LOW would quietly discount every untagged production asset a customer has
    -- and untagged is exactly what a hurried production estate looks like."""
    context = vm()

    assert context.criticality is Level.UNKNOWN
    assert context.criticality_source is ContextSource.NONE
    assert context.data_sensitivity is Level.UNKNOWN
    assert context.environment is None
    assert context.environment_source is ContextSource.NONE


def test_a_tag_is_read_and_attributed_to_the_tag() -> None:
    context = vm(criticality="critical", environment="production")

    assert context.criticality is Level.CRITICAL
    assert context.criticality_source is ContextSource.PROVIDER_TAG
    assert context.environment == "production"
    assert context.environment_source is ContextSource.PROVIDER_TAG


def test_a_production_looking_name_is_recorded_as_a_guess() -> None:
    """It is how most small teams mark an environment, and it is still a guess.

    The value is the same one the old normalizer produced; what is new is that
    it no longer arrives indistinguishable from something somebody meant.
    """
    context = infer(
        tags={}, name="prod-web-01", resource_type=ResourceType.VIRTUAL_MACHINE
    )

    assert context.environment == "production"
    assert context.environment_source is ContextSource.INFERRED
    assert context.criticality is Level.HIGH
    assert context.criticality_source is ContextSource.INFERRED
    assert context.criticality_source.confidence < ContextSource.PROVIDER_TAG.confidence


def test_a_database_holds_data_whatever_anyone_tagged() -> None:
    """A floor, not an inference: a SQL server with no classification tag is not
    a server with no data in it."""
    context = infer(tags={}, name="db", resource_type=ResourceType.SQL_SERVER)

    assert context.data_sensitivity is Level.HIGH
    assert context.data_sensitivity_source is ContextSource.TYPE_FLOOR


def test_a_tag_outranks_the_type_floor() -> None:
    context = infer(
        tags={"data_classification": "critical"},
        name="db",
        resource_type=ResourceType.SQL_SERVER,
    )

    assert context.data_sensitivity is Level.CRITICAL
    assert context.data_sensitivity_source is ContextSource.PROVIDER_TAG


def test_tag_keys_are_matched_case_insensitively() -> None:
    context = infer(
        tags={"Environment": "Production"},
        name="anything",
        resource_type=ResourceType.VIRTUAL_MACHINE,
    )
    assert context.environment == "Production"
    assert context.environment_source is ContextSource.PROVIDER_TAG


# ---------------------------------------------------------------- declaration
def test_a_declaration_fills_in_what_nothing_else_knew() -> None:
    resolved = resolve(vm(), ContextDeclaration(criticality=Level.HIGH))

    assert resolved.criticality is Level.HIGH
    assert resolved.criticality_source is ContextSource.INHERITED


def test_a_declaration_never_lowers_what_the_capture_showed() -> None:
    """The property that makes this safe to hand a customer.

    A declaration is a floor over a whole subscription, and an asset carrying
    its own critical tag is the more specific of the two facts. The worst a
    mistaken declaration can do is over-rank something, which is the direction
    a security product is allowed to be wrong in.
    """
    tagged = vm(criticality="critical")
    resolved = resolve(tagged, ContextDeclaration(criticality=Level.LOW))

    assert resolved.criticality is Level.CRITICAL
    assert resolved.criticality_source is ContextSource.PROVIDER_TAG


def test_a_declaration_wins_a_tie_on_value() -> None:
    """Same answer, better authority. Which matters because the source is shown:
    "you told us this" is a different sentence from "we read a tag"."""
    resolved = resolve(vm(criticality="high"), ContextDeclaration(criticality=Level.HIGH))

    assert resolved.criticality is Level.HIGH
    assert resolved.criticality_source is ContextSource.INHERITED


def test_a_declared_environment_replaces_a_guessed_one() -> None:
    """An environment is a name, not a level, so there is no maximum to take.

    A person naming it outranks a substring match on a resource name every time
    -- which is the case the whole declaration feature exists for: "sandbox-eu"
    is where this customer runs production.
    """
    guessed = infer(
        tags={}, name="sandbox-eu", resource_type=ResourceType.VIRTUAL_MACHINE
    )
    assert guessed.environment == "development"

    resolved = resolve(guessed, ContextDeclaration(environment="production"))
    assert resolved.environment == "production"
    assert resolved.environment_source is ContextSource.INHERITED


def test_declaring_nothing_changes_nothing() -> None:
    inferred = vm(criticality="high")
    assert resolve(inferred, ContextDeclaration()) == inferred
    assert resolve(inferred, None) == inferred


def test_a_declaration_about_the_asset_outranks_one_about_its_subscription() -> None:
    """Both are the customer speaking; only one is about this asset.

    Nothing writes a per-asset declaration yet, and the distinction is carried
    from the start because a source that cannot tell them apart would show
    "you told us this" against an asset nobody has ever looked at.
    """
    own = resolve(vm(), ContextDeclaration(criticality=Level.HIGH, inherited=False))
    assert own.criticality_source is ContextSource.CUSTOMER

    inherited = resolve(vm(), ContextDeclaration(criticality=Level.HIGH))
    assert inherited.criticality_source is ContextSource.INHERITED
    assert (
        ContextSource.CUSTOMER.confidence > ContextSource.INHERITED.confidence
    ), "a claim about this asset must outweigh one about its neighbours"


def test_unknown_is_absence_rather_than_a_low_value() -> None:
    """A declared level always displaces UNKNOWN, and never the other way round."""
    resolved = resolve(vm(), ContextDeclaration(criticality=Level.LOW))
    assert resolved.criticality is Level.LOW
    assert resolved.criticality_source is ContextSource.INHERITED

    kept = resolve(vm(criticality="medium"), ContextDeclaration(criticality=None))
    assert kept.criticality is Level.MEDIUM
    assert kept.criticality_source is ContextSource.PROVIDER_TAG


# ------------------------------------------------------------------ resources
def test_a_resource_is_enriched_without_being_rebuilt() -> None:
    """The pipeline normalizes a capture and then applies what the customer has
    since said about it, which is why this operates on a finished asset."""
    resource = CloudResource(
        provider_resource_id="/x/storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name="payroll",
        data_sensitivity=Level.HIGH,
        data_sensitivity_source=ContextSource.TYPE_FLOOR,
        metadata={"keep": True},
    )

    resolved = resolve_resource(
        resource,
        ContextDeclaration(criticality=Level.CRITICAL, environment="production"),
    )

    assert resolved.criticality is Level.CRITICAL
    assert resolved.criticality_source is ContextSource.INHERITED
    assert resolved.environment == "production"
    # Untouched: the declaration said nothing about sensitivity, and the type
    # floor is still the reason it is HIGH.
    assert resolved.data_sensitivity is Level.HIGH
    assert resolved.data_sensitivity_source is ContextSource.TYPE_FLOOR
    assert resolved.metadata == {"keep": True}
    assert resolved.name == "payroll"


def test_confidence_rises_with_authority() -> None:
    """The ordering is what decides ties, so it is worth pinning."""
    ordered = [
        ContextSource.NONE,
        ContextSource.INFERRED,
        ContextSource.TYPE_FLOOR,
        ContextSource.PROVIDER_TAG,
        ContextSource.INHERITED,
        ContextSource.CUSTOMER,
    ]
    confidences = [source.confidence for source in ordered]
    assert confidences == sorted(confidences)
    assert all(0.0 <= value <= 1.0 for value in confidences)
