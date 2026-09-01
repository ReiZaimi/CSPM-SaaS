"""Inferring asset context, and letting the customer overrule the inference."""

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict

from app.core.enums import ContextSource, Level, ResourceType
from app.domain.resource import CloudResource

# Tag keys customers actually use, in the order we trust them. Provider-neutral:
# an AWS tag and an Azure tag are the same idea spelled the same way, and the
# one thing that must not happen is each connector growing its own list.
ENVIRONMENT_TAG_KEYS = ("environment", "env", "tier", "stage")
CRITICALITY_TAG_KEYS = ("criticality", "critical", "business_criticality", "importance")
SENSITIVITY_TAG_KEYS = (
    "data_sensitivity",
    "sensitivity",
    "data_classification",
    "classification",
)

PRODUCTION_HINTS = {"prod", "production", "prd", "live"}
DEVELOPMENT_HINTS = {
    "dev",
    "development",
    "test",
    "testing",
    "staging",
    "stage",
    "qa",
    "sandbox",
}

LEVEL_WORDS = {
    "low": Level.LOW,
    "minimal": Level.LOW,
    "medium": Level.MEDIUM,
    "moderate": Level.MEDIUM,
    "normal": Level.MEDIUM,
    "standard": Level.MEDIUM,
    "high": Level.HIGH,
    "important": Level.HIGH,
    "critical": Level.CRITICAL,
    "confidential": Level.CRITICAL,
    "restricted": Level.CRITICAL,
    "secret": Level.CRITICAL,
    "public": Level.LOW,
    "internal": Level.MEDIUM,
}

# Resource types that hold data whatever anyone tagged them. A floor, not a
# guess: a SQL server with no classification tag is not a server with no data.
DATA_HOLDING_TYPES = {
    ResourceType.SQL_SERVER,
    ResourceType.SQL_DATABASE,
    ResourceType.POSTGRESQL_SERVER,
    ResourceType.STORAGE_ACCOUNT,
}

class ContextFields(TypedDict):
    """The context keyword arguments a :class:`CloudResource` takes.

    Spelled out as a type rather than left as a loose dict so a normalizer can
    spread one call's result and still be checked: the names here are the
    constructor's names, and a rename that broke the correspondence would fail
    at the type checker rather than at the first scan.
    """

    criticality: Level
    criticality_source: ContextSource
    data_sensitivity: Level
    data_sensitivity_source: ContextSource
    environment: str | None
    environment_source: ContextSource


@dataclass(frozen=True)
class AssetContext:
    """Three facts about an asset, each with where it came from.

    Flat pairs rather than value objects, because these map one-to-one onto
    columns and onto :class:`CloudResource` fields, and a rule reading
    ``resource.criticality`` should get a ``Level`` rather than something it has
    to unwrap. Confidence is not stored: it is a property of the source
    (:attr:`ContextSource.confidence`), so the two cannot drift apart.
    """

    criticality: Level = Level.UNKNOWN
    criticality_source: ContextSource = ContextSource.NONE
    data_sensitivity: Level = Level.UNKNOWN
    data_sensitivity_source: ContextSource = ContextSource.NONE
    environment: str | None = None
    environment_source: ContextSource = ContextSource.NONE

    def fields(self) -> ContextFields:
        """This context as the arguments a resource is constructed with.

        One spread instead of six arguments restated per resource type -- which
        is how five sites ended up passing subtly different things to the same
        three helpers.
        """
        return ContextFields(
            criticality=self.criticality,
            criticality_source=self.criticality_source,
            data_sensitivity=self.data_sensitivity,
            data_sensitivity_source=self.data_sensitivity_source,
            environment=self.environment,
            environment_source=self.environment_source,
        )


@dataclass(frozen=True)
class ContextDeclaration:
    """What a person at the customer has said about a scope.

    Every field optional, because a customer who knows one thing should be able
    to say that one thing. "This subscription is production" is the common case
    and is worth more than any amount of tag archaeology.

    ``inherited`` distinguishes a declaration made about *this asset* from one
    made about the subscription it happens to live in. Both are the customer
    speaking; only the first is the customer speaking about this asset, and the
    recorded source has to say which.
    """

    environment: str | None = None
    criticality: Level | None = None
    data_sensitivity: Level | None = None
    inherited: bool = True

    @property
    def is_empty(self) -> bool:
        return (
            self.environment is None
            and self.criticality is None
            and self.data_sensitivity is None
        )

    @property
    def source(self) -> ContextSource:
        return ContextSource.INHERITED if self.inherited else ContextSource.CUSTOMER


def normalize_tags(tags: Mapping[str, object] | None) -> dict[str, str]:
    """Tags as the engine reads them: lower-cased keys, string values."""
    return {str(k).lower(): str(v) for k, v in (tags or {}).items()}


def infer(
    *,
    tags: Mapping[str, object] | None,
    name: str = "",
    resource_type: ResourceType | None = None,
) -> AssetContext:
    """Context read off the capture alone. Pure, and deliberately cautious.

    Everything absent stays UNKNOWN. Saying LOW where nothing is known would
    quietly discount every untagged production asset a customer has, which is
    the population most likely to be untagged in the first place
    (``DECISIONS.md`` §7).
    """
    normalized = normalize_tags(tags)
    environment, environment_source = _environment(normalized, name)
    criticality, criticality_source = _criticality(normalized, environment)
    sensitivity, sensitivity_source = _sensitivity(normalized, resource_type)
    return AssetContext(
        criticality=criticality,
        criticality_source=criticality_source,
        data_sensitivity=sensitivity,
        data_sensitivity_source=sensitivity_source,
        environment=environment,
        environment_source=environment_source,
    )


def resolve(
    inferred: AssetContext, declaration: ContextDeclaration | None
) -> AssetContext:
    """Combine what was inferred with what the customer declared.

    A declaration is a **floor**, not an override, and that is the substantive
    decision in this module. "This subscription is production" is a statement
    about everything in it, so nothing inside it should score below what was
    declared -- but an asset carrying its own ``criticality=critical`` tag is
    more specific than a statement about its neighbours, and lowering it to the
    subscription's level would discard the more precise of two facts.

    So the higher value wins, and the declaration wins ties. Nothing here can
    make an asset look *safer* than the capture already said it was, which is
    the property that makes this safe to expose as a customer-editable control
    at all: the worst a wrong declaration can do is over-rank an asset.
    """
    if declaration is None or declaration.is_empty:
        return inferred

    source = declaration.source
    criticality, criticality_source = _stronger(
        (inferred.criticality, inferred.criticality_source),
        (declaration.criticality, source),
    )
    sensitivity, sensitivity_source = _stronger(
        (inferred.data_sensitivity, inferred.data_sensitivity_source),
        (declaration.data_sensitivity, source),
    )

    environment, environment_source = inferred.environment, inferred.environment_source
    if declaration.environment is not None:
        # Not a floor: an environment is a name, not a level, so there is
        # nothing to take a maximum of. A person naming it outranks a guess from
        # a resource name every time.
        environment, environment_source = declaration.environment, source

    return AssetContext(
        criticality=criticality,
        criticality_source=criticality_source,
        data_sensitivity=sensitivity,
        data_sensitivity_source=sensitivity_source,
        environment=environment,
        environment_source=environment_source,
    )


def resolve_resource(
    resource: CloudResource, declaration: ContextDeclaration | None
) -> CloudResource:
    """The same, applied to an already-normalized asset.

    Normalization happens per capture and knows nothing about declarations,
    which live in the database. This is the seam where the two meet: the
    pipeline reads a capture back, normalizes it, and enriches the result with
    what the customer has since said about the subscription it came from.
    """
    if declaration is None or declaration.is_empty:
        return resource

    resolved = resolve(
        AssetContext(
            criticality=resource.criticality,
            criticality_source=resource.criticality_source,
            data_sensitivity=resource.data_sensitivity,
            data_sensitivity_source=resource.data_sensitivity_source,
            environment=resource.environment,
            environment_source=resource.environment_source,
        ),
        declaration,
    )
    return dataclasses.replace(
        resource,
        criticality=resolved.criticality,
        criticality_source=resolved.criticality_source,
        data_sensitivity=resolved.data_sensitivity,
        data_sensitivity_source=resolved.data_sensitivity_source,
        environment=resolved.environment,
        environment_source=resolved.environment_source,
    )


# ------------------------------------------------------------------ inference
def _tag_level(tags: dict[str, str], keys: tuple[str, ...]) -> Level | None:
    for key in keys:
        if key in tags:
            word = tags[key].strip().lower()
            if word in LEVEL_WORDS:
                return LEVEL_WORDS[word]
    return None


def _environment(tags: dict[str, str], name: str) -> tuple[str | None, ContextSource]:
    for key in ENVIRONMENT_TAG_KEYS:
        if key in tags:
            return tags[key], ContextSource.PROVIDER_TAG
    # Falling back to the name, which is how most small teams actually mark an
    # environment -- and recorded as a guess, because that is what it is.
    lowered = name.lower()
    for hint in PRODUCTION_HINTS:
        if hint in lowered:
            return "production", ContextSource.INFERRED
    for hint in DEVELOPMENT_HINTS:
        if hint in lowered:
            return "development", ContextSource.INFERRED
    return None, ContextSource.NONE


def _criticality(
    tags: dict[str, str], environment: str | None
) -> tuple[Level, ContextSource]:
    explicit = _tag_level(tags, CRITICALITY_TAG_KEYS)
    if explicit:
        return explicit, ContextSource.PROVIDER_TAG
    if environment and environment.lower() in PRODUCTION_HINTS:
        return Level.HIGH, ContextSource.INFERRED
    if environment and environment.lower() in DEVELOPMENT_HINTS:
        return Level.LOW, ContextSource.INFERRED
    return Level.UNKNOWN, ContextSource.NONE


def _sensitivity(
    tags: dict[str, str], resource_type: ResourceType | None
) -> tuple[Level, ContextSource]:
    explicit = _tag_level(tags, SENSITIVITY_TAG_KEYS)
    if explicit:
        return explicit, ContextSource.PROVIDER_TAG
    if resource_type in DATA_HOLDING_TYPES:
        return Level.HIGH, ContextSource.TYPE_FLOOR
    return Level.UNKNOWN, ContextSource.NONE


def _stronger(
    held: tuple[Level, ContextSource], claimed: tuple[Level | None, ContextSource]
) -> tuple[Level, ContextSource]:
    """The higher of two claims, with the more authoritative source winning ties.

    UNKNOWN is absence, not a low value: a claim against an UNKNOWN wins
    outright, and an UNKNOWN claim never displaces a value.
    """
    value, source = held
    other, other_source = claimed
    if other is None or other is Level.UNKNOWN:
        return value, source
    if value is Level.UNKNOWN:
        return other, other_source

    if other.rank > value.rank:
        return other, other_source
    if (
        other.rank == value.rank
        and other_source.confidence > source.confidence
    ):
        return other, other_source
    return value, source
