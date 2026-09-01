"""The handler that explains a rejection must never itself fail.

A validator written the documented way -- raise ``ValueError`` with a sentence
for the customer -- puts the exception *object* into the error's ``ctx``, and
JSON cannot encode one. The symptom was the worst kind available: the request
was rejected correctly, and then the response explaining the rejection raised,
so the caller got a 500 for what was an ordinary 422. A validation message the
API cannot deliver is worse than no validation message, because the client is
now told the server is broken.
"""

import json

from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator

from app.core.errors import validation_error_handler


class Declaration(BaseModel):
    """A field validator of exactly the shape that broke this."""

    criticality: str | None = None
    label: str = Field(default="ok", max_length=4)

    @field_validator("criticality")
    @classmethod
    def _not_unknown(cls, value: str | None) -> str | None:
        if value == "UNKNOWN":
            raise ValueError("UNKNOWN is not something to declare. Leave it out.")
        return value


def rejection(payload: dict) -> RequestValidationError:
    try:
        Declaration(**payload)
    except Exception as exc:  # pydantic.ValidationError
        return RequestValidationError(exc.errors())  # type: ignore[attr-defined]
    raise AssertionError("the model accepted a payload the test expects it to reject")


async def response_for(payload: dict) -> dict:
    response = await validation_error_handler(None, rejection(payload))  # type: ignore[arg-type]
    return json.loads(response.body)


async def test_a_validator_raising_value_error_produces_a_422_a_client_can_read() -> None:
    body = await response_for({"criticality": "UNKNOWN"})

    assert body["error"]["code"] == "VALIDATION_FAILED"
    # The sentence the validator wrote, which is the whole point of writing one.
    assert "UNKNOWN is not something to declare" in body["meta"]["errors"][0]["msg"]


async def test_the_exception_in_the_context_becomes_words() -> None:
    """Rather than an empty object, which is what a generic encoder leaves
    behind: the message is the only part of an exception worth sending."""
    body = await response_for({"criticality": "UNKNOWN"})

    context = body["meta"]["errors"][0]["ctx"]
    assert context["error"] == "UNKNOWN is not something to declare. Leave it out."


async def test_the_numbers_a_constraint_failed_against_survive() -> None:
    """Only exceptions are rewritten. A limit or a length is what a client needs
    to correct the request, and stringifying it would cost them that."""
    body = await response_for({"label": "far too long"})

    error = body["meta"]["errors"][0]
    assert error["type"] == "string_too_long"
    assert error["ctx"]["max_length"] == 4


async def test_every_error_in_a_rejection_is_reported() -> None:
    body = await response_for({"criticality": "UNKNOWN", "label": "far too long"})

    assert len(body["meta"]["errors"]) == 2
