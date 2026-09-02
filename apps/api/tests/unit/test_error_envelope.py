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

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, field_validator

from app.core.errors import (
    AppError,
    PermissionDenied,
    UnhandledErrorMiddleware,
    app_error_handler,
    validation_error_handler,
)


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


# ---------------------------------------------- what a 500 looks like from a browser
class TestUnhandledErrors:
    """An unhandled exception must arrive as an answer, not as a network failure.

    Starlette hands a handler registered for bare ``Exception`` to
    ``ServerErrorMiddleware``, which is the outermost layer -- so its response
    never passes back out through ``CORSMiddleware`` and carries no
    ``Access-Control-Allow-Origin``. A browser refuses to read a cross-origin
    response without one, and ``fetch`` rejects with ``TypeError: Failed to
    fetch`` -- the same thing it says when the request never arrived at all.

    So a server-side bug was indistinguishable from the API being unreachable.
    On the connections page that read as "turn on change detection does
    nothing", while the request had in fact arrived, run, and raised.
    """

    @staticmethod
    def _app() -> FastAPI:
        app = FastAPI()
        app.add_middleware(UnhandledErrorMiddleware)
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["https://cspmcloud.vercel.app"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]

        @app.patch("/boom")
        async def boom() -> dict:
            raise RuntimeError("the database said no")

        @app.patch("/refused")
        async def refused() -> dict:
            raise PermissionDenied("Your role is read-only")

        return app

    def test_an_unhandled_exception_answers_in_the_envelope(self) -> None:
        client = TestClient(self._app(), raise_server_exceptions=False)

        response = client.patch("/boom")

        assert response.status_code == 500
        assert response.json()["error"]["code"] == "INTERNAL_ERROR"

    def test_the_answer_carries_the_header_a_browser_needs_to_read_it(self) -> None:
        """The whole point. Without this the frontend sees a network failure and
        tells the customer the request never went anywhere."""
        client = TestClient(self._app(), raise_server_exceptions=False)

        response = client.patch(
            "/boom", headers={"Origin": "https://cspmcloud.vercel.app"}
        )

        assert (
            response.headers["access-control-allow-origin"]
            == "https://cspmcloud.vercel.app"
        )

    def test_the_message_does_not_carry_the_exception(self) -> None:
        """A stack trace rendered into a browser is a disclosure, and this is a
        security product. The detail goes to the log."""
        client = TestClient(self._app(), raise_server_exceptions=False)

        body = client.patch("/boom").json()

        assert "the database said no" not in body["error"]["message"]
        assert "RuntimeError" not in body["error"]["message"]

    def test_an_anticipated_error_still_answers_as_itself(self) -> None:
        """The taxonomy runs further in, so a refusal is still a 403 saying why
        -- this catches only what nobody anticipated."""
        client = TestClient(self._app(), raise_server_exceptions=False)

        response = client.patch("/refused")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PERMISSION_DENIED"
