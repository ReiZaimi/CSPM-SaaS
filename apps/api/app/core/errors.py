"""The single response envelope and the error taxonomy behind it (API.md section 2)."""

from collections.abc import Sequence
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


def envelope(data: Any = None, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"data": data, "error": None, "meta": meta or {}}


def error_envelope(code: str, message: str, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"data": None, "error": {"code": code, "message": message}, "meta": meta or {}}


class AppError(HTTPException):
    """Base for errors that carry a stable machine-readable code."""

    code = "INTERNAL_ERROR"
    status_code_default = status.HTTP_500_INTERNAL_SERVER_ERROR

    def __init__(self, message: str | None = None, status_code: int | None = None) -> None:
        super().__init__(
            status_code=status_code or self.status_code_default,
            detail=message or self.__class__.__doc__ or self.code,
        )

    def __str__(self) -> str:
        """Just the message.

        HTTPException renders as "503: <detail>", which is fine in a log and
        wrong on a scan record the user reads. Anything that stores str(exc) as
        user-facing text -- the scan pipeline does -- should get the sentence,
        not the status code.
        """
        return str(self.detail)


class NotAuthenticated(AppError):
    """Authentication required"""

    code = "NOT_AUTHENTICATED"
    status_code_default = status.HTTP_401_UNAUTHORIZED


class PermissionDenied(AppError):
    """You do not have permission to perform this action"""

    code = "PERMISSION_DENIED"
    status_code_default = status.HTTP_403_FORBIDDEN


class NotFound(AppError):
    """Resource not found"""

    code = "NOT_FOUND"
    status_code_default = status.HTTP_404_NOT_FOUND


class OrganizationNotFound(NotFound):
    """Organization not found"""

    code = "ORGANIZATION_NOT_FOUND"


class CloudAccountNotFound(NotFound):
    """Cloud account not found"""

    code = "CLOUD_ACCOUNT_NOT_FOUND"


class FindingNotFound(NotFound):
    """Finding not found"""

    code = "FINDING_NOT_FOUND"


class ScanNotFound(NotFound):
    """Scan not found"""

    code = "SCAN_NOT_FOUND"


class ValidationFailed(AppError):
    """Request validation failed"""

    code = "VALIDATION_FAILED"
    status_code_default = status.HTTP_422_UNPROCESSABLE_ENTITY


class ConflictError(AppError):
    """Conflicting state"""

    code = "CONFLICT"
    status_code_default = status.HTTP_409_CONFLICT


class CloudConnectionError(AppError):
    """Could not reach the cloud provider"""

    code = "CLOUD_CONNECTION_ERROR"
    status_code_default = status.HTTP_502_BAD_GATEWAY


class NotConfigured(AppError):
    """Server is not configured for this operation"""

    code = "NOT_CONFIGURED"
    status_code_default = status.HTTP_503_SERVICE_UNAVAILABLE


async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code, content=error_envelope(exc.code, str(exc.detail))
    )


async def http_error_handler(_: Request, exc: HTTPException) -> JSONResponse:
    code = getattr(exc, "code", None) or f"HTTP_{exc.status_code}"
    return JSONResponse(status_code=exc.status_code, content=error_envelope(code, str(exc.detail)))


def _describable(errors: Sequence[Any]) -> list[Any]:
    """Pydantic's error list, with anything unserializable turned into words.

    A validator that raises ``ValueError`` -- the documented way to write one --
    puts the exception *object* into the error's ``ctx``, and JSON cannot encode
    that. The symptom is the worst kind: the request was rejected correctly, and
    then the handler explaining the rejection raised, so the caller got a 500
    for what was a perfectly ordinary 422.

    Only the exception values are rewritten. The rest of ``ctx`` carries the
    numbers a constraint failed against -- a limit, a length -- and stringifying
    those would cost a client the ability to read them.
    """
    described: list[Any] = []
    for error in errors:
        if not isinstance(error, dict):
            described.append(jsonable_encoder(error))
            continue
        context = error.get("ctx")
        if isinstance(context, dict):
            error = {
                **error,
                "ctx": {
                    key: str(value) if isinstance(value, BaseException) else value
                    for key, value in context.items()
                },
            }
        described.append(jsonable_encoder(error))
    return described


async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_envelope(
            "VALIDATION_FAILED",
            "Request validation failed",
            {"errors": _describable(exc.errors())},
        ),
    )
