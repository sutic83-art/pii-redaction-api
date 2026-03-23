from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


def error_payload(code: str, message: str, details=None, request_id=None):
    payload = {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }

    if request_id:
        payload["error"]["request_id"] = request_id

    return payload


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    code_map = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        429: "rate_limit_exceeded",
        500: "internal_error",
    }

    message = exc.detail if isinstance(exc.detail, str) else "Request failed"
    request_id = getattr(request.state, "request_id", None)

    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(
            code_map.get(exc.status_code, "http_error"),
            message,
            request_id=request_id,
        ),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None)

    return JSONResponse(
        status_code=422,
        content=error_payload(
            "validation_error",
            "Request validation failed",
            {"errors": exc.errors()},
            request_id=request_id,
        ),
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)

    return JSONResponse(
        status_code=500,
        content=error_payload(
            "internal_error",
            "Internal server error",
            request_id=request_id,
        ),
    )