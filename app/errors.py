from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException


def error_payload(code: str, message: str, details=None):
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    code_map = {
        400: "bad_request",
        401: "unauthorized",
        404: "not_found",
        405: "method_not_allowed",
        429: "rate_limit_exceeded",
        500: "internal_error",
    }

    message = exc.detail if isinstance(exc.detail, str) else "Request failed"

    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(
            code_map.get(exc.status_code, "http_error"),
            message,
        ),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=error_payload(
            "validation_error",
            "Request validation failed",
            {"errors": exc.errors()},
        ),
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=error_payload(
            "internal_error",
            "Internal server error",
        ),
    )