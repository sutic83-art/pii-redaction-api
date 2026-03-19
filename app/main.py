import os
import time
from typing import List, Optional
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.audit import audit_event
from app.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.policy import apply_policy
from app.rate_limit import enforce_rate_limit
from app.rec_sr import find_entities


def _get_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
    if not raw:
        return []

    if raw == "*":
        return ["*"]

    return [item.strip() for item in raw.split(",") if item.strip()]


app = FastAPI(
    title="PII Redaction API MVP",
    version="3.1.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

cors_origins = _get_cors_origins()
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False if cors_origins == ["*"] else True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["x-request-id", "x-response-time-ms"],
    )


class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    policy: str = Field(default="mask")
    entities: Optional[List[str]] = None


class DetectionItem(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float


class RedactResponse(BaseModel):
    redacted_text: str
    policy: str
    detections: List[DetectionItem]
    audit: dict


def _get_allowed_api_keys():
    raw = os.getenv("API_KEYS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _check_api_key(x_api_key: Optional[str]):
    allowed = _get_allowed_api_keys()
    if not allowed:
        return
    if not x_api_key or x_api_key not in allowed:
        raise HTTPException(status_code=401, detail="Unauthorized")


def redact_text(text: str, results: List[dict], policy: str) -> str:
    output = text
    for item in sorted(results, key=lambda x: x["start"], reverse=True):
        replacement = apply_policy(item["text"], policy)
        output = output[: item["start"]] + replacement + output[item["end"] :]
    return output


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid4())
    request.state.request_id = request_id
    started_at = time.time()

    response = await call_next(request)

    duration_ms = int((time.time() - started_at) * 1000)
    response.headers["x-request-id"] = request_id
    response.headers["x-response-time-ms"] = str(duration_ms)
    return response


@app.get("/", include_in_schema=False)
def root():
    return {
        "name": "PII Redaction API",
        "status": "running",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
        "redact": "/redact",
        "api_v1_redact": "/api/v1/redact",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/redact", response_model=RedactResponse)
@app.post("/api/v1/redact", response_model=RedactResponse)
def redact(
    req: RedactRequest,
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    enforce_rate_limit(request)
    _check_api_key(x_api_key)

    try:
        results = find_entities(req.text, req.entities)
        redacted = redact_text(req.text, results, req.policy)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit = audit_event(req.text, req.policy, results)

    detections = [
        DetectionItem(
            entity_type=r["entity_type"],
            start=r["start"],
            end=r["end"],
            score=r["score"],
        )
        for r in results
    ]

    return RedactResponse(
        redacted_text=redacted,
        policy=req.policy,
        detections=detections,
        audit=audit,
    )