import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.contact_store import append_contact_request
from app.contact_store_admin import read_contact_requests
from app.audit import audit_event
from app.client_registry import (
    create_client,
    get_client_by_api_key,
    list_clients_safe,
    reload_clients,
    rotate_client_key,
    sanitize_client,
    update_client,
)
from app.errors import (
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.policy import apply_policy
from app.rate_limit import enforce_rate_limit
from app.rec_sr import DEFAULT_ENTITIES, find_entities
from app.usage_store import append_usage_event, get_monthly_request_count, get_usage_summary


BASE_DIR = Path(__file__).resolve().parent


def _get_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "").strip()
    if not raw:
        return []

    if raw == "*":
        return ["*"]

    return [item.strip() for item in raw.split(",") if item.strip()]


app = FastAPI(
    title="PII Redaction API MVP",
    version="4.0.0",
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
        expose_headers=["x-request-id", "x-response-time-ms", "x-client-id", "x-client-plan"],
    )


class RedactRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    policy: str = Field(default="mask")
    entities: Optional[List[str]] = None


class ContactRequest(BaseModel):
    full_name: str = Field(..., min_length=1, max_length=200)
    email: str = Field(..., min_length=1, max_length=320)
    company: Optional[str] = Field(default=None, max_length=200)
    message: str = Field(..., min_length=1, max_length=8000)

    @field_validator("full_name", "email", "message", mode="before")
    @classmethod
    def _strip_and_require(cls, value: object) -> object:
        if value is None:
            return value

        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("must not be blank")
            return stripped

        return value

    @field_validator("company", mode="before")
    @classmethod
    def _strip_optional(cls, value: object) -> object:
        if value is None:
            return None

        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None

        return value


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


class ClientCreateRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=80)
    client_name: str = Field(..., min_length=1, max_length=120)
    plan: str = Field(default="standard", min_length=1, max_length=60)
    status: str = Field(default="active", min_length=1, max_length=30)
    rate_limit_per_minute: int = Field(default=30, ge=1, le=100000)
    monthly_quota: int = Field(default=0, ge=0, le=1000000000)
    allowed_entities: List[str] = Field(default_factory=lambda: ["*"])


class ClientPatchRequest(BaseModel):
    client_name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    plan: Optional[str] = Field(default=None, min_length=1, max_length=60)
    status: Optional[str] = Field(default=None, min_length=1, max_length=30)
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=100000)
    monthly_quota: Optional[int] = Field(default=None, ge=0, le=1000000000)
    allowed_entities: Optional[List[str]] = None


def _get_admin_api_key() -> str:
    return os.getenv("ADMIN_API_KEY", "").strip()


def _check_admin_key(x_admin_key: Optional[str]):
    expected = _get_admin_api_key()

    if not expected:
        raise HTTPException(status_code=503, detail="Admin key is not configured")

    if not x_admin_key or x_admin_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


def _authenticate_client(x_api_key: Optional[str]) -> dict:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    client = get_client_by_api_key(x_api_key)
    if not client:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if client.get("status") != "active":
        raise HTTPException(status_code=403, detail="Client is disabled")

    return client


def _resolve_entities(requested_entities: Optional[List[str]], client: dict) -> List[str]:
    allowed_entities = client.get("allowed_entities", ["*"])

    if "*" in allowed_entities:
        return requested_entities or DEFAULT_ENTITIES

    if requested_entities:
        requested = [str(item).strip().upper() for item in requested_entities if str(item).strip()]
        filtered = [item for item in requested if item in allowed_entities]

        if not filtered:
            raise HTTPException(
                status_code=403,
                detail="Requested entities are not allowed for this client",
            )

        return filtered

    return allowed_entities


def _check_monthly_quota(client: dict):
    monthly_quota = int(client.get("monthly_quota", 0) or 0)
    if monthly_quota <= 0:
        return

    used = get_monthly_request_count(client["client_id"])
    if used >= monthly_quota:
        raise HTTPException(status_code=429, detail="Monthly quota exceeded")


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
def landing():
    return FileResponse(BASE_DIR / "static" / "landing.html")


@app.get("/api", include_in_schema=False)
def api_info():
    return {
        "name": "PII Redaction API",
        "status": "running",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
        "demo": "/demo",
        "redact": "/redact",
        "api_v1_redact": "/api/v1/redact",
        "admin_clients": "/api/admin/clients",
        "admin_usage_summary": "/api/admin/usage-summary",
        "admin_reload_clients": "/api/admin/reload-clients",
    }


@app.get("/demo", include_in_schema=False)
def demo():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/admin", include_in_schema=False)
def admin():
    return FileResponse(BASE_DIR / "static" / "admin.html")


@app.get("/offer", include_in_schema=False)
def offer():
    return FileResponse(BASE_DIR / "static" / "offer.html")


@app.get("/onboarding", include_in_schema=False)
def onboarding():
    return FileResponse(BASE_DIR / "static" / "onboarding.html")


@app.get("/offer-print", include_in_schema=False)
def offer_print():
    return FileResponse(BASE_DIR / "static" / "offer-print.html")


@app.get("/ops", include_in_schema=False)
def ops():
    return FileResponse(BASE_DIR / "static" / "ops.html")


@app.get("/privacy", include_in_schema=False)
def privacy():
    return FileResponse(BASE_DIR / "static" / "privacy.html")


@app.get("/terms", include_in_schema=False)
def terms():
    return FileResponse(BASE_DIR / "static" / "terms.html")


@app.get("/security", include_in_schema=False)
def security():
    return FileResponse(BASE_DIR / "static" / "security.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/api/contact")
def submit_contact(req: ContactRequest, request: Request):
    append_contact_request(
        full_name=req.full_name,
        email=req.email,
        company=req.company,
        message=req.message,
        request_id=getattr(request.state, "request_id", None),
    )
    return {"success": {"status": "ok"}}


@app.post("/redact", response_model=RedactResponse)
@app.post("/api/v1/redact", response_model=RedactResponse)
def redact(
    req: RedactRequest,
    request: Request,
    response: Response,
    x_api_key: Optional[str] = Header(default=None),
):
    client = _authenticate_client(x_api_key)
    enforce_rate_limit(client["client_id"], client.get("rate_limit_per_minute", 30))
    _check_monthly_quota(client)

    effective_entities = _resolve_entities(req.entities, client)

    try:
        results = find_entities(req.text, effective_entities)
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

    append_usage_event(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", None),
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "plan": client["plan"],
            "route": str(request.url.path),
            "policy": req.policy,
            "requested_entities": req.entities or [],
            "effective_entities": effective_entities,
            "detections_count": len(results),
            "detected_entity_types": sorted(list({item["entity_type"] for item in results})),
            "input_length": len(req.text),
            "output_length": len(redacted),
            "success": True,
        }
    )

    response.headers["x-client-id"] = client["client_id"]
    response.headers["x-client-plan"] = client["plan"]

    return RedactResponse(
        redacted_text=redacted,
        policy=req.policy,
        detections=detections,
        audit=audit,
    )


@app.get("/api/admin/clients")
def admin_clients(x_admin_key: Optional[str] = Header(default=None)):
    _check_admin_key(x_admin_key)
    return {"clients": list_clients_safe()}


@app.get("/api/admin/usage-summary")
def admin_usage_summary(
    client_id: Optional[str] = None,
    x_admin_key: Optional[str] = Header(default=None),
):
    _check_admin_key(x_admin_key)
    return get_usage_summary(client_id=client_id)


@app.post("/api/admin/reload-clients")
def admin_reload_clients(x_admin_key: Optional[str] = Header(default=None)):
    _check_admin_key(x_admin_key)
    clients = reload_clients()
    return {"status": "ok", "count": len(clients)}


@app.post("/api/admin/clients")
def admin_create_client(req: ClientCreateRequest, x_admin_key: Optional[str] = Header(default=None)):
    _check_admin_key(x_admin_key)
    try:
        created = create_client(req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"client": sanitize_client(created), "api_key": created["api_key"]}


@app.patch("/api/admin/clients/{client_id}")
def admin_patch_client(
    client_id: str,
    req: ClientPatchRequest,
    x_admin_key: Optional[str] = Header(default=None),
):
    _check_admin_key(x_admin_key)
    patch = {k: v for k, v in req.model_dump().items() if v is not None}
    if not patch:
        raise HTTPException(status_code=400, detail="No fields provided for update")
    try:
        updated = update_client(client_id, patch)
    except KeyError:
        raise HTTPException(status_code=404, detail="Client not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"client": sanitize_client(updated)}


@app.get("/api/admin/contact-requests")
def admin_contact_requests(x_admin_key: Optional[str] = Header(default=None)):
    _check_admin_key(x_admin_key)
    requests = read_contact_requests()
    return {"contact_requests": requests}


@app.post("/api/admin/clients/{client_id}/rotate-key")
def admin_rotate_client_key(client_id: str, x_admin_key: Optional[str] = Header(default=None)):
    _check_admin_key(x_admin_key)
    try:
        updated = rotate_client_key(client_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Client not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"client": sanitize_client(updated), "api_key": updated["api_key"]}