# ruff: noqa: E402
import json
import os
import shutil
from pathlib import Path

os.environ["HASH_SALT"] = "test-salt"
os.environ["RATE_LIMIT_PER_MINUTE"] = "200"
os.environ["ADMIN_API_KEY"] = "admin-key-123"
TEST_CLIENTS_FILE = "data/test_clients.json"
shutil.copyfile("data/clients.json", TEST_CLIENTS_FILE)
os.environ["CLIENTS_FILE"] = TEST_CLIENTS_FILE
os.environ["USAGE_LOG_FILE"] = "data/test_usage_events.jsonl"

Path(os.environ["USAGE_LOG_FILE"]).unlink(missing_ok=True)
Path("data/contact_requests.jsonl").unlink(missing_ok=True)
Path(TEST_CLIENTS_FILE).unlink(missing_ok=True)
shutil.copyfile("data/clients.json", TEST_CLIENTS_FILE)

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

DEMO_KEY = "demo-local-key-123"
FINANCE_KEY = "finance-pilot-key-123"
DISABLED_KEY = "disabled-key-123"
ADMIN_KEY = "admin-key-123"

VALID_JMBG = "0101990712345"
VALID_PIB = "100000049"
VALID_MB_COMPANY = "17580175"
VALID_EMAIL = "kontakt@example.rs"
VALID_PHONE = "+381 64 123 4567"
VALID_IBAN = "RS69 1234 5678 9012 3456 78"
VALID_CARD = "4111 1111 1111 1111"

FULL_TEXT = (
    f"JMBG {VALID_JMBG}; "
    f"PIB {VALID_PIB}; "
    f"matični broj {VALID_MB_COMPANY}; "
    f"email {VALID_EMAIL}; "
    f"telefon {VALID_PHONE}; "
    f"IBAN {VALID_IBAN}; "
    f"kartica {VALID_CARD}"
)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_redact_mask_all_supported_entities_for_demo_client():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": DEMO_KEY},
        json={"text": FULL_TEXT, "policy": "mask"},
    )
    assert response.status_code == 200

    body = response.json()
    assert VALID_JMBG not in body["redacted_text"]
    assert VALID_PIB not in body["redacted_text"]
    assert VALID_MB_COMPANY not in body["redacted_text"]
    assert VALID_EMAIL not in body["redacted_text"]
    assert VALID_PHONE not in body["redacted_text"]
    assert VALID_IBAN not in body["redacted_text"]
    assert VALID_CARD not in body["redacted_text"]
    assert len(body["detections"]) == 7


def test_finance_client_only_redacts_allowed_entities():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": FINANCE_KEY},
        json={"text": FULL_TEXT, "policy": "mask"},
    )
    assert response.status_code == 200

    body = response.json()
    assert VALID_PIB not in body["redacted_text"]
    assert VALID_MB_COMPANY not in body["redacted_text"]
    assert VALID_IBAN not in body["redacted_text"]
    assert VALID_CARD not in body["redacted_text"]

    assert VALID_JMBG in body["redacted_text"]
    assert VALID_EMAIL in body["redacted_text"]
    assert VALID_PHONE in body["redacted_text"]


def test_forbidden_requested_entities_for_finance_client():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": FINANCE_KEY},
        json={
            "text": FULL_TEXT,
            "policy": "mask",
            "entities": ["EMAIL", "PHONE"],
        },
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_disabled_client_is_blocked():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": DISABLED_KEY},
        json={"text": FULL_TEXT, "policy": "mask"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_unauthorized_client():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "wrong-key"},
        json={"text": FULL_TEXT, "policy": "mask"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_admin_clients_endpoint():
    response = client.get(
        "/api/admin/clients",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert response.status_code == 200

    body = response.json()
    assert "clients" in body
    assert len(body["clients"]) >= 2
    assert "api_key" not in body["clients"][0]
    assert "api_key_hint" in body["clients"][0]


def test_admin_usage_summary_endpoint():
    client.post(
        "/api/v1/redact",
        headers={"x-api-key": DEMO_KEY},
        json={"text": FULL_TEXT, "policy": "mask"},
    )

    response = client.get(
        "/api/admin/usage-summary",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert response.status_code == 200

    body = response.json()
    assert "clients" in body
    assert body["total_requests"] >= 1


def test_admin_reload_clients_endpoint():
    response = client.post(
        "/api/admin/reload-clients",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_bad_policy():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": DEMO_KEY},
        json={"text": FULL_TEXT, "policy": "bad"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_validation_error_shape():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": DEMO_KEY},
        json={"policy": "mask"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_contact_endpoint_success_stores_jsonl():
    payload = {
        "full_name": "Jane Doe",
        "email": "jane@example.com",
        "company": "ACME",
        "message": "Hello, I'd like to talk.",
    }

    response = client.post("/api/contact", json=payload)
    assert response.status_code == 200
    assert response.json() == {"success": {"status": "ok"}}

    path = Path("data/contact_requests.jsonl")
    assert path.exists()

    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines
    last = json.loads(lines[-1])

    assert last["full_name"] == payload["full_name"]
    assert last["email"] == payload["email"]
    assert last["company"] == payload["company"]
    assert last["message"] == payload["message"]
    assert "ts" in last
    assert "request_id" in last


def test_contact_endpoint_validation_error_shape():
    response = client.post(
        "/api/contact",
        json={
            "email": "jane@example.com",
            "company": "ACME",
            # missing full_name and message
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_admin_create_client_returns_api_key_once():
    response = client.post(
        "/api/admin/clients",
        headers={"x-admin-key": ADMIN_KEY},
        json={
            "client_id": "new-client",
            "client_name": "New Client",
            "plan": "pilot",
            "status": "active",
            "rate_limit_per_minute": 55,
            "monthly_quota": 1234,
            "allowed_entities": ["EMAIL", "PHONE"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "client" in body
    assert "api_key" in body
    assert body["client"]["client_id"] == "new-client"
    assert "api_key" not in body["client"]
    assert len(body["api_key"]) >= 20


def test_admin_patch_client_updates_plan_and_limits():
    response = client.patch(
        "/api/admin/clients/finance-pilot",
        headers={"x-admin-key": ADMIN_KEY},
        json={
            "plan": "business",
            "rate_limit_per_minute": 77,
            "allowed_entities": ["*"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["client"]["plan"] == "business"
    assert body["client"]["rate_limit_per_minute"] == 77
    assert body["client"]["allowed_entities"] == ["*"]


def test_admin_contact_requests_endpoint():
    # First, create a contact request
    payload = {
        "full_name": "John Doe",
        "email": "john@example.com", 
        "company": "Test Corp",
        "message": "Test message for admin view",
    }
    response = client.post("/api/contact", json=payload)
    assert response.status_code == 200

    # Then retrieve via admin API
    response = client.get(
        "/api/admin/contact-requests",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert response.status_code == 200

    body = response.json()
    assert "contact_requests" in body
    assert len(body["contact_requests"]) >= 1
    
    # Check the structure of the first request
    request = body["contact_requests"][0]
    assert "ts" in request
    assert "full_name" in request
    assert "email" in request
    assert "company" in request
    assert "message" in request
    assert "request_id" in request
    
    # Verify it's in reverse chronological order (newest first)
    assert request["full_name"] == "John Doe"
    assert request["email"] == "john@example.com"


def test_admin_contact_requests_endpoint_unauthorized():
    response = client.get("/api/admin/contact-requests")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_admin_rotate_key_changes_key_for_client():
    before = client.get("/api/admin/clients", headers={"x-admin-key": ADMIN_KEY})
    assert before.status_code == 200
    old_hint = next(
        item["api_key_hint"]
        for item in before.json()["clients"]
        if item["client_id"] == "demo-local"
    )

    rotate = client.post(
        "/api/admin/clients/demo-local/rotate-key",
        headers={"x-admin-key": ADMIN_KEY},
    )
    assert rotate.status_code == 200
    body = rotate.json()
    assert "api_key" in body
    assert body["client"]["client_id"] == "demo-local"

    after = client.get("/api/admin/clients", headers={"x-admin-key": ADMIN_KEY})
    assert after.status_code == 200
    new_hint = next(
        item["api_key_hint"]
        for item in after.json()["clients"]
        if item["client_id"] == "demo-local"
    )
    assert new_hint != old_hint