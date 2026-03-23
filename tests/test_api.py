# ruff: noqa: E402
import os
from pathlib import Path

os.environ["HASH_SALT"] = "test-salt"
os.environ["RATE_LIMIT_PER_MINUTE"] = "200"
os.environ["ADMIN_API_KEY"] = "admin-key-123"
os.environ["CLIENTS_FILE"] = "data/clients.json"
os.environ["USAGE_LOG_FILE"] = "data/test_usage_events.jsonl"

Path(os.environ["USAGE_LOG_FILE"]).unlink(missing_ok=True)

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