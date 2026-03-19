import os

os.environ["API_KEYS"] = "test-key-123"
os.environ["HASH_SALT"] = "test-salt"
os.environ["RATE_LIMIT_PER_MINUTE"] = "200"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

VALID_JMBG = "0101990712345"
VALID_PIB = "100000049"
VALID_MB_COMPANY = "17580175"
VALID_EMAIL = "kontakt@example.rs"
VALID_PHONE = "+381 64 123 4567"
VALID_IBAN = "RS69 1234 5678 9012 3456 78"
VALID_CARD = "4111 1111 1111 1111"

INVALID_JMBG = "0101990712346"
INVALID_PIB = "123456789"
INVALID_EMAIL = "kontakt@@example.rs"
INVALID_PHONE = "12345"
INVALID_IBAN = "RS00 1234 5678 9012 3456 78"
INVALID_CARD = "4111 1111 1111 1112"

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
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_redact_mask_all_supported_entities():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
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


def test_entities_filter_only_email_and_phone():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={
            "text": FULL_TEXT,
            "policy": "mask",
            "entities": ["EMAIL", "PHONE"],
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert VALID_EMAIL not in body["redacted_text"]
    assert VALID_PHONE not in body["redacted_text"]

    assert VALID_JMBG in body["redacted_text"]
    assert VALID_PIB in body["redacted_text"]
    assert VALID_MB_COMPANY in body["redacted_text"]
    assert VALID_IBAN in body["redacted_text"]
    assert VALID_CARD in body["redacted_text"]

    assert len(body["detections"]) == 2


def test_invalid_identifiers_are_not_redacted():
    text = (
        f"JMBG {INVALID_JMBG}; "
        f"PIB {INVALID_PIB}; "
        f"email {INVALID_EMAIL}; "
        f"telefon {INVALID_PHONE}; "
        f"IBAN {INVALID_IBAN}; "
        f"kartica {INVALID_CARD}"
    )

    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"text": text, "policy": "mask"},
    )
    assert response.status_code == 200

    body = response.json()
    assert INVALID_JMBG in body["redacted_text"]
    assert INVALID_PIB in body["redacted_text"]
    assert INVALID_EMAIL in body["redacted_text"]
    assert INVALID_PHONE in body["redacted_text"]
    assert INVALID_IBAN in body["redacted_text"]
    assert INVALID_CARD in body["redacted_text"]
    assert len(body["detections"]) == 0


def test_redact_hash_card_number():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"text": f"Kartica {VALID_CARD}", "policy": "hash"},
    )
    assert response.status_code == 200

    body = response.json()
    assert VALID_CARD not in body["redacted_text"]
    assert len(body["redacted_text"]) > 20
    assert body["policy"] == "hash"


def test_redact_remove_iban():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"text": f"IBAN {VALID_IBAN}", "policy": "rm"},
    )
    assert response.status_code == 200

    body = response.json()
    assert VALID_IBAN not in body["redacted_text"]


def test_unauthorized():
    response = client.post(
        "/api/v1/redact",
        json={"text": FULL_TEXT, "policy": "mask"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_bad_policy():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"text": FULL_TEXT, "policy": "bad"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_api_v1_route_works():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"text": f"JMBG {VALID_JMBG}", "policy": "mask"},
    )
    assert response.status_code == 200


def test_validation_error_shape():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key-123"},
        json={"policy": "mask"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"