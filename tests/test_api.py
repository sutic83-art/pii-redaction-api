import os

os.environ["API_KEYS"] = "test-key"
os.environ["HASH_SALT"] = "test-salt"
os.environ["RATE_LIMIT_PER_MINUTE"] = "30"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

VALID_JMBG = "0101990712345"
VALID_PIB = "100000049"
INVALID_JMBG = "0101990712346"
INVALID_PIB = "123456789"


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "version" in response.json()


def test_redact_mask_valid_identifiers():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"JMBG {VALID_JMBG} i PIB {VALID_PIB}", "policy": "mask"},
    )
    assert response.status_code == 200
    body = response.json()
    assert VALID_JMBG not in body["redacted_text"]
    assert VALID_PIB not in body["redacted_text"]
    assert len(body["detections"]) == 2


def test_invalid_identifiers_are_not_redacted():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"JMBG {INVALID_JMBG} i PIB {INVALID_PIB}", "policy": "mask"},
    )
    assert response.status_code == 200
    body = response.json()
    assert INVALID_JMBG in body["redacted_text"]
    assert INVALID_PIB in body["redacted_text"]
    assert len(body["detections"]) == 0


def test_redact_hash_pib():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"PIB firme je {VALID_PIB}", "policy": "hash"},
    )
    assert response.status_code == 200
    body = response.json()
    assert VALID_PIB not in body["redacted_text"]
    assert len(body["redacted_text"]) > 20
    assert body["policy"] == "hash"


def test_redact_remove():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"JMBG {VALID_JMBG}", "policy": "rm"},
    )
    assert response.status_code == 200
    body = response.json()
    assert VALID_JMBG not in body["redacted_text"]


def test_unauthorized():
    response = client.post(
        "/redact",
        json={"text": f"JMBG {VALID_JMBG}", "policy": "mask"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_bad_policy():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"JMBG {VALID_JMBG}", "policy": "bad"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_api_v1_route_works():
    response = client.post(
        "/api/v1/redact",
        headers={"x-api-key": "test-key"},
        json={"text": f"JMBG {VALID_JMBG}", "policy": "mask"},
    )
    assert response.status_code == 200


def test_validation_error_shape():
    response = client.post(
        "/redact",
        headers={"x-api-key": "test-key"},
        json={"policy": "mask"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"