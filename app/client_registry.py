import json
import os
import secrets
import string
from pathlib import Path
from threading import Lock
from typing import Optional


DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_CACHE = {
    "stamp": None,
    "clients": [],
    "by_key": {},
}
_LOCK = Lock()


def _int_or_default(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _source_stamp():
    raw_env = os.getenv("CLIENTS_JSON", "").strip()
    if raw_env:
        return ("env", raw_env)

    path = Path(os.getenv("CLIENTS_FILE", str(DATA_DIR / "clients.json")))
    if not path.exists():
        return ("file-missing", str(path))

    return ("file", str(path), path.stat().st_mtime)


def _read_payload():
    raw_env = os.getenv("CLIENTS_JSON", "").strip()
    if raw_env:
        return json.loads(raw_env)

    path = Path(os.getenv("CLIENTS_FILE", str(DATA_DIR / "clients.json")))
    if not path.exists():
        return {"clients": []}

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _clients_file_path() -> Optional[Path]:
    # Keep CLIENTS_JSON support for read-only/runtime overrides.
    if os.getenv("CLIENTS_JSON", "").strip():
        return None
    return Path(os.getenv("CLIENTS_FILE", str(DATA_DIR / "clients.json")))


def _normalize_allowed_entities(value):
    if not value:
        return ["*"]

    normalized = [str(item).strip().upper() for item in value if str(item).strip()]
    if not normalized or "*" in normalized:
        return ["*"]

    return normalized


def _normalize_client(item: dict):
    client_id = str(item.get("client_id", "")).strip()
    client_name = str(item.get("client_name") or client_id).strip()
    api_key = str(item.get("api_key", "")).strip()
    status = str(item.get("status", "active")).strip().lower()
    plan = str(item.get("plan", "standard")).strip()

    if not client_id or not api_key:
        return None

    return {
        "client_id": client_id,
        "client_name": client_name,
        "api_key": api_key,
        "status": status,
        "plan": plan,
        "rate_limit_per_minute": _int_or_default(item.get("rate_limit_per_minute", 30), 30),
        "monthly_quota": _int_or_default(item.get("monthly_quota", 0), 0),
        "allowed_entities": _normalize_allowed_entities(item.get("allowed_entities", ["*"])),
    }


def _sanitize_and_validate_client(item: dict) -> dict:
    client = _normalize_client(item)
    if not client:
        raise ValueError("Invalid client payload")
    return client


def _random_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _next_unique_api_key(existing_clients: list[dict]) -> str:
    used = {item.get("api_key", "") for item in existing_clients}
    for _ in range(20):
        key = _random_api_key()
        if key not in used:
            return key
    raise RuntimeError("Failed to generate unique API key")


def _read_clients_from_source_unlocked() -> list[dict]:
    payload = _read_payload()
    raw_clients = payload.get("clients", []) if isinstance(payload, dict) else []
    clients = []
    for item in raw_clients:
        client = _normalize_client(item)
        if client:
            clients.append(client)
    return clients


def _write_clients_file_unlocked(clients: list[dict]):
    path = _clients_file_path()
    if path is None:
        raise ValueError("Client management is disabled while CLIENTS_JSON is set")

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"clients": clients}
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")

    _CACHE["stamp"] = None
    _CACHE["clients"] = []
    _CACHE["by_key"] = {}
    _load_clients_unlocked()


def _load_clients_unlocked():
    stamp = _source_stamp()
    if _CACHE["stamp"] == stamp:
        return _CACHE["clients"]

    payload = _read_payload()
    raw_clients = payload.get("clients", []) if isinstance(payload, dict) else []

    clients = []
    by_key = {}

    for item in raw_clients:
        client = _normalize_client(item)
        if not client:
            continue
        clients.append(client)
        by_key[client["api_key"]] = client

    _CACHE["stamp"] = stamp
    _CACHE["clients"] = clients
    _CACHE["by_key"] = by_key
    return clients


def get_clients():
    with _LOCK:
        return list(_load_clients_unlocked())


def get_client_by_api_key(api_key: Optional[str]):
    if not api_key:
        return None

    with _LOCK:
        _load_clients_unlocked()
        return _CACHE["by_key"].get(api_key.strip())


def reload_clients():
    with _LOCK:
        _CACHE["stamp"] = None
        _CACHE["clients"] = []
        _CACHE["by_key"] = {}
        return list(_load_clients_unlocked())


def sanitize_client(client: dict) -> dict:
    return {
        "client_id": client["client_id"],
        "client_name": client["client_name"],
        "status": client["status"],
        "plan": client["plan"],
        "rate_limit_per_minute": client["rate_limit_per_minute"],
        "monthly_quota": client["monthly_quota"],
        "allowed_entities": client["allowed_entities"],
        "api_key_hint": f"...{client['api_key'][-4:]}",
    }


def list_clients_safe():
    return [sanitize_client(client) for client in get_clients()]


def create_client(payload: dict) -> dict:
    with _LOCK:
        clients = _read_clients_from_source_unlocked()
        client_id = str(payload.get("client_id", "")).strip()
        if not client_id:
            raise ValueError("client_id is required")

        if any(item.get("client_id") == client_id for item in clients):
            raise ValueError("client_id already exists")

        candidate = {
            "client_id": client_id,
            "client_name": payload.get("client_name", client_id),
            "api_key": _next_unique_api_key(clients),
            "status": payload.get("status", "active"),
            "plan": payload.get("plan", "standard"),
            "rate_limit_per_minute": payload.get("rate_limit_per_minute", 30),
            "monthly_quota": payload.get("monthly_quota", 0),
            "allowed_entities": payload.get("allowed_entities", ["*"]),
        }
        created = _sanitize_and_validate_client(candidate)
        clients.append(created)
        _write_clients_file_unlocked(clients)
        return created


def update_client(client_id: str, patch: dict) -> dict:
    with _LOCK:
        clients = _read_clients_from_source_unlocked()
        target_idx = next((i for i, item in enumerate(clients) if item.get("client_id") == client_id), -1)
        if target_idx < 0:
            raise KeyError("client not found")

        current = clients[target_idx]
        updated = {
            **current,
            "client_name": patch.get("client_name", current.get("client_name")),
            "plan": patch.get("plan", current.get("plan")),
            "status": patch.get("status", current.get("status")),
            "rate_limit_per_minute": patch.get(
                "rate_limit_per_minute",
                current.get("rate_limit_per_minute"),
            ),
            "monthly_quota": patch.get("monthly_quota", current.get("monthly_quota")),
            "allowed_entities": patch.get("allowed_entities", current.get("allowed_entities")),
        }
        normalized = _sanitize_and_validate_client(updated)
        clients[target_idx] = normalized
        _write_clients_file_unlocked(clients)
        return normalized


def rotate_client_key(client_id: str) -> dict:
    with _LOCK:
        clients = _read_clients_from_source_unlocked()
        target_idx = next((i for i, item in enumerate(clients) if item.get("client_id") == client_id), -1)
        if target_idx < 0:
            raise KeyError("client not found")

        next_key = _next_unique_api_key(clients)
        updated = {
            **clients[target_idx],
            "api_key": next_key,
        }
        normalized = _sanitize_and_validate_client(updated)
        clients[target_idx] = normalized
        _write_clients_file_unlocked(clients)
        return normalized