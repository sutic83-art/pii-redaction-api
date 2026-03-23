import json
import os
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