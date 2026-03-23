import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_LOCK = Lock()


def _usage_path() -> Path:
    return Path(os.getenv("USAGE_LOG_FILE", str(DATA_DIR / "usage_events.jsonl")))


def append_usage_event(event: dict):
    path = _usage_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(event, ensure_ascii=False)
    with _LOCK:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


def _iter_events():
    path = _usage_path()
    if not path.exists():
        return

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def get_monthly_request_count(client_id: str, month: str | None = None) -> int:
    target_month = month or datetime.now(timezone.utc).strftime("%Y-%m")
    count = 0

    for event in _iter_events() or []:
        if event.get("client_id") == client_id and str(event.get("ts", "")).startswith(target_month):
            count += 1

    return count


def get_usage_summary(client_id: str | None = None) -> dict:
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")

    per_client = defaultdict(
        lambda: {
            "client_name": "",
            "total_requests": 0,
            "current_month_requests": 0,
            "last_request_at": None,
        }
    )

    total_requests = 0
    current_month_requests = 0

    for event in _iter_events() or []:
        cid = event.get("client_id", "unknown")

        if client_id and cid != client_id:
            continue

        total_requests += 1

        item = per_client[cid]
        item["client_name"] = event.get("client_name", "")
        item["total_requests"] += 1

        ts = str(event.get("ts", ""))
        if ts.startswith(current_month):
            item["current_month_requests"] += 1
            current_month_requests += 1

        if ts and (item["last_request_at"] is None or ts > item["last_request_at"]):
            item["last_request_at"] = ts

    clients = [
        {
            "client_id": cid,
            **data,
        }
        for cid, data in sorted(per_client.items())
    ]

    return {
        "month": current_month,
        "total_requests": total_requests,
        "current_month_requests": current_month_requests,
        "clients": clients,
    }