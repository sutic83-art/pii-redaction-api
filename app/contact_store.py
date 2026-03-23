import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_LOCK = Lock()


def _contact_requests_path() -> Path:
    # Keep storage local to the app container and repo.
    return Path(os.getenv("CONTACT_REQUESTS_FILE", str(DATA_DIR / "contact_requests.jsonl")))


def append_contact_request(
    *,
    full_name: str,
    email: str,
    company: Optional[str],
    message: str,
    request_id: Optional[str] = None,
) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "full_name": full_name,
        "email": email,
        "company": company,
        "message": message,
    }
    if request_id:
        payload["request_id"] = request_id

    path = _contact_requests_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(payload, ensure_ascii=False)
    with _LOCK:
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

