import hashlib
import json
import logging
import os
from datetime import datetime, timezone


logger = logging.getLogger("audit")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def _sha256_with_salt(value: str) -> str:
    salt = os.getenv("HASH_SALT", "change-me")
    raw = f"{salt}:{value}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def audit_event(text: str, policy: str, entities: list):
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "policy": policy,
        "sha": _sha256_with_salt(text),
        "entity_count": len(entities),
        "entities": sorted(list({e["entity_type"] for e in entities})),
    }
    logger.info(json.dumps(payload, ensure_ascii=False))
    return payload
