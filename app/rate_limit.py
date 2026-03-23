import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException


_BUCKETS = defaultdict(deque)
_LOCK = Lock()


def _normalize_limit(limit, default: int = 30) -> int:
    try:
        value = int(limit)
        return max(1, value)
    except (TypeError, ValueError):
        return default


def enforce_rate_limit(subject: str, limit: int):
    subject = subject or "unknown"
    limit = _normalize_limit(limit)
    now = time.time()
    window_seconds = 60

    with _LOCK:
        bucket = _BUCKETS[subject]

        while bucket and (now - bucket[0]) > window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Limit is {limit} requests per minute.",
            )

        bucket.append(now)