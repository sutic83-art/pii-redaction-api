import os
import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request


_BUCKETS = defaultdict(deque)
_LOCK = Lock()


def _limit_per_minute() -> int:
    raw = os.getenv("RATE_LIMIT_PER_MINUTE", "30").strip()
    try:
        value = int(raw)
        return max(1, value)
    except ValueError:
        return 30


def _client_key(request: Request) -> str:
    api_key = request.headers.get("x-api-key")
    if api_key:
        return f"api_key:{api_key}"

    if request.client and request.client.host:
        return f"ip:{request.client.host}"

    return "ip:unknown"


def enforce_rate_limit(request: Request):
    key = _client_key(request)
    now = time.time()
    window_seconds = 60
    limit = _limit_per_minute()

    with _LOCK:
        bucket = _BUCKETS[key]

        while bucket and (now - bucket[0]) > window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Limit is {limit} requests per minute.",
            )

        bucket.append(now)