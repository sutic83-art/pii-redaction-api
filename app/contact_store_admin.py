import json
from typing import List, Optional
from threading import Lock

from .contact_store import _contact_requests_path

_LOCK = Lock()


def read_contact_requests(limit: Optional[int] = None) -> List[dict]:
    """
    Read contact requests from the JSONL file in reverse chronological order.
    
    Args:
        limit: Maximum number of requests to return (most recent first)
    
    Returns:
        List of contact request dictionaries
    """
    path = _contact_requests_path()
    
    if not path.exists():
        return []
    
    requests = []
    
    with _LOCK:
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            request = json.loads(line)
                            requests.append(request)
                        except json.JSONDecodeError:
                            # Skip malformed lines
                            continue
        except (OSError, IOError):
            # If file can't be read, return empty list
            return []
    
    # Sort by timestamp in reverse chronological order (newest first)
    requests.sort(key=lambda x: x.get("ts", ""), reverse=True)
    
    if limit is not None and limit > 0:
        requests = requests[:limit]
    
    return requests
