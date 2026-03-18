import hashlib
import os


def apply_policy(value: str, policy: str) -> str:
    mode = (policy or "mask").strip().lower()

    if mode == "mask":
        return "*" * len(value)

    if mode == "hash":
        salt = os.getenv("HASH_SALT", "change-me")
        raw = f"{salt}:{value}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    if mode == "rm":
        return ""

    raise ValueError(f"Unsupported policy: {policy}")
