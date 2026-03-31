"""Shared utility functions."""

import hashlib
import hmac
import secrets


def generate_api_key() -> str:
    """Generate a new API key."""
    return f"cg_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """SHA-256 hash of an API key for storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(api_key: str, api_key_hash: str) -> bool:
    """Constant-time comparison of API key against stored hash."""
    return hmac.compare_digest(hash_api_key(api_key), api_key_hash)


def sanitize_path(path: str) -> str:
    """Remove user-home prefix from paths for safe logging."""
    import os

    home = os.path.expanduser("~")
    if path.startswith(home):
        return "~" + path[len(home) :]
    return path


def truncate(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length, appending '...' if truncated."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
