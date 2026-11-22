"""Pure deterministic canonical JSON serialization and SHA-256 hashing."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import ipaddress
import json
from typing import Any
from uuid import UUID


def _normalize_value(value: Any) -> Any:
    """Recursively normalize Python types into deterministic JSON-compatible structures."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {str(k): _normalize_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    return value


def canonicalize_json(data: Any) -> str:
    """Serialize data into a canonical JSON string with sorted keys and no extra whitespace."""
    normalized = _normalize_value(data)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_sha256_hash(data: Any) -> str:
    """Compute a deterministic lowercase hexadecimal SHA-256 digest over canonicalized data."""
    canonical_payload = canonicalize_json(data)
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def verify_sha256_hash(data: Any, expected_hash: str) -> bool:
    """Verify in constant time that data matches the expected SHA-256 hex digest."""
    if not expected_hash or len(expected_hash) != 64:
        return False
    computed = compute_sha256_hash(data)
    return hmac.compare_digest(computed, expected_hash.lower())
