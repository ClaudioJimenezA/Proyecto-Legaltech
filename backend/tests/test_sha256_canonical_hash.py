"""Unit tests for deterministic canonical JSON serialization and SHA-256 hashing."""

from datetime import datetime, timezone
from uuid import UUID

from app.compliance_engine.canonical_hasher import (
    canonicalize_json,
    compute_sha256_hash,
    verify_sha256_hash,
)


def test_canonical_hash_is_invariant_to_key_order():
    payload_a = {
        "title": "Pentest Q4",
        "version": 1,
        "target_assets": ["api.empresa.cl", "200.10.20.0/24"],
        "metadata": {"backup_confirmed": True, "cloud": False},
    }
    payload_b = {
        "metadata": {"cloud": False, "backup_confirmed": True},
        "target_assets": ["api.empresa.cl", "200.10.20.0/24"],
        "version": 1,
        "title": "Pentest Q4",
    }

    assert canonicalize_json(payload_a) == canonicalize_json(payload_b)
    assert compute_sha256_hash(payload_a) == compute_sha256_hash(payload_b)
    assert len(compute_sha256_hash(payload_a)) == 64


def test_canonical_hash_handles_datetime_and_uuid_deterministically():
    uid = UUID("12345678-1234-5678-1234-567812345678")
    dt_utc = datetime(2026, 11, 17, 15, 0, 0, tzinfo=timezone.utc)
    dt_naive = datetime(2026, 11, 17, 15, 0, 0)

    hash_utc = compute_sha256_hash({"id": uid, "ts": dt_utc})
    hash_naive = compute_sha256_hash({"id": str(uid), "ts": dt_naive})

    assert hash_utc == hash_naive


def test_verify_sha256_hash_detects_tampering():
    roe_data = {"title": "RoE Oficial", "scope": ["app.cliente.cl"]}
    digest = compute_sha256_hash(roe_data)

    assert verify_sha256_hash(roe_data, digest) is True
    assert verify_sha256_hash({"title": "RoE Modificado", "scope": ["app.cliente.cl"]}, digest) is False
    assert verify_sha256_hash(roe_data, "invalid_short_hash") is False
