"""Unit tests for Art. 2° Ley N° 21.459 exemption evaluator and scope validator."""

from datetime import datetime, timedelta, timezone

from app.compliance_engine.rules_evaluator import (
    ComplianceEvaluationInput,
    evaluate_art2_ley21459,
)
from app.compliance_engine.scope_validator import (
    is_target_in_scope,
    validate_auditor_source_ips,
    validate_scope_assets,
)


def _valid_compliance_input() -> ComplianceEvaluationInput:
    now = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)
    return ComplianceEvaluationInput(
        roe_status="ACTIVE",
        client_signed_at=now - timedelta(days=2),
        auditor_signed_at=now - timedelta(days=1),
        sha256_hash="a" * 64,
        execution_start=now - timedelta(hours=1),
        execution_end=now + timedelta(hours=5),
        target_assets=["api.cliente.cl", "190.10.20.0/24"],
        excluded_assets=["190.10.20.10"],
        auditor_source_ips=["200.50.10.5"],
        traffic_header_token="X-Assessment-Scope: LXP-2026-001",
        client_poc_id="poc-uuid-001",
        backup_confirmed=True,
        cloud_authorization_confirmed=True,
        uses_third_party_cloud=False,
        evaluation_time=now,
        action_target_host="api.cliente.cl",
        action_source_ip="200.50.10.5",
    )


def test_art2_all_conditions_met_grants_exemption():
    result = evaluate_art2_ley21459(_valid_compliance_input())
    assert result.is_exempt is True
    assert result.failed_conditions == []
    assert len(result.conditions) == 4


def test_art2_fails_when_roe_not_signed_or_draft():
    data = _valid_compliance_input()
    draft_data = ComplianceEvaluationInput(**{**data.__dict__, "roe_status": "DRAFT"})
    result = evaluate_art2_ley21459(draft_data)
    assert result.is_exempt is False
    assert "COND_1_PRIOR_AUTHORIZATION" in result.failed_conditions


def test_art2_fails_outside_time_window():
    data = _valid_compliance_input()
    late = ComplianceEvaluationInput(
        **{**data.__dict__, "evaluation_time": data.execution_end + timedelta(minutes=1)}
    )
    result = evaluate_art2_ley21459(late)
    assert result.is_exempt is False
    assert "COND_1_PRIOR_AUTHORIZATION" in result.failed_conditions


def test_art2_fails_without_backup_confirmation():
    data = _valid_compliance_input()
    no_backup = ComplianceEvaluationInput(**{**data.__dict__, "backup_confirmed": False})
    result = evaluate_art2_ley21459(no_backup)
    assert result.is_exempt is False
    assert "COND_2_NO_MALICIOUS_INTENT" in result.failed_conditions


def test_art2_fails_when_target_is_excluded_or_out_of_scope():
    data = _valid_compliance_input()
    excluded_target = ComplianceEvaluationInput(**{**data.__dict__, "action_target_host": "190.10.20.10"})
    result = evaluate_art2_ley21459(excluded_target)
    assert result.is_exempt is False
    assert "COND_3_OPERATIONAL_LIMITS" in result.failed_conditions


def test_art2_fails_when_source_ip_not_enrolled():
    data = _valid_compliance_input()
    rogue_ip = ComplianceEvaluationInput(**{**data.__dict__, "action_source_ip": "45.33.22.11"})
    result = evaluate_art2_ley21459(rogue_ip)
    assert result.is_exempt is False
    assert "COND_3_OPERATIONAL_LIMITS" in result.failed_conditions


def test_art2_fails_without_poc_or_header_token():
    data = _valid_compliance_input()
    no_poc = ComplianceEvaluationInput(**{**data.__dict__, "client_poc_id": ""})
    result = evaluate_art2_ley21459(no_poc)
    assert result.is_exempt is False
    assert "COND_4_REPORTING_DUTY" in result.failed_conditions


def test_scope_validator_blocks_state_domains_and_overlaps():
    res_state = validate_scope_assets(["portal.gob.cl", "api.empresa.cl"])
    assert res_state.is_valid is False
    assert any("estatal" in err for err in res_state.errors)

    res_overlap = validate_scope_assets(["190.10.20.0/24"], excluded_assets=["190.10.20.5"])
    assert res_overlap.is_valid is False
    assert any("Conflicto" in err for err in res_overlap.errors)


def test_scope_validator_accepts_valid_assets_and_public_ips():
    res = validate_scope_assets(["*.empresa.cl", "200.14.10.0/24"], excluded_assets=["db.empresa.cl"])
    assert res.is_valid is True
    assert is_target_in_scope("app.empresa.cl", ["*.empresa.cl"], ["db.empresa.cl"]) is True
    assert is_target_in_scope("db.empresa.cl", ["*.empresa.cl"], ["db.empresa.cl"]) is False

    ip_res = validate_auditor_source_ips(["200.50.10.5"])
    assert ip_res.is_valid is True

    private_ip_res = validate_auditor_source_ips(["192.168.1.10"])
    assert private_ip_res.is_valid is False
