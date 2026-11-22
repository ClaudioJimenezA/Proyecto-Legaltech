"""Tier 1 unit tests for spatiotemporal SOC/ANCI deconfliction matcher (+-2 minute window)."""

from datetime import datetime, timedelta, timezone

from app.compliance_engine.deconfliction_matcher import (
    DeconflictionResolution,
    IncidentAlarmInput,
    LogCandidate,
    compute_log_record_hash,
    match_incident_against_logs,
)


def _sample_log(
    *,
    started_at: datetime,
    ended_at: datetime | None = None,
    source_ip: str = "181.43.22.10",
    target_host: str = "api.cliente.cl",
) -> LogCandidate:
    return LogCandidate(
        log_id="log-uuid-001",
        agreement_id="roe-uuid-001",
        started_at=started_at,
        ended_at=ended_at,
        source_ip=source_ip,
        target_host=target_host,
        target_port=443,
        target_endpoint="/api/v1/auth/login",
        http_method="POST",
        injected_header_token="LEXPLOIT-2026-TOKEN",
        activity_type="AUTH_ATTEMPT",
        tool_or_technique="Burp Suite Intruder / Password Spraying PoC",
        description="Prueba controlada de bloqueo de cuenta por intentos fallidos.",
        record_hash="a" * 64,
    )


def test_match_within_plus_minus_2_minutes_is_confirmed_authorized():
    """Events within +-2 minutes with matching IP and asset must resolve as CONFIRMED_AUTHORIZED."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time)

    # SIEM alarm arrives 95 seconds AFTER started_at (within +120s tolerance)
    alarm_after = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=95),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="https://api.cliente.cl:443/api/v1/auth/login",
        internal_ticket_ref="INC-2026-904",
    )
    result_after = match_incident_against_logs(alarm_after, [log_entry])

    assert result_after.resolution == DeconflictionResolution.CONFIRMED_AUTHORIZED
    assert result_after.matched_log_id == "log-uuid-001"
    assert result_after.anci_report_required is False
    assert result_after.time_delta_seconds == 95.0

    # SIEM alarm arrives 110 seconds BEFORE started_at (NTP drift within -120s tolerance)
    alarm_before = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time - timedelta(seconds=110),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    result_before = match_incident_against_logs(alarm_before, [log_entry])

    assert result_before.resolution == DeconflictionResolution.CONFIRMED_AUTHORIZED
    assert result_before.matched_log_id == "log-uuid-001"
    assert result_before.anci_report_required is False
    assert result_before.time_delta_seconds == 110.0


def test_match_at_exact_120_second_boundary():
    """Exact 120-second boundary must still be considered CONFIRMED_AUTHORIZED."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time)

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=120),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(alarm, [log_entry])

    assert result.resolution == DeconflictionResolution.CONFIRMED_AUTHORIZED
    assert result.time_delta_seconds == 120.0


def test_match_inside_ongoing_start_and_end_interval():
    """Alarm inside [started_at, ended_at] range has 0.0s delta and is CONFIRMED_AUTHORIZED."""
    start = datetime(2026, 11, 19, 15, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 11, 19, 15, 30, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=start, ended_at=end)

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=datetime(2026, 11, 19, 15, 18, 0, tzinfo=timezone.utc),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(alarm, [log_entry])

    assert result.resolution == DeconflictionResolution.CONFIRMED_AUTHORIZED
    assert result.time_delta_seconds == 0.0


def test_unmatched_external_ip_is_suspicious_and_requires_anci_evaluation():
    """Traffic from an unknown IP outside the auditor's logs must return UNMATCHED_SUSPICIOUS."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time)

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=15),
        observed_attacker_ip="45.155.205.99",  # Malicious external IP
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(alarm, [log_entry])

    assert result.resolution == DeconflictionResolution.UNMATCHED_SUSPICIOUS
    assert result.matched_log_id is None
    assert result.anci_report_required is True


def test_event_far_outside_time_window_is_unmatched_suspicious():
    """Event 30 minutes outside the test window with no enrolled IP pool returns UNMATCHED_SUSPICIOUS."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time)

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(minutes=30),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(alarm, [log_entry])

    assert result.resolution == DeconflictionResolution.UNMATCHED_SUSPICIOUS
    assert result.anci_report_required is True


def test_partial_match_within_extended_window_returns_indeterminate():
    """Same IP and asset 5 minutes after log ends (outside 2m, inside 10m) resolves as INDETERMINATE."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time)

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(minutes=5),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(alarm, [log_entry])

    assert result.resolution == DeconflictionResolution.INDETERMINATE
    assert result.matched_log_id == "log-uuid-001"
    assert result.anci_report_required is False


def test_compute_log_record_hash_is_deterministic_and_tamper_evident():
    """Record hash must be a deterministic 64-char SHA-256 hex digest."""
    ts = datetime(2026, 11, 19, 16, 0, 0, tzinfo=timezone.utc)
    h1 = compute_log_record_hash(
        agreement_id="roe-1",
        auditor_id="aud-1",
        started_at=ts,
        ended_at=None,
        source_ip="181.43.22.10",
        target_host="api.cliente.cl",
        target_port=443,
        target_endpoint="/v1/users",
        http_method="GET",
        injected_header_token="LEXPLOIT-TOKEN",
        activity_type="RECON_SCAN",
        tool_or_technique="Nmap -sV",
        description="Escaneo de servicios expuestos",
        is_critical_finding=False,
    )
    h2 = compute_log_record_hash(
        agreement_id="roe-1",
        auditor_id="aud-1",
        started_at=ts,
        ended_at=None,
        source_ip="181.43.22.10",
        target_host="api.cliente.cl",
        target_port=443,
        target_endpoint="/v1/users",
        http_method="GET",
        injected_header_token="LEXPLOIT-TOKEN",
        activity_type="RECON_SCAN",
        tool_or_technique="Nmap -sV",
        description="Escaneo de servicios expuestos",
        is_critical_finding=False,
    )
    h_tampered = compute_log_record_hash(
        agreement_id="roe-1",
        auditor_id="aud-1",
        started_at=ts,
        ended_at=None,
        source_ip="181.43.22.10",
        target_host="db-prod.cliente.cl",  # Changed target_host
        target_port=443,
        target_endpoint="/v1/users",
        http_method="GET",
        injected_header_token="LEXPLOIT-TOKEN",
        activity_type="RECON_SCAN",
        tool_or_technique="Nmap -sV",
        description="Escaneo de servicios expuestos",
        is_critical_finding=False,
    )

    assert len(h1) == 64
    assert h1 == h2
    assert h1 != h_tampered


def test_auditor_hitting_excluded_asset_is_unmatched_suspicious():
    """Pentester touching an excluded (Hard Deny List) asset MUST be UNMATCHED_SUSPICIOUS even if logged."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time, target_host="db-prod.cliente.cl")

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=20),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="db-prod.cliente.cl",
    )
    result = match_incident_against_logs(
        alarm,
        [log_entry],
        authorized_auditor_ips=["181.43.22.10"],
        target_assets=["api.cliente.cl"],
        excluded_assets=["db-prod.cliente.cl"],
        execution_start=base_time - timedelta(hours=2),
        execution_end=base_time + timedelta(hours=4),
    )

    assert result.resolution == DeconflictionResolution.UNMATCHED_SUSPICIOUS
    assert result.anci_report_required is True
    # Preserves forensic attribution to the pentester's log
    assert result.matched_log_id == "log-uuid-001"
    assert "EXCESO DE MANDATO" in result.justification_notes


def test_auditor_hitting_unlisted_asset_outside_in_scope_is_unmatched_suspicious():
    """Pentester accessing a host not explicitly listed in target_assets MUST be UNMATCHED_SUSPICIOUS."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time, target_host="erp-interno.cliente.cl")

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=10),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="erp-interno.cliente.cl",
    )
    result = match_incident_against_logs(
        alarm,
        [log_entry],
        authorized_auditor_ips=["181.43.22.10"],
        target_assets=["api.cliente.cl", "10.0.10.0/24"],
        excluded_assets=["db-prod.cliente.cl"],
        execution_start=base_time - timedelta(hours=2),
        execution_end=base_time + timedelta(hours=4),
    )

    assert result.resolution == DeconflictionResolution.UNMATCHED_SUSPICIOUS
    assert result.anci_report_required is True
    assert result.matched_log_id == "log-uuid-001"


def test_permitted_asset_outside_contract_window_is_indeterminate():
    """Matching log on an explicitly permitted asset outside [execution_start, execution_end] is INDETERMINATE."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time, target_host="api.cliente.cl")

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=30),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="api.cliente.cl",
    )
    # Contract execution window ended 1 hour before the test
    result = match_incident_against_logs(
        alarm,
        [log_entry],
        authorized_auditor_ips=["181.43.22.10"],
        target_assets=["api.cliente.cl"],
        excluded_assets=["db-prod.cliente.cl"],
        execution_start=base_time - timedelta(hours=5),
        execution_end=base_time - timedelta(hours=1),
    )

    assert result.resolution == DeconflictionResolution.INDETERMINATE
    assert result.anci_report_required is False
    assert result.matched_log_id == "log-uuid-001"
    assert result.time_window_matched is False


def test_permitted_asset_logged_from_unenrolled_ip_is_indeterminate():
    """Matching log on an In-Scope asset from an un-enrolled source IP resolves as INDETERMINATE."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(
        started_at=base_time,
        source_ip="200.54.10.99",  # Not in authorized_auditor_ips
        target_host="api.cliente.cl",
    )

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=15),
        observed_attacker_ip="200.54.10.99",
        targeted_asset="api.cliente.cl",
    )
    result = match_incident_against_logs(
        alarm,
        [log_entry],
        authorized_auditor_ips=["181.43.22.10"],
        target_assets=["api.cliente.cl"],
        excluded_assets=["db-prod.cliente.cl"],
        execution_start=base_time - timedelta(hours=2),
        execution_end=base_time + timedelta(hours=2),
    )

    assert result.resolution == DeconflictionResolution.INDETERMINATE
    assert result.anci_report_required is False
    assert result.matched_log_id == "log-uuid-001"
    assert result.ip_matched is False


def test_ip_substring_does_not_falsely_authorize_different_ip():
    """Target IP 10.0.0.1 in whitelist must NEVER falsely authorize 10.0.0.10."""
    base_time = datetime(2026, 11, 19, 15, 40, 0, tzinfo=timezone.utc)
    log_entry = _sample_log(started_at=base_time, target_host="10.0.0.10")

    alarm = IncidentAlarmInput(
        agreement_id="roe-uuid-001",
        incident_timestamp=base_time + timedelta(seconds=10),
        observed_attacker_ip="181.43.22.10",
        targeted_asset="10.0.0.10",
    )
    result = match_incident_against_logs(
        alarm,
        [log_entry],
        authorized_auditor_ips=["181.43.22.10"],
        target_assets=["10.0.0.1"],
    )

    assert result.resolution == DeconflictionResolution.UNMATCHED_SUSPICIOUS
    assert result.anci_report_required is True
