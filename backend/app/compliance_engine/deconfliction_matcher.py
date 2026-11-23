"""Pure spatiotemporal deconfliction matcher and telemetry record hasher (Ley N° 21.663 ANCI).

Zero I/O, zero database, zero web framework dependencies.
Correlates SIEM/WAF/IDS alarms reported by the client's SOC against the auditor's
immutable assessment logs within a deterministic +-2 minute tolerance window.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import ipaddress
from typing import Any, Optional, Sequence

from .canonical_hasher import compute_sha256_hash

DEFAULT_TOLERANCE_SECONDS = 120  # +-2 minutes for NTP clock drift mitigation
EXTENDED_INDETERMINATE_SECONDS = 600  # +-10 minutes for partial match warning


class DeconflictionResolution(str, Enum):
    """Deterministic outcomes for an incident deconfliction query."""

    CONFIRMED_AUTHORIZED = "CONFIRMED_AUTHORIZED"
    UNMATCHED_SUSPICIOUS = "UNMATCHED_SUSPICIOUS"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class LogCandidate:
    """Pure representation of an assessment_logs entry."""

    log_id: str
    agreement_id: str
    started_at: datetime
    ended_at: Optional[datetime]
    source_ip: str
    target_host: str
    target_port: Optional[int] = None
    target_endpoint: Optional[str] = None
    http_method: Optional[str] = None
    injected_header_token: Optional[str] = None
    activity_type: str = "RECON_SCAN"
    tool_or_technique: str = ""
    description: str = ""
    record_hash: str = ""
    is_critical_finding: bool = False


@dataclass(frozen=True)
class IncidentAlarmInput:
    """Pure representation of a SIEM/WAF/EDR alarm queried by the SOC."""

    agreement_id: str
    incident_timestamp: datetime
    observed_attacker_ip: str
    targeted_asset: str
    internal_ticket_ref: Optional[str] = None


@dataclass(frozen=True)
class DeconflictionMatchResult:
    """Detailed outcome of correlating a SIEM alarm against active assessment logs."""

    resolution: DeconflictionResolution
    matched_log_id: Optional[str]
    matched_log: Optional[LogCandidate]
    time_delta_seconds: Optional[float]
    ip_matched: bool
    asset_matched: bool
    time_window_matched: bool
    anci_report_required: bool
    justification_notes: str


def _ensure_utc(dt: datetime) -> datetime:
    """Normalize any datetime to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ips_match(log_source_ip: str, observed_ip: str) -> bool:
    """Compare two IP strings or CIDR ranges deterministically."""
    clean_log = log_source_ip.strip()
    clean_obs = observed_ip.strip()
    if clean_log == clean_obs:
        return True
    try:
        obs_addr = ipaddress.ip_address(clean_obs.split("/")[0])
        if "/" in clean_log:
            net = ipaddress.ip_network(clean_log, strict=False)
            return obs_addr in net
        log_addr = ipaddress.ip_address(clean_log)
        return log_addr == obs_addr
    except ValueError:
        return clean_log.lower() == clean_obs.lower()


def _normalize_host(raw_asset: str) -> str:
    """Strip protocol, port, and path from a URL or host string."""
    cleaned = raw_asset.strip().lower()
    for prefix in ("https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    cleaned = cleaned.split("/")[0]
    if ":" in cleaned and not cleaned.startswith("["):
        host_part, maybe_port = cleaned.rsplit(":", 1)
        if maybe_port.isdigit():
            cleaned = host_part
    return cleaned


def _is_ip_or_network(value: str) -> bool:
    """Return True if value parses as an IPv4/IPv6 address or CIDR network."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _asset_matches_rule(rule_asset: str, candidate_asset: str) -> bool:
    """Strict directional check: does candidate_asset fall under rule_asset (In-Scope or Excluded)?

    - Exact match after normalization -> True
    - IP inside CIDR or subnet inside CIDR -> True
    - Wildcard domain (*.cliente.cl) matches cliente.cl or sub.cliente.cl -> True
    - Subdomain of rule domain (v1.api.cliente.cl under api.cliente.cl) -> True
    - NEVER matches IP substrings (e.g., 10.0.0.1 does NOT match 10.0.0.10)
    - NEVER authorizes a parent domain when only a subdomain was listed
    """
    norm_rule = _normalize_host(rule_asset)
    norm_cand = _normalize_host(candidate_asset)

    if not norm_rule or not norm_cand:
        return False

    if norm_rule == norm_cand:
        return True

    rule_is_ip = _is_ip_or_network(norm_rule)
    cand_is_ip = _is_ip_or_network(norm_cand)
    if rule_is_ip or cand_is_ip:
        try:
            rule_net = ipaddress.ip_network(norm_rule, strict=False)
            if "/" in norm_cand:
                cand_net = ipaddress.ip_network(norm_cand, strict=False)
                return cand_net.version == rule_net.version and cand_net.subnet_of(rule_net)
            cand_addr = ipaddress.ip_address(norm_cand)
            return cand_addr in rule_net
        except ValueError:
            return False

    if norm_rule.startswith("*."):
        base_domain = norm_rule[2:]
        return norm_cand == base_domain or norm_cand.endswith("." + base_domain)

    if norm_cand.endswith("." + norm_rule):
        return True

    return False


def _assets_match(log_target: str, queried_asset: str) -> bool:
    """Evaluate if the queried asset matches the logged target host, domain, or CIDR."""
    return _asset_matches_rule(log_target, queried_asset) or _asset_matches_rule(
        queried_asset, log_target
    )


def _compute_time_delta_seconds(
    incident_ts: datetime,
    started_at: datetime,
    ended_at: Optional[datetime],
) -> float:
    """Return 0.0 if incident_ts falls inside [started_at, effective_end], else minimum distance in seconds."""
    inc_utc = _ensure_utc(incident_ts)
    start_utc = _ensure_utc(started_at)
    end_utc = _ensure_utc(ended_at) if ended_at else start_utc
    if end_utc < start_utc:
        end_utc = start_utc

    if start_utc <= inc_utc <= end_utc:
        return 0.0
    if inc_utc < start_utc:
        return (start_utc - inc_utc).total_seconds()
    return (inc_utc - end_utc).total_seconds()


def compute_log_record_hash(
    *,
    agreement_id: str,
    auditor_id: str,
    started_at: datetime,
    ended_at: Optional[datetime],
    source_ip: str,
    target_host: str,
    target_port: Optional[int],
    target_endpoint: Optional[str],
    http_method: Optional[str],
    injected_header_token: Optional[str],
    activity_type: str,
    tool_or_technique: str,
    description: str,
    is_critical_finding: bool,
) -> str:
    """Compute an immutable 64-character SHA-256 digest for an assessment log entry."""
    canonical_payload: dict[str, Any] = {
        "agreement_id": str(agreement_id),
        "auditor_id": str(auditor_id),
        "started_at": _ensure_utc(started_at).isoformat(),
        "ended_at": _ensure_utc(ended_at).isoformat() if ended_at else None,
        "source_ip": str(source_ip).strip(),
        "target_host": target_host.strip().lower(),
        "target_port": target_port,
        "target_endpoint": (target_endpoint or "").strip(),
        "http_method": (http_method or "").strip().upper() or None,
        "injected_header_token": (injected_header_token or "").strip() or None,
        "activity_type": str(activity_type),
        "tool_or_technique": tool_or_technique.strip(),
        "description": description.strip(),
        "is_critical_finding": bool(is_critical_finding),
    }
    return compute_sha256_hash(canonical_payload)


def match_incident_against_logs(
    alarm: IncidentAlarmInput,
    logs: Sequence[LogCandidate],
    authorized_auditor_ips: Optional[Sequence[str]] = None,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    target_assets: Optional[Sequence[str]] = None,
    excluded_assets: Optional[Sequence[str]] = None,
    execution_start: Optional[datetime] = None,
    execution_end: Optional[datetime] = None,
) -> DeconflictionMatchResult:
    """Correlate a SIEM/WAF incident alarm against active assessment logs and RoE legal boundaries.

    Resolution Rules (Ley N° 21.459 Art. 1°/2° + Ley N° 21.663 ANCI):
    1. HARD SCOPE CHECK (Art. 1° Ley N° 21.459 — Exceso de Mandato):
       - If targeted_asset matches excluded_assets (Hard Deny List), OR target_assets is provided
         and targeted_asset is NOT explicitly permitted (In-Scope) -> UNMATCHED_SUSPICIOUS
         (anci_report_required=True), even if the IP belongs to the auditor or was logged.
         If a matching auditor log exists, it is linked as forensic evidence of contract breach.
    2. CONFIRMED_AUTHORIZED (anci_report_required=False):
       - Asset is permitted, matching log found within +-tolerance_seconds (default 120s),
         source IP is enrolled in authorized_auditor_ips (if provided), and incident_timestamp
         lies within the contract execution window [execution_start, execution_end] (if provided).
    3. INDETERMINATE (anci_report_required=False — Manual PoC verification to avoid ANCI false positives):
       - Asset IS explicitly permitted (In-Scope & not excluded), AND:
         a) Exact log match exists, but source IP is not enrolled in RoE and/or timestamp exceeds
            the contractual execution window; OR
         b) Partial log match (e.g. IP + Asset within +-10 minutes, or IP + Time on sibling In-Scope asset); OR
         c) Source IP belongs to authorized_auditor_ips without a synced log entry yet.
    4. UNMATCHED_SUSPICIOUS (anci_report_required=True):
       - No correlation with auditor logs or enrolled IPs -> treat as external intrusion requiring
         containment and evaluation of the 3-hour ANCI early warning (Art. 37 Ley N° 21.663).
    """
    agreement_logs = [log for log in logs if str(log.agreement_id) == str(alarm.agreement_id)]

    best_exact_match: Optional[tuple[float, LogCandidate]] = None
    best_partial_match: Optional[tuple[float, LogCandidate, bool, bool, bool]] = None

    for log in agreement_logs:
        ip_ok = _ips_match(log.source_ip, alarm.observed_attacker_ip)
        asset_ok = _assets_match(log.target_host, alarm.targeted_asset)
        delta_sec = _compute_time_delta_seconds(
            alarm.incident_timestamp, log.started_at, log.ended_at
        )
        time_ok = delta_sec <= float(tolerance_seconds)

        if ip_ok and asset_ok and time_ok:
            if best_exact_match is None or delta_sec < best_exact_match[0]:
                best_exact_match = (delta_sec, log)
        elif (ip_ok and asset_ok and delta_sec <= EXTENDED_INDETERMINATE_SECONDS) or (
            ip_ok and time_ok
        ):
            if best_partial_match is None or delta_sec < best_partial_match[0]:
                best_partial_match = (delta_sec, log, ip_ok, asset_ok, time_ok)

    # ------------------------------------------------------------------
    # 1. HARD LEGAL SCOPE BOUNDARY CHECK (Art. 1° Ley N° 21.459)
    # ------------------------------------------------------------------
    matched_excluded_rule: Optional[str] = None
    if excluded_assets:
        for excl in excluded_assets:
            if _asset_matches_rule(excl, alarm.targeted_asset):
                matched_excluded_rule = excl
                break

    asset_in_whitelist = True
    if target_assets:
        asset_in_whitelist = any(
            _asset_matches_rule(allowed, alarm.targeted_asset) for allowed in target_assets
        )

    if matched_excluded_rule is not None or not asset_in_whitelist:
        forensic_log: Optional[LogCandidate] = None
        forensic_delta: Optional[float] = None
        if best_exact_match is not None:
            forensic_delta, forensic_log = best_exact_match
        elif best_partial_match is not None and best_partial_match[2] and best_partial_match[3]:
            forensic_delta, forensic_log = best_partial_match[0], best_partial_match[1]

        is_enrolled_auditor_ip = bool(
            authorized_auditor_ips
            and any(_ips_match(auth_ip, alarm.observed_attacker_ip) for auth_ip in authorized_auditor_ips)
        )

        scope_reason = (
            f"figura expresamente en la Lista de Exclusión Prohibida (Hard Deny List: '{matched_excluded_rule}')"
            if matched_excluded_rule is not None
            else "NO figura en la lista blanca de activos autorizados (In-Scope) del contrato RoE"
        )
        attribution_clause = (
            f" Se detectó coincidencia forense con el registro de bitácora del auditor ID {forensic_log.log_id} "
            f"(SHA-256 {forensic_log.record_hash[:16]}...), acreditando un EXCESO DE MANDATO CONTRACTUAL."
            if forensic_log is not None
            else (
                " La IP de origen pertenece al pool declarado por el auditor, lo que configura un posible "
                "EXCESO DE MANDATO CONTRACTUAL no amparado por la autorización vigente."
                if is_enrolled_auditor_ip
                else " Además, no existe respaldo de actividad autorizada para esta IP."
            )
        )
        justification = (
            f"ALERTA CRÍTICA — ACTIVO FUERA DE ALCANCE AUTORIZADO (ART. 1° LEY N° 21.459): "
            f"El tráfico observado desde {alarm.observed_attacker_ip} incidió sobre el activo "
            f"'{alarm.targeted_asset}', el cual {scope_reason}.{attribution_clause} "
            f"Conforme al Art. 1° de la Ley N° 21.459 (acceso ilícito excediendo la autorización conferida), "
            f"esta actividad NO está eximida. ACCIÓN REQUERIDA: Contener inmediatamente el tráfico, "
            f"notificar al Punto de Contacto (PoC) y evaluar la Alerta Temprana ante la ANCI (3 horas, Art. 37 Ley N° 21.663)."
        )
        return DeconflictionMatchResult(
            resolution=DeconflictionResolution.UNMATCHED_SUSPICIOUS,
            matched_log_id=forensic_log.log_id if forensic_log else None,
            matched_log=forensic_log,
            time_delta_seconds=round(forensic_delta, 2) if forensic_delta is not None else None,
            ip_matched=bool(forensic_log is not None or is_enrolled_auditor_ip),
            asset_matched=False,
            time_window_matched=bool(best_exact_match is not None),
            anci_report_required=True,
            justification_notes=justification,
        )

    # ------------------------------------------------------------------
    # 2. CONTRACTUAL WINDOW & IP ENROLLMENT CHECKS ON PERMITTED ASSETS
    # ------------------------------------------------------------------
    inc_utc = _ensure_utc(alarm.incident_timestamp)
    within_contract_window = True
    window_deviation_note = ""
    if execution_start is not None:
        start_utc = _ensure_utc(execution_start) - timedelta(seconds=tolerance_seconds)
        if inc_utc < start_utc:
            within_contract_window = False
            window_deviation_note = (
                f"evento anterior al inicio contractual ({_ensure_utc(execution_start).isoformat()})"
            )
    if execution_end is not None and within_contract_window:
        end_utc = _ensure_utc(execution_end) + timedelta(seconds=tolerance_seconds)
        if inc_utc > end_utc:
            within_contract_window = False
            window_deviation_note = (
                f"evento posterior al término contractual ({_ensure_utc(execution_end).isoformat()})"
            )

    ip_is_enrolled = True
    if authorized_auditor_ips:
        ip_is_enrolled = any(
            _ips_match(auth_ip, alarm.observed_attacker_ip) for auth_ip in authorized_auditor_ips
        )

    if best_exact_match is not None:
        delta_sec, matched = best_exact_match
        ticket_clause = (
            f" (Ticket SOC: {alarm.internal_ticket_ref})" if alarm.internal_ticket_ref else ""
        )

        # Critical Break-Glass finding logged by pentester -> trigger critical alert / ANCI evaluation
        if matched.is_critical_finding:
            justification = (
                f"ALERTA CRÍTICA BREAK-GLASS CORRELACIONADA{ticket_clause} (CLÁUSULA 7ª RoE / LEY N° 21.663): "
                f"El tráfico desde {alarm.observed_attacker_ip} hacia '{alarm.targeted_asset}' coincide "
                f"espaciotemporalmente (desfase: {delta_sec:.1f}s) con el registro de bitácora ID {matched.log_id} "
                f"[{matched.activity_type} - {matched.tool_or_technique}], sellado con SHA-256 "
                f"{matched.record_hash[:16]}..., el cual fue marcado como HALLAZGO CRÍTICO (PROTOCOLO BREAK-GLASS). "
                f"Debido al impacto crítico detectado sobre el activo, NO procede archivar la alerta como inocua: "
                f"se requiere contención inmediata, suspensión de post-explotación, notificación de emergencia al PoC "
                f"y evaluación del reporte de Alerta Temprana ante la ANCI (3 horas, Art. 37 Ley N° 21.663)."
            )
            return DeconflictionMatchResult(
                resolution=DeconflictionResolution.UNMATCHED_SUSPICIOUS,
                matched_log_id=matched.log_id,
                matched_log=matched,
                time_delta_seconds=round(delta_sec, 2),
                ip_matched=ip_is_enrolled,
                asset_matched=True,
                time_window_matched=within_contract_window,
                anci_report_required=True,
                justification_notes=justification,
            )

        # Operational/administrative deviation on an explicitly permitted asset -> INDETERMINATE
        if not ip_is_enrolled or not within_contract_window:
            deviations: list[str] = []
            if not ip_is_enrolled:
                deviations.append(
                    f"la IP de origen {alarm.observed_attacker_ip} no figura enrolada en las IPs públicas autorizadas del RoE"
                )
            if not within_contract_window:
                deviations.append(f"la ventana horaria contractual fue excedida ({window_deviation_note})")

            justification = (
                f"VERIFICACIÓN MANUAL REQUERIDA (INDETERMINADA){ticket_clause}: El activo afectado "
                f"'{alarm.targeted_asset}' SÍ se encuentra dentro del alcance autorizado (In-Scope) y existe "
                f"coincidencia exacta con el registro de bitácora ID {matched.log_id} (desfase: {delta_sec:.1f}s, "
                f"SHA-256 {matched.record_hash[:16]}...), PERO se detectó una desviación operativa: "
                f"{'; '.join(deviations)}. Para evitar un falso positivo ante la ANCI, NO se emite exención "
                f"automática: valide telefónicamente con el PoC y el Lead Pentester antes de escalar el incidente."
            )
            return DeconflictionMatchResult(
                resolution=DeconflictionResolution.INDETERMINATE,
                matched_log_id=matched.log_id,
                matched_log=matched,
                time_delta_seconds=round(delta_sec, 2),
                ip_matched=ip_is_enrolled,
                asset_matched=True,
                time_window_matched=within_contract_window,
                anci_report_required=False,
                justification_notes=justification,
            )

        justification = (
            f"DESCONFLICTO POSITIVO CONFIRMADO{ticket_clause}: El evento detectado desde la IP "
            f"{alarm.observed_attacker_ip} hacia el activo autorizado '{alarm.targeted_asset}' coincide "
            f"espaciotemporalmente (diferencia de reloj: {delta_sec:.1f}s, dentro de la ventana "
            f"de tolerancia NTP de ±{tolerance_seconds}s) con la prueba autorizada ID {matched.log_id} "
            f"[{matched.activity_type} - {matched.tool_or_technique}], sellada con hash SHA-256 "
            f"{matched.record_hash[:16]}... Se acredita actividad legítima amparada en el Art. 2° de la "
            f"Ley N° 21.459. Se desestima la obligación de reporte de incidente ante la Agencia Nacional "
            f"de Ciberseguridad (ANCI - Art. 37 Ley N° 21.663)."
        )
        return DeconflictionMatchResult(
            resolution=DeconflictionResolution.CONFIRMED_AUTHORIZED,
            matched_log_id=matched.log_id,
            matched_log=matched,
            time_delta_seconds=round(delta_sec, 2),
            ip_matched=True,
            asset_matched=True,
            time_window_matched=True,
            anci_report_required=False,
            justification_notes=justification,
        )

    if best_partial_match is not None:
        delta_sec, partial_log, ip_ok, asset_ok, time_ok = best_partial_match
        extra_notes: list[str] = []
        if not ip_is_enrolled:
            extra_notes.append("IP no enrolada en el contrato RoE")
        if not within_contract_window:
            extra_notes.append(f"fuera de ventana horaria contractual ({window_deviation_note})")
        extra_clause = f" Observaciones adicionales: {'; '.join(extra_notes)}." if extra_notes else ""

        justification = (
            f"COINCIDENCIA PARCIAL SOBRE ACTIVO PERMITIDO (INDETERMINADA): Se detectó tráfico desde "
            f"{alarm.observed_attacker_ip} hacia el activo In-Scope '{alarm.targeted_asset}' correlacionado "
            f"parcialmente con el registro ID {partial_log.log_id} "
            f"(IP coincide con log: {'Sí' if ip_ok else 'No'}, Activo coincide: {'Sí' if asset_ok else 'No'}, "
            f"Desfase temporal: {delta_sec:.1f}s).{extra_clause} Se requiere verificación telefónica inmediata "
            f"con el Punto de Contacto (PoC) y el Lead Pentester antes de activar el protocolo de notificación "
            f"a la ANCI."
        )
        return DeconflictionMatchResult(
            resolution=DeconflictionResolution.INDETERMINATE,
            matched_log_id=partial_log.log_id,
            matched_log=partial_log,
            time_delta_seconds=round(delta_sec, 2),
            ip_matched=ip_ok and ip_is_enrolled,
            asset_matched=asset_ok,
            time_window_matched=time_ok and within_contract_window,
            anci_report_required=False,
            justification_notes=justification,
        )

    # Check if the IP is at least an enrolled auditor IP hitting a permitted In-Scope asset
    if authorized_auditor_ips and ip_is_enrolled:
        window_clause = (
            f" Además, el evento ocurrió fuera de la ventana horaria contractual ({window_deviation_note})."
            if not within_contract_window
            else ""
        )
        justification = (
            f"COINCIDENCIA PARCIAL POR IP ENROLADA EN ACTIVO PERMITIDO (INDETERMINADA): La IP "
            f"{alarm.observed_attacker_ip} pertenece al pool de IPs públicas declaradas por el Auditor "
            f"en el contrato RoE y el activo '{alarm.targeted_asset}' está dentro del alcance In-Scope, "
            f"pero no existe un evento registrado en la bitácora dentro de la ventana de ±{tolerance_seconds}s."
            f"{window_clause} Contacte de inmediato al PoC / Lead Pentester para confirmar si corresponde a "
            f"una prueba en curso pendiente de sincronización antes de notificar a la ANCI."
        )
        return DeconflictionMatchResult(
            resolution=DeconflictionResolution.INDETERMINATE,
            matched_log_id=None,
            matched_log=None,
            time_delta_seconds=None,
            ip_matched=True,
            asset_matched=True,
            time_window_matched=False,
            anci_report_required=False,
            justification_notes=justification,
        )

    justification = (
        f"ALERTA DE INTRUSIÓN NO AUTORIZADA (TRÁFICO SOSPECHOSO): No existe ningún registro en la "
        f"bitácora de auditoría para la IP {alarm.observed_attacker_ip} sobre el activo "
        f"'{alarm.targeted_asset}' dentro de la ventana temporal de ±{tolerance_seconds}s. "
        f"El tráfico NO corresponde a las pruebas autorizadas bajo el acuerdo RoE. "
        f"ACCIÓN REQUERIDA: Activar contención defensiva y evaluar el inicio del protocolo "
        f"de Alerta Temprana obligatoria (plazo máximo 3 horas) ante la Agencia Nacional de "
        f"Ciberseguridad (ANCI) conforme a los artículos 5° y 37 de la Ley N° 21.663."
    )
    return DeconflictionMatchResult(
        resolution=DeconflictionResolution.UNMATCHED_SUSPICIOUS,
        matched_log_id=None,
        matched_log=None,
        time_delta_seconds=None,
        ip_matched=False,
        asset_matched=False,
        time_window_matched=False,
        anci_report_required=True,
        justification_notes=justification,
    )
