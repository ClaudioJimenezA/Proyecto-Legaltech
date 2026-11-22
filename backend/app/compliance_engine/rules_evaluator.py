"""Pure evaluator for the 4 copulative exemption rules of Art. 2° Ley N° 21.459."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .scope_validator import is_target_in_scope, parse_ip_or_network

AUTHORIZED_ROE_STATUSES = frozenset({"SIGNED_AND_SEALED", "ACTIVE"})


@dataclass(frozen=True)
class ComplianceEvaluationInput:
    """Normalized state required to evaluate Art. 2° Ley N° 21.459 exemption."""

    roe_status: str
    client_signed_at: Optional[datetime]
    auditor_signed_at: Optional[datetime]
    sha256_hash: Optional[str]
    execution_start: datetime
    execution_end: datetime
    target_assets: list[str]
    excluded_assets: list[str]
    auditor_source_ips: list[str]
    traffic_header_token: str
    client_poc_id: str
    backup_confirmed: bool
    cloud_authorization_confirmed: bool = True
    uses_third_party_cloud: bool = False
    no_appropriation_or_damage_intent: bool = True
    non_destructive_limits_respected: bool = True
    formal_reporting_committed: bool = True
    evaluation_time: Optional[datetime] = None
    action_target_host: Optional[str] = None
    action_source_ip: Optional[str] = None


@dataclass(frozen=True)
class ComplianceConditionResult:
    """Evaluation status and reasoning for a single statutory condition."""

    code: str
    name: str
    passed: bool
    reason: str


@dataclass(frozen=True)
class ComplianceEvaluationResult:
    """Overall Art. 2° Ley N° 21.459 exemption assessment."""

    is_exempt: bool
    conditions: list[ComplianceConditionResult] = field(default_factory=list)
    failed_conditions: list[str] = field(default_factory=list)


def _to_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _ip_in_allowed_list(ip_str: str, allowed_ips: list[str]) -> bool:
    ip_net = parse_ip_or_network(ip_str)
    if ip_net is None:
        return False
    for entry in allowed_ips:
        allowed_net = parse_ip_or_network(entry)
        if allowed_net is not None and ip_net.version == allowed_net.version:
            if ip_net.subnet_of(allowed_net):
                return True
    return False


def _eval_prior_authorization(data: ComplianceEvaluationInput) -> ComplianceConditionResult:
    code = "COND_1_PRIOR_AUTHORIZATION"
    name = "Existencia de autorizacion o mandato marco previo"

    if data.roe_status not in AUTHORIZED_ROE_STATUSES:
        return ComplianceConditionResult(
            code, name, False, f"El acuerdo RoE se encuentra en estado '{data.roe_status}', no sellado/activo."
        )
    if data.client_signed_at is None or data.auditor_signed_at is None:
        return ComplianceConditionResult(
            code, name, False, "Falta la doble firma electronica (cliente y auditor)."
        )
    if not data.sha256_hash or len(data.sha256_hash) != 64:
        return ComplianceConditionResult(
            code, name, False, "El acuerdo carece de sellado criptografico SHA-256 valido."
        )
    if data.uses_third_party_cloud and not data.cloud_authorization_confirmed:
        return ComplianceConditionResult(
            code, name, False, "Falta autorizacion explicita para pruebas en infraestructura cloud de terceros."
        )

    eval_time = _to_utc(data.evaluation_time or datetime.now(timezone.utc))
    start_utc = _to_utc(data.execution_start)
    end_utc = _to_utc(data.execution_end)
    if not (start_utc <= eval_time <= end_utc):
        return ComplianceConditionResult(
            code, name, False, "La accion ocurre fuera de la ventana temporal autorizada en el RoE."
        )

    return ComplianceConditionResult(code, name, True, "Mandato previo sellado, vigente y firmado por ambas partes.")


def _eval_no_malicious_intent(data: ComplianceEvaluationInput) -> ComplianceConditionResult:
    code = "COND_2_NO_MALICIOUS_INTENT"
    name = "Ausencia de animo de apropiacion o dano"

    if not data.no_appropriation_or_damage_intent:
        return ComplianceConditionResult(
            code, name, False, "No se acredita ausencia de animo de apropiacion o dano."
        )
    if not data.backup_confirmed:
        return ComplianceConditionResult(
            code, name, False, "No existe confirmacion de respaldo previo (backup_confirmed=False)."
        )
    return ComplianceConditionResult(code, name, True, "Proposito estrictamente defensivo con respaldos confirmados.")


def _eval_operational_limits(data: ComplianceEvaluationInput) -> ComplianceConditionResult:
    code = "COND_3_OPERATIONAL_LIMITS"
    name = "Sujecion a limites operativos no destructivos"

    if not data.non_destructive_limits_respected:
        return ComplianceConditionResult(
            code, name, False, "Se vulneraron los limites operativos no destructivos."
        )
    if data.action_target_host is not None:
        if not is_target_in_scope(data.action_target_host, data.target_assets, data.excluded_assets):
            return ComplianceConditionResult(
                code,
                name,
                False,
                f"El activo '{data.action_target_host}' esta fuera de alcance o en la lista de excluidos.",
            )
    if data.action_source_ip is not None:
        if not _ip_in_allowed_list(data.action_source_ip, data.auditor_source_ips):
            return ComplianceConditionResult(
                code,
                name,
                False,
                f"La IP de origen '{data.action_source_ip}' no corresponde a las IPs enroladas del auditor.",
            )

    return ComplianceConditionResult(code, name, True, "Operacion ejecutada dentro del alcance y limites pactados.")


def _eval_reporting_duty(data: ComplianceEvaluationInput) -> ComplianceConditionResult:
    code = "COND_4_REPORTING_DUTY"
    name = "Cumplimiento del deber de reporte formal"

    if not data.client_poc_id or not data.client_poc_id.strip():
        return ComplianceConditionResult(
            code, name, False, "No se ha designado un Punto de Contacto (PoC) receptor de reportes."
        )
    if not data.traffic_header_token or not data.traffic_header_token.strip():
        return ComplianceConditionResult(
            code, name, False, "Falta el token de trazabilidad X-Assessment-Scope."
        )
    if not data.formal_reporting_committed:
        return ComplianceConditionResult(
            code, name, False, "No se ha comprometido el deber de reporte formal de hallazgos."
        )

    return ComplianceConditionResult(code, name, True, "Canal de reporte formal, PoC y trazabilidad configurados.")


def evaluate_art2_ley21459(data: ComplianceEvaluationInput) -> ComplianceEvaluationResult:
    """Strictly evaluate the 4 copulative conditions of Art. 2° Ley N° 21.459."""
    conditions = [
        _eval_prior_authorization(data),
        _eval_no_malicious_intent(data),
        _eval_operational_limits(data),
        _eval_reporting_duty(data),
    ]
    failed = [c.code for c in conditions if not c.passed]
    return ComplianceEvaluationResult(
        is_exempt=len(failed) == 0,
        conditions=conditions,
        failed_conditions=failed,
    )
