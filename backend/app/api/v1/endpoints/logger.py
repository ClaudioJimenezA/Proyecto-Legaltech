"""REST endpoints for Live Assessment Logger (Paso 2: Telemetry & Audit Trail)."""

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.v1.endpoints.roe import _unpack_agreement
from app.compliance_engine.deconfliction_matcher import (
    _asset_matches_rule,
    _ensure_utc,
    _ips_match,
    compute_log_record_hash,
)
from app.core.database import get_supabase_client
from app.core.security import (
    AuthenticatedUser,
    get_current_user,
    resolve_or_provision_auth_user_id,
)
from app.schemas.log_schema import (
    AssessmentLogCreateSchema,
    AssessmentLogFinishSchema,
)

router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_assessment_log(
    payload: AssessmentLogCreateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Register an immutable real-time assessment test event in the telemetry log."""
    supabase = get_supabase_client()
    agreement_id_str = str(payload.agreement_id)

    # 1. Verify RoE agreement exists
    roe_resp = (
        supabase.table("roe_agreements")
        .select("*")
        .eq("id", agreement_id_str)
        .execute()
    )
    if not roe_resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró el acuerdo RoE con ID {agreement_id_str}.",
        )

    agreement = _unpack_agreement(roe_resp.data[0])
    current_status = agreement.get("current_status")

    # 2. Enforce Art. 2° Ley N° 21.459: Only sealed/active contracts allow live testing
    if current_status not in ("ACTIVE", "SIGNED_AND_SEALED"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Bloqueo preventivo Art. 2° Ley N° 21.459: El acuerdo RoE se encuentra en estado "
                f"'{current_status}'. No se permite registrar ni ejecutar pruebas técnicas hasta que "
                f"el contrato cuente con doble firma y sellado criptográfico SHA-256 (En Ejecución Activa)."
            ),
        )

    auditor_uuid = resolve_or_provision_auth_user_id(supabase, current_user)
    started_at = payload.started_at or datetime.now(timezone.utc)
    header_token = payload.injected_header_token or agreement.get("traffic_header_token")

    # 3. Non-blocking forensic compliance check: NEVER drop anomalous logs so contract
    #    breaches remain immutably recorded and detectable by the Deconfliction Engine.
    scope_warnings: list[dict[str, str]] = []
    excluded_assets: list[str] = agreement.get("excluded_assets") or []
    target_assets: list[str] = agreement.get("target_assets") or []
    enrolled_ips: list[str] = agreement.get("auditor_source_ips") or []

    matched_excluded = next(
        (excl for excl in excluded_assets if _asset_matches_rule(excl, payload.target_host)),
        None,
    )
    if matched_excluded is not None:
        scope_warnings.append(
            {
                "code": "EXCLUDED_ASSET",
                "severity": "CRITICAL",
                "message": (
                    f"EXCESO DE MANDATO (Art. 1° Ley N° 21.459): El activo '{payload.target_host}' "
                    f"coincide con la Lista de Exclusión '{matched_excluded}' (Hard Deny List). "
                    f"El evento quedó registrado en la bitácora forense y el Motor de Desconflicto "
                    f"lo marcará como SOSPECHOSO / NO AUTORIZADO."
                ),
            }
        )
    elif target_assets and not any(
        _asset_matches_rule(allowed, payload.target_host) for allowed in target_assets
    ):
        scope_warnings.append(
            {
                "code": "OUT_OF_SCOPE_ASSET",
                "severity": "CRITICAL",
                "message": (
                    f"ACTIVO FUERA DE ALCANCE (Art. 1° Ley N° 21.459): El activo '{payload.target_host}' "
                    f"no figura en los activos In-Scope autorizados del contrato RoE. El registro quedó "
                    f"sellado para trazabilidad forense y será clasificado como SOSPECHOSO en el desconflicto."
                ),
            }
        )

    if enrolled_ips and not any(_ips_match(auth_ip, payload.source_ip) for auth_ip in enrolled_ips):
        scope_warnings.append(
            {
                "code": "UNENROLLED_SOURCE_IP",
                "severity": "WARNING",
                "message": (
                    f"IP NO ENROLADA EN CONTRATO RoE: La IP '{payload.source_ip}' no figura entre las IPs "
                    f"autorizadas ({', '.join(enrolled_ips)}). El evento quedó registrado, pero el Motor de "
                    f"Desconflicto lo marcará como INDETERMINADO para verificación manual con el PoC."
                ),
            }
        )

    raw_exec_start = agreement.get("execution_start")
    raw_exec_end = agreement.get("execution_end")
    started_utc = _ensure_utc(started_at)
    if raw_exec_start:
        exec_start_utc = _ensure_utc(
            datetime.fromisoformat(str(raw_exec_start).replace("Z", "+00:00"))
        )
        if started_utc < exec_start_utc:
            scope_warnings.append(
                {
                    "code": "OUTSIDE_TIME_WINDOW",
                    "severity": "WARNING",
                    "message": (
                        f"FUERA DE VENTANA HORARIA CONTRACTUAL: El inicio del evento es anterior a "
                        f"la fecha autorizada ({exec_start_utc.isoformat()}). El Motor de Desconflicto "
                        f"lo clasificará como INDETERMINADO para validación con el PoC."
                    ),
                }
            )
    if raw_exec_end:
        exec_end_utc = _ensure_utc(
            datetime.fromisoformat(str(raw_exec_end).replace("Z", "+00:00"))
        )
        if started_utc > exec_end_utc:
            scope_warnings.append(
                {
                    "code": "OUTSIDE_TIME_WINDOW",
                    "severity": "WARNING",
                    "message": (
                        f"FUERA DE VENTANA HORARIA CONTRACTUAL: El evento excede la fecha de término "
                        f"autorizada ({exec_end_utc.isoformat()}). El Motor de Desconflicto lo clasificará "
                        f"como INDETERMINADO para validación con el PoC."
                    ),
                }
            )

    # 5. Compute immutable SHA-256 record_hash
    record_hash = compute_log_record_hash(
        agreement_id=agreement_id_str,
        auditor_id=auditor_uuid,
        started_at=started_at,
        ended_at=payload.ended_at,
        source_ip=payload.source_ip,
        target_host=payload.target_host,
        target_port=payload.target_port,
        target_endpoint=payload.target_endpoint,
        http_method=payload.http_method,
        injected_header_token=header_token,
        activity_type=payload.activity_type.value,
        tool_or_technique=payload.tool_or_technique,
        description=payload.description,
        is_critical_finding=payload.is_critical_finding,
    )

    row_to_insert = {
        "agreement_id": agreement_id_str,
        "auditor_id": auditor_uuid,
        "started_at": started_at.isoformat(),
        "ended_at": payload.ended_at.isoformat() if payload.ended_at else None,
        "source_ip": payload.source_ip,
        "target_host": payload.target_host.strip(),
        "target_port": payload.target_port,
        "target_endpoint": payload.target_endpoint,
        "http_method": payload.http_method,
        "injected_header_token": header_token,
        "activity_type": payload.activity_type.value,
        "tool_or_technique": payload.tool_or_technique.strip(),
        "description": payload.description.strip(),
        "is_critical_finding": payload.is_critical_finding,
        "system_impact_observed": payload.system_impact_observed,
        "record_hash": record_hash,
    }

    insert_resp = supabase.table("assessment_logs").insert(row_to_insert).execute()
    if not insert_resp.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al persistir el registro de bitácora en Supabase.",
        )

    created_log = insert_resp.data[0]
    meta = agreement.get("contract_metadata") or {}

    break_glass_alert = None
    if payload.is_critical_finding:
        break_glass_hours = meta.get("break_glass_hours", 2)
        poc_name = meta.get("poc_primary_name", "PoC Titular")
        poc_phone = meta.get("poc_primary_phone", "No registrado")
        poc_email = meta.get("poc_primary_email", "No registrado")
        break_glass_alert = {
            "activated": True,
            "clause": "Cláusula Octava: Protocolo Break-Glass (Notificación de Emergencia)",
            "max_notification_hours": break_glass_hours,
            "poc_contact": f"{poc_name} | Tel 24/7: {poc_phone} | Email: {poc_email}",
            "instruction": (
                f"ATENCIÓN: Ha marcado un hallazgo crítico. Conforme a la Cláusula 8ª del RoE, debe "
                f"detener toda maniobra de post-explotación sobre '{payload.target_host}' y notificar "
                f"al PoC ({poc_name}) en un plazo máximo de {break_glass_hours} horas."
            ),
        }

    return {
        "log": created_log,
        "record_hash": record_hash,
        "break_glass_alert": break_glass_alert,
        "scope_warnings": scope_warnings,
    }


@router.get("/active/{agreement_id}")
def list_active_agreement_logs(
    agreement_id: str,
    source_ip: Optional[str] = Query(None, description="Filtrar por IP de origen"),
    activity_type: Optional[str] = Query(None, description="Filtrar por tipo de actividad"),
    target_host: Optional[str] = Query(None, description="Filtrar por host o dominio destino"),
    critical_only: bool = Query(False, description="Mostrar solo hallazgos críticos Break-Glass"),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Fetch the live telemetry audit trail for a specific RoE agreement."""
    supabase = get_supabase_client()

    roe_resp = (
        supabase.table("roe_agreements")
        .select("*")
        .eq("id", agreement_id)
        .execute()
    )
    if not roe_resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Acuerdo RoE {agreement_id} no encontrado.",
        )

    agreement = _unpack_agreement(roe_resp.data[0])

    query = (
        supabase.table("assessment_logs")
        .select("*")
        .eq("agreement_id", agreement_id)
        .order("started_at", desc=True)
    )
    if activity_type:
        query = query.eq("activity_type", activity_type)
    if critical_only:
        query = query.eq("is_critical_finding", True)

    logs_resp = query.execute()
    logs: list[dict[str, Any]] = logs_resp.data or []

    if source_ip:
        logs = [l for l in logs if source_ip.strip() in str(l.get("source_ip", ""))]
    if target_host:
        needle = target_host.strip().lower()
        logs = [l for l in logs if needle in str(l.get("target_host", "")).lower()]

    critical_count = sum(1 for l in logs if l.get("is_critical_finding"))
    ongoing_count = sum(1 for l in logs if not l.get("ended_at"))

    return {
        "agreement_id": agreement_id,
        "agreement_title": agreement.get("title"),
        "agreement_status": agreement.get("current_status"),
        "traffic_header_token": agreement.get("traffic_header_token"),
        "logs": logs,
        "summary": {
            "total_logs": len(logs),
            "critical_findings_count": critical_count,
            "ongoing_tests_count": ongoing_count,
        },
    }


@router.patch("/{log_id}/finish")
def finish_assessment_log(
    log_id: str,
    payload: AssessmentLogFinishSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Close an ongoing assessment test entry by recording ended_at and recomputing its hash."""
    supabase = get_supabase_client()
    existing_resp = (
        supabase.table("assessment_logs")
        .select("*")
        .eq("id", log_id)
        .execute()
    )
    if not existing_resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Registro de bitácora {log_id} no encontrado.",
        )

    row = existing_resp.data[0]
    ended_at = payload.ended_at or datetime.now(timezone.utc)
    started_at = datetime.fromisoformat(str(row["started_at"]).replace("Z", "+00:00"))

    if ended_at < started_at:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="La hora de término no puede ser anterior a la hora de inicio del registro.",
        )

    new_hash = compute_log_record_hash(
        agreement_id=str(row["agreement_id"]),
        auditor_id=str(row["auditor_id"]),
        started_at=started_at,
        ended_at=ended_at,
        source_ip=str(row["source_ip"]),
        target_host=str(row["target_host"]),
        target_port=row.get("target_port"),
        target_endpoint=row.get("target_endpoint"),
        http_method=row.get("http_method"),
        injected_header_token=row.get("injected_header_token"),
        activity_type=str(row["activity_type"]),
        tool_or_technique=str(row["tool_or_technique"]),
        description=str(row["description"]),
        is_critical_finding=bool(row.get("is_critical_finding")),
    )

    update_data: dict[str, Any] = {
        "ended_at": ended_at.isoformat(),
        "record_hash": new_hash,
    }
    if payload.system_impact_observed is not None:
        update_data["system_impact_observed"] = payload.system_impact_observed

    updated_resp = (
        supabase.table("assessment_logs")
        .update(update_data)
        .eq("id", log_id)
        .execute()
    )
    return {
        "log": updated_resp.data[0] if updated_resp.data else {**row, **update_data},
        "record_hash": new_hash,
    }
