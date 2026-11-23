"""REST endpoints for SOC & ANCI Real-Time Incident Deconfliction (Paso 2 - Ley N° 21.663)."""

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.v1.endpoints.roe import _unpack_agreement
from app.compliance_engine.canonical_hasher import compute_sha256_hash
from app.compliance_engine.deconfliction_matcher import (
    IncidentAlarmInput,
    LogCandidate,
    match_incident_against_logs,
)
from app.core.database import get_supabase_client
from app.core.security import (
    AuthenticatedUser,
    get_current_user,
    resolve_or_provision_auth_user_id,
)
from app.schemas.deconfliction_schema import DeconflictionQuerySchema

router = APIRouter()


def _parse_iso_dt(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


def _row_to_log_candidate(row: dict[str, Any]) -> LogCandidate:
    started = _parse_iso_dt(row.get("started_at")) or datetime.now(timezone.utc)
    ended = _parse_iso_dt(row.get("ended_at"))
    return LogCandidate(
        log_id=str(row["id"]),
        agreement_id=str(row["agreement_id"]),
        started_at=started,
        ended_at=ended,
        source_ip=str(row.get("source_ip", "")),
        target_host=str(row.get("target_host", "")),
        target_port=row.get("target_port"),
        target_endpoint=row.get("target_endpoint"),
        http_method=row.get("http_method"),
        injected_header_token=row.get("injected_header_token"),
        activity_type=str(row.get("activity_type", "RECON_SCAN")),
        tool_or_technique=str(row.get("tool_or_technique", "")),
        description=str(row.get("description", "")),
        record_hash=str(row.get("record_hash", "")).strip(),
        is_critical_finding=bool(row.get("is_critical_finding", False)),
    )


def _compute_certificate_hash(
    query_row: dict[str, Any],
    agreement_hash: Optional[str],
    matched_log_hash: Optional[str],
) -> str:
    payload = {
        "query_id": str(query_row.get("id")),
        "agreement_id": str(query_row.get("agreement_id")),
        "agreement_sha256": agreement_hash or "UNSEALED",
        "incident_timestamp": str(query_row.get("incident_timestamp")),
        "observed_attacker_ip": str(query_row.get("observed_attacker_ip")),
        "targeted_asset": str(query_row.get("targeted_asset")),
        "resolution": str(query_row.get("resolution")),
        "matched_log_id": str(query_row.get("matched_log_id")) if query_row.get("matched_log_id") else None,
        "matched_log_sha256": matched_log_hash,
    }
    return compute_sha256_hash(payload)


@router.post("/match", status_code=status.HTTP_201_CREATED)
def match_soc_incident(
    payload: DeconflictionQuerySchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Correlate a SIEM/WAF alarm against active assessment logs (+-2 min tolerance) and persist resolution."""
    supabase = get_supabase_client()
    agreement_id_str = str(payload.agreement_id)

    # 1. Fetch RoE Agreement
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

    # 2. Fetch all assessment logs for this agreement
    logs_resp = (
        supabase.table("assessment_logs")
        .select("*")
        .eq("agreement_id", agreement_id_str)
        .order("started_at", desc=True)
        .execute()
    )
    raw_logs: list[dict[str, Any]] = logs_resp.data or []
    logs_by_id: dict[str, dict[str, Any]] = {str(r["id"]): r for r in raw_logs}
    candidates = [_row_to_log_candidate(r) for r in raw_logs]

    # 3. Run pure spatiotemporal deconfliction matcher (+-2 minutes)
    alarm_input = IncidentAlarmInput(
        agreement_id=agreement_id_str,
        incident_timestamp=payload.incident_timestamp,
        observed_attacker_ip=payload.observed_attacker_ip,
        targeted_asset=payload.targeted_asset,
        internal_ticket_ref=payload.internal_ticket_ref,
    )
    match_result = match_incident_against_logs(
        alarm=alarm_input,
        logs=candidates,
        authorized_auditor_ips=agreement.get("auditor_source_ips") or [],
        target_assets=agreement.get("target_assets") or [],
        excluded_assets=agreement.get("excluded_assets") or [],
        execution_start=_parse_iso_dt(agreement.get("execution_start")),
        execution_end=_parse_iso_dt(agreement.get("execution_end")),
    )

    queried_by_uuid = resolve_or_provision_auth_user_id(supabase, current_user)

    query_row_to_insert = {
        "agreement_id": agreement_id_str,
        "queried_by": queried_by_uuid,
        "incident_timestamp": payload.incident_timestamp.isoformat(),
        "observed_attacker_ip": payload.observed_attacker_ip,
        "targeted_asset": payload.targeted_asset.strip(),
        "internal_ticket_ref": payload.internal_ticket_ref,
        "matched_log_id": match_result.matched_log_id,
        "resolution": match_result.resolution.value,
        "justification_notes": match_result.justification_notes,
    }

    insert_resp = (
        supabase.table("deconfliction_queries")
        .insert(query_row_to_insert)
        .execute()
    )
    if not insert_resp.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al persistir la consulta de desconflicto en Supabase.",
        )

    saved_query = insert_resp.data[0]
    matched_log_row = (
        logs_by_id.get(match_result.matched_log_id)
        if match_result.matched_log_id
        else None
    )

    cert_hash = _compute_certificate_hash(
        saved_query,
        agreement.get("sha256_hash"),
        matched_log_row.get("record_hash") if matched_log_row else None,
    )

    return {
        "query": saved_query,
        "resolution": match_result.resolution.value,
        "anci_report_required": match_result.anci_report_required,
        "time_delta_seconds": match_result.time_delta_seconds,
        "ip_matched": match_result.ip_matched,
        "asset_matched": match_result.asset_matched,
        "time_window_matched": match_result.time_window_matched,
        "matched_log": matched_log_row,
        "certificate_hash": cert_hash,
    }


@router.get("/history/{agreement_id}")
def list_deconfliction_history(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List all SOC deconfliction queries and resolutions for a specific RoE agreement."""
    supabase = get_supabase_client()
    queries_resp = (
        supabase.table("deconfliction_queries")
        .select("*")
        .eq("agreement_id", agreement_id)
        .order("created_at", desc=True)
        .execute()
    )
    queries = queries_resp.data or []
    return {
        "agreement_id": agreement_id,
        "queries": queries,
        "total": len(queries),
    }


@router.delete("/history/{agreement_id}")
def clear_deconfliction_history(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Clear deconfliction test/simulation queries for an agreement while preserving immutable assessment_logs."""
    supabase = get_supabase_client()
    existing_resp = (
        supabase.table("deconfliction_queries")
        .select("id")
        .eq("agreement_id", agreement_id)
        .execute()
    )
    existing_ids = [str(r["id"]) for r in (existing_resp.data or [])]
    if existing_ids:
        supabase.table("deconfliction_queries").delete().eq("agreement_id", agreement_id).execute()

    return {
        "agreement_id": agreement_id,
        "deleted_count": len(existing_ids),
        "preserved_immutable_telemetry_logs": True,
        "message": (
            f"Se eliminaron {len(existing_ids)} consultas del historial de desconflicto. "
            f"La Bitácora de Telemetría Inmutable (assessment_logs) se mantiene íntegra."
        ),
    }


@router.delete("/{query_id}")
def delete_single_deconfliction_query(
    query_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Delete a single deconfliction query (e.g. a hypothetical test simulation) from the history."""
    supabase = get_supabase_client()
    supabase.table("deconfliction_queries").delete().eq("id", query_id).execute()
    return {
        "deleted_query_id": query_id,
        "preserved_immutable_telemetry_logs": True,
    }


@router.get("/{query_id}/certificate")
def get_deconfliction_certificate(
    query_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Generate the signed Digital Deconfliction Certificate for ANCI compliance (Ley N° 21.663)."""
    supabase = get_supabase_client()

    q_resp = (
        supabase.table("deconfliction_queries")
        .select("*")
        .eq("id", query_id)
        .execute()
    )
    if not q_resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Consulta de desconflicto {query_id} no encontrada.",
        )
    query_row = q_resp.data[0]

    roe_resp = (
        supabase.table("roe_agreements")
        .select("*")
        .eq("id", str(query_row["agreement_id"]))
        .execute()
    )
    agreement = _unpack_agreement(roe_resp.data[0]) if roe_resp.data else {}
    meta = agreement.get("contract_metadata") or {}

    matched_log_row = None
    if query_row.get("matched_log_id"):
        log_resp = (
            supabase.table("assessment_logs")
            .select("*")
            .eq("id", str(query_row["matched_log_id"]))
            .execute()
        )
        if log_resp.data:
            matched_log_row = log_resp.data[0]

    cert_hash = _compute_certificate_hash(
        query_row,
        agreement.get("sha256_hash"),
        matched_log_row.get("record_hash") if matched_log_row else None,
    )

    resolution_value = query_row.get("resolution")
    is_authorized = resolution_value == "CONFIRMED_AUTHORIZED"
    is_indeterminate = resolution_value == "INDETERMINATE"

    if is_authorized:
        legal_determination = (
            "EXIMIDO DE DENUNCIA ANTE ANCI: El tráfico analizado corresponde a una prueba técnica "
            "expresamente autorizada por el titular del activo bajo contrato RoE sellado con SHA-256. "
            "No constituye un incidente de ciberseguridad real ni activa el plazo de 3 horas de "
            "alerta temprana del Art. 37 de la Ley N° 21.663."
        )
    elif is_indeterminate:
        legal_determination = (
            "VERIFICACIÓN MANUAL REQUERIDA (INDETERMINADO): El tráfico incidió sobre un activo "
            "permitido (In-Scope), pero presentó una desviación operativa o temporal (desfase de reloj, "
            "ventana horaria contractual o IP de origen no enrolada) que impide la exención automática. "
            "El Punto de Contacto (PoC) debe validar directamente con el Lead Pentester antes de "
            "activar el protocolo de notificación ante la ANCI."
        )
    else:
        if matched_log_row and matched_log_row.get("is_critical_finding"):
            legal_determination = (
                "NO EXIMIDO — ALERTA CRÍTICA BREAK-GLASS CORRELACIONADA: El tráfico coincide con un "
                "registro de la bitácora del auditor etiquetado como HALLAZGO CRÍTICO (Protocolo Break-Glass, "
                "Cláusula 7ª RoE). Se ordena suspensión inmediata de maniobras sobre el vector, contención "
                "defensiva coordinada con el PoC y evaluación de Alerta Temprana (3 horas) ante la ANCI "
                "(Art. 37 Ley N° 21.663)."
            )
        elif matched_log_row:
            legal_determination = (
                "NO EXIMIDO — EXCESO DE MANDATO / ACTIVO FUERA DE ALCANCE (ART. 1° LEY N° 21.459): "
                "Aunque existe un registro en la bitácora del auditor, el activo afectado se encuentra "
                "excluido (Hard Deny List) o fuera de los activos autorizados (In-Scope) del contrato RoE. "
                "Mantener contención defensiva y evaluar el reporte obligatorio ante la ANCI (Art. 37 Ley N° 21.663)."
            )
        else:
            legal_determination = (
                "NO EXIMIDO — ALERTA DE INTRUSIÓN EXTERNA NO AUTORIZADA: No existe coincidencia en la "
                "bitácora del auditor para la IP y activo consultados. El tráfico debe tratarse como un "
                "incidente de ciberseguridad real sujeto a contención inmediata y reporte de Alerta Temprana "
                "(plazo máximo 3 horas) ante la ANCI (Art. 37 Ley N° 21.663)."
            )

    return {
        "certificate_id": f"CERT-ANCI-{str(query_row['id'])[:8].upper()}",
        "query_id": query_row["id"],
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "regulatory_framework": [
            "Ley N° 21.663 (Ley Marco de Ciberseguridad - Art. 5° y Art. 37 Reporte a ANCI)",
            "Ley N° 21.459 (Delitos Informáticos - Art. 1° y Art. 2° Eximente por Mandato de Auditoría)",
            "Ley N° 19.799 (Documentos Electrónicos y Sellado Criptográfico SHA-256)",
        ],
        "resolution": resolution_value,
        "anci_early_warning_dismissed": is_authorized,
        "legal_determination": legal_determination,
        "client_entity": {
            "legal_name": meta.get("client_legal_name", "Entidad Mandante"),
            "tax_id": meta.get("client_tax_id", "N/A"),
            "regulatory_classification": meta.get("regulatory_classification", "OIV / Servicio Esencial"),
            "legal_representative": meta.get("client_rep_name", "N/A"),
            "legal_representative_rut": meta.get("client_rep_rut", "N/A"),
            "poc_name": meta.get("poc_primary_name", "N/A"),
            "poc_rut": meta.get("poc_primary_rut", "N/A"),
            "poc_email": meta.get("poc_primary_email", "N/A"),
        },
        "auditor_entity": {
            "legal_name": meta.get("auditor_legal_name", "Consultora de Ciberseguridad"),
            "tax_id": meta.get("auditor_tax_id", "N/A"),
            "lead_pentester_name": meta.get("auditor_lead_name", "N/A"),
            "lead_pentester_rut": meta.get("auditor_lead_rut", "N/A"),
        },
        "roe_contract_reference": {
            "agreement_id": agreement.get("id"),
            "title": agreement.get("title"),
            "traffic_header_token": agreement.get("traffic_header_token"),
            "contract_sha256_hash": agreement.get("sha256_hash"),
        },
        "siem_incident_queried": {
            "internal_ticket_ref": query_row.get("internal_ticket_ref") or "SIN-TICKET",
            "incident_timestamp": query_row.get("incident_timestamp"),
            "observed_attacker_ip": str(query_row.get("observed_attacker_ip")),
            "targeted_asset": query_row.get("targeted_asset"),
            "queried_at": query_row.get("created_at"),
        },
        "matched_telemetry_log": (
            {
                "log_id": matched_log_row.get("id"),
                "started_at": matched_log_row.get("started_at"),
                "ended_at": matched_log_row.get("ended_at"),
                "source_ip": str(matched_log_row.get("source_ip")),
                "target_host": matched_log_row.get("target_host"),
                "target_port": matched_log_row.get("target_port"),
                "target_endpoint": matched_log_row.get("target_endpoint"),
                "http_method": matched_log_row.get("http_method"),
                "activity_type": matched_log_row.get("activity_type"),
                "tool_or_technique": matched_log_row.get("tool_or_technique"),
                "is_critical_finding": bool(matched_log_row.get("is_critical_finding", False)),
                "record_sha256_hash": str(matched_log_row.get("record_hash", "")).strip(),
            }
            if matched_log_row
            else None
        ),
        "justification_notes": query_row.get("justification_notes"),
        "certificate_sha256_hash": cert_hash,
    }
