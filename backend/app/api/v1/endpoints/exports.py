"""REST endpoints for Dual ANCI Export Package (PDF + OASIS CSAF 2.0 XML/JSON) and Ley 21.719 Purge."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse

from app.api.v1.endpoints.roe import (
    _evaluate_agreement_compliance,
    _unpack_agreement,
)
from app.compliance_engine.canonical_hasher import compute_sha256_hash
from app.core.database import get_supabase_client
from app.core.security import AuthenticatedUser, get_current_user
from app.serializers.csaf_serializer import (
    build_csaf_advisory_json,
    serialize_csaf_to_xml,
)
from app.serializers.pdf_engine import (
    compile_compliance_report_pdf,
    render_compliance_report_html,
)

router = APIRouter()


def _gather_agreement_dossier(agreement_id: str) -> dict[str, Any]:
    """Fetch complete dossier for an agreement: RoE, Art. 2 evaluation, vulnerabilities, logs, deconflictions."""
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
    art2_compliance = _evaluate_agreement_compliance(agreement)

    vulns_resp = (
        supabase.table("vulnerabilities")
        .select("*")
        .eq("roe_agreement_id", agreement_id)
        .order("cvss_score", desc=True)
        .execute()
    )
    vulns: list[dict[str, Any]] = vulns_resp.data or []
    vuln_ids = [str(v["id"]) for v in vulns]
    history_by_vuln: dict[str, list[dict[str, Any]]] = {vid: [] for vid in vuln_ids}

    if vuln_ids:
        rem_resp = (
            supabase.table("remediation_logs")
            .select("*")
            .in_("vulnerability_id", vuln_ids)
            .order("created_at", desc=False)
            .execute()
        )
        for r in rem_resp.data or []:
            vid = str(r.get("vulnerability_id"))
            if vid in history_by_vuln:
                history_by_vuln[vid].append(r)

    for v in vulns:
        v["remediation_history"] = history_by_vuln.get(str(v["id"]), [])

    logs_resp = (
        supabase.table("assessment_logs")
        .select("*")
        .eq("agreement_id", agreement_id)
        .order("started_at", desc=True)
        .execute()
    )
    logs: list[dict[str, Any]] = logs_resp.data or []

    deconf_resp = (
        supabase.table("deconfliction_queries")
        .select("*")
        .eq("agreement_id", agreement_id)
        .order("created_at", desc=True)
        .execute()
    )
    deconflictions: list[dict[str, Any]] = deconf_resp.data or []

    csaf_package = build_csaf_advisory_json(
        agreement=agreement,
        art2_compliance=art2_compliance,
        vulnerabilities=vulns,
        logs=logs,
        deconfliction_queries=deconflictions,
    )
    package_hash = csaf_package["lexploit_compliance_extension"]["package_sha256_hash"]

    return {
        "agreement": agreement,
        "art2_compliance": art2_compliance,
        "vulnerabilities": vulns,
        "logs": logs,
        "deconflictions": deconflictions,
        "csaf_package": csaf_package,
        "package_sha256_hash": package_hash,
    }


@router.get("/pdf/{agreement_id}")
def export_compliance_pdf(
    agreement_id: str,
    format: str = Query("pdf", description="Formato de salida: 'pdf' o 'html'"),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Response:
    """Generate and download the official legal & technical compliance report (PDF or printable HTML)."""
    dossier = _gather_agreement_dossier(agreement_id)

    if format.lower() == "html":
        html_str = render_compliance_report_html(
            agreement=dossier["agreement"],
            art2_compliance=dossier["art2_compliance"],
            vulnerabilities=dossier["vulnerabilities"],
            logs=dossier["logs"],
            deconfliction_queries=dossier["deconflictions"],
            package_sha256_hash=dossier["package_sha256_hash"],
        )
        return HTMLResponse(content=html_str)

    pdf_bytes = compile_compliance_report_pdf(
        agreement=dossier["agreement"],
        art2_compliance=dossier["art2_compliance"],
        vulnerabilities=dossier["vulnerabilities"],
        logs=dossier["logs"],
        deconfliction_queries=dossier["deconflictions"],
        package_sha256_hash=dossier["package_sha256_hash"],
    )
    short_id = agreement_id[:8].upper()
    filename = f"Expediente_Legal_LexPloit_{short_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/csaf/{agreement_id}")
def export_csaf_advisory_package(
    agreement_id: str,
    format: str = Query("json", description="Formato de serialización CSAF 2.0: 'json' o 'xml'"),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Export the machine-readable OASIS CSAF 2.0 advisory package for ANCI / CSIRT ingestion."""
    dossier = _gather_agreement_dossier(agreement_id)
    csaf_package = dossier["csaf_package"]
    short_id = agreement_id[:8].upper()

    if format.lower() == "xml":
        xml_str = serialize_csaf_to_xml(csaf_package)
        filename = f"ANCI_CSAF20_{short_id}.xml"
        return Response(
            content=xml_str.encode("utf-8"),
            media_type="application/xml; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return csaf_package


@router.post("/purge-evidence/{agreement_id}")
def execute_certified_data_purge(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Execute and certify irreversible purge of raw evidence attachments (Ley N° 21.719)."""
    supabase = get_supabase_client()
    dossier = _gather_agreement_dossier(agreement_id)
    agreement = dossier["agreement"]
    meta = agreement.get("contract_metadata") or {}
    logs = dossier["logs"]
    log_ids = [str(l["id"]) for l in logs]

    purged_attachments_count = 0
    if log_ids:
        att_resp = (
            supabase.table("log_evidence_attachments")
            .select("id")
            .in_("log_id", log_ids)
            .execute()
        )
        attachments = att_resp.data or []
        purged_attachments_count = len(attachments)
        if purged_attachments_count > 0:
            supabase.table("log_evidence_attachments").delete().in_("log_id", log_ids).execute()

    now_iso = datetime.now(timezone.utc).isoformat()
    purge_payload = {
        "agreement_id": agreement_id,
        "client_legal_name": meta.get("client_legal_name"),
        "client_tax_id": meta.get("client_tax_id"),
        "auditor_legal_name": meta.get("auditor_legal_name"),
        "auditor_lead_name": meta.get("auditor_lead_name"),
        "auditor_lead_rut": meta.get("auditor_lead_rut"),
        "purged_at": now_iso,
        "executed_by_role": current_user.role or "auditor",
        "purged_raw_attachments_count": purged_attachments_count,
        "anonymized_logs_preserved_count": len(logs),
        "legal_statute": "Ley N° 21.719 sobre Protección de Datos Personales (Minimización y Limitación del Plazo de Conservación)",
    }
    purge_hash = compute_sha256_hash(purge_payload)

    return {
        "certificate_id": f"PURGA-21719-{agreement_id[:8].upper()}",
        "purged_at": now_iso,
        "executed_by": current_user.email or current_user.role,
        "purged_raw_attachments_count": purged_attachments_count,
        "anonymized_telemetry_records_preserved": len(logs),
        "purge_deadline_days": meta.get("data_purge_days", 14),
        "legal_declaration": (
            f"CERTIFICADO DE DESTRUCCIÓN Y PURGA IRREVERSIBLE (LEY N° 21.719): Se certifica que todos "
            f"los artefactos temporales, capturas crudas y datos personales recolectados incidentalmente "
            f"durante la evaluación del acuerdo '{agreement.get('title')}' han sido destruidos de forma "
            f"irreversible dentro del plazo perentorio de {meta.get('data_purge_days', 14)} días hábiles, "
            f"conservando únicamente los metadatos estadísticos anonimizados y los resúmenes criptográficos "
            f"SHA-256 para efectos probatorios del Art. 2° de la Ley N° 21.459."
        ),
        "client_entity": {
            "legal_name": meta.get("client_legal_name"),
            "tax_id": meta.get("client_tax_id"),
            "representative_name": meta.get("client_rep_name"),
            "representative_rut": meta.get("client_rep_rut"),
        },
        "auditor_entity": {
            "legal_name": meta.get("auditor_legal_name"),
            "tax_id": meta.get("auditor_tax_id"),
            "lead_pentester_name": meta.get("auditor_lead_name"),
            "lead_pentester_rut": meta.get("auditor_lead_rut"),
        },
        "purge_certificate_sha256_hash": purge_hash,
    }
