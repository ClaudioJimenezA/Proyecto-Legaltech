"""REST endpoints for Vulnerability Tracking & Retest Lifecycle (Paso 3)."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.v1.endpoints.roe import _unpack_agreement
from app.core.database import get_supabase_client
from app.core.security import (
    AuthenticatedUser,
    get_current_user,
    resolve_or_provision_auth_user_id,
)
from app.schemas.vulnerability_schema import (
    VulnerabilityCreateSchema,
    VulnerabilityStatusUpdateSchema,
    VulnStatusEnum,
)

router = APIRouter()


@router.post("", status_code=status.HTTP_201_CREATED)
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
def create_vulnerability_finding(
    payload: VulnerabilityCreateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Register a structured technical vulnerability finding classified with CVSS v3.1."""
    supabase = get_supabase_client()
    agreement_id_str = str(payload.roe_agreement_id)

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

    row_to_insert = {
        "roe_agreement_id": agreement_id_str,
        "title": payload.title.strip(),
        "cve_id": payload.cve_id.strip() if payload.cve_id else None,
        "cwe_id": payload.cwe_id.strip() if payload.cwe_id else None,
        "severity": payload.severity.value,
        "cvss_score": round(float(payload.cvss_score), 1),
        "cvss_vector": payload.cvss_vector.strip().upper(),
        "affected_asset": payload.affected_asset.strip(),
        "technical_description": payload.technical_description.strip(),
        "remediation_recommendation": payload.remediation_recommendation.strip(),
        "current_status": VulnStatusEnum.IDENTIFIED.value,
    }

    insert_resp = supabase.table("vulnerabilities").insert(row_to_insert).execute()
    if not insert_resp.data:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al registrar la vulnerabilidad en Supabase.",
        )

    created_vuln = insert_resp.data[0]
    user_uuid = resolve_or_provision_auth_user_id(supabase, current_user)

    # Record initial lifecycle milestone in remediation_logs
    initial_log = {
        "vulnerability_id": str(created_vuln["id"]),
        "changed_by_user_id": user_uuid,
        "previous_status": VulnStatusEnum.IDENTIFIED.value,
        "new_status": VulnStatusEnum.IDENTIFIED.value,
        "comment": f"Hallazgo registrado e ingresado a matriz CVSS v3.1 por rol '{current_user.role}'.",
        "retest_evidence_url": None,
    }
    rem_resp = supabase.table("remediation_logs").insert(initial_log).execute()
    created_vuln["remediation_history"] = rem_resp.data or [initial_log]

    return {"vulnerability": created_vuln}


@router.get("/agreement/{agreement_id}")
def list_agreement_vulnerabilities(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List all vulnerabilities and their remediation/retest audit trail for an agreement."""
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

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_status = {
        "IDENTIFIED": 0,
        "IN_REMEDIATION": 0,
        "READY_FOR_RETEST": 0,
        "RETEST_PASSED": 0,
        "RETEST_FAILED": 0,
        "CLOSED": 0,
    }
    for v in vulns:
        sev = str(v.get("severity", "INFO"))
        st = str(v.get("current_status", "IDENTIFIED"))
        if sev in by_severity:
            by_severity[sev] += 1
        if st in by_status:
            by_status[st] += 1

    return {
        "agreement_id": agreement_id,
        "agreement_title": agreement.get("title"),
        "vulnerabilities": vulns,
        "summary": {
            "total": len(vulns),
            "by_severity": by_severity,
            "by_status": by_status,
            "resolved_count": by_status["RETEST_PASSED"] + by_status["CLOSED"],
        },
    }


@router.patch("/{vuln_id}/status")
def update_vulnerability_status(
    vuln_id: str,
    payload: VulnerabilityStatusUpdateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Advance or update a finding in its remediation and re-testing lifecycle."""
    supabase = get_supabase_client()

    existing_resp = (
        supabase.table("vulnerabilities")
        .select("*")
        .eq("id", vuln_id)
        .execute()
    )
    if not existing_resp.data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerabilidad {vuln_id} no encontrada.",
        )

    vuln_row = existing_resp.data[0]
    previous_status = str(vuln_row.get("current_status", "IDENTIFIED"))
    new_status = payload.new_status.value
    now_iso = datetime.now(timezone.utc).isoformat()

    updated_resp = (
        supabase.table("vulnerabilities")
        .update({"current_status": new_status, "updated_at": now_iso})
        .eq("id", vuln_id)
        .execute()
    )
    updated_vuln = updated_resp.data[0] if updated_resp.data else {**vuln_row, "current_status": new_status}

    user_uuid = resolve_or_provision_auth_user_id(supabase, current_user)
    role_tag = (current_user.role or "auditor").upper()
    formatted_comment = (
        f"[{role_tag}] {payload.comment.strip()}"
        if payload.comment and payload.comment.strip()
        else f"[{role_tag}] Transición de estado: {previous_status} → {new_status}"
    )

    rem_entry = {
        "vulnerability_id": vuln_id,
        "changed_by_user_id": user_uuid,
        "previous_status": previous_status,
        "new_status": new_status,
        "comment": formatted_comment,
        "retest_evidence_url": (
            payload.retest_evidence_url.strip() if payload.retest_evidence_url else None
        ),
    }
    supabase.table("remediation_logs").insert(rem_entry).execute()

    history_resp = (
        supabase.table("remediation_logs")
        .select("*")
        .eq("vulnerability_id", vuln_id)
        .order("created_at", desc=False)
        .execute()
    )
    updated_vuln["remediation_history"] = history_resp.data or [rem_entry]

    return {"vulnerability": updated_vuln}
