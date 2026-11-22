"""REST endpoints for asynchronous RoE scope negotiation, editing, termination, and SHA-256 sealing."""

from datetime import datetime, timezone
import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse

from app.compliance_engine.canonical_hasher import (
    canonicalize_json,
    compute_sha256_hash,
    verify_sha256_hash,
)
from app.compliance_engine.rules_evaluator import (
    ComplianceEvaluationInput,
    evaluate_art2_ley21459,
)
from app.core.database import get_supabase_client
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.roe_schema import (
    RoeClientApproveSchema,
    RoeContractMetadataSchema,
    RoeCreateSchema,
    RoeRevisionRequestSchema,
    RoeSealSchema,
    RoeStatusEnum,
    RoeTerminateSchema,
)
from app.serializers.pdf_engine import (
    compile_roe_contract_pdf,
    render_roe_contract_html,
)

router = APIRouter()

_META_SENTINEL_KEY = "__lexploit_contract_meta__"
_LEGACY_IMMUTABLE_META_FIELDS = (
    "client_legal_name",
    "client_tax_id",
    "regulatory_classification",
    "client_address",
    "client_rep_name",
    "client_rep_rut",
    "auditor_legal_name",
    "auditor_tax_id",
    "auditor_address",
    "auditor_lead_name",
    "auditor_lead_rut",
    "poc_primary_name",
    "poc_primary_rut",
    "poc_primary_role",
    "poc_primary_phone",
    "poc_primary_email",
    "poc_secondary_name",
    "poc_secondary_role",
    "poc_secondary_phone",
    "poc_secondary_email",
    "testing_modality",
    "allowed_time_window",
    "cloud_providers",
    "break_glass_hours",
    "data_purge_days",
)
_IMMUTABLE_META_FIELDS = (
    *_LEGACY_IMMUTABLE_META_FIELDS,
    "client_rep_personeria",
    "auditor_rep_personeria",
    "nda_enabled",
    "nda_duration_years",
    "nda_survival_years",
    "nda_penalty_uf",
    "nda_custom_terms",
    "liability_cap_pct",
    "dispute_resolution_seat",
    "custom_clauses",
    "additional_stipulations",
)


def _unpack_agreement(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a database row ensuring contract_metadata and excluded_assets are cleanly separated."""
    record = dict(row)
    raw_excluded = record.get("excluded_assets") or []
    clean_excluded: list[str] = []
    embedded_meta: dict[str, Any] = {}

    for item in raw_excluded:
        if isinstance(item, dict) and _META_SENTINEL_KEY in item:
            embedded_meta = item[_META_SENTINEL_KEY] or {}
        elif isinstance(item, str):
            clean_excluded.append(item)

    col_meta = record.get("contract_metadata")
    merged_meta = {
        **RoeContractMetadataSchema().model_dump(),
        **embedded_meta,
        **(col_meta if isinstance(col_meta, dict) else {}),
    }
    record["excluded_assets"] = clean_excluded
    record["contract_metadata"] = merged_meta
    return record


def _persist_with_metadata_fallback(
    table_op: str,
    record: dict[str, Any],
    metadata: dict[str, Any],
    agreement_id: str | None = None,
) -> dict[str, Any]:
    """Insert or update roe_agreements using contract_metadata column or JSONB fallback."""
    db = get_supabase_client()
    payload_with_col = {**record, "contract_metadata": metadata}

    try:
        if table_op == "insert":
            res = db.table("roe_agreements").insert(payload_with_col).execute()
        else:
            res = db.table("roe_agreements").update(payload_with_col).eq("id", agreement_id).execute()
        return _unpack_agreement(res.data[0])
    except Exception as exc:
        if "contract_metadata" not in str(exc):
            raise
        # Fallback transparente si aun no se ha corrido la migracion de contract_metadata
        base_excluded = [x for x in (record.get("excluded_assets") or []) if isinstance(x, str)]
        fallback_record = {
            **record,
            "excluded_assets": [*base_excluded, {_META_SENTINEL_KEY: metadata}],
        }
        if table_op == "insert":
            res = db.table("roe_agreements").insert(fallback_record).execute()
        else:
            res = db.table("roe_agreements").update(fallback_record).eq("id", agreement_id).execute()
        return _unpack_agreement(res.data[0])


def _upsert_organization(org_id: str, meta: RoeContractMetadataSchema) -> None:
    """Sync the client organization record in public.organizations with Chilean legal fields."""
    db = get_supabase_client()
    classification = meta.regulatory_classification.upper()
    is_vital = "OIV" in classification or "VITAL" in classification
    is_essential = is_vital or "ESENCIAL" in classification

    existing = db.table("organizations").select("id").eq("id", org_id).execute()
    if existing.data:
        db.table("organizations").update({
            "legal_name": meta.client_legal_name,
            "is_essential_service": is_essential,
            "is_vital_operator": is_vital,
        }).eq("id", org_id).execute()
        return

    by_rut = db.table("organizations").select("id").eq("tax_id", meta.client_tax_id).execute()
    tax_id_to_use = (
        f"{meta.client_tax_id}-{secrets.token_hex(2).upper()}"
        if by_rut.data
        else meta.client_tax_id
    )
    db.table("organizations").insert({
        "id": org_id,
        "legal_name": meta.client_legal_name,
        "tax_id": tax_id_to_use,
        "is_essential_service": is_essential,
        "is_vital_operator": is_vital,
    }).execute()


def _fetch_agreement_or_404(agreement_id: str, user_id: str) -> dict[str, Any]:
    """Fetch a RoE agreement ensuring the authenticated user is a party to it."""
    db = get_supabase_client()
    response = (
        db.table("roe_agreements")
        .select("*")
        .eq("id", agreement_id)
        .limit(1)
        .execute()
    )
    if not response.data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Acuerdo RoE no encontrado.")

    agreement = _unpack_agreement(response.data[0])
    if user_id not in {agreement["auditor_lead_id"], agreement["client_poc_id"]}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene permisos para acceder a este acuerdo RoE.",
        )
    return agreement


def _build_canonical_roe_payload(
    agreement: dict[str, Any],
    auditor_signed_at: str,
    meta_fields: tuple[str, ...] = _IMMUTABLE_META_FIELDS,
) -> dict[str, Any]:
    """Extract the immutable legal and technical fields of a RoE agreement for SHA-256 sealing."""
    meta = agreement.get("contract_metadata") or {}
    immutable_meta = {k: meta.get(k) for k in meta_fields}
    return {
        "id": agreement["id"],
        "organization_id": agreement["organization_id"],
        "title": agreement["title"],
        "version": agreement["version"],
        "client_poc_id": agreement["client_poc_id"],
        "auditor_lead_id": agreement["auditor_lead_id"],
        "execution_start": agreement["execution_start"],
        "execution_end": agreement["execution_end"],
        "target_assets": agreement["target_assets"],
        "excluded_assets": agreement["excluded_assets"],
        "auditor_source_ips": agreement["auditor_source_ips"],
        "traffic_header_token": agreement["traffic_header_token"],
        "backup_confirmed": agreement["backup_confirmed"],
        "cloud_authorization_confirmed": agreement["cloud_authorization_confirmed"],
        "client_signed_at": agreement["client_signed_at"],
        "auditor_signed_at": auditor_signed_at,
        "contract_parties_and_terms": immutable_meta,
    }


def _evaluate_agreement_compliance(agreement: dict[str, Any]) -> dict[str, Any]:
    """Run pure Art. 2° Ley N° 21.459 evaluation over a persisted RoE record."""
    def _parse_dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))

    eval_input = ComplianceEvaluationInput(
        roe_status=agreement["current_status"],
        client_signed_at=_parse_dt(agreement.get("client_signed_at")),
        auditor_signed_at=_parse_dt(agreement.get("auditor_signed_at")),
        sha256_hash=agreement.get("sha256_hash"),
        execution_start=_parse_dt(agreement["execution_start"]),  # type: ignore[arg-type]
        execution_end=_parse_dt(agreement["execution_end"]),  # type: ignore[arg-type]
        target_assets=agreement.get("target_assets") or [],
        excluded_assets=agreement.get("excluded_assets") or [],
        auditor_source_ips=agreement.get("auditor_source_ips") or [],
        traffic_header_token=agreement.get("traffic_header_token") or "",
        client_poc_id=str(agreement.get("client_poc_id") or ""),
        backup_confirmed=bool(agreement.get("backup_confirmed")),
        cloud_authorization_confirmed=bool(agreement.get("cloud_authorization_confirmed")),
        evaluation_time=_parse_dt(agreement["execution_start"]),
    )
    res = evaluate_art2_ley21459(eval_input)
    return {
        "is_exempt": res.is_exempt,
        "failed_conditions": res.failed_conditions,
        "conditions": [
            {"code": c.code, "name": c.name, "passed": c.passed, "reason": c.reason}
            for c in res.conditions
        ],
    }


@router.post("/proposals", status_code=status.HTTP_201_CREATED)
def create_roe_proposal(
    payload: RoeCreateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Create a new RoE agreement in DRAFT state with Chilean legal party metadata."""
    token = payload.traffic_header_token or f"LXP-{secrets.token_hex(6).upper()}"
    org_id_str = str(payload.organization_id)
    _upsert_organization(org_id_str, payload.contract_metadata)

    record = {
        "organization_id": org_id_str,
        "title": payload.title,
        "current_status": RoeStatusEnum.DRAFT.value,
        "version": 1,
        "client_poc_id": str(payload.client_poc_id),
        "auditor_lead_id": current_user.user_id,
        "execution_start": payload.execution_start.astimezone(timezone.utc).isoformat(),
        "execution_end": payload.execution_end.astimezone(timezone.utc).isoformat(),
        "target_assets": payload.target_assets,
        "excluded_assets": payload.excluded_assets,
        "auditor_source_ips": payload.auditor_source_ips,
        "traffic_header_token": token,
        "backup_confirmed": payload.backup_confirmed,
        "cloud_authorization_confirmed": payload.cloud_authorization_confirmed,
    }

    created = _persist_with_metadata_fallback("insert", record, payload.contract_metadata.model_dump())
    return {"agreement": created}


@router.put("/{agreement_id}")
def update_roe_proposal(
    agreement_id: str,
    payload: RoeCreateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Update a RoE agreement when in DRAFT or REVISION_REQUESTED state (Auditor Lead)."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["auditor_lead_id"] != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo el Auditor Lead puede modificar la propuesta de RoE.",
        )

    if agreement.get("sha256_hash") or agreement["current_status"] not in {
        RoeStatusEnum.DRAFT.value,
        RoeStatusEnum.REVISION_REQUESTED.value,
    }:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Inmutabilidad contractual: No se puede editar un acuerdo en estado "
                f"'{agreement['current_status']}' o sellado con SHA-256."
            ),
        )

    org_id_str = str(payload.organization_id or agreement["organization_id"])
    _upsert_organization(org_id_str, payload.contract_metadata)

    existing_meta = agreement.get("contract_metadata") or {}
    updated_meta = {
        **payload.contract_metadata.model_dump(),
        "revision_history": existing_meta.get("revision_history", []),
    }

    record = {
        "organization_id": org_id_str,
        "title": payload.title,
        "execution_start": payload.execution_start.astimezone(timezone.utc).isoformat(),
        "execution_end": payload.execution_end.astimezone(timezone.utc).isoformat(),
        "target_assets": payload.target_assets,
        "excluded_assets": payload.excluded_assets,
        "auditor_source_ips": payload.auditor_source_ips,
        "traffic_header_token": payload.traffic_header_token or agreement["traffic_header_token"],
        "backup_confirmed": payload.backup_confirmed,
        "cloud_authorization_confirmed": payload.cloud_authorization_confirmed,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    saved = _persist_with_metadata_fallback("update", record, updated_meta, agreement_id)
    compliance = _evaluate_agreement_compliance(saved)
    return {"agreement": saved, "art2_compliance": compliance}


@router.get("/")
def list_roe_agreements(
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List RoE agreements where the authenticated user is auditor lead or client PoC."""
    db = get_supabase_client()
    response = (
        db.table("roe_agreements")
        .select("*")
        .or_(f"auditor_lead_id.eq.{current_user.user_id},client_poc_id.eq.{current_user.user_id}")
        .order("created_at", desc=True)
        .execute()
    )
    return {"agreements": [_unpack_agreement(row) for row in response.data]}


@router.get("/{agreement_id}")
def get_roe_agreement(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve a single RoE agreement along with its Art. 2° Ley N° 21.459 evaluation."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    compliance = _evaluate_agreement_compliance(agreement)
    return {"agreement": agreement, "art2_compliance": compliance}


@router.get("/{agreement_id}/verify-integrity")
def verify_roe_integrity(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Recompute the canonical SHA-256 digest of a sealed RoE and verify no tampering occurred."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    stored_hash = agreement.get("sha256_hash")
    auditor_signed_at = agreement.get("auditor_signed_at")

    if not stored_hash or not auditor_signed_at:
        return {
            "is_sealed": False,
            "is_intact": False,
            "message": "El acuerdo aun no ha sido contra-firmado ni sellado con SHA-256.",
            "stored_hash": None,
            "recomputed_hash": None,
        }

    canonical_payload = _build_canonical_roe_payload(agreement, auditor_signed_at)
    recomputed_hash = compute_sha256_hash(canonical_payload)
    is_intact = verify_sha256_hash(canonical_payload, stored_hash)

    if not is_intact:
        # Backward compatibility for contracts sealed under v1 schema before NDA fields were added
        legacy_payload = _build_canonical_roe_payload(
            agreement, auditor_signed_at, meta_fields=_LEGACY_IMMUTABLE_META_FIELDS
        )
        if verify_sha256_hash(legacy_payload, stored_hash):
            canonical_payload = legacy_payload
            recomputed_hash = compute_sha256_hash(legacy_payload)
            is_intact = True

    return {
        "is_sealed": True,
        "is_intact": is_intact,
        "stored_hash": stored_hash,
        "recomputed_hash": recomputed_hash,
        "canonical_json_preview": canonicalize_json(canonical_payload),
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "storage_location": "Supabase PostgreSQL (public.roe_agreements) con RLS + Trigger de Inmutabilidad",
        "message": (
            "INTEGRIDAD CRIPTOGRAFICA VERIFICADA: El contrato almacenado coincide bit a bit con el documento firmado."
            if is_intact
            else "ALERTA CRITICA DE SEGURIDAD: El contenido del acuerdo fue alterado despues del sellado SHA-256."
        ),
    }


@router.get("/{agreement_id}/export-pdf")
def export_roe_contract_pdf(
    agreement_id: str,
    format: str = Query("pdf", description="Formato de salida: 'pdf' o 'html'"),
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> Response:
    """Export the official RoE + Bilateral NDA Contract as PDF or printable HTML with Table of Contents."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    compliance = _evaluate_agreement_compliance(agreement)

    if format.lower() == "html":
        html_str = render_roe_contract_html(
            agreement=agreement,
            art2_compliance=compliance,
        )
        return HTMLResponse(content=html_str)

    pdf_bytes = compile_roe_contract_pdf(
        agreement=agreement,
        art2_compliance=compliance,
    )
    short_id = agreement_id[:8].upper()
    filename = f"Contrato_RoE_NDA_{short_id}_v{agreement.get('version', 1)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{agreement_id}/send-to-client")
def send_roe_to_client(
    agreement_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Transition RoE from DRAFT or REVISION_REQUESTED to UNDER_CLIENT_REVIEW (Auditor)."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["auditor_lead_id"] != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo el Auditor Lead puede enviar a revision.")

    if agreement["current_status"] not in {RoeStatusEnum.DRAFT.value, RoeStatusEnum.REVISION_REQUESTED.value}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Transicion invalida desde estado '{agreement['current_status']}'.",
        )

    record = {
        "current_status": RoeStatusEnum.UNDER_CLIENT_REVIEW.value,
        "excluded_assets": agreement["excluded_assets"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = _persist_with_metadata_fallback("update", record, agreement["contract_metadata"], agreement_id)
    return {"agreement": saved}


@router.post("/{agreement_id}/request-revision")
def request_roe_revision(
    agreement_id: str,
    payload: RoeRevisionRequestSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return RoE to REVISION_REQUESTED, record client observations, and increment version."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["client_poc_id"] != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo el Cliente PoC puede solicitar reparos.")

    if agreement["current_status"] != RoeStatusEnum.UNDER_CLIENT_REVIEW.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Solo se pueden ingresar reparos cuando el acuerdo esta en UNDER_CLIENT_REVIEW.",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    meta = dict(agreement.get("contract_metadata") or {})
    history = list(meta.get("revision_history") or [])
    history.append({
        "version": int(agreement["version"]),
        "observations": payload.observations,
        "requested_at": now_iso,
        "requested_by": meta.get("client_rep_name") or "Representante del Cliente",
    })
    meta["revision_history"] = history

    record = {
        "current_status": RoeStatusEnum.REVISION_REQUESTED.value,
        "version": int(agreement["version"]) + 1,
        "excluded_assets": agreement["excluded_assets"],
        "updated_at": now_iso,
    }
    saved = _persist_with_metadata_fallback("update", record, meta, agreement_id)
    return {"agreement": saved, "observations": payload.observations}


@router.post("/{agreement_id}/client-approve")
def client_approve_roe(
    agreement_id: str,
    payload: RoeClientApproveSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Record client approval and first timestamped electronic signature."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["client_poc_id"] != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo el Cliente PoC puede aprobar y firmar.")

    if agreement["current_status"] != RoeStatusEnum.UNDER_CLIENT_REVIEW.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El acuerdo debe estar en UNDER_CLIENT_REVIEW para ser aprobado.",
        )
    if not payload.backup_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El cliente debe confirmar la existencia de respaldos previos (backup_confirmed).",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    record = {
        "current_status": RoeStatusEnum.APPROVED_BY_CLIENT.value,
        "backup_confirmed": payload.backup_confirmed,
        "cloud_authorization_confirmed": payload.cloud_authorization_confirmed,
        "client_signed_at": now_iso,
        "excluded_assets": agreement["excluded_assets"],
        "updated_at": now_iso,
    }
    saved = _persist_with_metadata_fallback("update", record, agreement["contract_metadata"], agreement_id)
    return {"agreement": saved}


@router.post("/{agreement_id}/seal")
def seal_roe_agreement(
    agreement_id: str,
    payload: RoeSealSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Auditor counter-signs, computes canonical SHA-256 hash, and activates the RoE."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["auditor_lead_id"] != current_user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Solo el Auditor Lead puede sellar el acuerdo.")

    if agreement["current_status"] != RoeStatusEnum.APPROVED_BY_CLIENT.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El acuerdo requiere la firma previa del cliente (APPROVED_BY_CLIENT).",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    canonical_payload = _build_canonical_roe_payload(agreement, now_iso)
    sha256_digest = compute_sha256_hash(canonical_payload)

    target_status = (
        RoeStatusEnum.ACTIVE.value if payload.activate_immediately else RoeStatusEnum.SIGNED_AND_SEALED.value
    )

    record = {
        "current_status": target_status,
        "auditor_signed_at": now_iso,
        "sha256_hash": sha256_digest,
        "excluded_assets": agreement["excluded_assets"],
        "updated_at": now_iso,
    }
    sealed_agreement = _persist_with_metadata_fallback(
        "update", record, agreement["contract_metadata"], agreement_id
    )
    compliance = _evaluate_agreement_compliance(sealed_agreement)
    return {
        "agreement": sealed_agreement,
        "sha256_hash": sha256_digest,
        "art2_compliance": compliance,
    }


@router.post("/{agreement_id}/terminate")
def terminate_roe_agreement(
    agreement_id: str,
    payload: RoeTerminateSchema,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Reject, archive, or terminate a RoE agreement recording the reason and party."""
    agreement = _fetch_agreement_or_404(agreement_id, current_user.user_id)
    if agreement["current_status"] == RoeStatusEnum.TERMINATED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El acuerdo ya se encuentra en estado TERMINATED (archivado/rechazado).",
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    actor_role = "Auditor Lead" if current_user.user_id == agreement["auditor_lead_id"] else "Cliente / PoC"
    meta = dict(agreement.get("contract_metadata") or {})
    meta["termination_reason"] = payload.reason
    meta["terminated_by_role"] = actor_role
    meta["terminated_at"] = now_iso

    record = {
        "current_status": RoeStatusEnum.TERMINATED.value,
        "excluded_assets": agreement["excluded_assets"],
        "updated_at": now_iso,
    }
    saved = _persist_with_metadata_fallback("update", record, meta, agreement_id)
    compliance = _evaluate_agreement_compliance(saved)
    return {"agreement": saved, "art2_compliance": compliance}
