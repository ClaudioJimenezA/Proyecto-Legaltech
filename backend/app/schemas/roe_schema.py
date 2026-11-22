"""Pydantic v2 boundary contracts for Rules of Engagement (RoE) workflow."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import NAMESPACE_DNS, UUID, uuid5

from pydantic import BaseModel, Field, field_validator, model_validator

from app.compliance_engine.scope_validator import (
    validate_auditor_source_ips,
    validate_scope_assets,
)


class RoeStatusEnum(str, Enum):
    """Deterministic state machine statuses for roe_agreements."""

    DRAFT = "DRAFT"
    UNDER_CLIENT_REVIEW = "UNDER_CLIENT_REVIEW"
    REVISION_REQUESTED = "REVISION_REQUESTED"
    APPROVED_BY_CLIENT = "APPROVED_BY_CLIENT"
    SIGNED_AND_SEALED = "SIGNED_AND_SEALED"
    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"


class CustomClauseSchema(BaseModel):
    """Dynamic clause added or edited by the parties during RoE contract negotiation."""

    id: Optional[str] = Field(None, max_length=64)
    title: str = Field(..., min_length=3, max_length=255)
    content: str = Field(..., min_length=5, max_length=4000)


class RoeContractMetadataSchema(BaseModel):
    """Chilean legal & operational details for the RoE agreement (Leyes 21.459, 21.663, 21.719 + Estándar EPC y NDA Bilateral)."""

    # 1. Entidad Mandante (Cliente)
    client_legal_name: str = Field(
        "Banco Financiero Austral S.A.", min_length=2, max_length=255
    )
    client_tax_id: str = Field("76.543.210-K", min_length=8, max_length=20)
    regulatory_classification: str = Field(
        "Operador de Importancia Vital (OIV - Ley 21.663)", max_length=120
    )
    client_address: str = Field(
        "Av. Apoquindo 4500, Piso 18, Las Condes, Santiago", max_length=255
    )
    client_rep_name: str = Field("Roberto Domínguez Vial", min_length=3, max_length=150)
    client_rep_rut: str = Field("12.345.678-5", min_length=8, max_length=20)
    client_rep_personeria: str = Field(
        "Escritura pública de fecha 14 de marzo de 2024, otorgada en la 18ª Notaría de Santiago de don Evaldo Rehbein Utreras",
        max_length=300,
    )

    # 2. Entidad Ejecutora (Auditora)
    auditor_legal_name: str = Field(
        "LexPloit Offensive Security SpA", min_length=2, max_length=255
    )
    auditor_tax_id: str = Field("77.889.900-1", min_length=8, max_length=20)
    auditor_address: str = Field(
        "Av. Providencia 1208, Of. 804, Providencia, Santiago", max_length=255
    )
    auditor_lead_name: str = Field("Víctor Contreras Muñoz", min_length=3, max_length=150)
    auditor_lead_rut: str = Field("15.432.109-8", min_length=8, max_length=20)
    auditor_rep_personeria: str = Field(
        "Escritura pública de fecha 22 de enero de 2025, otorgada en la 27ª Notaría de Santiago de doña Nancy de la Fuente Hernández",
        max_length=300,
    )

    # 3. Punto de Contacto Titular (PoC Principal)
    poc_primary_name: str = Field("Carolina Morales Soto", min_length=3, max_length=150)
    poc_primary_rut: str = Field("16.789.012-3", min_length=8, max_length=20)
    poc_primary_role: str = Field(
        "CISO / Oficial de Seguridad de la Información", max_length=150
    )
    poc_primary_phone: str = Field("+56 9 8765 4321", min_length=8, max_length=40)
    poc_primary_email: str = Field("c.morales@bancoaustral.cl", min_length=5, max_length=150)

    # 4. Punto de Contacto Suplente (PoC Secundario)
    poc_secondary_name: Optional[str] = Field("Felipe Rojas Arancibia", max_length=150)
    poc_secondary_role: Optional[str] = Field("Subgerente de Infraestructura y SOC", max_length=150)
    poc_secondary_phone: Optional[str] = Field("+56 9 9123 4567", max_length=40)
    poc_secondary_email: Optional[str] = Field("f.rojas@bancoaustral.cl", max_length=150)

    # 5. Parametros Operativos, Break-Glass y Purga Ley 21.719
    testing_modality: str = Field("Gray-Box (Caja Gris)", max_length=60)
    allowed_time_window: str = Field(
        "Lunes a Viernes de 22:00 a 06:00 hrs (UTC-3 / Chile Continental)", max_length=150
    )
    cloud_providers: str = Field("AWS (us-east-1), Cloudflare Enterprise", max_length=255)
    break_glass_hours: int = Field(2, ge=1, le=24)
    data_purge_days: int = Field(14, ge=1, le=90)

    # 6. Acuerdo de Confidencialidad Bilateral (NDA) y Clausula Penal (Estándar Chileno)
    nda_enabled: bool = Field(True, description="Incluir Acuerdo de Confidencialidad Bilateral (NDA)")
    nda_duration_years: int = Field(3, ge=1, le=20, description="Años de vigencia del NDA")
    nda_survival_years: int = Field(2, ge=1, le=10, description="Años adicionales post-término")
    nda_penalty_uf: int = Field(
        500,
        ge=0,
        le=100000,
        description="Cláusula Penal (Art. 1535 Código Civil) en UF por divulgación no autorizada",
    )
    nda_custom_terms: str = Field(
        "Ambas Partes actuarán recíprocamente como Sociedad Emisora y Sociedad Receptora de Información Confidencial. "
        "Tendrá carácter de Información Confidencial toda arquitectura de red, código fuente, credenciales, vulnerabilidades "
        "zero-day o CVSS identificadas, bitácoras de telemetría, datos personales (Ley N° 21.719) y secretos comerciales. "
        "La Sociedad Receptora limitará el acceso exclusivamente al Personal Clave que haya suscrito acuerdos individuales de "
        "reserva, respondiendo solidariamente por cualquier filtración imputable a sus dependientes o asesores.",
        max_length=4000,
    )

    # 7. Gobernanza Corporativa EPC: Limitación de Responsabilidad, Arbitraje CAM y Ley 20.393
    liability_cap_pct: int = Field(
        30,
        ge=5,
        le=100,
        description="Límite máximo de responsabilidad contractual (% del valor del contrato, excluyendo dolo o culpa grave)",
    )
    dispute_resolution_seat: str = Field(
        "Centro de Arbitraje y Mediación (CAM) de la Cámara de Comercio de Santiago A.G. (Árbitro Mixto)",
        max_length=255,
    )

    # 8. Cláusulas Adicionales / Especiales y Edición de Texto Libre (Sugerencias del Cliente)
    custom_clauses: list[CustomClauseSchema] = Field(default_factory=list)
    additional_stipulations: Optional[str] = Field(
        "",
        max_length=4000,
        description="Texto editable para estipulaciones especiales o modificaciones solicitadas por el cliente",
    )

    # 9. Historial de revision y estado
    revision_history: list[dict[str, Any]] = Field(default_factory=list)
    termination_reason: Optional[str] = None
    terminated_by_role: Optional[str] = None
    terminated_at: Optional[str] = None


class RoeCreateSchema(BaseModel):
    """Payload to create or update a RoE proposal (DRAFT or REVISION_REQUESTED)."""

    organization_id: Optional[UUID] = Field(
        None, description="UUID de la organizacion (autogenerado desde el RUT si se omite)"
    )
    title: str = Field(..., min_length=5, max_length=255, description="Titulo del acuerdo RoE")
    client_poc_id: Optional[UUID] = Field(
        None, description="UUID del usuario PoC (asignado automaticamente si se omite)"
    )
    execution_start: datetime = Field(..., description="Inicio ventana autorizada UTC")
    execution_end: datetime = Field(..., description="Fin ventana autorizada UTC")
    target_assets: list[str] = Field(..., min_length=1, description="FQDNs, IPs o CIDRs In-Scope")
    excluded_assets: list[str] = Field(default_factory=list, description="Activos Out-of-Scope")
    auditor_source_ips: list[str] = Field(..., min_length=1, description="IPs publicas de salida del auditor")
    traffic_header_token: Optional[str] = Field(
        None,
        min_length=8,
        max_length=64,
        description="Valor de cabecera X-Assessment-Scope (autogenerado si se omite)",
    )
    backup_confirmed: bool = Field(False, description="Confirmacion de respaldo previo")
    cloud_authorization_confirmed: bool = Field(
        False, description="Autorizacion explicita para nube de terceros"
    )
    allow_state_domains: bool = Field(
        False, description="Permite dominios estatales solo bajo autorizacion expresa"
    )
    contract_metadata: RoeContractMetadataSchema = Field(
        default_factory=RoeContractMetadataSchema,
        description="Datos contractuales chilenos de comparecencia, PoC, NDA y clausulas",
    )

    @field_validator("auditor_source_ips")
    @classmethod
    def check_source_ips(cls, v: list[str]) -> list[str]:
        result = validate_auditor_source_ips(v)
        if not result.is_valid:
            raise ValueError("; ".join(result.errors))
        return result.valid_assets

    @model_validator(mode="after")
    def check_window_and_scope(self) -> "RoeCreateSchema":
        if self.execution_end <= self.execution_start:
            raise ValueError("La fecha/hora de termino debe ser posterior al inicio de ejecucion.")

        scope_res = validate_scope_assets(
            self.target_assets,
            self.excluded_assets,
            allow_state_domains=self.allow_state_domains,
        )
        if not scope_res.is_valid:
            raise ValueError("; ".join(scope_res.errors))
        self.target_assets = scope_res.valid_assets

        if self.organization_id is None:
            rut_seed = self.contract_metadata.client_tax_id.strip().upper()
            self.organization_id = uuid5(NAMESPACE_DNS, f"org.{rut_seed}.lexploit.cl")

        if self.client_poc_id is None:
            self.client_poc_id = UUID("00000000-0000-0000-0000-000000000002")

        return self


class RoeRevisionRequestSchema(BaseModel):
    """Client observations when returning a RoE to REVISION_REQUESTED."""

    observations: str = Field(..., min_length=5, max_length=2000)


class RoeClientApproveSchema(BaseModel):
    """Client approval & first digital signature payload."""

    backup_confirmed: bool = Field(
        ..., description="El cliente certifica que cuenta con respaldos previos verificados"
    )
    cloud_authorization_confirmed: bool = Field(
        default=True, description="El cliente confirma autorizacion de infraestructura cloud"
    )


class RoeSealSchema(BaseModel):
    """Auditor counter-signature & SHA-256 cryptographic sealing payload."""

    activate_immediately: bool = Field(
        default=True,
        description="Si es True, habilita la transicion inmediata a ACTIVE tras el sellado",
    )


class RoeTerminateSchema(BaseModel):
    """Payload to reject, cancel, or archive a RoE agreement when no consensus is reached."""

    reason: str = Field(
        ...,
        min_length=5,
        max_length=1000,
        description="Motivo formal del rechazo o termino anticipado del contrato",
    )
