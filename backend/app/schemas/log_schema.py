"""Pydantic v2 boundary contracts for Live Assessment Logger (Paso 2)."""

from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


class LogActivityTypeEnum(str, Enum):
    """Allowed telemetry activity categories in assessment_logs."""

    RECON_SCAN = "RECON_SCAN"
    VULN_PROBE = "VULN_PROBE"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    EXPLOIT_POC = "EXPLOIT_POC"
    POST_EXPLOIT_VERIF = "POST_EXPLOIT_VERIF"
    OTHER = "OTHER"


class AssessmentLogCreateSchema(BaseModel):
    """Payload contract for registering a live security test event."""

    agreement_id: UUID = Field(..., description="UUID del acuerdo RoE activo o sellado")
    started_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp exacto de inicio de la prueba en UTC",
    )
    ended_at: Optional[datetime] = Field(
        None, description="Timestamp de término de la prueba (opcional si está en curso)"
    )
    source_ip: str = Field(..., description="IP pública de origen desde la que actúa el pentester")
    target_host: str = Field(
        ..., min_length=3, max_length=255, description="FQDN o dirección IP evaluada"
    )
    target_port: Optional[int] = Field(
        None, ge=1, le=65535, description="Puerto de red destino (1-65535)"
    )
    target_endpoint: Optional[str] = Field(
        None, max_length=512, description="Ruta URI o endpoint específico evaluado"
    )
    http_method: Optional[str] = Field(
        None, description="Método HTTP (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)"
    )
    injected_header_token: Optional[str] = Field(
        None, max_length=64, description="Token X-Assessment-Scope inyectado en el tráfico"
    )
    activity_type: LogActivityTypeEnum = Field(
        ..., description="Categoría técnica de la actividad ejecutada"
    )
    tool_or_technique: str = Field(
        ..., min_length=2, max_length=150, description="Herramienta, script o técnica MITRE ATT&CK"
    )
    description: str = Field(
        ..., min_length=5, max_length=2000, description="Detalle técnico del vector o procedimiento"
    )
    is_critical_finding: bool = Field(
        False, description="Indica si activa protocolo de emergencia Break-Glass"
    )
    system_impact_observed: Optional[str] = Field(
        None, max_length=1000, description="Impacto observado en el servicio o integridad"
    )

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str) -> str:
        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned.split("/")[0])
        except ValueError as exc:
            raise ValueError(f"La dirección IP de origen '{value}' no es válida.") from exc
        return cleaned

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        upper = value.strip().upper()
        allowed = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if upper not in allowed:
            raise ValueError(f"Método HTTP inválido '{value}'. Permitidos: {', '.join(sorted(allowed))}")
        return upper

    @model_validator(mode="after")
    def validate_temporal_window(self) -> "AssessmentLogCreateSchema":
        if self.started_at is None:
            self.started_at = datetime.now(timezone.utc)
        if self.ended_at and self.started_at and self.ended_at < self.started_at:
            raise ValueError("La fecha/hora de término no puede preceder al inicio de la prueba.")
        return self


class AssessmentLogFinishSchema(BaseModel):
    """Payload to mark an ongoing assessment log entry as finished."""

    ended_at: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp de término de la prueba",
    )
    system_impact_observed: Optional[str] = Field(None, max_length=1000)
