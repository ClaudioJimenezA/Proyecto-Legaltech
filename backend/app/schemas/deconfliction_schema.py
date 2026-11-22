"""Pydantic v2 boundary contracts for SOC & ANCI Deconfliction queries (Paso 2)."""

from datetime import datetime
from enum import Enum
import ipaddress
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class DeconflictionStatusEnum(str, Enum):
    """Possible deconfliction resolutions under Ley N° 21.663 (ANCI)."""

    CONFIRMED_AUTHORIZED = "CONFIRMED_AUTHORIZED"
    UNMATCHED_SUSPICIOUS = "UNMATCHED_SUSPICIOUS"
    INDETERMINATE = "INDETERMINATE"


class DeconflictionQuerySchema(BaseModel):
    """Payload submitted by the client's SOC or PoC to correlate a SIEM/WAF alarm."""

    agreement_id: UUID = Field(..., description="UUID del acuerdo RoE sobre el que se consulta")
    incident_timestamp: datetime = Field(
        ..., description="Timestamp de la alarma detectada en el SIEM/WAF/EDR del cliente (UTC)"
    )
    observed_attacker_ip: str = Field(
        ..., description="Dirección IP atacante detectada por el firewall, WAF o IDS"
    )
    targeted_asset: str = Field(
        ..., min_length=3, max_length=255, description="Activo, dominio o IP afectada según la alarma"
    )
    internal_ticket_ref: Optional[str] = Field(
        None, max_length=60, description="Número de ticket interno del SOC (ej. INC-2026-904)"
    )

    @field_validator("observed_attacker_ip")
    @classmethod
    def validate_observed_ip(cls, value: str) -> str:
        cleaned = value.strip()
        try:
            ipaddress.ip_address(cleaned.split("/")[0])
        except ValueError as exc:
            raise ValueError(f"La IP observada '{value}' no es una dirección IPv4/IPv6 válida.") from exc
        return cleaned
