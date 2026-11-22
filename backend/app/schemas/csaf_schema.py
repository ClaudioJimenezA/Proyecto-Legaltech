"""Pydantic v2 schema for OASIS CSAF 2.0 (Common Security Advisory Framework) export to ANCI."""

from typing import Any, Optional
from pydantic import BaseModel, Field


class CsafPublisherSchema(BaseModel):
    category: str = "coordinator"
    name: str
    namespace: str = "https://anci.gob.cl/csaf"
    contact_details: Optional[str] = None


class CsafTrackingSchema(BaseModel):
    id: str
    status: str = "final"
    version: str = "1"
    initial_release_date: str
    current_release_date: str


class CsafDocumentMetadataSchema(BaseModel):
    category: str = "csaf_security_advisory"
    csaf_version: str = "2.0"
    lang: str = "es-CL"
    title: str
    publisher: CsafPublisherSchema
    tracking: CsafTrackingSchema
    notes: list[dict[str, str]] = Field(default_factory=list)


class CsafAdvisoryPackageSchema(BaseModel):
    """Top-level OASIS CSAF 2.0 structure enriched with Chilean compliance metadata."""

    document: CsafDocumentMetadataSchema
    product_tree: dict[str, Any]
    vulnerabilities: list[dict[str, Any]]
    lexploit_compliance_extension: dict[str, Any]
