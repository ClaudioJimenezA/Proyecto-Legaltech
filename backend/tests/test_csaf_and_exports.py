"""Tier 1 unit tests for OASIS CSAF 2.0 serializer and PDF/HTML report compiler (Paso 3)."""

from app.serializers.csaf_serializer import (
    build_csaf_advisory_json,
    serialize_csaf_to_xml,
)
from app.serializers.pdf_engine import (
    compile_compliance_report_pdf,
    compile_roe_contract_pdf,
    render_compliance_report_html,
    render_roe_contract_html,
)


def _sample_dossier():
    agreement = {
        "id": "11111111-2222-3333-4444-555555555555",
        "title": "Auditoría Red Team Core Bancario 2026",
        "version": 1,
        "current_status": "ACTIVE",
        "target_assets": ["api.bancoaustral.cl", "200.10.20.0/24"],
        "excluded_assets": ["db-prod.bancoaustral.cl"],
        "auditor_source_ips": ["181.43.22.10"],
        "traffic_header_token": "LXP-2026-BANCO",
        "sha256_hash": "e" * 64,
        "client_signed_at": "2026-11-19T12:00:00Z",
        "auditor_signed_at": "2026-11-19T12:05:00Z",
        "created_at": "2026-11-19T10:00:00Z",
        "contract_metadata": {
            "client_legal_name": "Banco Financiero Austral S.A.",
            "client_tax_id": "76.543.210-K",
            "regulatory_classification": "Operador de Importancia Vital (OIV - Ley 21.663)",
            "client_rep_name": "Roberto Domínguez Vial",
            "client_rep_rut": "12.345.678-5",
            "poc_primary_name": "Carolina Morales Soto",
            "poc_primary_rut": "16.789.012-3",
            "poc_primary_phone": "+56 9 8765 4321",
            "poc_primary_email": "ciso.poc@bancoaustral.cl",
            "auditor_legal_name": "LexPloit Offensive Security SpA",
            "auditor_tax_id": "77.889.900-1",
            "auditor_lead_name": "Víctor Contreras Muñoz",
            "auditor_lead_rut": "15.432.109-8",
            "testing_modality": "Gray-Box",
            "data_purge_days": 14,
        },
    }
    art2 = {
        "is_exempt": True,
        "failed_conditions": [],
        "conditions": [
            {
                "code": "ART2_C1_MANDATE",
                "name": "Mandato Previo",
                "passed": True,
                "reason": "Doble firma acreditada",
            }
        ],
    }
    vulns = [
        {
            "id": "vuln-1",
            "title": "SQL Injection en Endpoint de Consulta de Cartolas",
            "cve_id": "CVE-2026-1001",
            "cwe_id": "CWE-89",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_asset": "api.bancoaustral.cl",
            "technical_description": "Inyección SQL basada en errores en parámetro id_cuenta.",
            "remediation_recommendation": "Utilizar consultas parametrizadas (Prepared Statements).",
            "current_status": "RETEST_PASSED",
            "remediation_history": [],
        }
    ]
    return agreement, art2, vulns


def test_build_csaf_advisory_json_and_xml_serialization():
    """CSAF 2.0 builder must emit valid JSON and well-formed XML with a 64-char SHA-256 package hash."""
    agreement, art2, vulns = _sample_dossier()
    csaf = build_csaf_advisory_json(
        agreement=agreement,
        art2_compliance=art2,
        vulnerabilities=vulns,
        logs=[{"id": "log-1"}],
        deconfliction_queries=[{"id": "q-1", "resolution": "CONFIRMED_AUTHORIZED"}],
    )

    assert csaf["document"]["csaf_version"] == "2.0"
    assert len(csaf["vulnerabilities"]) == 1
    assert csaf["vulnerabilities"][0]["scores"][0]["cvss_v3"]["baseScore"] == 9.8
    pkg_hash = csaf["lexploit_compliance_extension"]["package_sha256_hash"]
    assert len(pkg_hash) == 64

    xml_output = serialize_csaf_to_xml(csaf)
    assert "<?xml" in xml_output
    assert "<CSAFAdvisoryPackage" in xml_output
    assert "CWE-89" in xml_output
    assert pkg_hash in xml_output


def test_render_html_and_compile_pdf_report():
    """HTML and PDF compilers must generate non-empty output with valid %PDF header."""
    agreement, art2, vulns = _sample_dossier()
    html_str = render_compliance_report_html(
        agreement=agreement,
        art2_compliance=art2,
        vulnerabilities=vulns,
        logs=[],
        deconfliction_queries=[],
        package_sha256_hash="f" * 64,
    )
    assert "Banco Financiero Austral S.A." in html_str
    assert "12.345.678-5" in html_str
    assert "15.432.109-8" in html_str

    pdf_bytes = compile_compliance_report_pdf(
        agreement=agreement,
        art2_compliance=art2,
        vulnerabilities=vulns,
        logs=[],
        deconfliction_queries=[],
        package_sha256_hash="f" * 64,
    )
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 400


def test_render_and_compile_roe_contract_pdf_with_toc_and_nda():
    """Formal RoE contract export must contain the Table of Contents, Bilateral NDA, and Custom Clauses."""
    agreement, art2, _ = _sample_dossier()
    agreement["contract_metadata"]["nda_penalty_uf"] = 750
    agreement["contract_metadata"]["custom_clauses"] = [
        {
            "id": "c-1",
            "title": "Restriccion Horaria CyberMonday",
            "content": "Se suspenden pruebas activas durante las 72 horas del evento CyberMonday Chile.",
        }
    ]

    html_contract = render_roe_contract_html(
        agreement=agreement,
        art2_compliance=art2,
    )
    assert "TABLA DE CONTENIDO" in html_contract
    assert "ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA)" in html_contract
    assert "750 UF" in html_contract
    assert "RESTRICCION HORARIA CYBERMONDAY" in html_contract.upper()

    pdf_contract = compile_roe_contract_pdf(
        agreement=agreement,
        art2_compliance=art2,
    )
    assert pdf_contract.startswith(b"%PDF-")
    assert len(pdf_contract) > 500
