"""OASIS CSAF 2.0 (Common Security Advisory Framework) JSON and XML serializer for ANCI / CSIRT.

Generates machine-readable cybersecurity advisories compliant with Ley N° 21.663 (Ley Marco de Ciberseguridad),
Art. 2° Ley N° 21.459 (Eximente Penal), and Ley N° 21.719 (Protección de Datos Personales).
"""

from datetime import datetime, timezone
from typing import Any
from xml.dom import minidom
import xml.etree.ElementTree as ET

from app.compliance_engine.canonical_hasher import compute_sha256_hash


def build_csaf_advisory_json(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    deconfliction_queries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct a deterministic OASIS CSAF 2.0 JSON advisory package for ANCI ingestion."""
    now_iso = datetime.now(timezone.utc).isoformat()
    meta = agreement.get("contract_metadata") or {}
    agreement_id = str(agreement.get("id", "00000000-0000-0000-0000-000000000000"))

    target_assets: list[str] = agreement.get("target_assets") or []
    product_branches = [
        {
            "category": "product_name",
            "name": asset,
            "product": {
                "name": f"{meta.get('client_legal_name', 'Cliente')} — {asset}",
                "product_id": f"ASSET-{idx + 1}",
            },
        }
        for idx, asset in enumerate(target_assets)
    ]

    csaf_vulns: list[dict[str, Any]] = []
    for idx, v in enumerate(vulnerabilities):
        v_status = str(v.get("current_status", "IDENTIFIED"))
        is_fixed = v_status in ("RETEST_PASSED", "CLOSED")
        product_status_key = "fixed" if is_fixed else "known_affected"

        csaf_vulns.append(
            {
                "title": v.get("title"),
                "cve": v.get("cve_id") or f"LEXPLOIT-2026-{idx + 1:03d}",
                "cwe": {
                    "id": v.get("cwe_id") or "CWE-Other",
                    "name": f"Debilidad reportada en {v.get('affected_asset')}",
                },
                "product_status": {
                    product_status_key: [str(v.get("affected_asset", "ASSET-1"))],
                },
                "scores": [
                    {
                        "products": [str(v.get("affected_asset", "ASSET-1"))],
                        "cvss_v3": {
                            "version": "3.1",
                            "vectorString": v.get("cvss_vector"),
                            "baseScore": float(v.get("cvss_score", 0.0)),
                            "baseSeverity": v.get("severity"),
                        },
                    }
                ],
                "notes": [
                    {
                        "category": "description",
                        "title": "Descripción Técnica y Prueba de Concepto No Destructiva",
                        "text": v.get("technical_description", ""),
                    },
                    {
                        "category": "general",
                        "title": "Estado en Ciclo de Remediación y Re-Testing",
                        "text": f"Estado actual certificado: {v_status}",
                    },
                ],
                "remediations": [
                    {
                        "category": "mitigation",
                        "details": v.get("remediation_recommendation", ""),
                        "product_ids": [str(v.get("affected_asset", "ASSET-1"))],
                    }
                ],
                "remediation_history": v.get("remediation_history", []),
            }
        )

    confirmed_deconflictions = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "CONFIRMED_AUTHORIZED"
    )

    core_package: dict[str, Any] = {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "lang": "es-CL",
            "title": f"Expediente de Cierre y Trazabilidad ANCI — {agreement.get('title')}",
            "publisher": {
                "category": "coordinator",
                "name": meta.get("auditor_legal_name", "LexPloit Offensive Security SpA"),
                "namespace": "https://anci.gob.cl/csaf/lexploit",
                "contact_details": (
                    f"Lead Pentester: {meta.get('auditor_lead_name')} "
                    f"(RUT: {meta.get('auditor_lead_rut')})"
                ),
            },
            "tracking": {
                "id": f"CSAF-CL-{agreement_id[:8].upper()}-V{agreement.get('version', 1)}",
                "status": "final",
                "version": str(agreement.get("version", 1)),
                "initial_release_date": str(agreement.get("created_at") or now_iso),
                "current_release_date": now_iso,
            },
            "notes": [
                {
                    "category": "legal_disclaimer",
                    "title": "Acreditación de Eximente Penal (Art. 2° Ley N° 21.459)",
                    "text": (
                        "Las actividades técnicas descritas en este expediente fueron ejecutadas bajo "
                        "mandato expreso previo, sin ánimo de lucro ilícito ni daño, dentro de límites "
                        "no destructivos y cumpliendo el deber de reporte formal al titular."
                    ),
                },
                {
                    "category": "general",
                    "title": "Interoperabilidad Ley Marco de Ciberseguridad N° 21.663 (ANCI)",
                    "text": (
                        f"Entidad Mandante: {meta.get('client_legal_name')} (RUT {meta.get('client_tax_id')}) "
                        f"— Clasificación: {meta.get('regulatory_classification')}."
                    ),
                },
            ],
        },
        "product_tree": {
            "branches": product_branches,
        },
        "vulnerabilities": csaf_vulns,
        "lexploit_compliance_extension": {
            "normative_pillars": [
                "Ley N° 21.459 (Art. 2° Eximente de Responsabilidad Penal en Auditorías)",
                "Ley N° 21.663 (Ley Marco de Ciberseguridad e Interoperabilidad ANCI)",
                "Ley N° 21.719 (Protección de Datos Personales y Purga Certificada en 14 días)",
                "Ley N° 19.799 (Documentos Electrónicos y Sellado SHA-256)",
            ],
            "contract_governance": {
                "agreement_id": agreement_id,
                "status": agreement.get("current_status"),
                "contract_sha256_hash": agreement.get("sha256_hash"),
                "traffic_header_token": agreement.get("traffic_header_token"),
                "client_legal_name": meta.get("client_legal_name"),
                "client_tax_id": meta.get("client_tax_id"),
                "client_rep_name": meta.get("client_rep_name"),
                "client_rep_rut": meta.get("client_rep_rut"),
                "poc_primary_name": meta.get("poc_primary_name"),
                "poc_primary_rut": meta.get("poc_primary_rut"),
                "auditor_legal_name": meta.get("auditor_legal_name"),
                "auditor_tax_id": meta.get("auditor_tax_id"),
                "auditor_lead_name": meta.get("auditor_lead_name"),
                "auditor_lead_rut": meta.get("auditor_lead_rut"),
            },
            "art2_ley21459_evaluation": art2_compliance,
            "telemetry_and_deconfliction_summary": {
                "total_assessment_logs": len(logs),
                "total_soc_deconfliction_queries": len(deconfliction_queries),
                "false_positive_anci_reports_prevented": confirmed_deconflictions,
            },
            "ley21719_data_protection": {
                "data_purge_deadline_business_days": meta.get("data_purge_days", 14),
                "purge_certified": bool(meta.get("ley21719_purge_certified", False)),
                "purge_certificate_hash": meta.get("ley21719_purge_hash"),
                "purge_certified_at": meta.get("ley21719_purge_certified_at"),
            },
        },
    }

    package_hash = compute_sha256_hash(core_package)
    core_package["lexploit_compliance_extension"]["package_sha256_hash"] = package_hash
    return core_package


def serialize_csaf_to_xml(csaf_data: dict[str, Any]) -> str:
    """Serialize the OASIS CSAF 2.0 dictionary into a formatted XML document for CSIRT/ANCI."""
    root = ET.Element(
        "CSAFAdvisoryPackage",
        attrib={
            "xmlns": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf.xsd",
            "csaf_version": "2.0",
            "xml:lang": "es-CL",
        },
    )

    doc = csaf_data.get("document") or {}
    doc_el = ET.SubElement(root, "Document")
    ET.SubElement(doc_el, "Title").text = str(doc.get("title", ""))
    ET.SubElement(doc_el, "Category").text = str(doc.get("category", "csaf_security_advisory"))

    tracking = doc.get("tracking") or {}
    track_el = ET.SubElement(doc_el, "Tracking")
    for k in ("id", "status", "version", "initial_release_date", "current_release_date"):
        ET.SubElement(track_el, k.title().replace("_", "")).text = str(tracking.get(k, ""))

    pub = doc.get("publisher") or {}
    pub_el = ET.SubElement(doc_el, "Publisher")
    ET.SubElement(pub_el, "Name").text = str(pub.get("name", ""))
    ET.SubElement(pub_el, "Namespace").text = str(pub.get("namespace", ""))
    ET.SubElement(pub_el, "ContactDetails").text = str(pub.get("contact_details", ""))

    # Compliance Extension Block
    ext = csaf_data.get("lexploit_compliance_extension") or {}
    gov = ext.get("contract_governance") or {}
    gov_el = ET.SubElement(root, "ChileanLegalCompliance")
    for k, v in gov.items():
        ET.SubElement(gov_el, k).text = str(v if v is not None else "")
    ET.SubElement(gov_el, "PackageSHA256Hash").text = str(ext.get("package_sha256_hash", ""))

    # Vulnerabilities Block
    vulns_el = ET.SubElement(root, "Vulnerabilities")
    for v in csaf_data.get("vulnerabilities") or []:
        v_el = ET.SubElement(vulns_el, "Vulnerability")
        ET.SubElement(v_el, "Title").text = str(v.get("title", ""))
        ET.SubElement(v_el, "CVE").text = str(v.get("cve", ""))
        cwe = v.get("cwe") or {}
        ET.SubElement(v_el, "CWE").text = str(cwe.get("id", ""))

        scores = v.get("scores") or []
        if scores:
            cvss = scores[0].get("cvss_v3") or {}
            score_el = ET.SubElement(v_el, "CVSSv31")
            ET.SubElement(score_el, "BaseScore").text = str(cvss.get("baseScore", ""))
            ET.SubElement(score_el, "BaseSeverity").text = str(cvss.get("baseSeverity", ""))
            ET.SubElement(score_el, "VectorString").text = str(cvss.get("vectorString", ""))

        rems = v.get("remediations") or []
        if rems:
            ET.SubElement(v_el, "Remediation").text = str(rems[0].get("details", ""))

    raw_bytes = ET.tostring(root, encoding="utf-8")
    parsed = minidom.parseString(raw_bytes)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")
