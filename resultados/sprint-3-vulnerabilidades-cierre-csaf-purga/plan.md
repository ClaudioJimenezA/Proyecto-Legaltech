# PLAN — Sprint 3 (Funcionalidad N° 3): Matriz de Vulnerabilidades CVSS v3.1, Ciclo de Re-Testing, Expediente Dual ANCI (PDF + OASIS CSAF 2.0) y Purga Certificada Ley N° 21.719

- **Funcionalidad:** Sprint 3 (Paso 3) — Seguimiento de Hitos de Vulnerabilidades con Calculadora CVSS v3.1, Auditoría de Re-Test, Exportación Dual (Humano PDF/HTML + Máquina OASIS CSAF 2.0 XML/JSON) y Acta de Destrucción/Purga de Evidencias Crudas
- **Actores:** `Auditor Lead` (registra hallazgos CVSS v3.1, ejecuta Re-Testing, certifica cierre y purga de datos) · `Cliente PoC / Rep. Legal` (solicita verificación de parches, audita matriz de remediación y descarga expedientes de cumplimiento para directorio y ANCI)
- **Marco Normativo:** Ley N° 21.663 (Ley Marco de Ciberseguridad — Interoperabilidad ANCI / CSIRT Nacional mediante estándar OASIS CSAF 2.0) · Ley N° 21.459 (Art. 2° Condición 4ª: Deber de Reporte Formal de Hallazgos al Titular) · Ley N° 21.719 (Protección de Datos Personales — Principio de Minimización y Limitación del Plazo de Conservación con Purga Certificada en 14 días hábiles) · Ley N° 19.799 (Sellado Criptográfico SHA-256 del expediente de cierre)
- **Estado / Sprint:** Implementado y Verificado · Sprint 3 · Prioridad Alta (Cierre Técnico-Jurídico e Interoperabilidad Regulatoria)
- **Depende de:** Sprint 1 (Contrato RoE sellado y evaluación Art. 2° Ley N° 21.459) y Sprint 2 (Bitácora `assessment_logs` y Consultas de Desconflicto `deconfliction_queries`) · **Requerido por:** Cierre formal del proyecto de auditoría y entrega regulatoria ante la ANCI
- **Rama:** `main` (`feat/sprint3-cvss-retest-csaf20-purge`)

---

## Start here

Para revisión arquitectónica, validación del estándar OASIS CSAF 2.0 y despliegue del Paso 3:

- **Leer primero:**
  - Calculadora pura CVSS v3.1 (Capa 1 Frontend): `frontend/src/lib/cvss_calculator.js` y `frontend/src/lib/cvss_calculator.test.js`.
  - Serializadores de cierre (Capa 2 Backend): `backend/app/serializers/csaf_serializer.py` (JSON y XML OASIS CSAF 2.0) y `backend/app/serializers/pdf_engine.py` (Reporte Ejecutivo y Legal en PDF y HTML imprimible).
  - Esquemas y Endpoints REST (Capa 2 Backend): `backend/app/schemas/vulnerability_schema.py`, `backend/app/schemas/csaf_schema.py`, `backend/app/api/v1/endpoints/vulnerabilities.py`, `backend/app/api/v1/endpoints/exports.py`.
  - Tests de serialización y exportación (Tier 1 Backend): `backend/tests/test_csaf_and_exports.py`.
  - Componentes, Servicios y Hooks (Capa 2 Frontend): `frontend/src/features/vulnerability_tracking/components/VulnerabilityWorkspace.jsx`, `frontend/src/features/vulnerability_tracking/components/CvssFormModal.jsx`, `frontend/src/features/vulnerability_tracking/components/VulnerabilityMatrix.jsx`, `frontend/src/features/vulnerability_tracking/components/ExportClosingPackagePanel.jsx`, `frontend/src/features/vulnerability_tracking/hooks/useVulnerabilityLifecycle.js`, `frontend/src/features/vulnerability_tracking/hooks/useExportReports.js`, `frontend/src/features/vulnerability_tracking/constants/vulnBadges.jsx`.
- **Invariantes que no se deben romper:**
  - Toda transición de estado de una vulnerabilidad (`IDENTIFIED` → `IN_REMEDIATION` → `READY_FOR_RETEST` → `RETEST_PASSED` / `RETEST_FAILED` → `CLOSED`) debe insertar simultáneamente un registro inmutable en `public.remediation_logs` con comentario técnico, usuario ejecutor y URL/commit de evidencia opcional.
  - El paquete OASIS CSAF 2.0 (`.JSON` y `.XML`) y el Informe Oficial (`.PDF` y `.HTML`) deben compartir el mismo `package_sha256_hash` calculado canónicamente sobre el dossier completo del acuerdo.
  - La **Purga Certificada Ley N° 21.719** (`POST /api/v1/exports/purge-evidence/{agreement_id}`) elimina de forma irreversible los adjuntos crudos de `log_evidence_attachments` y deja constancia firmada con SHA-256, conservando únicamente los metadatos estadísticos anonimizados y hashes de `assessment_logs` como prueba de exención penal (Art. 2° Ley N° 21.459).

---

## Standing questions

| # | Pregunta de Arquitectura / Cumplimiento | Respuesta |
| :- | :-------------------------------------- | :-------- |
| 1 | ¿Toca motores puros (`src/lib` / `compliance_engine`)? ¿Qué reglas cambiaron? | **Sí.** Implementa `ALG-CVSS-1` (`cvss_calculator.js`: fórmula oficial FIRST CVSS v3.1 Base Score con `RoundUp` a 1 decimal, vector `CVSS:3.1/AV:.../S:.../C:.../I:.../A:...` y clasificación `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) y reutiliza `compute_sha256_hash` para sellar el paquete CSAF 2.0 y el Acta de Purga Ley N° 21.719. |
| 2 | ¿Requiere RLS / aislamiento por rol? | **Sí.** En `VulnerabilityMatrix.jsx`, el registro de nuevos hallazgos CVSS v3.1 y la certificación de resultado de Re-Test (`RETEST_PASSED` / `RETEST_FAILED`) corresponden al `Auditor Lead`, mientras que solicitar Re-Test (`READY_FOR_RETEST`) y consultar el expediente están habilitados para el `Cliente PoC / Rep. Legal`. |
| 3 | ¿Requiere migración en Supabase? | **Usa tablas existentes** (`vulnerabilities`, `remediation_logs` y `log_evidence_attachments` definidas en `20261116000000_init_lexploit_schema.sql`). |
| 4 | ¿Cambia el contrato de API REST? | **Sí.** Expone `/api/v1/vulnerabilities` (`POST /`, `GET /agreement/{agreement_id}`, `PATCH /{vulnerability_id}/status`) y `/api/v1/exports` (`GET /pdf/{agreement_id}?format=pdf\|html`, `GET /csaf/{agreement_id}?format=json\|xml`, `POST /purge-evidence/{agreement_id}`). |
| 5 | ¿Impacto en privacidad (Ley N° 21.719) e interoperabilidad ANCI (Ley N° 21.663)? | **Sí, completo.** Materializa el canal dual exigido por la propuesta: documento ejecutivo humano (PDF/HTML) + documento máquina estándar **OASIS CSAF 2.0** (JSON/XML) para el CSIRT/ANCI, junto con el **Certificado de Destrucción y Purga Irreversible** dentro del plazo legal de 14 días hábiles. |

---

## Goal

Permitir que el equipo auditor y el cliente gestionen el ciclo completo de remediación y verificación de parches (*Re-Testing*) de cada vulnerabilidad con puntaje matemático **CVSS v3.1**, emitan el **Expediente Dual de Cierre** —compuesto por el **Informe Oficial Técnico-Jurídico (`.PDF` / `.HTML`)** y el paquete interoperable **OASIS CSAF 2.0 (`.JSON` / `.XML`)** con el desglose completo de telemetría y consultas de desconflicto ANCI— y ejecuten la **Purga Certificada de Evidencias Crudas** exigida por la **Ley N° 21.719**.

---

## Approach & Resolved decisions

Se implementó una calculadora CVSS v3.1 determinista en el frontend sincronizada con validación de rangos y severidades en Pydantic, una matriz interactiva con línea de tiempo plegable de `remediation_logs`, y un motor de exportación dual en backend (`csaf_serializer.py` y `pdf_engine.py`) que consolida en un solo dossier (`_gather_agreement_dossier`) el contrato RoE, la evaluación de las 4 condiciones del Art. 2° Ley N° 21.459, la bitácora de telemetría, las consultas de desconflicto SIEM/ANCI, la matriz de vulnerabilidades y el estado de purga de datos personales.

| Decisión | Justificación |
| :------- | :------------ |
| **Calculadora CVSS v3.1 oficial FIRST en vivo (`cvss_calculator.js`)** | Evita discrepancias subjetivas entre severidad y puntaje: al seleccionar las 8 métricas base (`AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`), calcula instantáneamente Impact Sub-Score (ISS), Exploitability, `RoundUp` a 1 decimal, severidad y vector string. |
| **Historial de hitos y Re-Testing plegable por vulnerabilidad** | Cada hallazgo registra su cadena inmutable de cambios de estado (`remediation_logs`), pero la línea de tiempo parte plegada (`Ver historial de Re-Test (N)`) para mantener limpia la matriz principal. |
| **Serialización dual OASIS CSAF 2.0 en `.JSON` y `.XML`** | Cumple el estándar internacional OASIS CSAF 2.0 (`document`, `product_tree`, `vulnerabilities` con `cvss_v3`, `cwe`, `remediations`) e incorpora el bloque de extensión `lexploit_compliance_extension` (`ChileanLegalCompliance` en XML) con los RUTs de las partes, dictamen Art. 2° Ley 21.459, auditoría de desconflicto y hash SHA-256 del paquete. |
| **Sección 3 del Reporte Final ANCI con desglose completo y tabla de consultas de desconflicto** | El expediente final (PDF, HTML y CSAF 2.0) detalla tanto los contadores de los 3 estados (`CONFIRMED_AUTHORIZED`, `INDETERMINATE`, `UNMATCHED_SUSPICIOUS`) y hallazgos críticos *Break-Glass* como la tabla completa de consultas de desconflicto activas. |
| **Botón de Expediente Imprimible HTML + Botón Informativo (`ⓘ`)** | Mantiene la vista HTML editorial junto a la descarga directa `.PDF` y añade un popover informativo (`ⓘ`) que explica su función de vista previa e impresión `Ctrl + P` de alta fidelidad en arquitecturas *Serverless*. |
| **Purga Certificada Ley N° 21.719 con preservación de hashes probatorios** | Destruye `log_evidence_attachments` (capturas/dumps crudos con posibles datos personales) y emite el certificado `PURGA-21719-...` sellado con SHA-256, conservando los registros anonimizados y hashes de `assessment_logs` para no debilitar la eximente penal del Art. 2° Ley N° 21.459. |

---

## Entities

| Superficie | Nuevo / Cambio | Propiedad e Historial |
| :--------- | :------------- | :-------------------- |
| `public.vulnerabilities` | Tabla de hallazgos CVSS v3.1 por acuerdo RoE | Almacena `title`, `cve_id`, `cwe_id`, `severity`, `cvss_score`, `cvss_vector`, `affected_asset`, `technical_description`, `remediation_recommendation` y `current_status`. |
| `public.remediation_logs` | Bitácora inmutable de transiciones y Re-Test | Registra cada transición (`previous_status` → `new_status`), `changed_by_user_id`, `comment`, `retest_evidence_url` y `created_at`. |
| `public.log_evidence_attachments` | Tabla de adjuntos crudos sujeta a purga Ley N° 21.719 | Sus registros asociados al acuerdo son eliminados irreversiblemente al ejecutar `POST /api/v1/exports/purge-evidence/{agreement_id}`. |
| `POST /api/v1/vulnerabilities` · `GET /api/v1/vulnerabilities/agreement/{id}` · `PATCH /api/v1/vulnerabilities/{id}/status` | API REST de ciclo de vida de vulnerabilidades | Crea hallazgos con log inicial en `remediation_logs`, lista hallazgos con su historial anidado y resumen por severidad/estado, y ejecuta transiciones auditadas. |
| `GET /api/v1/exports/pdf/{agreement_id}` | Exportación Canal Humano (`format=pdf\|html`) | Genera `Expediente_Legal_LexPloit_<ID>.pdf` (o vista HTML imprimible) con las 5 secciones oficiales: Partes/RUTs, Certificado Art. 2° Ley 21.459, Telemetría y Tabla de Desconflicto ANCI, Matriz CVSS v3.1 y Sello SHA-256. |
| `GET /api/v1/exports/csaf/{agreement_id}` | Exportación Canal Máquina OASIS CSAF 2.0 (`format=json\|xml`) | Genera el paquete estructurado JSON o `ANCI_CSAF20_<ID>.xml` listo para ingesta por el CSIRT Nacional / ANCI. |
| `POST /api/v1/exports/purge-evidence/{agreement_id}` | Ejecución y certificación de Purga Ley N° 21.719 | Elimina evidencias crudas, calcula `purge_certificate_sha256_hash` y retorna el Acta de Destrucción y Purga Irreversible. |
| `CvssFormModal.jsx`, `VulnerabilityMatrix.jsx` y `ExportClosingPackagePanel.jsx` | Interfaz de Paso 3 | Calculadora interactiva CVSS v3.1 con plantillas OWASP/CWE, matriz con historial de Re-Test plegable, panel de exportación dual con visor CSAF 2.0 integrado, popover `ⓘ` en botón HTML y modal del Acta de Purga Ley N° 21.719. |

---

## Algorithms & Pure Logic

- **`ALG-CVSS-1` — Calculadora Matemática FIRST CVSS v3.1 (`frontend/src/lib/cvss_calculator.js`):**
  - Calcula $\text{ISS} = 1 - (1 - C) \times (1 - I) \times (1 - A)$.
  - Si `Scope == U`: $\text{Impact} = 6.42 \times \text{ISS}$; si `Scope == C`: $\text{Impact} = 7.52 \times (\text{ISS} - 0.029) - 3.25 \times (\text{ISS} - 0.02)^{15}$.
  - $\text{Exploitability} = 8.22 \times AV \times AC \times PR_S \times UI$.
  - Aplica `roundUp1()` (techo exacto al décimo superior: $\lceil x \times 10 \rceil / 10$) y mapea el puntaje al enum `VulnSeverityEnum` (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **`ALG-CSAF-1` — Serializador Determinista OASIS CSAF 2.0 (`backend/app/serializers/csaf_serializer.py`):**
  - Transforma cada hallazgo de `vulnerabilities` y su historial de `remediation_logs` al árbol oficial CSAF 2.0 (`product_tree`, `scores[].cvss_v3`, `remediations`, `threats`), anexa el resumen de telemetría y el `deconfliction_audit_trail` completo, y sella el documento con `compute_sha256_hash()`.

---

## Scope

- **In scope:** Calculadora interactiva CVSS v3.1 con generación automática de vector y severidad · Plantillas rápidas de hallazgos (SQLi, RCE, BOLA/IDOR, Misconfiguration) · Máquina de estados de remediación y Re-Testing (`IDENTIFIED` → `IN_REMEDIATION` → `READY_FOR_RETEST` → `RETEST_PASSED` / `RETEST_FAILED` → `CLOSED`) · Línea de tiempo plegable de `remediation_logs` · Exportación Canal Humano en `.PDF` y `.HTML` (con botón informativo `ⓘ`) incluyendo tabla detallada de consultas de desconflicto · Exportación Canal Máquina en **OASIS CSAF 2.0 (`.JSON` y `.XML`)** con visor interactivo en pantalla · Ejecución de Purga Certificada Ley N° 21.719 con emisión de Acta descargable en `.JSON` firmado con SHA-256.
- **Out of scope:** Envío automático por correo electrónico o transmisión directa por API al portal privado de la ANCI (el sistema genera y descarga los artefactos oficiales firmados para que el Representante Legal / PoC los remita por el canal regulatorio correspondiente).

---

## Steps

1. **Implementar calculadora pura CVSS v3.1 (`cvss_calculator.js` y `cvss_calculator.test.js`).** Codificar pesos oficiales FIRST v3.1, función `roundUp1`, generador de `vectorString` y mapeo de severidad con pruebas unitarias Tier 1.
2. **Definir esquemas de vulnerabilidades y CSAF 2.0 (`vulnerability_schema.py` y `csaf_schema.py`).** Validar rangos CVSS (`0.0` a `10.0`), prefijo `CVSS:3.1/` y estructura de transiciones de estado.
3. **Construir serializador OASIS CSAF 2.0 (`csaf_serializer.py`) y motor de Reporte Ejecutivo PDF/HTML (`pdf_engine.py`).** Generar el paquete JSON/XML y el informe PDF/HTML con las 5 secciones normativas, incluyendo el desglose completo y la tabla detallada de consultas de desconflicto SIEM/ANCI.
4. **Implementar endpoints de vulnerabilidades y exportación/purga (`vulnerabilities.py` y `exports.py`).** Soportar creación y transición de estados con inserción en `remediation_logs`, descarga de PDF/HTML/CSAF y ejecución de purga de `log_evidence_attachments` bajo la Ley N° 21.719.
5. **Escribir pruebas unitarias de serialización y exportación (`test_csaf_and_exports.py`).** Verificar validez del JSON y XML OASIS CSAF 2.0, cabecera binaria `%PDF-1.4` del motor PDF y sellado SHA-256 del paquete.
6. **Desarrollar interfaz de Paso 3 (`VulnerabilityWorkspace.jsx`, `CvssFormModal.jsx`, `VulnerabilityMatrix.jsx`, `ExportClosingPackagePanel.jsx`).** Integrar calculadora CVSS v3.1, matriz con historial plegable de Re-Test, panel de cierre dual con botón informativo `ⓘ` junto al botón HTML, visor CSAF 2.0 y modal del Certificado de Purga Ley N° 21.719.

---

## Acceptance criteria map

| Criterio | Paso(s) | Verificado por |
| :------- | :------ | :------------- |
| `E1` — Cálculo exacto de puntaje, vector y severidad CVSS v3.1 según especificación FIRST | 1, 2, 6 | `frontend/src/lib/cvss_calculator.test.js` y `CvssFormModal.jsx` |
| `E2` — Trazabilidad completa del ciclo de Re-Testing con bitácora plegable en `remediation_logs` | 2, 4, 6 | `vulnerabilities.py` y línea de tiempo desplegable en `VulnerabilityMatrix.jsx` |
| `E3` — Exportación dual: Informe Ejecutivo (`.PDF` / `.HTML`) + Paquete Máquina OASIS CSAF 2.0 (`.JSON` / `.XML`) con tabla de desconflicto ANCI | 3, 4, 5, 6 | `backend/tests/test_csaf_and_exports.py` y `ExportClosingPackagePanel.jsx` |
| `E4` — Purga irreversible de evidencias crudas y emisión de Acta Certificada SHA-256 (Ley N° 21.719) | 4, 6 | `POST /api/v1/exports/purge-evidence/{agreement_id}` y modal de Acta de Purga en `ExportClosingPackagePanel.jsx` |

---

## Safeguards & Definition of done

- **Tier 1 en verde:** `backend/tests/test_csaf_and_exports.py` y `frontend/src/lib/cvss_calculator.test.js`.
- **Resiliencia Serverless en generación PDF:** Si el entorno de ejecución no dispone de librerías nativas de sistema para WeasyPrint, `compile_compliance_report_pdf()` genera automáticamente un documento binario multipágina `%PDF-1.4` válido en Python puro, complementado por la vista imprimible HTML explicada en el botón `ⓘ`.
- **Equilibrio entre Ley N° 21.719 y Ley N° 21.459:** La purga elimina únicamente artefactos crudos (`log_evidence_attachments`) y conserva los registros de telemetría anonimizados (`assessment_logs`) con sus hashes SHA-256 para mantener intacta la prueba de exención penal.
