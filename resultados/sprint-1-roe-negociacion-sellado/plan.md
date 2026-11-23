# PLAN — Sprint 1 (Funcionalidad N° 1): Negociación de Contratos RoE, NDA Bilateral, Estructura EPC y Sellado Criptográfico SHA-256

- **Funcionalidad:** Sprint 1 (Paso 1) — Generador y Negociador de Acuerdos de Reglas de Compromiso (*Rules of Engagement* - RoE), Acuerdo de Confidencialidad Bilateral (NDA) y Sellado de Inmutabilidad Criptográfica SHA-256
- **Actores:** `Auditor Lead` (Consultora / Equipo de Ciberseguridad) · `Cliente PoC / Rep. Legal` (Entidad Mandante / OIV / Servicio Esencial)
- **Marco Normativo:** Ley N° 21.459 (Art. 2° Eximente de Responsabilidad Penal) · Ley N° 19.799 (Firma Electrónica e Integridad SHA-256) · Ley N° 21.663 (ANCI) · Ley N° 20.393 (Responsabilidad Penal de Personas Jurídicas) · Art. 1535 Código Civil (Cláusula Penal en UF)
- **Estado / Sprint:** Implementado y Verificado · Sprint 1 · Prioridad Crítica (Core LegalTech)
- **Depende de:** Esquema base PostgreSQL/Supabase (`roe_agreements`, `organizations`) · **Requerido por:** Sprint 2 (Live Assessment Logger y Motor de Desconflicto) y Sprint 3 (Matriz CVSS v3.1 y Expediente ANCI)
- **Rama:** `main` (`feat/sprint1-roe-negotiation-sha256`)

---

## Start here

Para revisión arquitectónica, auditoría legal y despliegue del Paso 1:

- **Leer primero:**
  - Motor puro (Capa 1 Backend): `backend/app/compliance_engine/canonical_hasher.py`, `backend/app/compliance_engine/rules_evaluator.py`, `backend/app/compliance_engine/scope_validator.py`.
  - Esquemas, Serializador PDF y Endpoints (Capa 2 Backend): `backend/app/schemas/roe_schema.py`, `backend/app/serializers/pdf_engine.py`, `backend/app/api/v1/endpoints/roe.py`.
  - Validadores puros (Capa 1 Frontend): `frontend/src/lib/network_validators.js`, `frontend/src/lib/crypto_utils.js`.
  - Componentes y Hooks (Capa 2 Frontend): `frontend/src/features/roe_negotiation/components/ScopeEditor.jsx`, `frontend/src/features/roe_negotiation/components/ContractViewer.jsx`, `frontend/src/features/roe_negotiation/components/RoeDashboard.jsx`, `frontend/src/features/roe_negotiation/constants/roeStatus.jsx`, `frontend/src/features/roe_negotiation/hooks/useRoeWorkflow.js`.
  - Migración de inmutabilidad en base de datos: `supabase/migrations/20261119000000_roe_chilean_contract_and_immutability.sql`.
- **Invariantes que no se deben romper:**
  - Ningún contrato RoE puede pasar a estado `SIGNED_AND_SEALED` o `ACTIVE` si existe colisión entre `target_assets` (In-Scope) y `excluded_assets` (Hard Deny List), o si falta la confirmación de respaldos previos (`backup_confirmed`).
  - Una vez sellado con `sha256_hash`, el trigger PostgreSQL `trg_enforce_sealed_roe_immutability` bloquea cualquier modificación sobre los activos, IPs, fechas, token de tráfico o `contract_metadata`.
  - Los RUTs de cada compareciente se almacenan y exhiben en campos independientes (`client_rep_rut`, `auditor_lead_rut`, `poc_primary_rut`, `client_tax_id`, `auditor_tax_id`).

---

## Standing questions

| # | Pregunta de Arquitectura / Cumplimiento | Respuesta |
| :- | :-------------------------------------- | :-------- |
| 1 | ¿Toca motores puros (`compliance_engine` / `src/lib`)? ¿Qué reglas cambiaron? | **Sí.** Implementa `ALG-ROE-1` (`canonical_hasher.py`), `ALG-ROE-2` (`rules_evaluator.py` para las 4 condiciones copulativas del Art. 2° Ley N° 21.459) y `ALG-ROE-3` (`scope_validator.py` y `network_validators.js` para detección de colisiones IPv4/CIDR/FQDN y validación Módulo 11 de RUT chileno). |
| 2 | ¿Requiere RLS / aislamiento por rol? | **Sí.** Políticas RLS en `public.roe_agreements` (`roe_select_policy`) y separación de acciones en backend/frontend entre `Auditor Lead` (redacción, edición, envío a revisión, firma ejecutora y sellado) y `Cliente PoC / Rep. Legal` (solicitud de reparos, confirmación de backup/cloud y firma mandante). |
| 3 | ¿Requiere migración en Supabase? | **Sí.** `20261119000000_roe_chilean_contract_and_immutability.sql` añade `contract_metadata JSONB` y actualiza el trigger `enforce_sealed_roe_immutability()` para proteger también `contract_metadata` tras el sellado SHA-256. |
| 4 | ¿Cambia el contrato de API REST? | **Sí.** Expone `/api/v1/roe` (`POST`, `GET`, `PUT /{id}`), transiciones de ciclo de vida (`/send-to-client`, `/request-revision`, `/client-approve`, `/seal`, `/terminate`), auditoría criptográfica (`/verify-integrity`) y exportación documental (`/export-pdf?format=pdf|html`). |
| 5 | ¿Impacto en consentimiento, confidencialidad y validez legal? | **Sí, central.** Incorpora **Acuerdo de Confidencialidad Bilateral (NDA)** con cláusula penal tasada en UF (Art. 1535 Código Civil), **Personerías Legales** (adaptadas a empresas privadas, RES y OIV/Servicios Esenciales públicos), límite de responsabilidad EPC y arbitraje mixto CAM Santiago. |

---

## Goal

Permitir que una consultora de ciberseguridad (`Auditor Lead`) y una entidad mandante chilena (`Cliente PoC / Rep. Legal`) redacten, negocien iterativamente con historial de reparos, personalicen con cláusulas adicionales, firmen bilateralmente, sellen criptográficamente con **SHA-256** (Ley N° 19.799) y exporten a **PDF con Tabla de Contenido (Índice)** un contrato oficial de **Reglas de Compromiso (RoE) + NDA Bilateral**, preconstituyendo la prueba fehaciente de las **4 condiciones copulativas de exención penal del Artículo 2° de la Ley N° 21.459**.

---

## Approach & Resolved decisions

Se diseñó una arquitectura de **Dos Capas ("Two Layers, Everywhere")** donde toda la validación de redes (IPs, subredes CIDR, dominios), validación de RUT chileno (Módulo 11), evaluación de las 4 condiciones del Art. 2° Ley N° 21.459 y serialización canónica SHA-256 viven en módulos puros sin I/O (`backend/app/compliance_engine/` y `frontend/src/lib/`), mientras que FastAPI y React orquestan la máquina de estados contractual (`DRAFT` → `PENDING_CLIENT_APPROVAL` ⇄ `REVISION_REQUESTED` → `CLIENT_APPROVED` → `ACTIVE / SIGNED_AND_SEALED` o `TERMINATED`).

| Decisión | Justificación |
| :------- | :------------ |
| **Separación estricta de RUTs por rol y persona** | Evita ambigüedad jurídica en la comparecencia: se separan `RUT Empresa Cliente`, `RUT Representante Legal Cliente / PoC`, `RUT Punto de Contacto Titular`, `RUT Consultora` y `RUT Pentester / Representante Equipo de Ciberseguridad`. |
| **Cláusula Octava de NDA Bilateral + Cláusula Penal en UF** | Basado en las observaciones de ayudantía y doctrina chilena (Art. 1535 Código Civil): protege tanto la infraestructura del cliente como el *know-how* del auditor, fijando vigencia, supervivencia post-contractual y multa automática en UF sin necesidad de probar el monto del perjuicio. |
| **Estructura contractual inspirada en estándar EPC chileno** | Incorpora Sección Preliminar (*Exponen*), Cláusula de Definiciones, Personerías Legales (Escritura Pública, Decreto/Resolución para OIV públicos o Certificado RES), Tope de Responsabilidad (*Liability Cap %*), Ley N° 20.393 y Arbitraje Mixto ante el CAM Santiago. |
| **Cláusulas adicionales dinámicas (`custom_clauses`) post-formulario** | Permite agregar, editar o eliminar cláusulas específicas sugeridas por el cliente durante la negociación (`DRAFT` o `REVISION_REQUESTED`) e incluirlas dentro del payload canónico sellado con SHA-256. |
| **Tabla de Contenido (Índice) automática en Visor Web y PDF** | Numeración dinámica (Secciones `0.` a `15.`, incluyendo cláusulas personalizadas `12.1`, `12.2`, etc.) tanto al inicio del PDF exportado como en un índice interactivo con enlaces en la vista web. |
| **Compatibilidad retroactiva en verificación SHA-256 (`verify_roe_integrity`)** | Verifica primero el conjunto extendido `_IMMUTABLE_META_FIELDS` (incluyendo NDA, personerías y cláusulas personalizadas) y mantiene fallback a `_LEGACY_IMMUTABLE_META_FIELDS` para contratos sellados en versiones previas. |
| **Vista Imprimible HTML + Botón Informativo (`ⓘ`) junto al PDF** | Garantiza exportación editorial de alta fidelidad mediante `Ctrl + P` en despliegues *Serverless* (Vercel) donde WeasyPrint no dispone de librerías nativas Cairo/Pango y activa el motor PDF 1.4 puro en Python. |

---

## Entities

| Superficie | Nuevo / Cambio | Propiedad e Historial |
| :--------- | :------------- | :-------------------- |
| `public.roe_agreements` | Columnas core + `contract_metadata JSONB` (`20261119000000_...sql`) | Almacena alcance técnico (`target_assets`, `excluded_assets`, `auditor_source_ips`, `traffic_header_token`), firmas (`client_signed_at`, `auditor_signed_at`), `sha256_hash` y metadatos legales completos (comparecencia, RUTs, NDA, personerías, `custom_clauses`, `revision_history`). |
| `trg_enforce_sealed_roe_immutability` | Trigger PostgreSQL `BEFORE UPDATE` | Impide alterar cualquier campo técnico o `contract_metadata` cuando `OLD.sha256_hash IS NOT NULL` (salvo transición a `TERMINATED`), garantizando inmutabilidad bajo Ley N° 19.799. |
| `POST /api/v1/roe` y `PUT /api/v1/roe/{id}` | Creación y edición de propuesta RoE | Valida colisiones In-Scope vs Out-of-Scope antes de persistir; bloquea edición si el contrato ya tiene `sha256_hash`. |
| `POST /api/v1/roe/{id}/send-to-client` · `/request-revision` · `/client-approve` · `/seal` · `/terminate` | Máquina de estados de negociación bilateral | Registra observaciones del cliente en `revision_history`, exige `backup_confirmed` al aprobar y calcula el digest SHA-256 canónico al sellar. |
| `GET /api/v1/roe/{id}/verify-integrity` | Auditoría criptográfica en vivo | Recalcula el hash SHA-256 desde la base de datos y lo compara contra `sha256_hash` almacenado para detectar adulteraciones (`tampered`). |
| `GET /api/v1/roe/{id}/export-pdf` | Exportación de contrato RoE + NDA (`format=pdf\|html`) | Genera el contrato formal con Tabla de Contenido (Índice) al inicio, cláusulas 0 a 15 y certificado de sellado SHA-256. |
| `ScopeEditor.jsx` | Formulario legal/técnico y editor de cláusulas | Valida IPs/CIDR y RUTs en tiempo real; permite editar términos del NDA, personerías y agregar cláusulas adicionales dinámicas. |
| `ContractViewer.jsx` y `roeStatus.jsx` | Visor contractual con índice, flujo de firmas y cápsulas de estado en español | Muestra checklist del Art. 2° Ley 21.459, Tabla de Contenido interactiva, botones de exportación PDF/HTML (con popover `ⓘ`) y verificador de integridad SHA-256. |

---

## Algorithms & Pure Logic

- **`ALG-ROE-1` — Canonical JSON SHA-256 Hasher (`backend/app/compliance_engine/canonical_hasher.py` y `frontend/src/lib/crypto_utils.js`):**
  - Ordenamiento recursivo de claves JSON (`sort_keys=True`), normalización de listas y codificación UTF-8 sin espacios superfluos (`separators=(",", ":")`) para producir un digest SHA-256 determinista idéntico en Python y Web Crypto API.
- **`ALG-ROE-2` — Evaluador de Eximente Penal Art. 2° Ley N° 21.459 (`backend/app/compliance_engine/rules_evaluator.py`):**
  - Evalúa determinísticamente las 4 condiciones copulativas:
    1. *Autorización expresa previa del titular* (doble firma + RUTs + confirmación Cloud/Backup).
    2. *Ausencia de ánimo de lucro ilícito o daño* (objeto contractual y cláusula penal NDA).
    3. *Ejecución dentro de límites técnicos no destructivos* (disyunción estricta entre `target_assets` y `excluded_assets` + protocolo Break-Glass).
    4. *Obligación de reporte formal y purga de datos* (plazo de purga Ley N° 21.719 y entrega de informe final).
- **`ALG-ROE-3` — Validador de Alcance de Red y RUT Chileno (`backend/app/compliance_engine/scope_validator.py` y `frontend/src/lib/network_validators.js`):**
  - Detecta solapamientos entre IPs individuales, bloques CIDR (`ipaddress.ip_network.overlaps`) y dominios FQDN entre la lista permitida (*In-Scope*) y la lista prohibida (*Hard Deny List*), además de validar el dígito verificador Módulo 11 de RUTs chilenos.

---

## Scope

- **In scope:** Redacción y edición iterativa del contrato RoE · Separación explícita de todos los RUTs · Validación de colisiones de red In-Scope vs Hard Deny List · Flujo bilateral de envío, reparos (`revision_history`), aprobación de cliente y sellado del auditor · Cláusula 8ª de NDA Bilateral con Cláusula Penal en UF · Personerías Legales para sector privado y público (OIV/SE) · Cláusulas adicionales dinámicas (`custom_clauses`) y estipulaciones libres · Exportación PDF y HTML con Tabla de Contenido (Índice) · Trigger PostgreSQL de inmutabilidad · Auditoría criptográfica SHA-256 en vivo.
- **Out of scope:** Integración con proveedores externos de Firma Electrónica Avanzada (FEA) con token físico USB (se utiliza firma electrónica simple + sellado criptográfico SHA-256 conforme a la Ley N° 19.799) · Gestión de pagos o facturación comercial.

---

## Steps

1. **Implementar motores puros de validación y hashing (`compliance_engine` y `src/lib`).** Crear `canonical_hasher.py`, `scope_validator.py`, `rules_evaluator.py`, `network_validators.js` y `crypto_utils.js` con cobertura unitaria Tier 1 sin dependencias de red ni base de datos.
2. **Definir esquema contractual chileno e inmutabilidad en Supabase.** Aplicar la migración `20261119000000_roe_chilean_contract_and_immutability.sql` con `contract_metadata JSONB` y el trigger `trg_enforce_sealed_roe_immutability`.
3. **Estructurar esquemas Pydantic (`roe_schema.py`).** Incorporar RUTs separados, campos del NDA Bilateral (`nda_duration_years`, `nda_survival_years`, `nda_penalty_uf`, `nda_custom_terms`), cláusulas EPC (`client_rep_personeria`, `auditor_rep_personeria`, `liability_cap_pct`, `dispute_resolution_seat`) y lista `custom_clauses`.
4. **Construir endpoints del ciclo de vida RoE (`roe.py`).** Implementar creación, actualización, máquina de estados bilateral (`send-to-client`, `request-revision`, `client-approve`, `seal`, `terminate`), verificación SHA-256 retrocompatible (`verify-integrity`) y exportación (`/export-pdf`).
5. **Implementar motor de generación de Contrato PDF/HTML con Tabla de Contenido (`pdf_engine.py`).** Incorporar `build_roe_toc_items()`, `render_roe_contract_html()` y `compile_roe_contract_pdf()` con fallback multipágina PDF 1.4 puro en Python.
6. **Construir interfaz de negociación y visor contractual (`ScopeEditor.jsx`, `ContractViewer.jsx`, `RoeDashboard.jsx`, `roeStatus.jsx`).** Implementar formulario con validación en vivo, constructor de cláusulas adicionales, índice interactivo, exportación PDF/HTML con botón informativo `ⓘ`, selector de roles (`Auditor Lead` y `Cliente PoC / Rep. Legal`) y cápsulas de estado en español.

---

## Acceptance criteria map

| Criterio | Paso(s) | Verificado por |
| :------- | :------ | :------------- |
| `E1` — Bloqueo de colisiones entre activos In-Scope y Hard Deny List (IP/CIDR/FQDN) | 1, 3, 4 | `backend/tests/test_compliance_rules.py` y `frontend/src/lib/network_validators.test.js` |
| `E2` — Evaluación automática de las 4 condiciones copulativas del Art. 2° Ley N° 21.459 | 1, 4, 6 | `backend/tests/test_compliance_rules.py` y panel de cumplimiento en `ContractViewer.jsx` |
| `E3` — Sellado criptográfico SHA-256 determinista e inmutabilidad post-firma (Ley N° 19.799) | 1, 2, 4 | `backend/tests/test_sha256_canonical_hash.py`, `frontend/src/lib/crypto_utils.test.js`, trigger SQL y botón `Auditar Integridad en BD` |
| `E4` — Contrato con NDA Bilateral (Cláusula Penal en UF), estructura EPC, cláusulas personalizadas e Índice en PDF | 3, 4, 5, 6 | `GET /api/v1/roe/{id}/export-pdf`, `ScopeEditor.jsx` y `ContractViewer.jsx` |

---

## Safeguards & Definition of done

- **Tier 1 en verde:** `pytest` (`test_compliance_rules.py`, `test_sha256_canonical_hash.py`) y `vitest` (`network_validators.test.js`, `crypto_utils.test.js`).
- **Aislamiento de capas:** `backend/app/compliance_engine/` y `frontend/src/lib/` mantienen cero llamadas HTTP, cero acceso a Supabase y cero dependencias de FastAPI/React.
- **Inmutabilidad garantizada en dos niveles:** validación en endpoint FastAPI (`HTTP 403`) + trigger `BEFORE UPDATE` en PostgreSQL (`trg_enforce_sealed_roe_immutability`).
