# PLAN — Sprint 2 (Funcionalidad N° 2): Bitácora de Telemetría Inmutable en Vivo y Motor de Desconflicto Espaciotemporal SIEM / ANCI (±2 min)

- **Funcionalidad:** Sprint 2 (Paso 2) — Live Assessment Logger con Protocolo *Break-Glass* y Motor de Desconflicto de Incidentes en Tiempo Real (±2 minutos NTP)
- **Actores:** `Auditor Lead` (registra telemetría en vivo y audita cruces) · `Cliente PoC / Rep. Legal` (opera la consola de desconflicto SIEM/ANCI, descarga comprobantes ANCI y exporta la ficha operativa para su SOC externo)
- **Marco Normativo:** Ley N° 21.663 (Ley Marco de Ciberseguridad — Art. 5° y Art. 37 Alerta Temprana de 3 horas ante la ANCI) · Ley N° 21.459 (Art. 1° Acceso Ilícito por Exceso de Mandato y Art. 2° Eximente por Mandato Autorizado) · Ley N° 19.799 (Sellado Criptográfico SHA-256 por evento)
- **Estado / Sprint:** Implementado y Verificado · Sprint 2 · Prioridad Alta (Operación y Desconflicto en Tiempo Real)
- **Depende de:** Acuerdo RoE sellado con SHA-256 en Sprint 1 (`ACTIVE` / `SIGNED_AND_SEALED`) · **Requerido por:** Sprint 3 (Expediente Dual de Cierre ANCI PDF + OASIS CSAF 2.0 y Purga Ley N° 21.719)
- **Rama:** `main` (`feat/sprint2-live-logger-anci-deconfliction`)

---

## Start here

Para revisión arquitectónica, pruebas de correlación espaciotemporal y despliegue del Paso 2:

- **Leer primero:**
  - Motor puro de desconflicto y hashing de telemetría (Capa 1 Backend): `backend/app/compliance_engine/deconfliction_matcher.py`.
  - Tests unitarios del motor puro (Tier 1): `backend/tests/test_deconfliction_matcher.py`.
  - Esquemas y Endpoints REST (Capa 2 Backend): `backend/app/schemas/log_schema.py`, `backend/app/schemas/deconfliction_schema.py`, `backend/app/api/v1/endpoints/logger.py`, `backend/app/api/v1/endpoints/deconfliction.py`.
  - Componentes, Servicios y Hooks (Capa 2 Frontend): `frontend/src/features/live_logger/components/LiveLoggerWorkspace.jsx`, `frontend/src/features/live_logger/components/QuickLogForm.jsx`, `frontend/src/features/live_logger/components/TelemetryFeed.jsx`, `frontend/src/features/live_logger/components/DeconflictionPanel.jsx`, `frontend/src/features/live_logger/hooks/useLiveAssessmentLogger.js`, `frontend/src/features/live_logger/hooks/useDeconflictionSearch.js`, `frontend/src/features/live_logger/constants/loggerBadges.jsx`.
- **Invariantes que no se deben romper:**
  - **Bloqueo preventivo sin contrato sellado:** `POST /api/v1/logger` rechaza con `HTTP 409` cualquier intento de registrar pruebas si el acuerdo RoE no está en estado `ACTIVE` o `SIGNED_AND_SEALED`.
  - **Trazabilidad forense no bloqueante en el Logger:** Cuando un contrato ya está activo, el logger **nunca descarta ni bloquea** un registro si el pentester ingresa un activo fuera de alcance o una IP no enrolada; lo sella con SHA-256 en `assessment_logs` y emite `scope_warnings` para conservar la prueba forense del incumplimiento y permitir que el Motor de Desconflicto lo detecte.
  - **Separación de vistas por rol:** El perfil `Cliente PoC / Rep. Legal` no ve la `Consola Pentester (Live Logger)` ni la alerta interna *Break-Glass* del auditor; accede directamente al **Motor de Desconflicto SIEM/ANCI** y a la **Bitácora de Telemetría Inmutable en Vivo**.
  - **Limpieza segura del historial de pruebas:** Resetear el historial de consultas de desconflicto (`deconfliction_queries`) limpia únicamente las simulaciones/consultas del motor y preserva 100% intacta la bitácora forense del pentester (`assessment_logs`).

---

## Standing questions

| # | Pregunta de Arquitectura / Cumplimiento | Respuesta |
| :- | :-------------------------------------- | :-------- |
| 1 | ¿Toca motores puros (`compliance_engine`)? ¿Qué reglas cambiaron? | **Sí.** Implementa `ALG-DECONF-1` (`compute_log_record_hash`) y `ALG-DECONF-2` (`match_incident_against_logs` y `_asset_matches_rule` en `deconfliction_matcher.py`) con ventana NTP de `±120s` (`DEFAULT_TOLERANCE_SECONDS`) y ventana extendida de `±600s` (`EXTENDED_INDETERMINATE_SECONDS`). |
| 2 | ¿Requiere RLS / aislamiento por rol? | **Sí.** Se eliminó el rol ficticio `Operador SOC / ANCI` de la plataforma (`security.py` y `RoeDashboard.jsx`), dejando únicamente los 2 roles reales del acuerdo (`Auditor Lead` y `Cliente PoC / Rep. Legal`). El SOC externo recibe una **Ficha de Desconflicto Sanitizada (`.JSON`)** exportada por el PoC. |
| 3 | ¿Requiere migración o provisión de usuarios en Supabase? | **Usa tablas existentes** (`assessment_logs` y `deconfliction_queries` de `20261116000000_init_lexploit_schema.sql`) e incorpora `resolve_or_provision_auth_user_id()` en `security.py` para garantizar integridad referencial con `auth.users(id)`. |
| 4 | ¿Cambia el contrato de API REST? | **Sí.** Expone `/api/v1/logger` (`POST /`, `GET /active/{agreement_id}`, `PATCH /{log_id}/finish`) y `/api/v1/deconfliction` (`POST /match`, `GET /history/{agreement_id}`, `DELETE /history/{agreement_id}`, `DELETE /{query_id}`, `GET /{query_id}/certificate`). |
| 5 | ¿Impacto en reporte regulatorio ANCI (Ley N° 21.663) y responsabilidad penal (Ley N° 21.459)? | **Sí, directo.** Distingue determinísticamente entre falsos positivos eximidos de reporte ANCI (`CONFIRMED_AUTHORIZED`), desvíos operativos en activos permitidos (`INDETERMINATE`) y excesos de mandato / hallazgos críticos *Break-Glass* / intrusiones reales (`UNMATCHED_SUSPICIOUS`). |

---

## Goal

Permitir que el `Auditor Lead` registre en tiempo real cada vector de prueba con sellado criptográfico **SHA-256** individual y activación del protocolo de emergencia **Break-Glass**, y que el `Cliente PoC / Rep. Legal` cruce cualquier alarma de su SIEM/WAF/EDR en una ventana espaciotemporal de **±2 minutos** para obtener un **Comprobante Digital de Desconflicto ANCI** sellado con SHA-256 que acredite si una alerta es una prueba legítima (evitando falsos positivos ante la ANCI), una desviación operativa que requiere validación con el PoC, o una intrusión / exceso de mandato que exige contención inmediata y evaluación del reporte de Alerta Temprana de 3 horas (Art. 37 Ley N° 21.663).

---

## Approach & Resolved decisions

El motor puro `match_incident_against_logs()` evalúa primero las fronteras legales duras del contrato RoE (`excluded_assets`, `target_assets` y flag `is_critical_finding`) antes de emitir cualquier exención automática, y luego correlaciona IP de origen (exacta o CIDR), activo destino (exacto, CIDR, wildcard `*.dominio.cl` o subdominio) y distancia temporal en segundos con tolerancia NTP de `±120s`.

| Decisión | Justificación |
| :------- | :------------ |
| **Logger forense no bloqueante con `scope_warnings`** | Si el logger bloqueara registros fuera de alcance, el pentester que incumple el contrato no dejaría rastro en la bitácora. Al sellar el registro y emitir `scope_warnings`, el exceso de mandato queda probado y el Motor de Desconflicto lo captura. |
| **Regla de 3 estados para evitar tanto falsos positivos ANCI como impunidad por exceso de alcance** | 1) **`UNMATCHED_SUSPICIOUS`** (`anci_report_required = True`): si el activo está en `excluded_assets` (*Hard Deny List*), o fuera de `target_assets` (*In-Scope*), o el log está marcado como **Hallazgo Crítico Break-Glass** (`is_critical_finding = True`), o la IP es externa sin correlación. 2) **`INDETERMINATE`** (`anci_report_required = False`): cuando el activo **SÍ está permitido (*In-Scope*)**, pero hay una desviación operativa verificable (fuera de ventana horaria `[execution_start, execution_end]`, IP no enrolada en el RoE o desfase NTP de 2 a 10 min). 3) **`CONFIRMED_AUTHORIZED`** (`anci_report_required = False`): activo permitido, IP enrolada, dentro de ventana contractual y desfase `≤ 120s`. |
| **Comparación estricta de activos (`_asset_matches_rule`) sin falsos positivos por *substring*** | Reemplaza la búsqueda por subcadena simple por validación real de IP/CIDR (`ipaddress`), wildcards y frontera de punto (`.`), evitando que autorizar `10.0.0.1` autorice accidentalmente `10.0.0.10`. |
| **Eliminación del rol `Operador SOC` y creación de Ficha Exportable para el SOC (`.JSON`)** | El operador SOC es externo al contrato confidencial RoE. El `Cliente PoC` opera la consola de desconflicto y puede descargar una ficha JSON sanitizada (con header `X-Assessment-Scope`, IPs enroladas, activos In-Scope/Excluidos y contacto PoC 24/7) para entregársela a su SOC sin exponer cláusulas comerciales ni el NDA. |
| **Ticket SOC/CSIRT opcional con autogeneración (`LEX-SOC-XXXX`)** | Permite al PoC pegar el ID real de su sistema de tickets externo (Jira, ServiceNow, TheHive) o dejarlo vacío para que LexPloit autogenere un código de correlación. |
| **Historial de consultas plegable y reseteable sin afectar la Bitácora Inmutable** | Reduce la carga cognitiva plegando el historial por defecto y permite borrar consultas individuales o resetear las simulaciones de prueba (`DELETE /history/{agreement_id}`) antes de emitir el expediente final ANCI, manteniendo intacta la tabla `assessment_logs`. |

---

## Entities

| Superficie | Nuevo / Cambio | Propiedad e Historial |
| :--------- | :------------- | :-------------------- |
| `public.assessment_logs` | Tabla de telemetría en vivo con `record_hash` SHA-256 | Propiedad del `Auditor Lead`. Cada evento registra `started_at`, `ended_at`, `source_ip`, `target_host`, `target_port`, `http_method`, `target_endpoint`, `injected_header_token`, `activity_type`, `tool_or_technique`, `is_critical_finding` y `record_hash`. No se elimina al resetear el historial de desconflicto. |
| `public.deconfliction_queries` | Tabla de consultas de desconflicto SIEM/ANCI | Registra `incident_timestamp`, `observed_attacker_ip`, `targeted_asset`, `internal_ticket_ref`, `matched_log_id`, `resolution` y `justification_notes`. Permite limpieza de pruebas individuales o por acuerdo. |
| `POST /api/v1/logger` · `GET /api/v1/logger/active/{id}` · `PATCH /api/v1/logger/{id}/finish` | API REST de Bitácora en Vivo | Sella eventos con SHA-256, activa `break_glass_alert` ante hallazgos críticos y devuelve `scope_warnings` no bloqueantes. |
| `POST /api/v1/deconfliction/match` | Endpoint de cruce espaciotemporal (±2 min) | Ejecuta `match_incident_against_logs` pasando `target_assets`, `excluded_assets`, `auditor_source_ips`, `execution_start` y `execution_end` del RoE, persiste la consulta y calcula `certificate_hash`. |
| `GET /api/v1/deconfliction/{query_id}/certificate` | Emisor de Comprobante Digital ANCI | Genera el certificado firmado con SHA-256, individualización de partes con RUTs separados, dictamen normativo (Ley 21.663 / Ley 21.459) y evidencia del log correlacionado. |
| `DELETE /api/v1/deconfliction/history/{agreement_id}` y `DELETE /api/v1/deconfliction/{query_id}` | Limpieza de consultas de prueba del motor | Elimina simulaciones de `deconfliction_queries` conservando intacta la bitácora `assessment_logs`. |
| `QuickLogForm.jsx` y `TelemetryFeed.jsx` | Consola de registro táctico (solo Auditor) y feed en vivo | Incluye 5 plantillas rápidas (Nmap, API Fuzzing, Auth Spray, Break-Glass PoC y Simulación Fuera de Alcance), copia de header `X-Assessment-Scope` y botón `Comprobar Cruce en Motor de Desconflicto (±2 min)` que precarga los datos del log en el motor. |
| `DeconflictionPanel.jsx` y `LiveLoggerWorkspace.jsx` | Consola de Desconflicto PoC Cliente, Historial Plegable y Modal Comprobante ANCI | Incluye 3 escenarios de simulación rápida, exportación de Ficha para el SOC (`.JSON`), historial plegable con botón de reset/respaldo y modal imprimible/descargable del Comprobante Digital ANCI. |

---

## Algorithms & Pure Logic

- **`ALG-DECONF-1` — Hash Criptográfico de Registro de Telemetría (`compute_log_record_hash` en `deconfliction_matcher.py`):**
  - Construye un payload canónico con los 14 atributos del vector de prueba normalizados a UTC/lowercase y genera un digest SHA-256 de 64 caracteres que se recalcula al cerrar una prueba en curso (`finish_assessment_log`).
- **`ALG-DECONF-2` — Motor Determinista de Desconflicto Espaciotemporal y Alcance (`match_incident_against_logs` en `deconfliction_matcher.py`):**
  - **Paso 1 (Frontera Legal Art. 1° Ley N° 21.459):** Verifica si `targeted_asset` coincide con `excluded_assets` o queda fuera de `target_assets` usando `_asset_matches_rule()`. Si viola el alcance, retorna `UNMATCHED_SUSPICIOUS` (`anci_report_required = True`) y adjunta el `forensic_log` si fue registrado por el auditor.
  - **Paso 2 (Correlación Exacta ±120s):** Si existe coincidencia de IP, activo y ventana de `±120s`:
    - Si `matched.is_critical_finding == True` (*Break-Glass*) → retorna `UNMATCHED_SUSPICIOUS` (`anci_report_required = True`) activando el protocolo de emergencia Ley N° 21.663.
    - Si la IP no está enrolada en `authorized_auditor_ips` o el timestamp cae fuera de `[execution_start, execution_end]` → retorna `INDETERMINATE` (`anci_report_required = False`).
    - Si cumple todas las condiciones → retorna `CONFIRMED_AUTHORIZED` (`anci_report_required = False`).
  - **Paso 3 (Correlación Parcial ±600s o IP Enrolada en Activo Permitido):** Retorna `INDETERMINATE` (`anci_report_required = False`) instruyendo validación telefónica con el PoC.
  - **Paso 4 (Sin Correlación):** Retorna `UNMATCHED_SUSPICIOUS` (`anci_report_required = True`).

---

## Scope

- **In scope:** Consola de registro en vivo con plantillas rápidas (exclusiva para `Auditor Lead`) · Sellado SHA-256 por cada evento de telemetría · Protocolo *Break-Glass* con alerta de parada inmediata (solo visible al Auditor) · Registro forense no bloqueante con alertas de desvío de RoE (`scope_warnings`) · Motor de desconflicto espaciotemporal (`±120s` / `±600s`) con validación de activos In-Scope y Hard Deny List · Precarga en 1 clic desde cualquier entrada de la bitácora hacia el motor de desconflicto · Ticket SOC externo opcional con autogeneración · Exportación de Ficha de Desconflicto para el SOC externo (`.JSON`) · Historial de consultas plegable con borrado individual y reset completo sin pérdida de bitácora · Comprobante Digital ANCI imprimible y descargable en JSON firmado.
- **Out of scope:** Ingesta directa por syslog/webhook desde SIEMs propietarios o bloqueo automático en firewalls del cliente (el desconflicto opera bajo arquitectura *Serverless* desacoplada entregando fichas JSON y comprobantes firmados al PoC).

---

## Steps

1. **Construir el motor puro de correlación espaciotemporal (`deconfliction_matcher.py`).** Implementar `_ips_match`, `_asset_matches_rule`, `_compute_time_delta_seconds`, `compute_log_record_hash` y `match_incident_against_logs` con soporte para fronteras contractuales (`target_assets`, `excluded_assets`, `execution_start`, `execution_end`) y hallazgos críticos *Break-Glass*.
2. **Escribir suite de pruebas unitarias Tier 1 (`test_deconfliction_matcher.py`).** Cubrir coincidencias dentro de `±120s`, frontera exacta de `120s`, intervalos en curso `[started_at, ended_at]`, ventana extendida `±600s` (`INDETERMINATE`), IPs externas maliciosas, activos excluidos (*Hard Deny List*), activos fuera de *In-Scope*, desvíos de ventana horaria, IPs no enroladas, prevención de falso positivo por substring IP (`10.0.0.1` vs `10.0.0.10`) y hallazgos críticos *Break-Glass*.
3. **Implementar endpoints del Live Assessment Logger (`logger.py` y `log_schema.py`).** Validar estado sellado del contrato (`HTTP 409`), registrar eventos con hash SHA-256, emitir `break_glass_alert` y `scope_warnings` no bloqueantes, y permitir cierre de pruebas en curso (`PATCH /{log_id}/finish`).
4. **Implementar endpoints de Desconflicto y Comprobante ANCI (`deconfliction.py` y `deconfliction_schema.py`).** Conectar `/match` con las reglas del contrato RoE, generar el Comprobante Digital ANCI (`/{query_id}/certificate`) con dictámenes diferenciados para los 3 estados y habilitar limpieza del historial (`DELETE /history/{agreement_id}` y `DELETE /{query_id}`).
5. **Desarrollar interfaz diferenciada por rol (`LiveLoggerWorkspace.jsx`, `QuickLogForm.jsx`, `TelemetryFeed.jsx`, `DeconflictionPanel.jsx`).** Ocultar la consola pentester y el banner *Break-Glass* al `Cliente PoC`, conectar la precarga desde la bitácora hacia el motor de desconflicto, añadir exportación de Ficha para el SOC (`.JSON`), hacer plegable el historial de consultas y agregar el modal de reset seguro con opción de respaldo JSON.

---

## Acceptance criteria map

| Criterio | Paso(s) | Verificado por |
| :------- | :------ | :------------- |
| `E1` — Correlación positiva dentro de `±2 minutos` sobre activo In-Scope e IP enrolada (`CONFIRMED_AUTHORIZED`) | 1, 2, 4 | `test_match_within_plus_minus_2_minutes_is_confirmed_authorized` y `test_match_at_exact_120_second_boundary` |
| `E2` — Detección de exceso de mandato (activo excluido o fuera de In-Scope) y hallazgos críticos *Break-Glass* como `UNMATCHED_SUSPICIOUS` | 1, 2, 3, 4 | `test_auditor_hitting_excluded_asset_is_unmatched_suspicious`, `test_auditor_hitting_unlisted_asset_outside_in_scope_is_unmatched_suspicious` y `test_critical_break_glass_log_triggers_unmatched_suspicious_alert` |
| `E3` — Clasificación `INDETERMINATE` ante desvíos operativos en activos permitidos (fuera de ventana horaria, IP no enrolada o desfase 2–10 min) | 1, 2, 4 | `test_permitted_asset_outside_contract_window_is_indeterminate`, `test_permitted_asset_logged_from_unenrolled_ip_is_indeterminate` y `test_partial_match_within_extended_window_returns_indeterminate` |
| `E4` — Separación de vistas Auditor/Cliente, precarga desde bitácora, historial plegable/reseteable y Ficha JSON para el SOC | 4, 5 | `LiveLoggerWorkspace.jsx`, `TelemetryFeed.jsx` y `DeconflictionPanel.jsx` |

---

## Safeguards & Definition of done

- **Tier 1 en verde:** 12 tests unitarios en `backend/tests/test_deconfliction_matcher.py` verificando todas las combinaciones de tiempo, IP, activo y severidad *Break-Glass*.
- **Integridad forense preservada:** Ninguna operación de limpieza del historial de desconflicto modifica ni elimina filas de `public.assessment_logs`.
- **Confidencialidad frente a terceros:** La Ficha de Desconflicto para el SOC (`.JSON`) exporta únicamente parámetros de red, cabeceras HTTP y contacto de emergencia PoC, excluyendo montos, cláusulas penales NDA y anexos comerciales.
