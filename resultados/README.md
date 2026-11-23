# Resultados de Implementación — LexPloit v2.0 (Planes de Ingeniería por Sprint)

Esta carpeta documenta todo lo implementado en los **3 Sprints (Funcionalidades N° 1, N° 2 y N° 3)** de **LexPloit v2.0**, siguiendo el formato estructurado de `plan.md` utilizado en *RutaHogar* (`Standing questions`, `Goal`, `Approach & Resolved decisions`, `Entities`, `Algorithms & Pure Logic`, `Scope`, `Steps`, `Acceptance criteria map` y `Safeguards & Definition of done`).

---

## Índice de Planes por Funcionalidad / Sprint

1. **[Sprint 1 (Paso 1) — Negociación de Contratos RoE, NDA Bilateral, Estructura EPC y Sellado SHA-256](./sprint-1-roe-negociacion-sellado/plan.md)**
   - **Marco legal:** Art. 2° Ley N° 21.459 · Ley N° 19.799 · Ley N° 20.393 · Art. 1535 Código Civil (Cláusula Penal en UF).
   - **Qué incluye:** Formulario y negociador bilateral de Reglas de Compromiso (RoE), separación explícita de RUTs por rol, validación pura de colisiones de red (*In-Scope* vs *Hard Deny List*), Cláusula 8ª de NDA Bilateral con multa en UF, Personerías Legales (privadas, RES y OIV/Servicios Esenciales públicos), cláusulas adicionales dinámicas post-formulario, exportación a PDF/HTML con **Tabla de Contenido (Índice)** al inicio, botón informativo `ⓘ` para la vista HTML e inmutabilidad criptográfica SHA-256 con trigger en PostgreSQL.

2. **[Sprint 2 (Paso 2) — Bitácora de Telemetría Inmutable en Vivo y Motor de Desconflicto SIEM / ANCI (±2 min)](./sprint-2-bitacora-desconflicto-anci/plan.md)**
   - **Marco legal:** Art. 1° y Art. 2° Ley N° 21.459 · Art. 5° y Art. 37 Ley N° 21.663 (Ley Marco de Ciberseguridad / ANCI) · Ley N° 19.799.
   - **Qué incluye:** Consola de registro táctico en vivo exclusiva para el `Auditor Lead` con sellado SHA-256 por evento, alerta *Break-Glass* restringida al auditor, registro forense no bloqueante con `scope_warnings`, Motor de Desconflicto Espaciotemporal (`±120s` / `±600s`) con clasificación en 3 estados (`CONFIRMED_AUTHORIZED`, `INDETERMINATE` para desvíos operativos en activos permitidos, y `UNMATCHED_SUSPICIOUS` para activos excluidos/no autorizados o hallazgos críticos *Break-Glass*), precarga en 1 clic desde la bitácora, ticket SOC opcional autogenerado, exportación de **Ficha de Desconflicto para el SOC externo (`.JSON`)** e historial de consultas plegable y reseteable sin afectar la bitácora inmutable.

3. **[Sprint 3 (Paso 3) — Matriz de Vulnerabilidades CVSS v3.1, Ciclo de Re-Testing, Expediente Dual ANCI (PDF + OASIS CSAF 2.0) y Purga Ley N° 21.719](./sprint-3-vulnerabilidades-cierre-csaf-purga/plan.md)**
   - **Marco legal:** Ley N° 21.663 (Interoperabilidad ANCI / CSIRT) · Art. 2° Ley N° 21.459 · Ley N° 21.719 (Protección de Datos Personales y Purga en 14 días hábiles) · Ley N° 19.799.
   - **Qué incluye:** Calculadora matemática oficial FIRST CVSS v3.1 en tiempo real, flujo completo de remediación y verificación de parches (*Re-Testing*) con línea de tiempo plegable en `remediation_logs`, exportación dual compuesta por el **Informe Oficial Ejecutivo (`.PDF` y `.HTML` con tabla detallada de consultas de desconflicto)** y el paquete máquina **OASIS CSAF 2.0 (`.JSON` y `.XML`)**, y ejecución de **Purga Certificada de Evidencias Crudas** con emisión de Acta firmada con SHA-256.
