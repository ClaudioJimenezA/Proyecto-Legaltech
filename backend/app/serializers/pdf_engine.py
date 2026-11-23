"""Executive & Legal Compliance Report and Formal RoE + NDA Contract compiler (Jinja2 + WeasyPrint + PDF 1.4 fallback).

Produces:
1. Official Signed & Sealed RoE Contract PDF with EPC-style Cover Header and Table of Contents (Índice),
   Bilateral NDA + Penal Clause in UF, Custom Clauses, CAM Santiago Arbitration, Personerías, and SHA-256 Seal.
2. Dual ANCI Closing Package Executive Report PDF/HTML (Paso 3).
"""

from datetime import datetime, timezone
from typing import Any
from jinja2 import Template

_ROE_CONTRACT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Contrato RoE & NDA Bilateral — {{ agreement.title }}</title>
  <style>
    @page { size: A4; margin: 18mm; }
    body {
      font-family: Georgia, "Times New Roman", serif;
      color: #0f172a;
      line-height: 1.5;
      font-size: 11px;
      margin: 0;
      padding: 0;
    }
    .sans {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .mono { font-family: "Courier New", Courier, monospace; }
    .cover-box {
      border: 2px solid #0f172a;
      padding: 24px 20px;
      text-align: center;
      margin-bottom: 20px;
      background: #f8fafc;
    }
    .cover-eyebrow {
      font-size: 10px;
      font-weight: 800;
      letter-spacing: 0.1em;
      color: #3730a3;
      text-transform: uppercase;
    }
    .cover-title {
      font-size: 17px;
      font-weight: 900;
      margin: 10px 0 6px 0;
      text-transform: uppercase;
      color: #0f172a;
    }
    .cover-parties {
      font-size: 12px;
      font-weight: 700;
      margin: 12px 0;
      color: #1e293b;
    }
    .toc-box {
      border: 1px solid #94a3b8;
      background: #ffffff;
      padding: 16px 20px;
      border-radius: 6px;
      margin-bottom: 22px;
    }
    .toc-title {
      text-align: center;
      font-weight: 900;
      font-size: 13px;
      text-decoration: underline;
      letter-spacing: 0.06em;
      margin-bottom: 12px;
      text-transform: uppercase;
    }
    .toc-row {
      display: flex;
      justify-content: space-between;
      border-bottom: 1px dotted #94a3b8;
      padding: 3px 0;
      font-size: 10.5px;
    }
    .toc-row strong { color: #0f172a; }
    h2 {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      background: #f1f5f9;
      padding: 6px 10px;
      border-left: 4px solid #1e1b4b;
      margin-top: 18px;
      margin-bottom: 8px;
    }
    .clause-box {
      margin-bottom: 12px;
      text-align: justify;
    }
    .grid-2 {
      display: table;
      width: 100%;
      table-layout: fixed;
      margin-bottom: 10px;
    }
    .col {
      display: table-cell;
      vertical-align: top;
      padding-right: 10px;
    }
    .card {
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 10px;
      background: #f8fafc;
      margin-bottom: 8px;
      text-align: left;
    }
    .seal-box {
      background: #0f172a;
      color: #f8fafc;
      padding: 14px;
      border-radius: 6px;
      font-family: "Courier New", Courier, monospace;
      font-size: 10px;
      word-break: break-all;
      margin-top: 18px;
    }
    .sig-grid {
      display: table;
      width: 100%;
      table-layout: fixed;
      margin-top: 22px;
    }
    .sig-col {
      display: table-cell;
      text-align: center;
      padding: 10px 16px;
    }
    .sig-line {
      border-top: 1.5px solid #0f172a;
      margin-top: 30px;
      padding-top: 6px;
      font-size: 10.5px;
    }
  </style>
</head>
<body>
  <!-- PORTADA FORMAL ESTILO CONTRATO EPC / NDA CHILENO -->
  <div class="cover-box">
    <div class="cover-eyebrow sans">
      INSTRUMENTO PRECONSTITUIDO DE EXENCIÓN PENAL (ART. 2° LEY N° 21.459) Y DESCONFLICTO ANCI (LEY N° 21.663)
    </div>
    <div class="cover-title">
      CONTRATO DE REGLAS DE COMPROMISO (RULES OF ENGAGEMENT - RoE),<br/>
      AUTORIZACIÓN DE AUDITORÍA DE CIBERSEGURIDAD Y ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA)
    </div>
    <div class="cover-parties">
      ENTRE<br/>
      {{ meta.client_legal_name }} (RUT {{ meta.client_tax_id }})<br/>
      Y<br/>
      {{ meta.auditor_legal_name }} (RUT {{ meta.auditor_tax_id }})
    </div>
    <div class="sans" style="font-size: 11px;">
      <strong>PROYECTO:</strong> "{{ agreement.title }}" — <strong>Versión:</strong> v{{ agreement.version }}<br/>
      <strong>ID Instrumento:</strong> <span class="mono">{{ agreement.id }}</span> |
      <strong>Fecha Emisión:</strong> {{ generated_at }}
    </div>
  </div>

  <!-- TABLA DE CONTENIDO (ÍNDICE) AL INICIO DEL CONTRATO -->
  <div class="toc-box sans">
    <div class="toc-title">TABLA DE CONTENIDO (ÍNDICE DEL CONTRATO)</div>
    {% for item in toc_items %}
      <div class="toc-row">
        <span><strong>{{ item.number }}</strong> {{ item.title }}</span>
        <span class="mono">{{ item.section_ref }}</span>
      </div>
    {% endfor %}
  </div>

  <!-- ANTECEDENTES Y EXPOSITIVOS -->
  <h2 id="sec-antecedentes">ANTECEDENTES Y EXPOSITIVOS (EXPONEN)</h2>
  <div class="clause-box">
    <p>
      En Santiago de Chile, comparecen las Partes individualizadas en la Cláusula Primera, quienes exponen:
      <strong>(I)</strong> Que <strong>{{ meta.client_legal_name }}</strong> requiere evaluar empíricamente la
      resiliencia de su infraestructura tecnológica mediante pruebas de penetración controladas (*Pentesting* / *Red Teaming*),
      bajo el marco de exención de responsabilidad penal del <strong>Artículo 2° de la Ley N° 21.459 sobre Delitos Informáticos</strong>;
      <strong>(II)</strong> Que <strong>{{ meta.auditor_legal_name }}</strong> cuenta con las certificaciones, personal clave y
      solvencia técnica para ejecutar dichas pruebas conforme a las Buenas Prácticas de la Industria (OWASP, PTES, NIST SP 800-115); y
      <strong>(III)</strong> Que ambas Partes requieren resguardar la estricta reserva de los hallazgos y evitar falsas alarmas
      ante la <strong>Agencia Nacional de Ciberseguridad (ANCI - Ley N° 21.663)</strong>.
    </p>
  </div>

  <!-- CLÁUSULA PRIMERA -->
  <h2 id="sec-c1">1. CLÁUSULA PRIMERA: COMPARECENCIA E INDIVIDUALIZACIÓN DE LAS PARTES</h2>
  <div class="grid-2 sans">
    <div class="col">
      <div class="card">
        <strong>1.1. Parte Mandante (El Cliente / Propietario)</strong><br/>
        <strong>Razón Social Empresa:</strong> {{ meta.client_legal_name }}<br/>
        <strong>RUT Empresa Cliente:</strong> <span class="mono">{{ meta.client_tax_id }}</span><br/>
        <strong>Clasificación Ley N° 21.663:</strong> {{ meta.regulatory_classification }}<br/>
        <strong>Domicilio Legal:</strong> {{ meta.client_address }}<br/>
        <strong>Nombre Representante Legal Cliente:</strong> {{ meta.client_rep_name }}<br/>
        <strong>RUT Representante Legal Cliente / PoC:</strong> <span class="mono">{{ meta.client_rep_rut }}</span>
      </div>
    </div>
    <div class="col">
      <div class="card">
        <strong>1.2. Parte Ejecutora (El Auditor / Contratista)</strong><br/>
        <strong>Razón Social Consultora:</strong> {{ meta.auditor_legal_name }}<br/>
        <strong>RUT Consultora:</strong> <span class="mono">{{ meta.auditor_tax_id }}</span><br/>
        <strong>Domicilio Comercial:</strong> {{ meta.auditor_address }}<br/>
        <strong>Líder Técnico (Lead Pentester):</strong> {{ meta.auditor_lead_name }}<br/>
        <strong>RUT Pentester / Representante Equipo Ciberseguridad:</strong> <span class="mono">{{ meta.auditor_lead_rut }}</span>
      </div>
    </div>
  </div>

  <!-- CLÁUSULA SEGUNDA -->
  <h2 id="sec-c2">2. CLÁUSULA SEGUNDA: DEFINICIONES CONTRACTUALES Y TÉCNICAS (ESTÁNDAR EPC)</h2>
  <div class="clause-box">
    <p>
      Para efectos de este Contrato: <strong>2.1. Activos In-Scope:</strong> Dominios FQDN, direcciones IP y bloques CIDR expresamente autorizados en la Cláusula Cuarta.
      <strong>2.2. Hard Deny List (Out-of-Scope):</strong> Sistemas excluidos cuyo acceso está estrictamente vedado.
      <strong>2.3. Protocolo Break-Glass:</strong> Procedimiento de suspensión inmediata y alerta de emergencia al Punto de Contacto ante hallazgos críticos.
      <strong>2.4. Desconflicto SOC/ANCI:</strong> Cruce espaciotemporal (±2 minutos) entre alarmas SIEM/WAF y la bitácora del Auditor para descartar falsos positivos antes de reportar a la ANCI.
      <strong>2.5. Día Hábil:</strong> Cualquier día lunes a viernes, excluyendo festivos legales en la República de Chile.
    </p>
  </div>

  <!-- CLÁUSULA TERCERA -->
  <h2 id="sec-c3">3. CLÁUSULA TERCERA: TITULARIDAD, MANDATO EXPRESO (ART. 2° LEY 21.459), CLOUD Y BACKUP</h2>
  <div class="clause-box">
    <p>
      <strong>3.1. Mandato Expreso Eximente Penal:</strong> El Cliente declara ser legítimo titular o custodio autorizado de los activos In-Scope y confiere mandato expreso al Auditor bajo modalidad <strong>{{ meta.testing_modality }}</strong>, acreditando el consentimiento previo exigido por el Art. 2° de la Ley N° 21.459.<br/>
      <strong>3.2. Infraestructura Cloud:</strong> Proveedores autorizados: <span class="mono">{{ meta.cloud_providers }}</span> (Confirmación: <strong>{{ 'CONFIRMADA' if agreement.cloud_authorization_confirmed else 'PENDIENTE' }}</strong>).<br/>
      <strong>3.3. Certificación de Respaldo Previo (Backup):</strong> El Cliente certifica contar con copias de respaldo íntegras y verificadas (Estado: <strong>{{ 'RESPALDOS VERIFICADOS' if agreement.backup_confirmed else 'PENDIENTE' }}</strong>).
    </p>
  </div>

  <!-- CLÁUSULA CUARTA -->
  <h2 id="sec-c4">4. CLÁUSULA CUARTA: DELIMITACIÓN DEL ALCANCE (IN-SCOPE / OUT-OF-SCOPE) Y REGLA ABIERTA</h2>
  <div class="clause-box">
    <p>
      <strong>4.1. Regla de Ejecución Abierta:</strong> Dentro de los activos In-Scope no se restringen puertos ni vectores de antemano para preservar el descubrimiento empírico de vulnerabilidades.<br/>
      <strong>4.2. Activos Autorizados (In-Scope):</strong> <span class="mono">{{ agreement.target_assets | join(', ') }}</span>.<br/>
      <strong>4.3. Activos Excluidos (Hard Deny List / Out-of-Scope):</strong> <span class="mono">{{ (agreement.excluded_assets | join(', ')) if agreement.excluded_assets else 'Sin exclusiones adicionales' }}</span>.
    </p>
  </div>

  <!-- CLÁUSULA QUINTA -->
  <h2 id="sec-c5">5. CLÁUSULA QUINTA: VENTANA TEMPORAL, HORARIOS Y FIRMA DE TRÁFICO</h2>
  <div class="clause-box">
    <p>
      <strong>5.1. Vigencia Temporal:</strong> Desde <span class="mono">{{ agreement.execution_start }}</span> hasta <span class="mono">{{ agreement.execution_end }}</span>.<br/>
      <strong>5.2. Franja Horaria Operativa:</strong> {{ meta.allowed_time_window }}.<br/>
      <strong>5.3. Firma de Tráfico e IPs del Auditor:</strong> Cabecera HTTP obligatoria <span class="mono"><strong>X-Assessment-Scope: {{ agreement.traffic_header_token }}</strong></span> originada desde las IPs públicas fijas: <span class="mono">{{ agreement.auditor_source_ips | join(', ') }}</span>.
    </p>
  </div>

  <!-- CLÁUSULA SEXTA -->
  <h2 id="sec-c6">6. CLÁUSULA SEXTA: PUNTOS DE CONTACTO EXCLUSIVOS (PoC) Y RESERVA OPERATIVA</h2>
  <div class="clause-box">
    <p>
      Para medir los tiempos reales de detección y respuesta del SOC, no se notificará previamente a los administradores de TI. Toda coordinación o desconflicto se realizará con:<br/>
      • <strong>PoC Titular:</strong> {{ meta.poc_primary_name }} | <strong>RUT Punto de Contacto Titular:</strong> <span class="mono">{{ meta.poc_primary_rut }}</span> | Cargo: {{ meta.poc_primary_role }} | Teléfono 24/7: <span class="mono">{{ meta.poc_primary_phone }}</span> | Email: <span class="mono">{{ meta.poc_primary_email }}</span>.<br/>
      • <strong>PoC Suplente:</strong> {{ meta.poc_secondary_name or 'N/A' }} | Cargo: {{ meta.poc_secondary_role or 'N/A' }} | Teléfono 24/7: <span class="mono">{{ meta.poc_secondary_phone or 'N/A' }}</span> | Email: <span class="mono">{{ meta.poc_secondary_email or 'N/A' }}</span>.
    </p>
  </div>

  <!-- CLÁUSULA SÉPTIMA -->
  <h2 id="sec-c7">7. CLÁUSULA SÉPTIMA: LÍNEAS ROJAS OPERATIVAS Y PROTOCOLO DE EMERGENCIA BREAK-GLASS</h2>
  <div class="clause-box">
    <p>
      <strong>7.1. Prohibiciones Absolutas:</strong> Queda estrictamente prohibido ejecutar ataques de Denegación de Servicio (DoS/DDoS), destrucción o cifrado de datos productivos (ransomware), instalación de backdoors persistentes o exfiltración masiva.<br/>
      <strong>7.2. Protocolo Break-Glass:</strong> Ante el hallazgo de una vulnerabilidad crítica (RCE, compromiso de dominio o exposición masiva), el Auditor suspenderá la explotación sobre dicho vector y notificará de emergencia al PoC Titular en un plazo máximo de <strong>{{ meta.break_glass_hours }} horas</strong>.
    </p>
  </div>

  <!-- CLÁUSULA OCTAVA: NDA BILATERAL Y CLÁUSULA PENAL -->
  <h2 id="sec-c8">8. CLÁUSULA OCTAVA: ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA) Y CLÁUSULA PENAL</h2>
  <div class="clause-box">
    <p>
      <strong>8.1. Alcance Bilateral (Both-Ways NDA):</strong> {{ meta.nda_custom_terms }}<br/>
      <strong>8.2. Excepciones Legales:</strong> No constituirá infracción la revelación exigida por resolución judicial o requerimiento formal de la ANCI, previo aviso inmediato a la otra Parte.<br/>
      <strong>8.3. Vigencia y Supervivencia Post-Contractual:</strong> Las obligaciones de confidencialidad regirán durante toda la vigencia del Contrato por <strong>{{ meta.nda_duration_years }} años</strong> y sobrevivirán por un período adicional de <strong>{{ meta.nda_survival_years }} años</strong> tras su terminación o finiquito.<br/>
      <strong>8.4. Cláusula Penal por Incumplimiento de Confidencialidad (Art. 1535 Código Civil):</strong> Las Partes avalúan anticipada y convencionalmente los perjuicios derivados de cualquier divulgación dolosa o culpable de Información Confidencial o hallazgos de vulnerabilidades a terceros no autorizados en una multa única e inmediata de <strong>{{ meta.nda_penalty_uf }} UF (Unidades de Fomento)</strong>, sin perjuicio de las acciones penales y del derecho de la Parte afectada a reclamar el daño emergente que exceda dicha suma.
    </p>
  </div>

  <!-- CLÁUSULA NOVENA -->
  <h2 id="sec-c9">9. CLÁUSULA NOVENA: PROTECCIÓN DE DATOS PERSONALES Y PURGA CERTIFICADA (LEY N° 21.719)</h2>
  <div class="clause-box">
    <p>
      El Auditor aplicará el principio de minimización de datos. Todo artefacto temporal, captura o evidencia cruda que contenga datos personales será destruido de forma irreversible dentro del plazo máximo de <strong>{{ meta.data_purge_days }} días hábiles</strong> posteriores a la entrega del informe final, emitiéndose el correspondiente Certificado de Purga con sello SHA-256.
    </p>
  </div>

  <!-- CLÁUSULA DÉCIMA -->
  <h2 id="sec-c10">10. CLÁUSULA DÉCIMA: DESCONFLICTO SOC, CICLO DE RE-TEST Y REPORTE DUAL ANCI (LEY N° 21.663)</h2>
  <div class="clause-box">
    <p>
      El Auditor registrará sus vectores en tiempo real en la Bitácora Inmutable de LexPloit para permitir al SOC del Cliente el desconflicto automático (±2 minutos) antes de activar alertas de 3 horas ante la ANCI. Al cierre, se incluirá una ronda de verificación de parches (Re-Testing) y la entrega del paquete dual: Informe PDF Ejecutivo y archivo máquina estándar <strong>OASIS CSAF 2.0 (XML/JSON)</strong>.
    </p>
  </div>

  <!-- CLÁUSULA UNDÉCIMA -->
  <h2 id="sec-c11">11. CLÁUSULA UNDÉCIMA: DECLARACIONES, LIMITACIÓN DE RESPONSABILIDAD, INDEMNIDAD Y LEY N° 20.393</h2>
  <div class="clause-box">
    <p>
      <strong>11.1. Contratista Independiente:</strong> El Auditor actúa como contratista independiente, sin vínculo de subordinación laboral con el Cliente.<br/>
      <strong>11.2. Limitación de Responsabilidad (Estándar EPC):</strong> Salvo en casos de dolo, culpa grave o infracción al Acuerdo de Confidencialidad (NDA), la responsabilidad total máxima agregada de cualquiera de las Partes bajo este Contrato no excederá del <strong>{{ meta.liability_cap_pct }}%</strong> del valor total de los servicios contratados, excluyéndose el lucro cesante y daños indirectos.<br/>
      <strong>11.3. Cumplimiento Ley N° 20.393:</strong> Ambas Partes declaran dar estricto cumplimiento a la Ley N° 20.393 sobre Responsabilidad Penal de las Personas Jurídicas y prevención de delitos informáticos y cohecho.
    </p>
  </div>

  <!-- CLÁUSULAS ESPECIALES / ADICIONALES PERSONALIZADAS -->
  {% if meta.custom_clauses %}
    {% for c in meta.custom_clauses %}
      <h2 id="sec-custom-{{ loop.index }}">12.{{ loop.index }}. CLÁUSULA ESPECIAL ADICIONAL: {{ c.title | upper }}</h2>
      <div class="clause-box">
        <p>{{ c.content }}</p>
      </div>
    {% endfor %}
  {% endif %}

  {% if meta.additional_stipulations %}
    <h2 id="sec-stipulations">ESTIPULACIONES PARTICULARES Y ACUERDOS COMPLEMENTARIOS INCORPORADOS</h2>
    <div class="clause-box">
      <p>{{ meta.additional_stipulations }}</p>
    </div>
  {% endif %}

  <!-- CLÁUSULA DE ARBITRAJE Y PERSONERÍAS -->
  <h2 id="sec-arbitraje">CLÁUSULA FINAL: LEY APLICABLE, ARBITRAJE CAM SANTIAGO, PERSONERÍAS Y SELLADO SHA-256</h2>
  <div class="clause-box">
    <p>
      <strong>Ley Aplicable y Solución de Controversias:</strong> Este Contrato se rige por las leyes de la República de Chile. Toda controversia que no sea resuelta mediante negociación directa entre las Partes en un plazo de quince (15) Días Hábiles será sometida a arbitraje ante el <strong>{{ meta.dispute_resolution_seat }}</strong>.<br/>
      <strong>Personería Parte Mandante (Cliente):</strong> La personería de don/doña <strong>{{ meta.client_rep_name }}</strong> (RUT <span class="mono">{{ meta.client_rep_rut }}</span>) para representar a <strong>{{ meta.client_legal_name }}</strong> consta en {{ meta.client_rep_personeria }}.<br/>
      <strong>Personería Parte Ejecutora (Auditor):</strong> La personería de don/doña <strong>{{ meta.auditor_lead_name }}</strong> (RUT <span class="mono">{{ meta.auditor_lead_rut }}</span>) para representar a <strong>{{ meta.auditor_legal_name }}</strong> consta en {{ meta.auditor_rep_personeria }}.
    </p>
  </div>

  <!-- BLOQUE DE FIRMAS -->
  <div class="sig-grid sans">
    <div class="sig-col">
      <div class="sig-line">
        <strong>p.p. {{ meta.client_legal_name }}</strong><br/>
        Firmante Representante Legal: {{ meta.client_rep_name }}<br/>
        RUT Representante Legal Cliente / PoC: <span class="mono">{{ meta.client_rep_rut }}</span><br/>
        Estado Firma: <strong>{{ agreement.client_signed_at or 'PENDIENTE DE FIRMA' }}</strong>
      </div>
    </div>
    <div class="sig-col">
      <div class="sig-line">
        <strong>p.p. {{ meta.auditor_legal_name }}</strong><br/>
        Firmante Líder Técnico: {{ meta.auditor_lead_name }}<br/>
        RUT Pentester / Representante Equipo Ciberseguridad: <span class="mono">{{ meta.auditor_lead_rut }}</span><br/>
        Estado Firma: <strong>{{ agreement.auditor_signed_at or 'PENDIENTE DE CONTRA-FIRMA' }}</strong>
      </div>
    </div>
  </div>

  <!-- SELLO CRIPTOGRÁFICO SHA-256 -->
  <div class="seal-box">
    <strong>CERTIFICADO DE INMUTABILIDAD CRIPTOGRÁFICA SHA-256 (LEY N° 19.799)</strong><br/>
    Estado del Contrato: {{ agreement.current_status }} | Exención Art. 2° Ley 21.459: {{ 'ACREDITADA (4/4)' if art2_compliance.is_exempt else 'EN PROCESO' }}<br/>
    Digest SHA-256 del Contrato: {{ agreement.sha256_hash or 'PENDIENTE DE SELLADO DEFINITIVO' }}
  </div>
</body>
</html>
"""

_HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <title>Expediente Técnico-Legal LexPloit — {{ agreement.title }}</title>
  <style>
    @page { size: A4; margin: 18mm; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      line-height: 1.45;
      font-size: 11px;
      margin: 0;
      padding: 0;
    }
    .header {
      border-bottom: 3px solid #0f172a;
      padding-bottom: 12px;
      margin-bottom: 16px;
    }
    .eyebrow {
      font-family: monospace;
      color: #4f46e5;
      font-weight: 800;
      font-size: 10px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    h1 { font-size: 18px; margin: 4px 0; color: #0f172a; }
    h2 {
      font-size: 12px;
      text-transform: uppercase;
      background: #f1f5f9;
      padding: 6px 10px;
      border-left: 4px solid #4f46e5;
      margin-top: 16px;
      margin-bottom: 8px;
    }
    .grid-2 {
      display: table;
      width: 100%;
      table-layout: fixed;
      margin-bottom: 10px;
    }
    .col {
      display: table-cell;
      vertical-align: top;
      padding-right: 10px;
    }
    .card {
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 10px;
      background: #f8fafc;
      margin-bottom: 10px;
    }
    .mono { font-family: monospace; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 6px;
      margin-bottom: 12px;
      font-size: 10px;
    }
    th, td {
      border: 1px solid #cbd5e1;
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
    }
    th { background: #e2e8f0; font-weight: 700; }
    .seal-box {
      background: #0f172a;
      color: #f8fafc;
      padding: 12px;
      border-radius: 6px;
      font-family: monospace;
      font-size: 10px;
      word-break: break-all;
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="eyebrow">EXPEDIENTE OFICIAL DE CUMPLIMIENTO, TRAZABILIDAD Y CIERRE ANCI — LEXPLOIT v2.0</div>
    <h1>{{ agreement.title }} (Versión v{{ agreement.version }})</h1>
    <div class="mono">
      ID Acuerdo: {{ agreement.id }} | Emisión Reporte: {{ generated_at }} | Estado: {{ agreement.current_status }}
    </div>
  </div>

  <h2>1. Individualización de las Partes Contratantes y Puntos de Contacto</h2>
  <div class="grid-2">
    <div class="col">
      <div class="card">
        <strong>1.1. Parte Mandante (El Cliente)</strong><br/>
        <strong>Razón Social Empresa:</strong> {{ meta.client_legal_name }}<br/>
        <strong>RUT Empresa Cliente:</strong> <span class="mono">{{ meta.client_tax_id }}</span><br/>
        <strong>Clasificación Ley N° 21.663:</strong> {{ meta.regulatory_classification }}<br/>
        <strong>Nombre Representante Legal Cliente:</strong> {{ meta.client_rep_name }}<br/>
        <strong>RUT Representante Legal Cliente / PoC:</strong> <span class="mono">{{ meta.client_rep_rut }}</span><br/>
        <strong>Nombre PoC Titular:</strong> {{ meta.poc_primary_name }}<br/>
        <strong>RUT Punto de Contacto Titular:</strong> <span class="mono">{{ meta.poc_primary_rut }}</span><br/>
        <strong>Contacto 24/7 PoC:</strong> <span class="mono">{{ meta.poc_primary_phone }} | {{ meta.poc_primary_email }}</span>
      </div>
    </div>
    <div class="col">
      <div class="card">
        <strong>1.2. Parte Ejecutora (Equipo de Ciberseguridad)</strong><br/>
        <strong>Razón Social Consultora:</strong> {{ meta.auditor_legal_name }}<br/>
        <strong>RUT Consultora:</strong> <span class="mono">{{ meta.auditor_tax_id }}</span><br/>
        <strong>Líder Técnico (Lead Pentester):</strong> {{ meta.auditor_lead_name }}<br/>
        <strong>RUT Pentester / Representante Equipo Ciberseguridad:</strong> <span class="mono">{{ meta.auditor_lead_rut }}</span><br/>
        <strong>Modalidad de Evaluación:</strong> {{ meta.testing_modality }}<br/>
        <strong>Cabecera de Tráfico:</strong> <span class="mono">X-Assessment-Scope: {{ agreement.traffic_header_token }}</span><br/>
        <strong>IPs Públicas Auditor:</strong> <span class="mono">{{ agreement.auditor_source_ips | join(', ') }}</span>
      </div>
    </div>
  </div>

  <h2>2. Certificado de Exención de Responsabilidad Penal (Art. 2° Ley N° 21.459)</h2>
  <div class="card">
    <strong>Dictamen General:</strong>
    {% if art2_compliance.is_exempt %}
      EXENCIÓN PENAL ACREDITADA — Se cumplen las 4 condiciones copulativas del Artículo 2° de la Ley N° 21.459.
    {% else %}
      CONDICIONES PENDIENTES DE ACREDITACIÓN COMPLETA.
    {% endif %}
    <table>
      <thead>
        <tr>
          <th>Condición Legal Copulativa (Art. 2° Ley N° 21.459)</th>
          <th>Estado</th>
          <th>Fundamento Técnico-Jurídico</th>
        </tr>
      </thead>
      <tbody>
        {% for cond in art2_compliance.conditions %}
        <tr>
          <td><strong>{{ cond.name }}</strong></td>
          <td>{{ 'ACREDITADA' if cond.passed else 'PENDIENTE' }}</td>
          <td>{{ cond.reason }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <h2>3. Resumen de Telemetría en Vivo y Desconflicto SOC / ANCI (Ley N° 21.663)</h2>
  <div class="card">
    <strong>Pruebas Registradas en Bitácora Inmutable:</strong> {{ logs | length }} eventos sellados con SHA-256 ({{ critical_logs_count }} marcados como Hallazgo Crítico Break-Glass).<br/>
    <strong>Consultas de Desconflicto Ejecutadas:</strong> {{ deconfliction_queries | length }} cruces (±2 min NTP).<br/>
    <strong>• Falsos Positivos Descartados (CONFIRMED_AUTHORIZED):</strong> {{ confirmed_deconflictions }} alarmas eximidas de reporte ANCI.<br/>
    <strong>• Desvíos Operativos en Activos Permitidos (INDETERMINATE):</strong> {{ indeterminate_deconflictions }} consultas sujetas a validación con PoC.<br/>
    <strong>• Alertas Críticas / Sospechosas / Break-Glass o Exceso de Alcance (UNMATCHED_SUSPICIOUS):</strong> {{ suspicious_deconflictions }} eventos que requieren contención y evaluación ANCI.
  </div>
  {% if deconfliction_queries %}
  <table>
    <thead>
      <tr>
        <th>Ticket / Fecha Alarma</th>
        <th>IP Observada → Activo</th>
        <th>Dictamen Desconflicto</th>
        <th>Log Correlacionado</th>
        <th>Fundamento Técnico-Jurídico (Ley N° 21.459 / Ley N° 21.663)</th>
      </tr>
    </thead>
    <tbody>
      {% for q in deconfliction_queries %}
      <tr>
        <td class="mono">
          <strong>{{ q.internal_ticket_ref or 'S/N' }}</strong><br/>
          {{ q.incident_timestamp }}
        </td>
        <td class="mono">{{ q.observed_attacker_ip }} → <strong>{{ q.targeted_asset }}</strong></td>
        <td><strong>{{ q.resolution }}</strong></td>
        <td class="mono">{{ (q.matched_log_id | string)[:8] if q.matched_log_id else 'Sin Log' }}</td>
        <td>{{ q.justification_notes }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>4. Matriz de Hallazgos Técnicos, CVSS v3.1 y Ciclo de Remediación (Re-Testing)</h2>
  {% if vulnerabilities %}
  <table>
    <thead>
      <tr>
        <th>Hallazgo / CWE / CVE</th>
        <th>Activo Afectado</th>
        <th>Severidad & CVSS v3.1</th>
        <th>Estado de Remediación / Re-Test</th>
        <th>Recomendación de Mitigación</th>
      </tr>
    </thead>
    <tbody>
      {% for v in vulnerabilities %}
      <tr>
        <td>
          <strong>{{ v.title }}</strong><br/>
          <span class="mono">{{ v.cwe_id or 'CWE-N/A' }} | {{ v.cve_id or 'Sin CVE' }}</span>
        </td>
        <td class="mono">{{ v.affected_asset }}</td>
        <td>
          <strong>{{ v.severity }} ({{ v.cvss_score }})</strong><br/>
          <span class="mono" style="font-size:8px;">{{ v.cvss_vector }}</span>
        </td>
        <td><strong>{{ v.current_status }}</strong></td>
        <td>{{ v.remediation_recommendation }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="card">No se registraron vulnerabilidades abiertas en este ciclo de evaluación.</div>
  {% endif %}

  <h2>5. Cumplimiento de Protección de Datos y Purga Certificada (Ley N° 21.719)</h2>
  <div class="card">
    <strong>Plazo Máximo de Destrucción de Evidencias Crudas:</strong> {{ meta.data_purge_days or 14 }} días hábiles.<br/>
    <strong>Estado de Purga Certificada:</strong>
    {{ 'CERTIFICADA Y SANITIZADA' if meta.ley21719_purge_certified else 'PROGRAMADA DENTRO DE PLAZO LEGAL' }}
  </div>

  <div class="seal-box">
    <strong>SELLO DE INMUTABILIDAD CRIPTOGRÁFICA (LEY N° 19.799 SOBRE DOCUMENTOS ELECTRÓNICOS)</strong><br/>
    Hash SHA-256 Contrato RoE: {{ agreement.sha256_hash or 'PENDIENTE DE SELLADO' }}<br/>
    Hash SHA-256 Paquete de Cierre CSAF 2.0: {{ package_sha256_hash }}<br/>
    Firmante Cliente: {{ meta.client_rep_name }} (RUT: {{ meta.client_rep_rut }}) — {{ agreement.client_signed_at or 'Pendiente' }}<br/>
    Firmante Auditor: {{ meta.auditor_lead_name }} (RUT: {{ meta.auditor_lead_rut }}) — {{ agreement.auditor_signed_at or 'Pendiente' }}
  </div>
</body>
</html>
"""


def build_roe_toc_items(meta: dict[str, Any]) -> list[dict[str, str]]:
    """Build the ordered Table of Contents (Índice) items for the RoE + NDA Contract."""
    items = [
        {"number": "0.", "title": "ANTECEDENTES Y EXPOSITIVOS (EXPONEN)", "section_ref": "Secc. Preliminar"},
        {"number": "1.", "title": "COMPARECENCIA E INDIVIDUALIZACIÓN DE LAS PARTES", "section_ref": "Cláusula 1ª"},
        {"number": "2.", "title": "DEFINICIONES CONTRACTUALES Y TÉCNICAS (ESTÁNDAR EPC)", "section_ref": "Cláusula 2ª"},
        {"number": "3.", "title": "TITULARIDAD, MANDATO EXPRESO (ART. 2° LEY 21.459), CLOUD Y BACKUP", "section_ref": "Cláusula 3ª"},
        {"number": "4.", "title": "DELIMITACIÓN DEL ALCANCE (IN-SCOPE / HARD DENY LIST) Y REGLA ABIERTA", "section_ref": "Cláusula 4ª"},
        {"number": "5.", "title": "VENTANA TEMPORAL, FRANJA HORARIA Y FIRMA DE TRÁFICO", "section_ref": "Cláusula 5ª"},
        {"number": "6.", "title": "PUNTOS DE CONTACTO EXCLUSIVOS (PoC) Y RESERVA OPERATIVA", "section_ref": "Cláusula 6ª"},
        {"number": "7.", "title": "LÍNEAS ROJAS OPERATIVAS Y PROTOCOLO DE EMERGENCIA BREAK-GLASS", "section_ref": "Cláusula 7ª"},
        {"number": "8.", "title": "ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA) Y CLÁUSULA PENAL EN UF", "section_ref": "Cláusula 8ª"},
        {"number": "9.", "title": "PROTECCIÓN DE DATOS PERSONALES Y PURGA CERTIFICADA (LEY N° 21.719)", "section_ref": "Cláusula 9ª"},
        {"number": "10.", "title": "DESCONFLICTO SOC, CICLO DE RE-TEST Y REPORTE DUAL ANCI (LEY N° 21.663)", "section_ref": "Cláusula 10ª"},
        {"number": "11.", "title": "LIMITACIÓN DE RESPONSABILIDAD, INDEMNIDAD Y CUMPLIMIENTO LEY N° 20.393", "section_ref": "Cláusula 11ª"},
    ]

    custom_clauses = meta.get("custom_clauses") or []
    for idx, c in enumerate(custom_clauses, 1):
        title_str = c.get("title", f"Cláusula Especial {idx}") if isinstance(c, dict) else getattr(c, "title", "")
        items.append(
            {
                "number": f"12.{idx}.",
                "title": f"CLÁUSULA ESPECIAL ADICIONAL: {str(title_str).upper()}",
                "section_ref": f"Adicional {idx}",
            }
        )

    if meta.get("additional_stipulations"):
        items.append(
            {
                "number": "13.",
                "title": "ESTIPULACIONES PARTICULARES Y ACUERDOS COMPLEMENTARIOS",
                "section_ref": "Anexo Especial",
            }
        )

    items.extend(
        [
            {"number": "14.", "title": "LEY APLICABLE, ARBITRAJE CAM SANTIAGO Y PERSONERÍAS LEGALES", "section_ref": "Cláusula Final"},
            {"number": "15.", "title": "SUSCRIPCIÓN ELECTRÓNICA E INMUTABILIDAD CRIPTOGRÁFICA SHA-256 (LEY 19.799)", "section_ref": "Certificado"},
        ]
    )
    return items


def render_roe_contract_html(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
) -> str:
    """Render the formal RoE + Bilateral NDA Contract with Table of Contents as HTML."""
    template = Template(_ROE_CONTRACT_HTML_TEMPLATE)
    meta = agreement.get("contract_metadata") or {}
    toc_items = build_roe_toc_items(meta)
    return template.render(
        agreement=agreement,
        meta=meta,
        art2_compliance=art2_compliance,
        toc_items=toc_items,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def _escape_pdf_text(text: str) -> str:
    """Sanitize string to ASCII/Latin-1 safe characters for standard Type1 Courier in PDF 1.4."""
    replacements = {
        "á": "a", "é": "e", "í": "i", "ó": "o", "ú": "u",
        "Á": "A", "É": "E", "Í": "I", "Ó": "O", "Ú": "U",
        "ñ": "n", "Ñ": "N", "°": "o", "ª": "a", "±": "+-", "—": "-", "–": "-", "•": "*",
        "“": '"', "”": '"',
    }
    out = str(text)
    for k, v in replacements.items():
        out = out.replace(k, v)
    out = out.encode("ascii", "replace").decode("ascii")
    return out.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _lines_to_multipage_pdf(lines: list[str], lines_per_page: int = 52) -> bytes:
    """Pack an arbitrary list of text lines into a valid multi-page PDF 1.4 binary document."""
    chunks = [
        lines[i : i + lines_per_page]
        for i in range(0, max(1, len(lines)), lines_per_page)
    ]

    # Object 1: Catalog, Object 2: Pages, Object 3: Font
    num_pages = len(chunks)
    page_obj_ids = [4 + i * 2 for i in range(num_pages)]
    kids_ref = " ".join(f"{pid} 0 R" for pid in page_obj_ids)

    objects: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        f"2 0 obj\n<< /Type /Pages /Kids [{kids_ref}] /Count {num_pages} >>\nendobj\n".encode("ascii"),
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n",
    ]

    for idx, page_lines in enumerate(chunks):
        page_id = 4 + idx * 2
        content_id = page_id + 1
        content_ops = ["BT", "/F1 8.5 Tf", "40 795 Td", "14 TL"]
        for line in page_lines:
            content_ops.append(f"({_escape_pdf_text(line[:94])}) '")
        content_ops.append(f"(--- Pagina {idx + 1} de {num_pages} ---) '")
        content_ops.append("ET")
        stream_data = "\n".join(content_ops).encode("ascii")

        page_obj = (
            f"{page_id} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>\n"
            f"endobj\n"
        ).encode("ascii")
        content_obj = (
            f"{content_id} 0 obj\n<< /Length {len(stream_data)} >>\nstream\n".encode("ascii")
            + stream_data
            + b"\nendstream\nendobj\n"
        )
        objects.append(page_obj)
        objects.append(content_obj)

    pdf_out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf_out))
        pdf_out.extend(obj)

    xref_pos = len(pdf_out)
    pdf_out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        pdf_out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    pdf_out.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(pdf_out)


def compile_roe_contract_pdf(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
) -> bytes:
    """Compile the formal RoE + Bilateral NDA Contract PDF with Table of Contents at the start."""
    html_str = render_roe_contract_html(
        agreement=agreement,
        art2_compliance=art2_compliance,
    )
    try:
        from weasyprint import HTML  # type: ignore

        pdf_bytes = HTML(string=html_str).write_pdf()
        if pdf_bytes:
            return pdf_bytes
    except Exception:
        pass

    meta = agreement.get("contract_metadata") or {}
    toc_items = build_roe_toc_items(meta)
    lines = [
        "==========================================================================================",
        "  CONTRATO DE REGLAS DE COMPROMISO (RoE) Y ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA)",
        "  (Instrumento Preconstituido Art. 2 Ley 21.459 | Ley 21.663 ANCI | Ley 21.719 | Ley 19.799)",
        "==========================================================================================",
        f"ENTRE: {meta.get('client_legal_name')} (RUT {meta.get('client_tax_id')})",
        f"Y    : {meta.get('auditor_legal_name')} (RUT {meta.get('auditor_tax_id')})",
        f"PROYECTO: {agreement.get('title')} (Version v{agreement.get('version', 1)})",
        f"ID CONTRATO: {agreement.get('id')} | ESTADO: {agreement.get('current_status')}",
        "",
        "------------------------------------------------------------------------------------------",
        "                        TABLA DE CONTENIDO (INDICE DEL CONTRATO)",
        "------------------------------------------------------------------------------------------",
    ]
    for item in toc_items:
        title_col = f"{item['number']} {item['title']}"[:68].ljust(70, ".")
        lines.append(f"{title_col} {item['section_ref']}")

    lines.extend(
        [
            "------------------------------------------------------------------------------------------",
            "",
            "0. ANTECEDENTES Y EXPOSITIVOS (EXPONEN)",
            f"En Santiago de Chile, {meta.get('client_legal_name')} encarga a {meta.get('auditor_legal_name')}",
            "la ejecucion de pruebas de penetracion bajo las 4 condiciones eximentes del Art. 2 Ley 21.459.",
            "",
            "1. CLAUSULA PRIMERA: COMPARECENCIA E INDIVIDUALIZACION DE LAS PARTES",
            f"  1.1. MANDANTE (CLIENTE): {meta.get('client_legal_name')} | RUT Empresa: {meta.get('client_tax_id')}",
            f"       Clasificacion Ley 21.663: {meta.get('regulatory_classification')}",
            f"       Domicilio Legal: {meta.get('client_address')}",
            f"       Nombre Representante Legal Cliente: {meta.get('client_rep_name')}",
            f"       RUT Representante Legal Cliente / PoC: {meta.get('client_rep_rut')}",
            f"  1.2. EJECUTORA (AUDITOR): {meta.get('auditor_legal_name')} | RUT: {meta.get('auditor_tax_id')}",
            f"       Domicilio Comercial: {meta.get('auditor_address')}",
            f"       Lider Tecnico (Lead Pentester): {meta.get('auditor_lead_name')}",
            f"       RUT Pentester / Representante Equipo Ciberseguridad: {meta.get('auditor_lead_rut')}",
            "",
            "2. CLAUSULA SEGUNDA: DEFINICIONES CONTRACTUALES Y TECNICAS (ESTANDAR EPC)",
            "  Define Activos In-Scope, Hard Deny List, Protocolo Break-Glass, Desconflicto SOC (+-2m) y Dia Habil.",
            "",
            "3. CLAUSULA TERCERA: TITULARIDAD, MANDATO EXPRESO (ART. 2 LEY 21.459), CLOUD Y BACKUP",
            f"  Modalidad Autorizada: {meta.get('testing_modality')} | Cloud: {meta.get('cloud_providers')}",
            f"  Respaldos Verificados (Backup): {'CONFIRMADO' if agreement.get('backup_confirmed') else 'PENDIENTE'}",
            "",
            "4. CLAUSULA CUARTA: DELIMITACION DEL ALCANCE (IN-SCOPE / HARD DENY LIST)",
            f"  Activos In-Scope: {', '.join(agreement.get('target_assets') or [])}",
            f"  Activos Excluidos (Out-of-Scope): {', '.join(agreement.get('excluded_assets') or []) or 'Ninguno'}",
            "",
            "5. CLAUSULA QUINTA: VENTANA TEMPORAL, HORARIOS Y FIRMA DE TRAFICO",
            f"  Vigencia: {agreement.get('execution_start')} hasta {agreement.get('execution_end')}",
            f"  Franja Permitida: {meta.get('allowed_time_window')}",
            f"  Header HTTP: X-Assessment-Scope: {agreement.get('traffic_header_token')}",
            f"  IPs Publicas Auditor: {', '.join(agreement.get('auditor_source_ips') or [])}",
            "",
            "6. CLAUSULA SEXTA: PUNTOS DE CONTACTO EXCLUSIVOS (PoC) Y RESERVA OPERATIVA",
            f"  PoC Titular: {meta.get('poc_primary_name')} | RUT PoC Titular: {meta.get('poc_primary_rut')}",
            f"  Cargo: {meta.get('poc_primary_role')} | Tel 24/7: {meta.get('poc_primary_phone')} | {meta.get('poc_primary_email')}",
            f"  PoC Suplente: {meta.get('poc_secondary_name')} | Tel 24/7: {meta.get('poc_secondary_phone')}",
            "",
            "7. CLAUSULA SEPTIMA: LINEAS ROJAS Y PROTOCOLO DE EMERGENCIA BREAK-GLASS",
            f"  Prohibicion estricta de DoS/DDoS y alteracion de datos. Alerta Break-Glass maxima: {meta.get('break_glass_hours', 2)} horas.",
            "",
            "8. CLAUSULA OCTAVA: ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA) Y CLAUSULA PENAL",
            f"  Vigencia NDA: {meta.get('nda_duration_years', 3)} anos + {meta.get('nda_survival_years', 2)} anos post-termino.",
            f"  Clausula Penal por Incumplimiento NDA (Art. 1535 Codigo Civil): {meta.get('nda_penalty_uf', 500)} UF.",
            f"  Terminos NDA: {str(meta.get('nda_custom_terms', ''))[:180]}",
            "",
            "9. CLAUSULA NOVENA: PROTECCION DE DATOS PERSONALES Y PURGA (LEY N 21.719)",
            f"  Destruccion irreversible de evidencias crudas en {meta.get('data_purge_days', 14)} dias habiles.",
            "",
            "10. CLAUSULA DECIMA: DESCONFLICTO SOC, RE-TEST Y REPORTE DUAL ANCI (LEY N 21.663)",
            "  Bitacora en vivo, cruce +-2 min y cierre con paquete PDF + OASIS CSAF 2.0 (XML/JSON).",
            "",
            "11. CLAUSULA UNDECIMA: LIMITACION DE RESPONSABILIDAD, INDEMNIDAD Y LEY N 20.393",
            f"  Limite maximo de responsabilidad contractual (Estandar EPC): {meta.get('liability_cap_pct', 30)}%.",
        ]
    )

    for idx, c in enumerate(meta.get("custom_clauses") or [], 1):
        c_title = c.get("title") if isinstance(c, dict) else getattr(c, "title", "")
        c_content = c.get("content") if isinstance(c, dict) else getattr(c, "content", "")
        lines.append(f"12.{idx}. CLAUSULA ESPECIAL ADICIONAL: {c_title}")
        lines.append(f"  {c_content}")

    if meta.get("additional_stipulations"):
        lines.append("13. ESTIPULACIONES PARTICULARES INCORPORADAS:")
        lines.append(f"  {meta.get('additional_stipulations')}")

    lines.extend(
        [
            "",
            "14. LEY APLICABLE, ARBITRAJE CAM SANTIAGO Y PERSONERIAS LEGALES",
            f"  Arbitraje: {meta.get('dispute_resolution_seat')}",
            f"  Personeria Cliente: {meta.get('client_rep_personeria')}",
            f"  Personeria Auditor: {meta.get('auditor_rep_personeria')}",
            "",
            "15. SUSCRIPCION ELECTRONICA Y SELLO CRIPTOGRAFICO SHA-256 (LEY N 19.799)",
            f"  Firma Cliente ({meta.get('client_rep_name')} - RUT {meta.get('client_rep_rut')}): {agreement.get('client_signed_at') or 'PENDIENTE'}",
            f"  Firma Auditor ({meta.get('auditor_lead_name')} - RUT {meta.get('auditor_lead_rut')}): {agreement.get('auditor_signed_at') or 'PENDIENTE'}",
            f"  SHA-256 Digest: {agreement.get('sha256_hash') or 'PENDIENTE DE SELLADO'}",
        ]
    )

    return _lines_to_multipage_pdf(lines)


def render_compliance_report_html(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    deconfliction_queries: list[dict[str, Any]],
    package_sha256_hash: str,
) -> str:
    """Render the complete legal & technical compliance report as HTML via Jinja2."""
    template = Template(_HTML_REPORT_TEMPLATE)
    meta = agreement.get("contract_metadata") or {}
    confirmed_deconflictions = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "CONFIRMED_AUTHORIZED"
    )
    indeterminate_deconflictions = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "INDETERMINATE"
    )
    suspicious_deconflictions = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "UNMATCHED_SUSPICIOUS"
    )
    critical_logs_count = sum(1 for l in logs if l.get("is_critical_finding"))
    return template.render(
        agreement=agreement,
        meta=meta,
        art2_compliance=art2_compliance,
        vulnerabilities=vulnerabilities,
        logs=logs,
        deconfliction_queries=deconfliction_queries,
        confirmed_deconflictions=confirmed_deconflictions,
        indeterminate_deconflictions=indeterminate_deconflictions,
        suspicious_deconflictions=suspicious_deconflictions,
        critical_logs_count=critical_logs_count,
        package_sha256_hash=package_sha256_hash,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


def _build_pure_python_pdf_fallback(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    deconfliction_queries: list[dict[str, Any]],
    package_sha256_hash: str,
) -> bytes:
    """Generate a valid PDF 1.4 binary document using pure Python if WeasyPrint native libs are missing."""
    meta = agreement.get("contract_metadata") or {}
    lines = [
        "EXPEDIENTE OFICIAL DE CUMPLIMIENTO Y CIERRE ANCI - LEXPLOIT v2.0",
        "======================================================================",
        f"Proyecto: {agreement.get('title')} (Version v{agreement.get('version', 1)})",
        f"ID Acuerdo RoE: {agreement.get('id')}",
        f"Estado del Contrato: {agreement.get('current_status')}",
        f"Fecha Emision: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "1. INDIVIDUALIZACION DE LAS PARTES (REALIDAD EMPRESARIAL CHILE)",
        "----------------------------------------------------------------------",
        f"Cliente Mandante: {meta.get('client_legal_name')} | RUT Empresa: {meta.get('client_tax_id')}",
        f"Clasificacion Ley 21.663: {meta.get('regulatory_classification')}",
        f"Nombre Representante Legal Cliente: {meta.get('client_rep_name')}",
        f"RUT Representante Legal Cliente / PoC: {meta.get('client_rep_rut')}",
        f"Nombre PoC Titular: {meta.get('poc_primary_name')} | RUT PoC: {meta.get('poc_primary_rut')}",
        f"Contacto Emergencia 24/7 PoC: {meta.get('poc_primary_phone')} | {meta.get('poc_primary_email')}",
        "",
        f"Consultora Auditora: {meta.get('auditor_legal_name')} | RUT: {meta.get('auditor_tax_id')}",
        f"Lider Tecnico (Lead Pentester): {meta.get('auditor_lead_name')}",
        f"RUT Pentester / Representante Equipo Ciberseguridad: {meta.get('auditor_lead_rut')}",
        f"Token Header Trafico: X-Assessment-Scope: {agreement.get('traffic_header_token')}",
        "",
        "2. CERTIFICADO DE EXENCION PENAL (ART. 2 LEY N 21.459)",
        "----------------------------------------------------------------------",
        f"Dictamen Eximente Penal: {'ACREDITADA (4/4 CONDICIONES)' if art2_compliance.get('is_exempt') else 'PENDIENTE'}",
    ]
    for cond in art2_compliance.get("conditions") or []:
        status_txt = "OK" if cond.get("passed") else "PENDIENTE"
        lines.append(f"  [{status_txt}] {cond.get('name')}: {cond.get('reason')}")

    confirmed_cnt = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "CONFIRMED_AUTHORIZED"
    )
    indeterminate_cnt = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "INDETERMINATE"
    )
    suspicious_cnt = sum(
        1 for q in deconfliction_queries if q.get("resolution") == "UNMATCHED_SUSPICIOUS"
    )
    critical_logs_cnt = sum(1 for l in logs if l.get("is_critical_finding"))
    lines.extend([
        "",
        "3. TELEMETRIA EN VIVO Y DESCONFLICTO SOC / ANCI (LEY N 21.663)",
        "----------------------------------------------------------------------",
        f"Total Eventos en Bitacora Inmutable: {len(logs)} (Criticos Break-Glass: {critical_logs_cnt})",
        f"Consultas de Desconflicto (+-2 min): {len(deconfliction_queries)}",
        f"  - Autorizadas / Eximidas ANCI (CONFIRMED_AUTHORIZED): {confirmed_cnt}",
        f"  - Verificacion Manual PoC (INDETERMINATE): {indeterminate_cnt}",
        f"  - Alertas Criticas / Sospechosas / Break-Glass (UNMATCHED_SUSPICIOUS): {suspicious_cnt}",
    ])
    for idx, q in enumerate(deconfliction_queries, 1):
        lines.append(
            f"  [{idx}] Ticket {q.get('internal_ticket_ref') or 'S/N'} | {q.get('observed_attacker_ip')} -> {q.get('targeted_asset')} | {q.get('resolution')}"
        )
    lines.extend([
        "",
        "4. MATRIZ DE VULNERABILIDADES CVSS v3.1 Y CICLO DE RE-TEST",
        "----------------------------------------------------------------------",
    ])
    if vulnerabilities:
        for idx, v in enumerate(vulnerabilities, 1):
            lines.append(
                f"  {idx}. [{v.get('severity')} - CVSS {v.get('cvss_score')}] {v.get('title')}"
            )
            lines.append(
                f"     Activo: {v.get('affected_asset')} | Estado: {v.get('current_status')} | Vector: {v.get('cvss_vector')}"
            )
            lines.append(
                f"     Mitigacion: {str(v.get('remediation_recommendation', ''))[:95]}"
            )
    else:
        lines.append("  Sin hallazgos registrados en este acuerdo.")

    lines.extend([
        "",
        "5. PROTECCION DE DATOS (LEY 21.719) Y SELLO SHA-256 (LEY 19.799)",
        "----------------------------------------------------------------------",
        f"Plazo Purga Evidencias Ley 21.719: {meta.get('data_purge_days', 14)} dias habiles",
        f"Purga Certificada: {'SI' if meta.get('ley21719_purge_certified') else 'PROGRAMADA'}",
        f"SHA-256 Contrato RoE: {agreement.get('sha256_hash') or 'PENDIENTE'}",
        f"SHA-256 Expediente Cierre CSAF: {package_sha256_hash}",
    ])

    return _lines_to_multipage_pdf(lines)


def compile_compliance_report_pdf(
    *,
    agreement: dict[str, Any],
    art2_compliance: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    deconfliction_queries: list[dict[str, Any]],
    package_sha256_hash: str,
) -> bytes:
    """Compile the official compliance report to PDF bytes via WeasyPrint or pure-Python fallback."""
    html_str = render_compliance_report_html(
        agreement=agreement,
        art2_compliance=art2_compliance,
        vulnerabilities=vulnerabilities,
        logs=logs,
        deconfliction_queries=deconfliction_queries,
        package_sha256_hash=package_sha256_hash,
    )
    try:
        from weasyprint import HTML  # type: ignore

        pdf_bytes = HTML(string=html_str).write_pdf()
        if pdf_bytes:
            return pdf_bytes
    except Exception:
        pass

    return _build_pure_python_pdf_fallback(
        agreement=agreement,
        art2_compliance=art2_compliance,
        vulnerabilities=vulnerabilities,
        logs=logs,
        deconfliction_queries=deconfliction_queries,
        package_sha256_hash=package_sha256_hash,
    )
