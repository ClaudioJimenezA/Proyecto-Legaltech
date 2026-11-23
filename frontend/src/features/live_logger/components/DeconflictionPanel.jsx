import React, { useEffect, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Download,
  FileBadge,
  Fingerprint,
  History,
  Printer,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import {
  ActivityTypeBadge,
  DeconflictionResolutionBadge,
} from '../constants/loggerBadges';

function toDatetimeLocal(isoOrDate) {
  const d = isoOrDate ? new Date(isoOrDate) : new Date();
  const tzOffsetMs = d.getTimezoneOffset() * 60000;
  return new Date(d.getTime() - tzOffsetMs).toISOString().slice(0, 19);
}

export default function DeconflictionPanel({
  agreement,
  logs = [],
  prefilledAlarm = null,
  matchResult,
  history = [],
  activeCertificate,
  onExecuteMatch,
  onLoadCertificate,
  onCloseCertificate,
  onClearHistory,
  onDeleteQuery,
  loading = false,
  error = null,
}) {
  const [confirmClearModal, setConfirmClearModal] = useState(false);
  const [incidentTimeLocal, setIncidentTimeLocal] = useState(() => toDatetimeLocal());
  const [observedIp, setObservedIp] = useState(
    agreement?.auditor_source_ips?.[0] || '181.43.22.10'
  );
  const [targetedAsset, setTargetedAsset] = useState(
    agreement?.target_assets?.[0] || 'api.cliente.cl'
  );
  const [ticketRef, setTicketRef] = useState('');
  const [prefillNotice, setPrefillNotice] = useState(null);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    const logEntry = prefilledAlarm?.log || prefilledAlarm;
    if (logEntry && logEntry.started_at) {
      const baseTs = new Date(logEntry.started_at);
      // Simular +35 segundos de desfase de reloj NTP entre el pentester y el SIEM
      const driftedTs = new Date(baseTs.getTime() + 35 * 1000);
      setIncidentTimeLocal(toDatetimeLocal(driftedTs));
      setObservedIp(logEntry.source_ip || '181.43.22.10');
      setTargetedAsset(logEntry.target_host || 'api.cliente.cl');
      setTicketRef('');
      setPrefillNotice(
        `Campos rellenados desde el registro de bitácora (${logEntry.source_ip} → ${logEntry.target_host}, +35s NTP simulado). Presione "Ejecutar Cruce" para verificar.`
      );
    }
  }, [prefilledAlarm]);

  const simulateAuthorizedMatch = () => {
    if (logs.length > 0) {
      const latest = logs[0];
      const drifted = new Date(new Date(latest.started_at).getTime() + 45 * 1000);
      setIncidentTimeLocal(toDatetimeLocal(drifted));
      setObservedIp(latest.source_ip);
      setTargetedAsset(latest.target_host);
      setTicketRef('INC-SIEM-4021');
    } else {
      setIncidentTimeLocal(toDatetimeLocal());
      setObservedIp(agreement?.auditor_source_ips?.[0] || '181.43.22.10');
      setTargetedAsset(agreement?.target_assets?.[0] || 'api.cliente.cl');
      setTicketRef('INC-SIEM-4021');
    }
  };

  const simulateMaliciousAttack = () => {
    setIncidentTimeLocal(toDatetimeLocal());
    setObservedIp('45.155.205.99');
    setTargetedAsset(agreement?.target_assets?.[0] || 'api.cliente.cl');
    setTicketRef('INC-CRIT-9918');
  };

  const simulateScopeBreachByAuditor = () => {
    setIncidentTimeLocal(toDatetimeLocal());
    setObservedIp(agreement?.auditor_source_ips?.[0] || '181.43.22.10');
    setTargetedAsset(agreement?.excluded_assets?.[0] || 'db-prod.cliente.cl');
    setTicketRef('INC-SCOPE-7701');
  };

  const handleExportSocBriefingJson = () => {
    if (!agreement) return;
    const metaInfo = agreement.contract_metadata || {};
    const briefing = {
      document_type: 'FICHA_DESCONFLICTO_SOC_EXTERNO',
      generated_at: new Date().toISOString(),
      purpose:
        'Paquete operativo sanitizado para entregar al equipo SOC / SIEM externo (sin exponer cláusulas comerciales ni anexos confidenciales del contrato RoE).',
      agreement_reference: {
        agreement_id: agreement.id,
        title: agreement.title,
        version: agreement.version,
        status: agreement.current_status,
        contract_sha256_hash: agreement.sha256_hash || null,
      },
      siem_waf_filtering_parameters: {
        http_identification_header: `X-Assessment-Scope: ${agreement.traffic_header_token || ''}`,
        authorized_auditor_source_ips: agreement.auditor_source_ips || [],
        execution_window_utc: {
          start: agreement.execution_start,
          end: agreement.execution_end,
        },
        ntp_deconfliction_tolerance_seconds: 120,
      },
      authorized_scope_boundaries: {
        in_scope_target_assets: agreement.target_assets || [],
        hard_deny_excluded_assets: agreement.excluded_assets || [],
      },
      emergency_escalation_poc: {
        client_legal_name: metaInfo.client_legal_name || null,
        regulatory_classification: metaInfo.regulatory_classification || null,
        poc_primary_name: metaInfo.poc_primary_name || null,
        poc_primary_phone_24_7: metaInfo.poc_primary_phone || null,
        poc_primary_email: metaInfo.poc_primary_email || null,
        break_glass_max_hours: metaInfo.break_glass_hours || 2,
      },
      recent_deconfliction_resolutions: history.slice(0, 10).map((q) => ({
        query_id: q.id,
        internal_ticket_ref: q.internal_ticket_ref,
        incident_timestamp: q.incident_timestamp,
        observed_attacker_ip: q.observed_attacker_ip,
        targeted_asset: q.targeted_asset,
        resolution: q.resolution,
      })),
      soc_operating_instructions: [
        '1. Filtre alertas provenientes de las IPs declaradas que porten la cabecera X-Assessment-Scope SOLO sobre activos listados en in_scope_target_assets.',
        '2. Cualquier tráfico hacia hard_deny_excluded_assets o activos fuera de in_scope_target_assets DEBE ser contenido y escalado de inmediato al PoC del Cliente (Art. 1° Ley N° 21.459).',
        '3. Ante alertas dudosas, solicite al PoC del Cliente el Comprobante Digital de Desconflicto ANCI emitido desde LexPloit antes de activar el plazo de 3 horas de la Ley N° 21.663.',
      ],
    };

    const blob = new Blob([JSON.stringify(briefing, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Ficha_Desconflicto_SOC_${String(agreement.id).slice(0, 8).toUpperCase()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!agreement) return;

    const isoTimestamp = incidentTimeLocal
      ? new Date(incidentTimeLocal).toISOString()
      : new Date().toISOString();

    const effectiveTicketRef =
      ticketRef.trim() || `LEX-SOC-${Math.floor(1000 + Math.random() * 9000)}`;

    await onExecuteMatch({
      agreement_id: agreement.id,
      incident_timestamp: isoTimestamp,
      observed_attacker_ip: observedIp.trim(),
      targeted_asset: targetedAsset.trim(),
      internal_ticket_ref: effectiveTicketRef,
    });
    setPrefillNotice(null);
  };

  const handleDownloadCertificateJson = (cert) => {
    const blob = new Blob([JSON.stringify(cert, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${cert.certificate_id || 'Comprobante_Desconflicto_ANCI'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const meta = agreement?.contract_metadata || {};

  return (
    <div className="space-y-6">
      {/* Panel Principal de Consulta SOC / Desconflicto ANCI */}
      <div className="bg-white rounded-xl shadow border border-slate-200 overflow-hidden">
        <div className="bg-slate-900 text-white px-5 py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-600 rounded-lg">
              <Radar className="w-5 h-5 text-white" />
            </div>
            <div>
              <h3 className="text-sm font-black tracking-wide">
                Motor de Desconflicto de Alertas SIEM / ANCI — Consola PoC Cliente (Ley N° 21.663)
              </h3>
              <p className="text-[11px] text-slate-400">
                Cruce espaciotemporal (±2 min) y validación de alcance (In-Scope / Hard Deny List) para entregar certeza jurídica al SOC externo y a la ANCI
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <span className="px-3 py-1 rounded-full bg-slate-800 border border-slate-700 text-[11px] font-mono text-emerald-300">
              Tolerancia NTP: ±120s
            </span>
            <button
              type="button"
              disabled={!agreement}
              onClick={handleExportSocBriefingJson}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-700 text-white text-[11px] font-bold flex items-center gap-1.5 shadow transition-colors"
              title="Descarga una ficha sanitizada (IPs, Header X-Assessment-Scope, In-Scope, Exclusiones y PoC) para enviar al equipo SOC externo"
            >
              <Download className="w-3.5 h-3.5" />
              Exportar Ficha para el SOC (.JSON)
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {/* Botones de Simulación Rápida para Evaluación */}
          <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-200">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1">
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
              Escenarios de Prueba Rápida (SIEM / WAF):
            </span>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={simulateAuthorizedMatch}
                className="px-3 py-1.5 text-xs font-bold rounded-lg border border-emerald-300 bg-emerald-50 text-emerald-900 hover:bg-emerald-100 transition-colors"
              >
                🟢 Alarma Coincidente con Último Log (+45s)
              </button>
              <button
                type="button"
                onClick={simulateScopeBreachByAuditor}
                className="px-3 py-1.5 text-xs font-bold rounded-lg border border-amber-300 bg-amber-50 text-amber-900 hover:bg-amber-100 transition-colors"
              >
                🟠 Desvío de Alcance (IP Auditor → Activo Excluido)
              </button>
              <button
                type="button"
                onClick={simulateMaliciousAttack}
                className="px-3 py-1.5 text-xs font-bold rounded-lg border border-rose-300 bg-rose-50 text-rose-900 hover:bg-rose-100 transition-colors"
              >
                🔴 IP Externa Maliciosa (45.155.205.99)
              </button>
            </div>
          </div>

          {prefillNotice && (
            <div className="p-3 bg-indigo-50 border border-indigo-200 text-indigo-900 text-xs rounded-lg flex items-center justify-between gap-2">
              <span className="font-medium">ℹ️ {prefillNotice}</span>
              <button
                type="button"
                onClick={() => setPrefillNotice(null)}
                className="text-indigo-500 hover:text-indigo-800 font-bold"
              >
                ✕
              </button>
            </div>
          )}

          {error && (
            <div className="p-3 bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-lg">
              ⚠️ {error}
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Timestamp de Alarma SIEM/WAF *
              </label>
              <input
                type="datetime-local"
                step="1"
                required
                value={incidentTimeLocal}
                onChange={(e) => setIncidentTimeLocal(e.target.value)}
                className="w-full px-2.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                IP Atacante Detectada (WAF/IDS) *
              </label>
              <input
                type="text"
                required
                value={observedIp}
                onChange={(e) => setObservedIp(e.target.value)}
                placeholder="181.43.22.10"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                Activo / Host Afectado *
              </label>
              <input
                type="text"
                required
                value={targetedAsset}
                onChange={(e) => setTargetedAsset(e.target.value)}
                placeholder="api.cliente.cl"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1">
                N° Ticket Externo SOC / CSIRT <span className="font-normal text-slate-400">(Opcional)</span>
              </label>
              <input
                type="text"
                value={ticketRef}
                onChange={(e) => setTicketRef(e.target.value)}
                placeholder="Vacío = autogenerado (LEX-SOC-...)"
                className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={loading || !agreement}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-300 text-white rounded-lg text-xs font-bold shadow flex items-center gap-2 transition-colors"
            >
              <Radar className="w-4 h-4" />
              {loading
                ? 'Correlacionando con Bitácora (±2 min)...'
                : 'Ejecutar Cruce de Desconflicto SOC / ANCI'}
            </button>
          </div>
        </form>
      </div>

      {/* Resultado Inmediato del Cruce de Desconflicto */}
      {matchResult && (
        <div
          className={`rounded-xl shadow-md border-2 p-6 space-y-4 ${
            matchResult.resolution === 'CONFIRMED_AUTHORIZED'
              ? 'bg-emerald-50/90 border-emerald-400 text-emerald-950'
              : matchResult.resolution === 'INDETERMINATE'
              ? 'bg-amber-50/90 border-amber-400 text-amber-950'
              : 'bg-rose-50/95 border-rose-500 text-rose-950'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-black/10 pb-4">
            <div className="flex items-start gap-3">
              {matchResult.resolution === 'CONFIRMED_AUTHORIZED' ? (
                <ShieldCheck className="w-8 h-8 text-emerald-600 shrink-0" />
              ) : matchResult.resolution === 'INDETERMINATE' ? (
                <AlertTriangle className="w-8 h-8 text-amber-600 shrink-0" />
              ) : (
                <AlertOctagon className="w-8 h-8 text-rose-600 shrink-0 animate-bounce" />
              )}
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <DeconflictionResolutionBadge resolution={matchResult.resolution} />
                  {matchResult.time_delta_seconds !== null &&
                    matchResult.time_delta_seconds !== undefined && (
                      <span className="px-2.5 py-0.5 rounded-full bg-white/80 border border-black/10 text-xs font-mono font-bold">
                        Desfase de reloj: {matchResult.time_delta_seconds}s (
                        {matchResult.time_delta_seconds <= 120 ? '≤ 120s' : '> 120s'})
                      </span>
                    )}
                </div>
                <h4 className="text-base font-black mt-1.5">
                  {matchResult.resolution === 'CONFIRMED_AUTHORIZED'
                    ? 'DESCARTE DE INCIDENTE CONFIRMADO — NO REPORTAR A LA ANCI'
                    : matchResult.resolution === 'INDETERMINATE'
                    ? 'COINCIDENCIA PARCIAL — REQUIERE VALIDACIÓN TELEFÓNICA CON POC'
                    : '¡ALERTA DE INTRUSIÓN REAL NO AUTORIZADA! — EVALUAR REPORTE ANCI (3 HORAS)'}
                </h4>
              </div>
            </div>

            {matchResult.query?.id && (
              <button
                type="button"
                onClick={() => onLoadCertificate(matchResult.query.id)}
                className="px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-bold shadow flex items-center gap-2 shrink-0"
              >
                <FileBadge className="w-4 h-4 text-emerald-400" />
                Ver Comprobante Digital ANCI
              </button>
            )}
          </div>

          <p className="text-xs leading-relaxed font-medium">
            {matchResult.query?.justification_notes}
          </p>

          {/* Si hizo match con un registro del pentester, mostrar el detalle forense */}
          {matchResult.matched_log && (
            <div className="bg-white/90 p-4 rounded-xl border border-black/10 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900 uppercase tracking-wider text-[11px]">
                  {matchResult.resolution === 'CONFIRMED_AUTHORIZED'
                    ? 'Registro de Telemetría Correlacionado (Prueba Autorizada Art. 2° Ley 21.459)'
                    : matchResult.resolution === 'INDETERMINATE'
                    ? 'Registro de Telemetría Correlacionado (Requiere Validación Operativa con PoC)'
                    : matchResult.matched_log?.is_critical_finding
                    ? '🚨 Hallazgo Crítico Break-Glass Correlacionado (Protocolo de Emergencia Cláusula 7ª RoE)'
                    : 'Evidencia Forense Correlacionada — Exceso de Mandato / Fuera de Alcance (Art. 1° Ley 21.459)'}
                </span>
                <ActivityTypeBadge type={matchResult.matched_log.activity_type} />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 font-mono text-[11px] text-slate-700">
                <div>
                  <strong>ID Log:</strong> {matchResult.matched_log.id}
                </div>
                <div>
                  <strong>Origen → Destino:</strong> {matchResult.matched_log.source_ip} →{' '}
                  {matchResult.matched_log.target_host}
                  {matchResult.matched_log.target_port
                    ? `:${matchResult.matched_log.target_port}`
                    : ''}
                </div>
                <div>
                  <strong>Herramienta:</strong> {matchResult.matched_log.tool_or_technique}
                </div>
              </div>
              <div className="text-[11px] font-mono text-emerald-800 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200 break-all">
                <strong>SHA-256 Evidencia Log:</strong> {matchResult.matched_log.record_hash}
              </div>
            </div>
          )}

          {/* Si es tráfico malicioso no autorizado, mostrar protocolo de emergencia Ley 21.663 */}
          {matchResult.anci_report_required && (
            <div className="bg-rose-900 text-white p-4 rounded-xl space-y-2 text-xs">
              <div className="font-black text-sm flex items-center gap-2 text-rose-200">
                <ShieldAlert className="w-5 h-5 text-rose-300" />
                PROTOCOLO OBLIGATORIO LEY MARCO DE CIBERSEGURIDAD N° 21.663 (ART. 37)
              </div>
              <p className="text-rose-100 leading-relaxed">
                1. <strong>Contención Inmediata:</strong> Aísle o bloquee la IP{' '}
                <span className="font-mono font-bold underline">
                  {matchResult.query?.observed_attacker_ip}
                </span>{' '}
                en el WAF/Firewall perimetral.
                <br />
                2. <strong>Alerta Temprana a la ANCI (Máximo 3 Horas):</strong> Si la entidad califica
                como Operador de Importancia Vital (OIV) o Servicio Esencial ({meta.regulatory_classification}),
                debe emitir la alerta temprana al CSIRT Nacional / ANCI dentro de las próximas 3 horas.
              </p>
            </div>
          )}
        </div>
      )}

      {/* Historial Plegable de Consultas de Desconflicto */}
      <div className="bg-white rounded-xl shadow border border-slate-200 overflow-hidden">
        <div className="px-5 py-3.5 bg-slate-50 flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => setShowHistory((prev) => !prev)}
            className="flex items-center gap-2 text-left hover:opacity-80 transition-opacity"
          >
            <History className="w-4 h-4 text-indigo-600" />
            <h4 className="text-xs font-black text-slate-800 uppercase tracking-wider">
              Historial de Consultas de Desconflicto ({history.length})
            </h4>
            <span className="inline-flex items-center gap-1 text-xs font-bold text-indigo-700 ml-2">
              {showHistory ? (
                <>
                  Ocultar <ChevronUp className="w-4 h-4" />
                </>
              ) : (
                <>
                  Desplegar <ChevronDown className="w-4 h-4" />
                </>
              )}
            </span>
          </button>

          {history.length > 0 && onClearHistory && (
            <button
              type="button"
              onClick={() => setConfirmClearModal(true)}
              className="px-3 py-1 bg-rose-50 hover:bg-rose-100 text-rose-800 border border-rose-300 rounded-lg text-[11px] font-bold flex items-center gap-1.5 transition-colors"
              title="Limpia las consultas de prueba del motor sin borrar la Bitácora Inmutable del Pentester"
            >
              <Trash2 className="w-3.5 h-3.5 text-rose-600" />
              Resetear Historial de Pruebas
            </button>
          )}
        </div>

        {showHistory && (
          <div className="border-t border-slate-200">
            {!history.length ? (
              <div className="p-8 text-center text-xs text-slate-400">
                Aún no se han ejecutado consultas de desconflicto para este acuerdo RoE.
              </div>
            ) : (
              <div className="divide-y divide-slate-200">
                {history.map((item) => (
                  <div
                    key={item.id}
                    className="p-4 hover:bg-slate-50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <DeconflictionResolutionBadge resolution={item.resolution} short />
                        <span className="font-mono font-bold text-slate-900">
                          Ticket: {item.internal_ticket_ref || 'S/N'}
                        </span>
                        <span className="text-slate-400">|</span>
                        <span className="font-mono text-slate-700">
                          IP Observada: <strong>{item.observed_attacker_ip}</strong> →{' '}
                          <strong>{item.targeted_asset}</strong>
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-mono flex items-center gap-1.5">
                        <Clock className="w-3 h-3" />
                        Alarma SIEM: {new Date(item.incident_timestamp).toLocaleString()} | Consultada:{' '}
                        {new Date(item.created_at).toLocaleString()}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => onLoadCertificate(item.id)}
                        className="px-3 py-1.5 bg-slate-100 hover:bg-indigo-50 hover:text-indigo-800 border border-slate-300 rounded-lg font-bold text-xs flex items-center gap-1.5 transition-colors"
                      >
                        <FileBadge className="w-3.5 h-3.5 text-indigo-600" />
                        Comprobante ANCI
                      </button>
                      {onDeleteQuery && (
                        <button
                          type="button"
                          onClick={() => onDeleteQuery(item.id)}
                          className="p-1.5 bg-white hover:bg-rose-50 text-slate-400 hover:text-rose-700 border border-slate-200 hover:border-rose-300 rounded-lg transition-colors"
                          title="Eliminar esta consulta de prueba del historial"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Modal de Confirmación para Resetear el Historial de Consultas sin perder la Bitácora */}
      {confirmClearModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-300 max-w-md w-full p-6 space-y-4 text-xs text-slate-800">
            <div className="flex items-start justify-between border-b border-slate-200 pb-3">
              <div className="flex items-center gap-2 text-rose-700 font-black text-sm">
                <Trash2 className="w-5 h-5" />
                Resetear Historial de Consultas de Desconflicto
              </div>
              <button
                type="button"
                onClick={() => setConfirmClearModal(false)}
                className="p-1 text-slate-400 hover:text-slate-700"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="leading-relaxed text-slate-600">
              Esta acción limpiará las <strong>{history.length} consultas/simulaciones</strong> del
              Motor de Desconflicto para que no ensucien el Expediente Final de Cierre ANCI.
            </p>
            <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-950 font-medium">
              ✅ <strong>Resguardo Forense:</strong> La{' '}
              <strong>Bitácora de Telemetría Inmutable en Vivo</strong> (los registros sellados con
              SHA-256 del Pentester) <strong>NO se borra</strong> y permanece 100% intacta.
            </div>

            <div className="flex flex-wrap items-center justify-end gap-2 pt-2 border-t border-slate-200">
              <button
                type="button"
                onClick={() => {
                  handleExportSocBriefingJson();
                }}
                className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg font-bold flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                Respaldar JSON Primero
              </button>
              <button
                type="button"
                onClick={() => setConfirmClearModal(false)}
                className="px-3 py-2 bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 rounded-lg font-bold"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={async () => {
                  await onClearHistory();
                  setConfirmClearModal(false);
                }}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg font-bold shadow"
              >
                Confirmar Reset
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal del Comprobante Digital de Desconflicto para la ANCI */}
      {activeCertificate && (
        <div className="fixed inset-0 z-50 bg-slate-950/75 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl shadow-2xl border border-slate-300 max-w-3xl w-full p-6 space-y-5 text-slate-800 my-8">
            <div className="flex items-start justify-between border-b-2 border-slate-900 pb-4">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-widest text-indigo-600 font-bold">
                  COMPROBANTE DIGITAL DE DESCONFLICTO DE INCIDENTES (LEY N° 21.663 ANCI)
                </span>
                <h3 className="text-lg font-black text-slate-900 mt-0.5">
                  Certificado N° {activeCertificate.certificate_id}
                </h3>
                <p className="text-[11px] text-slate-500 font-mono">
                  Emitido: {new Date(activeCertificate.issued_at).toLocaleString()} (UTC)
                </p>
              </div>

              <div className="flex items-center gap-2">
                <DeconflictionResolutionBadge resolution={activeCertificate.resolution} short />
                <button
                  type="button"
                  onClick={onCloseCertificate}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Determinación Jurídica ANCI */}
            <div
              className={`p-4 rounded-xl border text-xs ${
                activeCertificate.anci_early_warning_dismissed
                  ? 'bg-emerald-50 border-emerald-300 text-emerald-950'
                  : 'bg-rose-50 border-rose-300 text-rose-950'
              }`}
            >
              <strong className="block font-black uppercase mb-1">
                Dictamen de Cumplimiento Normativo (Art. 37 Ley N° 21.663 y Art. 2° Ley N° 21.459):
              </strong>
              <p className="leading-relaxed">{activeCertificate.legal_determination}</p>
            </div>

            {/* Individualización de las Partes (con RUTs en campos separados) */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                <span className="text-[11px] font-bold uppercase text-indigo-600">
                  Entidad Mandante (Titular del Activo)
                </span>
                <p>
                  <strong>Razón Social:</strong> {activeCertificate.client_entity?.legal_name}
                </p>
                <p>
                  <strong>RUT Empresa Cliente:</strong>{' '}
                  <span className="font-mono font-semibold">
                    {activeCertificate.client_entity?.tax_id}
                  </span>
                </p>
                <p>
                  <strong>Clasificación Ley 21.663:</strong>{' '}
                  {activeCertificate.client_entity?.regulatory_classification}
                </p>
                <p>
                  <strong>Nombre Representante Legal:</strong>{' '}
                  {activeCertificate.client_entity?.legal_representative}
                </p>
                <p>
                  <strong>RUT Representante Legal Cliente / PoC:</strong>{' '}
                  <span className="font-mono font-semibold">
                    {activeCertificate.client_entity?.legal_representative_rut}
                  </span>
                </p>
                <p>
                  <strong>Nombre PoC Titular:</strong> {activeCertificate.client_entity?.poc_name}
                </p>
                <p>
                  <strong>RUT Punto de Contacto Titular:</strong>{' '}
                  <span className="font-mono font-semibold">
                    {activeCertificate.client_entity?.poc_rut}
                  </span>
                </p>
              </div>

              <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
                <span className="text-[11px] font-bold uppercase text-indigo-600">
                  Entidad Ejecutora (Equipo de Ciberseguridad)
                </span>
                <p>
                  <strong>Razón Social Consultora:</strong>{' '}
                  {activeCertificate.auditor_entity?.legal_name}
                </p>
                <p>
                  <strong>RUT Consultora:</strong>{' '}
                  <span className="font-mono font-semibold">
                    {activeCertificate.auditor_entity?.tax_id}
                  </span>
                </p>
                <p>
                  <strong>Líder Técnico (Lead Pentester):</strong>{' '}
                  {activeCertificate.auditor_entity?.lead_pentester_name}
                </p>
                <p>
                  <strong>RUT Pentester / Representante Equipo Ciberseguridad:</strong>{' '}
                  <span className="font-mono font-semibold">
                    {activeCertificate.auditor_entity?.lead_pentester_rut}
                  </span>
                </p>
                <p>
                  <strong>Contrato RoE:</strong> {activeCertificate.roe_contract_reference?.title}
                </p>
                <p>
                  <strong>Token Tráfico:</strong>{' '}
                  <span className="font-mono">
                    {activeCertificate.roe_contract_reference?.traffic_header_token}
                  </span>
                </p>
              </div>
            </div>

            {/* Datos de la Alarma vs Evidencia Correlacionada */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-3.5 bg-white rounded-xl border border-slate-200 space-y-1">
                <span className="text-[11px] font-bold uppercase text-slate-600">
                  Alarma Consultada por el SOC
                </span>
                <p>
                  <strong>Ticket Interno SOC:</strong>{' '}
                  <span className="font-mono font-bold">
                    {activeCertificate.siem_incident_queried?.internal_ticket_ref}
                  </span>
                </p>
                <p>
                  <strong>Timestamp SIEM:</strong>{' '}
                  <span className="font-mono">
                    {new Date(
                      activeCertificate.siem_incident_queried?.incident_timestamp
                    ).toISOString()}
                  </span>
                </p>
                <p>
                  <strong>IP Atacante Observada:</strong>{' '}
                  <span className="font-mono font-bold">
                    {activeCertificate.siem_incident_queried?.observed_attacker_ip}
                  </span>
                </p>
                <p>
                  <strong>Activo Afectado:</strong>{' '}
                  <span className="font-mono">
                    {activeCertificate.siem_incident_queried?.targeted_asset}
                  </span>
                </p>
              </div>

              <div className="p-3.5 bg-white rounded-xl border border-slate-200 space-y-1">
                <span
                  className={`text-[11px] font-bold uppercase ${
                    activeCertificate.anci_early_warning_dismissed
                      ? 'text-emerald-700'
                      : 'text-rose-700'
                  }`}
                >
                  {activeCertificate.anci_early_warning_dismissed
                    ? 'Registro de Auditoría Autorizado Correlacionado (±2 min)'
                    : 'Evidencia en Bitácora Correlacionada (±2 min)'}
                </span>
                {activeCertificate.matched_telemetry_log ? (
                  <>
                    <p>
                      <strong>ID Registro Log:</strong>{' '}
                      <span className="font-mono">
                        {activeCertificate.matched_telemetry_log.log_id}
                      </span>
                    </p>
                    <p>
                      <strong>Categoría:</strong>{' '}
                      {activeCertificate.matched_telemetry_log.activity_type}
                      {activeCertificate.matched_telemetry_log.is_critical_finding && (
                        <span className="ml-1.5 px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300 font-extrabold text-[10px]">
                          HALLAZGO CRÍTICO BREAK-GLASS
                        </span>
                      )}
                    </p>
                    <p>
                      <strong>Herramienta:</strong>{' '}
                      {activeCertificate.matched_telemetry_log.tool_or_technique}
                    </p>
                    <p className="break-all">
                      <strong>Hash SHA-256 Log:</strong>{' '}
                      <span className="font-mono text-[10px]">
                        {activeCertificate.matched_telemetry_log.record_sha256_hash}
                      </span>
                    </p>
                  </>
                ) : (
                  <p className="text-rose-700 font-semibold">
                    Sin coincidencia en la bitácora del auditor.
                  </p>
                )}
              </div>
            </div>

            {/* Sello Criptográfico del Comprobante */}
            <div className="p-4 bg-slate-900 text-slate-100 rounded-xl font-mono text-[11px] space-y-1.5">
              <div className="text-indigo-400 font-bold uppercase flex items-center gap-1.5">
                <Fingerprint className="w-4 h-4" />
                Sello de Integridad Criptográfica SHA-256 (Ley N° 19.799)
              </div>
              <p className="text-slate-400">
                Hash Contrato RoE:{' '}
                <span className="text-slate-200 break-all">
                  {activeCertificate.roe_contract_reference?.contract_sha256_hash || 'N/A'}
                </span>
              </p>
              <p className="text-slate-400">
                Hash Comprobante ANCI:{' '}
                <span className="text-emerald-300 font-bold break-all">
                  {activeCertificate.certificate_sha256_hash}
                </span>
              </p>
            </div>

            {/* Botones de Descarga e Impresión */}
            <div className="flex flex-wrap items-center justify-end gap-3 pt-2 border-t border-slate-200">
              <button
                type="button"
                onClick={() => window.print()}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 rounded-lg text-xs font-bold flex items-center gap-1.5"
              >
                <Printer className="w-4 h-4" />
                Imprimir / Guardar PDF
              </button>
              <button
                type="button"
                onClick={() => handleDownloadCertificateJson(activeCertificate)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold shadow flex items-center gap-1.5"
              >
                <Download className="w-4 h-4" />
                Descargar Comprobante JSON Firmado
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
