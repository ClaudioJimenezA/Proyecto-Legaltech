import React, { useEffect, useState } from 'react';
import {
  AlertOctagon,
  Clock,
  Copy,
  Check,
  Flame,
  Send,
  ShieldAlert,
  Sparkles,
  Terminal,
} from 'lucide-react';
import { LOG_ACTIVITY_CONFIG } from '../constants/loggerBadges';

const TACTICAL_PRESETS = [
  {
    id: 'nmap_recon',
    label: '1. Escaneo Nmap / Servicios',
    activityType: 'RECON_SCAN',
    port: 443,
    method: 'GET',
    endpoint: '/',
    tool: 'Nmap v7.94 (-sV -sC -Pn)',
    description:
      'Enumeración de servicios expuestos, versiones TLS y cabeceras de seguridad en activo In-Scope.',
    critical: false,
  },
  {
    id: 'api_fuzz',
    label: '2. Sondeo API / Inyección Controlada',
    activityType: 'VULN_PROBE',
    port: 443,
    method: 'POST',
    endpoint: '/api/v1/clientes/consulta',
    tool: 'Burp Suite Pro / Nuclei Template',
    description:
      'Inyección de cargas útiles de prueba no destructivas para evaluar sanitización de parámetros y controles BOLA/IDOR.',
    critical: false,
  },
  {
    id: 'auth_spray',
    label: '3. Evaluación de Autenticación',
    activityType: 'AUTH_ATTEMPT',
    port: 443,
    method: 'POST',
    endpoint: '/api/v1/auth/login',
    tool: 'Burp Intruder (Rate-Limit & Lockout Verification)',
    description:
      'Verificación de políticas de bloqueo de cuenta y resistencia ante intentos controlados de autenticación (sin causar DoS).',
    critical: false,
  },
  {
    id: 'exploit_poc',
    label: '4. Explotación PoC (Break-Glass)',
    activityType: 'EXPLOIT_POC',
    port: 443,
    method: 'POST',
    endpoint: '/api/v1/admin/export',
    tool: 'PoC Controlada SSRF / RCE No Destructivo',
    description:
      'Ejecución de prueba de concepto mínima para demostrar ejecución remota de comandos (whoami / hostname) sin extracción de datos.',
    critical: true,
  },
];

function toDatetimeLocalNow() {
  const now = new Date();
  const tzOffsetMs = now.getTimezoneOffset() * 60000;
  return new Date(now.getTime() - tzOffsetMs).toISOString().slice(0, 19);
}

export default function QuickLogForm({ agreement, onCreateLog, loading }) {
  const enrolledIps = agreement?.auditor_source_ips || ['181.43.22.10'];
  const inScopeAssets = agreement?.target_assets || ['api.cliente.cl'];
  const meta = agreement?.contract_metadata || {};

  const [sourceIp, setSourceIp] = useState(enrolledIps[0] || '');
  const [targetHost, setTargetHost] = useState(inScopeAssets[0] || '');
  const [targetPort, setTargetPort] = useState('443');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [targetEndpoint, setTargetEndpoint] = useState('/api/v1/health');
  const [activityType, setActivityType] = useState('RECON_SCAN');
  const [toolOrTechnique, setToolOrTechnique] = useState('Nmap v7.94 / HTTP Probe');
  const [description, setDescription] = useState(
    'Reconocimiento activo de puertos y huella digital de servicios web dentro del alcance autorizado.'
  );
  const [startedAtLocal, setStartedAtLocal] = useState(() => toDatetimeLocalNow());
  const [isOngoing, setIsOngoing] = useState(false);
  const [isCriticalFinding, setIsCriticalFinding] = useState(false);
  const [systemImpact, setSystemImpact] = useState('Sin degradación ni alteración de datos');

  const [formError, setFormError] = useState('');
  const [copiedHeader, setCopiedHeader] = useState(false);

  useEffect(() => {
    if (agreement) {
      setSourceIp(agreement.auditor_source_ips?.[0] || '');
      setTargetHost(agreement.target_assets?.[0] || '');
    }
  }, [agreement]);

  const applyPreset = (preset) => {
    setActivityType(preset.activityType);
    setTargetPort(String(preset.port));
    setHttpMethod(preset.method);
    setTargetEndpoint(preset.endpoint);
    setToolOrTechnique(preset.tool);
    setDescription(preset.description);
    setIsCriticalFinding(preset.critical);
    setStartedAtLocal(toDatetimeLocalNow());
  };

  const handleCopyHeader = () => {
    const snippet = `X-Assessment-Scope: ${agreement?.traffic_header_token || ''}`;
    navigator.clipboard?.writeText(snippet);
    setCopiedHeader(true);
    setTimeout(() => setCopiedHeader(false), 2000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    if (!agreement) {
      setFormError('Seleccione un acuerdo RoE activo primero.');
      return;
    }

    try {
      const startIso = startedAtLocal
        ? new Date(startedAtLocal).toISOString()
        : new Date().toISOString();

      await onCreateLog({
        agreement_id: agreement.id,
        started_at: startIso,
        ended_at: isOngoing ? null : new Date().toISOString(),
        source_ip: sourceIp.trim(),
        target_host: targetHost.trim(),
        target_port: targetPort ? Number(targetPort) : null,
        target_endpoint: targetEndpoint.trim() || null,
        http_method: httpMethod || null,
        injected_header_token: agreement.traffic_header_token,
        activity_type: activityType,
        tool_or_technique: toolOrTechnique.trim(),
        description: description.trim(),
        is_critical_finding: isCriticalFinding,
        system_impact_observed: systemImpact.trim() || null,
      });

      setStartedAtLocal(toDatetimeLocalNow());
      setIsCriticalFinding(false);
    } catch (err) {
      setFormError(err.message || 'Error al registrar evento en la bitácora.');
    }
  };

  const isContractSealed =
    agreement?.current_status === 'ACTIVE' ||
    agreement?.current_status === 'SIGNED_AND_SEALED';

  return (
    <div className="bg-white rounded-xl shadow border border-slate-200 overflow-hidden">
      {/* Cabecera tipo Terminal para el Pentester */}
      <div className="bg-slate-900 text-white px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-indigo-600 rounded-lg">
            <Terminal className="w-4 h-4 text-white" />
          </div>
          <div>
            <h3 className="text-sm font-black tracking-wide">
              Consola de Registro en Vivo (Live Assessment Logger)
            </h3>
            <p className="text-[11px] text-slate-400">
              Cada vector ejecutado se sella con SHA-256 para respaldar la eximente del Art. 2° Ley 21.459
            </p>
          </div>
        </div>

        {agreement?.traffic_header_token && (
          <button
            type="button"
            onClick={handleCopyHeader}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-[11px] font-mono text-indigo-300 flex items-center gap-1.5 transition-colors"
            title="Copiar cabecera HTTP para Burp Suite / cURL"
          >
            {copiedHeader ? (
              <Check className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
            <span>X-Assessment-Scope: {agreement.traffic_header_token}</span>
          </button>
        )}
      </div>

      {!isContractSealed && (
        <div className="m-5 p-4 bg-amber-50 border border-amber-300 rounded-xl text-amber-950 text-xs flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div>
            <strong className="block text-sm font-bold text-amber-900">
              Bloqueo Preventivo (Art. 2° Ley N° 21.459)
            </strong>
            <p className="mt-0.5">
              El acuerdo seleccionado se encuentra en estado{' '}
              <span className="font-mono font-bold">{agreement?.current_status}</span>. Para poder
              registrar y ejecutar pruebas de intrusión, el contrato debe haber completado la{' '}
              <strong>doble firma electrónica y sellado SHA-256</strong> en el Paso 1.
            </p>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="p-5 space-y-4">
        {/* Plantillas Rápidas de Vector para Agilidad en Terminal */}
        <div>
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
            Plantillas Rápidas de Telemetría (1-Clic):
          </span>
          <div className="flex flex-wrap gap-2">
            {TACTICAL_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => applyPreset(preset)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 bg-slate-50 hover:bg-indigo-50 hover:border-indigo-300 hover:text-indigo-900 transition-colors"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        {formError && (
          <div className="p-3 bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-lg font-medium">
            ⚠️ {formError}
          </div>
        )}

        {/* Fila 1: IP Origen, Activo Destino, Puerto y Timestamp */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              IP Pública Origen (Auditor) *
            </label>
            <input
              type="text"
              required
              list="enrolled-auditor-ips"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder="181.43.22.10"
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
            />
            <datalist id="enrolled-auditor-ips">
              {enrolledIps.map((ip, idx) => (
                <option key={idx} value={ip} />
              ))}
            </datalist>
            <span className="text-[10px] text-slate-400">
              Enroladas: {enrolledIps.join(', ')}
            </span>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Activo Destino (In-Scope) *
            </label>
            <input
              type="text"
              required
              list="inscope-target-assets"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              placeholder="api.cliente.cl"
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
            />
            <datalist id="inscope-target-assets">
              {inScopeAssets.map((asset, idx) => (
                <option key={idx} value={asset} />
              ))}
            </datalist>
            <span className="text-[10px] text-emerald-700 font-medium">
              Monitoreado contra In-Scope y Hard Deny List (registro forense)
            </span>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Puerto y Método HTTP
            </label>
            <div className="flex gap-1.5">
              <input
                type="number"
                min="1"
                max="65535"
                value={targetPort}
                onChange={(e) => setTargetPort(e.target.value)}
                placeholder="443"
                className="w-20 px-2.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
              />
              <select
                value={httpMethod}
                onChange={(e) => setHttpMethod(e.target.value)}
                className="flex-1 px-2.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono font-bold"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-bold text-slate-700">
                Inicio de la Prueba *
              </label>
              <button
                type="button"
                onClick={() => setStartedAtLocal(toDatetimeLocalNow())}
                className="text-[10px] text-indigo-600 font-bold hover:underline flex items-center gap-0.5"
              >
                <Clock className="w-3 h-3" /> Ahora
              </button>
            </div>
            <input
              type="datetime-local"
              step="1"
              required
              value={startedAtLocal}
              onChange={(e) => setStartedAtLocal(e.target.value)}
              className="w-full px-2.5 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
            />
          </div>
        </div>

        {/* Fila 2: Categoría, Herramienta y Endpoint */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Categoría de Actividad *
            </label>
            <select
              value={activityType}
              onChange={(e) => setActivityType(e.target.value)}
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-semibold"
            >
              {Object.entries(LOG_ACTIVITY_CONFIG).map(([key, cfg]) => (
                <option key={key} value={key}>
                  {cfg.label} ({key})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Herramienta / Técnica Ejecutada *
            </label>
            <input
              type="text"
              required
              value={toolOrTechnique}
              onChange={(e) => setToolOrTechnique(e.target.value)}
              placeholder="Ej. Burp Suite / Nmap / SQLMap --level=2"
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Endpoint URI / Ruta Específica
            </label>
            <input
              type="text"
              value={targetEndpoint}
              onChange={(e) => setTargetEndpoint(e.target.value)}
              placeholder="/api/v1/auth/login"
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs font-mono"
            />
          </div>
        </div>

        {/* Fila 3: Descripción Técnica e Impacto Observado */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="md:col-span-2">
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Descripción del Procedimiento y Vector Probado *
            </label>
            <input
              type="text"
              required
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Detalle técnico de la prueba para trazabilidad forense y desconflicto..."
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs"
            />
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">
              Impacto Observado en Sistema
            </label>
            <input
              type="text"
              value={systemImpact}
              onChange={(e) => setSystemImpact(e.target.value)}
              placeholder="Sin degradación de servicio"
              className="w-full px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-xs"
            />
          </div>
        </div>

        {/* Fila 4: Opciones Break-Glass, En Ejecución y Botón Registrar */}
        <div className="pt-2 border-t border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-xs font-semibold text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={isOngoing}
                onChange={(e) => setIsOngoing(e.target.checked)}
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span>Dejar prueba como "En Curso" (sin hora de término aún)</span>
            </label>

            <label
              className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-bold cursor-pointer transition-colors ${
                isCriticalFinding
                  ? 'bg-rose-100 border-rose-400 text-rose-900'
                  : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-rose-50'
              }`}
            >
              <input
                type="checkbox"
                checked={isCriticalFinding}
                onChange={(e) => setIsCriticalFinding(e.target.checked)}
                className="rounded border-rose-400 text-rose-600 focus:ring-rose-500"
              />
              <Flame className="w-4 h-4 text-rose-600" />
              <span>Hallazgo Crítico — Activar Protocolo Break-Glass</span>
            </label>
          </div>

          <button
            type="submit"
            disabled={loading || !isContractSealed}
            className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-300 text-white rounded-lg text-xs font-bold shadow flex items-center justify-center gap-2 shrink-0 transition-colors"
          >
            <Send className="w-4 h-4" />
            {loading ? 'Sellando Registro...' : 'Registrar y Sellar Evento (SHA-256)'}
          </button>
        </div>

        {/* Advertencia activa si marca Protocolo Break-Glass */}
        {isCriticalFinding && (
          <div className="p-3.5 bg-rose-50 border border-rose-300 rounded-xl text-rose-950 text-xs flex items-start gap-2.5">
            <AlertOctagon className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            <div>
              <strong className="font-bold text-rose-900">
                Cláusula Octava — Protocolo de Parada Inmediata (Break-Glass):
              </strong>{' '}
              Al registrar un acceso crítico (RCE, Domain Admin o exposición de datos), usted debe
              detener la explotación sobre este vector y notificar al PoC Titular (
              <strong>{meta.poc_primary_name || 'PoC Designado'}</strong> — Tel 24/7:{' '}
              <span className="font-mono font-bold">{meta.poc_primary_phone || 'N/A'}</span>) en un
              plazo máximo de <strong>{meta.break_glass_hours || 2} horas</strong>.
            </div>
          </div>
        )}
      </form>
    </div>
  );
}
