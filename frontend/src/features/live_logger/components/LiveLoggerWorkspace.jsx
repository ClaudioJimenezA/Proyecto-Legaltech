import React, { useEffect, useState } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  FileText,
  Radar,
  Shield,
  Terminal,
  X,
} from 'lucide-react';
import { RoeStatusBadge } from '../../roe_negotiation/constants/roeStatus';
import { useLiveAssessmentLogger } from '../hooks/useLiveAssessmentLogger';
import { useDeconflictionSearch } from '../hooks/useDeconflictionSearch';
import QuickLogForm from './QuickLogForm';
import TelemetryFeed from './TelemetryFeed';
import DeconflictionPanel from './DeconflictionPanel';

export default function LiveLoggerWorkspace({
  agreements = [],
  selectedAgreementId = null,
  onSelectAgreementId,
  activeRole = 'auditor',
  onBackToContract,
}) {
  const {
    logs,
    summary,
    lastBreakGlassAlert,
    clearBreakGlassAlert,
    lastScopeWarnings,
    clearScopeWarnings,
    loading: loggerLoading,
    error: loggerError,
    fetchLogs,
    createLog,
    finishLog,
  } = useLiveAssessmentLogger();

  const {
    matchResult,
    clearMatchResult,
    history,
    activeCertificate,
    closeCertificate,
    loading: deconflictionLoading,
    error: deconflictionError,
    fetchHistory,
    executeMatch,
    loadCertificate,
  } = useDeconflictionSearch();

  const [subTab, setSubTab] = useState(
    activeRole === 'auditor' ? 'pentester_console' : 'soc_deconfliction'
  );
  const [prefilledAlarm, setPrefilledAlarm] = useState(null);

  // Switch default subTab when user changes role in top header
  useEffect(() => {
    if (activeRole === 'auditor') {
      setSubTab('pentester_console');
    } else {
      setSubTab('soc_deconfliction');
    }
  }, [activeRole]);

  const activeAgreement =
    agreements.find((a) => a.id === selectedAgreementId) ||
    agreements.find(
      (a) => a.current_status === 'ACTIVE' || a.current_status === 'SIGNED_AND_SEALED'
    ) ||
    agreements[0] ||
    null;

  useEffect(() => {
    if (activeAgreement?.id) {
      fetchLogs(activeAgreement.id);
      fetchHistory(activeAgreement.id);
      clearMatchResult();
    }
  }, [activeAgreement?.id, fetchLogs, fetchHistory]);

  const handleSimulateSiemFromLog = (logEntry) => {
    setPrefilledAlarm(logEntry);
    setSubTab('soc_deconfliction');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (!agreements.length) {
    return (
      <div className="bg-white rounded-xl shadow border border-slate-200 p-12 text-center space-y-3">
        <Shield className="w-10 h-10 mx-auto text-slate-300" />
        <h3 className="text-base font-bold text-slate-800">
          No existen acuerdos RoE registrados para iniciar la Bitácora en Vivo
        </h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto">
          Primero debe redactar, aprobar y sellar con SHA-256 un Acuerdo de Reglas de Compromiso
          en el Paso 1 para habilitar el registro de pruebas y el desconflicto SOC.
        </p>
        {onBackToContract && (
          <button
            type="button"
            onClick={onBackToContract}
            className="px-4 py-2 bg-indigo-600 text-white text-xs font-bold rounded-lg hover:bg-indigo-700"
          >
            Ir al Paso 1: Crear y Sellar Contrato RoE
          </button>
        )}
      </div>
    );
  }

  const meta = activeAgreement?.contract_metadata || {};

  return (
    <div className="space-y-6">
      {/* Selector de Contrato Activo y Resumen de Contexto Legal */}
      <div className="bg-white rounded-xl shadow border border-slate-200 p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1.5 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-mono uppercase tracking-wider text-indigo-600 font-bold">
              PROYECTO EN MONITOREO (PASO 2):
            </span>
            {activeAgreement && (
              <RoeStatusBadge status={activeAgreement.current_status} size="sm" />
            )}
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-3">
            <select
              value={activeAgreement?.id || ''}
              onChange={(e) => onSelectAgreementId && onSelectAgreementId(e.target.value)}
              className="px-3 py-2 bg-slate-50 border border-slate-300 rounded-lg text-sm font-bold text-slate-900 max-w-md"
            >
              {agreements.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.title} (v{a.version}) — {a.contract_metadata?.client_legal_name || 'Cliente'}
                </option>
              ))}
            </select>

            {onBackToContract && activeAgreement && (
              <button
                type="button"
                onClick={onBackToContract}
                className="text-xs font-bold text-indigo-600 hover:underline flex items-center gap-1"
              >
                <FileText className="w-3.5 h-3.5" />
                Ver Contrato RoE Sellado →
              </button>
            )}
          </div>

          {activeAgreement && (
            <div className="text-xs text-slate-600 flex flex-wrap gap-x-4 gap-y-1 pt-1">
              <span>
                <strong>Cliente:</strong> {meta.client_legal_name}{' '}
                <span className="font-mono">({meta.client_tax_id})</span>
              </span>
              <span>
                <strong>Rep. Legal Cliente:</strong> {meta.client_rep_name} |{' '}
                <strong>RUT Rep. Legal:</strong>{' '}
                <span className="font-mono font-semibold">{meta.client_rep_rut}</span>
              </span>
              <span>
                <strong>Líder Pentester:</strong> {meta.auditor_lead_name} |{' '}
                <strong>RUT Pentester:</strong>{' '}
                <span className="font-mono font-semibold">{meta.auditor_lead_rut}</span>
              </span>
              <span>
                <strong>PoC 24/7:</strong> {meta.poc_primary_name} (
                <span className="font-mono">{meta.poc_primary_phone}</span>)
              </span>
            </div>
          )}
        </div>

        {/* Selector de Consola: Pentester vs Operador SOC */}
        <div className="flex bg-slate-100 p-1 rounded-xl border border-slate-200 self-start lg:self-center shrink-0">
          <button
            type="button"
            onClick={() => setSubTab('pentester_console')}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all ${
              subTab === 'pentester_console'
                ? 'bg-indigo-600 text-white shadow'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Terminal className="w-4 h-4" />
            Consola Pentester (Live Logger)
          </button>
          <button
            type="button"
            onClick={() => setSubTab('soc_deconfliction')}
            className={`px-3.5 py-2 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all ${
              subTab === 'soc_deconfliction'
                ? 'bg-emerald-600 text-white shadow'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Radar className="w-4 h-4" />
            Desconflicto SIEM / ANCI (PoC Cliente)
          </button>
        </div>
      </div>

      {/* Alerta Emergente Break-Glass si se acaba de registrar un hallazgo crítico */}
      {lastBreakGlassAlert && (
        <div className="p-4 bg-rose-900 text-white rounded-xl shadow-lg border-2 border-rose-400 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 text-xs">
            <AlertOctagon className="w-6 h-6 text-rose-300 shrink-0 mt-0.5 animate-pulse" />
            <div className="space-y-1">
              <strong className="text-sm font-black uppercase tracking-wide text-rose-200 block">
                🚨 {lastBreakGlassAlert.clause} ACTIVADO
              </strong>
              <p className="text-rose-100 leading-relaxed">{lastBreakGlassAlert.instruction}</p>
              <p className="font-mono text-rose-200 font-bold">
                Contacto directo PoC: {lastBreakGlassAlert.poc_contact}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={clearBreakGlassAlert}
            className="p-1 text-rose-200 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Advertencias Forenses No Bloqueantes al Registrar Eventos con Desvío de RoE */}
      {lastScopeWarnings && lastScopeWarnings.length > 0 && (
        <div
          className={`p-4 rounded-xl shadow border-2 flex items-start justify-between gap-4 text-xs ${
            lastScopeWarnings.some((w) => w.severity === 'CRITICAL')
              ? 'bg-rose-50 border-rose-400 text-rose-950'
              : 'bg-amber-50 border-amber-400 text-amber-950'
          }`}
        >
          <div className="flex items-start gap-3">
            <AlertTriangle
              className={`w-5 h-5 shrink-0 mt-0.5 ${
                lastScopeWarnings.some((w) => w.severity === 'CRITICAL')
                  ? 'text-rose-600'
                  : 'text-amber-600'
              }`}
            />
            <div className="space-y-1.5">
              <strong className="text-xs font-black uppercase tracking-wide block">
                Registro sellado en bitácora forense con alerta de cumplimiento RoE:
              </strong>
              <ul className="list-disc pl-4 space-y-1">
                {lastScopeWarnings.map((w, idx) => (
                  <li key={idx} className="leading-relaxed font-medium">
                    {w.message}
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <button
            type="button"
            onClick={clearScopeWarnings}
            className="p-1 opacity-70 hover:opacity-100"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {loggerError && (
        <div className="p-3 bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-lg">
          ⚠️ {loggerError}
        </div>
      )}

      {/* Vista 1: Consola de Registro del Pentester + Bitácora en Vivo */}
      {subTab === 'pentester_console' && (
        <div className="space-y-6">
          <QuickLogForm
            agreement={activeAgreement}
            onCreateLog={createLog}
            loading={loggerLoading}
          />

          <TelemetryFeed
            logs={logs}
            summary={summary}
            loading={loggerLoading}
            currentRole={activeRole}
            onRefresh={() => activeAgreement && fetchLogs(activeAgreement.id)}
            onFinishLog={(logId) => finishLog(logId)}
            onSimulateSiemAlarm={handleSimulateSiemFromLog}
          />
        </div>
      )}

      {/* Vista 2: Consola del Operador SOC / Desconflicto ANCI + Bitácora de Referencia */}
      {subTab === 'soc_deconfliction' && (
        <div className="space-y-6">
          <DeconflictionPanel
            agreement={activeAgreement}
            logs={logs}
            prefilledAlarm={prefilledAlarm}
            matchResult={matchResult}
            history={history}
            activeCertificate={activeCertificate}
            onExecuteMatch={executeMatch}
            onLoadCertificate={loadCertificate}
            onCloseCertificate={closeCertificate}
            loading={deconflictionLoading}
            error={deconflictionError}
          />

          <TelemetryFeed
            logs={logs}
            summary={summary}
            loading={loggerLoading}
            currentRole={activeRole}
            onRefresh={() => activeAgreement && fetchLogs(activeAgreement.id)}
            onFinishLog={(logId) => finishLog(logId)}
            onSimulateSiemAlarm={handleSimulateSiemFromLog}
          />
        </div>
      )}
    </div>
  );
}
