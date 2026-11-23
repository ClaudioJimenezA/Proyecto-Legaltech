import React, { useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Clock,
  Filter,
  Fingerprint,
  Flame,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
} from 'lucide-react';
import { ActivityTypeBadge, LOG_ACTIVITY_CONFIG } from '../constants/loggerBadges';

export default function TelemetryFeed({
  logs = [],
  summary = {},
  loading = false,
  currentRole = 'auditor',
  onRefresh,
  onFinishLog,
  onSimulateSiemAlarm,
}) {
  const [searchQuery, setSearchQuery] = useState('');
  const [activityFilter, setActivityFilter] = useState('');
  const [criticalOnly, setCriticalOnly] = useState(false);

  const filteredLogs = logs.filter((log) => {
    if (activityFilter && log.activity_type !== activityFilter) return false;
    if (criticalOnly && !log.is_critical_finding) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const targetMatch = (log.target_host || '').toLowerCase().includes(q);
      const ipMatch = (log.source_ip || '').toLowerCase().includes(q);
      const toolMatch = (log.tool_or_technique || '').toLowerCase().includes(q);
      const descMatch = (log.description || '').toLowerCase().includes(q);
      return targetMatch || ipMatch || toolMatch || descMatch;
    }
    return true;
  });

  return (
    <div className="bg-white rounded-xl shadow border border-slate-200 overflow-hidden">
      {/* Cabecera y Resumen Estadístico */}
      <div className="p-5 border-b border-slate-200 bg-slate-50 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-600" />
            Bitácora de Telemetría Inmutable en Vivo ({filteredLogs.length})
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Trazabilidad forense de vectores ejecutados con sellado SHA-256 individual por evento
          </p>
        </div>

        {/* Tarjetas de Métricas Rápidas */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <div className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 font-semibold text-slate-700">
            Total Eventos: <strong className="text-slate-900">{summary.total_logs ?? logs.length}</strong>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-amber-50 border border-amber-200 font-semibold text-amber-900">
            En Curso: <strong>{summary.ongoing_tests_count ?? 0}</strong>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-rose-50 border border-rose-200 font-semibold text-rose-900">
            Break-Glass Críticos: <strong>{summary.critical_findings_count ?? 0}</strong>
          </div>
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="p-2 bg-white border border-slate-200 rounded-lg text-slate-600 hover:text-slate-900 shadow-xs"
              title="Actualizar bitácora"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* Barra de Filtros */}
      <div className="px-5 py-3 bg-white border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrar por IP origen, host destino, herramienta o descripción..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-600">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={activityFilter}
              onChange={(e) => setActivityFilter(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-medium"
            >
              <option value="">Todas las Categorías</option>
              {Object.entries(LOG_ACTIVITY_CONFIG).map(([key, cfg]) => (
                <option key={key} value={key}>
                  {cfg.label}
                </option>
              ))}
            </select>
          </div>

          <label className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 bg-slate-50 text-xs font-semibold text-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={criticalOnly}
              onChange={(e) => setCriticalOnly(e.target.checked)}
              className="rounded border-slate-300 text-rose-600"
            />
            <span>Solo Críticos (Break-Glass)</span>
          </label>
        </div>
      </div>

      {/* Lista / Tabla de Registros */}
      {loading && !logs.length ? (
        <div className="p-10 text-center text-xs text-slate-500">
          Cargando bitácora de telemetría en vivo...
        </div>
      ) : !filteredLogs.length ? (
        <div className="p-12 text-center text-slate-500 space-y-2">
          <ShieldCheck className="w-9 h-9 mx-auto text-slate-300" />
          <p className="text-sm font-semibold text-slate-700">
            No hay eventos registrados en la bitácora con estos filtros.
          </p>
          <p className="text-xs text-slate-400">
            Utilice la consola superior para registrar una prueba técnica en tiempo real.
          </p>
        </div>
      ) : (
        <div className="divide-y divide-slate-200">
          {filteredLogs.map((log) => {
            const isOngoing = !log.ended_at;
            return (
              <div
                key={log.id}
                className={`p-4 hover:bg-slate-50/80 transition-colors space-y-2.5 ${
                  log.is_critical_finding ? 'bg-rose-50/40' : ''
                }`}
              >
                {/* Fila superior del registro */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <ActivityTypeBadge type={log.activity_type} />

                    {isOngoing ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border bg-amber-50 text-amber-900 border-amber-300 text-[11px] font-bold">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse" />
                        Prueba en Curso
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border bg-emerald-50 text-emerald-900 border-emerald-300 text-[11px] font-bold">
                        <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                        Completada
                      </span>
                    )}

                    {log.is_critical_finding && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full border bg-rose-100 text-rose-900 border-rose-400 text-[11px] font-extrabold">
                        <Flame className="w-3 h-3 text-rose-600" />
                        HALLAZGO CRÍTICO (BREAK-GLASS)
                      </span>
                    )}

                    <span className="text-xs font-bold text-slate-900">
                      {log.tool_or_technique}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-slate-500 font-mono">
                    <Clock className="w-3.5 h-3.5 text-indigo-500" />
                    <span>
                      Inicio: <strong>{new Date(log.started_at).toLocaleString()}</strong> (UTC:{' '}
                      {new Date(log.started_at).toISOString().slice(11, 19)}Z)
                    </span>
                  </div>
                </div>

                {/* Fila media: Flujo de Red Origen -> Destino */}
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono bg-slate-100/90 px-3 py-2 rounded-lg border border-slate-200">
                  <span className="text-slate-500 font-sans font-semibold">Origen Auditor:</span>
                  <span className="px-2 py-0.5 bg-white border border-slate-300 rounded font-bold text-indigo-900">
                    {log.source_ip}
                  </span>
                  <span className="text-slate-400 font-bold">→</span>
                  <span className="text-slate-500 font-sans font-semibold">Destino:</span>
                  <span className="px-2 py-0.5 bg-white border border-emerald-300 rounded font-bold text-emerald-950">
                    {log.target_host}
                    {log.target_port ? `:${log.target_port}` : ''}
                  </span>
                  {log.http_method && (
                    <span className="px-2 py-0.5 bg-indigo-100 text-indigo-900 rounded font-bold">
                      {log.http_method}
                    </span>
                  )}
                  {log.target_endpoint && (
                    <span className="text-slate-700 break-all">{log.target_endpoint}</span>
                  )}
                </div>

                {/* Descripción e Impacto */}
                <p className="text-xs text-slate-700 leading-relaxed">{log.description}</p>

                {/* Fila inferior: Hash SHA-256 y Acciones Rápidas */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1 text-[11px]">
                  <div className="flex flex-wrap items-center gap-3 text-slate-500 font-mono">
                    <span className="flex items-center gap-1" title="Digest SHA-256 del registro">
                      <Fingerprint className="w-3.5 h-3.5 text-emerald-600" />
                      SHA-256:{' '}
                      <strong className="text-slate-700">
                        {(log.record_hash || '').slice(0, 20)}...
                      </strong>
                    </span>
                    {log.injected_header_token && (
                      <span>
                        Header: <strong className="text-indigo-700">{log.injected_header_token}</strong>
                      </span>
                    )}
                    {log.system_impact_observed && (
                      <span className="font-sans">
                        Impacto: <strong>{log.system_impact_observed}</strong>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    {isOngoing && currentRole === 'auditor' && onFinishLog && (
                      <button
                        type="button"
                        onClick={() => onFinishLog(log.id)}
                        className="px-2.5 py-1 bg-amber-600 hover:bg-amber-700 text-white rounded-md font-bold text-[11px] transition-colors"
                      >
                        Marcar Término Ahora
                      </button>
                    )}

                    {onSimulateSiemAlarm && (
                      <button
                        type="button"
                        onClick={() => onSimulateSiemAlarm(log)}
                        className="px-2.5 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-800 border border-indigo-200 rounded-md font-bold text-[11px] flex items-center gap-1 transition-colors"
                        title="Cargar este evento en el Motor de Desconflicto SOC para verificar cruce ±2 min"
                      >
                        <Radar className="w-3.5 h-3.5 text-indigo-600" />
                        Comprobar Cruce en Motor de Desconflicto (±2 min)
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
