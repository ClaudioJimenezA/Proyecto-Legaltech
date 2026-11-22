import React from 'react';

/**
 * Configuración en español y cápsulas de color (Status Pills estilo RutaHogar)
 * para las actividades técnicas de la bitácora y resoluciones de desconflicto SOC/ANCI.
 */
export const LOG_ACTIVITY_CONFIG = {
  RECON_SCAN: {
    label: 'Reconocimiento / Escaneo',
    badgeClass: 'bg-sky-50 text-sky-900 border-sky-300',
    dotClass: 'bg-sky-500',
  },
  VULN_PROBE: {
    label: 'Sondeo de Vulnerabilidad',
    badgeClass: 'bg-indigo-50 text-indigo-900 border-indigo-300',
    dotClass: 'bg-indigo-500',
  },
  AUTH_ATTEMPT: {
    label: 'Prueba de Autenticación',
    badgeClass: 'bg-amber-50 text-amber-900 border-amber-300',
    dotClass: 'bg-amber-500',
  },
  EXPLOIT_POC: {
    label: 'Explotación Controlada (PoC)',
    badgeClass: 'bg-orange-50 text-orange-900 border-orange-300',
    dotClass: 'bg-orange-500',
  },
  POST_EXPLOIT_VERIF: {
    label: 'Verificación Post-Explotación',
    badgeClass: 'bg-purple-50 text-purple-900 border-purple-300',
    dotClass: 'bg-purple-500',
  },
  OTHER: {
    label: 'Otra Maniobra Técnica',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300',
    dotClass: 'bg-slate-400',
  },
};

export const DECONFLICTION_STATUS_CONFIG = {
  CONFIRMED_AUTHORIZED: {
    label: 'Tráfico Autorizado Confirmado (Eximido ANCI)',
    shortLabel: 'Autorizado (Descartar Alarma)',
    badgeClass: 'bg-emerald-50 text-emerald-900 border-emerald-300',
    dotClass: 'bg-emerald-600',
  },
  INDETERMINATE: {
    label: 'Coincidencia Parcial (Verificar con PoC)',
    shortLabel: 'Indeterminado (Validar PoC)',
    badgeClass: 'bg-amber-50 text-amber-900 border-amber-300',
    dotClass: 'bg-amber-500 animate-pulse',
  },
  UNMATCHED_SUSPICIOUS: {
    label: 'Alerta de Intrusión Real (Evaluar Reporte ANCI 3h)',
    shortLabel: 'No Autorizado / Sospechoso',
    badgeClass: 'bg-rose-50 text-rose-900 border-rose-300 font-extrabold',
    dotClass: 'bg-rose-600 animate-ping',
  },
};

export function ActivityTypeBadge({ type }) {
  const config = LOG_ACTIVITY_CONFIG[type] || {
    label: type || 'Actividad',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300',
    dotClass: 'bg-slate-400',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[11px] font-bold tracking-wide ${config.badgeClass}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${config.dotClass}`} />
      <span>{config.label}</span>
    </span>
  );
}

export function DeconflictionResolutionBadge({ resolution, short = false }) {
  const config = DECONFLICTION_STATUS_CONFIG[resolution] || {
    label: resolution || 'Sin Resolución',
    shortLabel: resolution || 'Sin Resolución',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300',
    dotClass: 'bg-slate-400',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-bold tracking-wide ${config.badgeClass}`}
    >
      <span className={`w-2 h-2 rounded-full shrink-0 ${config.dotClass}`} />
      <span>{short ? config.shortLabel : config.label}</span>
    </span>
  );
}
