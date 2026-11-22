import React from 'react';

/**
 * Configuración centralizada de estados del Acuerdo RoE (Rules of Engagement).
 * Inspirada en el sistema de cápsulas de estado (.status-pill) de RutaHogar,
 * adaptada al ciclo de vida formal y legaltech chileno (Leyes 21.459, 21.663, 21.719, 19.799).
 */
export const ROE_STATUS_CONFIG = {
  DRAFT: {
    label: 'Borrador',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300',
    dotClass: 'bg-slate-400',
    description: 'Borrador en preparación técnica por el auditor.',
  },
  UNDER_CLIENT_REVIEW: {
    label: 'En Revisión por Cliente',
    badgeClass: 'bg-amber-50 text-amber-900 border-amber-300',
    dotClass: 'bg-amber-500 animate-pulse',
    description: 'Enviado formalmente a la contraparte para revisión y firma legal.',
  },
  REVISION_REQUESTED: {
    label: 'Con Reparos del Cliente',
    badgeClass: 'bg-orange-50 text-orange-900 border-orange-300',
    dotClass: 'bg-orange-500',
    description: 'El cliente devolvió observaciones o reparos para ser subsanados.',
  },
  APPROVED_BY_CLIENT: {
    label: 'Aprobado por Cliente',
    badgeClass: 'bg-blue-50 text-blue-900 border-blue-300',
    dotClass: 'bg-blue-500',
    description: 'Firmado digitalmente por el cliente; pendiente de contra-firma y sellado.',
  },
  SIGNED_AND_SEALED: {
    label: 'Sellado Inmutable (SHA-256)',
    badgeClass: 'bg-emerald-50 text-emerald-900 border-emerald-300',
    dotClass: 'bg-emerald-600',
    description: 'Firmado por ambas partes y congelado criptográficamente con SHA-256.',
  },
  ACTIVE: {
    label: 'En Ejecución Activa',
    badgeClass: 'bg-emerald-100 text-emerald-950 border-emerald-400 font-extrabold shadow-xs',
    dotClass: 'bg-emerald-600 animate-pulse',
    description: 'Auditoría en curso dentro de la ventana temporal autorizada.',
  },
  TERMINATED: {
    label: 'Rechazado / Archivado',
    badgeClass: 'bg-rose-50 text-rose-900 border-rose-300',
    dotClass: 'bg-rose-500',
    description: 'Acuerdo terminado formalmente sin ejecución.',
  },
};

/**
 * Cápsula de estado (Status Pill) reutilizable con colores distintivos y etiquetas 100% en español.
 */
export function RoeStatusBadge({ status, size = 'md', className = '' }) {
  const config = ROE_STATUS_CONFIG[status] || {
    label: status || 'Estado no definido',
    badgeClass: 'bg-slate-100 text-slate-700 border-slate-300',
    dotClass: 'bg-slate-400',
  };

  const sizeClasses =
    size === 'sm'
      ? 'px-2.5 py-0.5 text-[11px] gap-1.5'
      : size === 'lg'
      ? 'px-4 py-1.5 text-xs gap-2'
      : 'px-3 py-1 text-xs gap-2';

  return (
    <span
      className={`inline-flex items-center rounded-full border font-bold tracking-wide transition-all ${sizeClasses} ${config.badgeClass} ${className}`}
      title={config.description}
    >
      <span className={`w-2 h-2 rounded-full shrink-0 ${config.dotClass}`} aria-hidden="true" />
      <span>{config.label}</span>
    </span>
  );
}

export default RoeStatusBadge;
