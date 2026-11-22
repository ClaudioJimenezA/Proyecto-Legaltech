import React, { useState } from 'react';
import { generateScopeToken } from '../../../lib/crypto_utils';
import {
  validateAuditorSourceIps,
  validateScopeList,
} from '../../../lib/network_validators';
import {
  AlertCircle,
  Building2,
  MessageSquareWarning,
  PhoneCall,
  Plus,
  Shield,
  Sliders,
  Trash2,
  UserCheck,
} from 'lucide-react';

function toDatetimeLocal(isoString, fallbackOffsetDays = 0) {
  const date = isoString
    ? new Date(isoString)
    : new Date(Date.now() + fallbackOffsetDays * 24 * 60 * 60 * 1000);
  return date.toISOString().slice(0, 16);
}

export default function ScopeEditor({ initialAgreement = null, onSaved, onCancel }) {
  const isEditing = Boolean(initialAgreement?.id);
  const initialMeta = initialAgreement?.contract_metadata || {};

  const [title, setTitle] = useState(
    initialAgreement?.title || 'Auditoría Web & API Red Team Q4 2026'
  );
  const [executionStart, setExecutionStart] = useState(() =>
    toDatetimeLocal(initialAgreement?.execution_start, 0)
  );
  const [executionEnd, setExecutionEnd] = useState(() =>
    toDatetimeLocal(initialAgreement?.execution_end, 7)
  );
  const [token, setToken] = useState(
    () => initialAgreement?.traffic_header_token || generateScopeToken()
  );

  // 1. Datos Empresa Cliente (Mandante)
  const [clientLegalName, setClientLegalName] = useState(
    initialMeta.client_legal_name || 'Banco Financiero Austral S.A.'
  );
  const [clientTaxId, setClientTaxId] = useState(
    initialMeta.client_tax_id || '76.543.210-K'
  );
  const [regulatoryClassification, setRegulatoryClassification] = useState(
    initialMeta.regulatory_classification || 'Operador de Importancia Vital (OIV - Ley 21.663)'
  );
  const [clientAddress, setClientAddress] = useState(
    initialMeta.client_address || 'Av. Apoquindo 4500, Piso 18, Las Condes, Santiago'
  );
  const [clientRepName, setClientRepName] = useState(
    initialMeta.client_rep_name || 'Roberto Domínguez Vial'
  );
  const [clientRepRut, setClientRepRut] = useState(
    initialMeta.client_rep_rut || '12.345.678-5'
  );
  const [clientRepPersoneria, setClientRepPersoneria] = useState(
    initialMeta.client_rep_personeria ||
      'Escritura pública de fecha 14 de marzo de 2024, otorgada en la 18ª Notaría de Santiago de don Evaldo Rehbein Utreras'
  );

  // 2. Datos Consultora Auditora (Ejecutora)
  const [auditorLegalName, setAuditorLegalName] = useState(
    initialMeta.auditor_legal_name || 'LexPloit Offensive Security SpA'
  );
  const [auditorTaxId, setAuditorTaxId] = useState(
    initialMeta.auditor_tax_id || '77.889.900-1'
  );
  const [auditorAddress, setAuditorAddress] = useState(
    initialMeta.auditor_address || 'Av. Providencia 1208, Of. 804, Providencia, Santiago'
  );
  const [auditorLeadName, setAuditorLeadName] = useState(
    initialMeta.auditor_lead_name || 'Víctor Contreras Muñoz'
  );
  const [auditorLeadRut, setAuditorLeadRut] = useState(
    initialMeta.auditor_lead_rut || '15.432.109-8'
  );
  const [auditorRepPersoneria, setAuditorRepPersoneria] = useState(
    initialMeta.auditor_rep_personeria ||
      'Escritura pública de fecha 22 de enero de 2025, otorgada en la 27ª Notaría de Santiago de doña Nancy de la Fuente Hernández'
  );

  // 3. Punto de Contacto Titular (PoC Principal)
  const [pocPrimaryName, setPocPrimaryName] = useState(
    initialMeta.poc_primary_name || 'Carolina Morales Soto'
  );
  const [pocPrimaryRut, setPocPrimaryRut] = useState(
    initialMeta.poc_primary_rut || '16.789.012-3'
  );
  const [pocPrimaryRole, setPocPrimaryRole] = useState(
    initialMeta.poc_primary_role || 'CISO / Oficial de Seguridad de la Información'
  );
  const [pocPrimaryPhone, setPocPrimaryPhone] = useState(
    initialMeta.poc_primary_phone || '+56 9 8765 4321'
  );
  const [pocPrimaryEmail, setPocPrimaryEmail] = useState(
    initialMeta.poc_primary_email || 'c.morales@bancoaustral.cl'
  );

  // 4. Punto de Contacto Suplente (PoC Secundario)
  const [pocSecondaryName, setPocSecondaryName] = useState(
    initialMeta.poc_secondary_name ?? 'Felipe Rojas Arancibia'
  );
  const [pocSecondaryRole, setPocSecondaryRole] = useState(
    initialMeta.poc_secondary_role ?? 'Subgerente de Infraestructura y SOC'
  );
  const [pocSecondaryPhone, setPocSecondaryPhone] = useState(
    initialMeta.poc_secondary_phone ?? '+56 9 9123 4567'
  );
  const [pocSecondaryEmail, setPocSecondaryEmail] = useState(
    initialMeta.poc_secondary_email ?? 'f.rojas@bancoaustral.cl'
  );

  // 5. Parametros Operativos y Legales
  const [testingModality, setTestingModality] = useState(
    initialMeta.testing_modality || 'Gray-Box (Caja Gris)'
  );
  const [allowedTimeWindow, setAllowedTimeWindow] = useState(
    initialMeta.allowed_time_window || 'Lunes a Viernes de 22:00 a 06:00 hrs (UTC-3 / Chile)'
  );
  const [cloudProviders, setCloudProviders] = useState(
    initialMeta.cloud_providers || 'AWS (us-east-1), Cloudflare Enterprise'
  );
  const [breakGlassHours, setBreakGlassHours] = useState(
    initialMeta.break_glass_hours || 2
  );
  const [dataPurgeDays, setDataPurgeDays] = useState(
    initialMeta.data_purge_days || 14
  );

  // 5.1. Acuerdo de Confidencialidad Bilateral (NDA), Cláusula Penal en UF y Estándar EPC Chile
  const [ndaEnabled, setNdaEnabled] = useState(initialMeta.nda_enabled ?? true);
  const [ndaDurationYears, setNdaDurationYears] = useState(
    initialMeta.nda_duration_years ?? 3
  );
  const [ndaSurvivalYears, setNdaSurvivalYears] = useState(
    initialMeta.nda_survival_years ?? 2
  );
  const [ndaPenaltyUf, setNdaPenaltyUf] = useState(
    initialMeta.nda_penalty_uf ?? 500
  );
  const [ndaCustomTerms, setNdaCustomTerms] = useState(
    initialMeta.nda_custom_terms ||
      'Ambas Partes actuarán recíprocamente como Sociedad Emisora y Sociedad Receptora de Información Confidencial. Tendrá carácter de Información Confidencial toda arquitectura de red, código fuente, credenciales, vulnerabilidades zero-day o CVSS identificadas, bitácoras de telemetría, datos personales (Ley N° 21.719) y secretos comerciales. La Sociedad Receptora limitará el acceso exclusivamente al Personal Clave que haya suscrito acuerdos individuales de reserva, respondiendo solidariamente por cualquier filtración imputable a sus dependientes o asesores.'
  );
  const [liabilityCapPct, setLiabilityCapPct] = useState(
    initialMeta.liability_cap_pct ?? 30
  );
  const [disputeResolutionSeat, setDisputeResolutionSeat] = useState(
    initialMeta.dispute_resolution_seat ||
      'Centro de Arbitraje y Mediación (CAM) de la Cámara de Comercio de Santiago A.G. (Árbitro Mixto)'
  );

  // 5.2. Cláusulas Especiales / Adicionales y Texto Libre para Sugerencias del Cliente
  const [customClauses, setCustomClauses] = useState(
    initialMeta.custom_clauses || []
  );
  const [additionalStipulations, setAdditionalStipulations] = useState(
    initialMeta.additional_stipulations || ''
  );

  const addCustomClause = (preset = null) => {
    const nextIdx = customClauses.length + 1;
    const newClause = preset || {
      id: `clause-${Date.now()}`,
      title: `Cláusula Especial Adicional N° ${nextIdx}`,
      content:
        'A solicitud del Cliente, el equipo auditor acuerda aplicar las siguientes condiciones operativas específicas durante la vigencia de las pruebas...',
    };
    setCustomClauses((prev) => [...prev, { ...newClause, id: `clause-${Date.now()}-${nextIdx}` }]);
  };

  const updateCustomClause = (index, field, value) => {
    setCustomClauses((prev) =>
      prev.map((item, idx) => (idx === index ? { ...item, [field]: value } : item))
    );
  };

  const removeCustomClause = (index) => {
    setCustomClauses((prev) => prev.filter((_, idx) => idx !== index));
  };

  // 6. Activos e IPs
  const [targetInput, setTargetInput] = useState('');
  const [targetAssets, setTargetAssets] = useState(
    initialAgreement?.target_assets || ['api.bancoaustral.cl', '200.10.20.0/24']
  );

  const [excludedInput, setExcludedInput] = useState('');
  const [excludedAssets, setExcludedAssets] = useState(
    initialAgreement?.excluded_assets || ['core-swift.bancoaustral.cl']
  );

  const [ipInput, setIpInput] = useState('');
  const [sourceIps, setSourceIps] = useState(
    initialAgreement?.auditor_source_ips || ['200.54.12.8']
  );

  const [backupConfirmed, setBackupConfirmed] = useState(
    initialAgreement?.backup_confirmed ?? true
  );
  const [cloudConfirmed, setCloudConfirmed] = useState(
    initialAgreement?.cloud_authorization_confirmed ?? true
  );
  const [allowStateDomains, setAllowStateDomains] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  const scopeValidation = validateScopeList(targetAssets, excludedAssets, allowStateDomains);
  const ipValidation = validateAuditorSourceIps(sourceIps);

  const addItem = (input, setInput, setList) => {
    if (!input.trim()) return;
    setList((prev) => [...new Set([...prev, input.trim()])]);
    setInput('');
  };

  const removeItem = (index, setList) => {
    setList((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');

    if (!title || !clientLegalName || !clientTaxId || !pocPrimaryName || !pocPrimaryEmail) {
      setFormError('Complete los datos obligatorios del Cliente, Representante y Punto de Contacto.');
      return;
    }

    if (!scopeValidation.isValid) {
      setFormError(scopeValidation.errors.join(' '));
      return;
    }

    if (!ipValidation.isValid) {
      setFormError(ipValidation.errors.join(' '));
      return;
    }

    setSubmitting(true);
    try {
      const payload = {
        title,
        execution_start: new Date(executionStart).toISOString(),
        execution_end: new Date(executionEnd).toISOString(),
        target_assets: targetAssets,
        excluded_assets: excludedAssets,
        auditor_source_ips: sourceIps,
        traffic_header_token: token,
        backup_confirmed: backupConfirmed,
        cloud_authorization_confirmed: cloudConfirmed,
        allow_state_domains: allowStateDomains,
        contract_metadata: {
          client_legal_name: clientLegalName,
          client_tax_id: clientTaxId,
          regulatory_classification: regulatoryClassification,
          client_address: clientAddress,
          client_rep_name: clientRepName,
          client_rep_rut: clientRepRut,
          client_rep_personeria: clientRepPersoneria,
          auditor_legal_name: auditorLegalName,
          auditor_tax_id: auditorTaxId,
          auditor_address: auditorAddress,
          auditor_lead_name: auditorLeadName,
          auditor_lead_rut: auditorLeadRut,
          auditor_rep_personeria: auditorRepPersoneria,
          poc_primary_name: pocPrimaryName,
          poc_primary_rut: pocPrimaryRut,
          poc_primary_role: pocPrimaryRole,
          poc_primary_phone: pocPrimaryPhone,
          poc_primary_email: pocPrimaryEmail,
          poc_secondary_name: pocSecondaryName,
          poc_secondary_role: pocSecondaryRole,
          poc_secondary_phone: pocSecondaryPhone,
          poc_secondary_email: pocSecondaryEmail,
          testing_modality: testingModality,
          allowed_time_window: allowedTimeWindow,
          cloud_providers: cloudProviders,
          break_glass_hours: Number(breakGlassHours) || 2,
          data_purge_days: Number(dataPurgeDays) || 14,
          nda_enabled: Boolean(ndaEnabled),
          nda_duration_years: Number(ndaDurationYears) || 3,
          nda_survival_years: Number(ndaSurvivalYears) || 2,
          nda_penalty_uf: Number(ndaPenaltyUf) || 500,
          nda_custom_terms: ndaCustomTerms,
          liability_cap_pct: Number(liabilityCapPct) || 30,
          dispute_resolution_seat: disputeResolutionSeat,
          custom_clauses: customClauses.filter(
            (c) => c.title?.trim() && c.content?.trim()
          ),
          additional_stipulations: additionalStipulations,
        },
      };
      await onSaved(payload);
    } catch (err) {
      setFormError(err.message || 'Error al guardar la propuesta de RoE.');
    } finally {
      setSubmitting(false);
    }
  };

  const revisionHistory = initialMeta.revision_history || [];

  return (
    <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-6 max-w-5xl mx-auto my-6 text-slate-800">
      <div className="flex items-center justify-between border-b border-slate-200 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-indigo-50 text-indigo-600 rounded-lg">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900">
              {isEditing
                ? `Editar Contrato RoE (v${initialAgreement.version}): ${initialAgreement.title}`
                : 'Formulación de Contrato de Reglas de Compromiso (RoE v2.0 Chile)'}
            </h2>
            <p className="text-xs text-slate-500">
              Instrumento jurídico-técnico bajo Ley N° 21.459 (Art. 2°), Ley N° 21.663 (ANCI), Ley N° 21.719 y Ley N° 19.799
            </p>
          </div>
        </div>
      </div>

      {/* Historial de Reparos del Cliente si se esta editando */}
      {revisionHistory.length > 0 && (
        <div className="mb-6 p-4 bg-orange-50 border border-orange-300 rounded-lg text-orange-900 text-xs space-y-2">
          <div className="font-bold flex items-center gap-2 text-sm">
            <MessageSquareWarning className="w-5 h-5 text-orange-600" />
            Observaciones y Reparos Solicitados por el Cliente:
          </div>
          {revisionHistory.map((rev, idx) => (
            <div key={idx} className="bg-white/80 p-2.5 rounded border border-orange-200">
              <span className="font-bold">Versión v{rev.version} ({rev.requested_by}):</span>{' '}
              <span>{rev.observations}</span>
            </div>
          ))}
        </div>
      )}

      {formError && (
        <div className="mb-6 p-4 bg-rose-50 border border-rose-200 rounded-lg text-rose-700 text-sm flex items-start gap-2">
          <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <span>{formError}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* Titulo general */}
        <div>
          <label className="block text-xs font-bold uppercase tracking-wider text-slate-600 mb-1">
            Título Oficial del Acuerdo / Auditoría *
          </label>
          <input
            type="text"
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 text-sm font-semibold"
          />
        </div>

        {/* SECCIÓN 1: Comparecencia Entidad Mandante (Cliente) */}
        <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-2">
            <Building2 className="w-4 h-4 text-indigo-600" />
            1. Individualización de la Entidad Mandante (Empresa Cliente)
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Razón Social Empresa Cliente *
              </label>
              <input
                type="text"
                required
                value={clientLegalName}
                onChange={(e) => setClientLegalName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                RUT Empresa Cliente *
              </label>
              <input
                type="text"
                required
                placeholder="76.543.210-K"
                value={clientTaxId}
                onChange={(e) => setClientTaxId(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Clasificación Ley N° 21.663 (ANCI) *
              </label>
              <select
                value={regulatoryClassification}
                onChange={(e) => setRegulatoryClassification(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              >
                <option value="Operador de Importancia Vital (OIV - Ley 21.663)">
                  Operador de Importancia Vital (OIV)
                </option>
                <option value="Prestador de Servicio Esencial (SE - Ley 21.663)">
                  Prestador de Servicio Esencial (SE)
                </option>
                <option value="Empresa Privada Bajo Régimen General">
                  Empresa Privada (Régimen General)
                </option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Domicilio Legal Cliente *
              </label>
              <input
                type="text"
                required
                value={clientAddress}
                onChange={(e) => setClientAddress(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Nombre Representante Legal Cliente *
              </label>
              <input
                type="text"
                required
                value={clientRepName}
                onChange={(e) => setClientRepName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                RUT Representante Legal Cliente / PoC *
              </label>
              <input
                type="text"
                required
                placeholder="12.345.678-5"
                value={clientRepRut}
                onChange={(e) => setClientRepRut(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Personería Legal del Representante Cliente (Escritura Pública, Decreto de Nombramiento o Certificado RES) *
              </label>
              <input
                type="text"
                required
                value={clientRepPersoneria}
                onChange={(e) => setClientRepPersoneria(e.target.value)}
                placeholder="Ej: Escritura pública en Notaría de Santiago..., Decreto Supremo de Nombramiento N°..., o Certificado de Poderes RES"
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
          </div>
        </div>

        {/* SECCIÓN 2: Comparecencia Entidad Ejecutora (Consultora Auditora) */}
        <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-2">
            <UserCheck className="w-4 h-4 text-indigo-600" />
            2. Individualización de la Entidad Ejecutora (Consultora Auditora y Líder Técnico)
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Razón Social Consultora Auditora *
              </label>
              <input
                type="text"
                required
                value={auditorLegalName}
                onChange={(e) => setAuditorLegalName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                RUT Consultora Auditora *
              </label>
              <input
                type="text"
                required
                value={auditorTaxId}
                onChange={(e) => setAuditorTaxId(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Domicilio Legal Consultora *
              </label>
              <input
                type="text"
                required
                value={auditorAddress}
                onChange={(e) => setAuditorAddress(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Nombre Líder Técnico / Pentester Responsable *
              </label>
              <input
                type="text"
                required
                value={auditorLeadName}
                onChange={(e) => setAuditorLeadName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                RUT Pentester / Representante Equipo de Ciberseguridad *
              </label>
              <input
                type="text"
                required
                value={auditorLeadRut}
                onChange={(e) => setAuditorLeadRut(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div className="md:col-span-3">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Personería Legal del Representante Consultora Auditora (Escritura Pública o Certificado RES) *
              </label>
              <input
                type="text"
                required
                value={auditorRepPersoneria}
                onChange={(e) => setAuditorRepPersoneria(e.target.value)}
                placeholder="Ej: Escritura pública en Notaría de Santiago..., o Certificado de Estatuto Actualizado RES"
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
          </div>
        </div>

        {/* SECCIÓN 3: Puntos de Contacto Exclusivos (PoC) — Reserva Operativa */}
        <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-2">
            <PhoneCall className="w-4 h-4 text-indigo-600" />
            3. Puntos de Contacto Exclusivos (PoC) y Reserva Operativa (Sin Aviso a TI/Infraestructura)
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Nombre PoC Titular *
              </label>
              <input
                type="text"
                required
                value={pocPrimaryName}
                onChange={(e) => setPocPrimaryName(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                RUT Punto de Contacto Titular (PoC) *
              </label>
              <input
                type="text"
                required
                value={pocPrimaryRut}
                onChange={(e) => setPocPrimaryRut(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Cargo Corporativo PoC Titular *
              </label>
              <input
                type="text"
                required
                value={pocPrimaryRole}
                onChange={(e) => setPocPrimaryRole(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Teléfono Emergencia 24/7 PoC Titular *
              </label>
              <input
                type="text"
                required
                placeholder="+56 9 8765 4321"
                value={pocPrimaryPhone}
                onChange={(e) => setPocPrimaryPhone(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Correo Electrónico Corporativo PoC Titular *
              </label>
              <input
                type="email"
                required
                value={pocPrimaryEmail}
                onChange={(e) => setPocPrimaryEmail(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
          </div>

          <div className="pt-3 border-t border-slate-200 grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                Nombre PoC Suplente (Respaldo)
              </label>
              <input
                type="text"
                value={pocSecondaryName}
                onChange={(e) => setPocSecondaryName(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                Cargo PoC Suplente
              </label>
              <input
                type="text"
                value={pocSecondaryRole}
                onChange={(e) => setPocSecondaryRole(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                Teléfono 24/7 Suplente
              </label>
              <input
                type="text"
                value={pocSecondaryPhone}
                onChange={(e) => setPocSecondaryPhone(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">
                Email PoC Suplente
              </label>
              <input
                type="email"
                value={pocSecondaryEmail}
                onChange={(e) => setPocSecondaryEmail(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>
          </div>
        </div>

        {/* SECCIÓN 4: Parámetros Técnicos, Ventana Temporal y Protocolos */}
        <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-2">
            <Sliders className="w-4 h-4 text-indigo-600" />
            4. Modalidad Técnica, Ventana Temporal, Break-Glass y Purga Ley N° 21.719
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Modalidad de Evaluación *
              </label>
              <select
                value={testingModality}
                onChange={(e) => setTestingModality(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              >
                <option value="Black-Box (Caja Negra - Sin información previa)">
                  Black-Box (Caja Negra)
                </option>
                <option value="Gray-Box (Caja Gris - Credenciales/Arquitectura parcial)">
                  Gray-Box (Caja Gris)
                </option>
                <option value="White-Box (Caja Blanca - Acceso completo/Código)">
                  White-Box (Caja Blanca)
                </option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Inicio Ventana Autorizada *
              </label>
              <input
                type="datetime-local"
                required
                value={executionStart}
                onChange={(e) => setExecutionStart(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Término Ventana Autorizada *
              </label>
              <input
                type="datetime-local"
                required
                value={executionEnd}
                onChange={(e) => setExecutionEnd(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Franja Horaria Operativa Permitida *
              </label>
              <input
                type="text"
                required
                value={allowedTimeWindow}
                onChange={(e) => setAllowedTimeWindow(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Proveedores Cloud / Hosting (Cláusula 2.2)
              </label>
              <input
                type="text"
                value={cloudProviders}
                onChange={(e) => setCloudProviders(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Alerta Crítica Break-Glass (Horas máx.)
              </label>
              <input
                type="number"
                min={1}
                max={24}
                value={breakGlassHours}
                onChange={(e) => setBreakGlassHours(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Plazo Purga Evidencias Ley 21.719 (Días hábiles)
              </label>
              <input
                type="number"
                min={1}
                max={90}
                value={dataPurgeDays}
                onChange={(e) => setDataPurgeDays(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-semibold text-slate-700">
                  Header X-Assessment-Scope
                </label>
                <button
                  type="button"
                  onClick={() => setToken(generateScopeToken())}
                  className="text-[11px] text-indigo-600 hover:underline font-bold"
                >
                  Regenerar
                </button>
              </div>
              <input
                type="text"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg font-mono text-xs font-bold"
              />
            </div>
          </div>
        </div>

        {/* SECCIÓN 5: Alcance Técnico (Activos In-Scope, Out-of-Scope e IPs) */}
        <div className="space-y-5">
          {/* In-Scope */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-slate-700">
              Activos Autorizados (In-Scope: FQDN, IPs o CIDRs — Sin restricción previa de puertos) *
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Ej: api.bancoaustral.cl, *.portal.cl, 200.10.20.0/24"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addItem(targetInput, setTargetInput, setTargetAssets);
                  }
                }}
                className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm"
              />
              <button
                type="button"
                onClick={() => addItem(targetInput, setTargetInput, setTargetAssets)}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 flex items-center gap-1"
              >
                <Plus className="w-4 h-4" /> Agregar In-Scope
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {targetAssets.map((asset, idx) => (
                <span
                  key={idx}
                  className="inline-flex items-center gap-1.5 px-3 py-1 bg-indigo-50 text-indigo-800 border border-indigo-200 rounded-full text-xs font-mono font-medium"
                >
                  {asset}
                  <button
                    type="button"
                    onClick={() => removeItem(idx, setTargetAssets)}
                    className="hover:text-rose-600"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </span>
              ))}
            </div>
            {scopeValidation.errors.length > 0 && (
              <div className="text-xs text-rose-600 space-y-0.5">
                {scopeValidation.errors.map((err, i) => (
                  <p key={i}>⚠️ {err}</p>
                ))}
              </div>
            )}
          </div>

          {/* Out-of-Scope */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-slate-700">
              Activos Excluidos Expresamente (Out-of-Scope / Hard Deny List)
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Ej: core-swift.bancoaustral.cl, 190.98.10.5"
                value={excludedInput}
                onChange={(e) => setExcludedInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addItem(excludedInput, setExcludedInput, setExcludedAssets);
                  }
                }}
                className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm"
              />
              <button
                type="button"
                onClick={() => addItem(excludedInput, setExcludedInput, setExcludedAssets)}
                className="px-4 py-2 bg-slate-600 text-white rounded-lg text-xs font-bold hover:bg-slate-700 flex items-center gap-1"
              >
                <Plus className="w-4 h-4" /> Agregar Excluido
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {excludedAssets.map((asset, idx) => (
                <span
                  key={idx}
                  className="inline-flex items-center gap-1.5 px-3 py-1 bg-rose-50 text-rose-800 border border-rose-200 rounded-full text-xs font-mono font-medium"
                >
                  {asset}
                  <button
                    type="button"
                    onClick={() => removeItem(idx, setExcludedAssets)}
                    className="hover:text-rose-900"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* Auditor Source IPs */}
          <div className="space-y-2">
            <label className="block text-sm font-semibold text-slate-700">
              Direcciones IP Públicas Fijas de Salida del Auditor *
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Ej: 200.54.12.8"
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addItem(ipInput, setIpInput, setSourceIps);
                  }
                }}
                className="flex-1 px-3 py-2 border border-slate-300 rounded-lg text-sm font-mono"
              />
              <button
                type="button"
                onClick={() => addItem(ipInput, setIpInput, setSourceIps)}
                className="px-4 py-2 bg-emerald-600 text-white rounded-lg text-xs font-bold hover:bg-emerald-700 flex items-center gap-1"
              >
                <Plus className="w-4 h-4" /> Enrolar IP
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {sourceIps.map((ip, idx) => (
                <span
                  key={idx}
                  className="inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-50 text-emerald-800 border border-emerald-200 rounded-full text-xs font-mono font-medium"
                >
                  {ip}
                  <button
                    type="button"
                    onClick={() => removeItem(idx, setSourceIps)}
                    className="hover:text-emerald-950"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </span>
              ))}
            </div>
            {ipValidation.errors.length > 0 && (
              <p className="text-xs text-rose-600">⚠️ {ipValidation.errors.join(' ')}</p>
            )}
          </div>
        </div>

        {/* SECCIÓN 6: Acuerdo de Confidencialidad Bilateral (NDA), Cláusula Penal en UF y Estándar EPC Chile */}
        <div className="bg-slate-50 p-5 rounded-xl border border-slate-200 space-y-4">
          <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-2">
            <Shield className="w-4 h-4 text-indigo-600" />
            6. Acuerdo de Confidencialidad Bilateral (NDA), Cláusula Penal en UF y Gobernanza EPC Chile
          </h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Vigencia del NDA (Años) *
              </label>
              <input
                type="number"
                min="1"
                max="20"
                value={ndaDurationYears}
                onChange={(e) => setNdaDurationYears(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Supervivencia Post-Término (Años) *
              </label>
              <input
                type="number"
                min="1"
                max="10"
                value={ndaSurvivalYears}
                onChange={(e) => setNdaSurvivalYears(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Cláusula Penal Incumplimiento NDA (UF) *
              </label>
              <input
                type="number"
                min="0"
                max="100000"
                value={ndaPenaltyUf}
                onChange={(e) => setNdaPenaltyUf(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono font-bold text-indigo-900"
              />
              <span className="text-[10px] text-slate-500">
                Avaluación anticipada Art. 1535 Código Civil
              </span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Tope Responsabilidad EPC (% Contrato) *
              </label>
              <input
                type="number"
                min="5"
                max="100"
                value={liabilityCapPct}
                onChange={(e) => setLiabilityCapPct(e.target.value)}
                className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Sede de Resolución de Controversias y Arbitraje (Estándar EPC Cláusula 23 / NDA Cláusula 9) *
            </label>
            <input
              type="text"
              value={disputeResolutionSeat}
              onChange={(e) => setDisputeResolutionSeat(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Texto Editable de la Cláusula de Confidencialidad Bilateral (Both-Ways NDA) *
            </label>
            <textarea
              rows={3}
              value={ndaCustomTerms}
              onChange={(e) => setNdaCustomTerms(e.target.value)}
              className="w-full px-3 py-2 bg-white border border-slate-300 rounded-lg text-xs leading-relaxed"
            />
          </div>
        </div>

        {/* SECCIÓN 7: Cláusulas Especiales / Adicionales y Edición de Texto para Sugerencias del Cliente */}
        <div className="bg-indigo-50/60 p-5 rounded-xl border border-indigo-200 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-indigo-200 pb-3">
            <div>
              <h3 className="text-sm font-bold text-indigo-950 flex items-center gap-2">
                <Sliders className="w-4 h-4 text-indigo-600" />
                7. Cláusulas Especiales Adicionales y Edición de Texto Libre (Sugerencias del Cliente)
              </h3>
              <p className="text-[11px] text-indigo-800 mt-0.5">
                Agregue cláusulas personalizadas o estipulaciones solicitadas por el Cliente. Se numeran automáticamente en la Tabla de Contenido y en el PDF.
              </p>
            </div>

            <button
              type="button"
              onClick={() => addCustomClause()}
              className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-bold shadow-xs flex items-center gap-1.5 shrink-0"
            >
              <Plus className="w-4 h-4" />
              Agregar Cláusula en Blanco
            </button>
          </div>

          {/* Plantillas Rápidas de Cláusulas Especiales sugeridas habitualmente por Clientes en Chile */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-bold text-indigo-900">
              Insertar Cláusula Tipo (1-Clic):
            </span>
            <button
              type="button"
              onClick={() =>
                addCustomClause({
                  title: 'Suspensión en Ventanas Críticas de Negocio (CyberDay / Cierre Bancario)',
                  content:
                    'A requerimiento del Cliente, el Auditor suspenderá toda prueba activa durante eventos de alta demanda transaccional (CyberDay, CyberMonday o cierres contables de fin de mes), reanudando la ventana sin costo adicional.',
                })
              }
              className="px-2.5 py-1 bg-white hover:bg-indigo-100 text-indigo-900 border border-indigo-300 rounded-lg text-[11px] font-semibold"
            >
              + Ventana CyberDay / Cierre Contable
            </button>
            <button
              type="button"
              onClick={() =>
                addCustomClause({
                  title: 'Prohibición de Uso de Modelos de IA Pública con Datos del Cliente',
                  content:
                    'El Auditor garantiza que ningún fragmento de código fuente, respuesta HTTP, captura o hallazgo del Cliente será procesado en motores de Inteligencia Artificial de terceros fuera de entornos locales aislados.',
                })
              }
              className="px-2.5 py-1 bg-white hover:bg-indigo-100 text-indigo-900 border border-indigo-300 rounded-lg text-[11px] font-semibold"
            >
              + Prohibición IA Externa / Soberanía de Datos
            </button>
            <button
              type="button"
              onClick={() =>
                addCustomClause({
                  title: 'Obligaciones Laborales, Personal Clave y Seguros (Estándar EPC Chile)',
                  content:
                    'Conforme al estándar corporativo EPC y artículos 183-B del Código del Trabajo, la Consultora Auditora declara estar al día en las cotizaciones previsionales de su Personal Clave y mantener póliza vigente de Responsabilidad Civil Profesional.',
                })
              }
              className="px-2.5 py-1 bg-white hover:bg-indigo-100 text-indigo-900 border border-indigo-300 rounded-lg text-[11px] font-semibold"
            >
              + Personal Clave y Seguros (Cláusula EPC)
            </button>
          </div>

          {/* Lista Editable de Cláusulas Adicionales */}
          {customClauses.length > 0 && (
            <div className="space-y-3">
              {customClauses.map((clause, idx) => (
                <div
                  key={clause.id || idx}
                  className="bg-white p-4 rounded-xl border border-indigo-200 shadow-2xs space-y-2.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-black text-indigo-700 uppercase">
                      Cláusula Especial Adicional 12.{idx + 1}
                    </span>
                    <button
                      type="button"
                      onClick={() => removeCustomClause(idx)}
                      className="text-xs text-rose-600 hover:text-rose-800 font-bold flex items-center gap-1"
                    >
                      <Trash2 className="w-3.5 h-3.5" /> Eliminar Cláusula
                    </button>
                  </div>
                  <div>
                    <label className="block text-[11px] font-bold text-slate-700 mb-1">
                      Título de la Cláusula Especial (Aparecerá en la Tabla de Contenido) *
                    </label>
                    <input
                      type="text"
                      value={clause.title}
                      onChange={(e) => updateCustomClause(idx, 'title', e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs font-bold"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-bold text-slate-700 mb-1">
                      Redacción Íntegra de la Cláusula *
                    </label>
                    <textarea
                      rows={3}
                      value={clause.content}
                      onChange={(e) => updateCustomClause(idx, 'content', e.target.value)}
                      className="w-full px-3 py-1.5 bg-slate-50 border border-slate-300 rounded-lg text-xs leading-relaxed"
                    />
                  </div>
                </div>
              ))}
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-indigo-950 mb-1">
              Estipulaciones Particulares / Notas o Modificaciones de Texto Libre Solicitud del Cliente (Opcional)
            </label>
            <textarea
              rows={3}
              value={additionalStipulations}
              onChange={(e) => setAdditionalStipulations(e.target.value)}
              placeholder="Escriba aquí cualquier modificación adicional, anexo específico o condición solicitada por el Cliente que no esté en los campos anteriores..."
              className="w-full px-3 py-2 bg-white border border-indigo-300 rounded-lg text-xs leading-relaxed"
            />
          </div>
        </div>

        {/* Prerrequisitos */}
        <div className="pt-3 border-t border-slate-200 space-y-2">
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={backupConfirmed}
              onChange={(e) => setBackupConfirmed(e.target.checked)}
              className="mt-0.5 h-4 w-4 text-indigo-600 rounded"
            />
            <span className="text-xs text-slate-700">
              <strong>Deber de Respaldo Previo (Cláusula 3.1):</strong> Se certifica la existencia de copias de
              seguridad íntegras y verificadas antes de ejecutar pruebas.
            </span>
          </label>
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={cloudConfirmed}
              onChange={(e) => setCloudConfirmed(e.target.checked)}
              className="mt-0.5 h-4 w-4 text-indigo-600 rounded"
            />
            <span className="text-xs text-slate-700">
              <strong>Autorización Cloud de Terceros (Cláusula 2.2):</strong> Se ratifica compatibilidad con políticas
              de pentesting de los proveedores cloud declarados.
            </span>
          </label>
        </div>

        <div className="flex justify-end gap-3 pt-4 border-t border-slate-200">
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 border border-slate-300 text-slate-700 rounded-lg text-xs font-bold hover:bg-slate-50"
            >
              Cancelar
            </button>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="px-6 py-2.5 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 shadow disabled:opacity-50"
          >
            {submitting
              ? 'Guardando en Supabase...'
              : isEditing
              ? 'Guardar Correcciones en Contrato RoE'
              : 'Emitir Borrador Oficial de Contrato RoE'}
          </button>
        </div>
      </form>
    </div>
  );
}
