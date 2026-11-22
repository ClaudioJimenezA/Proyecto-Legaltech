import React, { useEffect, useState } from 'react';
import { useRoeWorkflow } from '../hooks/useRoeWorkflow';
import ContractViewer from './ContractViewer';
import ScopeEditor from './ScopeEditor';
import { RoeStatusBadge } from '../constants/roeStatus';
import LiveLoggerWorkspace from '../../live_logger/components/LiveLoggerWorkspace';
import VulnerabilityWorkspace from '../../vulnerability_tracking/components/VulnerabilityWorkspace';
import {
  Activity,
  Bug,
  FilePlus,
  FileText,
  Radar,
  RefreshCw,
  Shield,
  UserCheck,
} from 'lucide-react';

export default function RoeDashboard() {
  const {
    agreements,
    currentAgreement,
    compliance,
    loading,
    error,
    fetchAgreements,
    fetchAgreement,
    createProposal,
    updateProposal,
    sendToClient,
    requestRevision,
    clientApprove,
    sealAgreement,
    terminateAgreement,
    verifyIntegrity,
    downloadContractPdf,
    openContractPrintableHtml,
  } = useRoeWorkflow();

  // 'step_1_roe' | 'step_2_logger' | 'step_3_vulns'
  const [activeStep, setActiveStep] = useState('step_1_roe');
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'create' | 'edit' | 'detail'
  const [selectedLoggerAgreementId, setSelectedLoggerAgreementId] = useState(null);

  const [activeRole, setActiveRole] = useState(() => {
    const saved = localStorage.getItem('lexploit_active_role');
    if (saved === 'client' || saved === 'auditor') return saved;
    if (saved === 'soc') {
      localStorage.setItem('lexploit_active_role', 'client');
      return 'client';
    }
    return 'auditor';
  });

  const handleRoleChange = (newRole) => {
    setActiveRole(newRole);
    localStorage.setItem('lexploit_active_role', newRole);
    fetchAgreements();
  };

  useEffect(() => {
    fetchAgreements();
  }, [fetchAgreements]);

  const handleSelectAgreement = async (id) => {
    await fetchAgreement(id);
    setSelectedLoggerAgreementId(id);
    setViewMode('detail');
    setActiveStep('step_1_roe');
  };

  const handleOpenLiveLoggerForAgreement = (id) => {
    setSelectedLoggerAgreementId(id);
    setActiveStep('step_2_logger');
  };

  const handleOpenVulnTrackerForAgreement = (id) => {
    setSelectedLoggerAgreementId(id);
    setActiveStep('step_3_vulns');
  };

  const handleCreated = async (payload) => {
    const created = await createProposal(payload);
    await fetchAgreement(created.id);
    setSelectedLoggerAgreementId(created.id);
    setViewMode('detail');
  };

  const handleUpdated = async (payload) => {
    if (!currentAgreement) return;
    await updateProposal(currentAgreement.id, payload);
    setViewMode('detail');
  };

  return (
    <div className="min-h-screen bg-slate-100 text-slate-800">
      {/* Barra Superior con Selector de Rol */}
      <header className="bg-slate-900 text-white border-b border-slate-800 px-6 py-4">
        <div className="max-w-6xl mx-auto flex flex-col lg:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600 rounded-lg text-white">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-black tracking-wide">LEXPLOIT v2.0</h1>
              <p className="text-xs text-slate-400">
                Plataforma de Informática Legal, Trazabilidad y Cumplimiento Normativo para Pentesting en Chile (Leyes 21.459, 21.663, 21.719, 19.799)
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5 bg-slate-800 p-1 rounded-lg border border-slate-700 text-xs">
            <span className="text-slate-400 px-2 flex items-center gap-1 font-medium">
              <UserCheck className="w-3.5 h-3.5" /> Rol activo:
            </span>
            <button
              type="button"
              onClick={() => handleRoleChange('auditor')}
              className={`px-3 py-1 rounded font-bold transition-colors ${
                activeRole === 'auditor'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Auditor Lead
            </button>
            <button
              type="button"
              onClick={() => handleRoleChange('client')}
              className={`px-3 py-1 rounded font-bold transition-colors ${
                activeRole === 'client'
                  ? 'bg-blue-600 text-white shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Cliente PoC / Rep. Legal
            </button>
          </div>
        </div>
      </header>

      {/* Selector de Módulo (Paso 1, Paso 2 y Paso 3) */}
      <div className="bg-white border-b border-slate-200 shadow-2xs">
        <div className="max-w-6xl mx-auto px-6 flex flex-wrap items-center gap-2 py-2.5">
          <button
            type="button"
            onClick={() => setActiveStep('step_1_roe')}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all ${
              activeStep === 'step_1_roe'
                ? 'bg-indigo-600 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <FileText className="w-4 h-4" />
            Paso 1: Contratos RoE y Sellado SHA-256
          </button>

          <button
            type="button"
            onClick={() => setActiveStep('step_2_logger')}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all ${
              activeStep === 'step_2_logger'
                ? 'bg-emerald-600 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Radar className="w-4 h-4" />
            Paso 2: Bitácora en Vivo y Desconflicto ANCI (±2 min)
          </button>

          <button
            type="button"
            onClick={() => setActiveStep('step_3_vulns')}
            className={`px-3.5 py-2 rounded-lg text-xs font-extrabold flex items-center gap-2 transition-all ${
              activeStep === 'step_3_vulns'
                ? 'bg-slate-900 text-white shadow-xs'
                : 'text-slate-600 hover:bg-slate-100'
            }`}
          >
            <Bug className="w-4 h-4 text-indigo-400" />
            Paso 3: Hitos CVSS v3.1, Re-Test y Cierre ANCI (PDF / CSAF 2.0)
          </button>
        </div>
      </div>

      {/* Contenido Principal */}
      <main className="max-w-6xl mx-auto p-6">
        {activeStep === 'step_2_logger' ? (
          <LiveLoggerWorkspace
            agreements={agreements}
            selectedAgreementId={selectedLoggerAgreementId || currentAgreement?.id}
            onSelectAgreementId={(id) => {
              setSelectedLoggerAgreementId(id);
              fetchAgreement(id);
            }}
            activeRole={activeRole}
            onBackToContract={async () => {
              const targetId = selectedLoggerAgreementId || currentAgreement?.id;
              if (targetId) {
                await fetchAgreement(targetId);
                setViewMode('detail');
              } else {
                setViewMode('list');
              }
              setActiveStep('step_1_roe');
            }}
          />
        ) : activeStep === 'step_3_vulns' ? (
          <VulnerabilityWorkspace
            agreements={agreements}
            selectedAgreementId={selectedLoggerAgreementId || currentAgreement?.id}
            onSelectAgreementId={(id) => {
              setSelectedLoggerAgreementId(id);
              fetchAgreement(id);
            }}
            activeRole={activeRole}
            onBackToContract={async () => {
              const targetId = selectedLoggerAgreementId || currentAgreement?.id;
              if (targetId) {
                await fetchAgreement(targetId);
                setViewMode('detail');
              } else {
                setViewMode('list');
              }
              setActiveStep('step_1_roe');
            }}
          />
        ) : (
          <>
            {/* Barra de Navegación de Vistas del Paso 1 */}
            <div className="flex items-center justify-between mb-6">
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setViewMode('list')}
                  className={`px-4 py-2 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                    viewMode === 'list'
                      ? 'bg-white text-slate-900 shadow border border-slate-200'
                      : 'text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  <FileText className="w-4 h-4" /> Todos los Acuerdos ({agreements.length})
                </button>

                {currentAgreement && (
                  <button
                    type="button"
                    onClick={() => setViewMode('detail')}
                    className={`px-4 py-2 rounded-lg text-xs font-bold transition-colors flex items-center gap-1.5 ${
                      viewMode === 'detail'
                        ? 'bg-white text-slate-900 shadow border border-slate-200'
                        : 'text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    Contrato: {currentAgreement.title}
                  </button>
                )}
              </div>

              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={fetchAgreements}
                  disabled={loading}
                  className="p-2 bg-white border border-slate-200 rounded-lg text-slate-600 hover:text-slate-900 text-xs shadow-sm"
                  title="Refrescar lista"
                >
                  <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                </button>

                {activeRole === 'auditor' && (
                  <button
                    type="button"
                    onClick={() => setViewMode('create')}
                    className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 shadow flex items-center gap-1.5"
                  >
                    <FilePlus className="w-4 h-4" /> Redactar Nuevo Contrato
                  </button>
                )}
              </div>
            </div>

            {error && (
              <div className="mb-6 p-4 bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-lg">
                ⚠️ {error}
              </div>
            )}

            {/* Vistas Condicionales del Paso 1 */}
            {viewMode === 'create' && (
              <ScopeEditor
                onSaved={handleCreated}
                onCancel={() => setViewMode('list')}
              />
            )}

            {viewMode === 'edit' && currentAgreement && (
              <ScopeEditor
                initialAgreement={currentAgreement}
                onSaved={handleUpdated}
                onCancel={() => setViewMode('detail')}
              />
            )}

            {viewMode === 'detail' && (
              <ContractViewer
                agreement={currentAgreement}
                compliance={compliance}
                currentRole={activeRole}
                onEdit={() => setViewMode('edit')}
                onSendToClient={sendToClient}
                onRequestRevision={requestRevision}
                onClientApprove={clientApprove}
                onSeal={sealAgreement}
                onTerminate={terminateAgreement}
                onVerifyIntegrity={verifyIntegrity}
                onDownloadContractPdf={downloadContractPdf}
                onOpenContractHtml={openContractPrintableHtml}
                onOpenLiveLogger={() =>
                  currentAgreement && handleOpenLiveLoggerForAgreement(currentAgreement.id)
                }
              />
            )}

            {viewMode === 'list' && (
              <div className="bg-white rounded-xl shadow border border-slate-200 overflow-hidden">
                <div className="p-4 border-b border-slate-200 bg-slate-50 font-bold text-xs text-slate-700 uppercase tracking-wider">
                  Bandeja de Acuerdos de Reglas de Compromiso (RoE)
                </div>

                {loading && !agreements.length ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    Cargando acuerdos...
                  </div>
                ) : !agreements.length ? (
                  <div className="p-12 text-center text-slate-500 space-y-3">
                    <Shield className="w-10 h-10 mx-auto text-slate-300" />
                    <p className="text-sm font-medium">No hay acuerdos registrados todavía.</p>
                    {activeRole === 'auditor' ? (
                      <button
                        type="button"
                        onClick={() => setViewMode('create')}
                        className="px-4 py-2 bg-indigo-600 text-white text-xs font-bold rounded-lg hover:bg-indigo-700"
                      >
                        Crear primera propuesta de RoE
                      </button>
                    ) : (
                      <p className="text-xs text-slate-400">
                        Cambie al rol Auditor Lead para redactar una propuesta.
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="divide-y divide-slate-200">
                    {agreements.map((item) => {
                      const meta = item.contract_metadata || {};
                      const isItemSealed =
                        item.current_status === 'ACTIVE' ||
                        item.current_status === 'SIGNED_AND_SEALED';
                      return (
                        <div
                          key={item.id}
                          onClick={() => handleSelectAgreement(item.id)}
                          className="p-4 hover:bg-slate-50 cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                        >
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-sm text-slate-900">
                                {item.title}
                              </span>
                              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-semibold">
                                v{item.version}
                              </span>
                            </div>
                            <div className="text-xs text-slate-600 flex flex-wrap gap-x-3 gap-y-1">
                              <span>
                                <strong>Cliente:</strong> {meta.client_legal_name || 'N/A'}{' '}
                                <span className="font-mono text-slate-500 font-semibold">
                                  ({meta.client_tax_id || 'N/A'})
                                </span>
                              </span>
                              <span>|</span>
                              <span>
                                <strong>Rep. Legal:</strong> {meta.client_rep_name || 'N/A'}{' '}
                                <span className="font-mono text-slate-500">
                                  ({meta.client_rep_rut || 'N/A'})
                                </span>
                              </span>
                              <span>|</span>
                              <span>
                                <strong>Pentester:</strong> {meta.auditor_lead_name || 'N/A'}{' '}
                                <span className="font-mono text-slate-500">
                                  ({meta.auditor_lead_rut || 'N/A'})
                                </span>
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-500 font-mono">
                              PoC: {meta.poc_primary_name || 'N/A'} (
                              {meta.poc_primary_email || 'N/A'}) | Activos:{' '}
                              {item.target_assets?.length || 0} In-Scope | Modalidad:{' '}
                              {meta.testing_modality || 'Gray-Box'} | Token:{' '}
                              {item.traffic_header_token}
                            </p>
                          </div>

                          <div className="flex flex-wrap items-center gap-2 shrink-0">
                            <RoeStatusBadge status={item.current_status} size="sm" />

                            {isItemSealed && (
                              <>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleOpenLiveLoggerForAgreement(item.id);
                                  }}
                                  className="px-2.5 py-1 bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 rounded-lg text-[11px] font-bold flex items-center gap-1 transition-colors"
                                >
                                  <Activity className="w-3.5 h-3.5 text-emerald-600" />
                                  Paso 2
                                </button>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleOpenVulnTrackerForAgreement(item.id);
                                  }}
                                  className="px-2.5 py-1 bg-indigo-50 hover:bg-indigo-100 text-indigo-800 border border-indigo-300 rounded-lg text-[11px] font-bold flex items-center gap-1 transition-colors"
                                >
                                  <Bug className="w-3.5 h-3.5 text-indigo-600" />
                                  Paso 3 / ANCI
                                </button>
                              </>
                            )}

                            <span className="text-xs text-indigo-600 font-bold hover:underline">
                              Abrir Contrato →
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
