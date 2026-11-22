import React, { useState } from 'react';
import {
  AlertTriangle,
  ArchiveX,
  BookOpen,
  Calendar,
  CheckCircle2,
  Database,
  Download,
  Edit3,
  FileCheck2,
  Fingerprint,
  Info,
  Lock,
  MessageSquare,
  MessageSquareWarning,
  PhoneCall,
  Printer,
  Scale,
  Send,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from 'lucide-react';
import { RoeStatusBadge } from '../constants/roeStatus';

export default function ContractViewer({
  agreement,
  compliance,
  currentRole = 'auditor',
  onEdit,
  onSendToClient,
  onRequestRevision,
  onClientApprove,
  onSeal,
  onTerminate,
  onVerifyIntegrity,
  onOpenLiveLogger,
  onDownloadContractPdf,
  onOpenContractHtml,
}) {
  const [showRevisionModal, setShowRevisionModal] = useState(false);
  const [observations, setObservations] = useState('');

  const [showTerminateModal, setShowTerminateModal] = useState(false);
  const [terminateReason, setTerminateReason] = useState('');

  const [backupConfirmCheck, setBackupConfirmCheck] = useState(
    agreement?.backup_confirmed ?? true
  );
  const [cloudConfirmCheck, setCloudConfirmCheck] = useState(
    agreement?.cloud_authorization_confirmed ?? true
  );

  const [integrityReport, setIntegrityReport] = useState(null);
  const [showHtmlInfo, setShowHtmlInfo] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState('');

  if (!agreement) {
    return (
      <div className="p-8 text-center text-slate-500 bg-white rounded-xl border border-slate-200">
        Seleccione un acuerdo de la lista para visualizar su contrato oficial.
      </div>
    );
  }

  const meta = agreement.contract_metadata || {};
  const revisionHistory = meta.revision_history || [];
  const isSealed = Boolean(agreement.sha256_hash);
  const isEditable =
    !isSealed &&
    (agreement.current_status === 'DRAFT' ||
      agreement.current_status === 'REVISION_REQUESTED');

  const handleSend = async () => {
    setActionLoading(true);
    setActionError('');
    try {
      await onSendToClient(agreement.id);
    } catch (err) {
      setActionError(err.message || 'Error al enviar al cliente.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevisionSubmit = async () => {
    if (!observations.trim()) return;
    setActionLoading(true);
    setActionError('');
    try {
      await onRequestRevision(agreement.id, observations);
      setShowRevisionModal(false);
      setObservations('');
    } catch (err) {
      setActionError(err.message || 'Error al enviar reparos.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!backupConfirmCheck) {
      setActionError('Debe marcar la casilla de confirmación de respaldos previos para firmar.');
      return;
    }
    setActionLoading(true);
    setActionError('');
    try {
      await onClientApprove(agreement.id, {
        backupConfirmed: backupConfirmCheck,
        cloudAuthorizationConfirmed: cloudConfirmCheck,
      });
    } catch (err) {
      setActionError(err.message || 'Error al firmar como cliente.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleSeal = async () => {
    setActionLoading(true);
    setActionError('');
    try {
      await onSeal(agreement.id);
    } catch (err) {
      setActionError(err.message || 'Error al sellar el acuerdo.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleTerminateSubmit = async () => {
    if (!terminateReason.trim()) return;
    setActionLoading(true);
    setActionError('');
    try {
      await onTerminate(agreement.id, terminateReason);
      setShowTerminateModal(false);
      setTerminateReason('');
    } catch (err) {
      setActionError(err.message || 'Error al archivar/rechazar el acuerdo.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    setActionLoading(true);
    setActionError('');
    try {
      const report = await onVerifyIntegrity(agreement.id);
      setIntegrityReport(report);
    } catch (err) {
      setActionError(err.message || 'Error al auditar integridad SHA-256.');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-lg border border-slate-200 p-8 max-w-5xl mx-auto my-6 text-slate-800">
      {/* Cabecera Oficial del Contrato */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b-2 border-slate-900 pb-6 mb-6">
        <div>
          <span className="text-xs font-mono uppercase tracking-widest text-indigo-600 font-bold">
            ACUERDO DE REGLAS DE COMPROMISO Y AUTORIZACIÓN LEGAL DE PENTESTING (CHILE v2.0)
          </span>
          <h1 className="text-2xl font-black text-slate-900 mt-1">{agreement.title}</h1>
          <p className="text-xs text-slate-500 font-mono mt-1">
            Marco Normativo: Art. 2° Ley N° 21.459 | Ley N° 21.663 (ANCI) | Ley N° 21.719 | Ley N° 19.799
          </p>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            ID Proyecto: {agreement.id} | Versión: v{agreement.version} | Emisión:{' '}
            {new Date(agreement.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex flex-col items-start md:items-end gap-2">
          <RoeStatusBadge status={agreement.current_status} size="lg" />
          {isSealed && (
            <span className="text-[11px] text-emerald-700 font-bold flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5" /> Bloqueado contra edición (Inmutable SHA-256)
            </span>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            {onDownloadContractPdf && (
              <button
                type="button"
                onClick={() => onDownloadContractPdf(agreement.id, agreement.title)}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold shadow-xs flex items-center gap-1.5 transition-colors ${
                  isSealed
                    ? 'bg-emerald-600 hover:bg-emerald-700 text-white'
                    : 'bg-indigo-600 hover:bg-indigo-700 text-white'
                }`}
              >
                <Download className="w-3.5 h-3.5" />
                {isSealed
                  ? 'Exportar Contrato Firmado (.PDF con Índice)'
                  : 'Exportar Borrador a PDF (con Índice)'}
              </button>
            )}
            {onOpenContractHtml && (
              <div className="relative inline-flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => onOpenContractHtml(agreement.id)}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 rounded-lg text-xs font-bold flex items-center gap-1.5"
                >
                  <Printer className="w-3.5 h-3.5" />
                  Vista Imprimible (HTML)
                </button>
                <button
                  type="button"
                  onClick={() => setShowHtmlInfo((prev) => !prev)}
                  className={`p-1.5 rounded-lg border text-xs transition-colors ${
                    showHtmlInfo
                      ? 'bg-indigo-100 border-indigo-400 text-indigo-800'
                      : 'bg-white border-slate-300 text-slate-500 hover:text-indigo-700 hover:border-indigo-300'
                  }`}
                  title="¿Por qué existe la opción Vista Imprimible (HTML)?"
                  aria-label="Información sobre Vista Imprimible HTML"
                >
                  <Info className="w-3.5 h-3.5" />
                </button>
                {showHtmlInfo && (
                  <div className="absolute right-0 top-10 z-30 w-80 p-3.5 bg-slate-900 text-slate-100 rounded-xl shadow-xl border border-slate-700 text-[11px] leading-relaxed text-left">
                    <div className="font-bold text-indigo-300 mb-1 flex items-center justify-between">
                      <span>¿Por qué incluir la Vista Imprimible (HTML)?</span>
                      <button
                        type="button"
                        onClick={() => setShowHtmlInfo(false)}
                        className="text-slate-400 hover:text-white font-mono text-xs"
                      >
                        ✕
                      </button>
                    </div>
                    <p className="text-slate-300">
                      Abre el contrato con maquetación editorial completa (índice, tablas y sellos visuales)
                      para imprimir o guardar como PDF desde el navegador (<strong>Ctrl + P</strong>). Sirve
                      como respaldo visual de alta fidelidad en entornos <em>Serverless</em> donde los motores
                      PDF sin librerías gráficas nativas generan una versión simplificada.
                    </p>
                  </div>
                )}
              </div>
            )}
            {isEditable && onEdit && (
              <button
                type="button"
                onClick={onEdit}
                className="px-3 py-1.5 bg-indigo-50 hover:bg-indigo-100 text-indigo-800 border border-indigo-300 rounded-lg text-xs font-bold flex items-center gap-1.5"
              >
                <Edit3 className="w-3.5 h-3.5" />
                Agregar Cláusulas / Editar Texto
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Banner si el acuerdo fue rechazado o terminado */}
      {agreement.current_status === 'TERMINATED' && (
        <div className="mb-6 p-4 bg-rose-50 border border-rose-300 rounded-lg text-rose-900 text-xs space-y-1">
          <div className="font-bold text-sm flex items-center gap-2">
            <ArchiveX className="w-5 h-5 text-rose-600" />
            Acuerdo Rechazado / Archivado Definitivamente
          </div>
          <p>
            <strong>Motivo registrado:</strong>{' '}
            {meta.termination_reason || 'Terminado por falta de acuerdo entre las partes.'}
          </p>
          {meta.terminated_by_role && (
            <p className="text-[11px] text-rose-700">
              Ejecutado por: {meta.terminated_by_role} el{' '}
              {new Date(meta.terminated_at).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {/* Historial de Observaciones / Reparos del Cliente */}
      {revisionHistory.length > 0 && (
        <div className="mb-6 p-4 bg-orange-50 border border-orange-300 rounded-lg text-orange-950 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-bold text-sm flex items-center gap-2 text-orange-900">
              <MessageSquareWarning className="w-5 h-5 text-orange-600" />
              Bitácora de Observaciones y Reparos del Cliente ({revisionHistory.length})
            </span>
            {currentRole === 'auditor' && isEditable && onEdit && (
              <button
                type="button"
                onClick={onEdit}
                className="px-3 py-1 bg-orange-600 text-white rounded font-bold hover:bg-orange-700 flex items-center gap-1"
              >
                <Edit3 className="w-3.5 h-3.5" /> Editar Propuesta para Subsanar Reparos
              </button>
            )}
          </div>
          {revisionHistory.map((rev, i) => (
            <div key={i} className="bg-white p-3 rounded border border-orange-200">
              <div className="flex justify-between text-[11px] text-slate-500 mb-1">
                <strong className="text-orange-900">
                  Versión observada: v{rev.version} — Por: {rev.requested_by}
                </strong>
                <span>{new Date(rev.requested_at).toLocaleString()}</span>
              </div>
              <p className="text-slate-800 font-medium">{rev.observations}</p>
            </div>
          ))}
        </div>
      )}

      {actionError && (
        <div className="mb-6 p-4 bg-rose-50 border border-rose-200 text-rose-700 text-sm rounded-lg flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}

      {/* CUERPO ÍNTEGRO DEL CONTRATO LEGAL CHILENO */}
      <div className="space-y-6 text-xs leading-relaxed text-slate-700">
        {/* TABLA DE CONTENIDO (ÍNDICE DEL CONTRATO ESTILO EPC CHILE) */}
        <section className="p-5 bg-white rounded-xl border-2 border-slate-300 shadow-2xs space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-300 pb-2">
            <h3 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-indigo-600" />
              TABLA DE CONTENIDO (ÍNDICE DEL CONTRATO)
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              Estructura Formal Corporativa (Estándar EPC & NDA Chile)
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5 text-[11px]">
            <a href="#sec-antecedentes" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>0.</strong> ANTECEDENTES Y EXPOSITIVOS (EXPONEN)</span>
              <span className="font-mono text-slate-500">Preámbulo</span>
            </a>
            <a href="#sec-c1" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>1.</strong> COMPARECENCIA, PARTES Y PERSONERÍAS</span>
              <span className="font-mono text-slate-500">Cláusula 1ª</span>
            </a>
            <a href="#sec-c2" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>2.</strong> DEFINICIONES CONTRACTUALES Y TÉCNICAS (EPC)</span>
              <span className="font-mono text-slate-500">Cláusula 2ª</span>
            </a>
            <a href="#sec-c3" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>3.</strong> MANDATO EXPRESO (ART. 2° LEY 21.459) Y BACKUP</span>
              <span className="font-mono text-slate-500">Cláusula 3ª</span>
            </a>
            <a href="#sec-c4" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>4.</strong> DELIMITACIÓN DEL ALCANCE (IN-SCOPE / HARD DENY)</span>
              <span className="font-mono text-slate-500">Cláusula 4ª</span>
            </a>
            <a href="#sec-c5" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>5.</strong> VENTANA TEMPORAL, HORARIOS Y FIRMA DE TRÁFICO</span>
              <span className="font-mono text-slate-500">Cláusula 5ª</span>
            </a>
            <a href="#sec-c6" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>6.</strong> PUNTOS DE CONTACTO (PoC) Y RESERVA OPERATIVA</span>
              <span className="font-mono text-slate-500">Cláusula 6ª</span>
            </a>
            <a href="#sec-c7" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>7.</strong> LÍNEAS ROJAS Y PROTOCOLO BREAK-GLASS</span>
              <span className="font-mono text-slate-500">Cláusula 7ª</span>
            </a>
            <a href="#sec-c8-nda" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700 font-semibold text-indigo-900">
              <span><strong>8.</strong> ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA) Y MULTA UF</span>
              <span className="font-mono text-indigo-600">Cláusula 8ª</span>
            </a>
            <a href="#sec-c9" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>9.</strong> PROTECCIÓN DE DATOS Y PURGA (LEY N° 21.719)</span>
              <span className="font-mono text-slate-500">Cláusula 9ª</span>
            </a>
            <a href="#sec-c10" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>10.</strong> DESCONFLICTO SOC, RE-TEST Y PAQUETE ANCI (LEY 21.663)</span>
              <span className="font-mono text-slate-500">Cláusula 10ª</span>
            </a>
            <a href="#sec-c11-epc" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>11.</strong> LIMITACIÓN DE RESPONSABILIDAD, LEY 20.393 Y ARBITRAJE CAM</span>
              <span className="font-mono text-slate-500">Cláusula 11ª</span>
            </a>
            {(meta.custom_clauses || []).map((c, idx) => (
              <a
                key={c.id || idx}
                href={`#sec-custom-${idx}`}
                className="flex justify-between border-b border-dotted border-indigo-300 py-0.5 text-indigo-900 font-semibold hover:text-indigo-700"
              >
                <span className="truncate pr-2">
                  <strong>12.{idx + 1}.</strong> {c.title}
                </span>
                <span className="font-mono text-indigo-600 shrink-0">Cláusula Adicional</span>
              </a>
            ))}
            <a href="#sec-c13-seal" className="flex justify-between border-b border-dotted border-slate-300 py-0.5 hover:text-indigo-700">
              <span><strong>13.</strong> SUSCRIPCIÓN ELECTRÓNICA Y SELLADO SHA-256 (LEY 19.799)</span>
              <span className="font-mono text-slate-500">Certificado</span>
            </a>
          </div>
        </section>

        {/* SECCIÓN PRELIMINAR: ANTECEDENTES Y DEFINICIONES ESTILO EPC */}
        <section id="sec-antecedentes" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2.5">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2">
            Sección Preliminar: Antecedentes (Exponen) y Definiciones Contractuales (Estándar EPC)
          </h3>
          <p>
            <strong>0.1. Antecedentes (Exponen):</strong> Que <strong>{meta.client_legal_name}</strong> requiere
            evaluar empíricamente la seguridad de su infraestructura tecnológica mediante pruebas de penetración
            controladas bajo la eximente penal del <strong>Artículo 2° de la Ley N° 21.459</strong>, y que{' '}
            <strong>{meta.auditor_legal_name}</strong> cuenta con el Personal Clave y metodologías (OWASP, PTES,
            NIST SP 800-115) para ejecutarlas conforme al Estándar de Cuidado de la industria.
          </p>
          <p id="sec-c2">
            <strong>Cláusula 2ª (Definiciones Técnicas y Legales):</strong> Para efectos de este Contrato:
            <strong> (a) Activos In-Scope:</strong> Dominios FQDN, IPs y rangos CIDR autorizados en la Cláusula 4ª;
            <strong> (b) Hard Deny List (Out-of-Scope):</strong> Sistemas excluidos cuyo acceso está estrictamente vedado;
            <strong> (c) Protocolo Break-Glass:</strong> Parada inmediata y alerta de emergencia al PoC ante vulnerabilidades críticas;
            <strong> (d) Desconflicto SOC/ANCI:</strong> Cruce espaciotemporal (±2 minutos) para descartar falsas alarmas antes de reportar a la ANCI;
            <strong> (e) Día Hábil:</strong> Lunes a viernes excluyendo feriados legales en Chile.
          </p>
        </section>

        {/* CLÁUSULA PRIMERA: COMPARECENCIA */}
        <section id="sec-c1" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2">
            Cláusula Primera: Comparecencia, Individualización de las Partes y Personerías Legales
          </h3>
          <p>
            En la ciudad de Santiago de Chile, a{' '}
            <strong>{new Date(agreement.created_at).toLocaleDateString()}</strong>, comparecen:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            <div className="bg-white p-3.5 rounded-lg border border-slate-200 space-y-1">
              <span className="text-[11px] font-bold uppercase text-indigo-600">
                1.1. Parte Mandante (El Cliente / Propietario)
              </span>
              <p>
                <strong>Razón Social Empresa:</strong> {meta.client_legal_name}
              </p>
              <p>
                <strong>RUT Empresa Cliente:</strong> <span className="font-mono font-semibold">{meta.client_tax_id}</span>
              </p>
              <p>
                <strong>Clasificación Ley N° 21.663:</strong> {meta.regulatory_classification}
              </p>
              <p>
                <strong>Domicilio Legal:</strong> {meta.client_address}
              </p>
              <p>
                <strong>Nombre Representante Legal Cliente:</strong> {meta.client_rep_name}
              </p>
              <p>
                <strong>RUT Representante Legal Cliente / PoC:</strong>{' '}
                <span className="font-mono font-semibold text-slate-900">{meta.client_rep_rut}</span>
              </p>
              <p className="text-[11px] text-slate-600 pt-1 border-t border-slate-100">
                <strong>Personería Representante Cliente:</strong>{' '}
                {meta.client_rep_personeria || 'Escritura pública otorgada en Notaría de Santiago.'}
              </p>
            </div>

            <div className="bg-white p-3.5 rounded-lg border border-slate-200 space-y-1">
              <span className="text-[11px] font-bold uppercase text-indigo-600">
                1.2. Parte Ejecutora (El Auditor / Contratista)
              </span>
              <p>
                <strong>Razón Social Consultora:</strong> {meta.auditor_legal_name}
              </p>
              <p>
                <strong>RUT Consultora:</strong>{' '}
                <span className="font-mono font-semibold">{meta.auditor_tax_id}</span>
              </p>
              <p>
                <strong>Domicilio Comercial:</strong> {meta.auditor_address}
              </p>
              <p>
                <strong>Líder Técnico (Lead Pentester):</strong> {meta.auditor_lead_name}
              </p>
              <p>
                <strong>RUT Pentester / Representante Equipo de Ciberseguridad:</strong>{' '}
                <span className="font-mono font-semibold text-slate-900">{meta.auditor_lead_rut}</span>
              </p>
              <p className="text-[11px] text-slate-600 pt-1 border-t border-slate-100">
                <strong>Personería Representante Consultora:</strong>{' '}
                {meta.auditor_rep_personeria || 'Escritura pública otorgada en Notaría de Santiago.'}
              </p>
            </div>
          </div>
        </section>

        {/* CLÁUSULA TERCERA: MANDATO, CLOUD Y RESPALDO */}
        <section id="sec-c3" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2">
            Cláusula Tercera: Titularidad, Mandato Expreso (Art. 2° Ley 21.459) y Deber de Respaldo
          </h3>
          <p>
            <strong>2.1. Concesión de Mandato Expreso:</strong> El Cliente declara ser legítimo titular
            de los activos listados en la Cláusula Cuarta y otorga mandato técnico y jurídico explícito
            al Auditor para ejecutar pruebas de intrusión bajo la modalidad{' '}
            <strong className="text-indigo-900">{meta.testing_modality}</strong>, configurando el
            consentimiento previo que exime de responsabilidad penal conforme al Artículo 2° de la Ley
            N° 21.459.
          </p>
          <p>
            <strong>2.2. Infraestructura Cloud de Terceros:</strong> Proveedores declarados:{' '}
            <span className="font-mono font-semibold">{meta.cloud_providers || 'N/A'}</span> (Estado
            autorización:{' '}
            <strong>
              {agreement.cloud_authorization_confirmed ? 'CONFIRMADA' : 'PENDIENTE'}
            </strong>
            ).
          </p>
          <p>
            <strong>3.1. Prerrequisito de Respaldo (Backup):</strong> El Cliente certifica la
            existencia de copias de seguridad íntegras y verificadas (Estado:{' '}
            <strong className={agreement.backup_confirmed ? 'text-emerald-700' : 'text-rose-600'}>
              {agreement.backup_confirmed
                ? 'RESPALDOS REALIZADOS Y VERIFICADOS'
                : 'PENDIENTE DE CONFIRMACIÓN'}
            </strong>
            ).
          </p>
        </section>

        {/* CLÁUSULA CUARTA Y QUINTA: ALCANCE Y VENTANA TEMPORAL */}
        <section id="sec-c4" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-4">
          <h3 id="sec-c5" className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2">
            Cláusulas Cuarta y Quinta: Delimitación Macro del Alcance, Vigencia Temporal y Firma de Tráfico
          </h3>
          <p>
            <strong>4.2. Regla de Ejecución Abierta:</strong> Dentro de los activos In-Scope, el Auditor
            no está sujeto a restricciones previas de puertos o herramientas para no desvirtuar el
            descubrimiento empírico de vulnerabilidades.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-emerald-200 bg-emerald-50/70 p-3.5 rounded-lg">
              <h4 className="text-xs font-bold text-emerald-900 uppercase mb-2">
                4.1. Activos Autorizados In-Scope ({agreement.target_assets?.length || 0})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {agreement.target_assets?.map((asset, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-white border border-emerald-300 text-emerald-950 font-mono text-xs rounded"
                  >
                    {asset}
                  </span>
                ))}
              </div>
            </div>

            <div className="border border-rose-200 bg-rose-50/70 p-3.5 rounded-lg">
              <h4 className="text-xs font-bold text-rose-900 uppercase mb-2">
                4.3. Activos Excluidos Out-of-Scope ({agreement.excluded_assets?.length || 0})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {agreement.excluded_assets?.length ? (
                  agreement.excluded_assets.map((asset, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 bg-white border border-rose-300 text-rose-950 font-mono text-xs rounded"
                    >
                      {asset}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-400 italic">Sin exclusiones adicionales</span>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-white border border-slate-200 p-3.5 rounded-lg space-y-1">
              <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <Calendar className="w-4 h-4 text-indigo-600" />
                5.1. Ventana Temporal y Franja Horaria
              </span>
              <p className="font-mono">
                <strong>Inicio:</strong> {new Date(agreement.execution_start).toLocaleString()}
              </p>
              <p className="font-mono">
                <strong>Término:</strong> {new Date(agreement.execution_end).toLocaleString()}
              </p>
              <p>
                <strong>Franja Permitida:</strong> {meta.allowed_time_window}
              </p>
            </div>

            <div className="bg-white border border-slate-200 p-3.5 rounded-lg space-y-1.5">
              <span className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                <Fingerprint className="w-4 h-4 text-indigo-600" />
                5.2. Firma de Origen de Tráfico para Desconflicto SOC
              </span>
              <p className="font-mono text-indigo-900 bg-indigo-50 px-2 py-1 rounded border border-indigo-200 font-bold">
                X-Assessment-Scope: {agreement.traffic_header_token}
              </p>
              <div className="flex flex-wrap gap-1 items-center">
                <strong>IPs Públicas Auditor:</strong>
                {agreement.auditor_source_ips?.map((ip, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-slate-100 border border-slate-300 font-mono rounded"
                  >
                    {ip}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* CLÁUSULA SEXTA: PUNTOS DE CONTACTO (PoC) */}
        <section id="sec-c6" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2 flex items-center gap-2">
            <PhoneCall className="w-4 h-4 text-indigo-600" />
            Cláusula Sexta: Reserva Operativa y Puntos de Contacto Exclusivos (PoC)
          </h3>
          <p>
            <strong>6.1. Reserva ante Equipos TI/SOC:</strong> Para evaluar tiempos reales de detección,
            las partes acuerdan no alertar previamente a los administradores de infraestructura. Toda
            comunicación o desconflicto de alertas ANCI se canalizará exclusivamente con:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-white p-3.5 rounded-lg border border-slate-200 space-y-1">
              <span className="text-[11px] font-bold uppercase text-indigo-600">
                Punto de Contacto Titular (Principal)
              </span>
              <p>
                <strong>Nombre PoC Titular:</strong> {meta.poc_primary_name}
              </p>
              <p>
                <strong>RUT Punto de Contacto Titular:</strong>{' '}
                <span className="font-mono font-semibold text-slate-900">{meta.poc_primary_rut}</span>
              </p>
              <p>
                <strong>Cargo:</strong> {meta.poc_primary_role}
              </p>
              <p>
                <strong>Teléfono 24/7:</strong>{' '}
                <span className="font-mono">{meta.poc_primary_phone}</span>
              </p>
              <p>
                <strong>Email Cifrado:</strong>{' '}
                <span className="font-mono">{meta.poc_primary_email}</span>
              </p>
            </div>

            <div className="bg-white p-3.5 rounded-lg border border-slate-200 space-y-1">
              <span className="text-[11px] font-bold uppercase text-slate-500">
                Punto de Contacto Suplente (Respaldo)
              </span>
              <p>
                <strong>Nombre:</strong> {meta.poc_secondary_name || 'No designado'}
              </p>
              <p>
                <strong>Cargo:</strong> {meta.poc_secondary_role || 'N/A'}
              </p>
              <p>
                <strong>Teléfono 24/7:</strong>{' '}
                <span className="font-mono">{meta.poc_secondary_phone || 'N/A'}</span>
              </p>
              <p>
                <strong>Email:</strong>{' '}
                <span className="font-mono">{meta.poc_secondary_email || 'N/A'}</span>
              </p>
            </div>
          </div>
        </section>

        {/* CLÁUSULAS SÉPTIMA A DÉCIMA: LÍNEAS ROJAS, BREAK-GLASS, LEY 21.719 Y ANCI */}
        <section id="sec-c7" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2">
            Cláusulas Séptima, Novena y Décima: Líneas Rojas, Protocolo Break-Glass, Ley N° 21.719 y Reporte ANCI
          </h3>
          <p>
            <strong>Cláusula 7.1 (Líneas Rojas Art. 2° Ley 21.459):</strong> Prohibición absoluta de
            Denegación de Servicio (DoS/DDoS), alteración o borrado de datos productivos, instalación de
            malware persistente o ingeniería social no autorizada.
          </p>
          <p>
            <strong>Cláusula 7.2 (Protocolo Break-Glass):</strong> Ante hallazgos críticos (RCE, root o
            exposición masiva de datos), el Auditor detendrá la post-explotación y notificará al PoC
            Titular en un plazo máximo de <strong>{meta.break_glass_hours || 2} horas</strong>.
          </p>
          <p id="sec-c9">
            <strong>Cláusula 9ª (Protección de Datos Ley N° 21.719):</strong> Principio de minimización
            y obligación de sanitización y destrucción irreversible de evidencias técnicas dentro de{' '}
            <strong>{meta.data_purge_days || 14} días hábiles</strong> tras el informe de cierre.
          </p>
          <p id="sec-c10">
            <strong>Cláusula 10ª (Ciclo de Re-Test e Interoperabilidad ANCI Ley N° 21.663):</strong>{' '}
            Seguimiento interactivo de vulnerabilidades CVSS v3.1, ronda de Re-Testing y entrega de
            paquete dual (PDF Ejecutivo + XML/JSON estándar OASIS CSAF 2.0).
          </p>
        </section>

        {/* CLÁUSULA OCTAVA: ACUERDO DE CONFIDENCIALIDAD BILATERAL (NDA) Y CLÁUSULA PENAL EN UF */}
        <section id="sec-c8-nda" className="p-5 bg-indigo-50/50 rounded-xl border border-indigo-200 space-y-2.5">
          <h3 className="text-sm font-black text-indigo-950 uppercase tracking-wide border-b border-indigo-200 pb-2 flex items-center gap-2">
            <Lock className="w-4 h-4 text-indigo-600" />
            Cláusula Octava: Acuerdo de Confidencialidad Bilateral (Both-Ways NDA) y Cláusula Penal en UF
          </h3>
          <p>
            <strong>8.1. Alcance Bilateral y Reserva Estricta:</strong>{' '}
            {meta.nda_custom_terms ||
              'Ambas Partes actuarán recíprocamente como Sociedad Emisora y Sociedad Receptora de Información Confidencial, quedando prohibida toda divulgación a terceros de vulnerabilidades, código fuente, arquitectura de red o datos personales.'}
          </p>
          <p>
            <strong>8.2. Vigencia y Supervivencia Post-Contractual:</strong> Las obligaciones de reserva y
            confidencialidad tendrán una duración de{' '}
            <strong>{meta.nda_duration_years ?? 3} años</strong> y sobrevivirán por un plazo adicional de{' '}
            <strong>{meta.nda_survival_years ?? 2} años</strong> tras el término o finiquito del Contrato,
            obligando al Auditor a restituir o destruir todo soporte con certificación firmada.
          </p>
          <p>
            <strong>8.3. Cláusula Penal y Avaluación Anticipada de Perjuicios (Art. 1535 Código Civil):</strong>{' '}
            En caso de incumplimiento de la obligación de confidencialidad o filtración no autorizada de
            hallazgos técnicos imputable a una Parte o a su Personal, la Parte infractora pagará a título de
            multa convencional e indemnización punitiva anticipada la suma de{' '}
            <strong className="text-indigo-950 font-mono">
              {meta.nda_penalty_uf ?? 500} UF (Unidades de Fomento)
            </strong>
            , sin perjuicio del derecho a perseguir la responsabilidad penal y el daño emergente superior.
          </p>
        </section>

        {/* CLÁUSULA UNDÉCIMA: GOBERNANZA EPC CHILE, LIMITACIÓN DE RESPONSABILIDAD, LEY 20.393 Y ARBITRAJE CAM */}
        <section id="sec-c11-epc" className="p-5 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
          <h3 className="text-sm font-black text-slate-900 uppercase tracking-wide border-b border-slate-200 pb-2 flex items-center gap-2">
            <Scale className="w-4 h-4 text-indigo-600" />
            Cláusula Undécima: Limitación de Responsabilidad, Ley N° 20.393 y Arbitraje CAM Santiago (Estándar EPC)
          </h3>
          <p>
            <strong>11.1. Contratista Independiente y Limitación de Responsabilidad (Cláusula 15 Modelo EPC):</strong>{' '}
            El Auditor actúa como contratista independiente sin subordinación laboral. Salvo casos de dolo,
            culpa grave o infracción al NDA, la responsabilidad total máxima agregada bajo este Contrato no
            excederá del <strong>{meta.liability_cap_pct ?? 30}%</strong> del valor de los servicios,
            excluyéndose lucro cesante y daños indirectos.
          </p>
          <p>
            <strong>11.2. Modelo de Prevención de Delitos (Ley N° 20.393):</strong> Las Partes declaran dar
            estricto cumplimiento a la Ley N° 20.393 sobre Responsabilidad Penal de las Personas Jurídicas.
          </p>
          <p>
            <strong>11.3. Ley Aplicable y Solución de Controversias:</strong> Este Contrato se rige por las
            leyes de la República de Chile. Toda controversia no resuelta en quince (15) Días Hábiles de
            negociación directa será sometida a arbitraje ante el{' '}
            <strong>
              {meta.dispute_resolution_seat ||
                'Centro de Arbitraje y Mediación (CAM) de la Cámara de Comercio de Santiago A.G.'}
            </strong>
            .
          </p>
        </section>

        {/* CLÁUSULAS ESPECIALES ADICIONALES Y ESTIPULACIONES PERSONALIZADAS DEL CLIENTE */}
        {((meta.custom_clauses && meta.custom_clauses.length > 0) ||
          meta.additional_stipulations) && (
          <section className="p-5 bg-amber-50/60 rounded-xl border border-amber-300 space-y-3">
            <div className="flex items-center justify-between border-b border-amber-200 pb-2">
              <h3 className="text-sm font-black text-amber-950 uppercase tracking-wide">
                Cláusulas Especiales Adicionales y Estipulaciones Acordadas con el Cliente
              </h3>
              {isEditable && onEdit && (
                <button
                  type="button"
                  onClick={onEdit}
                  className="text-[11px] font-bold text-indigo-700 hover:underline flex items-center gap-1"
                >
                  <Edit3 className="w-3 h-3" /> Editar Cláusulas
                </button>
              )}
            </div>

            {(meta.custom_clauses || []).map((c, idx) => (
              <div
                key={c.id || idx}
                id={`sec-custom-${idx}`}
                className="bg-white p-3.5 rounded-lg border border-amber-200 space-y-1"
              >
                <span className="text-xs font-black text-amber-900 uppercase block">
                  Cláusula Especial 12.{idx + 1}: {c.title}
                </span>
                <p className="text-slate-700 leading-relaxed whitespace-pre-line">{c.content}</p>
              </div>
            ))}

            {meta.additional_stipulations && (
              <div className="bg-white p-3.5 rounded-lg border border-amber-200 space-y-1">
                <span className="text-xs font-black text-amber-900 uppercase block">
                  Estipulaciones Particulares y Modificaciones Incorporadas:
                </span>
                <p className="text-slate-700 leading-relaxed whitespace-pre-line">
                  {meta.additional_stipulations}
                </p>
              </div>
            )}
          </section>
        )}

        {/* EVALUACIÓN AUTOMÁTICA ART. 2° LEY 21.459 */}
        {compliance && (
          <div className="border border-slate-200 rounded-xl overflow-hidden">
            <div className="bg-slate-100 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-indigo-600" />
                Evaluación Automatizada de Exención Penal (Art. 2° Ley N° 21.459)
              </span>
              <span
                className={`text-xs font-bold px-2.5 py-0.5 rounded ${
                  compliance.is_exempt
                    ? 'bg-emerald-100 text-emerald-800'
                    : 'bg-rose-100 text-rose-800'
                }`}
              >
                {compliance.is_exempt ? 'EXENCIÓN PENAL ACREDITADA' : 'CONDICIONES PENDIENTES'}
              </span>
            </div>
            <div className="p-4 space-y-2 bg-white">
              {compliance.conditions?.map((c, i) => (
                <div key={i} className="flex items-start gap-2.5 text-xs">
                  {c.passed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                  )}
                  <div>
                    <strong className={c.passed ? 'text-slate-900' : 'text-rose-900'}>
                      {c.name}:
                    </strong>{' '}
                    <span className="text-slate-600">{c.reason}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CLÁUSULA DÉCIMA TERCERA: SUSCRIPCIÓN ELECTRÓNICA, INMUTABILIDAD Y AUDITORÍA SHA-256 */}
        <div id="sec-c13-seal" className="bg-slate-900 text-slate-100 p-6 rounded-xl font-mono text-xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div>
              <span className="text-indigo-400 font-bold uppercase tracking-wider block">
                Cláusula 13ª: Suscripción Electrónica e Inmutabilidad Criptográfica (Ley N° 19.799)
              </span>
              <span className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                <Database className="w-3.5 h-3.5 text-emerald-400" />
                Almacenamiento: Supabase PostgreSQL (public.roe_agreements) + RLS + Trigger Inmutable
              </span>
            </div>

            {isSealed && onVerifyIntegrity && (
              <button
                type="button"
                onClick={handleVerifyIntegrity}
                disabled={actionLoading}
                className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-sans font-bold text-xs flex items-center gap-1.5 shadow shrink-0"
              >
                <Fingerprint className="w-4 h-4" />
                {actionLoading ? 'Verificando...' : 'Auditar Integridad SHA-256 en Vivo'}
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[11px]">
            <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700 space-y-1.5">
              <span className="text-slate-400 uppercase font-bold block border-b border-slate-700 pb-1">
                Por la Parte Mandante (El Cliente)
              </span>
              <p>
                <span className="text-slate-400">Firmante Representante Legal:</span>{' '}
                <span className="text-white font-semibold">{meta.client_rep_name}</span>
              </p>
              <p>
                <span className="text-slate-400">RUT Representante Legal Cliente / PoC:</span>{' '}
                <span className="font-mono text-emerald-300 font-bold">{meta.client_rep_rut}</span>
              </p>
              <p className={agreement.client_signed_at ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                {agreement.client_signed_at
                  ? `SUSCRITO ELECTRÓNICAMENTE: ${new Date(agreement.client_signed_at).toISOString()}`
                  : 'PENDIENTE DE FIRMA'}
              </p>
            </div>

            <div className="bg-slate-800/80 p-3 rounded-lg border border-slate-700 space-y-1.5">
              <span className="text-slate-400 uppercase font-bold block border-b border-slate-700 pb-1">
                Por la Parte Ejecutora (El Auditor)
              </span>
              <p>
                <span className="text-slate-400">Firmante Líder Técnico:</span>{' '}
                <span className="text-white font-semibold">{meta.auditor_lead_name}</span>
              </p>
              <p>
                <span className="text-slate-400">RUT Pentester / Representante Equipo de Ciberseguridad:</span>{' '}
                <span className="font-mono text-emerald-300 font-bold">{meta.auditor_lead_rut}</span>
              </p>
              <p className={agreement.auditor_signed_at ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                {agreement.auditor_signed_at
                  ? `SUSCRITO Y SELLADO: ${new Date(agreement.auditor_signed_at).toISOString()}`
                  : 'PENDIENTE DE CONTRA-FIRMA'}
              </p>
            </div>
          </div>

          <div>
            <span className="text-slate-400">Digest Criptográfico SHA-256 Estampado:</span>
            <p className="text-emerald-300 break-all select-all mt-1 font-bold bg-slate-950 p-2.5 rounded border border-slate-800">
              {agreement.sha256_hash || 'PENDIENTE DE CONTRA-FIRMA Y SELLADO'}
            </p>
          </div>

          {/* Resultado de la Auditoría Criptográfica en Vivo */}
          {integrityReport && (
            <div
              className={`p-4 rounded-lg border ${
                integrityReport.is_intact
                  ? 'bg-emerald-950/70 border-emerald-500/60 text-emerald-200'
                  : 'bg-rose-950/80 border-rose-500 text-rose-200'
              } space-y-2`}
            >
              <div className="font-bold flex items-center gap-2 text-xs">
                {integrityReport.is_intact ? (
                  <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
                )}
                <span>{integrityReport.message}</span>
              </div>
              <div className="text-[11px] space-y-1 text-slate-300">
                <p>
                  <strong>Hash original almacenado:</strong> {integrityReport.stored_hash}
                </p>
                <p>
                  <strong>Hash recalculado en vivo:</strong> {integrityReport.recomputed_hash}
                </p>
                <p>
                  <strong>Ubicación verificada:</strong> {integrityReport.storage_location}
                </p>
                <p>
                  <strong>Timestamp de verificación:</strong> {integrityReport.verified_at}
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* BARRA DE ACCIONES CONTEXTUALES POR ROL */}
      <div className="mt-8 pt-6 border-t border-slate-200 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">
            Operando como: <strong className="uppercase text-slate-800">{currentRole}</strong>
          </span>

          {/* Botón Rechazar / Archivar Acuerdo (disponible mientras no esté TERMINATED) */}
          {agreement.current_status !== 'TERMINATED' && (
            <button
              type="button"
              onClick={() => setShowTerminateModal(true)}
              disabled={actionLoading}
              className="px-3.5 py-2 border border-rose-300 text-rose-700 bg-rose-50 hover:bg-rose-100 rounded-lg text-xs font-bold flex items-center gap-1.5"
            >
              <ArchiveX className="w-4 h-4" />
              {isSealed ? 'Terminar Vigencia del Acuerdo' : 'Rechazar / Archivar Contrato'}
            </button>
          )}
        </div>

        <div className="flex flex-wrap gap-3">
          {/* Acciones Auditor en DRAFT o REVISION_REQUESTED: Editar y Enviar a Revisión */}
          {currentRole === 'auditor' && isEditable && (
            <>
              {onEdit && (
                <button
                  type="button"
                  onClick={onEdit}
                  disabled={actionLoading}
                  className="px-4 py-2.5 border border-indigo-300 text-indigo-700 bg-indigo-50 rounded-lg text-xs font-bold hover:bg-indigo-100 flex items-center gap-1.5"
                >
                  <Edit3 className="w-4 h-4" />
                  Editar Contrato / Aplicar Correcciones
                </button>
              )}
              <button
                type="button"
                onClick={handleSend}
                disabled={actionLoading}
                className="px-5 py-2.5 bg-indigo-600 text-white rounded-lg text-xs font-bold hover:bg-indigo-700 shadow-sm flex items-center gap-1.5 disabled:opacity-50"
              >
                <Send className="w-4 h-4" />
                {actionLoading ? 'Enviando...' : 'Enviar a Revisión del Cliente'}
              </button>
            </>
          )}

          {/* Acciones Cliente en UNDER_CLIENT_REVIEW: Solicitar Reparos o Aprobar y Firmar */}
          {currentRole === 'client' && agreement.current_status === 'UNDER_CLIENT_REVIEW' && (
            <>
              <button
                type="button"
                onClick={() => setShowRevisionModal(true)}
                disabled={actionLoading}
                className="px-4 py-2.5 border border-orange-300 text-orange-700 bg-orange-50 rounded-lg text-xs font-bold hover:bg-orange-100 flex items-center gap-1.5 disabled:opacity-50"
              >
                <MessageSquare className="w-4 h-4" />
                Solicitar Reparos / Modificaciones
              </button>

              <div className="flex items-center gap-3">
                <label className="text-[11px] text-slate-700 flex items-center gap-1.5 cursor-pointer font-semibold">
                  <input
                    type="checkbox"
                    checked={backupConfirmCheck}
                    onChange={(e) => setBackupConfirmCheck(e.target.checked)}
                    className="rounded text-blue-600"
                  />
                  Certifico respaldos previos (Cláusula 3ª)
                </label>
                <button
                  type="button"
                  onClick={handleApprove}
                  disabled={actionLoading}
                  className="px-5 py-2.5 bg-blue-600 text-white rounded-lg text-xs font-bold hover:bg-blue-700 shadow-sm flex items-center gap-1.5 disabled:opacity-50"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  {actionLoading ? 'Firmando...' : 'Aprobar y Firmar (Cliente)'}
                </button>
              </div>
            </>
          )}

          {/* Acción Auditor en APPROVED_BY_CLIENT: Contra-firmar y Sellar con SHA-256 */}
          {currentRole === 'auditor' && agreement.current_status === 'APPROVED_BY_CLIENT' && (
            <button
              type="button"
              onClick={handleSeal}
              disabled={actionLoading}
              className="px-6 py-2.5 bg-emerald-600 text-white rounded-lg text-xs font-bold hover:bg-emerald-700 shadow-md flex items-center gap-2 disabled:opacity-50"
            >
              <Fingerprint className="w-4 h-4" />
              {actionLoading ? 'Sellando...' : 'Contra-Firmar y Sellar con SHA-256'}
            </button>
          )}

          {/* Cuando el contrato ya está sellado: Acceso directo al Paso 2 (Live Logger & SOC Deconfliction) */}
          {isSealed && onOpenLiveLogger && (
            <button
              type="button"
              onClick={onOpenLiveLogger}
              className="px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-bold shadow-md flex items-center gap-2 transition-colors"
            >
              <ShieldCheck className="w-4 h-4" />
              Ir a Bitácora en Vivo y Desconflicto SOC / ANCI (Paso 2) →
            </button>
          )}
        </div>
      </div>

      {/* Modal de Reparos del Cliente */}
      {showRevisionModal && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl max-w-lg w-full p-6 shadow-2xl border border-slate-200">
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              Devolver con Reparos / Observaciones al Auditor
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              Detalle qué activos, horarios, datos de contacto o cláusulas deben corregirse antes de firmar.
            </p>
            <textarea
              rows={4}
              value={observations}
              onChange={(e) => setObservations(e.target.value)}
              placeholder="Ej: Por favor excluir el subdominio pagos.bancoaustral.cl y ajustar la franja horaria de 23:00 a 05:00 hrs."
              className="w-full px-3 py-2 border border-slate-300 rounded-lg text-xs focus:ring-2 focus:ring-indigo-500 focus:outline-none mb-4"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowRevisionModal(false)}
                className="px-3 py-1.5 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg hover:bg-slate-50"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleRevisionSubmit}
                disabled={actionLoading || !observations.trim()}
                className="px-4 py-1.5 bg-orange-600 text-white text-xs font-bold rounded-lg hover:bg-orange-700 disabled:opacity-50"
              >
                {actionLoading ? 'Enviando...' : 'Devolver al Auditor para Corrección'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal de Rechazo / Archivo / Terminación */}
      {showTerminateModal && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl max-w-lg w-full p-6 shadow-2xl border border-rose-200">
            <h3 className="text-lg font-bold text-rose-900 mb-1">
              {isSealed
                ? 'Terminar Vigencia del Acuerdo RoE'
                : 'Rechazar / Archivar Propuesta de Contrato'}
            </h3>
            <p className="text-xs text-slate-600 mb-4">
              El acuerdo pasará al estado final <strong>TERMINATED</strong> y no permitirá la ejecución de
              pruebas de intrusión. Indique el fundamento formal:
            </p>
            <textarea
              rows={3}
              value={terminateReason}
              onChange={(e) => setTerminateReason(e.target.value)}
              placeholder="Ej: No se alcanzó acuerdo respecto de las ventanas de mantenimiento ni autorización del directorio."
              className="w-full px-3 py-2 border border-slate-300 rounded-lg text-xs focus:ring-2 focus:ring-rose-500 focus:outline-none mb-4"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowTerminateModal(false)}
                className="px-3 py-1.5 border border-slate-300 text-slate-700 text-xs font-medium rounded-lg hover:bg-slate-50"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleTerminateSubmit}
                disabled={actionLoading || !terminateReason.trim()}
                className="px-4 py-1.5 bg-rose-600 text-white text-xs font-bold rounded-lg hover:bg-rose-700 disabled:opacity-50"
              >
                {actionLoading ? 'Procesando...' : 'Confirmar Rechazo / Archivo'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
