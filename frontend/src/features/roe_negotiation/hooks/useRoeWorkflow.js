import { useCallback, useState } from 'react';
import { roeApi } from '../services/roeApi';

function formatApiError(err, fallback) {
  const detail = err?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === 'string') return item;
        const field = Array.isArray(item?.loc) ? item.loc.slice(1).join('.') : '';
        return field ? `${field}: ${item.msg}` : item?.msg || JSON.stringify(item);
      })
      .join(' | ');
  }
  if (detail && typeof detail === 'object') {
    return detail.msg || JSON.stringify(detail);
  }
  return err?.message || fallback;
}

export function useRoeWorkflow() {
  const [agreements, setAgreements] = useState([]);
  const [currentAgreement, setCurrentAgreement] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchAgreements = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await roeApi.listAgreements();
      setAgreements(list);
    } catch (err) {
      setError(formatApiError(err, 'Error al cargar acuerdos'));
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchAgreement = useCallback(async (id) => {
    setLoading(true);
    setError(null);
    try {
      const data = await roeApi.getAgreement(id);
      setCurrentAgreement(data.agreement);
      setCompliance(data.art2_compliance);
      return data;
    } catch (err) {
      setError(formatApiError(err, 'Error al obtener el acuerdo'));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const createProposal = async (proposalData) => {
    setLoading(true);
    setError(null);
    try {
      const agreement = await roeApi.createProposal(proposalData);
      setAgreements((prev) => [agreement, ...prev]);
      setCurrentAgreement(agreement);
      return agreement;
    } catch (err) {
      const msg = formatApiError(err, 'Error al crear propuesta');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const updateProposal = async (id, proposalData) => {
    setLoading(true);
    setError(null);
    try {
      const res = await roeApi.updateProposal(id, proposalData);
      setCurrentAgreement(res.agreement);
      setCompliance(res.art2_compliance);
      setAgreements((prev) => prev.map((a) => (a.id === id ? res.agreement : a)));
      return res.agreement;
    } catch (err) {
      const msg = formatApiError(err, 'Error al actualizar propuesta');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const sendToClient = async (id) => {
    setLoading(true);
    setError(null);
    try {
      const updated = await roeApi.sendToClient(id);
      setCurrentAgreement(updated);
      setAgreements((prev) => prev.map((a) => (a.id === id ? updated : a)));
      return updated;
    } catch (err) {
      const msg = formatApiError(err, 'Error al enviar a revisión del auditor');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const requestRevision = async (id, observations) => {
    setLoading(true);
    setError(null);
    try {
      const res = await roeApi.requestRevision(id, observations);
      setCurrentAgreement(res.agreement);
      setAgreements((prev) => prev.map((a) => (a.id === id ? res.agreement : a)));
      return res;
    } catch (err) {
      const msg = formatApiError(err, 'Error al solicitar reparos');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const clientApprove = async (id, approvalData) => {
    setLoading(true);
    setError(null);
    try {
      const updated = await roeApi.clientApprove(id, approvalData);
      setCurrentAgreement(updated);
      setAgreements((prev) => prev.map((a) => (a.id === id ? updated : a)));
      return updated;
    } catch (err) {
      const msg = formatApiError(err, 'Error al aprobar acuerdo');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const sealAgreement = async (id, options = {}) => {
    setLoading(true);
    setError(null);
    try {
      const res = await roeApi.sealAgreement(id, options);
      setCurrentAgreement(res.agreement);
      setCompliance(res.art2_compliance);
      setAgreements((prev) => prev.map((a) => (a.id === id ? res.agreement : a)));
      return res;
    } catch (err) {
      const msg = formatApiError(err, 'Error al sellar el acuerdo');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const terminateAgreement = async (id, reason) => {
    setLoading(true);
    setError(null);
    try {
      const res = await roeApi.terminateAgreement(id, reason);
      setCurrentAgreement(res.agreement);
      setCompliance(res.art2_compliance);
      setAgreements((prev) => prev.map((a) => (a.id === id ? res.agreement : a)));
      return res;
    } catch (err) {
      const msg = formatApiError(err, 'Error al rechazar o archivar el acuerdo');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const verifyIntegrity = async (id) => {
    return await roeApi.verifyIntegrity(id);
  };

  const downloadContractPdf = async (id, title = 'Contrato_RoE') => {
    try {
      const pdfBlob = await roeApi.downloadContractPdf(id);
      const url = URL.createObjectURL(new Blob([pdfBlob], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      const safeTitle = title.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 35);
      a.download = `Contrato_RoE_NDA_${safeTitle}_${id.slice(0, 8).toUpperCase()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(formatApiError(err, 'Error al exportar el contrato RoE a PDF'));
    }
  };

  const openContractPrintableHtml = async (id) => {
    try {
      const htmlStr = await roeApi.fetchContractPrintableHtml(id);
      const win = window.open('', '_blank');
      if (win) {
        win.document.write(htmlStr);
        win.document.close();
      }
    } catch (err) {
      setError(formatApiError(err, 'Error al abrir vista imprimible del contrato RoE'));
    }
  };

  return {
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
  };
}
