import { useCallback, useState } from 'react';
import { deconflictionApi } from '../services/deconflictionApi';

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

export function useDeconflictionSearch() {
  const [matchResult, setMatchResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeCertificate, setActiveCertificate] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHistory = useCallback(async (agreementId) => {
    if (!agreementId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await deconflictionApi.listHistory(agreementId);
      setHistory(data.queries || []);
      return data.queries;
    } catch (err) {
      setError(formatApiError(err, 'Error al cargar el historial de consultas del SOC'));
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  const executeMatch = async (queryPayload) => {
    setLoading(true);
    setError(null);
    try {
      const data = await deconflictionApi.matchIncident(queryPayload);
      setMatchResult(data);
      if (data.query) {
        setHistory((prev) => [data.query, ...prev]);
      }
      return data;
    } catch (err) {
      const msg = formatApiError(err, 'Error al ejecutar correlación de desconflicto');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const loadCertificate = async (queryId) => {
    setLoading(true);
    setError(null);
    try {
      const cert = await deconflictionApi.getCertificate(queryId);
      setActiveCertificate(cert);
      return cert;
    } catch (err) {
      const msg = formatApiError(err, 'Error al generar el comprobante digital ANCI');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const clearHistory = async (agreementId) => {
    if (!agreementId) return;
    setLoading(true);
    setError(null);
    try {
      await deconflictionApi.clearHistory(agreementId);
      setHistory([]);
      setMatchResult(null);
    } catch (err) {
      const msg = formatApiError(err, 'Error al limpiar el historial de consultas de desconflicto');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const deleteQuery = async (queryId) => {
    if (!queryId) return;
    setLoading(true);
    setError(null);
    try {
      await deconflictionApi.deleteQuery(queryId);
      setHistory((prev) => prev.filter((item) => item.id !== queryId));
      setMatchResult((prev) => (prev?.query?.id === queryId ? null : prev));
    } catch (err) {
      const msg = formatApiError(err, 'Error al eliminar la consulta de desconflicto');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  return {
    matchResult,
    clearMatchResult: () => setMatchResult(null),
    history,
    activeCertificate,
    closeCertificate: () => setActiveCertificate(null),
    loading,
    error,
    fetchHistory,
    executeMatch,
    loadCertificate,
    clearHistory,
    deleteQuery,
  };
}
