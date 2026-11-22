import { useCallback, useState } from 'react';
import { loggerApi } from '../services/loggerApi';

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

export function useLiveAssessmentLogger() {
  const [logs, setLogs] = useState([]);
  const [summary, setSummary] = useState({
    total_logs: 0,
    critical_findings_count: 0,
    ongoing_tests_count: 0,
  });
  const [lastBreakGlassAlert, setLastBreakGlassAlert] = useState(null);
  const [lastScopeWarnings, setLastScopeWarnings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchLogs = useCallback(async (agreementId, filters = {}) => {
    if (!agreementId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await loggerApi.listAgreementLogs(agreementId, filters);
      setLogs(data.logs || []);
      setSummary(
        data.summary || {
          total_logs: (data.logs || []).length,
          critical_findings_count: 0,
          ongoing_tests_count: 0,
        }
      );
      return data;
    } catch (err) {
      setError(formatApiError(err, 'Error al cargar la bitácora de telemetría'));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const createLog = async (payload) => {
    setLoading(true);
    setError(null);
    try {
      const data = await loggerApi.createLog(payload);
      setLogs((prev) => [data.log, ...prev]);
      setSummary((prev) => ({
        total_logs: prev.total_logs + 1,
        critical_findings_count:
          prev.critical_findings_count + (data.log?.is_critical_finding ? 1 : 0),
        ongoing_tests_count: prev.ongoing_tests_count + (data.log?.ended_at ? 0 : 1),
      }));
      if (data.break_glass_alert) {
        setLastBreakGlassAlert(data.break_glass_alert);
      }
      setLastScopeWarnings(Array.isArray(data.scope_warnings) ? data.scope_warnings : []);
      return data;
    } catch (err) {
      const msg = formatApiError(err, 'Error al registrar prueba en la bitácora');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  const finishLog = async (logId, options = {}) => {
    setLoading(true);
    setError(null);
    try {
      const data = await loggerApi.finishLog(logId, options);
      setLogs((prev) => prev.map((l) => (l.id === logId ? data.log : l)));
      setSummary((prev) => ({
        ...prev,
        ongoing_tests_count: Math.max(0, prev.ongoing_tests_count - 1),
      }));
      return data;
    } catch (err) {
      const msg = formatApiError(err, 'Error al finalizar registro en curso');
      setError(msg);
      throw new Error(msg);
    } finally {
      setLoading(false);
    }
  };

  return {
    logs,
    summary,
    lastBreakGlassAlert,
    clearBreakGlassAlert: () => setLastBreakGlassAlert(null),
    lastScopeWarnings,
    clearScopeWarnings: () => setLastScopeWarnings([]),
    loading,
    error,
    fetchLogs,
    createLog,
    finishLog,
  };
}
