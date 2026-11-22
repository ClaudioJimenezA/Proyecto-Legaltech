import axios from 'axios';
import { supabase } from '../../../services/supabaseClient';

const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/logs`,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(async (config) => {
  try {
    const activeRole = localStorage.getItem('lexploit_active_role') || 'auditor';
    config.headers['X-Simulated-Role'] = activeRole;

    const { data } = await supabase.auth.getSession();
    const token = data?.session?.access_token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (err) {
    console.debug('No active Supabase session for logger request:', err);
  }
  return config;
});

export const loggerApi = {
  async createLog(logPayload) {
    const { data } = await apiClient.post('', logPayload);
    return data;
  },

  async listAgreementLogs(agreementId, filters = {}) {
    const params = {};
    if (filters.sourceIp) params.source_ip = filters.sourceIp;
    if (filters.activityType) params.activity_type = filters.activityType;
    if (filters.targetHost) params.target_host = filters.targetHost;
    if (filters.criticalOnly) params.critical_only = true;

    const { data } = await apiClient.get(`/active/${agreementId}`, { params });
    return data;
  },

  async finishLog(logId, { endedAt, systemImpactObserved } = {}) {
    const { data } = await apiClient.patch(`/${logId}/finish`, {
      ended_at: endedAt || new Date().toISOString(),
      system_impact_observed: systemImpactObserved || null,
    });
    return data;
  },
};
