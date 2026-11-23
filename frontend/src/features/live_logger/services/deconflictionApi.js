import axios from 'axios';
import { supabase } from '../../../services/supabaseClient';

const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/deconfliction`,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(async (config) => {
  try {
    const activeRole = localStorage.getItem('lexploit_active_role') || 'client';
    config.headers['X-Simulated-Role'] = activeRole;

    const { data } = await supabase.auth.getSession();
    const token = data?.session?.access_token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  } catch (err) {
    console.debug('No active Supabase session for deconfliction request:', err);
  }
  return config;
});

export const deconflictionApi = {
  async matchIncident(queryPayload) {
    const { data } = await apiClient.post('/match', queryPayload);
    return data;
  },

  async listHistory(agreementId) {
    const { data } = await apiClient.get(`/history/${agreementId}`);
    return data;
  },

  async getCertificate(queryId) {
    const { data } = await apiClient.get(`/${queryId}/certificate`);
    return data;
  },

  async clearHistory(agreementId) {
    const { data } = await apiClient.delete(`/history/${agreementId}`);
    return data;
  },

  async deleteQuery(queryId) {
    const { data } = await apiClient.delete(`/${queryId}`);
    return data;
  },
};
