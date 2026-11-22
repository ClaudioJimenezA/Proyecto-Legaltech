import axios from 'axios';
import { supabase } from '../../../services/supabaseClient';

const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/roe`,
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
    console.debug('No active Supabase session for RoE request:', err);
  }
  return config;
});

export const roeApi = {
  async listAgreements() {
    const { data } = await apiClient.get('/');
    return data.agreements;
  },

  async getAgreement(id) {
    const { data } = await apiClient.get(`/${id}`);
    return data;
  },

  async createProposal(proposalData) {
    const { data } = await apiClient.post('/proposals', proposalData);
    return data.agreement;
  },

  async updateProposal(id, proposalData) {
    const { data } = await apiClient.put(`/${id}`, proposalData);
    return data;
  },

  async sendToClient(id) {
    const { data } = await apiClient.post(`/${id}/send-to-client`);
    return data.agreement;
  },

  async requestRevision(id, observations) {
    const { data } = await apiClient.post(`/${id}/request-revision`, { observations });
    return data;
  },

  async clientApprove(id, { backupConfirmed, cloudAuthorizationConfirmed }) {
    const { data } = await apiClient.post(`/${id}/client-approve`, {
      backup_confirmed: backupConfirmed,
      cloud_authorization_confirmed: cloudAuthorizationConfirmed,
    });
    return data.agreement;
  },

  async sealAgreement(id, { activateImmediately = true } = {}) {
    const { data } = await apiClient.post(`/${id}/seal`, {
      activate_immediately: activateImmediately,
    });
    return data;
  },

  async terminateAgreement(id, reason) {
    const { data } = await apiClient.post(`/${id}/terminate`, { reason });
    return data;
  },

  async verifyIntegrity(id) {
    const { data } = await apiClient.get(`/${id}/verify-integrity`);
    return data;
  },

  async downloadContractPdf(id) {
    const response = await apiClient.get(`/${id}/export-pdf`, {
      params: { format: 'pdf' },
      responseType: 'blob',
    });
    return response.data;
  },

  async fetchContractPrintableHtml(id) {
    const { data } = await apiClient.get(`/${id}/export-pdf`, {
      params: { format: 'html' },
      responseType: 'text',
    });
    return data;
  },
};
