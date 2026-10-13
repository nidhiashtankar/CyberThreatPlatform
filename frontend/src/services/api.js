import axios from 'axios';

// Base API configuration
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

// Centralized API Service functions
export const api = {
  // Stats
  getStats: async () => {
    const res = await apiClient.get('/stats/dashboard');
    return res.data;
  },

  // Alerts
  getAlerts: async (params = {}) => {
    const res = await apiClient.get('/alerts', { params });
    return res.data;
  },
  getAlertDetail: async (alertId) => {
    const res = await apiClient.get(`/alerts/${alertId}`);
    return res.data;
  },

  // Incidents
  getIncidents: async (params = {}) => {
    const res = await apiClient.get('/incidents', { params });
    return res.data;
  },
  getIncidentDetail: async (incidentId, applyDecay = false) => {
    const res = await apiClient.get(`/incidents/${incidentId}`, {
      params: { apply_decay: applyDecay }
    });
    return res.data;
  },
  getIncidentGraph: async (incidentId) => {
    const res = await apiClient.get(`/incidents/${incidentId}/graph`);
    return res.data;
  },
  submitFeedback: async (incidentId, data) => {
    const res = await apiClient.post(`/incidents/${incidentId}/feedback`, data);
    return res.data;
  },
  submitResponse: async (incidentId, data) => {
    const res = await apiClient.post(`/incidents/${incidentId}/respond`, data);
    return res.data;
  },

  // Detection & Ingestion
  ingestEvent: async (eventPayload) => {
    const res = await apiClient.post('/events/ingest', eventPayload);
    return res.data;
  },
  detectPhishingUrl: async (url) => {
    const res = await apiClient.post('/detect/phishing-url', { url });
    return res.data;
  },
  getEvents: async (params = {}) => {
    const res = await apiClient.get('/events', { params });
    return res.data;
  },
};

export default api;
