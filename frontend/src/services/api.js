const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

class ApiClient {
  constructor() {
    this.baseUrl = `${API_BASE}/api/v1`;
  }

  getToken() {
    return localStorage.getItem('access_token');
  }

  setToken(token) {
    if (token) localStorage.setItem('access_token', token);
    else localStorage.removeItem('access_token');
  }

  async request(path, options = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    };

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (res.status === 401 && path !== '/auth/login') {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
      throw new Error('Unauthorized');
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.error || 'Request failed');
    return data;
  }

  get(path) { return this.request(path); }
  post(path, body) { return this.request(path, { method: 'POST', body: JSON.stringify(body) }); }
  put(path, body) { return this.request(path, { method: 'PUT', body: JSON.stringify(body) }); }
  del(path) { return this.request(path, { method: 'DELETE' }); }

  // Auth
  login(email, password) { return this.post('/auth/login', { email, password }); }
  register(data) { return this.post('/auth/register', data); }
  me() { return this.get('/auth/me'); }
  forgotPassword(email) { return this.post('/auth/forgot-password', { email }); }
  resetPassword(token, password) { return this.post('/auth/reset-password', { token, password }); }
  invalidateSessions() { return this.post('/auth/sessions/invalidate'); }

  // MFA
  mfaSetup() { return this.post('/auth/mfa/setup'); }
  mfaVerify(code) { return this.post('/auth/mfa/verify', { code }); }
  mfaDisable(password) { return this.post('/auth/mfa/disable', { password }); }
  mfaChallenge(sessionToken, code) { return this.post('/auth/mfa/challenge', { session_token: sessionToken, code }); }

  // Users
  getUsers() { return this.get('/users'); }

  // Policies
  getPolicies() { return this.get('/policies'); }
  createPolicy(data) { return this.post('/policies', data); }

  // Guardrails
  evaluatePrompt(prompt, toolId) { return this.post('/guardrails/evaluate/prompt', { prompt, tool_id: toolId }); }
  evaluateOutput(prompt, output, toolId) { return this.post('/guardrails/evaluate/output', { prompt, output, tool_id: toolId }); }
  getGuardrailLogs(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/guardrails/logs?${q}`);
  }
  getGuardrailStats() { return this.get('/guardrails/stats'); }
  getGuardrailRules() { return this.get('/guardrails/rules'); }
  createGuardrailRule(data) { return this.post('/guardrails/rules', data); }

  // API Keys
  getApiKeys() { return this.get('/api-keys'); }
  createApiKey(data) { return this.post('/api-keys', data); }
  deleteApiKey(id) { return this.del(`/api-keys/${id}`); }
  rotateApiKey(id) { return this.post(`/api-keys/${id}/rotate`); }
  revokeApiKey(id) { return this.post(`/api-keys/${id}/revoke`); }
  getKeyRateLimit(id) { return this.get(`/api-keys/${id}/rate-limit`); }

  // Webhooks
  getWebhooks() { return this.get('/webhooks'); }
  createWebhook(data) { return this.post('/webhooks', data); }
  deleteWebhook(id) { return this.del(`/webhooks/${id}`); }
  testWebhook(id) { return this.post(`/webhooks/${id}/test`); }

  // Audit
  getAuditLogs(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/audit?${q}`);
  }

  // Reports
  getReports() { return this.get('/reporting'); }
  createReport(data) { return this.post('/reporting', data); }

  // Integrations
  getIntegrations() { return this.get('/integrations'); }

  // Incidents
  getIncidents(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/incidents?${q}`);
  }

  // Inventory
  getInventory(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/inventory?${q}`);
  }

  // Health
  getHealth() { return this.get('/health'); }
  getHealthComponents() { return this.get('/health/components'); }

  // Dashboard stats
  async getDashboardStats() {
    const [guardrailStats, health] = await Promise.all([
      this.getGuardrailStats().catch(() => null),
      this.getHealthComponents().catch(() => null),
    ]);
    return {
      total_guardrails: guardrailStats?.total_evaluations || 0,
      active_evaluations: guardrailStats?.blocked || 0,
      total_users: 0,
      pass_rate: guardrailStats?.pass_rate || 0,
      recent_activity: [],
      health,
    };
  }
}

export const api = new ApiClient();
