import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Dashboard
export const getDashboardStats = async () => {
  // Mock data since endpoint doesn't exist yet
  return {
    total_guardrails: 5,
    active_evaluations: 23,
    total_users: 8,
    pass_rate: 94,
    recent_activity: [
      'Guardrail "Content Filter" evaluated 5 minutes ago',
      'User "admin" created new guardrail "PII Detection"',
      'System health check passed',
      'Database backup completed successfully'
    ]
  }
}

// Guardrails
export const getGuardrails = async () => {
  const response = await api.get('/guardrails')
  return response.data
}

export const getGuardrail = async (id) => {
  const response = await api.get(`/guardrails/${id}`)
  return response.data
}

export const createGuardrail = async (data) => {
  const response = await api.post('/guardrails', data)
  return response.data
}

export const updateGuardrail = async (id, data) => {
  const response = await api.put(`/guardrails/${id}`, data)
  return response.data
}

export const deleteGuardrail = async (id) => {
  const response = await api.delete(`/guardrails/${id}`)
  return response.data
}

export const getGuardrailRules = async (guardrailId) => {
  const response = await api.get(`/guardrails/${guardrailId}/rules`)
  return response.data
}

export const createGuardrailRule = async (guardrailId, data) => {
  const response = await api.post(`/guardrails/${guardrailId}/rules`, data)
  return response.data
}

// Users
export const getUsers = async () => {
  const response = await api.get('/users')
  return response.data
}

export const getUser = async (id) => {
  const response = await api.get(`/users/${id}`)
  return response.data
}

export const createUser = async (data) => {
  const response = await api.post('/users', data)
  return response.data
}

export const updateUser = async (id, data) => {
  const response = await api.put(`/users/${id}`, data)
  return response.data
}

export const deleteUser = async (id) => {
  // Mock delete since full CRUD isn't implemented yet
  console.log(`Deleting user ${id}`)
  return { message: 'User deleted successfully' }
}

export default api
