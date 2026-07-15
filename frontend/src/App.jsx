import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Guardrails from './pages/Guardrails'
import GuardrailDetail from './pages/GuardrailDetail'
import Users from './pages/Users'
import Login from './pages/Login'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import Policies from './pages/Policies'
import ApiKeys from './pages/ApiKeys'
import Webhooks from './pages/Webhooks'
import AuditLog from './pages/AuditLog'
import Reports from './pages/Reports'
import Integrations from './pages/Integrations'
import Incidents from './pages/Incidents'
import Inventory from './pages/Inventory'
import Settings from './pages/Settings'
import Admin from './pages/Admin'
import GuardrailLogs from './pages/GuardrailLogs'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000,
    },
  },
})

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Layout>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password/:token" element={<ResetPassword />} />
            <Route path="/" element={<Dashboard />} />
            <Route path="/guardrails" element={<Guardrails />} />
            <Route path="/guardrails/:id" element={<GuardrailDetail />} />
            <Route path="/guardrail-logs" element={<GuardrailLogs />} />
            <Route path="/users" element={<Users />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/api-keys" element={<ApiKeys />} />
            <Route path="/webhooks" element={<Webhooks />} />
            <Route path="/audit-log" element={<AuditLog />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/admin" element={<Admin />} />
          </Routes>
        </Layout>
      </Router>
    </QueryClientProvider>
  )
}

export default App
