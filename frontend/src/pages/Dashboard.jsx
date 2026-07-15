import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const StatCard = ({ label, value, color }) => (
  <div style={{ background: '#fff', borderRadius: 10, padding: 20, flex: 1, minWidth: 180, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
    <div style={{ fontSize: 13, color: '#6b7280', marginBottom: 8 }}>{label}</div>
    <div style={{ fontSize: 28, fontWeight: 700, color }}>{value ?? '—'}</div>
  </div>
);

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [health, setHealth] = useState(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [d, h] = await Promise.all([
          api.getDashboardStats(),
          api.getHealthComponents().catch(() => null),
        ]);
        setStats(d);
        setHealth(h);
      } catch (e) { console.error(e); }
      setLoading(false);
    };
    load();
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Dashboard</h1>

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 32 }}>
        <StatCard label="Evaluations Today" value={stats?.total_guardrails} color="#6366f1" />
        <StatCard label="Prompt Blocks" value={stats?.active_evaluations} color="#ef4444" />
        <StatCard label="Pass Rate" value={stats?.pass_rate != null ? `${(stats.pass_rate * 100).toFixed(1)}%` : '—'} color="#22c55e" />
        <StatCard label="Active Users" value={stats?.total_users} color="#f59e0b" />
      </div>

      {health && (
        <div style={{ background: '#fff', borderRadius: 10, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', marginBottom: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>System Health</h3>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {Object.entries(health).map(([name, status]) => (
              <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: status === 'healthy' ? '#f0fdf4' : '#fef2f2', borderRadius: 6, fontSize: 13 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: status === 'healthy' ? '#22c55e' : '#ef4444', display: 'inline-block' }} />
                {name}: {status}
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ background: '#fff', borderRadius: 10, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        <h3 style={{ margin: '0 0 12px', fontSize: 16 }}>Quick Actions</h3>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <QuickAction icon="🛡️" label="Evaluate Prompt" to="/guardrails" />
          <QuickAction icon="📋" label="Create Policy" to="/policies" />
          <QuickAction icon="🔑" label="Generate API Key" to="/api-keys" />
          <QuickAction icon="📝" label="View Audit Log" to="/audit-log" />
        </div>
      </div>
    </div>
  );
};

const QuickAction = ({ icon, label, to }) => (
  <a href={to} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', background: '#f5f6fa', borderRadius: 8, color: '#374151', textDecoration: 'none', fontSize: 13 }}>
    <span>{icon}</span>
    <span>{label}</span>
  </a>
);

export default Dashboard;
