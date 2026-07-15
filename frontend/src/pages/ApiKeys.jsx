import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const ApiKeys = () => {
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [newKey, setNewKey] = useState('');
  const [form, setForm] = useState({ name: '', rate_limit: 60 });
  const [rateLimits, setRateLimits] = useState({});

  const load = async () => {
    try {
      const k = await api.getApiKeys();
      setKeys(k);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const res = await api.createApiKey(form);
      setNewKey(res.key || '');
      setShowForm(false);
      setForm({ name: '', rate_limit: 60 });
      load();
    } catch (err) { alert(err.message); }
  };

  const handleRotate = async (id) => {
    try {
      const res = await api.rotateApiKey(id);
      alert(`New key: ${res.key}\n\nSave this immediately — it won't be shown again.`);
      load();
    } catch (err) { alert(err.message); }
  };

  const handleRevoke = async (id) => {
    if (!confirm('Revoke this API key? This cannot be undone.')) return;
    try { await api.revokeApiKey(id); load(); } catch (err) { alert(err.message); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this API key?')) return;
    try { await api.deleteApiKey(id); load(); } catch (err) { alert(err.message); }
  };

  const checkRateLimit = async (id) => {
    try {
      const rl = await api.getKeyRateLimit(id);
      setRateLimits((prev) => ({ ...prev, [id]: rl }));
    } catch (err) { alert(err.message); }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ margin: 0, fontSize: 24 }}>API Keys</h1>
        <button onClick={() => setShowForm(!showForm)} style={{ padding: '8px 16px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
          {showForm ? 'Cancel' : 'New API Key'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} style={{ background: '#fff', padding: 20, borderRadius: 10, marginBottom: 24, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Name</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Rate Limit (req/min)</label>
              <input type="number" value={form.rate_limit} onChange={(e) => setForm({ ...form, rate_limit: +e.target.value })} min={1} max={10000} style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
          </div>
          <button type="submit" style={{ marginTop: 16, padding: '8px 16px', background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>Generate Key</button>
        </form>
      )}

      {newKey && (
        <div style={{ background: '#fefce8', border: '1px solid #fde047', borderRadius: 10, padding: 16, marginBottom: 24 }}>
          <strong style={{ color: '#854d0e', fontSize: 13 }}>Save this key — it won't be shown again:</strong>
          <div style={{ fontFamily: 'monospace', background: '#fff', padding: 12, borderRadius: 6, marginTop: 8, fontSize: 13, wordBreak: 'break-all' }}>{newKey}</div>
        </div>
      )}

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Name</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Status</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Created</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.length === 0 && <tr><td colSpan={4} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No API keys</td></tr>}
              {keys.map((k) => (
                <tr key={k.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500 }}>{k.name}</td>
                  <td style={{ padding: '12px 16px' }}>{k.revoked ? <span style={{ color: '#ef4444' }}>Revoked</span> : <span style={{ color: '#22c55e' }}>Active</span>}</td>
                  <td style={{ padding: '12px 16px', color: '#6b7280', fontSize: 13 }}>{k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <button onClick={() => checkRateLimit(k.id)} style={{ padding: '4px 8px', border: '1px solid #d1d5db', borderRadius: 4, background: '#fff', cursor: 'pointer', fontSize: 12, marginRight: 6 }}>Rate Limit</button>
                    <button onClick={() => handleRotate(k.id)} style={{ padding: '4px 8px', border: '1px solid #f59e0b', borderRadius: 4, background: '#fff', cursor: 'pointer', fontSize: 12, marginRight: 6 }}>Rotate</button>
                    {!k.revoked && <button onClick={() => handleRevoke(k.id)} style={{ padding: '4px 8px', border: '1px solid #ef4444', borderRadius: 4, background: '#fff', cursor: 'pointer', fontSize: 12, marginRight: 6 }}>Revoke</button>}
                    <button onClick={() => handleDelete(k.id)} style={{ padding: '4px 8px', border: '1px solid #ef4444', borderRadius: 4, background: '#fef2f2', cursor: 'pointer', fontSize: 12 }}>Delete</button>
                    {rateLimits[k.id] && <div style={{ fontSize: 11, color: '#6b7280', marginTop: 4 }}>Used: {rateLimits[k.id].current}/{rateLimits[k.id].limit} ({rateLimits[k.id].remaining} remaining)</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ApiKeys;
