import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const Webhooks = () => {
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ url: '', events: '', secret: '' });

  const load = async () => {
    try { setWebhooks(await api.getWebhooks()); } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await api.createWebhook({ ...form, events: form.events.split(',').map((s) => s.trim()) });
      setShowForm(false);
      setForm({ url: '', events: '', secret: '' });
      load();
    } catch (err) { alert(err.message); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this webhook?')) return;
    try { await api.deleteWebhook(id); load(); } catch (err) { alert(err.message); }
  };

  const handleTest = async (id) => {
    try { await api.testWebhook(id); alert('Test event sent!'); } catch (err) { alert(err.message); }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ margin: 0, fontSize: 24 }}>Webhooks</h1>
        <button onClick={() => setShowForm(!showForm)} style={{ padding: '8px 16px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>
          {showForm ? 'Cancel' : 'New Webhook'}
        </button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} style={{ background: '#fff', padding: 20, borderRadius: 10, marginBottom: 24, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
          <div style={{ display: 'grid', gap: 16 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>URL</label>
              <input type="url" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required placeholder="https://hooks.example.com/events" style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Events (comma-separated)</label>
              <input value={form.events} onChange={(e) => setForm({ ...form, events: e.target.value })} required placeholder="evaluation.completed,incident.created" style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Secret (for HMAC signing)</label>
              <input value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
          </div>
          <button type="submit" style={{ marginTop: 16, padding: '8px 16px', background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>Create Webhook</button>
        </form>
      )}

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>URL</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Events</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.length === 0 && <tr><td colSpan={3} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No webhooks configured</td></tr>}
              {webhooks.map((w) => (
                <tr key={w.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{w.url}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{(w.events || []).join(', ')}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <button onClick={() => handleTest(w.id)} style={{ padding: '4px 8px', border: '1px solid #d1d5db', borderRadius: 4, background: '#fff', cursor: 'pointer', fontSize: 12, marginRight: 6 }}>Test</button>
                    <button onClick={() => handleDelete(w.id)} style={{ padding: '4px 8px', border: '1px solid #ef4444', borderRadius: 4, background: '#fef2f2', cursor: 'pointer', fontSize: 12 }}>Delete</button>
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

export default Webhooks;
