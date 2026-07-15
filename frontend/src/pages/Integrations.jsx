import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try { setIntegrations(await api.getIntegrations()); } catch (e) { console.error(e); }
      setLoading(false);
    };
    load();
  }, []);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Integrations</h1>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Name</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Type</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Status</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Last Sync</th>
              </tr>
            </thead>
            <tbody>
              {integrations.length === 0 && <tr><td colSpan={4} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No integrations configured</td></tr>}
              {integrations.map((i) => (
                <tr key={i.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500 }}>{i.name}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{i.type}</td>
                  <td style={{ padding: '12px 16px' }}><span style={{ background: i.enabled ? '#f0fdf4' : '#f3f4f6', color: i.enabled ? '#16a34a' : '#6b7280', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{i.enabled ? 'Enabled' : 'Disabled'}</span></td>
                  <td style={{ padding: '12px 16px', color: '#6b7280', fontSize: 13 }}>{i.last_sync_at ? new Date(i.last_sync_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Integrations;
