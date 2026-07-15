import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const AuditLog = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ action: '', limit: 50, offset: 0 });

  const load = async () => {
    try { setLogs(await api.getAuditLogs(filter)); } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Audit Log</h1>

      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <input placeholder="Filter by action..." value={filter.action} onChange={(e) => setFilter({ ...filter, action: e.target.value, offset: 0 })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, flex: 1 }} />
        <button onClick={() => setFilter({ ...filter, offset: Math.max(0, filter.offset - filter.limit) }} disabled={filter.offset === 0} style={{ padding: '8px 12px', background: '#fff', border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Prev</button>
        <button onClick={() => setFilter({ ...filter, offset: filter.offset + filter.limit })} style={{ padding: '8px 12px', background: '#fff', border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Next</button>
      </div>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Timestamp</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>User</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Action</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Resource</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>IP</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && <tr><td colSpan={5} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No audit log entries</td></tr>}
              {logs.map((l, i) => (
                <tr key={l.id || i} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontSize: 13, fontFamily: 'monospace' }}>{l.created_at ? new Date(l.created_at).toLocaleString() : '—'}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{l.user_email || l.user_id || 'system'}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}><span style={{ background: '#eff6ff', color: '#2563eb', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>{l.action}</span></td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{l.resource}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{l.ip_address || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default AuditLog;
