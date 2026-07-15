import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const severityColors = {
  critical: { bg: '#fef2f2', color: '#dc2626' },
  high: { bg: '#fff7ed', color: '#ea580c' },
  medium: { bg: '#fefce8', color: '#ca8a04' },
  low: { bg: '#f0fdf4', color: '#16a34a' },
};

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ severity: '', status: '', limit: 50 });

  const load = async () => {
    try { setIncidents(await api.getIncidents(filter)); } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Incidents</h1>

      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <select value={filter.severity} onChange={(e) => setFilter({ ...filter, severity: e.target.value })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, background: '#fff' }}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, background: '#fff' }}>
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="closed">Closed</option>
        </select>
      </div>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Title</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Severity</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Status</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Source</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Created</th>
              </tr>
            </thead>
            <tbody>
              {incidents.length === 0 && <tr><td colSpan={5} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No incidents found</td></tr>}
              {incidents.map((inc) => {
                const s = severityColors[inc.severity] || severityColors.medium;
                return (
                  <tr key={inc.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 500 }}>{inc.title}</td>
                    <td style={{ padding: '12px 16px' }}><span style={{ background: s.bg, color: s.color, padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 600 }}>{inc.severity}</span></td>
                    <td style={{ padding: '12px 16px', fontSize: 13 }}>{inc.status}</td>
                    <td style={{ padding: '12px 16px', fontSize: 13 }}>{inc.source || '—'}</td>
                    <td style={{ padding: '12px 16px', color: '#6b7280', fontSize: 13 }}>{inc.created_at ? new Date(inc.created_at).toLocaleString() : '—'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Incidents;
