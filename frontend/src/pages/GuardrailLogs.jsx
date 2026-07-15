import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const GuardrailLogs = () => {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ result: '', limit: 50, offset: 0 });

  const load = async () => {
    try {
      const [l, s] = await Promise.all([
        api.getGuardrailLogs(filter),
        api.getGuardrailStats(),
      ]);
      setLogs(l);
      setStats(s);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Guardrail Logs</h1>

      {stats && (
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 24 }}>
          <div style={{ background: '#fff', borderRadius: 8, padding: '12px 20px', flex: 1, minWidth: 120, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Total Evaluations</div>
            <div style={{ fontSize: 22, fontWeight: 700 }}>{stats.total_evaluations || 0}</div>
          </div>
          <div style={{ background: '#fff', borderRadius: 8, padding: '12px 20px', flex: 1, minWidth: 120, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Blocked</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#ef4444' }}>{stats.blocked || 0}</div>
          </div>
          <div style={{ background: '#fff', borderRadius: 8, padding: '12px 20px', flex: 1, minWidth: 120, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Pass Rate</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#22c55e' }}>{stats.pass_rate != null ? `${(stats.pass_rate * 100).toFixed(1)}%` : '—'}</div>
          </div>
          <div style={{ background: '#fff', borderRadius: 8, padding: '12px 20px', flex: 1, minWidth: 120, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
            <div style={{ fontSize: 12, color: '#6b7280' }}>Flagged</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#f59e0b' }}>{stats.flagged || 0}</div>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <select value={filter.result} onChange={(e) => setFilter({ ...filter, result: e.target.value, offset: 0 })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, background: '#fff' }}>
          <option value="">All Results</option>
          <option value="pass">Pass</option>
          <option value="block">Block</option>
          <option value="flag">Flag</option>
        </select>
        <button onClick={() => setFilter({ ...filter, offset: Math.max(0, filter.offset - filter.limit) })} disabled={filter.offset === 0} style={{ padding: '8px 12px', background: '#fff', border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Prev</button>
        <button onClick={() => setFilter({ ...filter, offset: filter.offset + filter.limit })} style={{ padding: '8px 12px', background: '#fff', border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Next</button>
      </div>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Timestamp</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Result</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Tool</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Risk Score</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Triggers</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && <tr><td colSpan={5} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No guardrail logs</td></tr>}
              {logs.map((l, i) => (
                <tr key={l.id || i} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontSize: 13, fontFamily: 'monospace' }}>{l.created_at ? new Date(l.created_at).toLocaleString() : '—'}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{
                      background: l.result === 'pass' ? '#f0fdf4' : l.result === 'block' ? '#fef2f2' : '#fefce8',
                      color: l.result === 'pass' ? '#16a34a' : l.result === 'block' ? '#dc2626' : '#ca8a04',
                      padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 600
                    }}>{l.result}</span>
                  </td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{l.tool_id || '—'}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13, fontFamily: 'monospace' }}>{l.risk_score != null ? l.risk_score.toFixed(2) : '—'}</td>
                  <td style={{ padding: '12px 16px', fontSize: 12, color: '#6b7280' }}>{l.triggers ? l.triggers.join(', ') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default GuardrailLogs;
