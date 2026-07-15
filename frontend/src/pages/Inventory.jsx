import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const Inventory = () => {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({ type: '', search: '' });

  const load = async () => {
    try { setItems(await api.getInventory(filter)); } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Inventory</h1>

      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        <input placeholder="Search..." value={filter.search} onChange={(e) => setFilter({ ...filter, search: e.target.value })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, flex: 1 }} />
        <select value={filter.type} onChange={(e) => setFilter({ ...filter, type: e.target.value })} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, background: '#fff' }}>
          <option value="">All Types</option>
          <option value="ai_model">AI Model</option>
          <option value="tool">Tool</option>
          <option value="agent">Agent</option>
          <option value="endpoint">Endpoint</option>
          <option value="data_source">Data Source</option>
        </select>
      </div>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Name</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Type</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Risk Level</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && <tr><td colSpan={4} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No inventory items</td></tr>}
              {items.map((item) => (
                <tr key={item.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500 }}>{item.name}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{item.type}</td>
                  <td style={{ padding: '12px 16px' }}><span style={{ background: item.risk_level === 'high' ? '#fef2f2' : item.risk_level === 'medium' ? '#fefce8' : '#f0fdf4', color: item.risk_level === 'high' ? '#dc2626' : item.risk_level === 'medium' ? '#ca8a04' : '#16a34a', padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 600 }}>{item.risk_level || 'unknown'}</span></td>
                  <td style={{ padding: '12px 16px' }}>{item.status || 'active'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Inventory;
