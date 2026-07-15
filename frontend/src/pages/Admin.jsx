import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const Admin = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try { setUsers(await api.getUsers()); } catch (e) { console.error(e); }
      setLoading(false);
    };
    load();
  }, []);

  return (
    <div>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Admin</h1>

      {loading ? <div>Loading...</div> : (
        <div style={{ background: '#fff', borderRadius: 10, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#f9fafb' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Email</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Role</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>MFA</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: 12, textTransform: 'uppercase', color: '#6b7280' }}>Created</th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && <tr><td colSpan={4} style={{ padding: 20, textAlign: 'center', color: '#9ca3af' }}>No users found</td></tr>}
              {users.map((u) => (
                <tr key={u.id} style={{ borderTop: '1px solid #f3f4f6' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 500 }}>{u.email}</td>
                  <td style={{ padding: '12px 16px', fontSize: 13 }}>{u.role}</td>
                  <td style={{ padding: '12px 16px' }}>{u.mfa_enabled ? <span style={{ color: '#16a34a' }}>✓</span> : <span style={{ color: '#9ca3af' }}>—</span>}</td>
                  <td style={{ padding: '12px 16px', color: '#6b7280', fontSize: 13 }}>{u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Admin;
