import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const Settings = () => {
  const [user, setUser] = useState(null);
  const [mfaQr, setMfaQr] = useState('');
  const [mfa, setMfa] = useState({ code: '', secret: '', enabled: false });
  const [pwdForm, setPwdForm] = useState({ current: '', new: '', confirm: '' });

  useEffect(() => {
    api.me().then(setUser).catch(console.error);
  }, []);

  const setupMfa = async () => {
    try {
      const res = await api.mfaSetup();
      setMfaQr(res.qr_code || res.secret || '');
    } catch (err) { alert(err.message); }
  };

  const verifyMfa = async () => {
    try {
      const res = await api.mfaVerify(mfa.code);
      if (res.success) {
        setMfaQr('');
        setMfa({ ...mfa, enabled: true });
        alert('MFA enabled successfully');
      }
    } catch (err) { alert(err.message); }
  };

  const disableMfa = async () => {
    const pwd = prompt('Enter your password to disable MFA:');
    if (!pwd) return;
    try {
      await api.mfaDisable(pwd);
      setMfa({ ...mfa, enabled: false });
      alert('MFA disabled');
    } catch (err) { alert(err.message); }
  };

  const changePassword = async (e) => {
    e.preventDefault();
    if (pwdForm.new !== pwdForm.confirm) { alert('Passwords do not match'); return; }
    try {
      await api.post('/auth/change-password', { current_password: pwdForm.current, new_password: pwdForm.new });
      setPwdForm({ current: '', new: '', confirm: '' });
      alert('Password changed successfully');
    } catch (err) { alert(err.message); }
  };

  return (
    <div style={{ maxWidth: 640 }}>
      <h1 style={{ margin: '0 0 24px', fontSize: 24 }}>Settings</h1>

      <div style={{ background: '#fff', borderRadius: 10, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', marginBottom: 24 }}>
        <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Profile</h3>
        <div style={{ display: 'grid', gap: 12, gridTemplateColumns: '1fr 1fr' }}>
          <div><label style={{ fontSize: 12, color: '#6b7280' }}>Email</label><div style={{ fontWeight: 500 }}>{user?.email || '—'}</div></div>
          <div><label style={{ fontSize: 12, color: '#6b7280' }}>Role</label><div style={{ fontWeight: 500 }}>{user?.role || '—'}</div></div>
        </div>
      </div>

      <div style={{ background: '#fff', borderRadius: 10, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.08)', marginBottom: 24 }}>
        <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Multi-Factor Authentication</h3>
        {mfa.enabled ? (
          <div>
            <span style={{ background: '#f0fdf4', color: '#16a34a', padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 600 }}>MFA is enabled</span>
            <button onClick={disableMfa} style={{ marginLeft: 12, padding: '6px 12px', border: '1px solid #ef4444', borderRadius: 4, background: '#fef2f2', cursor: 'pointer', fontSize: 12 }}>Disable</button>
          </div>
        ) : (
          <div>
            {mfaQr ? (
              <div>
                <p style={{ fontSize: 13, margin: '0 0 12px' }}>Scan this QR code with your authenticator app, or enter the secret manually:</p>
                <div style={{ background: '#f3f4f6', padding: 12, borderRadius: 6, fontFamily: 'monospace', fontSize: 12, marginBottom: 12, wordBreak: 'break-all' }}>{mfaQr}</div>
                <input value={mfa.code} onChange={(e) => setMfa({ ...mfa, code: e.target.value })} placeholder="Enter 6-digit code" maxLength={6} style={{ padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, marginRight: 8 }} />
                <button onClick={verifyMfa} style={{ padding: '8px 16px', background: '#6366f1', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>Verify</button>
              </div>
            ) : (
              <button onClick={setupMfa} style={{ padding: '8px 16px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Setup MFA</button>
            )}
          </div>
        )}
      </div>

      <div style={{ background: '#fff', borderRadius: 10, padding: 20, boxShadow: '0 1px 3px rgba(0,0,0,0.08)' }}>
        <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Change Password</h3>
        <form onSubmit={changePassword}>
          <div style={{ display: 'grid', gap: 12 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Current Password</label>
              <input type="password" value={pwdForm.current} onChange={(e) => setPwdForm({ ...pwdForm, current: e.target.value })} required style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>New Password</label>
                <input type="password" value={pwdForm.new} onChange={(e) => setPwdForm({ ...pwdForm, new: e.target.value })} required minLength={8} style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: 4, fontWeight: 600, fontSize: 13 }}>Confirm</label>
                <input type="password" value={pwdForm.confirm} onChange={(e) => setPwdForm({ ...pwdForm, confirm: e.target.value })} required minLength={8} style={{ width: '100%', padding: '8px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
              </div>
            </div>
          </div>
          <button type="submit" style={{ marginTop: 16, padding: '8px 16px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer' }}>Change Password</button>
        </form>
      </div>
    </div>
  );
};

export default Settings;
