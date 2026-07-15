import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../services/api';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [mfaSession, setMfaSession] = useState(null);
  const [mfaCode, setMfaCode] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await api.login(email, password);
      if (res.token_type === 'mfa_required') {
        setMfaSession(res.csrf_token);
        return;
      }
      api.setToken(res.access_token);
      navigate('/');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await api.mfaChallenge(mfaSession, mfaCode);
      api.setToken(res.access_token);
      navigate('/');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: '#1a1a2e' }}>
      <div style={{ background: '#fff', padding: 40, borderRadius: 12, width: 360, boxShadow: '0 10px 40px rgba(0,0,0,0.2)' }}>
        <h2 style={{ margin: '0 0 24px', textAlign: 'center', color: '#1a1a2e' }}>Guardrail AI</h2>
        {error && <div style={{ background: '#fef2f2', color: '#dc2626', padding: '8px 12px', borderRadius: 6, marginBottom: 16, fontSize: 13 }}>{error}</div>}

        {mfaSession ? (
          <form onSubmit={handleMfa}>
            <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13 }}>Authenticator Code</label>
            <input value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="000000" maxLength={6} style={{ width: '100%', padding: '10px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 20, textAlign: 'center', letterSpacing: 8, marginBottom: 16, boxSizing: 'border-box' }} />
            <button type="submit" style={{ width: '100%', padding: '10px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, cursor: 'pointer' }}>Verify Code</button>
          </form>
        ) : (
          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13 }}>Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" required style={{ width: '100%', padding: '10px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13 }}>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required style={{ width: '100%', padding: '10px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, boxSizing: 'border-box' }} />
            </div>
            <button type="submit" style={{ width: '100%', padding: '10px', background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, cursor: 'pointer', marginBottom: 12 }}>Sign In</button>
            <Link to="/forgot-password" style={{ display: 'block', textAlign: 'center', color: '#6366f1', fontSize: 13, textDecoration: 'none' }}>Forgot password?</Link>
          </form>
        )}
      </div>
    </div>
  );
};

export default Login;
