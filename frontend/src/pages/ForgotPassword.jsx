import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api.forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: '#1a1a2e' }}>
      <div style={{ background: '#fff', padding: 40, borderRadius: 12, width: 360 }}>
        <h2 style={{ margin: '0 0 8px', color: '#1a1a2e' }}>Reset Password</h2>
        <p style={{ margin: '0 0 24px', color: '#6b7280', fontSize: 13 }}>Enter your email and we'll send you a reset link.</p>
        {error && <div style={{ background: '#fef2f2', color: '#dc2626', padding: '8px 12px', borderRadius: 6, marginBottom: 16, fontSize: 13 }}>{error}</div>}
        {sent ? (
          <div style={{ background: '#f0fdf4', color: '#16a34a', padding: 16, borderRadius: 6, fontSize: 13 }}>Check your email for a password reset link.</div>
        ) : (
          <form onSubmit={handleSubmit}>
            <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 13 }}>Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required style={{ width: '100%', padding: '10px 12px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 14, marginBottom: 16, boxSizing: 'border-box' }} />
            <button type="submit" style={{ width: '100%', padding: 10, background: '#1a1a2e', color: '#fff', border: 'none', borderRadius: 6, fontSize: 14, cursor: 'pointer', marginBottom: 12 }}>Send Reset Link</button>
            <Link to="/login" style={{ display: 'block', textAlign: 'center', color: '#6366f1', fontSize: 13 }}>Back to Login</Link>
          </form>
        )}
      </div>
    </div>
  );
};

export default ForgotPassword;
