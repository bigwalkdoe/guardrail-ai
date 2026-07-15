import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

const navGroups = [
  {
    label: 'Management',
    items: [
      { to: '/', label: 'Dashboard', icon: '📊' },
      { to: '/guardrails', label: 'Guardrails', icon: '🛡️' },
      { to: '/policies', label: 'Policies', icon: '📋' },
      { to: '/users', label: 'Users', icon: '👥' },
      { to: '/api-keys', label: 'API Keys', icon: '🔑' },
      { to: '/webhooks', label: 'Webhooks', icon: '🔗' },
    ],
  },
  {
    label: 'Security',
    items: [
      { to: '/guardrail-logs', label: 'Guardrail Logs', icon: '📝' },
      { to: '/audit-log', label: 'Audit Log', icon: '📄' },
      { to: '/incidents', label: 'Incidents', icon: '🚨' },
      { to: '/inventory', label: 'Inventory', icon: '💻' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { to: '/reports', label: 'Reports', icon: '📈' },
      { to: '/integrations', label: 'Integrations', icon: '🔌' },
      { to: '/settings', label: 'Settings', icon: '⚙️' },
      { to: '/admin', label: 'Admin', icon: '🔐' },
    ],
  },
];

const Layout = ({ children }) => {
  const navigate = useNavigate();
  const isLoginPage = window.location.pathname === '/login';
  const token = localStorage.getItem('access_token');

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  if (isLoginPage) return <>{children}</>;

  if (!token && window.location.pathname !== '/login' && window.location.pathname !== '/forgot-password' && !window.location.pathname.startsWith('/reset-password')) {
    navigate('/login');
    return null;
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <nav style={{ width: 240, background: '#1a1a2e', color: '#fff', padding: '20px 0', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '0 20px 20px', borderBottom: '1px solid rgba(255,255,255,0.1)', marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 18 }}>Guardrail AI</h2>
          <small style={{ opacity: 0.6 }}>Enterprise Governance</small>
        </div>

        <div style={{ flex: 1, overflowY: 'auto' }}>
          {navGroups.map((group) => (
            <div key={group.label} style={{ marginBottom: 16 }}>
              <div style={{ padding: '4px 20px', fontSize: 11, textTransform: 'uppercase', opacity: 0.4, letterSpacing: 1 }}>{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  style={({ isActive }) => ({
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    padding: '8px 20px',
                    color: isActive ? '#fff' : 'rgba(255,255,255,0.7)',
                    background: isActive ? 'rgba(255,255,255,0.1)' : 'transparent',
                    textDecoration: 'none',
                    fontSize: 14,
                    borderLeft: isActive ? '3px solid #4fc3f7' : '3px solid transparent',
                  })}
                >
                  <span>{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </div>

        <div style={{ padding: '16px 20px', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
          <button onClick={handleLogout} style={{ width: '100%', padding: '8px 16px', background: 'rgba(255,255,255,0.1)', border: '1px solid rgba(255,255,255,0.2)', color: '#fff', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>
            Logout
          </button>
        </div>
      </nav>

      <main style={{ flex: 1, padding: 24, background: '#f5f6fa', overflowY: 'auto' }}>
        {children}
      </main>
    </div>
  );
};

export default Layout;
