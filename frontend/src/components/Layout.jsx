import React from 'react'
import { Link, useLocation } from 'react-router-dom'

const Layout = ({ children }) => {
  const location = useLocation()
  
  const isActive = (path) => location.pathname === path
  
  return (
    <div className="app">
      <header className="header">
        <nav className="nav">
          <h1>Guardrail AI</h1>
          <div>
            <Link 
              to="/" 
              className={`nav-link ${isActive('/') ? 'active' : ''}`}
            >
              Dashboard
            </Link>
            <Link 
              to="/guardrails" 
              className={`nav-link ${isActive('/guardrails') ? 'active' : ''}`}
            >
              Guardrails
            </Link>
            <Link 
              to="/users" 
              className={`nav-link ${isActive('/users') ? 'active' : ''}`}
            >
              Users
            </Link>
          </div>
        </nav>
      </header>
      <main className="container">
        {children}
      </main>
    </div>
  )
}

export default Layout
