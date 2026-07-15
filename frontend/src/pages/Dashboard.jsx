import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../services/api'

const Dashboard = () => {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: api.getDashboardStats
  })

  if (isLoading) {
    return <div>Loading dashboard...</div>
  }

  return (
    <div>
      <h2>Dashboard</h2>
      <div className="card">
        <h3>System Overview</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginTop: '20px' }}>
          <div>
            <h4>Total Guardrails</h4>
            <p style={{ fontSize: '2em', fontWeight: 'bold' }}>{stats?.total_guardrails || 0}</p>
          </div>
          <div>
            <h4>Active Evaluations</h4>
            <p style={{ fontSize: '2em', fontWeight: 'bold' }}>{stats?.active_evaluations || 0}</p>
          </div>
          <div>
            <h4>Total Users</h4>
            <p style={{ fontSize: '2em', fontWeight: 'bold' }}>{stats?.total_users || 0}</p>
          </div>
          <div>
            <h4>Pass Rate</h4>
            <p style={{ fontSize: '2em', fontWeight: 'bold' }}>{stats?.pass_rate || 0}%</p>
          </div>
        </div>
      </div>
      
      <div className="card">
        <h3>Recent Activity</h3>
        <ul>
          {stats?.recent_activity?.map((activity, index) => (
            <li key={index} style={{ padding: '10px 0', borderBottom: '1px solid #eee' }}>
              {activity}
            </li>
          )) || <li>No recent activity</li>}
        </ul>
      </div>
    </div>
  )
}

export default Dashboard
