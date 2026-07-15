import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import { api } from '../services/api'

const GuardrailDetail = () => {
  const { id } = useParams()
  const { data: guardrail, isLoading } = useQuery({
    queryKey: ['guardrail', id],
    queryFn: () => api.getGuardrail(id)
  })

  const { data: rules, isLoading: rulesLoading } = useQuery({
    queryKey: ['guardrail-rules', id],
    queryFn: () => api.getGuardrailRules(id)
  })

  if (isLoading || rulesLoading) {
    return <div>Loading guardrail details...</div>
  }

  return (
    <div>
      <Link to="/guardrails">← Back to Guardrails</Link>
      
      <div className="card" style={{ marginTop: '20px' }}>
        <h2>{guardrail?.name}</h2>
        <p>{guardrail?.description || 'No description'}</p>
        <div style={{ marginTop: '20px' }}>
          <p><strong>Status:</strong> {guardrail?.status}</p>
          <p><strong>Version:</strong> {guardrail?.version}</p>
          <p><strong>Created:</strong> {new Date(guardrail?.created_at).toLocaleDateString()}</p>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3>Rules</h3>
          <button className="button">Add Rule</button>
        </div>
        
        {rules?.length === 0 ? (
          <p>No rules configured for this guardrail.</p>
        ) : (
          <div>
            {rules?.map(rule => (
              <div key={rule.id} style={{ padding: '15px', border: '1px solid #eee', borderRadius: '4px', marginBottom: '10px' }}>
                <h4>{rule.name}</h4>
                <p>{rule.description || 'No description'}</p>
                <div style={{ marginTop: '10px' }}>
                  <span className="status-badge" style={{ backgroundColor: '#3498db', color: 'white' }}>
                    {rule.rule_type}
                  </span>
                  <span className="status-badge" style={{ backgroundColor: '#f39c12', color: 'white', marginLeft: '10px' }}>
                    {rule.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default GuardrailDetail
