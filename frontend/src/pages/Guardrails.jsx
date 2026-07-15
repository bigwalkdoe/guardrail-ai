import React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '../services/api'

const Guardrails = () => {
  const queryClient = useQueryClient()
  const { data: guardrails, isLoading } = useQuery({
    queryKey: ['guardrails'],
    queryFn: api.getGuardrails
  })

  const deleteMutation = useMutation({
    mutationFn: api.deleteGuardrail,
    onSuccess: () => {
      queryClient.invalidateQueries(['guardrails'])
    }
  })

  const handleDelete = (id) => {
    if (window.confirm('Are you sure you want to delete this guardrail?')) {
      deleteMutation.mutate(id)
    }
  }

  if (isLoading) {
    return <div>Loading guardrails...</div>
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2>Guardrails</h2>
        <button className="button">Create Guardrail</button>
      </div>
      
      {guardrails?.length === 0 ? (
        <div className="card">
          <p>No guardrails found. Create your first guardrail to get started.</p>
        </div>
      ) : (
        <div>
          {guardrails?.map(guardrail => (
            <div key={guardrail.id} className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div>
                  <h3>
                    <Link to={`/guardrails/${guardrail.id}`}>
                      {guardrail.name}
                    </Link>
                  </h3>
                  <p>{guardrail.description || 'No description'}</p>
                  <div style={{ marginTop: '10px' }}>
                    <span className={`status-badge status-${guardrail.status}`}>
                      {guardrail.status}
                    </span>
                    <span style={{ marginLeft: '10px', color: '#666' }}>
                      Version {guardrail.version}
                    </span>
                  </div>
                </div>
                <div>
                  <button 
                    className="button" 
                    style={{ backgroundColor: '#e74c3c', marginRight: '10px' }}
                    onClick={() => handleDelete(guardrail.id)}
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default Guardrails
