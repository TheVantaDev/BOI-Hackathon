import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Filter, ArrowRight, Shield, Calendar, Loader2, AlertTriangle } from 'lucide-react'
import RiskScoreCard from '../components/RiskScoreCard'
import { getRecentUploads } from '../api/client'



const SEVERITY_ORDER = { 'Highly Malicious': 0, 'Suspicious': 1, 'Low Risk': 2, 'Safe': 3 }

function SeverityBadge({ severity }) {
  const map = {
    'Highly Malicious': 'badge-malicious',
    'Suspicious': 'badge-suspicious',
    'Low Risk': 'badge-low',
    'Safe': 'badge-safe',
  }
  return severity ? <span className={`badge ${map[severity] || 'badge-pending'}`}>{severity}</span> : <span className="badge badge-pending">—</span>
}

function StatusDot({ status }) {
  const colors = { completed: '#22c55e', processing: '#06b6d4', failed: '#ef4444', pending: '#64748b' }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ width: 6, height: 6, borderRadius: '50%', background: colors[status] || '#64748b' }} />
      <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{status}</span>
    </div>
  )
}

export default function History() {
  const [items, setItems] = useState([])
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    getRecentUploads(50)
      .then(({ data }) => setItems(data || []))
      .catch(() => setError(true))
      .finally(() => setLoading(false))
  }, [])

  const filtered = items
    .filter((i) => {
      const q = search.toLowerCase()
      return !q || i.filename?.toLowerCase().includes(q) || i.sha256?.includes(q)
    })
    .filter((i) => severityFilter === 'all' || i.severity === severityFilter)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9))

  return (
    <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
      <div className="animate-fade-in-up" style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4 }}>Analysis History</h1>
        <p style={{ fontSize: 13, color: 'var(--text-2)' }}>All submitted APKs and their investigation results</p>
      </div>

      {/* Filters */}
      <div
        className="card animate-fade-in-up delay-100"
        style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 12, alignItems: 'center' }}
      >
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
          <input
            className="input-field"
            style={{ paddingLeft: 32 }}
            placeholder="Search by filename or SHA256…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <Filter size={13} color="var(--text-3)" />
          {['all', 'Highly Malicious', 'Suspicious', 'Low Risk', 'Safe'].map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              style={{
                fontSize: 11,
                padding: '5px 12px',
                borderRadius: 6,
                border: '1px solid',
                cursor: 'pointer',
                fontWeight: 500,
                background: severityFilter === s ? 'rgba(6,182,212,0.1)' : 'transparent',
                borderColor: severityFilter === s ? 'rgba(6,182,212,0.3)' : 'var(--border)',
                color: severityFilter === s ? 'var(--cyan)' : 'var(--text-3)',
                transition: 'all 0.15s ease',
              }}
            >
              {s === 'all' ? 'All' : s}
            </button>
          ))}
        </div>
        <span style={{ fontSize: 12, color: 'var(--text-3)', flexShrink: 0 }}>
          {filtered.length} results
        </span>
      </div>

      {/* Table */}
      <div className="card animate-fade-in-up delay-200" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ padding: 48, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <Loader2 size={24} className="animate-spin" color="var(--cyan)" />
            <span style={{ fontSize: 13, color: 'var(--text-3)' }}>Loading history...</span>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 48, textAlign: 'center' }}>
            <AlertTriangle size={28} color="var(--text-3)" style={{ marginBottom: 12 }} />
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>
              {error ? 'Could not reach backend' : items.length === 0 ? 'No analyses yet' : 'No matching results'}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
              {error ? 'Connect the backend to see analysis history' : items.length === 0 ? 'Upload an APK to get started' : 'Try adjusting your search or filters'}
            </div>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>SHA256</th>
                <th>Risk Score</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Analyzed</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr
                  key={item.apk_id}
                  style={{ cursor: item.status === 'completed' ? 'pointer' : 'default' }}
                  onClick={() => item.status === 'completed' && navigate(`/analysis/${item.apk_id}`)}
                >
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Shield size={13} color="var(--cyan)" style={{ flexShrink: 0 }} />
                      <span style={{ fontSize: 13, color: 'var(--text-1)', fontFamily: 'monospace' }}>{item.filename}</span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{item.sha256?.slice(0, 16)}…</td>
                  <td>
                    {item.risk_score != null ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div
                          style={{
                            width: 60,
                            height: 5,
                            background: 'var(--border)',
                            borderRadius: 3,
                            overflow: 'hidden',
                          }}
                        >
                          <div
                            style={{
                              width: `${item.risk_score}%`,
                              height: '100%',
                              background: item.risk_score >= 75 ? '#ef4444' : item.risk_score >= 55 ? '#f97316' : item.risk_score >= 30 ? '#eab308' : '#22c55e',
                              borderRadius: 3,
                            }}
                          />
                        </div>
                        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-1)' }}>{item.risk_score}</span>
                      </div>
                    ) : (
                      <span style={{ color: 'var(--text-3)', fontSize: 12 }}>—</span>
                    )}
                  </td>
                  <td><SeverityBadge severity={item.severity} /></td>
                  <td><StatusDot status={item.status} /></td>
                  <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Calendar size={11} />
                      {new Date(item.upload_time).toLocaleDateString('en-IN')}
                    </div>
                  </td>
                  <td>
                    {item.status === 'completed' && <ArrowRight size={14} color="var(--text-3)" />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
