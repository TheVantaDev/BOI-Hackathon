import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertTriangle, Activity, CheckCircle, Clock, ArrowRight, TrendingUp } from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts'
import StatCard from '../components/StatCard'
import { getDashboardStats } from '../api/client'

const SEVERITY_COLORS = {
  'Safe': '#22c55e',
  'Low Risk': '#a3e635',
  'Suspicious': '#f97316',
  'Highly Malicious': '#ef4444',
  'Unknown': '#64748b',
}

const MOCK_STATS = {
  total_uploads: 247,
  completed: 231,
  processing: 3,
  failed: 13,
  severity_distribution: {
    'Safe': 84,
    'Low Risk': 61,
    'Suspicious': 52,
    'Highly Malicious': 34,
  },
  recent_uploads: [
    { apk_id: '1', filename: 'com.banking.trojan.apk', status: 'completed', sha256: 'a1b2c3d4...', upload_time: new Date().toISOString() },
    { apk_id: '2', filename: 'fake_hdfc_app.apk', status: 'completed', sha256: 'e5f6g7h8...', upload_time: new Date().toISOString() },
    { apk_id: '3', filename: 'sbi_update.apk', status: 'processing', sha256: 'i9j0k1l2...', upload_time: new Date().toISOString() },
    { apk_id: '4', filename: 'phonepe_clone.apk', status: 'completed', sha256: 'm3n4o5p6...', upload_time: new Date().toISOString() },
    { apk_id: '5', filename: 'unknown_finance.apk', status: 'failed', sha256: 'q7r8s9t0...', upload_time: new Date().toISOString() },
  ],
}

function StatusBadge({ status }) {
  const map = {
    completed: 'badge-safe',
    processing: 'badge-processing',
    failed: 'badge-malicious',
    pending: 'badge-pending',
  }
  return <span className={`badge ${map[status] || 'badge-pending'}`}>{status}</span>
}

function formatTime(iso) {
  return new Date(iso).toLocaleString('en-IN', { dateStyle: 'short', timeStyle: 'short' })
}

export default function Dashboard() {
  const [stats, setStats] = useState(MOCK_STATS)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    getDashboardStats()
      .then(({ data }) => setStats(data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const pieData = Object.entries(stats.severity_distribution || {}).map(([name, value]) => ({
    name,
    value,
    color: SEVERITY_COLORS[name] || '#64748b',
  }))

  const barData = [
    { label: 'Mon', count: 18 },
    { label: 'Tue', count: 31 },
    { label: 'Wed', count: 25 },
    { label: 'Thu', count: 42 },
    { label: 'Fri', count: 37 },
    { label: 'Sat', count: 14 },
    { label: 'Sun', count: 22 },
  ]

  const maliciousCount = (stats.severity_distribution?.['Highly Malicious'] || 0) + (stats.severity_distribution?.['Suspicious'] || 0)

  return (
    <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
      {/* Header */}
      <div className="animate-fade-in-up" style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-1)', marginBottom: 4 }}>
          Threat Intelligence Dashboard
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-2)' }}>
          Real-time APK analysis and malware investigation overview
        </p>
      </div>

      {/* Stat cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 16,
          marginBottom: 24,
        }}
      >
        <StatCard icon={Shield} label="Total Analyzed" value={stats.total_uploads} sub="All time" color="#06b6d4" delay={0} />
        <StatCard icon={AlertTriangle} label="Threats Detected" value={maliciousCount} sub="Suspicious + Malicious" color="#ef4444" delay={80} glow="glow-red" />
        <StatCard icon={Activity} label="Processing" value={stats.processing} sub="In pipeline now" color="#3b82f6" delay={160} />
        <StatCard icon={CheckCircle} label="Completed" value={stats.completed} sub="Successfully analyzed" color="#22c55e" delay={240} />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: 16, marginBottom: 24 }}>
        {/* Severity distribution */}
        <div className="card animate-fade-in-up delay-200" style={{ padding: 24 }}>
          <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 20, color: 'var(--text-1)' }}>
            Severity Distribution
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={80}
                paddingAngle={3}
                dataKey="value"
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#111827',
                  border: '1px solid #1e2d4a',
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {pieData.map((d) => (
              <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, flexShrink: 0 }} />
                <span style={{ color: 'var(--text-2)', flex: 1 }}>{d.name}</span>
                <span style={{ color: 'var(--text-1)', fontWeight: 600 }}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Weekly activity */}
        <div className="card animate-fade-in-up delay-300" style={{ padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>Weekly Analysis Activity</div>
            <TrendingUp size={16} color="var(--cyan)" />
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={barData} barSize={24}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{
                  background: '#111827',
                  border: '1px solid #1e2d4a',
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Bar dataKey="count" fill="url(#barGrad)" radius={[4, 4, 0, 0]} />
              <defs>
                <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.8} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.4} />
                </linearGradient>
              </defs>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent uploads */}
      <div className="card animate-fade-in-up delay-400" style={{ padding: 0, overflow: 'hidden' }}>
        <div
          style={{
            padding: '16px 24px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>Recent Uploads</div>
          <button
            onClick={() => navigate('/history')}
            className="btn-secondary"
            style={{ fontSize: 12, padding: '6px 12px' }}
          >
            View All <ArrowRight size={12} />
          </button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>SHA256</th>
              <th>Status</th>
              <th>Uploaded</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {stats.recent_uploads?.map((u) => (
              <tr key={u.apk_id} style={{ cursor: 'pointer' }} onClick={() => u.status === 'completed' && navigate(`/analysis/${u.apk_id}`)}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Shield size={13} color="var(--cyan)" />
                    <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-1)' }}>{u.filename}</span>
                  </div>
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{u.sha256?.slice(0, 16)}…</td>
                <td><StatusBadge status={u.status} /></td>
                <td>{formatTime(u.upload_time)}</td>
                <td>
                  {u.status === 'completed' && (
                    <ArrowRight size={14} color="var(--text-3)" />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
