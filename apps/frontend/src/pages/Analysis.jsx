import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, Wifi, Lock, Code2, FileWarning,
  ChevronLeft, ExternalLink, Info, Bug, Activity
} from 'lucide-react'
import RiskScoreCard from '../components/RiskScoreCard'
import AttackChainGraph from '../components/AttackChainGraph'
import { getAnalysis, getReport } from '../api/client'

const MOCK_ANALYSIS = {
  filename: 'fake_hdfc_app.apk',
  sha256: 'a3f8c2d1e9b04756f2e1a8c3d4b5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3',
  status: 'completed',
  static_analysis: {
    permissions: [
      { name: 'READ_SMS', dangerous: true, description: 'Read SMS messages' },
      { name: 'RECEIVE_SMS', dangerous: true, description: 'Receive SMS messages' },
      { name: 'BIND_ACCESSIBILITY_SERVICE', dangerous: true, description: 'Accessibility service abuse' },
      { name: 'INTERNET', dangerous: false, description: 'Network access' },
      { name: 'READ_CONTACTS', dangerous: true, description: 'Access contact list' },
      { name: 'RECORD_AUDIO', dangerous: true, description: 'Microphone access' },
    ],
    suspicious_apis: ['getDeviceId', 'getSubscriberId', 'sendTextMessage', 'execCommand'],
    obfuscation_detected: true,
    dynamic_code_loading: true,
    hardcoded_urls: ['http://185.220.101.45/c2/', 'http://malware-c2.xyz/upload'],
    yara_matches: ['BankingTrojan.Android', 'SMSInterceptor.Generic'],
  },
  dynamic_analysis: {
    network_requests: [
      { url: 'http://185.220.101.45/c2/checkin', method: 'POST', suspicious: true },
      { url: 'https://api.ipify.org', method: 'GET', suspicious: false },
    ],
    sms_intercepted: true,
    accessibility_abuse: true,
    file_writes: ['/data/data/com.fake.hdfc/files/stolen_creds.db'],
    background_services: ['OTPHarvesterService', 'ContactSyncService'],
  },
  threat_intel: {
    malicious_domains: ['malware-c2.xyz'],
    malicious_ips: ['185.220.101.45'],
    mitre_techniques: [
      { id: 'T1430', name: 'Location Tracking', tactic: 'Collection' },
      { id: 'T1412', name: 'Capture SMS Messages', tactic: 'Collection' },
      { id: 'T1417', name: 'Input Capture', tactic: 'Collection' },
      { id: 'T1544', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
    ],
  },
  ai_summary: `This application exhibits behavior consistent with an advanced banking trojan targeting Indian financial institutions. The APK impersonates HDFC Bank's official application and employs multiple sophisticated attack vectors.\n\nKey findings:\n• SMS interception via BroadcastReceiver captures OTPs from banking applications\n• Accessibility service abuse enables overlay attacks on legitimate banking apps to steal credentials\n• Dynamic code loading from remote C2 server (185.220.101.45) allows post-infection capability updates\n• Extensive obfuscation using ProGuard with custom string encryption makes static detection difficult\n\nThe application likely targets account takeover through credential harvesting combined with OTP interception, enabling unauthorized fund transfers without victim awareness.`,
}

const MOCK_REPORT = {
  risk_score: 92,
  severity: 'Highly Malicious',
  classification: 'Banking Trojan',
  fraud_intent: 'Account Takeover via OTP Interception',
  fraud_journey: {
    nodes: [],
    edges: [],
  },
  recommendations: [
    'Immediately block domains: malware-c2.xyz and IPs: 185.220.101.45',
    'Alert affected customers who may have installed this application',
    'Report to CERT-In under IT Act Section 70B',
    'Coordinate with Google Play Protect for broader detection coverage',
    'Update threat signatures across endpoint security tools',
  ],
}

const TABS = ['Overview', 'Static Analysis', 'Dynamic Analysis', 'Threat Intel', 'AI Report']

function PermBadge({ dangerous }) {
  return (
    <span
      style={{
        fontSize: 10,
        padding: '2px 8px',
        borderRadius: 4,
        fontWeight: 600,
        background: dangerous ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.08)',
        color: dangerous ? '#ef4444' : '#22c55e',
        border: `1px solid ${dangerous ? 'rgba(239,68,68,0.25)' : 'rgba(34,197,94,0.2)'}`,
      }}
    >
      {dangerous ? 'DANGEROUS' : 'NORMAL'}
    </span>
  )
}

function MitreBadge({ id, name, tactic }) {
  return (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: 8,
        background: 'rgba(239,68,68,0.06)',
        border: '1px solid rgba(239,68,68,0.2)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#ef4444', fontWeight: 700 }}>{id}</span>
        <span style={{ fontSize: 10, color: 'var(--text-3)', padding: '1px 8px', background: 'rgba(100,116,139,0.1)', borderRadius: 4 }}>{tactic}</span>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{name}</div>
    </div>
  )
}

export default function Analysis() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [tab, setTab] = useState(0)
  const [analysis, setAnalysis] = useState(MOCK_ANALYSIS)
  const [report, setReport] = useState(MOCK_REPORT)

  useEffect(() => {
    if (!id) return
    Promise.all([getAnalysis(id), getReport(id)])
      .then(([a, r]) => {
        setAnalysis(a.data)
        setReport(r.data)
      })
      .catch(() => {})
  }, [id])

  const sa = analysis?.static_analysis || {}
  const da = analysis?.dynamic_analysis || {}
  const ti = analysis?.threat_intel || {}

  return (
    <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
      {/* Back + header */}
      <div className="animate-fade-in-up" style={{ marginBottom: 24 }}>
        <button
          onClick={() => navigate(-1)}
          className="btn-secondary"
          style={{ marginBottom: 16, fontSize: 12 }}
        >
          <ChevronLeft size={14} /> Back
        </button>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
              <Shield size={20} color="var(--cyan)" />
              {analysis?.filename || 'APK Analysis'}
            </h1>
            <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>
              SHA256: {analysis?.sha256}
            </div>
          </div>
          <div>
            <span
              className={`badge badge-${report?.severity?.toLowerCase().replace(' ', '-') || 'pending'}`}
              style={{ fontSize: 12 }}
            >
              {report?.classification || analysis?.status}
            </span>
          </div>
        </div>
      </div>

      {/* Top row: gauge + quick stats */}
      <div
        className="card animate-fade-in-up delay-100"
        style={{
          padding: 28,
          marginBottom: 20,
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: 40,
          alignItems: 'center',
        }}
      >
        <RiskScoreCard score={report?.risk_score || 0} classification={report?.severity} />
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4, color: '#ef4444' }}>
            {report?.fraud_intent || 'Analysis Pending'}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 20, lineHeight: 1.5 }}>
            {report?.classification} — Detected through static analysis, dynamic sandbox, and AI investigation
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { icon: FileWarning, label: `${sa.yara_matches?.length || 0} YARA Matches`, color: '#ef4444' },
              { icon: Wifi, label: `${da.network_requests?.length || 0} C2 Connections`, color: '#f97316' },
              { icon: Code2, label: `${sa.suspicious_apis?.length || 0} Suspicious APIs`, color: '#eab308' },
              { icon: Lock, label: `${ti.mitre_techniques?.length || 0} MITRE Techniques`, color: '#3b82f6' },
            ].map(({ icon: Icon, label, color }) => (
              <div
                key={label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 12px',
                  borderRadius: 8,
                  background: `${color}10`,
                  border: `1px solid ${color}25`,
                  fontSize: 12,
                  color,
                  fontWeight: 500,
                }}
              >
                <Icon size={13} />
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div
        className="animate-fade-in-up delay-200"
        style={{
          display: 'flex',
          gap: 4,
          marginBottom: 16,
          background: 'var(--bg-secondary)',
          padding: 4,
          borderRadius: 10,
          border: '1px solid var(--border)',
          width: 'fit-content',
        }}
      >
        {TABS.map((t, i) => (
          <button key={t} className={`tab-btn ${tab === i ? 'active' : ''}`} onClick={() => setTab(i)}>
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="animate-fade-in" key={tab}>
        {tab === 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Bug size={14} color="#ef4444" /> Key Indicators
              </div>
              {[
                { label: 'Obfuscation Detected', value: sa.obfuscation_detected, flag: true },
                { label: 'Dynamic Code Loading', value: sa.dynamic_code_loading, flag: true },
                { label: 'SMS Interception', value: da.sms_intercepted, flag: true },
                { label: 'Accessibility Abuse', value: da.accessibility_abuse, flag: true },
              ].map(({ label, value }) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 0', borderBottom: '1px solid rgba(30,45,74,0.4)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{label}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: value ? '#ef4444' : '#22c55e' }}>
                    {value ? '⚠ Detected' : '✓ Clean'}
                  </span>
                </div>
              ))}
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={14} color="#3b82f6" /> Recommendations
              </div>
              {report?.recommendations?.map((r, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 12, fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  <div style={{ width: 18, height: 18, borderRadius: '50%', background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#3b82f6', fontWeight: 700 }}>
                    {i + 1}
                  </div>
                  {r}
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Permissions ({sa.permissions?.length})</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {sa.permissions?.map((p) => (
                  <div key={p.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '9px 12px', background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)' }}>
                    <div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: p.dangerous ? '#ef4444' : 'var(--text-1)', fontWeight: 600 }}>{p.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{p.description}</div>
                    </div>
                    <PermBadge dangerous={p.dangerous} />
                  </div>
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>YARA Rule Matches</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {sa.yara_matches?.map((y) => (
                  <span key={y} style={{ padding: '4px 12px', borderRadius: 6, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', color: '#ef4444', fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>
                    {y}
                  </span>
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Hardcoded URLs / IPs</div>
              {sa.hardcoded_urls?.map((u) => (
                <div key={u} style={{ fontFamily: 'monospace', fontSize: 12, color: '#f97316', padding: '6px 0', borderBottom: '1px solid rgba(30,45,74,0.3)' }}>{u}</div>
              ))}
            </div>
          </div>
        )}

        {tab === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Network Requests</div>
              <table>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {da.network_requests?.map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{r.url}</td>
                      <td><span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--cyan)' }}>{r.method}</span></td>
                      <td>
                        <span style={{ fontSize: 11, color: r.suspicious ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                          {r.suspicious ? '⚠ Malicious C2' : '✓ Benign'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Background Services</div>
              {da.background_services?.map((s) => (
                <div key={s} style={{ fontFamily: 'monospace', fontSize: 12, color: '#f97316', padding: '6px 0', borderBottom: '1px solid rgba(30,45,74,0.3)' }}>{s}</div>
              ))}
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Fraud Journey Reconstruction</div>
              <AttackChainGraph height={300} />
            </div>
          </div>
        )}

        {tab === 3 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>MITRE ATT&CK Techniques</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                {ti.mitre_techniques?.map((t) => (
                  <MitreBadge key={t.id} {...t} />
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Malicious Indicators</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[...(ti.malicious_domains || []), ...(ti.malicious_ips || [])].map((ioc) => (
                  <div key={ioc} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'rgba(239,68,68,0.06)', borderRadius: 8, border: '1px solid rgba(239,68,68,0.15)', fontFamily: 'monospace', fontSize: 12, color: '#ef4444' }}>
                    <AlertTriangle size={12} />
                    {ioc}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === 4 && (
          <div className="card" style={{ padding: 28 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--cyan)' }} />
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>AI Investigation Report</div>
              <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.2)', color: 'var(--cyan)', fontWeight: 600 }}>
                llama3:8b-instruct
              </span>
            </div>
            <div
              style={{
                fontSize: 13,
                color: 'var(--text-2)',
                lineHeight: 1.8,
                whiteSpace: 'pre-line',
                background: 'var(--bg-secondary)',
                padding: 20,
                borderRadius: 10,
                border: '1px solid var(--border)',
              }}
            >
              {analysis?.ai_summary}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
