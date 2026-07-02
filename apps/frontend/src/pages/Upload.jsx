import { Shield, ShieldAlert } from 'lucide-react'
import UploadPanel from '../components/UploadPanel'

export default function Upload() {
  return (
    <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
      <div className="animate-fade-in-up" style={{ marginBottom: 28 }}>
        <h1 style={{ fontSize: 22, fontWeight: 800, marginBottom: 4 }}>Upload APK for Analysis</h1>
        <p style={{ fontSize: 13, color: 'var(--text-2)' }}>
          Submit a suspicious Android application for automated malware investigation
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 24, alignItems: 'start' }}>
        <UploadPanel />

        {/* Info panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Pipeline steps */}
          <div className="card animate-fade-in-up delay-100" style={{ padding: 24 }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-1)' }}>
              Analysis Pipeline
            </div>
            {[
              { step: '01', title: 'Reverse Engineering', desc: 'JADX, APKTool, Androguard decompilation' },
              { step: '02', title: 'Static Analysis', desc: 'Permissions, APIs, YARA rules, obfuscation' },
              { step: '03', title: 'Dynamic Sandbox', desc: 'Runtime behavior, network, SMS monitoring' },
              { step: '04', title: 'Threat Intelligence', desc: 'IOC lookup, MITRE ATT&CK mapping' },
              { step: '05', title: 'AI Investigation', desc: 'Multi-agent generative AI analysis' },
              { step: '06', title: 'Risk Scoring', desc: 'XGBoost + SHAP explainability' },
            ].map(({ step, title, desc }, i) => (
              <div
                key={step}
                style={{
                  display: 'flex',
                  gap: 12,
                  paddingBottom: i < 5 ? 14 : 0,
                  marginBottom: i < 5 ? 14 : 0,
                  borderBottom: i < 5 ? '1px solid rgba(30,45,74,0.4)' : 'none',
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: 'var(--cyan)',
                    background: 'rgba(6,182,212,0.1)',
                    border: '1px solid rgba(6,182,212,0.2)',
                    borderRadius: 6,
                    padding: '3px 7px',
                    flexShrink: 0,
                    height: 'fit-content',
                    marginTop: 2,
                  }}
                >
                  {step}
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)', marginBottom: 2 }}>{title}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Warning */}
          <div
            className="card animate-fade-in-up delay-200"
            style={{
              padding: 16,
              borderColor: 'rgba(249, 115, 22, 0.3)',
              background: 'rgba(249, 115, 22, 0.05)',
            }}
          >
            <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              <ShieldAlert size={16} color="#f97316" style={{ flexShrink: 0, marginTop: 1 }} />
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#f97316', marginBottom: 4 }}>Secure Analysis</div>
                <div style={{ fontSize: 11, color: 'var(--text-3)', lineHeight: 1.5 }}>
                  All APKs are executed in an isolated sandbox environment. No data leaves the on-premise deployment.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
