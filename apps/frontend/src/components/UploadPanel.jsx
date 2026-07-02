import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileWarning, CheckCircle2, Loader2, ShieldAlert } from 'lucide-react'
import { uploadAPK, getAnalysisStatus } from '../api/client'

const ACCEPTED_TYPE = 'application/vnd.android.package-archive'

export default function UploadPanel() {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('idle') // idle | uploading | analyzing | done | error
  const [apkId, setApkId] = useState(null)
  const [error, setError] = useState('')
  const inputRef = useRef(null)
  const pollRef = useRef(null)
  const navigate = useNavigate()

  const reset = () => {
    setFile(null)
    setProgress(0)
    setPhase('idle')
    setApkId(null)
    setError('')
    clearInterval(pollRef.current)
  }

  const startPolling = (id) => {
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getAnalysisStatus(id)
        if (data.status === 'completed') {
          clearInterval(pollRef.current)
          setPhase('done')
          setTimeout(() => navigate(`/analysis/${id}`), 1200)
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current)
          setPhase('error')
          setError('Analysis pipeline failed. Please try again.')
        }
      } catch {
        // keep polling
      }
    }, 3000)
  }

  const handleFile = useCallback(async (f) => {
    if (!f) return
    if (!f.name.endsWith('.apk')) {
      setError('Only .apk files are accepted.')
      return
    }
    setError('')
    setFile(f)
    setPhase('uploading')
    setProgress(0)

    try {
      const { data } = await uploadAPK(f, setProgress)
      setApkId(data.apk_id)
      setPhase('analyzing')
      startPolling(data.apk_id)
    } catch (err) {
      setPhase('error')
      setError(err?.response?.data?.detail || 'Upload failed. Is the backend running?')
    }
  }, [])

  const onDrop = (e) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    handleFile(f)
  }

  const onDragOver = (e) => { e.preventDefault(); setDragging(true) }
  const onDragLeave = () => setDragging(false)
  const onInputChange = (e) => handleFile(e.target.files[0])

  if (phase === 'done') {
    return (
      <div className="card animate-fade-in-up" style={{ padding: 48, textAlign: 'center' }}>
        <CheckCircle2 size={52} color="#22c55e" style={{ margin: '0 auto 16px' }} />
        <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-1)' }}>Analysis Complete</div>
        <div style={{ color: 'var(--text-2)', fontSize: 13, marginTop: 8 }}>Redirecting to report…</div>
      </div>
    )
  }

  if (phase === 'analyzing') {
    return (
      <div className="card animate-fade-in-up" style={{ padding: 48, textAlign: 'center' }}>
        <div style={{ position: 'relative', width: 64, height: 64, margin: '0 auto 20px' }}>
          <ShieldAlert size={64} color="var(--cyan)" style={{ opacity: 0.3 }} />
          <Loader2
            size={64}
            color="var(--cyan)"
            style={{ position: 'absolute', top: 0, left: 0, animation: 'spin 1.4s linear infinite' }}
          />
        </div>
        <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>AI Engine Analyzing…</div>
        <div style={{ color: 'var(--text-2)', fontSize: 13, marginBottom: 20 }}>
          Running static analysis, dynamic sandbox, and threat intelligence checks
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 320, margin: '0 auto' }}>
          {['Reverse Engineering', 'Static Analysis', 'Threat Intel Lookup', 'AI Investigation', 'Risk Scoring'].map((step, i) => (
            <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: 'var(--text-2)' }}>
              <Loader2 size={12} color="var(--cyan)" style={{ animation: 'spin 1s linear infinite', animationDelay: `${i * 0.15}s` }} />
              {step}
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="card animate-fade-in-up" style={{ padding: 32 }}>
      <div
        className={`upload-zone ${dragging ? 'drag-over' : ''}`}
        style={{ padding: '60px 32px', textAlign: 'center', cursor: 'pointer', position: 'relative', overflow: 'hidden' }}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => phase === 'idle' && inputRef.current?.click()}
      >
        {dragging && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(6, 182, 212, 0.05)',
              pointerEvents: 'none',
            }}
          />
        )}
        <input ref={inputRef} type="file" accept=".apk" onChange={onInputChange} />

        <div
          style={{
            width: 72,
            height: 72,
            borderRadius: 20,
            background: 'rgba(6, 182, 212, 0.1)',
            border: '1px solid rgba(6, 182, 212, 0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
          }}
        >
          <Upload size={28} color="var(--cyan)" />
        </div>

        {phase === 'uploading' ? (
          <div style={{ maxWidth: 280, margin: '0 auto' }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 16 }}>Uploading {file?.name}</div>
            <div
              style={{
                height: 4,
                background: 'var(--border)',
                borderRadius: 4,
                overflow: 'hidden',
              }}
            >
              <div
                style={{
                  height: '100%',
                  width: `${progress}%`,
                  background: 'linear-gradient(90deg, var(--cyan), var(--blue))',
                  borderRadius: 4,
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 8 }}>{progress}%</div>
          </div>
        ) : (
          <>
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
              Drop APK here, or <span style={{ color: 'var(--cyan)' }}>browse</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-3)' }}>
              Supports Android APK files only · Max 200MB
            </div>
          </>
        )}
      </div>

      {error && (
        <div
          style={{
            marginTop: 16,
            padding: '10px 14px',
            borderRadius: 8,
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            color: '#ef4444',
            fontSize: 13,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <FileWarning size={14} />
          {error}
          <button
            onClick={reset}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 11 }}
          >
            Dismiss
          </button>
        </div>
      )}

      <div style={{ marginTop: 20, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {['Banking Trojan Detection', 'OTP Interception', 'Overlay Attack', 'Data Exfiltration', 'MITRE ATT&CK Mapping'].map((f) => (
          <span
            key={f}
            style={{
              fontSize: 11,
              padding: '3px 10px',
              borderRadius: 6,
              background: 'rgba(30, 45, 74, 0.5)',
              border: '1px solid var(--border)',
              color: 'var(--text-3)',
            }}
          >
            {f}
          </span>
        ))}
      </div>
    </div>
  )
}
