import { useEffect, useRef } from 'react'

function getSeverityColor(score) {
  if (score < 30) return '#22c55e'
  if (score < 55) return '#eab308'
  if (score < 75) return '#f97316'
  return '#ef4444'
}

function getSeverityLabel(score) {
  if (score < 30) return 'Safe'
  if (score < 55) return 'Low Risk'
  if (score < 75) return 'Suspicious'
  return 'Highly Malicious'
}

export default function RiskScoreCard({ score = 0, classification, compact = false }) {
  const arcRef = useRef(null)
  const color = getSeverityColor(score)
  const label = classification || getSeverityLabel(score)

  const size = compact ? 160 : 220
  const cx = size / 2
  const cy = size / 2
  const r = compact ? 60 : 85
  const strokeWidth = compact ? 10 : 14
  const circumference = Math.PI * r
  const dashOffset = circumference - (score / 100) * circumference

  useEffect(() => {
    if (!arcRef.current) return
    arcRef.current.style.transition = 'none'
    arcRef.current.setAttribute('stroke-dasharray', `0 ${circumference}`)
    requestAnimationFrame(() => {
      setTimeout(() => {
        if (arcRef.current) {
          arcRef.current.style.transition = 'stroke-dasharray 1.2s cubic-bezier(0.4, 0, 0.2, 1)'
          arcRef.current.setAttribute(
            'stroke-dasharray',
            `${circumference - dashOffset} ${circumference}`
          )
        }
      }, 100)
    })
  }, [score])

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: compact ? 8 : 12,
      }}
    >
      <div style={{ position: 'relative', width: size, height: size * 0.6 }}>
        <svg
          width={size}
          height={size * 0.65}
          viewBox={`0 0 ${size} ${size * 0.65}`}
          style={{ overflow: 'visible' }}
        >
          {/* Gradient defs */}
          <defs>
            <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={color} stopOpacity="0.6" />
              <stop offset="100%" stopColor={color} />
            </linearGradient>
          </defs>

          {/* Track arc */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="#1e2d4a"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Score arc */}
          <path
            ref={arcRef}
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="url(#gaugeGrad)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={`0 ${circumference}`}
            style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
          />

          {/* Score number */}
          <text
            x={cx}
            y={cy - (compact ? 6 : 8)}
            textAnchor="middle"
            fill="white"
            fontFamily="Inter, sans-serif"
            fontSize={compact ? 28 : 40}
            fontWeight="800"
          >
            {score}
          </text>
          <text
            x={cx}
            y={cy + (compact ? 12 : 16)}
            textAnchor="middle"
            fill="var(--text-3)"
            fontFamily="Inter, sans-serif"
            fontSize={compact ? 10 : 12}
            fontWeight="500"
          >
            / 100
          </text>

          {/* Min / Max labels */}
          <text
            x={cx - r + 4}
            y={cy + (compact ? 18 : 24)}
            fill="var(--text-3)"
            fontFamily="Inter"
            fontSize="10"
          >
            0
          </text>
          <text
            x={cx + r - 18}
            y={cy + (compact ? 18 : 24)}
            fill="var(--text-3)"
            fontFamily="Inter"
            fontSize="10"
          >
            100
          </text>
        </svg>
      </div>

      {/* Severity badge */}
      <div
        style={{
          padding: compact ? '4px 14px' : '6px 20px',
          borderRadius: 9999,
          border: `1px solid ${color}40`,
          background: `${color}12`,
          color: color,
          fontSize: compact ? 11 : 13,
          fontWeight: 700,
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </div>
    </div>
  )
}
