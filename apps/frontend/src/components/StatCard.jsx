export default function StatCard({ icon: Icon, label, value, sub, color = '#06b6d4', delay = 0, glow }) {
  return (
    <div
      className={`card animate-fade-in-up ${glow || ''}`}
      style={{
        padding: '20px',
        animationDelay: `${delay}ms`,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: 2,
          background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
          opacity: 0.6,
        }}
      />
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 12, color: 'var(--text-3)', fontWeight: 500, marginBottom: 8, letterSpacing: '0.04em' }}>
            {label}
          </div>
          <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--text-1)', lineHeight: 1 }}>
            {value}
          </div>
          {sub && (
            <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 6 }}>{sub}</div>
          )}
        </div>
        <div
          style={{
            width: 40,
            height: 40,
            borderRadius: 10,
            background: `${color}18`,
            border: `1px solid ${color}30`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <Icon size={18} color={color} />
        </div>
      </div>
    </div>
  )
}
