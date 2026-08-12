import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Upload, History, Shield, Activity, ChevronRight } from 'lucide-react'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/upload', label: 'Upload APK', icon: Upload },
  { to: '/history', label: 'History', icon: History },
]

export default function Sidebar() {
  return (
    <aside
      style={{
        width: '240px',
        minWidth: '240px',
        background: 'rgba(13, 18, 38, 0.3)',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '0',
        zIndex: 10,
        boxShadow: '4px 0 24px rgba(0, 0, 0, 0.1)'
      }}
    >
      {/* Logo */}
      <div style={{ padding: '24px 20px 20px', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <Shield size={18} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-1)', lineHeight: 1.2 }}>
              BOI Cognidroid
            </div>
            <div style={{ fontSize: 10, color: 'var(--cyan)', fontWeight: 500, letterSpacing: '0.06em' }}>
              AI PLATFORM
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '16px 12px' }}>
        <div style={{ fontSize: 10, color: 'var(--text-3)', fontWeight: 600, letterSpacing: '0.08em', padding: '0 8px 8px' }}>
          NAVIGATION
        </div>
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '10px 12px',
              borderRadius: 8,
              marginBottom: 2,
              textDecoration: 'none',
              fontSize: 13,
              fontWeight: 500,
              color: isActive ? 'var(--cyan)' : 'var(--text-2)',
              background: isActive ? 'rgba(6, 182, 212, 0.1)' : 'transparent',
              border: isActive ? '1px solid rgba(6, 182, 212, 0.2)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            {({ isActive }) => (
              <>
                <Icon size={16} />
                <span style={{ flex: 1 }}>{label}</span>
                {isActive && <ChevronRight size={14} style={{ opacity: 0.6 }} />}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Status Footer */}
      <div
        style={{
          padding: '16px 20px',
          borderTop: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <div style={{ position: 'relative', width: 8, height: 8 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#22c55e',
              position: 'absolute',
            }}
          />
          <div
            className="animate-ping"
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: '#22c55e',
              position: 'absolute',
              opacity: 0.4,
            }}
          />
        </div>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-2)', fontWeight: 500 }}>AI Engine</div>
          <div style={{ fontSize: 10, color: '#22c55e' }}>Online</div>
        </div>
        <Activity size={14} style={{ marginLeft: 'auto', color: 'var(--text-3)' }} />
      </div>
    </aside>
  )
}
