import { useEffect, useRef } from 'react'

const defaultElements = [
  { data: { id: 'infection', label: 'App Installed' }, position: { x: 100, y: 200 } },
  { data: { id: 'perm', label: 'Permission Granted' }, position: { x: 280, y: 100 } },
  { data: { id: 'overlay', label: 'Overlay Attack' }, position: { x: 280, y: 300 } },
  { data: { id: 'creds', label: 'Credential Theft' }, position: { x: 460, y: 100 } },
  { data: { id: 'otp', label: 'OTP Interception' }, position: { x: 460, y: 300 } },
  { data: { id: 'exfil', label: 'Data Exfiltration' }, position: { x: 640, y: 200 } },
  { data: { source: 'infection', target: 'perm' } },
  { data: { source: 'infection', target: 'overlay' } },
  { data: { source: 'perm', target: 'creds' } },
  { data: { source: 'overlay', target: 'otp' } },
  { data: { source: 'creds', target: 'exfil' } },
  { data: { source: 'otp', target: 'exfil' } },
]

const style = [
  {
    selector: 'node',
    style: {
      'background-color': '#111827',
      'border-width': 2,
      'border-color': '#06b6d4',
      label: 'data(label)',
      color: '#f1f5f9',
      'font-size': 11,
      'font-family': 'Inter, sans-serif',
      'font-weight': 600,
      'text-valign': 'center',
      'text-halign': 'center',
      width: 80,
      height: 80,
      'text-wrap': 'wrap',
      'text-max-width': 70,
      'box-shadow': '0 0 20px rgba(6, 182, 212, 0.3)',
    },
  },
  {
    selector: 'node[id = "exfil"]',
    style: {
      'border-color': '#ef4444',
      'background-color': '#1a0d0d',
    },
  },
  {
    selector: 'node[id = "infection"]',
    style: {
      'border-color': '#f97316',
      'background-color': '#1a1008',
    },
  },
  {
    selector: 'edge',
    style: {
      width: 2,
      'line-color': '#1e2d4a',
      'target-arrow-color': '#1e2d4a',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
    },
  },
]

export default function AttackChainGraph({ elements, height = 360 }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)

  useEffect(() => {
    let cy
    ;(async () => {
      const cytoscape = (await import('cytoscape')).default
      if (!containerRef.current) return

      cy = cytoscape({
        container: containerRef.current,
        elements: elements || defaultElements,
        style,
        layout: { name: 'preset' },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        autoungrabify: false,
      })

      cyRef.current = cy

      cy.nodes().forEach((node, i) => {
        node.style({
          opacity: 0,
          'transition-property': 'opacity',
          'transition-duration': '0.3s',
          'transition-delay': `${i * 80}ms`,
        })
        setTimeout(() => node.style('opacity', 1), 50)
      })
    })()

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy()
        cyRef.current = null
      }
    }
  }, [elements])

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height,
        background: 'var(--bg-secondary)',
        borderRadius: 10,
        border: '1px solid var(--border)',
        overflow: 'hidden',
      }}
    />
  )
}
