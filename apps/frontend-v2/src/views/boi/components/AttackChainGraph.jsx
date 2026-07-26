import { useEffect, useRef } from 'react';

import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';

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
  { data: { source: 'otp', target: 'exfil' } }
];

export default function AttackChainGraph({ elements, height = 300 }) {
  const theme = useTheme();
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    let cy;
    (async () => {
      const cytoscape = (await import('cytoscape')).default;
      if (!containerRef.current) return;

      const primary = theme.palette.primary.main;
      const secondary = theme.palette.secondary.main;
      const error = theme.palette.error.main;
      const paper = theme.palette.background.paper;
      const text = theme.palette.text.primary;
      const edge = theme.palette.grey[300];

      cy = cytoscape({
        container: containerRef.current,
        elements: elements || defaultElements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': paper,
              'border-width': 2,
              'border-color': primary,
              label: 'data(label)',
              color: text,
              'font-size': 11,
              'font-family': 'Roboto, sans-serif',
              'font-weight': 600,
              'text-valign': 'center',
              'text-halign': 'center',
              width: 80,
              height: 80,
              'text-wrap': 'wrap',
              'text-max-width': 70
            }
          },
          {
            selector: 'node[id = "exfil"]',
            style: {
              'border-color': error,
              'background-color': paper
            }
          },
          {
            selector: 'node[id = "infection"]',
            style: {
              'border-color': secondary
            }
          },
          {
            selector: 'edge',
            style: {
              width: 2,
              'line-color': edge,
              'target-arrow-color': edge,
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier'
            }
          }
        ],
        layout: { name: 'preset' },
        userZoomingEnabled: true,
        userPanningEnabled: true,
        autoungrabify: false
      });

      cyRef.current = cy;

      cy.nodes().forEach((node, i) => {
        node.style({
          opacity: 0,
          'transition-property': 'opacity',
          'transition-duration': '0.3s',
          'transition-delay': `${i * 80}ms`
        });
        setTimeout(() => node.style('opacity', 1), 50);
      });
    })();

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [elements, theme]);

  return (
    <Box
      ref={containerRef}
      sx={{
        width: '100%',
        height,
        bgcolor: 'grey.50',
        borderRadius: 2,
        border: '1px solid',
        borderColor: 'divider',
        overflow: 'hidden'
      }}
    />
  );
}
