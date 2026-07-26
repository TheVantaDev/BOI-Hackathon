import { useEffect, useRef } from 'react';

import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/material/styles';

import { riskScoreColor, severityToChipColor } from '../utils/status';

function severityLabel(score) {
  if (score < 30) return 'Safe';
  if (score < 55) return 'Low Risk';
  if (score < 75) return 'Suspicious';
  return 'Highly Malicious';
}

export default function RiskGauge({ score = 0, classification, compact = false }) {
  const theme = useTheme();
  const arcRef = useRef(null);
  const color = riskScoreColor(score, theme);
  const label = classification || severityLabel(score);
  const chipColor = severityToChipColor(label);

  const size = compact ? 160 : 220;
  const cx = size / 2;
  const cy = size / 2;
  const r = compact ? 60 : 85;
  const strokeWidth = compact ? 10 : 14;
  const circumference = Math.PI * r;
  const dashOffset = circumference - (score / 100) * circumference;
  const track = theme.palette.grey[200];
  const fontFamily = theme.typography.fontFamily;

  useEffect(() => {
    if (!arcRef.current) return;
    arcRef.current.style.transition = 'none';
    arcRef.current.setAttribute('stroke-dasharray', `0 ${circumference}`);
    requestAnimationFrame(() => {
      setTimeout(() => {
        if (arcRef.current) {
          arcRef.current.style.transition = 'stroke-dasharray 1.2s cubic-bezier(0.4, 0, 0.2, 1)';
          arcRef.current.setAttribute('stroke-dasharray', `${circumference - dashOffset} ${circumference}`);
        }
      }, 100);
    });
  }, [score, circumference, dashOffset]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: compact ? 1 : 1.5 }}>
      <Box sx={{ position: 'relative', width: size, height: size * 0.6 }}>
        <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`} style={{ overflow: 'visible' }}>
          <defs>
            <linearGradient id="berryGaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={color} stopOpacity="0.55" />
              <stop offset="100%" stopColor={color} />
            </linearGradient>
          </defs>
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke={track}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          <path
            ref={arcRef}
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="url(#berryGaugeGrad)"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={`0 ${circumference}`}
          />
          <text
            x={cx}
            y={cy - (compact ? 6 : 8)}
            textAnchor="middle"
            fill={theme.palette.text.primary}
            fontFamily={fontFamily}
            fontSize={compact ? 28 : 40}
            fontWeight="800"
          >
            {score}
          </text>
          <text
            x={cx}
            y={cy + (compact ? 12 : 16)}
            textAnchor="middle"
            fill={theme.palette.text.secondary}
            fontFamily={fontFamily}
            fontSize={compact ? 10 : 12}
            fontWeight="500"
          >
            / 100
          </text>
        </svg>
      </Box>
      <Chip label={label} size="small" color={chipColor} sx={{ fontWeight: 700, letterSpacing: 0.4 }} />
    </Box>
  );
}
