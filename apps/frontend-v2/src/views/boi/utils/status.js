/** Map analysis status → MUI Chip color */
export function statusToChipColor(status) {
  if (status === 'completed') return 'success';
  if (status === 'processing') return 'info';
  if (status === 'failed') return 'error';
  return 'default';
}

/** Map severity label → MUI Chip color */
export function severityToChipColor(severity) {
  if (severity === 'Highly Malicious') return 'error';
  if (severity === 'Suspicious') return 'warning';
  if (severity === 'Low Risk') return 'success';
  if (severity === 'Safe') return 'success';
  return 'default';
}

/** Hex/token colors for charts & risk bars */
export function severityChartColor(name, theme) {
  const map = {
    Safe: theme.palette.success.main,
    'Low Risk': theme.palette.success.dark,
    Suspicious: theme.palette.orange.dark,
    'Highly Malicious': theme.palette.error.main,
    Unknown: theme.palette.grey[500]
  };
  return map[name] || theme.palette.grey[500];
}

/** Risk score → bar/gauge fill color */
export function riskScoreColor(score, theme) {
  if (score == null) return theme.palette.grey[500];
  if (score >= 75) return theme.palette.error.main;
  if (score >= 55) return theme.palette.orange.dark;
  if (score >= 30) return theme.palette.warning.dark;
  return theme.palette.success.dark;
}

/** Classification / severity string → Chip color for Analysis header */
export function classificationToChipColor(classification) {
  if (!classification) return 'default';
  const c = String(classification).toLowerCase();
  if (c.includes('malicious') || c.includes('high')) return 'error';
  if (c.includes('suspicious') || c.includes('medium')) return 'warning';
  if (c.includes('safe') || c.includes('low') || c.includes('clean')) return 'success';
  return 'primary';
}
