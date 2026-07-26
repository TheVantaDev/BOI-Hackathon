import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';

import { riskScoreColor } from '../utils/status';

export default function RiskBar({ score }) {
  const theme = useTheme();

  if (score == null) {
    return (
      <Typography variant="caption" color="text.secondary">
        —
      </Typography>
    );
  }

  const color = riskScoreColor(score, theme);

  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 100 }}>
      <Box sx={{ flex: 1, height: 6, bgcolor: 'grey.200', borderRadius: 1, overflow: 'hidden' }}>
        <Box sx={{ width: `${score}%`, height: '100%', bgcolor: color, borderRadius: 1 }} />
      </Box>
      <Typography variant="body2" fontWeight={700}>
        {score}
      </Typography>
    </Stack>
  );
}
