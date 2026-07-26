import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';

import { IconActivity, IconAlertTriangle, IconCircleCheck, IconShield } from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';

const ICONS = {
  shield: IconShield,
  alert: IconAlertTriangle,
  activity: IconActivity,
  check: IconCircleCheck
};

export default function StatTile({ label, value, sub, color, icon = 'shield' }) {
  const theme = useTheme();
  const Icon = ICONS[icon] || IconShield;
  const accent = color || theme.palette.primary.main;

  return (
    <MainCard content={false} border boxShadow sx={{ position: 'relative', overflow: 'hidden' }}>
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 16,
          right: 16,
          height: 3,
          borderRadius: '0 0 4px 4px',
          background: `linear-gradient(90deg, transparent, ${accent}, transparent)`,
          opacity: 0.7
        }}
      />
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" sx={{ p: 2.5 }}>
        <Box>
          <Typography variant="caption" color="text.secondary" sx={{ letterSpacing: 0.6, fontWeight: 600 }}>
            {label}
          </Typography>
          <Typography variant="h2" sx={{ mt: 0.75, mb: 0.5 }}>
            {value}
          </Typography>
          {sub && (
            <Typography variant="caption" color="text.secondary">
              {sub}
            </Typography>
          )}
        </Box>
        <Box
          sx={{
            width: 44,
            height: 44,
            borderRadius: 2,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: alpha(accent, 0.12),
            border: `1px solid ${alpha(accent, 0.25)}`,
            color: accent
          }}
        >
          <Icon size={20} />
        </Box>
      </Stack>
    </MainCard>
  );
}
