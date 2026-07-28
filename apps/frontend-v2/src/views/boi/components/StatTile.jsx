import Avatar from '@mui/material/Avatar';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';

import { IconActivity, IconAlertTriangle, IconCircleCheck, IconShield } from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';

const ICONS = {
  shield: IconShield,
  alert: IconAlertTriangle,
  activity: IconActivity,
  check: IconCircleCheck
};

/**
 * Berry KPI tile.
 * @param {'primary'|'secondary'|'error'|'success'|'warning'|'orange'} tone
 * @param {'filled'|'light'} variant
 */
export default function StatTile({ label, value, sub, tone = 'primary', variant = 'filled', icon = 'shield' }) {
  const theme = useTheme();
  const Icon = ICONS[icon] || IconShield;
  const filled = variant === 'filled';
  const palette = theme.palette[tone] || theme.palette.primary;
  // ponytail: error/orange lack 200/800 — fall back to light/dark
  const circle = palette[800] || palette.dark;
  const labelColor = filled ? palette[200] || palette.light : theme.palette.grey[500];
  // filled: icon only (no nested box); light: soft tone well
  const avatarBg = filled ? 'transparent' : palette.light;
  const avatarFg = filled ? '#fff' : palette.dark;

  return (
    <MainCard
      border={false}
      boxShadow
      hoverLift
      content={false}
      sx={{
        ...(filled
          ? {
              bgcolor: palette.dark,
              color: '#fff',
              overflow: 'hidden',
              position: 'relative',
              '&:after': {
                content: '""',
                position: 'absolute',
                width: 210,
                height: 210,
                background: circle,
                borderRadius: '50%',
                top: { xs: -85 },
                right: { xs: -95 }
              },
              '&:before': {
                content: '""',
                position: 'absolute',
                width: 210,
                height: 210,
                background: circle,
                borderRadius: '50%',
                top: { xs: -125 },
                right: { xs: -15 },
                opacity: 0.5
              }
            }
          : {
              overflow: 'hidden',
              position: 'relative',
              '&:after': {
                content: '""',
                position: 'absolute',
                width: 210,
                height: 210,
                background: `linear-gradient(210.04deg, ${palette.dark} -50.94%, rgba(144, 202, 249, 0) 83.49%)`,
                borderRadius: '50%',
                top: -30,
                right: -180
              },
              '&:before': {
                content: '""',
                position: 'absolute',
                width: 210,
                height: 210,
                background: `linear-gradient(140.9deg, ${palette.dark} -14.02%, rgba(144, 202, 249, 0) 70.50%)`,
                borderRadius: '50%',
                top: -160,
                right: -130
              }
            })
      }}
    >
      <Box sx={{ p: 2.25 }}>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
          <Box sx={{ position: 'relative', zIndex: 1 }}>
            <Typography
              sx={{
                fontSize: '2.125rem',
                fontWeight: 500,
                mt: 0.25,
                mb: 0.5,
                color: filled ? '#fff' : 'inherit'
              }}
            >
              {value}
            </Typography>
            <Typography sx={{ fontSize: '1rem', fontWeight: 500, color: labelColor }}>{label}</Typography>
            {sub && (
              <Typography variant="caption" sx={{ color: labelColor, opacity: 0.85 }}>
                {sub}
              </Typography>
            )}
          </Box>
          <Avatar
            variant="rounded"
            sx={{
              width: 52,
              height: 52,
              borderRadius: 2,
              bgcolor: avatarBg,
              color: avatarFg,
              mt: 0.25,
              zIndex: 1
            }}
          >
            <Icon size={28} />
          </Avatar>
        </Stack>
      </Box>
    </MainCard>
  );
}
