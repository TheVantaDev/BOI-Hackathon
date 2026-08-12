import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';

import { IconShield } from '@tabler/icons-react';

// ==============================|| LOGO — BOI COGNIDROID ||============================== //

export default function Logo({ compact = false }) {
  const theme = useTheme();

  return (
    <Stack direction="row" alignItems="center" spacing={compact ? 0 : 1.25} sx={{ textDecoration: 'none' }}>
      <Box
        sx={{
          width: 36,
          height: 36,
          borderRadius: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
          background: `linear-gradient(135deg, ${theme.palette.secondary.main}, ${theme.palette.secondary.dark})`,
          color: '#fff',
          boxShadow: `0 4px 12px ${alpha(theme.palette.secondary.main, 0.35)}`
        }}
      >
        <IconShield size={18} />
      </Box>
      <Box
        sx={{
          lineHeight: 1.15,
          overflow: 'hidden',
          maxWidth: compact ? 0 : 160,
          opacity: compact ? 0 : 1,
          whiteSpace: 'nowrap',
          transition: (t) =>
            t.transitions.create(['max-width', 'opacity'], {
              easing: t.transitions.easing.easeInOut,
              duration: 250
            })
        }}
      >
        <Typography
          sx={{
            fontSize: '1.125rem',
            fontWeight: 800,
            color: 'text.primary',
            letterSpacing: 0.2,
            lineHeight: 1.2
          }}
        >
          BOI Cognidroid
        </Typography>
        <Typography
          variant="caption"
          sx={{
            color: 'secondary.main',
            fontWeight: 600,
            letterSpacing: 1,
            textTransform: 'uppercase',
            fontSize: 10
          }}
        >
          AI Platform
        </Typography>
      </Box>
    </Stack>
  );
}
