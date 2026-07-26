import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { alpha } from '@mui/material/styles';

import { IconShield } from '@tabler/icons-react';

// ==============================|| LOGO — BOI SENTINEL ||============================== //

export default function Logo() {
  const theme = useTheme();

  return (
    <Stack direction="row" alignItems="center" spacing={1.25} sx={{ textDecoration: 'none' }}>
      <Box
        sx={{
          width: 36,
          height: 36,
          borderRadius: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
          color: '#fff',
          boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.35)}`
        }}
      >
        <IconShield size={18} />
      </Box>
      <Box sx={{ lineHeight: 1.15 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: 'text.primary', letterSpacing: 0.2 }}>
          BOI Sentinel
        </Typography>
        <Typography
          variant="caption"
          sx={{
            color: 'primary.main',
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
