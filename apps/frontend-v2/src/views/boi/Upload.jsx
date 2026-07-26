import { useCallback, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import LinearProgress from '@mui/material/LinearProgress';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { alpha, useTheme } from '@mui/material/styles';

import { IconCloudUpload, IconShieldCheck } from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';
import { gridSpacing } from 'store/constant';
import { getAnalysisStatus, uploadAPK } from 'api/client';
import { PageEnter, StaggerItem } from './components/Motion';

const PIPELINE = [
  { step: '01', title: 'Reverse Engineering', desc: 'JADX, APKTool, Androguard decompilation' },
  { step: '02', title: 'Static Analysis', desc: 'Permissions, APIs, YARA rules, obfuscation' },
  { step: '03', title: 'Dynamic Sandbox', desc: 'Runtime behavior, network, SMS monitoring' },
  { step: '04', title: 'Threat Intelligence', desc: 'IOC lookup, MITRE ATT&CK mapping' },
  { step: '05', title: 'AI Investigation', desc: 'Multi-agent generative AI analysis' },
  { step: '06', title: 'Risk Scoring', desc: 'XGBoost + SHAP explainability' }
];

const FEATURES = [
  'Banking Trojan Detection',
  'OTP Interception',
  'Overlay Attack',
  'Data Exfiltration',
  'MITRE ATT&CK Mapping'
];

export default function BoiUpload() {
  const theme = useTheme();
  const navigate = useNavigate();
  const inputRef = useRef(null);
  const pollRef = useRef(null);

  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState('idle');
  const [error, setError] = useState('');

  const reset = () => {
    setFile(null);
    setProgress(0);
    setPhase('idle');
    setError('');
    clearInterval(pollRef.current);
  };

  const startPolling = (id) => {
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getAnalysisStatus(id);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          setPhase('done');
          setTimeout(() => navigate(`/analysis/${id}`), 1200);
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setPhase('error');
          setError('Analysis pipeline failed. Please try again.');
        }
      } catch {
        // keep polling
      }
    }, 3000);
  };

  const handleFile = useCallback(
    async (f) => {
      if (!f) return;
      if (!f.name.endsWith('.apk')) {
        setError('Only .apk files are accepted.');
        return;
      }
      setError('');
      setFile(f);
      setPhase('uploading');
      setProgress(0);
      try {
        const { data } = await uploadAPK(f, setProgress);
        if (data.status === 'completed') {
          setPhase('done');
          setTimeout(() => navigate(`/analysis/${data.apk_id}`), 500);
        } else {
          setPhase('analyzing');
          startPolling(data.apk_id);
        }
      } catch (err) {
        setPhase('error');
        setError(err?.response?.data?.detail || 'Upload failed. Is the backend running?');
      }
    },
    [navigate]
  );

  return (
    <PageEnter>
    <Grid container spacing={gridSpacing}>
      <Grid size={12}>
        <StaggerItem delayIndex={0}>
        <Typography variant="h2" gutterBottom>
          Upload APK for Analysis
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Submit a suspicious Android application for automated malware investigation
        </Typography>
        </StaggerItem>
      </Grid>

      <Grid size={{ xs: 12, md: 7 }}>
        <StaggerItem delayIndex={1}>
        <MainCard>
          {phase === 'done' && (
            <Stack alignItems="center" spacing={2} sx={{ py: 8 }}>
              <IconShieldCheck size={52} color={theme.palette.success.main} />
              <Typography variant="h3">Analysis Complete</Typography>
              <Typography color="text.secondary">Redirecting to report…</Typography>
            </Stack>
          )}

          {phase === 'analyzing' && (
            <Stack alignItems="center" spacing={2} sx={{ py: 6 }}>
              <CircularProgress size={48} />
              <Typography variant="h3">AI Engine Analyzing…</Typography>
              <Typography color="text.secondary" align="center" sx={{ maxWidth: 360 }}>
                Running static analysis, dynamic sandbox, and threat intelligence checks
              </Typography>
              <Stack spacing={1} sx={{ mt: 2, width: '100%', maxWidth: 320 }}>
                {PIPELINE.slice(0, 5).map((s) => (
                  <Stack key={s.step} direction="row" spacing={1} alignItems="center">
                    <CircularProgress size={12} />
                    <Typography variant="body2" color="text.secondary">
                      {s.title}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            </Stack>
          )}

          {(phase === 'idle' || phase === 'uploading' || phase === 'error') && (
            <>
              <Box
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  handleFile(e.dataTransfer.files[0]);
                }}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
                onClick={() => phase === 'idle' && inputRef.current?.click()}
                sx={{
                  border: '2px dashed',
                  borderColor: dragging ? 'primary.main' : 'divider',
                  borderRadius: 3,
                  p: { xs: 4, md: 7 },
                  textAlign: 'center',
                  cursor: phase === 'idle' ? 'pointer' : 'default',
                  bgcolor: dragging ? alpha(theme.palette.primary.main, 0.06) : alpha(theme.palette.primary.main, 0.02),
                  transition: 'all 0.2s ease'
                }}
              >
                <input ref={inputRef} type="file" accept=".apk" hidden onChange={(e) => handleFile(e.target.files[0])} />
                <Box
                  sx={{
                    width: 72,
                    height: 72,
                    borderRadius: 3,
                    mx: 'auto',
                    mb: 2.5,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.25)}`,
                    color: 'primary.main'
                  }}
                >
                  <IconCloudUpload size={28} />
                </Box>

                {phase === 'uploading' ? (
                  <Stack spacing={1.5} sx={{ maxWidth: 280, mx: 'auto' }}>
                    <Typography fontWeight={600}>Uploading {file?.name}</Typography>
                    <LinearProgress variant="determinate" value={progress} />
                    <Typography variant="caption" color="text.secondary">
                      {progress}%
                    </Typography>
                  </Stack>
                ) : (
                  <>
                    <Typography variant="h4" gutterBottom>
                      Drop APK here, or{' '}
                      <Box component="span" color="primary.main">
                        browse
                      </Box>
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Supports Android APK files only · Max 200MB
                    </Typography>
                  </>
                )}
              </Box>

              {error && (
                <Alert severity="error" sx={{ mt: 2 }} action={<Button onClick={reset}>Dismiss</Button>}>
                  {error}
                </Alert>
              )}

              <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 2.5 }}>
                {FEATURES.map((f) => (
                  <Chip key={f} label={f} size="small" variant="outlined" />
                ))}
              </Stack>
            </>
          )}
        </MainCard>
        </StaggerItem>
      </Grid>

      <Grid size={{ xs: 12, md: 5 }}>
        <StaggerItem delayIndex={2}>
        <Stack spacing={gridSpacing}>
          <MainCard title="Analysis Pipeline">
            {PIPELINE.map((item, i) => (
              <Box key={item.step}>
                <Stack direction="row" spacing={1.5} sx={{ py: 1.5 }}>
                  <Chip
                    label={item.step}
                    size="small"
                    sx={{
                      fontWeight: 700,
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                      color: 'primary.main',
                      border: `1px solid ${alpha(theme.palette.primary.main, 0.25)}`
                    }}
                  />
                  <Box>
                    <Typography variant="subtitle1">{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Box>
                </Stack>
                {i < PIPELINE.length - 1 && <Divider />}
              </Box>
            ))}
          </MainCard>

          <Alert severity="warning" icon={<IconShieldCheck size={18} />}>
            <Typography variant="subtitle2" gutterBottom>
              Secure Analysis
            </Typography>
            All APKs are executed in an isolated sandbox environment. No data leaves the on-premise deployment.
          </Alert>
        </Stack>
        </StaggerItem>
      </Grid>
    </Grid>
    </PageEnter>
  );
}
