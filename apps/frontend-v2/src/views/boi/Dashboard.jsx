import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { alpha, useTheme } from '@mui/material/styles';

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

import MainCard from 'ui-component/cards/MainCard';
import { gridSpacing } from 'store/constant';
import { getDashboardStats } from 'api/client';
import StatTile from './components/StatTile';
import { PageEnter, StaggerItem } from './components/Motion';

const EMPTY = {
  total_uploads: 0,
  completed: 0,
  processing: 0,
  failed: 0,
  severity_distribution: {},
  recent_uploads: [],
  weekly_activity: []
};

function statusColor(status) {
  if (status === 'completed') return 'success';
  if (status === 'processing') return 'info';
  if (status === 'failed') return 'error';
  return 'default';
}

function RiskBar({ score, theme }) {
  if (score == null) {
    return (
      <Typography variant="caption" color="text.secondary">
        —
      </Typography>
    );
  }
  const color =
    score >= 75
      ? theme.palette.error.main
      : score >= 55
        ? theme.palette.orange.dark
        : score >= 30
          ? theme.palette.warning.dark
          : theme.palette.success.dark;
  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 100 }}>
      <Box sx={{ flex: 1, height: 6, bgcolor: theme.palette.grey[200], borderRadius: 1, overflow: 'hidden' }}>
        <Box sx={{ width: `${score}%`, height: '100%', bgcolor: color, borderRadius: 1 }} />
      </Box>
      <Typography variant="body2" fontWeight={700}>
        {score}
      </Typography>
    </Stack>
  );
}

export default function BoiDashboard() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [stats, setStats] = useState(EMPTY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    getDashboardStats()
      .then(({ data }) => setStats(data))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  const severityColors = {
    Safe: theme.palette.success.main,
    'Low Risk': theme.palette.success.dark,
    Suspicious: theme.palette.orange.dark,
    'Highly Malicious': theme.palette.error.main,
    Unknown: theme.palette.grey[500]
  };

  const pieData = Object.entries(stats.severity_distribution || {}).map(([name, value]) => ({
    name,
    value,
    color: severityColors[name] || theme.palette.grey[500]
  }));

  const barData = stats.weekly_activity?.length
    ? stats.weekly_activity
    : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((label) => ({ label, count: 0 }));

  const threats =
    (stats.severity_distribution?.['Highly Malicious'] || 0) + (stats.severity_distribution?.Suspicious || 0);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <PageEnter>
        <Grid container spacing={gridSpacing}>
          <Grid size={12}>
            <StaggerItem delayIndex={0}>
              <Typography variant="h2" gutterBottom>
                Threat Intelligence Dashboard
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Real-time APK analysis and malware investigation overview
              </Typography>
              {error && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  Could not reach backend. Connect the backend to see live data.
                </Alert>
              )}
            </StaggerItem>
          </Grid>

          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <StaggerItem delayIndex={1}>
              <StatTile
                label="Total Analyzed"
                value={stats.total_uploads}
                sub="All time"
                color={theme.palette.primary.main}
                icon="shield"
              />
            </StaggerItem>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <StaggerItem delayIndex={2}>
              <StatTile
                label="Threats Detected"
                value={threats}
                sub="Suspicious + Malicious"
                color={theme.palette.error.main}
                icon="alert"
              />
            </StaggerItem>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <StaggerItem delayIndex={3}>
              <StatTile
                label="Processing"
                value={stats.processing}
                sub="In pipeline now"
                color={theme.palette.secondary.main}
                icon="activity"
              />
            </StaggerItem>
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <StaggerItem delayIndex={4}>
              <StatTile
                label="Completed"
                value={stats.completed}
                sub="Successfully analyzed"
                color={theme.palette.success.dark}
                icon="check"
              />
            </StaggerItem>
          </Grid>

          <Grid size={12}>
            <StaggerItem delayIndex={5}>
              <Box
                sx={{
                  display: 'grid',
                  gridTemplateColumns: { xs: '1fr', md: '1fr 1.6fr' },
                  gap: 2,
                  alignItems: 'stretch',
                  mb: 2
                }}
              >
          <MainCard
            title="Severity Distribution"
            border
            sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}
            headerSX={{ px: 3, py: 2, '& .MuiCardHeader-title': { fontSize: 14, fontWeight: 600 } }}
            contentSX={{ px: 3, pt: 2, pb: 3, flex: 1, display: 'flex', flexDirection: 'column' }}
          >
            <Box sx={{ height: 200, flexShrink: 0 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </Box>
            <Stack spacing={0.75} sx={{ mt: 2 }}>
              {pieData.map((d) => (
                <Stack key={d.name} direction="row" alignItems="center" spacing={1}>
                  <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: d.color }} />
                  <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
                    {d.name}
                  </Typography>
                  <Typography variant="body2" fontWeight={700}>
                    {d.value}
                  </Typography>
                </Stack>
              ))}
              {!pieData.length && (
                <Typography variant="body2" color="text.secondary">
                  No severity data yet
                </Typography>
              )}
            </Stack>
          </MainCard>

          <MainCard
            title="Weekly Analysis Activity"
            border
            sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}
            headerSX={{ px: 3, py: 2, '& .MuiCardHeader-title': { fontSize: 14, fontWeight: 600 } }}
            contentSX={{ px: 3, pt: 2, pb: 3, flex: 1, display: 'flex', flexDirection: 'column' }}
          >
            <Box sx={{ flex: 1, minHeight: 200 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} barSize={24}>
                  <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.grey[200]} vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 11, fill: theme.palette.text.secondary }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: theme.palette.text.secondary }} axisLine={false} tickLine={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill={theme.palette.primary.main} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Box>
          </MainCard>
        </Box>
            </StaggerItem>

            <StaggerItem delayIndex={6}>
        <MainCard
          title="Recent Uploads"
          border
          headerSX={{ px: 3, py: 2, '& .MuiCardHeader-title': { fontSize: 14, fontWeight: 600 } }}
          contentSX={{ px: 0, py: 0 }}
          secondary={
            <Button size="small" variant="outlined" onClick={() => navigate('/history')}>
              View All
            </Button>
          }
        >
          {!stats.recent_uploads?.length ? (
            <Box sx={{ py: 6, px: 3, textAlign: 'center' }}>
              <Typography variant="subtitle1" color="text.secondary" gutterBottom>
                {error ? 'Could not reach backend' : 'No uploads yet'}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {error ? 'Connect the backend to see live data' : 'Upload an APK to get started with analysis'}
              </Typography>
            </Box>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ pl: 3 }}>Filename</TableCell>
                  <TableCell>SHA256</TableCell>
                  <TableCell>Risk Score</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Uploaded</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {stats.recent_uploads.map((u) => (
                  <TableRow
                    key={u.apk_id}
                    hover
                    sx={{
                      cursor: 'pointer',
                      '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.04) }
                    }}
                    onClick={() => u.status === 'completed' && navigate(`/analysis/${u.apk_id}`)}
                  >
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, pl: 3 }}>{u.filename}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                      {u.sha256 ? `${u.sha256.slice(0, 16)}…` : '—'}
                    </TableCell>
                    <TableCell>
                      <RiskBar score={u.risk_score} theme={theme} />
                    </TableCell>
                    <TableCell>{u.severity || '—'}</TableCell>
                    <TableCell>
                      <Chip size="small" label={u.status} color={statusColor(u.status)} />
                    </TableCell>
                    <TableCell>{u.upload_time ? new Date(u.upload_time).toLocaleString('en-IN') : '—'}</TableCell>
                    <TableCell sx={{ color: 'text.secondary', width: 28 }}>
                      {u.status === 'completed' ? '→' : ''}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </MainCard>
            </StaggerItem>
          </Grid>
        </Grid>
    </PageEnter>
  );
}
