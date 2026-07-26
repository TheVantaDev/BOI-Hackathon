import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import CardActions from '@mui/material/CardActions';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';

import ChevronRightOutlinedIcon from '@mui/icons-material/ChevronRightOutlined';

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
import SkeletonEarningCard from 'ui-component/cards/Skeleton/EarningCard';
import { gridSpacing } from 'store/constant';
import { getDashboardStats } from 'api/client';
import StatTile from './components/StatTile';
import RiskBar from './components/RiskBar';
import { PageEnter, StaggerItem } from './components/Motion';
import { severityChartColor, severityToChipColor, statusToChipColor } from './utils/status';

const EMPTY = {
  total_uploads: 0,
  completed: 0,
  processing: 0,
  failed: 0,
  severity_distribution: {},
  recent_uploads: [],
  weekly_activity: []
};

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

  const pieData = Object.entries(stats.severity_distribution || {}).map(([name, value]) => ({
    name,
    value,
    color: severityChartColor(name, theme)
  }));

  const barData = stats.weekly_activity?.length
    ? stats.weekly_activity
    : ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((label) => ({ label, count: 0 }));

  const threats =
    (stats.severity_distribution?.['Highly Malicious'] || 0) + (stats.severity_distribution?.Suspicious || 0);

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

        {loading ? (
          [0, 1, 2, 3].map((i) => (
            <Grid key={i} size={{ xs: 12, sm: 6, md: 3 }}>
              <SkeletonEarningCard />
            </Grid>
          ))
        ) : (
          <>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <StaggerItem delayIndex={1}>
                <StatTile
                  label="Total Analyzed"
                  value={stats.total_uploads}
                  sub="All time"
                  tone="primary"
                  variant="filled"
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
                  tone="error"
                  variant="filled"
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
                  tone="secondary"
                  variant="filled"
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
                  tone="success"
                  variant="light"
                  icon="check"
                />
              </StaggerItem>
            </Grid>
          </>
        )}

        <Grid size={12}>
          <StaggerItem delayIndex={5}>
            <Grid container spacing={gridSpacing}>
              <Grid size={{ xs: 12, md: 4 }}>
                <MainCard title="Severity Distribution" sx={{ height: '100%' }}>
                  <Box sx={{ height: 200 }}>
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
              </Grid>

              <Grid size={{ xs: 12, md: 8 }}>
                <MainCard title="Weekly Analysis Activity" sx={{ height: '100%' }}>
                  <Box sx={{ height: 260 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={barData} barSize={24}>
                        <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.grey[200]} vertical={false} />
                        <XAxis dataKey="label" tick={{ fontSize: 11, fill: theme.palette.text.secondary }} axisLine={false} tickLine={false} />
                        <YAxis tick={{ fontSize: 11, fill: theme.palette.text.secondary }} axisLine={false} tickLine={false} />
                        <Tooltip />
                        <Bar dataKey="count" fill={theme.palette.secondary.main} radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </Box>
                </MainCard>
              </Grid>
            </Grid>
          </StaggerItem>
        </Grid>

        <Grid size={12}>
          <StaggerItem delayIndex={6}>
            <MainCard title="Recent Uploads" content={false}>
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
                          '&:hover': { bgcolor: 'secondary.light' }
                        }}
                        onClick={() => u.status === 'completed' && navigate(`/analysis/${u.apk_id}`)}
                      >
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, pl: 3 }}>{u.filename}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                          {u.sha256 ? `${u.sha256.slice(0, 16)}…` : '—'}
                        </TableCell>
                        <TableCell>
                          <RiskBar score={u.risk_score} />
                        </TableCell>
                        <TableCell>
                          {u.severity ? (
                            <Chip size="small" label={u.severity} color={severityToChipColor(u.severity)} />
                          ) : (
                            '—'
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip size="small" label={u.status} color={statusToChipColor(u.status)} />
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
              <CardActions sx={{ p: 1.25, justifyContent: 'center' }}>
                <Button size="small" disableElevation onClick={() => navigate('/history')}>
                  View All
                  <ChevronRightOutlinedIcon />
                </Button>
              </CardActions>
            </MainCard>
          </StaggerItem>
        </Grid>
      </Grid>
    </PageEnter>
  );
}
