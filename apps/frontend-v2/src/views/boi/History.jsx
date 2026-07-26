import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import InputAdornment from '@mui/material/InputAdornment';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';

import { IconCalendar, IconFilter, IconSearch } from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';
import { gridSpacing } from 'store/constant';
import { getRecentUploads } from 'api/client';
import RiskBar from './components/RiskBar';
import { PageEnter, StaggerItem } from './components/Motion';
import { severityToChipColor, statusToChipColor } from './utils/status';

const SEVERITY_ORDER = { 'Highly Malicious': 0, Suspicious: 1, 'Low Risk': 2, Safe: 3 };
const FILTERS = ['all', 'Highly Malicious', 'Suspicious', 'Low Risk', 'Safe'];

export default function BoiHistory() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    getRecentUploads(50)
      .then(({ data }) => setItems(data || []))
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(
    () =>
      items
        .filter((i) => {
          const q = search.toLowerCase();
          return !q || i.filename?.toLowerCase().includes(q) || i.sha256?.includes(q);
        })
        .filter((i) => severityFilter === 'all' || i.severity === severityFilter)
        .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)),
    [items, search, severityFilter]
  );

  return (
    <PageEnter>
      <Stack spacing={gridSpacing}>
        <StaggerItem delayIndex={0}>
          <Box>
            <Typography variant="h2" gutterBottom>
              Analysis History
            </Typography>
            <Typography variant="body2" color="text.secondary">
              All submitted APKs and their investigation results
            </Typography>
          </Box>
        </StaggerItem>

        <StaggerItem delayIndex={1}>
          <MainCard contentSX={{ py: 2 }}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search by filename or SHA256…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <IconSearch size={16} />
                    </InputAdornment>
                  )
                }}
              />
              <Stack direction="row" flexWrap="wrap" gap={1} alignItems="center" sx={{ flexShrink: 0 }}>
                <IconFilter size={14} color={theme.palette.text.secondary} />
                {FILTERS.map((s) => {
                  const active = severityFilter === s;
                  return (
                    <Chip
                      key={s}
                      label={s === 'all' ? 'All' : s}
                      size="small"
                      clickable
                      onClick={() => setSeverityFilter(s)}
                      color={active ? (s === 'all' ? 'secondary' : severityToChipColor(s) || 'primary') : 'default'}
                      variant="light"
                    />
                  );
                })}
                <Typography variant="caption" color="text.secondary" sx={{ ml: 1, whiteSpace: 'nowrap' }}>
                  {filtered.length} results
                </Typography>
              </Stack>
            </Stack>
          </MainCard>
        </StaggerItem>

        <StaggerItem delayIndex={2}>
          <MainCard content={false}>
            {loading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
                <CircularProgress />
              </Box>
            ) : error ? (
              <Alert severity="warning" sx={{ m: 2 }}>
                Could not reach backend.
              </Alert>
            ) : filtered.length === 0 ? (
              <Box sx={{ py: 8, textAlign: 'center' }}>
                <Typography variant="subtitle1" color="text.secondary" gutterBottom>
                  {items.length === 0 ? 'No analyses yet' : 'No matching results'}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {items.length === 0 ? 'Upload an APK to get started' : 'Try adjusting your search or filters'}
                </Typography>
              </Box>
            ) : (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Filename</TableCell>
                    <TableCell>SHA256</TableCell>
                    <TableCell>Risk Score</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Analyzed</TableCell>
                    <TableCell />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filtered.map((item) => (
                    <TableRow
                      key={item.apk_id}
                      hover
                      sx={{
                        cursor: item.status === 'completed' ? 'pointer' : 'default',
                        '&:hover': item.status === 'completed' ? { bgcolor: 'secondary.light' } : undefined
                      }}
                      onClick={() => item.status === 'completed' && navigate(`/analysis/${item.apk_id}`)}
                    >
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: 13 }}>{item.filename}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {item.sha256 ? `${item.sha256.slice(0, 16)}…` : '—'}
                      </TableCell>
                      <TableCell>
                        <RiskBar score={item.risk_score} />
                      </TableCell>
                      <TableCell>
                        {item.severity ? (
                          <Chip size="small" label={item.severity} color={severityToChipColor(item.severity)} />
                        ) : (
                          '—'
                        )}
                      </TableCell>
                      <TableCell>
                        <Chip size="small" label={item.status} color={statusToChipColor(item.status)} />
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.75} alignItems="center">
                          <IconCalendar size={14} color={theme.palette.text.secondary} />
                          <Typography variant="caption" color="text.secondary">
                            {item.upload_time ? new Date(item.upload_time).toLocaleDateString('en-IN') : '—'}
                          </Typography>
                        </Stack>
                      </TableCell>
                      <TableCell sx={{ color: 'text.secondary', width: 28 }}>
                        {item.status === 'completed' ? '→' : ''}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </MainCard>
        </StaggerItem>
      </Stack>
    </PageEnter>
  );
}
