import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import CircularProgress from '@mui/material/CircularProgress';
import Divider from '@mui/material/Divider';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Tab from '@mui/material/Tab';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Tabs from '@mui/material/Tabs';
import Typography from '@mui/material/Typography';
import { alpha, useTheme } from '@mui/material/styles';

import {
  IconActivity,
  IconAlertTriangle,
  IconArrowLeft,
  IconBug,
  IconCode,
  IconLock,
  IconNetwork,
  IconShield
} from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';
import { gridSpacing } from 'store/constant';
import { downloadPdf, getAnalysis, getAnalysisStatus, getReport } from 'api/client';
import RiskGauge from './components/RiskGauge';
import AttackChainGraph from './components/AttackChainGraph';
import DecompiledView from './components/DecompiledView';
import { PageEnter, StaggerItem, TabFade } from './components/Motion';

const TABS = ['Overview', 'Static Analysis', 'Dynamic Analysis', 'Threat Intel', 'AI Report', 'Decompiled Source'];

function FlagRow({ label, value, theme }) {
  return (
    <Stack
      direction="row"
      justifyContent="space-between"
      sx={{ py: 1.25, borderBottom: `1px solid ${theme.palette.divider}` }}
    >
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography variant="body2" fontWeight={700} color={value ? 'error.main' : 'success.dark'}>
        {value ? 'Detected' : 'Clean'}
      </Typography>
    </Stack>
  );
}

function SignalChip({ icon: Icon, label, color }) {
  return (
    <Chip
      icon={<Icon size={14} />}
      label={label}
      size="small"
      sx={{
        fontWeight: 600,
        color,
        bgcolor: alpha(color, 0.08),
        border: `1px solid ${alpha(color, 0.25)}`,
        '& .MuiChip-icon': { color }
      }}
      variant="outlined"
    />
  );
}

export default function BoiAnalysis() {
  const theme = useTheme();
  const { id } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState(0);
  const [analysis, setAnalysis] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [processingStatus, setProcessingStatus] = useState(null);

  useEffect(() => {
    if (!id) return;
    let pollInterval = null;

    const loadData = async () => {
      setLoading(true);
      setError(null);
      const [analysisResult, reportResult] = await Promise.allSettled([getAnalysis(id), getReport(id)]);
      const analysisData = analysisResult.status === 'fulfilled' ? analysisResult.value.data : null;
      const reportData = reportResult.status === 'fulfilled' ? reportResult.value.data : null;

      if (!analysisData) {
        setError('Failed to load analysis. Make sure the backend is running and this analysis exists.');
        setLoading(false);
        return;
      }

      setAnalysis(analysisData);
      setReport(reportData);
      setLoading(false);

      const status = analysisData.status;
      if (status === 'processing' || status === 'pending') {
        setProcessingStatus(status);
        pollInterval = setInterval(async () => {
          try {
            const statusRes = await getAnalysisStatus(id);
            const newStatus = statusRes.data.status;
            setProcessingStatus(newStatus);
            if (newStatus === 'completed' || newStatus === 'failed') {
              clearInterval(pollInterval);
              const [a2, r2] = await Promise.allSettled([getAnalysis(id), getReport(id)]);
              if (a2.status === 'fulfilled') setAnalysis(a2.value.data);
              if (r2.status === 'fulfilled') setReport(r2.value.data);
              setProcessingStatus(null);
            }
          } catch {
            clearInterval(pollInterval);
          }
        }, 4000);
      }
    };

    loadData();
    return () => {
      if (pollInterval) clearInterval(pollInterval);
    };
  }, [id]);

  const handleDownloadPdf = async () => {
    try {
      const res = await downloadPdf(id);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      alert('PDF download failed');
    }
  };

  const risk = report?.risk_assessment || {};
  const fraudAnalysis = report?.fraud_intent_analysis || {};
  const sa = analysis?.static_analysis || {};
  const da = analysis?.dynamic_analysis || {};
  const ti = analysis?.threat_intel || {};

  let aiData = {};
  try {
    aiData = analysis?.ai_summary ? JSON.parse(analysis.ai_summary) : {};
  } catch {
    aiData = { summary: analysis?.ai_summary };
  }
  const agentOutputs = aiData.agent_outputs || {};
  const confidence = aiData.confidence != null ? Math.round(aiData.confidence * 100) : null;

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !analysis) {
    return (
      <Stack spacing={2}>
        <Button startIcon={<IconArrowLeft size={16} />} onClick={() => navigate(-1)}>
          Back
        </Button>
        <Alert severity="error">{error || 'No analysis data available for this ID.'}</Alert>
      </Stack>
    );
  }

  return (
    <PageEnter>
    <Stack spacing={gridSpacing}>
      {processingStatus && (
        <Alert severity="warning" icon={<CircularProgress size={16} />}>
          Analysis pipeline is running ({processingStatus})… Results will update automatically.
        </Alert>
      )}

      <StaggerItem delayIndex={0}>
      <Box>
        <Button startIcon={<IconArrowLeft size={16} />} onClick={() => navigate(-1)} sx={{ mb: 1.5 }}>
          Back
        </Button>
        <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2}>
          <Box>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
              <IconShield size={22} color={theme.palette.primary.main} />
              <Typography variant="h2">{analysis.filename || 'APK Analysis'}</Typography>
            </Stack>
            <Typography variant="caption" sx={{ fontFamily: 'monospace' }} color="text.secondary">
              SHA256: {analysis.sha256}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Button variant="outlined" onClick={handleDownloadPdf}>
              Download PDF
            </Button>
            <Chip label={risk.classification || analysis.status} color="primary" />
          </Stack>
        </Stack>
      </Box>
      </StaggerItem>

      <StaggerItem delayIndex={1}>
      <MainCard>
        <Grid container spacing={gridSpacing} alignItems="center">
          <Grid size={{ xs: 12, md: 'auto' }}>
            <RiskGauge score={risk.risk_score || 0} classification={risk.severity} />
          </Grid>
          <Grid size={{ xs: 12, md: 8 }}>
            <Typography variant="h3" color="error.main" gutterBottom>
              {fraudAnalysis.predicted_intent || 'Analysis Pending'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5, maxWidth: 560 }}>
              {risk.classification || 'Pending'} — Detected through static analysis, dynamic sandbox, and AI investigation
            </Typography>
            <Stack direction="row" flexWrap="wrap" gap={1}>
              <SignalChip
                icon={IconAlertTriangle}
                label={`${sa.yara_matches?.length || 0} YARA Matches`}
                color={theme.palette.error.main}
              />
              <SignalChip
                icon={IconNetwork}
                label={`${da.network_requests?.length || 0} C2 Connections`}
                color={theme.palette.orange.dark}
              />
              <SignalChip
                icon={IconCode}
                label={`${sa.suspicious_apis?.length || 0} Suspicious APIs`}
                color={theme.palette.warning.dark}
              />
              <SignalChip
                icon={IconLock}
                label={`${ti.mitre_techniques?.length || 0} MITRE Techniques`}
                color={theme.palette.primary.main}
              />
            </Stack>
          </Grid>
        </Grid>
      </MainCard>
      </StaggerItem>

      <StaggerItem delayIndex={2}>
      <MainCard content={false} sx={{ px: 2, pt: 1 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" allowScrollButtonsMobile>
          {TABS.map((t) => (
            <Tab key={t} label={t} />
          ))}
        </Tabs>
        <Divider />
        <Box sx={{ p: 2.5 }}>
          <TabFade tabKey={tab}>
          {tab === 0 && (
            <Grid container spacing={gridSpacing}>
              <Grid size={{ xs: 12, md: 6 }}>
                <MainCard
                  title={
                    <Stack direction="row" spacing={1} alignItems="center">
                      <IconBug size={16} color={theme.palette.error.main} />
                      <span>Key Indicators</span>
                    </Stack>
                  }
                >
                  <FlagRow label="Obfuscation Detected" value={sa.obfuscation_detected} theme={theme} />
                  <FlagRow label="Dynamic Code Loading" value={sa.dynamic_code_loading} theme={theme} />
                  <FlagRow label="SMS Interception" value={da.sms_intercepted} theme={theme} />
                  <FlagRow label="Accessibility Abuse" value={da.accessibility_abuse} theme={theme} />
                </MainCard>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <MainCard
                  title={
                    <Stack direction="row" spacing={1} alignItems="center">
                      <IconActivity size={16} color={theme.palette.primary.main} />
                      <span>Recommendations</span>
                    </Stack>
                  }
                >
                  {(report?.recommendations || []).length ? (
                    (report.recommendations || []).map((r, i) => (
                      <Stack key={i} direction="row" spacing={1.25} sx={{ mb: 1.5 }}>
                        <Chip label={i + 1} size="small" color="primary" sx={{ minWidth: 28 }} />
                        <Typography variant="body2" color="text.secondary">
                          {r}
                        </Typography>
                      </Stack>
                    ))
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      No recommendations yet.
                    </Typography>
                  )}
                </MainCard>
              </Grid>
            </Grid>
          )}

          {tab === 1 && (
            <Stack spacing={gridSpacing}>
              <MainCard title={`Permissions (${sa.permissions?.length || 0})`}>
                <Grid container spacing={1}>
                  {(sa.permissions || []).map((p) => {
                    const name = typeof p === 'string' ? p : p.name;
                    const dangerous = typeof p === 'object' && p.dangerous;
                    const desc = typeof p === 'object' ? p.description : '';
                    return (
                      <Grid key={name} size={{ xs: 12, md: 6 }}>
                        <Box
                          sx={{
                            p: 1.5,
                            borderRadius: 2,
                            border: `1px solid ${theme.palette.divider}`,
                            bgcolor: alpha(theme.palette.primary.main, 0.02)
                          }}
                        >
                          <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                            <Box>
                              <Typography
                                variant="body2"
                                fontWeight={700}
                                sx={{ fontFamily: 'monospace', color: dangerous ? 'error.main' : 'text.primary' }}
                              >
                                {name}
                              </Typography>
                              {desc && (
                                <Typography variant="caption" color="text.secondary">
                                  {desc}
                                </Typography>
                              )}
                            </Box>
                            <Chip
                              size="small"
                              label={dangerous ? 'DANGEROUS' : 'NORMAL'}
                              color={dangerous ? 'error' : 'success'}
                              variant="outlined"
                            />
                          </Stack>
                        </Box>
                      </Grid>
                    );
                  })}
                </Grid>
                {!sa.permissions?.length && <Alert severity="info">No permissions listed.</Alert>}
              </MainCard>

              <MainCard title="YARA Rule Matches">
                <Stack direction="row" flexWrap="wrap" gap={1}>
                  {(sa.yara_matches || []).map((y) => (
                    <Chip
                      key={typeof y === 'string' ? y : JSON.stringify(y)}
                      label={typeof y === 'string' ? y : y.rule || JSON.stringify(y)}
                      color="error"
                      variant="outlined"
                      sx={{ fontFamily: 'monospace' }}
                    />
                  ))}
                  {!sa.yara_matches?.length && (
                    <Typography variant="body2" color="text.secondary">
                      No YARA matches.
                    </Typography>
                  )}
                </Stack>
              </MainCard>

              <MainCard title="Hardcoded URLs / IPs">
                {(sa.hardcoded_urls || []).map((u) => (
                  <Typography
                    key={u}
                    variant="body2"
                    sx={{
                      fontFamily: 'monospace',
                      color: 'orange.dark',
                      py: 0.75,
                      borderBottom: `1px solid ${theme.palette.divider}`
                    }}
                  >
                    {u}
                  </Typography>
                ))}
                {!sa.hardcoded_urls?.length && (
                  <Typography variant="body2" color="text.secondary">
                    None found.
                  </Typography>
                )}
              </MainCard>
            </Stack>
          )}

          {tab === 2 && (
            <Stack spacing={gridSpacing}>
              <MainCard title="Dynamic Sandbox Environment & Execution">
                <Grid container spacing={2}>
                  {[
                    {
                      label: 'Execution Engine',
                      value: da.source === 'adb_dynamic' ? 'ADB + Emulator Engine' : da.source || 'Standard Sandbox'
                    },
                    { label: 'Installed Package', value: da.installed_package || 'Active Sandbox' },
                    { label: 'Frida Runtime Hooks', value: `${da.frida?.scripts_injected?.length || 0} Scripts Active` },
                    { label: 'Sandbox Duration', value: `${da.sandbox_duration_seconds || 5} seconds` }
                  ].map((item) => (
                    <Grid key={item.label} size={{ xs: 12, sm: 6, md: 3 }}>
                      <Box
                        sx={{
                          p: 2,
                          borderRadius: 2,
                          border: `1px solid ${theme.palette.divider}`,
                          bgcolor: alpha(theme.palette.secondary.main, 0.04)
                        }}
                      >
                        <Typography variant="caption" color="text.secondary">
                          {item.label}
                        </Typography>
                        <Typography variant="subtitle1" sx={{ mt: 0.5, fontFamily: item.label.includes('Package') ? 'monospace' : 'inherit' }}>
                          {item.value}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </MainCard>

              <Grid container spacing={gridSpacing}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <MainCard
                    title="SMS / OTP Interception"
                    secondary={
                      <Chip
                        size="small"
                        label={da.sms_intercepted ? 'DETECTED' : 'Clean'}
                        color={da.sms_intercepted ? 'error' : 'success'}
                      />
                    }
                  >
                    {(da.sms_content_samples || []).length ? (
                      da.sms_content_samples.map((s, i) => (
                        <Typography key={i} variant="body2" sx={{ fontFamily: 'monospace', mb: 1 }}>
                          {s}
                        </Typography>
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        No active SMS theft detected during execution.
                      </Typography>
                    )}
                  </MainCard>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <MainCard
                    title="Overlay Attack Detection"
                    secondary={
                      <Chip
                        size="small"
                        label={da.overlay_attack_detected ? 'DETECTED' : 'Clean'}
                        color={da.overlay_attack_detected ? 'error' : 'success'}
                      />
                    }
                  >
                    {(da.overlay_events || []).length ? (
                      da.overlay_events.map((e, i) => (
                        <Typography key={i} variant="body2" color="error.main" sx={{ fontFamily: 'monospace', mb: 1 }}>
                          {typeof e === 'string' ? e : JSON.stringify(e)}
                        </Typography>
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary">
                        No overlay window abuse detected.
                      </Typography>
                    )}
                  </MainCard>
                </Grid>
              </Grid>

              <MainCard title="Runtime Network Requests & C2 Connections" content={false}>
                {(da.network_requests || []).length ? (
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>URL / Endpoint</TableCell>
                        <TableCell>Method</TableCell>
                        <TableCell>Risk Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {da.network_requests.map((r, i) => (
                        <TableRow key={i}>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: 12 }}>{r.url || r}</TableCell>
                          <TableCell sx={{ fontFamily: 'monospace', color: 'primary.main' }}>{r.method || '—'}</TableCell>
                          <TableCell>
                            <Typography variant="body2" fontWeight={700} color={r.suspicious ? 'error.main' : 'success.dark'}>
                              {r.suspicious ? 'Malicious C2' : 'Benign'}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <Box sx={{ p: 2.5 }}>
                    <Typography variant="body2" color="text.secondary">
                      No external C2 HTTP requests captured during the dynamic window.
                    </Typography>
                  </Box>
                )}
              </MainCard>

              <MainCard title="Background Services & Active Processes">
                {(da.background_services || []).length ? (
                  da.background_services.map((s) => (
                    <Typography
                      key={s}
                      variant="body2"
                      sx={{
                        fontFamily: 'monospace',
                        color: 'orange.dark',
                        p: 1.25,
                        mb: 1,
                        borderRadius: 1,
                        bgcolor: alpha(theme.palette.orange.main, 0.08),
                        border: `1px solid ${theme.palette.divider}`
                      }}
                    >
                      {s}
                    </Typography>
                  ))
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No persistent background services registered.
                  </Typography>
                )}
              </MainCard>

              <MainCard title="Fraud Journey & Attack Vector Reconstruction">
                <AttackChainGraph height={300} />
              </MainCard>
            </Stack>
          )}

          {tab === 3 && (
            <Stack spacing={gridSpacing}>
              <MainCard title="MITRE ATT&CK Techniques">
                <Grid container spacing={1.5}>
                  {(ti.mitre_techniques || []).map((t, i) => (
                    <Grid key={t.id || i} size={{ xs: 12, md: 6 }}>
                      <Box
                        sx={{
                          p: 1.75,
                          borderRadius: 2,
                          bgcolor: alpha(theme.palette.error.main, 0.05),
                          border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
                        }}
                      >
                        <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                          <Typography variant="body2" fontWeight={700} color="error.main" sx={{ fontFamily: 'monospace' }}>
                            {t.id || t.technique_id || 'T?'}
                          </Typography>
                          <Chip size="small" label={t.tactic || '—'} />
                        </Stack>
                        <Typography variant="body2" color="text.secondary">
                          {t.name || t.technique || ''}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
                {!ti.mitre_techniques?.length && <Alert severity="info">No MITRE mappings.</Alert>}
              </MainCard>

              <MainCard title="Malicious Indicators">
                <Stack spacing={1}>
                  {[...(ti.malicious_domains || []), ...(ti.malicious_ips || [])].map((ioc) => (
                    <Alert key={ioc} severity="error" icon={<IconAlertTriangle size={16} />} variant="outlined">
                      <Typography sx={{ fontFamily: 'monospace', fontSize: 13 }}>{ioc}</Typography>
                    </Alert>
                  ))}
                  {!ti.malicious_domains?.length && !ti.malicious_ips?.length && (
                    <Typography variant="body2" color="text.secondary">
                      No malicious IOCs listed.
                    </Typography>
                  )}
                </Stack>
              </MainCard>
            </Stack>
          )}

          {tab === 4 && (
            <Stack spacing={gridSpacing}>
              <MainCard
                title="AI Investigation Report"
                secondary={
                  <Stack direction="row" spacing={1}>
                    <Chip size="small" label="llama3:8b" color="primary" variant="outlined" />
                    {aiData.classification && <Chip size="small" label={aiData.classification} color="error" />}
                    {confidence != null && <Chip size="small" label={`Confidence: ${confidence}%`} />}
                  </Stack>
                }
              >
                {aiData.summary || report?.executive_summary ? (
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{
                      whiteSpace: 'pre-line',
                      lineHeight: 1.8,
                      p: 2,
                      borderRadius: 2,
                      bgcolor: alpha(theme.palette.primary.main, 0.03),
                      border: `1px solid ${theme.palette.divider}`
                    }}
                  >
                    {aiData.summary || report?.executive_summary}
                  </Typography>
                ) : (
                  <Alert severity="info">AI report not yet available. Upload the APK again to generate a fresh report.</Alert>
                )}
              </MainCard>

              {Object.keys(agentOutputs).length > 0 && (
                <MainCard title="Agent Analysis Breakdown">
                  <Grid container spacing={2}>
                    {[
                      { key: 'static', label: 'Static Agent' },
                      { key: 'dynamic', label: 'Dynamic Agent' },
                      { key: 'threat_intel', label: 'Threat Intel Agent' },
                      { key: 'knowledge', label: 'Knowledge Base Agent' }
                    ].map(
                      ({ key, label }) =>
                        agentOutputs[key] && (
                          <Grid key={key} size={{ xs: 12, md: 6 }}>
                            <Box
                              sx={{
                                p: 2,
                                borderRadius: 2,
                                border: `1px solid ${theme.palette.divider}`,
                                bgcolor: alpha(theme.palette.secondary.main, 0.04),
                                height: '100%'
                              }}
                            >
                              <Typography variant="caption" color="primary" fontWeight={700} sx={{ letterSpacing: 0.5 }}>
                                {label.toUpperCase()}
                              </Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mt: 1, lineHeight: 1.7 }}>
                                {agentOutputs[key]}
                              </Typography>
                            </Box>
                          </Grid>
                        )
                    )}
                  </Grid>
                </MainCard>
              )}

              {aiData.recommendations?.length > 0 && (
                <MainCard title="Recommendations">
                  {aiData.recommendations.map((rec, i) => (
                    <Stack
                      key={i}
                      direction="row"
                      spacing={1.5}
                      sx={{
                        p: 1.5,
                        mb: 1,
                        borderRadius: 2,
                        border: `1px solid ${theme.palette.divider}`,
                        bgcolor: alpha(theme.palette.primary.main, 0.02)
                      }}
                    >
                      <Typography color="primary" fontWeight={700}>
                        {i + 1}.
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {rec}
                      </Typography>
                    </Stack>
                  ))}
                </MainCard>
              )}

              {aiData.mitre_mappings?.length > 0 && (
                <MainCard title="MITRE ATT&CK Mappings">
                  <Stack direction="row" flexWrap="wrap" gap={1}>
                    {aiData.mitre_mappings.map((t, i) => (
                      <Chip key={i} label={t} color="error" variant="outlined" sx={{ fontFamily: 'monospace' }} />
                    ))}
                  </Stack>
                </MainCard>
              )}
            </Stack>
          )}

          {tab === 5 && <DecompiledView apkId={id} />}
          </TabFade>
        </Box>
      </MainCard>
      </StaggerItem>
    </Stack>
    </PageEnter>
  );
}
