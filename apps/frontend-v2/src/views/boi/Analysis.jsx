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
  IconListCheck,
  IconLock,
  IconNetwork,
  IconShield
} from '@tabler/icons-react';

import MainCard from 'ui-component/cards/MainCard';
import SkeletonPopularCard from 'ui-component/cards/Skeleton/PopularCard';
import { gridSpacing } from 'store/constant';
import {
  downloadActionsPdf,
  downloadPdf,
  getActions,
  getAnalysis,
  getAnalysisStatus,
  getReport
} from 'api/client';
import RiskGauge from './components/RiskGauge';
import AttackChainGraph from './components/AttackChainGraph';
import DecompiledView from './components/DecompiledView';
import { PageEnter, StaggerItem, TabFade } from './components/Motion';
import { classificationToChipColor } from './utils/status';

const TABS = ['Overview', 'Static Analysis', 'Dynamic Analysis', 'AI Report', 'Actions', 'Decompiled Source'];

const PRIORITY_COLOR = {
  P1: 'error',
  P2: 'warning',
  P3: 'default',
  P4: 'default'
};

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

function SignalChip({ icon: Icon, label, color = 'primary' }) {
  return (
    <Chip
      icon={<Icon size={14} />}
      label={label}
      size="small"
      color={color}
      sx={{ fontWeight: 600, '& .MuiChip-icon': { color: 'inherit' } }}
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
  const [actionsData, setActionsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [processingStatus, setProcessingStatus] = useState(null);

  useEffect(() => {
    if (!id) return;
    let pollInterval = null;

    const loadData = async () => {
      setLoading(true);
      setError(null);
      const [analysisResult, reportResult, actionsResult] = await Promise.allSettled([
        getAnalysis(id),
        getReport(id),
        getActions(id)
      ]);
      const analysisData = analysisResult.status === 'fulfilled' ? analysisResult.value.data : null;
      const reportData = reportResult.status === 'fulfilled' ? reportResult.value.data : null;
      const actionsPayload = actionsResult.status === 'fulfilled' ? actionsResult.value.data : null;

      if (!analysisData) {
        setError('Failed to load analysis. Make sure the backend is running and this analysis exists.');
        setLoading(false);
        return;
      }

      setAnalysis(analysisData);
      setReport(reportData);
      setActionsData(actionsPayload);
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
              const [a2, r2, act2] = await Promise.allSettled([
                getAnalysis(id),
                getReport(id),
                getActions(id)
              ]);
              if (a2.status === 'fulfilled') setAnalysis(a2.value.data);
              if (r2.status === 'fulfilled') setReport(r2.value.data);
              if (act2.status === 'fulfilled') setActionsData(act2.value.data);
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
      alert('Report PDF download failed');
    }
  };

  const handleDownloadActions = async () => {
    try {
      const res = await downloadActionsPdf(id);
      const url = window.URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `actions-${id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      alert('Actions PDF download failed');
    }
  };

  const risk = report?.risk_assessment || {};
  const fraudAnalysis = report?.fraud_intent_analysis || {};
  const sa = analysis?.static_analysis || {};
  const da = analysis?.dynamic_analysis || {};
  const ti = analysis?.threat_intel || {};
  const actionItems = actionsData?.actions || [];
  const canDownloadActions = actionItems.length > 0;

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
      <Box sx={{ p: 1 }}>
        <SkeletonPopularCard />
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
      <Box className="page-header">
        <Button startIcon={<IconArrowLeft size={16} />} onClick={() => navigate(-1)} sx={{ mb: 1.5 }}>
          Back
        </Button>
        <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={2}>
          <Box>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 0.5 }}>
              <IconShield size={22} color={theme.palette.primary.main} />
              <Typography variant="h2" className="page-heading" sx={{ mb: '0 !important' }}>
                {analysis.filename || 'APK Analysis'}
              </Typography>
            </Stack>
            <Typography variant="caption" sx={{ fontFamily: 'monospace' }} color="text.secondary">
              SHA256: {analysis.sha256}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Button variant="outlined" onClick={handleDownloadPdf}>
              Download Report
            </Button>
            <Button variant="outlined" onClick={handleDownloadActions} disabled={!canDownloadActions}>
              Download Actions
            </Button>
            <Chip
              label={risk.classification || analysis.status}
              color={classificationToChipColor(risk.classification || risk.severity || analysis.status)}
            />
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
              <SignalChip icon={IconAlertTriangle} label={`${sa.yara_matches?.length || 0} YARA Matches`} color="error" />
              <SignalChip icon={IconNetwork} label={`${da.network_requests?.length || 0} C2 Connections`} color="warning" />
              <SignalChip icon={IconCode} label={`${sa.suspicious_apis?.length || 0} Suspicious APIs`} color="warning" />
            </Stack>
          </Grid>
        </Grid>
      </MainCard>
      </StaggerItem>

      <StaggerItem delayIndex={2}>
      <MainCard content={false} sx={{ overflow: 'hidden' }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" allowScrollButtonsMobile sx={{ px: 1, pt: 0.5 }}>
          {TABS.map((t) => (
            <Tab key={t} label={t} />
          ))}
        </Tabs>
        <Divider />
        <Box sx={{ p: 3 }}>
          <TabFade tabKey={tab}>
          {tab === 0 && (
            <>
            <Grid container spacing={gridSpacing} alignItems="stretch">
              <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
                <MainCard
                  sx={{ width: '100%', height: '100%' }}
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
              <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
                <MainCard
                  sx={{ width: '100%', height: '100%' }}
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
              {(report?.shap_explainability || []).filter(s => s.shap_value > 0).length > 0 && (
                <MainCard
                  title={
                    <Stack direction="row" spacing={1} alignItems="center">
                      <IconActivity size={16} color={theme.palette.primary.main} />
                      <span>SHAP Feature Importance - What Drove the Risk Score</span>
                    </Stack>
                  }
                  sx={{ mt: 2 }}
                >
                  <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: 'block' }}>
                    Each bar shows how much a feature increased (red) or decreased (green) the malware risk score. Based on SHAP (SHapley Additive exPlanations) values from the XGBoost model.
                  </Typography>
                  <Stack spacing={0.75}>
                    {(report?.shap_explainability || [])
                      .filter(s => s.shap_value > 0.001)
                      .sort((a, b) => b.shap_value - a.shap_value)
                      .slice(0, 15)
                      .map((s, i) => {
                        const maxShap = Math.max(
                          ...(report?.shap_explainability || []).filter(x => x.shap_value > 0).map(x => x.shap_value),
                          0.01
                        );
                        const pct = Math.min((s.shap_value / maxShap) * 100, 100);
                        const isRisk = s.direction === 'increases_risk';
                        return (
                          <Stack key={i} direction="row" alignItems="center" spacing={1.5}>
                            <Typography
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                minWidth: 180,
                                textAlign: 'right',
                                color: 'text.secondary',
                                fontSize: 11,
                              }}
                            >
                              {s.feature}
                            </Typography>
                            <Box sx={{ flex: 1, position: 'relative', height: 18, bgcolor: 'grey.100', borderRadius: 1, overflow: 'hidden' }}>
                              <Box
                                sx={{
                                  position: 'absolute',
                                  left: 0,
                                  top: 0,
                                  height: '100%',
                                  width: `${pct}%`,
                                  bgcolor: isRisk ? 'error.main' : 'success.main',
                                  borderRadius: 1,
                                  opacity: 0.75,
                                  transition: 'width 0.6s ease',
                                }}
                              />
                            </Box>
                            <Chip
                              size="small"
                              label={s.value > 0 ? 'PRESENT' : 'ABSENT'}
                              color={s.value > 0 ? (isRisk ? 'error' : 'success') : 'default'}
                              sx={{ minWidth: 70, fontSize: 10, height: 20 }}
                            />
                          </Stack>
                        );
                      })}
                  </Stack>
                </MainCard>
              )}
            </>
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
                            bgcolor: 'grey.50',
                            transition: 'box-shadow 0.2s ease, background-color 0.2s ease',
                            '&:hover': {
                              bgcolor: 'secondary.light',
                              boxShadow: '0 4px 14px rgba(16, 24, 40, 0.06)'
                            }
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

              {sa.quark_crime_count > 0 && (
              <MainCard title="QuarkEngine Behavioral Crime Analysis">
                <Grid container spacing={2}>
                  {[
                    { label: 'Crime Count', value: sa.quark_crime_count ?? 0 },
                    { label: 'Max Confidence', value: sa.quark_max_confidence != null ? `${(sa.quark_max_confidence * 100).toFixed(0)}%` : '0%' },
                    { label: 'Banking Crime', value: sa.quark_banking_crime ? 'Detected' : 'Clean', color: sa.quark_banking_crime ? 'error.main' : 'success.dark' },
                    { label: 'SMS Crime', value: sa.quark_sms_crime ? 'Detected' : 'Clean', color: sa.quark_sms_crime ? 'error.main' : 'success.dark' },
                  ].map((item) => (
                    <Grid key={item.label} size={{ xs: 6, md: 3 }}>
                      <Box sx={{ p: 2, borderRadius: 2, bgcolor: 'grey.50', boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)' }}>
                        <Typography variant="caption" color="text.secondary">{item.label}</Typography>
                        <Typography variant="subtitle1" fontWeight={700} sx={{ mt: 0.5 }} color={item.color || 'text.primary'}>
                          {item.value}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </MainCard>
              )}
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
                          bgcolor: 'grey.50',
                          boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)'
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

              <Grid container spacing={gridSpacing} alignItems="stretch">
                <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
                  <MainCard
                    sx={{ width: '100%', height: '100%' }}
                    title="SMS / OTP Interception"
                    secondary={
                      <Chip size="small" label={da.sms_intercepted ? 'DETECTED' : 'Clean'} color={da.sms_intercepted ? 'error' : 'success'} />
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
                <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex' }}>
                  <MainCard
                    sx={{ width: '100%', height: '100%' }}
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
                        <TableRow
                          key={i}
                          hover
                          sx={{
                            transition: 'background-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease',
                            '&:hover': {
                              bgcolor: 'secondary.light',
                              boxShadow: '0 4px 14px rgba(16, 24, 40, 0.08)',
                              transform: 'translateY(-2px)',
                              position: 'relative',
                              zIndex: 1
                            }
                          }}
                        >
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
                        bgcolor: alpha(theme.palette.orange.main, 0.08)
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
                <AttackChainGraph elements={(() => { const j = fraudAnalysis.journey_stages; if (!j?.nodes?.length) return undefined; return [...j.nodes.map(n => ({ data: n.data, position: n.position })), ...j.edges]; })()} height={300} />
              </MainCard>
            </Stack>
          )}

          {tab === 3 && (
            <Stack spacing={gridSpacing}>
              <MainCard
                title="AI Investigation Report"
                secondary={
                  <Stack direction="row" spacing={1}>
                    <Chip size="small" label="llama3.2:3b" color="primary" />
                    {aiData.classification && <Chip size="small" label={aiData.classification} color="error" />}
                    {confidence != null && <Chip size="small" label={`Confidence: ${confidence}%`} color="secondary" />}
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
                      bgcolor: 'grey.50',
                      boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)'
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
                                bgcolor: 'grey.50',
                                boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)',
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
                        bgcolor: 'grey.50',
                        boxShadow: '0 1px 2px rgba(16, 24, 40, 0.04)'
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
                      <Chip key={i} label={t} color="error" sx={{ fontFamily: 'monospace' }} />
                    ))}
                  </Stack>
                </MainCard>
              )}
            </Stack>
          )}

          {tab === 4 && (
            <Stack spacing={gridSpacing}>
              <MainCard
                title={
                  <Stack direction="row" spacing={1} alignItems="center">
                    <IconListCheck size={16} color={theme.palette.primary.main} />
                    <span>Recommended Bank Actions</span>
                  </Stack>
                }
                secondary={
                  <Typography variant="caption" color="text.secondary">
                    Status: {actionsData?.status || 'missing'}
                    {actionsData?.generated_at ? ` · ${new Date(actionsData.generated_at).toLocaleString()}` : ''}
                  </Typography>
                }
              >
                <Typography variant="body2" color="text.secondary">
                  Operational playbook for SOC / Fraud / IT — separate from the investigation report.
                </Typography>
              </MainCard>

              {actionItems.length > 0 ? (
                actionItems.map((a, i) => {
                  const p = (a.priority || 'P3').toUpperCase();
                  return (
                    <MainCard
                      key={i}
                      sx={{
                        borderLeft: 3,
                        borderColor: p === 'P1' ? 'error.main' : p === 'P2' ? 'warning.main' : 'divider'
                      }}
                    >
                      <Stack direction="row" justifyContent="space-between" spacing={1} sx={{ mb: 1 }}>
                        <Typography variant="subtitle1" fontWeight={700}>
                          {i + 1}. {a.title}
                        </Typography>
                        <Chip size="small" label={p} color={PRIORITY_COLOR[p] || 'default'} />
                      </Stack>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                        Owner: <strong>{a.owner || '—'}</strong> · SLA: <strong>{a.sla || '—'}</strong>
                      </Typography>
                      {Array.isArray(a.steps) && a.steps.length > 0 && (
                        <Box component="ol" sx={{ m: 0, pl: 2.5, mb: a.rationale ? 1.5 : 0 }}>
                          {a.steps.map((step, si) => (
                            <Typography key={si} component="li" variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                              {step}
                            </Typography>
                          ))}
                        </Box>
                      )}
                      {a.rationale && (
                        <Typography variant="body2" color="text.secondary" sx={{ pt: 1.5, borderTop: 1, borderColor: 'divider' }}>
                          <strong>Why:</strong> {a.rationale}
                        </Typography>
                      )}
                    </MainCard>
                  );
                })
              ) : (
                <Alert severity="info">
                  No recommended actions yet. If analysis is complete, regenerate via the API or re-upload the APK.
                </Alert>
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
