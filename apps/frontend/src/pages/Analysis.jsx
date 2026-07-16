import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, Wifi, Lock, Code2, FileWarning,
  ChevronLeft, ExternalLink, Info, Bug, Activity,
  Folder, FolderOpen, FileCode, ChevronRight, ChevronDown, Loader2
} from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import RiskScoreCard from '../components/RiskScoreCard'
import AttackChainGraph from '../components/AttackChainGraph'
import { getAnalysis, getReport, getDecompiledTree, getDecompiledFile } from '../api/client'

function getLanguageFromFilename(filename) {
  const ext = filename?.split('.').pop()?.toLowerCase()
  const map = { java: 'java', xml: 'xml', smali: 'smali', kt: 'kotlin', json: 'json', yml: 'yaml', yaml: 'yaml', properties: 'properties' }
  return map[ext] || 'text'
}

const TABS = ['Overview', 'Static Analysis', 'Dynamic Analysis', 'Threat Intel', 'AI Report', 'Decompiled Source']

function PermBadge({ dangerous }) {
  return (
    <span
      style={{
        fontSize: 10,
        padding: '2px 8px',
        borderRadius: 4,
        fontWeight: 600,
        background: dangerous ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.08)',
        color: dangerous ? '#ef4444' : '#22c55e',
        border: `1px solid ${dangerous ? 'rgba(239,68,68,0.25)' : 'rgba(34,197,94,0.2)'}`,
      }}
    >
      {dangerous ? 'DANGEROUS' : 'NORMAL'}
    </span>
  )
}

function MitreBadge({ id, name, tactic }) {
  return (
    <div
      style={{
        padding: '10px 14px',
        borderRadius: 8,
        background: 'rgba(239,68,68,0.06)',
        border: '1px solid rgba(239,68,68,0.2)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#ef4444', fontWeight: 700 }}>{id}</span>
        <span style={{ fontSize: 10, color: 'var(--text-3)', padding: '1px 8px', background: 'rgba(100,116,139,0.1)', borderRadius: 4 }}>{tactic}</span>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-2)' }}>{name}</div>
    </div>
  )
}

function TreeNode({ node, expandedDirs, dirContents, onToggleDir, onSelectFile, selectedFile }) {
  const isDir = node.type === 'directory';
  const isExpanded = !!expandedDirs[node.path];
  const children = dirContents[node.path] || [];
  const isSelected = selectedFile === node.path;
  const [isHovered, setIsHovered] = useState(false);
  
  const handleItemClick = () => {
    if (isDir) {
      onToggleDir(node.path);
    } else {
      onSelectFile(node.path, node.name);
    }
  };

  return (
    <div style={{ marginLeft: 8 }}>
      <div
        onClick={handleItemClick}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          padding: '6px 8px',
          borderRadius: 6,
          cursor: 'pointer',
          fontSize: 12,
          color: isSelected ? 'var(--cyan)' : (isHovered ? 'var(--text-1)' : 'var(--text-2)'),
          background: isSelected ? 'rgba(6, 182, 212, 0.1)' : (isHovered ? 'rgba(30, 45, 74, 0.3)' : 'transparent'),
          transition: 'all 0.15s ease',
          userSelect: 'none',
        }}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {isDir ? (
          <>
            <span style={{ color: 'var(--text-3)', display: 'flex', alignItems: 'center' }}>
              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </span>
            <span style={{ color: isExpanded ? 'var(--cyan)' : 'var(--text-3)', display: 'flex', alignItems: 'center' }}>
              {isExpanded ? <FolderOpen size={14} /> : <Folder size={14} />}
            </span>
          </>
        ) : (
          <>
            <span style={{ width: 14 }} />
            <span style={{ color: isSelected ? 'var(--cyan)' : 'var(--text-3)', display: 'flex', alignItems: 'center' }}>
              <FileCode size={14} />
            </span>
          </>
        )}
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {node.name}
        </span>
      </div>
      
      {isDir && isExpanded && (
        <div style={{ borderLeft: '1px solid var(--border)', marginLeft: 15, paddingLeft: 4 }}>
          {children.length === 0 ? (
            <div style={{ padding: '4px 20px', fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>
              Empty
            </div>
          ) : (
            children.map((childNode) => (
              <TreeNode
                key={childNode.path}
                node={childNode}
                expandedDirs={expandedDirs}
                dirContents={dirContents}
                onToggleDir={onToggleDir}
                onSelectFile={onSelectFile}
                selectedFile={selectedFile}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}

function CodeViewer({ content, filename }) {
  if (!content) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-3)', fontSize: 13 }}>
        Select a file from the explorer to view its contents
      </div>
    )
  }

  const language = getLanguageFromFilename(filename);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600, color: 'var(--cyan)', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 8 }}>
        <FileCode size={14} />
        {filename}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase' }}>{language}</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto', background: '#090d16' }}>
        <SyntaxHighlighter
          language={language}
          style={vscDarkPlus}
          showLineNumbers
          wrapLongLines={false}
          customStyle={{
            margin: 0,
            padding: '12px 0',
            background: '#090d16',
            fontSize: 12,
            lineHeight: 1.6,
            minHeight: '100%',
          }}
          lineNumberStyle={{
            minWidth: 45,
            paddingRight: 12,
            color: 'rgba(148,163,184,0.4)',
            userSelect: 'none',
          }}
        >
          {content}
        </SyntaxHighlighter>
      </div>
    </div>
  )
}

function DecompiledView({ apkId }) {
  const [tool, setTool] = useState('jadx');
  const [tree, setTree] = useState([]);
  const [loadingTree, setLoadingTree] = useState(false);
  const [expandedDirs, setExpandedDirs] = useState({});
  const [dirContents, setDirContents] = useState({});
  
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedFileName, setSelectedFileName] = useState('');
  const [fileContent, setFileContent] = useState(null);
  const [loadingFile, setLoadingFile] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  useEffect(() => {
    setTree([]);
    setExpandedDirs({});
    setDirContents({});
    setSelectedFile(null);
    setSelectedFileName('');
    setFileContent(null);
    setErrorMsg(null);
    
    setLoadingTree(true);
    getDecompiledTree(apkId, tool, '')
      .then(resp => {
        setTree(resp.data.tree);
        setLoadingTree(false);
      })
      .catch(err => {
        console.error("Failed to load root tree:", err);
        setErrorMsg("Failed to load decompiled files. Make sure this APK is decompiled.");
        setTree([]);
        setLoadingTree(false);
      });
  }, [apkId, tool]);

  const handleToggleDir = async (path) => {
    const isExpanded = !!expandedDirs[path];
    if (!isExpanded && !dirContents[path]) {
      try {
        const resp = await getDecompiledTree(apkId, tool, path);
        setDirContents(prev => ({ ...prev, [path]: resp.data.tree }));
      } catch (err) {
        console.error("Failed to load folder contents:", err);
      }
    }
    setExpandedDirs(prev => ({ ...prev, [path]: !isExpanded }));
  };

  const handleSelectFile = async (path, name) => {
    setSelectedFile(path);
    setSelectedFileName(name);
    setLoadingFile(true);
    setFileContent(null);
    try {
      const resp = await getDecompiledFile(apkId, tool, path);
      setFileContent(resp.data.content);
      setLoadingFile(false);
    } catch (err) {
      console.error("Failed to load file contents:", err);
      setFileContent("Error: Failed to load file contents.");
      setLoadingFile(false);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, height: 'calc(100vh - 280px)', minHeight: 500 }}>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: 16, borderBottom: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-1)' }}>File Explorer</div>
          <div style={{ display: 'flex', background: 'var(--bg-secondary)', padding: 3, borderRadius: 8, border: '1px solid var(--border)' }}>
            <button
              onClick={() => setTool('jadx')}
              style={{
                flex: 1,
                padding: '6px 0',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                background: tool === 'jadx' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: tool === 'jadx' ? 'var(--cyan)' : 'var(--text-2)',
                transition: 'all 0.15s ease',
              }}
            >
              JADX (Java)
            </button>
            <button
              onClick={() => setTool('apktool')}
              style={{
                flex: 1,
                padding: '6px 0',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                background: tool === 'apktool' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
                color: tool === 'apktool' ? 'var(--cyan)' : 'var(--text-2)',
                transition: 'all 0.15s ease',
              }}
            >
              APKTool (Res/Smali)
            </button>
          </div>
        </div>
        
        <div style={{ flex: 1, overflow: 'auto', padding: '12px 6px' }}>
          {loadingTree ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8, color: 'var(--text-3)' }}>
              <Loader2 size={16} className="animate-spin" /> Loading files...
            </div>
          ) : errorMsg ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--red)', textAlign: 'center' }}>
              {errorMsg}
            </div>
          ) : tree.length === 0 ? (
            <div style={{ padding: 16, fontSize: 12, color: 'var(--text-3)', textAlign: 'center' }}>
              No files decompiled.
            </div>
          ) : (
            tree.map(node => (
              <TreeNode
                key={node.path}
                node={node}
                expandedDirs={expandedDirs}
                dirContents={dirContents}
                onToggleDir={handleToggleDir}
                onSelectFile={handleSelectFile}
                selectedFile={selectedFile}
              />
            ))
          )}
        </div>
      </div>
      
      <div className="card" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {loadingFile ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, gap: 12, color: 'var(--text-3)' }}>
            <Loader2 size={24} className="animate-spin" color="var(--cyan)" />
            <span>Retrieving source code...</span>
          </div>
        ) : (
          <CodeViewer content={fileContent} filename={selectedFileName} />
        )}
      </div>
    </div>
  );
}

export default function Analysis() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [tab, setTab] = useState(0)
  const [analysis, setAnalysis] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    setError(null)
    Promise.all([getAnalysis(id), getReport(id)])
      .then(([a, r]) => {
        setAnalysis(a.data)
        setReport(r.data)
      })
      .catch(() => {
        setError('Failed to load analysis. Make sure the backend is running and this analysis exists.')
      })
      .finally(() => setLoading(false))
  }, [id])

  const sa = analysis?.static_analysis || {}
  const da = analysis?.dynamic_analysis || {}
  const ti = analysis?.threat_intel || {}

  if (loading) {
    return (
      <div style={{ padding: '28px 32px', minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
        <Loader2 size={32} className="animate-spin" color="var(--cyan)" />
        <span style={{ fontSize: 14, color: 'var(--text-2)' }}>Loading analysis...</span>
      </div>
    )
  }

  if (error || !analysis) {
    return (
      <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
        <button onClick={() => navigate(-1)} className="btn-secondary" style={{ marginBottom: 24, fontSize: 12 }}>
          <ChevronLeft size={14} /> Back
        </button>
        <div className="card" style={{ padding: 48, textAlign: 'center' }}>
          <AlertTriangle size={36} color="var(--text-3)" style={{ marginBottom: 16 }} />
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', marginBottom: 8 }}>Analysis Not Found</div>
          <div style={{ fontSize: 13, color: 'var(--text-3)', maxWidth: 400, margin: '0 auto', lineHeight: 1.6 }}>
            {error || 'No analysis data available for this ID. Upload an APK to get started.'}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{ padding: '28px 32px', minHeight: '100vh' }}>
      {/* Back + header */}
      <div className="animate-fade-in-up" style={{ marginBottom: 24 }}>
        <button
          onClick={() => navigate(-1)}
          className="btn-secondary"
          style={{ marginBottom: 16, fontSize: 12 }}
        >
          <ChevronLeft size={14} /> Back
        </button>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 800, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
              <Shield size={20} color="var(--cyan)" />
              {analysis?.filename || 'APK Analysis'}
            </h1>
            <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-3)' }}>
              SHA256: {analysis?.sha256}
            </div>
          </div>
          <div>
            <span
              className={`badge badge-${report?.severity?.toLowerCase().replace(' ', '-') || 'pending'}`}
              style={{ fontSize: 12 }}
            >
              {report?.classification || analysis?.status}
            </span>
          </div>
        </div>
      </div>

      {/* Top row: gauge + quick stats */}
      <div
        className="card animate-fade-in-up delay-100"
        style={{
          padding: 28,
          marginBottom: 20,
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: 40,
          alignItems: 'center',
        }}
      >
        <RiskScoreCard score={report?.risk_score || 0} classification={report?.severity} />
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 4, color: '#ef4444' }}>
            {report?.fraud_intent || 'Analysis Pending'}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 20, lineHeight: 1.5 }}>
            {report?.classification} — Detected through static analysis, dynamic sandbox, and AI investigation
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { icon: FileWarning, label: `${sa.yara_matches?.length || 0} YARA Matches`, color: '#ef4444' },
              { icon: Wifi, label: `${da.network_requests?.length || 0} C2 Connections`, color: '#f97316' },
              { icon: Code2, label: `${sa.suspicious_apis?.length || 0} Suspicious APIs`, color: '#eab308' },
              { icon: Lock, label: `${ti.mitre_techniques?.length || 0} MITRE Techniques`, color: '#3b82f6' },
            ].map(({ icon: Icon, label, color }) => (
              <div
                key={label}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  padding: '6px 12px',
                  borderRadius: 8,
                  background: `${color}10`,
                  border: `1px solid ${color}25`,
                  fontSize: 12,
                  color,
                  fontWeight: 500,
                }}
              >
                <Icon size={13} />
                {label}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div
        className="animate-fade-in-up delay-200"
        style={{
          display: 'flex',
          gap: 4,
          marginBottom: 16,
          background: 'var(--bg-secondary)',
          padding: 4,
          borderRadius: 10,
          border: '1px solid var(--border)',
          width: 'fit-content',
        }}
      >
        {TABS.map((t, i) => (
          <button key={t} className={`tab-btn ${tab === i ? 'active' : ''}`} onClick={() => setTab(i)}>
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="animate-fade-in" key={tab}>
        {tab === 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Bug size={14} color="#ef4444" /> Key Indicators
              </div>
              {[
                { label: 'Obfuscation Detected', value: sa.obfuscation_detected, flag: true },
                { label: 'Dynamic Code Loading', value: sa.dynamic_code_loading, flag: true },
                { label: 'SMS Interception', value: da.sms_intercepted, flag: true },
                { label: 'Accessibility Abuse', value: da.accessibility_abuse, flag: true },
              ].map(({ label, value }) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 0', borderBottom: '1px solid rgba(30,45,74,0.4)' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-2)' }}>{label}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: value ? '#ef4444' : '#22c55e' }}>
                    {value ? '⚠ Detected' : '✓ Clean'}
                  </span>
                </div>
              ))}
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={14} color="#3b82f6" /> Recommendations
              </div>
              {report?.recommendations?.map((r, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, marginBottom: 12, fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>
                  <div style={{ width: 18, height: 18, borderRadius: '50%', background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.3)', flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#3b82f6', fontWeight: 700 }}>
                    {i + 1}
                  </div>
                  {r}
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Permissions ({sa.permissions?.length})</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {sa.permissions?.map((p) => (
                  <div key={p.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '9px 12px', background: 'var(--bg-secondary)', borderRadius: 8, border: '1px solid var(--border)' }}>
                    <div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: p.dangerous ? '#ef4444' : 'var(--text-1)', fontWeight: 600 }}>{p.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-3)' }}>{p.description}</div>
                    </div>
                    <PermBadge dangerous={p.dangerous} />
                  </div>
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>YARA Rule Matches</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {sa.yara_matches?.map((y) => (
                  <span key={y} style={{ padding: '4px 12px', borderRadius: 6, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', color: '#ef4444', fontSize: 12, fontFamily: 'monospace', fontWeight: 600 }}>
                    {y}
                  </span>
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Hardcoded URLs / IPs</div>
              {sa.hardcoded_urls?.map((u) => (
                <div key={u} style={{ fontFamily: 'monospace', fontSize: 12, color: '#f97316', padding: '6px 0', borderBottom: '1px solid rgba(30,45,74,0.3)' }}>{u}</div>
              ))}
            </div>
          </div>
        )}

        {tab === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Network Requests</div>
              <table>
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {da.network_requests?.map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{r.url}</td>
                      <td><span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--cyan)' }}>{r.method}</span></td>
                      <td>
                        <span style={{ fontSize: 11, color: r.suspicious ? '#ef4444' : '#22c55e', fontWeight: 600 }}>
                          {r.suspicious ? '⚠ Malicious C2' : '✓ Benign'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Background Services</div>
              {da.background_services?.map((s) => (
                <div key={s} style={{ fontFamily: 'monospace', fontSize: 12, color: '#f97316', padding: '6px 0', borderBottom: '1px solid rgba(30,45,74,0.3)' }}>{s}</div>
              ))}
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Fraud Journey Reconstruction</div>
              <AttackChainGraph height={300} />
            </div>
          </div>
        )}

        {tab === 3 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>MITRE ATT&CK Techniques</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                {ti.mitre_techniques?.map((t) => (
                  <MitreBadge key={t.id} {...t} />
                ))}
              </div>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>Malicious Indicators</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[...(ti.malicious_domains || []), ...(ti.malicious_ips || [])].map((ioc) => (
                  <div key={ioc} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: 'rgba(239,68,68,0.06)', borderRadius: 8, border: '1px solid rgba(239,68,68,0.15)', fontFamily: 'monospace', fontSize: 12, color: '#ef4444' }}>
                    <AlertTriangle size={12} />
                    {ioc}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === 4 && (
          <div className="card" style={{ padding: 28 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--cyan)' }} />
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>AI Investigation Report</div>
              <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.2)', color: 'var(--cyan)', fontWeight: 600 }}>
                llama3:8b-instruct
              </span>
            </div>
            <div
              style={{
                fontSize: 13,
                color: 'var(--text-2)',
                lineHeight: 1.8,
                whiteSpace: 'pre-line',
                background: 'var(--bg-secondary)',
                padding: 20,
                borderRadius: 10,
                border: '1px solid var(--border)',
              }}
            >
              {analysis?.ai_summary}
            </div>
          </div>
        )}

        {tab === 5 && (
          <div className="animate-fade-in">
            <DecompiledView apkId={id} />
          </div>
        )}
      </div>
    </div>
  )
}
