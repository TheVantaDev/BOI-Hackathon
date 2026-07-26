import { useEffect, useState } from 'react';

import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import Stack from '@mui/material/Stack';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import { alpha, useTheme } from '@mui/material/styles';

import {
  IconChevronDown,
  IconChevronRight,
  IconFileCode,
  IconFolder,
  IconFolderOpen
} from '@tabler/icons-react';

import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneLight } from 'react-syntax-highlighter/dist/esm/styles/prism';

import MainCard from 'ui-component/cards/MainCard';
import { getDecompiledFile, getDecompiledTree } from 'api/client';

function getLanguageFromFilename(filename) {
  const ext = filename?.split('.').pop()?.toLowerCase();
  const map = { java: 'java', xml: 'xml', smali: 'text', kt: 'kotlin', json: 'json', yml: 'yaml', yaml: 'yaml', properties: 'properties' };
  return map[ext] || 'text';
}

function TreeNode({ node, expandedDirs, dirContents, onToggleDir, onSelectFile, selectedFile }) {
  const theme = useTheme();
  const isDir = node.type === 'directory';
  const isExpanded = !!expandedDirs[node.path];
  const children = dirContents[node.path] || [];
  const isSelected = selectedFile === node.path;

  return (
    <Box sx={{ ml: 1 }}>
      <Stack
        direction="row"
        alignItems="center"
        spacing={0.75}
        onClick={() => (isDir ? onToggleDir(node.path) : onSelectFile(node.path, node.name))}
        sx={{
          py: 0.75,
          px: 1,
          borderRadius: 1,
          cursor: 'pointer',
          userSelect: 'none',
          bgcolor: isSelected ? alpha(theme.palette.primary.main, 0.1) : 'transparent',
          color: isSelected ? 'primary.main' : 'text.secondary',
          '&:hover': {
            bgcolor: alpha(theme.palette.primary.main, 0.06),
            color: 'text.primary'
          }
        }}
      >
        {isDir ? (
          <>
            {isExpanded ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
            {isExpanded ? <IconFolderOpen size={14} color={theme.palette.primary.main} /> : <IconFolder size={14} />}
          </>
        ) : (
          <>
            <Box sx={{ width: 14 }} />
            <IconFileCode size={14} color={isSelected ? theme.palette.primary.main : undefined} />
          </>
        )}
        <Typography variant="caption" noWrap sx={{ fontSize: 12 }}>
          {node.name}
        </Typography>
      </Stack>

      {isDir && isExpanded && (
        <Box sx={{ borderLeft: '1px solid', borderColor: 'divider', ml: 1.75, pl: 0.5 }}>
          {children.length === 0 ? (
            <Typography variant="caption" color="text.secondary" sx={{ pl: 2, fontStyle: 'italic' }}>
              Empty
            </Typography>
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
        </Box>
      )}
    </Box>
  );
}

function CodeViewer({ content, filename }) {
  const theme = useTheme();
  if (!content) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'text.secondary' }}>
        <Typography variant="body2">Select a file from the explorer to view its contents</Typography>
      </Box>
    );
  }

  const language = getLanguageFromFilename(filename);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Stack
        direction="row"
        alignItems="center"
        spacing={1}
        sx={{
          px: 2,
          py: 1.25,
          borderBottom: '1px solid',
          borderColor: 'divider',
          bgcolor: alpha(theme.palette.primary.main, 0.04)
        }}
      >
        <IconFileCode size={14} color={theme.palette.primary.main} />
        <Typography variant="caption" fontWeight={700} color="primary.main" sx={{ fontFamily: 'monospace' }}>
          {filename}
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ ml: 'auto', textTransform: 'uppercase' }}>
          {language}
        </Typography>
      </Stack>
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        <SyntaxHighlighter
          language={language}
          style={oneLight}
          showLineNumbers
          wrapLongLines={false}
          customStyle={{
            margin: 0,
            padding: '12px 0',
            fontSize: 12,
            lineHeight: 1.6,
            minHeight: '100%',
            background: theme.palette.background.paper
          }}
        >
          {content}
        </SyntaxHighlighter>
      </Box>
    </Box>
  );
}

export default function DecompiledView({ apkId }) {
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
      .then((resp) => {
        setTree(resp.data.tree);
        setLoadingTree(false);
      })
      .catch(() => {
        setErrorMsg('Failed to load decompiled files. Make sure this APK is decompiled.');
        setTree([]);
        setLoadingTree(false);
      });
  }, [apkId, tool]);

  const handleToggleDir = async (path) => {
    const isExpanded = !!expandedDirs[path];
    if (!isExpanded && !dirContents[path]) {
      try {
        const resp = await getDecompiledTree(apkId, tool, path);
        setDirContents((prev) => ({ ...prev, [path]: resp.data.tree }));
      } catch {
        // ignore folder load errors
      }
    }
    setExpandedDirs((prev) => ({ ...prev, [path]: !isExpanded }));
  };

  const handleSelectFile = async (path, name) => {
    setSelectedFile(path);
    setSelectedFileName(name);
    setLoadingFile(true);
    setFileContent(null);
    try {
      const resp = await getDecompiledFile(apkId, tool, path);
      setFileContent(resp.data.content);
    } catch {
      setFileContent('Error: Failed to load file contents.');
    } finally {
      setLoadingFile(false);
    }
  };

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', md: '320px 1fr' },
        gap: 2,
        height: { md: 'calc(100vh - 280px)' },
        minHeight: 500
      }}
    >
      <MainCard content={false} sx={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <Box sx={{ p: 2, borderBottom: '1px solid', borderColor: 'divider' }}>
          <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1.5 }}>
            File Explorer
          </Typography>
          <ToggleButtonGroup
            exclusive
            fullWidth
            size="small"
            value={tool}
            onChange={(_, v) => v && setTool(v)}
          >
            <ToggleButton value="jadx">JADX (Java)</ToggleButton>
            <ToggleButton value="apktool">APKTool (Res/Smali)</ToggleButton>
          </ToggleButtonGroup>
        </Box>
        <Box sx={{ flex: 1, overflow: 'auto', p: 1 }}>
          {loadingTree ? (
            <Stack direction="row" spacing={1} alignItems="center" justifyContent="center" sx={{ py: 6, color: 'text.secondary' }}>
              <CircularProgress size={16} />
              <Typography variant="caption">Loading files...</Typography>
            </Stack>
          ) : errorMsg ? (
            <Alert severity="error" sx={{ m: 1 }}>
              {errorMsg}
            </Alert>
          ) : tree.length === 0 ? (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', p: 2, textAlign: 'center' }}>
              No files decompiled.
            </Typography>
          ) : (
            tree.map((node) => (
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
        </Box>
      </MainCard>

      <MainCard content={false} sx={{ overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 400 }}>
        {loadingFile ? (
          <Stack alignItems="center" justifyContent="center" spacing={1.5} sx={{ flex: 1, color: 'text.secondary', py: 8 }}>
            <CircularProgress size={24} />
            <Typography variant="body2">Retrieving source code...</Typography>
          </Stack>
        ) : (
          <CodeViewer content={fileContent} filename={selectedFileName} />
        )}
      </MainCard>
    </Box>
  );
}
