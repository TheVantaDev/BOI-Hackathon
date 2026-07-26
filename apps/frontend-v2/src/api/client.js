import axios from 'axios';

// Same contract as apps/frontend — both UIs hit the same FastAPI routes
const api = axios.create({
  baseURL: '/api',
  timeout: 120000
});

export const uploadAPK = (file, onProgress) => {
  const form = new FormData();
  form.append('file', file);
  return api.post('/upload/', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress) onProgress(Math.round((e.loaded * 100) / e.total));
    }
  });
};

export const getAnalysis = (apkId) => api.get(`/analysis/${apkId}`);
export const getAnalysisStatus = (apkId) => api.get(`/analysis/${apkId}/status`);
export const getReport = (apkId) => api.get(`/reports/${apkId}`);
export const downloadPdf = (apkId) => api.get(`/reports/${apkId}/pdf`, { responseType: 'blob' });
export const getDashboardStats = () => api.get('/dashboard/stats');
export const getRecentUploads = (limit = 20) => api.get(`/dashboard/recent?limit=${limit}`);
export const getDecompiledTree = (apkId, tool, path = '') =>
  api.get(`/analysis/${apkId}/decompiled/tree`, { params: { tool, path } });
export const getDecompiledFile = (apkId, tool, path) =>
  api.get(`/analysis/${apkId}/decompiled/file`, { params: { tool, path } });

export default api;
