import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
})

export const uploadAPK = (file, onProgress) => {
  const form = new FormData()
  form.append('file', file)
  return api.post('/upload/', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress) onProgress(Math.round((e.loaded * 100) / e.total))
    },
  })
}

export const getAnalysis = (apkId) => api.get(`/analysis/${apkId}`)
export const getAnalysisStatus = (apkId) => api.get(`/analysis/${apkId}/status`)
export const getReport = (apkId) => api.get(`/reports/${apkId}`)
export const getDashboardStats = () => api.get('/dashboard/stats')
export const getRecentUploads = (limit = 20) => api.get(`/dashboard/recent?limit=${limit}`)

export default api
