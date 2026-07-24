import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        // In Docker: backend service is reachable via its service name.
        // Falls back to localhost for running outside Docker (npm run dev locally).
        // Local npm run dev → localhost. Docker compose can set VITE_API_URL=http://backend:8000
        target: 'http://backend:8000',
        changeOrigin: true,
      },
    },
  },
})
