import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import jsconfigPaths from 'vite-jsconfig-paths';

export default defineConfig(({ mode }) => {
    // depending on your application, base can also be "/"
    const env = loadEnv(mode, process.cwd(), '');
    const API_URL = env.VITE_APP_BASE_NAME || '/';
    // ponytail: classic frontend owns 3000; v2 runs beside it
    const PORT = 3001;

    return {
        server: {
            open: false,
            port: PORT,
            host: true,
            // same backend contract as apps/frontend
            proxy: {
                '/api': {
                    target: process.env.VITE_API_URL || env.VITE_API_URL || 'http://backend:8000',
                    changeOrigin: true
                }
            }
        },
        build: {
            chunkSizeWarningLimit: 1600
        },
        preview: {
            open: false,
            host: true,
            port: PORT
        },
        define: {
            global: 'window'
        },
        resolve: {
            alias: {
                '@tabler/icons-react': '@tabler/icons-react/dist/esm/icons/index.mjs'
            }
        },
        base: API_URL,
        plugins: [react(), jsconfigPaths()]
    };
});