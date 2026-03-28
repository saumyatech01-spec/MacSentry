import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // AI suggestion API — FastAPI on port 5002
      // Must come BEFORE the generic /api rule so Vite matches it first
      '/api/ai-suggestion': {
        target: 'http://localhost:5002',
        changeOrigin: true,
      },
      // Health check for the AI API
      '/api/health': {
        target: 'http://localhost:5002',
        changeOrigin: true,
      },
      // Everything else under /api — legacy Flask server on port 5001
      '/api': {
        target: 'http://localhost:5001',
        changeOrigin: true,
      },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true }
})
