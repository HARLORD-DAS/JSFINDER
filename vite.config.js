import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev: the UI runs on :5173 and proxies /api/* to the Python scanner on :5000.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true
      }
    }
  }
})
