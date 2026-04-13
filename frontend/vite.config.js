import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Proxy API calls to the Express backend during development
    proxy: {
      '/analyze-prompt': 'http://localhost:3001',
      '/rewrite-prompt': 'http://localhost:3001',
    }
  }
})
