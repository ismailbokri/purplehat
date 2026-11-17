import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/health':    'http://localhost:8000',
      '/auth':      'http://localhost:8000',
      '/checklist': 'http://localhost:8000',
      '/runs':      'http://localhost:8000',
      // Modular sessions API lives under /api/* to avoid colliding with the
      // SPA routes /sessions/* (which React Router owns). WebSocket included.
      '/api': {
        target: 'http://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
});
