/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { execSync } from 'child_process'

// The freeq server's --web-addr (HTTP/WebSocket listener)
const FREEQ_WEB = process.env.FREEQ_WEB || 'http://127.0.0.1:8080'
// A remote HTTPS target terminates TLS under its own name, and Node validates
// the certificate against the Host the proxy forwards — keeping the browser's
// `localhost` fails the handshake (ERR_TLS_CERT_ALTNAME_INVALID) and every
// /api call dies as an empty 500. So: rewrite Host for a remote target. A
// local server keeps the browser Host so OAuth redirect URIs stay localhost.
const REMOTE_TARGET = !/^https?:\/\/(127\.0\.0\.1|localhost)([:/]|$)/.test(FREEQ_WEB)
const GIT_COMMIT = process.env.GIT_COMMIT || (() => {
  try { return execSync('git rev-parse --short HEAD').toString().trim() }
  catch { return 'unknown' }
})()

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    '__FREEQ_TARGET__': JSON.stringify(FREEQ_WEB),
    '__GIT_COMMIT__': JSON.stringify(GIT_COMMIT),
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test-setup.ts'],
  },
  server: {
    host: '127.0.0.1',
    proxy: {
      '/irc': {
        target: FREEQ_WEB,
        ws: true,
        changeOrigin: REMOTE_TARGET,
      },
      '/api': {
        target: FREEQ_WEB,
        changeOrigin: REMOTE_TARGET,
      },
      '/auth': {
        target: FREEQ_WEB,
        changeOrigin: REMOTE_TARGET,
      },
      '/av': {
        target: FREEQ_WEB,
        ws: true,
        changeOrigin: REMOTE_TARGET,
      },
    },
  },
})
