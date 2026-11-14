import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const releaseNumber = '24000'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    target: ['es2018', 'chrome79', 'edge79', 'firefox78', 'safari13'],
    cssTarget: ['chrome79', 'firefox78', 'safari13'],
    modulePreload: { polyfill: true },
    cssCodeSplit: false,
    emptyOutDir: true,
    chunkSizeWarningLimit: 1800,
    rollupOptions: {
      output: {
        entryFileNames: `assets/index-v${releaseNumber}.js`,
        chunkFileNames: `assets/r${releaseNumber}-[name]-[hash].js`,
        assetFileNames: (assetInfo) => {
          const name = assetInfo.name || ''
          if (name.endsWith('.css')) return `assets/index-v${releaseNumber}.css`
          return `assets/r${releaseNumber}-[name]-[hash][extname]`
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
