import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/verify/aether/': {
        target: 'http://127.0.0.1:8787',
        followRedirects: false,
        rewrite: (path) => path.replace(/^\/verify\/aether/, ''),
      },
      '/verify/bastion/': {
        target: 'http://127.0.0.1:8788',
        followRedirects: false,
        rewrite: (path) => path.replace(/^\/verify\/bastion/, ''),
      },
    },
  },
})
