import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const target = 'http://127.0.0.1:8788'
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5175,
    strictPort: true,
    proxy: {
      ...Object.fromEntries(
        ['/v1', '/.well-known', '/health'].map((path) => [path, { target, followRedirects: false }]),
      ),
      '/socket.io': { target, ws: true, followRedirects: false },
    },
  },
})
