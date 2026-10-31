import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

const target = 'http://127.0.0.1:8787'
export default defineConfig({
  plugins: [vue()],
  server: {
    host: '127.0.0.1',
    port: 5174,
    strictPort: true,
    proxy: Object.fromEntries(
      ['/v1', '/.well-known', '/health'].map((path) => [path, { target, followRedirects: false }]),
    ),
  },
})
