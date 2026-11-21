import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import tailwindcss from '@tailwindcss/vite'
// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    host: "127.0.0.1"
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/react") || id.includes("node_modules/react-dom")) {
            return "react"
          }
          if (id.includes("node_modules/react-router")) {
            return "router"
          }
          if (id.includes("node_modules/recharts")) {
            return "charts"
          }
          if (id.includes("node_modules/lucide-react")) {
            return "icons"
          }
        }
      }
    }
  }
})
