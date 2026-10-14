import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The browser talks only to Vite (port 5173). Vite forwards every /api request to the
// FastAPI backend on port 8000, so there are no CORS settings to manage.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
