import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

export default defineConfig({
  plugins: [react()],
  base: "/static/dist/",
  build: {
    outDir: "../static/dist",
    emptyOutDir: true,
    cssCodeSplit: false,
    rollupOptions: {
      input: resolve(__dirname, "src/main.tsx"),
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunks/[name]-[hash].js",
        manualChunks(id) {
          const normalized = id.replaceAll("\\", "/");
          if (!normalized.includes("node_modules")) return undefined;
          if (normalized.includes("/echarts/")) return "charts";
          if (normalized.includes("/leaflet/")) return "maps";
          if (normalized.includes("/@mantine/")) return "mantine";
          if (normalized.includes("/@tabler/")) return "icons";
          if (normalized.includes("/react/") || normalized.includes("/react-dom/") || normalized.includes("/scheduler/")) return "react";
          return "vendor";
        },
        assetFileNames: (assetInfo) => {
          if (assetInfo.name === "style.css") {
            return "app.css";
          }
          return "assets/[name]-[hash][extname]";
        }
      }
    }
  }
});
