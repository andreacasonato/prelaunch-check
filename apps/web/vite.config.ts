import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Relative base so the build works at https://<user>.github.io/<repo>/ (TRD §11).
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: { sourcemap: false },
});
