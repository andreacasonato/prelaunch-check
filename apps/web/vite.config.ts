import { readFileSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const cliVersion = (
  JSON.parse(readFileSync(new URL("../../packages/cli/package.json", import.meta.url), "utf8")) as {
    version: string;
  }
).version;

// The site's own Content-Security-Policy (TRD §11). Added to production builds only: Vite's dev
// server injects inline scripts. A <meta> CSP can't carry frame-ancestors (see About page).
export const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "worker-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self' https://api.osv.dev",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join("; ");

function csp(): Plugin {
  return {
    name: "prelaunch-check-csp",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "<head>",
        `<head>\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`,
      );
    },
  };
}

// Relative base so the build works at https://<user>.github.io/<repo>/ (TRD §11).
export default defineConfig({
  base: "./",
  plugins: [react(), csp()],
  define: { __APP_VERSION__: JSON.stringify(cliVersion) },
  worker: { format: "es" },
  build: { sourcemap: false, target: "es2022" },
});
