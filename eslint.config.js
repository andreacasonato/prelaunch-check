import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

const nodeBuiltins = [
  "assert",
  "buffer",
  "child_process",
  "cluster",
  "crypto",
  "dgram",
  "dns",
  "events",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "net",
  "os",
  "path",
  "perf_hooks",
  "process",
  "readline",
  "stream",
  "string_decoder",
  "timers",
  "tls",
  "tty",
  "url",
  "util",
  "v8",
  "vm",
  "worker_threads",
  "zlib",
];

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "fixtures/**",
      "spikes/**",
      "prelaunch-check-report/**",
      "coverage/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["apps/web/src/**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser } },
  },
  // Hard rule (CLAUDE.md): core never imports node:* or touches window/document.
  {
    files: ["packages/core/src/**/*.ts"],
    languageOptions: { globals: {} },
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["node:*"],
              message: "packages/core must not import Node APIs. Use FileSource/OnlineServices.",
            },
          ],
          paths: nodeBuiltins.map((name) => ({
            name,
            message: "packages/core must not import Node APIs. Use FileSource/OnlineServices.",
          })),
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "window", message: "packages/core must not use DOM APIs." },
        { name: "document", message: "packages/core must not use DOM APIs." },
        { name: "process", message: "packages/core must not use Node globals." },
        { name: "require", message: "packages/core must not use Node globals." },
        { name: "Buffer", message: "packages/core must not use Node globals." },
        { name: "__dirname", message: "packages/core must not use Node globals." },
        // Core never talks to the network: online lookups are injected through OnlineServices.
        { name: "fetch", message: "packages/core must not make network requests. Use OnlineServices." },
        { name: "XMLHttpRequest", message: "packages/core must not make network requests." },
        { name: "WebSocket", message: "packages/core must not make network requests." },
        { name: "EventSource", message: "packages/core must not make network requests." },
        { name: "importScripts", message: "packages/core must not load code at runtime." },
      ],
      // Scanned code is data, never executed.
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
    },
  },
);
