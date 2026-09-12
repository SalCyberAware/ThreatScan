import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// `defineConfig` comes from vitest/config so the `test` block below is typed and
// the build config stays in a single file.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
  },
  test: {
    // jsdom for the React Testing Library specs. The pure detectInputType specs
    // do not need a DOM, but sharing one environment keeps the config short.
    environment: "jsdom",
    setupFiles: ["./src/test/setup.js"],
    include: ["src/**/*.test.{js,jsx}"],
    // No `globals: true` on purpose: every spec imports describe/it/expect/vi
    // from vitest explicitly, so eslint needs no extra global allowlist.
    globals: false,
  },
});
