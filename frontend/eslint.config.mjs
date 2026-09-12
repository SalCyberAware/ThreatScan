// Flat config. Named .mjs because package.json has no "type": "module" — the
// build already works that way and this keeps the change to tooling only.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import { defineConfig, globalIgnores } from "eslint/config";

export default defineConfig([
  globalIgnores(["dist"]),
  {
    files: ["**/*.{js,jsx}"],
    extends: [
      js.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: "latest",
        ecmaFeatures: { jsx: true },
        sourceType: "module",
      },
    },
    rules: {
      "no-unused-vars": ["error", { varsIgnorePattern: "^[A-Z_]" }],

      // App.jsx is the whole app: components plus the constants and helpers they
      // share. Splitting it up to satisfy the Fast Refresh heuristic would be a
      // refactor, and the rule only guards dev-server ergonomics, not behaviour.
      "react-refresh/only-export-components": "off",

      // `try { localStorage.setItem(...) } catch {}` — history persistence is
      // best-effort by design (private mode, quota), so the empty catch is the
      // intended behaviour rather than a swallowed error.
      "no-empty": ["error", { allowEmptyCatch: true }],

      // The query -> detectedType effect predates this config. Warn so the smell
      // stays visible without failing CI on untouched application code.
      "react-hooks/set-state-in-effect": "warn",
    },
  },
  {
    files: ["src/**/*.test.{js,jsx}", "src/test/**/*.js"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
]);
