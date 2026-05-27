# Contributing to ThreatScan

ThreatScan is a free, open-source threat-intelligence aggregator that scans URLs, IPs, file hashes, and domains across 11 live security engines and streams the results back in real time. Contributions are welcome — bug reports, new engines, UI polish, docs, all of it.

## Prerequisites

- **Node.js 20+** and **npm**
- A handful of free API keys for the engines you want to exercise locally (see [API Keys](#api-keys))

## Setup

```bash
git clone https://github.com/SalCyberAware/ThreatScan.git
cd ThreatScan

# Backend
cd backend && npm install

# Frontend
cd ../frontend && npm install
```

## Environment Variables

There is no `.env.example` in the repo. Create `backend/.env` yourself with the keys for the engines you want active — every engine without a key set is reported as `skipped` at scan time, so you can run with whichever subset you have.

```dotenv
# backend/.env
VT_API_KEY=...          # VirusTotal
ABUSEIPDB_KEY=...       # AbuseIPDB
URLSCAN_KEY=...         # URLScan.io
MALWAREBAZAAR_KEY=...   # MalwareBazaar
OTX_KEY=...             # AlienVault OTX
GREYNOISE_KEY=...       # GreyNoise
IPINFO_KEY=...          # IPInfo
GSB_KEY=...             # Google Safe Browsing

# Optional
PORT=4000               # default 4000
FRONTEND_URL=http://localhost:5173   # CORS allowlist origin (required in production)
```

URLhaus, ThreatFox, and WHOIS/DNS need no API key.

The frontend reads `VITE_API_URL` from `frontend/.env` if you point it at a non-default backend:

```dotenv
# frontend/.env (optional, defaults to http://localhost:4000/api)
VITE_API_URL=http://localhost:4000/api
```

See the [README](README.md#api-keys) for direct links to each provider's signup page.

## Running Locally

```bash
# Terminal 1 — backend (auto-reloads via nodemon)
cd backend && npm run dev

# Terminal 2 — frontend (Vite dev server on http://localhost:5173)
cd frontend && npm run dev
```

## Running Tests

The backend has a Jest test suite covering all 11 engines, the utils, and the Express server (integration tests use `supertest` with all engines mocked).

```bash
cd backend
npm test                   # full suite (152 tests as of 1.0.0)
npm run test:coverage      # coverage report — text summary + lcov in coverage/
```

Tests are also run on every push by GitHub Actions; coverage is uploaded to Codecov.

## Adding a New Threat-Intel Engine

Engines live in `backend/engines/`. Each engine module exports four async scan methods — one per indicator type — and each method returns a verdict object.

```js
// backend/engines/yourengine.js
const axios = require("axios");
const KEY = () => process.env.YOURENGINE_KEY;

async function scanUrl(url) {
  // Call the API, classify the result.
  // Return verdict ∈ "clean" | "suspicious" | "malicious" | "skipped" | "error" | "info"
  return { verdict: "clean", detail: "..." };
}

async function scanIp(ip)       { /* ... */ return { verdict: "info", detail: "IP-only engine" }; }
async function scanHash(hash)   { /* ... */ return { verdict: "info", detail: "hash-only engine" }; }
async function scanDomain(dom)  { /* ... */ return { verdict: "info", detail: "domain-only engine" }; }

module.exports = { scanUrl, scanIp, scanHash, scanDomain };
```

[`backend/engines/virustotal.js`](backend/engines/virustotal.js) is a good template — it covers all four indicator types and demonstrates the submit-and-poll fallback pattern.

After adding the module, register it in `backend/server.js` in **four** places:

- `engines` — the `require()` map
- `ENGINE_KEYS` — the env-var name (or `null` if no key needed)
- `ENGINE_TIMEOUTS` — per-engine timeout in ms
- `ENGINE_WEIGHTS` — score weight (VT is 5, IPinfo is 1, WHOIS is 0)

Then add a `<engineName>.test.js` next to the module — every existing engine has one and the project keeps engine coverage above 95%.

## Commit Conventions

This repo uses [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`.

Types in active use:

- `feat` — new feature
- `fix` — bug fix
- `test` — adding or updating tests
- `docs` — documentation only
- `refactor` — non-behavioral code change
- `ci` — CI/build pipeline change
- `chore` — tooling, dependencies, housekeeping

Recent examples from `git log`:

```
fix(server): return 400 instead of silently truncating bulk queries over 20
test(server): SSE integration tests for /api/scan/stream and /api/scan/bulk
refactor(server): export app and internals for integration tests
ci: upload coverage to Codecov, add badge to README
```

## Pull Request Process

1. Fork or branch from `main`.
2. Make focused commits using the convention above.
3. `cd backend && npm test` — make sure the full suite stays green; add tests for any new behavior.
4. Push and open a pull request against `main`.
5. CI must be green (backend tests + coverage + frontend build) before merge.

For larger or design-level changes, please open an issue first to discuss the approach.

## License

By contributing you agree your changes are licensed under the project's [MIT License](LICENSE).
