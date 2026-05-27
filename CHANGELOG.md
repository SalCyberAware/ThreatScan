# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-27

Initial public release.

### Added

- **11-engine multi-source threat scanning** — aggregated verdicts from AbuseIPDB, GreyNoise, IPinfo, MalwareBazaar, AlienVault OTX, Google Safe Browsing, ThreatFox, URLhaus, URLScan.io, VirusTotal, and WHOIS/DNS.
- **Indicator auto-detection** — accepts URLs, IPv4/IPv6 addresses, MD5/SHA1/SHA256 file hashes, and domains; auto-routes each to the engine method that supports it (`scanUrl` / `scanIp` / `scanHash` / `scanDomain`).
- **Real-time streaming via SSE** — `GET /api/scan/stream` emits `start` → per-engine `engine` events → `done` so the UI shows results as each engine responds rather than waiting for the slowest.
- **Bulk scanning** — `GET /api/scan/bulk` accepts up to 20 unique queries (newline- or comma-separated), de-duplicates them, and streams `start` → `progress`/`result` per query → `done` with an aggregate summary. Returns `400` on >20 queries instead of silently truncating.
- **Legacy JSON endpoint** — `POST /api/scan` returns a single aggregated JSON response for clients that don't speak SSE.
- **Weighted threat score** — 0–100 score combining each engine's verdict with a reputation weight (VirusTotal 5, Safe Browsing 4, mid-tier engines 3, low-signal sources 1–2, WHOIS 0). Final verdict thresholds: `≥50` malicious, `≥20` suspicious, else clean.
- **In-memory result cache** — 5-minute TTL, FIFO eviction at 500 entries; shared across the JSON, stream, and bulk endpoints.
- **Per-IP rate limiting** — 60 requests / 15 min for scan endpoints, 10 requests / 15 min for bulk.
- **Security middleware** — `helmet`, CORS allowlist driven by `FRONTEND_URL` (strict in `NODE_ENV=production`, permissive in dev), JSON body limit of 10kb, query sanitization (length cap, control-character rejection).
- **Health endpoint** — `GET /api/health` reports per-engine key status (`active` / `inactive` / `no key needed`), process uptime, and current cache size.
- **152-test Jest suite** covering all 11 engines, the indicator-detection utility, and the Express server end-to-end (validation, happy paths per indicator type, cache replay, score aggregation, SSE event sequencing, bulk dedup/overflow, missing-key skipping, engine-error handling, CORS rejection).
- **Coverage** — `server.js` 92.77% statements / 97.23% lines; engines collectively 98.25% statements.
- **GitHub Actions CI** — backend tests with coverage + frontend build on every push to `main`; coverage uploaded to Codecov.
- **React + Vite frontend** deployed to Vercel; **Express backend** deployed to Railway.

### Security

- API keys are server-side only; the frontend never sees them.
- File uploads are hashed client-side (SHA-256); only the hash is sent to the backend.
- No logging, no analytics, no database — the cache is in-memory and forgotten on restart.

[Unreleased]: https://github.com/SalCyberAware/ThreatScan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/SalCyberAware/ThreatScan/releases/tag/v1.0.0
