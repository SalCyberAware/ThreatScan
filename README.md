<div align="center">

# ⚔ ThreatScan

**Free, open-source, self-hostable threat intelligence platform**

Scan URLs, IPs, file hashes & domains across **11 live security engines** simultaneously — results stream live as each engine responds.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-threat--scan.vercel.app-00ff88?style=for-the-badge&logo=vercel&logoColor=black)](https://threat-scan.vercel.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge)](LICENSE)
[![Deploy on Railway](https://img.shields.io/badge/Backend-Railway-blueviolet?style=for-the-badge&logo=railway)](https://railway.app)
[![Frontend on Vercel](https://img.shields.io/badge/Frontend-Vercel-black?style=for-the-badge&logo=vercel)](https://vercel.com)

![ThreatScan Screenshot](https://threat-scan.vercel.app/og.png)

</div>

---

## What is ThreatScan?

ThreatScan is a free, open-source alternative to VirusTotal. Instead of sending your data to a single engine, ThreatScan queries **11 threat intelligence APIs simultaneously** and streams results live — engine by engine — so you see data immediately without waiting for all engines to finish.

**Privacy-first:** API keys are stored server-side. ThreatScan logs nothing and has no database. Files are never uploaded — only their SHA256 hash is scanned.

---

## Features

- ⚡ **Live streaming results** — Server-Sent Events stream each engine result as it arrives
- 🔬 **11 engines** — VirusTotal, AbuseIPDB, URLScan, MalwareBazaar, AlienVault OTX, GreyNoise, IPInfo, PhishTank, Google SafeBrowse, ThreatFox, WHOIS/DNS
- 📁 **File upload** — drag & drop any file, hashed locally with SHA256 (file never leaves your device)
- ⚡ **Bulk scan** — paste up to 20 URLs, IPs, or domains and scan them all at once with CSV export
- 🌍 **WHOIS + DNS** — registrar, creation date, expiry, A/MX/NS records for any domain
- 📸 **URLScan screenshots** — inline screenshot preview of scanned pages
- 📊 **Weighted threat score** — 0–100 score weighted by engine reputation (VirusTotal carries more weight than a single-source engine)
- 🔥 **Trending threats** — your scan history ranked by threat score
- 📥 **Export** — download single scan results as JSON or bulk results as CSV
- 🕐 **5-minute cache** — repeat scans return instantly without hitting API limits
- 📱 **Mobile responsive** — works on all screen sizes
- 🔒 **Rate limiting** — 60 scans per 15 minutes per IP
- 🚀 **CI/CD** — auto-deploys on every push to main

---

## Live Demo

**[https://threat-scan.vercel.app](https://threat-scan.vercel.app)**

---

## Engines

| Engine | Supports | Free Tier | Key Required |
|--------|----------|-----------|--------------|
| VirusTotal | URL, IP, Domain, Hash | 500/day | ✅ |
| AbuseIPDB | IP | 1,000/day | ✅ |
| URLScan.io | URL, Domain | 1,000/day | ✅ |
| MalwareBazaar | Hash | Unlimited | ❌ |
| AlienVault OTX | All | Unlimited | ✅ |
| GreyNoise | IP | 1,000/day | ✅ |
| IPInfo | IP | 50,000/month | ✅ |
| PhishTank | URL | Free | ✅ |
| Google SafeBrowse | URL, Domain | 10,000/day | ✅ |
| ThreatFox | All | Unlimited | ❌ |
| WHOIS / DNS | URL, Domain | Unlimited | ❌ |

---

## Quick Start (Local)

```bash
# 1. Clone the repo
git clone https://github.com/SalCyberAware/ThreatScan.git
cd ThreatScan

# 2. Install backend dependencies
cd backend && npm install

# 3. Create your .env file
cp .env.example .env
# Add your API keys (see API Keys section below)

# 4. Start the backend
node server.js

# 5. In a new terminal, install and start the frontend
cd ../frontend && npm install && npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

---

## API Keys

All keys are free. Get them here:

| Key | Where to get it |
|-----|----------------|
| `VT_API_KEY` | [virustotal.com](https://virustotal.com) → Sign up → API Key |
| `ABUSEIPDB_KEY` | [abuseipdb.com](https://abuseipdb.com) → Account → API |
| `URLSCAN_KEY` | [urlscan.io](https://urlscan.io) → Profile → API Key |
| `OTX_KEY` | [otx.alienvault.com](https://otx.alienvault.com) → Settings → OTX Key |
| `GREYNOISE_KEY` | [greynoise.io](https://greynoise.io) → Account → API |
| `IPINFO_KEY` | [ipinfo.io](https://ipinfo.io) → Token |
| `PHISHTANK_KEY` | [phishtank.org](https://phishtank.org) → Register |
| `GSB_KEY` | [console.cloud.google.com](https://console.cloud.google.com) → Safe Browsing API |

---

## Deploy Your Own

### Backend → Railway

1. Fork this repo
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select `ThreatScan` → set **Root Directory** to `backend`
4. Add all API keys as environment variables
5. Set `PORT=4000`

### Frontend → Vercel

1. Go to [vercel.com](https://vercel.com) → New Project → Import from GitHub
2. Set **Root Directory** to `frontend`
3. Add environment variable: `VITE_API_URL=https://your-railway-url.up.railway.app/api`
4. Deploy

---

## Architecture

```
User Browser
     │
     ▼
Vercel (React + Vite)          Railway (Node.js + Express)
threat-scan.vercel.app    →    Port 4000
     │                              │
     │  Server-Sent Events          │
     │◄─────────────────────────────│
                                    │
                        ┌───────────┴────────────┐
                        │     11 Engine Modules  │
                        │  virustotal.js         │
                        │  abuseipdb.js          │
                        │  urlscan.js            │
                        │  malwarebazaar.js      │
                        │  otx.js                │
                        │  greynoise.js          │
                        │  ipinfo.js             │
                        │  phishtank.js          │
                        │  safebrowsing.js       │
                        │  threatfox.js          │
                        │  whois.js              │
                        └────────────────────────┘
```

---

## Adding a New Engine

1. Create `backend/engines/yourengine.js` and export `scanUrl`, `scanIp`, `scanHash`, `scanDomain`
2. Register it in `backend/server.js` under `engines`, `ENGINE_KEYS`, `ENGINE_TIMEOUTS`, `ENGINE_WEIGHTS`
3. Add it to `ENGINE_META` in `frontend/src/App.jsx` with a name and icon

```js
// backend/engines/yourengine.js
async function scanUrl(url) {
  // call your API
  return { verdict: "clean" | "suspicious" | "malicious" | "info", detail: "..." };
}
module.exports = { scanUrl, scanIp, scanHash, scanDomain };
```

---

## Tech Stack

- **Frontend:** React, Vite, Server-Sent Events
- **Backend:** Node.js, Express
- **Deployment:** Vercel (frontend), Railway (backend)
- **Security:** Helmet.js, CORS, rate limiting, no logging

---

## Contributing

Pull requests welcome. Please open an issue first for major changes.

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-engine`
3. Commit your changes
4. Open a pull request

---

## License

MIT — free to use, modify, and self-host.

---

<div align="center">

Made with ⚔ by [SalCyberAware](https://github.com/SalCyberAware)

**[Live Demo](https://threat-scan.vercel.app) · [Report a Bug](https://github.com/SalCyberAware/ThreatScan/issues) · [Request a Feature](https://github.com/SalCyberAware/ThreatScan/issues)**

</div>
