const axios = require("axios");
const BASE = "https://urlscan.io/api/v1";
const KEY  = () => process.env.URLSCAN_KEY;

async function scanUrl(url) {
  const submit = await axios.post(`${BASE}/scan/`, { url, visibility: "public" }, {
    headers: { "API-Key": KEY(), "Content-Type": "application/json" }
  });
  const resultUrl = submit.data.api;
  for (let i = 0; i < 8; i++) {
    await new Promise(r => setTimeout(r, 2500));
    try {
      const res   = await axios.get(resultUrl);
      const d     = res.data;
      const score = d.verdicts?.overall?.score ?? 0;
      return {
        verdict:    score >= 70 ? "malicious" : score >= 30 ? "suspicious" : "clean",
        score,
        brands:     d.verdicts?.overall?.brands ?? [],
        malicious:  d.verdicts?.overall?.malicious ?? false,
        screenshot: d.task?.screenshotURL ?? null,
        country:    d.page?.country ?? null,
        server:     d.page?.server  ?? null,
      };
    } catch { /* not ready yet, keep polling */ }
  }
  return { verdict: "info", detail: "urlscan timeout" };
}

async function scanDomain(domain) {
  // ── FIX: strip any existing protocol before prepending https:// ────────────
  // When a full URL like "https://google.com" is passed to scanDomain,
  // prepending "https://" produced "https://https://google.com" → 400 error.
  const clean = domain.replace(/^https?:\/\//i, "");
  return scanUrl(`https://${clean}`);
}

async function scanIp()   { return { verdict: "info", detail: "URL/domain engine" }; }
async function scanHash() { return { verdict: "info", detail: "URL/domain engine" }; }

module.exports = { scanUrl, scanDomain, scanIp, scanHash };
