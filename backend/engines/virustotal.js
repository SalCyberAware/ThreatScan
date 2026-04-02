const axios = require("axios");
const BASE = "https://www.virustotal.com/api/v3";
const KEY  = () => process.env.VT_API_KEY;

const URL_RE  = /^https?:\/\/.+/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH_RE = /^[a-fA-F0-9]{32,64}$/;

// Base64url-encode a URL for VT's /urls/{id} endpoint
function b64url(str) {
  return Buffer.from(str).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function scanUrl(url) {
  if (!URL_RE.test(url)) return { verdict:"info", detail:"URL-only engine" };

  const headers = { "x-apikey": KEY() };

  // ── FIX: Try cached report first (instant, no polling needed) ─────────────
  try {
    const cached = await axios.get(`${BASE}/urls/${b64url(url)}`, { headers, timeout:8000 });
    const stats  = cached.data?.data?.attributes?.last_analysis_stats;
    if (stats) return formatStats(stats);
  } catch (e) {
    // 404 = not in cache yet, fall through to submit
    if (e.response?.status !== 404) throw e;
  }

  // ── Submit for fresh scan ─────────────────────────────────────────────────
  const submit = await axios.post(
    `${BASE}/urls`,
    `url=${encodeURIComponent(url)}`,
    { headers: { ...headers, "Content-Type":"application/x-www-form-urlencoded" } }
  );
  const analysisId = submit.data.data.id;

  // ── Poll up to 6 times × 3s = 18s max (free tier needs more time) ─────────
  for (let i = 0; i < 6; i++) {
    await new Promise(r => setTimeout(r, 3000));
    try {
      const report = await axios.get(`${BASE}/analyses/${analysisId}`, { headers, timeout:8000 });
      const attrs  = report.data.data.attributes;
      if (attrs.status === "completed" && attrs.stats) return formatStats(attrs.stats);
    } catch {}
  }

  return { verdict:"info", detail:"Analysis still in progress — try again shortly" };
}

async function scanHash(hash) {
  if (!HASH_RE.test(hash)) return { verdict:"info", detail:"Hash-only engine" };
  const res = await axios.get(`${BASE}/files/${hash}`,
    { headers:{ "x-apikey":KEY() }, timeout:8000 });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanDomain(domain) {
  if (URL_RE.test(domain) || IPV4_RE.test(domain))
    return { verdict:"info", detail:"Use URL or IP tab instead" };
  const res = await axios.get(`${BASE}/domains/${domain}`,
    { headers:{ "x-apikey":KEY() }, timeout:8000 });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanIp(ip) {
  if (URL_RE.test(ip) || (!IPV4_RE.test(ip) && !ip.includes(":")))
    return { verdict:"info", detail:"Use URL or Domain tab instead" };
  const res = await axios.get(`${BASE}/ip_addresses/${ip}`,
    { headers:{ "x-apikey":KEY() }, timeout:8000 });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

function formatStats(stats) {
  const total   = Object.values(stats).reduce((a, b) => a + b, 0);
  const flagged = (stats.malicious||0) + (stats.suspicious||0);
  const verdict = stats.malicious > 2  ? "malicious"
                : stats.suspicious > 2 ? "suspicious" : "clean";
  return { verdict, engines:total, flagged, malicious:stats.malicious, suspicious:stats.suspicious };
}

module.exports = { scanUrl, scanHash, scanDomain, scanIp };
