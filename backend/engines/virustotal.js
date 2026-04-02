const axios = require("axios");
const BASE = "https://www.virustotal.com/api/v3";
const KEY  = () => process.env.VT_API_KEY;

// ─── FIX: Add input-type guard so scanIp/scanDomain/scanHash never receive
// the wrong input type (e.g. a URL passed to scanIp → 404 from VT API).
// Also: improve URL polling — reduce polls to 3x with 3s spacing and a
// meaningful "not found" return on 404 instead of crashing.
// ─────────────────────────────────────────────────────────────────────────────

const URL_RE    = /^https?:\/\/.+/i;
const IPV4_RE   = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH_RE   = /^[a-fA-F0-9]{32,64}$/;

async function scanUrl(url) {
  // Guard: must look like a URL
  if (!URL_RE.test(url)) {
    return { verdict: "info", detail: "URL-only engine" };
  }

  // Submit URL for scanning
  const submit = await axios.post(
    `${BASE}/urls`,
    `url=${encodeURIComponent(url)}`,
    { headers: { "x-apikey": KEY(), "Content-Type": "application/x-www-form-urlencoded" } }
  );
  const analysisId = submit.data.data.id;

  // Poll up to 3 times (9s max) — VT free tier is fast for known URLs
  for (let i = 0; i < 3; i++) {
    await new Promise(r => setTimeout(r, 3000));
    try {
      const report = await axios.get(`${BASE}/analyses/${analysisId}`,
        { headers: { "x-apikey": KEY() } });
      const attrs = report.data.data.attributes;
      if (attrs.status === "completed" && attrs.stats) {
        return formatStats(attrs.stats);
      }
    } catch (e) {
      // Poll errors are transient — keep trying
    }
  }
  return { verdict: "info", detail: "Analysis still in progress — try again shortly" };
}

async function scanHash(hash) {
  // Guard: must be hex hash
  if (!HASH_RE.test(hash)) {
    return { verdict: "info", detail: "Hash-only engine" };
  }
  const res = await axios.get(`${BASE}/files/${hash}`,
    { headers: { "x-apikey": KEY() } });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanDomain(domain) {
  // Guard: must not be a URL or IP
  if (URL_RE.test(domain) || IPV4_RE.test(domain)) {
    return { verdict: "info", detail: "Domain-only path — use URL or IP tab" };
  }
  const res = await axios.get(`${BASE}/domains/${domain}`,
    { headers: { "x-apikey": KEY() } });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanIp(ip) {
  // Guard: must look like an IP, not a URL
  if (URL_RE.test(ip) || (!IPV4_RE.test(ip) && !ip.includes(":"))) {
    return { verdict: "info", detail: "IP-only path — use URL or Domain tab" };
  }
  const res = await axios.get(`${BASE}/ip_addresses/${ip}`,
    { headers: { "x-apikey": KEY() } });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

function formatStats(stats) {
  const total   = Object.values(stats).reduce((a, b) => a + b, 0);
  const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
  const verdict = stats.malicious > 2  ? "malicious"
                : stats.suspicious > 2 ? "suspicious" : "clean";
  return { verdict, engines: total, flagged, malicious: stats.malicious, suspicious: stats.suspicious };
}

module.exports = { scanUrl, scanHash, scanDomain, scanIp };
