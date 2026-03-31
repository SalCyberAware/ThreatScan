const axios = require("axios");
const BASE = "https://www.virustotal.com/api/v3";
const KEY  = () => process.env.VT_API_KEY;

async function scanUrl(url) {
  const submit = await axios.post(
    `${BASE}/urls`,
    `url=${encodeURIComponent(url)}`,
    { headers: { "x-apikey": KEY(), "Content-Type": "application/x-www-form-urlencoded" } }
  );
  const analysisId = submit.data.data.id;
  for (let i = 0; i < 5; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const report = await axios.get(`${BASE}/analyses/${analysisId}`,
      { headers: { "x-apikey": KEY() } });
    const stats = report.data.data.attributes.stats;
    if (stats) return formatStats(stats);
  }
  return { verdict: "unknown", detail: "Analysis timeout" };
}

async function scanHash(hash) {
  const res = await axios.get(`${BASE}/files/${hash}`,
    { headers: { "x-apikey": KEY() } });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanDomain(domain) {
  const res = await axios.get(`${BASE}/domains/${domain}`,
    { headers: { "x-apikey": KEY() } });
  return formatStats(res.data.data.attributes.last_analysis_stats);
}

async function scanIp(ip) {
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
