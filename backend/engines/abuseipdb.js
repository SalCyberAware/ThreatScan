const axios = require("axios");
const BASE = "https://api.abuseipdb.com/api/v2";
const KEY  = () => process.env.ABUSEIPDB_KEY;

// ─── FIX: Validate input is actually an IP before calling the API ─────────────
// The 422 error happened because the URL "https://otx.alienvault.com/dashboard/new"
// was passed to scanIp() when the user had "IP / Host" manually selected.
// AbuseIPDB rejects non-IP input with 422 Unprocessable Entity.
// This guard returns a graceful "IP-only engine" info instead of erroring.
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

function isValidIP(str) {
  if (IPV4_RE.test(str)) {
    return str.split(".").map(Number).every(n => n >= 0 && n <= 255);
  }
  return IPV6_RE.test(str);
}
// ─────────────────────────────────────────────────────────────────────────────

async function scanIp(ip) {
  if (!isValidIP(ip)) {
    return { verdict: "info", detail: "IP-only engine" };
  }

  const res = await axios.get(`${BASE}/check`, {
    params: { ipAddress: ip, maxAgeInDays: 90, verbose: true },
    headers: { Key: KEY(), Accept: "application/json" }
  });
  const d = res.data.data;
  const verdict = d.abuseConfidenceScore >= 75 ? "malicious"
                : d.abuseConfidenceScore >= 25 ? "suspicious"
                : "clean";
  return {
    verdict,
    confidence:    d.abuseConfidenceScore,
    reports:       d.totalReports,
    country:       d.countryCode,
    isp:           d.isp,
    domain:        d.domain,
    lastSeen:      d.lastReportedAt,
    isWhitelisted: d.isWhitelisted
  };
}

async function scanUrl()    { return { verdict: "info", detail: "IP-only engine" }; }
async function scanHash()   { return { verdict: "info", detail: "IP-only engine" }; }
async function scanDomain() { return { verdict: "info", detail: "IP-only engine" }; }

module.exports = { scanIp, scanUrl, scanHash, scanDomain };
