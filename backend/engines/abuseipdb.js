const axios = require("axios");
const BASE = "https://api.abuseipdb.com/api/v2";
const KEY  = () => process.env.ABUSEIPDB_KEY;

async function scanIp(ip) {
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
    confidence:  d.abuseConfidenceScore,
    reports:     d.totalReports,
    country:     d.countryCode,
    isp:         d.isp,
    domain:      d.domain,
    lastSeen:    d.lastReportedAt,
    isWhitelisted: d.isWhitelisted
  };
}

async function scanUrl()    { return { verdict: "info", detail: "IP-only engine" }; }
async function scanHash()   { return { verdict: "info", detail: "IP-only engine" }; }
async function scanDomain() { return { verdict: "info", detail: "IP-only engine" }; }

module.exports = { scanIp, scanUrl, scanHash, scanDomain };
