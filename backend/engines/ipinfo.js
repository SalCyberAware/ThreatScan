const axios = require("axios");
const { DEFAULT_TIMEOUT, pathSegment } = require("../utils/upstream");
const KEY = () => process.env.IPINFO_KEY;

async function scanIp(ip, signal) {
  const res = await axios.get(`https://ipinfo.io/${pathSegment(ip)}/json`, {
    params: { token: KEY() },
    timeout: DEFAULT_TIMEOUT, signal,
  });
  const d = res.data;
  return {
    verdict:  "info",
    org:      d.org,
    country:  d.country,
    region:   d.region,
    city:     d.city,
    timezone: d.timezone,
    hostname: d.hostname,
    abuse:    d.abuse?.email ?? null,
  };
}

async function scanUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return { verdict: "info", detail: `Use IP scan for ${hostname}` };
  } catch { return { verdict: "info" }; }
}

async function scanHash()   { return { verdict: "info", detail: "IP-only engine" }; }
async function scanDomain() { return { verdict: "info", detail: "IP-only engine" }; }

module.exports = { scanIp, scanUrl, scanHash, scanDomain };
