const axios = require("axios");
const BASE = "https://otx.alienvault.com/api/v1";
const KEY  = () => process.env.OTX_KEY;
const headers = () => ({ "X-OTX-API-KEY": KEY() });
const TIMEOUT = { timeout: 8000 };

async function scanIp(ip) {
  try {
    const [general, rep] = await Promise.all([
      axios.get(`${BASE}/indicators/IPv4/${ip}/general`, { headers: headers(), ...TIMEOUT }),
      axios.get(`${BASE}/indicators/IPv4/${ip}/reputation`, { headers: headers(), ...TIMEOUT }),
    ]);
    const pulses = general.data.pulse_info?.count ?? 0;
    const score  = rep.data.reputation?.threat_score ?? 0;
    return {
      verdict:    pulses > 5 ? "malicious" : pulses > 0 ? "suspicious" : "clean",
      pulses, score,
      country:    general.data.country_name,
      indicators: general.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
    };
  } catch { return { verdict: "clean", detail: "OTX timeout or error" }; }
}

async function scanDomain(domain) {
  try {
    const res = await axios.get(`${BASE}/indicators/domain/${domain}/general`,
      { headers: headers(), ...TIMEOUT });
    const pulses = res.data.pulse_info?.count ?? 0;
    return {
      verdict:    pulses > 5 ? "malicious" : pulses > 0 ? "suspicious" : "clean",
      pulses,
      indicators: res.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
    };
  } catch { return { verdict: "clean", detail: "OTX timeout or error" }; }
}

async function scanUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return scanDomain(hostname);
  } catch { return { verdict: "clean" }; }
}

async function scanHash(hash) {
  try {
    const res = await axios.get(`${BASE}/indicators/file/${hash}/general`,
      { headers: headers(), ...TIMEOUT });
    const pulses = res.data.pulse_info?.count ?? 0;
    return {
      verdict:    pulses > 0 ? "malicious" : "clean",
      pulses,
      malware:    res.data.malware_families?.[0]?.display_name ?? null,
      indicators: res.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
    };
  } catch { return { verdict: "clean", detail: "OTX timeout or error" }; }
}

module.exports = { scanIp, scanDomain, scanUrl, scanHash };
