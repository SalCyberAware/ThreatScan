const axios = require("axios");
const BASE = "https://otx.alienvault.com/api/v1";
const KEY  = () => process.env.OTX_KEY;
const headers = () => ({ "X-OTX-API-KEY": KEY() });

async function scanIp(ip) {
  const [general, rep] = await Promise.all([
    axios.get(`${BASE}/indicators/IPv4/${ip}/general`,    { headers: headers() }),
    axios.get(`${BASE}/indicators/IPv4/${ip}/reputation`, { headers: headers() }),
  ]);
  const pulses = general.data.pulse_info?.count ?? 0;
  const score  = rep.data.reputation?.threat_score ?? 0;
  return {
    verdict:    pulses > 5 ? "malicious" : pulses > 0 ? "suspicious" : "clean",
    pulses, score,
    country:    general.data.country_name,
    indicators: general.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
  };
}

async function scanDomain(domain) {
  const res = await axios.get(`${BASE}/indicators/domain/${domain}/general`, { headers: headers() });
  const pulses = res.data.pulse_info?.count ?? 0;
  return {
    verdict:    pulses > 5 ? "malicious" : pulses > 0 ? "suspicious" : "clean",
    pulses,
    indicators: res.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
  };
}

async function scanUrl(url) {
  const hostname = new URL(url).hostname;
  return scanDomain(hostname);
}

async function scanHash(hash) {
  const res = await axios.get(`${BASE}/indicators/file/${hash}/general`, { headers: headers() });
  const pulses = res.data.pulse_info?.count ?? 0;
  return {
    verdict:    pulses > 0 ? "malicious" : "clean",
    pulses,
    malware:    res.data.malware_families?.[0]?.display_name ?? null,
    indicators: res.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
  };
}

module.exports = { scanIp, scanDomain, scanUrl, scanHash };
