const axios = require("axios");
const BASE = "https://otx.alienvault.com/api/v1";
const KEY  = () => process.env.OTX_KEY;
const headers = () => ({ "X-OTX-API-KEY": KEY() });

// FIX 1: Increased timeout from 8s to 15s — OTX free tier is slow
const TIMEOUT = { timeout: 15000 };

async function scanIp(ip) {
  try {
    const [general, rep] = await Promise.all([
      axios.get(`${BASE}/indicators/IPv4/${ip}/general`,    { headers: headers(), ...TIMEOUT }),
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
  } catch (e) {
    // FIX 2: Return "error" with a real message instead of silently returning "clean"
    const msg = e.code === "ECONNABORTED" ? "otx timeout" : "otx error";
    return { verdict: "error", detail: msg };
  }
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
  } catch (e) {
    const msg = e.code === "ECONNABORTED" ? "otx timeout" : "otx error";
    return { verdict: "error", detail: msg };
  }
}

async function scanUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return scanDomain(hostname);
  } catch (e) {
    const msg = e.code === "ECONNABORTED" ? "otx timeout" : "otx error";
    return { verdict: "error", detail: msg };
  }
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
  } catch (e) {
    const msg = e.code === "ECONNABORTED" ? "otx timeout" : "otx error";
    return { verdict: "error", detail: msg };
  }
}

module.exports = { scanIp, scanDomain, scanUrl, scanHash };
