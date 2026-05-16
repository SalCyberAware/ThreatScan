const axios = require("axios");
const BASE = "https://otx.alienvault.com/api/v1";
const KEY  = () => process.env.OTX_KEY;
const headers = () => ({ "X-OTX-API-KEY": KEY() });

// 15s axios timeout (orchestrator in server.js allows 16s — see ENGINE_TIMEOUTS).
// OTX free tier is slow, especially on /reputation, so we keep this generous.
const TIMEOUT = { timeout: 15000 };

async function scanIp(ip) {
  // Best-effort dual-fetch: /general is load-bearing (drives the verdict),
  // /reputation is supplemental (just provides the score). Use allSettled so
  // a slow /reputation does not nuke a perfectly good /general result.
  const [generalResult, repResult] = await Promise.allSettled([
    axios.get(`${BASE}/indicators/IPv4/${ip}/general`,    { headers: headers(), ...TIMEOUT }),
    axios.get(`${BASE}/indicators/IPv4/${ip}/reputation`, { headers: headers(), ...TIMEOUT }),
  ]);

  // /general failure is a real error — surface it.
  if (generalResult.status === "rejected") {
    const e = generalResult.reason;
    const msg = e?.code === "ECONNABORTED" ? "otx timeout" : "otx error";
    return { verdict: "error", detail: msg };
  }

  // /reputation failure is acceptable — fall back to score = 0.
  const general = generalResult.value;
  const pulses  = general.data.pulse_info?.count ?? 0;
  const score   = repResult.status === "fulfilled"
    ? (repResult.value.data.reputation?.threat_score ?? 0)
    : 0;

  return {
    verdict:    pulses > 5 ? "malicious" : pulses > 0 ? "suspicious" : "clean",
    pulses, score,
    country:    general.data.country_name,
    indicators: general.data.pulse_info?.pulses?.slice(0,3).map(p => p.name) ?? [],
  };
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
