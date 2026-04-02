/**
 * URLhaus Engine (abuse.ch)
 * Free with auth key from bazaar.abuse.ch
 */
const axios = require("axios");
const BASE    = "https://urlhaus-api.abuse.ch/v1";
const KEY     = () => process.env.URLHAUS_KEY;
const TIMEOUT = { timeout: 8000 };

function buildParams(base) {
  // FIX: Include auth_key if available — required since abuse.ch added authentication
  if (KEY()) base.auth_key = KEY();
  return new URLSearchParams(base).toString();
}

async function scanUrl(url) {
  try {
    const res = await axios.post(`${BASE}/url/`,
      buildParams({ url }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results")
      return { verdict: "clean", detail: "Not found in URLhaus" };

    if (d.query_status === "is_page" || d.url_status === "online") {
      return {
        verdict: "malicious",
        detail:  `URLhaus: ${d.url_status || "listed"} — ${d.threat || "malware"}`,
        tags:    d.tags || [],
        malware: d.payloads?.[0]?.filename || null,
      };
    }

    if (d.url_status === "offline") {
      return {
        verdict: "suspicious",
        detail:  "Previously malicious — now offline",
        tags:    d.tags || [],
      };
    }

    return { verdict: "info", detail: `URLhaus status: ${d.query_status}` };

  } catch (err) {
    const msg = err.response?.status
      ? `URLhaus HTTP ${err.response.status}`
      : err.code === "ECONNABORTED" ? "URLhaus timeout"
      : `URLhaus error: ${err.message?.slice(0, 80)}`;
    return { verdict: "info", detail: msg };
  }
}

async function scanDomain(domain) {
  try {
    const res = await axios.post(`${BASE}/host/`,
      buildParams({ host: domain }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results")
      return { verdict: "clean", detail: "Not found in URLhaus" };

    const urlCount = d.urls?.length || 0;
    const online   = d.urls?.filter(u => u.url_status === "online").length || 0;

    return {
      verdict: online > 0 ? "malicious" : "suspicious",
      detail:  `${urlCount} malicious URLs — ${online} currently online`,
      tags:    [...new Set(d.urls?.flatMap(u => u.tags || []))].slice(0, 5),
    };

  } catch (err) {
    const msg = err.response?.status
      ? `URLhaus HTTP ${err.response.status}`
      : err.code === "ECONNABORTED" ? "URLhaus timeout"
      : `URLhaus error: ${err.message?.slice(0, 80)}`;
    return { verdict: "info", detail: msg };
  }
}

async function scanHash(hash) {
  if (hash.length !== 64)
    return { verdict: "info", detail: "URLhaus supports SHA256 only" };

  try {
    const res = await axios.post(`${BASE}/payload/`,
      buildParams({ sha256_hash: hash }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results")
      return { verdict: "clean", detail: "Not found in URLhaus" };

    return {
      verdict: "malicious",
      detail:  `Malware: ${d.file_type || "unknown"} — ${d.urls_count || 0} distribution URLs`,
      malware: d.signature || null,
      tags:    d.tags || [],
    };

  } catch (err) {
    const msg = err.response?.status
      ? `URLhaus HTTP ${err.response.status}`
      : err.code === "ECONNABORTED" ? "URLhaus timeout"
      : `URLhaus error: ${err.message?.slice(0, 80)}`;
    return { verdict: "info", detail: msg };
  }
}

async function scanIp() {
  return { verdict: "info", detail: "URL/domain/hash engine" };
}

module.exports = { scanUrl, scanDomain, scanHash, scanIp };
