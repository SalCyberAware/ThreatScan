/**
 * URLhaus Engine (abuse.ch)
 *
 * Free, no API key required.
 * Same trusted source as MalwareBazaar and ThreatFox.
 *
 * Supports: URL, domain, hash (SHA256 only)
 * Does not support: IP addresses (use AbuseIPDB/GreyNoise for IPs)
 *
 * API docs: https://urlhaus-api.abuse.ch/
 */

const axios = require("axios");
const BASE    = "https://urlhaus-api.abuse.ch/v1";
const TIMEOUT = { timeout: 8000 };

async function scanUrl(url) {
  try {
    const res  = await axios.post(`${BASE}/url/`, `url=${encodeURIComponent(url)}`,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results") {
      return { verdict: "clean", detail: "Not found in URLhaus" };
    }

    if (d.query_status === "is_page" || d.url_status === "online") {
      const tags    = d.tags || [];
      const malware = d.payloads?.[0]?.filename || null;
      return {
        verdict:  "malicious",
        detail:   `URLhaus: ${d.url_status || "listed"} — ${d.threat || "malware"}`,
        tags,
        malware,
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
  } catch {
    return { verdict: "info", detail: "URLhaus lookup failed" };
  }
}

async function scanDomain(domain) {
  try {
    const res = await axios.post(`${BASE}/host/`,
      `host=${encodeURIComponent(domain)}`,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results") {
      return { verdict: "clean", detail: "Not found in URLhaus" };
    }

    const urlCount = d.urls?.length || 0;
    const online   = d.urls?.filter(u => u.url_status === "online").length || 0;

    return {
      verdict: online > 0 ? "malicious" : "suspicious",
      detail:  `${urlCount} malicious URLs — ${online} currently online`,
      tags:    [...new Set(d.urls?.flatMap(u => u.tags || []))].slice(0, 5),
    };
  } catch {
    return { verdict: "info", detail: "URLhaus lookup failed" };
  }
}

async function scanHash(hash) {
  // URLhaus only supports SHA256
  if (hash.length !== 64) {
    return { verdict: "info", detail: "URLhaus supports SHA256 only" };
  }
  try {
    const res = await axios.post(`${BASE}/payload/`,
      `sha256_hash=${hash}`,
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, ...TIMEOUT });
    const d = res.data;

    if (d.query_status === "no_results") {
      return { verdict: "clean", detail: "Not found in URLhaus" };
    }

    return {
      verdict: "malicious",
      detail:  `Malware: ${d.file_type || "unknown"} — ${d.urls_count || 0} distribution URLs`,
      malware: d.signature || null,
      tags:    d.tags || [],
    };
  } catch {
    return { verdict: "info", detail: "URLhaus lookup failed" };
  }
}

async function scanIp() {
  return { verdict: "info", detail: "URL/domain/hash engine" };
}

module.exports = { scanUrl, scanDomain, scanHash, scanIp };
