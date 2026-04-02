/**
 * WHOIS + DNS Engine
 * Free, no API key required.
 *
 * Uses:
 *   - whoisjson.com  → WHOIS data (registrar, dates, country)
 *   - dns.google     → DNS records (A, MX, NS)
 */

const axios = require("axios");
const TIMEOUT = { timeout: 8000 };

async function scanDomain(domain) {
  const results = {};

  // ── WHOIS ──────────────────────────────────────────────────────────────────
  try {
    const res  = await axios.get(`https://whoisjson.com/api/v1/whois?domain=${domain}`, TIMEOUT);
    const data = res.data;
    results.registrar  = data.registrar        || null;
    results.created    = data.creation_date    || null;
    results.expires    = data.expiration_date  || null;
    results.country    = data.registrant_country || null;
    results.nameservers = data.name_servers?.slice(0, 3) || [];
  } catch {}

  // ── DNS (A records) ────────────────────────────────────────────────────────
  try {
    const res = await axios.get(
      `https://dns.google/resolve?name=${domain}&type=A`, TIMEOUT);
    results.aRecords = res.data.Answer?.map(r => r.data).slice(0, 4) || [];
  } catch {}

  // ── DNS (MX records) ───────────────────────────────────────────────────────
  try {
    const res = await axios.get(
      `https://dns.google/resolve?name=${domain}&type=MX`, TIMEOUT);
    results.mxRecords = res.data.Answer?.map(r => r.data).slice(0, 3) || [];
  } catch {}

  if (Object.keys(results).length === 0) {
    return { verdict:"info", detail:"WHOIS/DNS lookup failed" };
  }

  return {
    verdict:     "info",
    registrar:   results.registrar,
    created:     results.created    ? results.created.slice(0, 10)  : null,
    expires:     results.expires    ? results.expires.slice(0, 10)  : null,
    country:     results.country,
    nameservers: results.nameservers,
    aRecords:    results.aRecords,
    mxRecords:   results.mxRecords,
  };
}

async function scanUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return scanDomain(hostname);
  } catch {
    return { verdict:"info", detail:"Invalid URL" };
  }
}

async function scanIp(ip) {
  // Use ipinfo for IP WHOIS-like data (already have ipinfo engine)
  return { verdict:"info", detail:"Use domain or URL for WHOIS" };
}

async function scanHash() {
  return { verdict:"info", detail:"N/A for file hashes" };
}

module.exports = { scanDomain, scanUrl, scanIp, scanHash };
