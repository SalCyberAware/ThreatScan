const axios = require("axios");
const BASE = "https://threatfox-api.abuse.ch/api/v1/";

async function query(body) {
  const res = await axios.post(BASE, JSON.stringify(body), {
    headers: { 
      "Content-Type": "application/json",
      "Accept": "application/json"
    }
  });
  return res.data;
}

async function scanHash(hash) {
  try {
    const data = await query({ query: "search_hash", hash });
    if (data.query_status === "no_result") return { verdict: "clean" };
    const ioc = data.data?.[0];
    return {
      verdict: "malicious",
      malware: ioc?.malware ?? null,
      confidence: ioc?.confidence_level ?? null,
      tags: ioc?.tags ?? [],
    };
  } catch { return { verdict: "clean" }; }
}

async function scanIp(ip) {
  try {
    const data = await query({ query: "search_ioc", search_term: ip });
    if (data.query_status === "no_result") return { verdict: "clean" };
    const ioc = data.data?.[0];
    return {
      verdict: "malicious",
      malware: ioc?.malware ?? null,
      confidence: ioc?.confidence_level ?? null,
    };
  } catch { return { verdict: "clean" }; }
}

async function scanUrl(url) {
  try {
    const data = await query({ query: "search_ioc", search_term: url });
    if (data.query_status === "no_result") return { verdict: "clean" };
    const ioc = data.data?.[0];
    return {
      verdict: "malicious",
      malware: ioc?.malware ?? null,
    };
  } catch { return { verdict: "clean" }; }
}

async function scanDomain(domain) { return scanUrl(domain); }

module.exports = { scanHash, scanIp, scanUrl, scanDomain };
