const axios = require("axios");
const { DEFAULT_TIMEOUT } = require("../utils/upstream");
const BASE = "https://threatfox-api.abuse.ch/api/v1/";

async function query(body, signal) {
  const res = await axios.post(BASE, JSON.stringify(body), {
    headers: { 
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    timeout: DEFAULT_TIMEOUT, signal,
  });
  return res.data;
}

async function scanHash(hash, signal) {
  try {
    const data = await query({ query: "search_hash", hash }, signal);
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

async function scanIp(ip, signal) {
  try {
    const data = await query({ query: "search_ioc", search_term: ip }, signal);
    if (data.query_status === "no_result") return { verdict: "clean" };
    const ioc = data.data?.[0];
    return {
      verdict: "malicious",
      malware: ioc?.malware ?? null,
      confidence: ioc?.confidence_level ?? null,
    };
  } catch { return { verdict: "clean" }; }
}

async function scanUrl(url, signal) {
  try {
    const data = await query({ query: "search_ioc", search_term: url }, signal);
    if (data.query_status === "no_result") return { verdict: "clean" };
    const ioc = data.data?.[0];
    return {
      verdict: "malicious",
      malware: ioc?.malware ?? null,
    };
  } catch { return { verdict: "clean" }; }
}

async function scanDomain(domain, signal) { return scanUrl(domain, signal); }

module.exports = { scanHash, scanIp, scanUrl, scanDomain };
