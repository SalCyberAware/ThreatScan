const axios = require("axios");
const { DEFAULT_TIMEOUT } = require("../utils/upstream");
const { authHeaders } = require("../utils/abusech");
const BASE = "https://threatfox-api.abuse.ch/api/v1/";

async function query(body, signal) {
  const res = await axios.post(BASE, JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      ...authHeaders(),
    },
    timeout: DEFAULT_TIMEOUT, signal,
  });
  // Anything other than a hit or a clean miss (a rejected key, an illegal
  // search term) is an error, never a verdict. Errors propagate so the scan
  // reports this engine as "error" instead of a "clean" it never established.
  const status = res.data?.query_status;
  if (status !== "ok" && status !== "no_result")
    throw new Error(`ThreatFox: ${status ?? "unexpected response"}`);
  return res.data;
}

async function scanHash(hash, signal) {
  const data = await query({ query: "search_hash", hash }, signal);
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict: "malicious",
    malware: ioc?.malware ?? null,
    confidence: ioc?.confidence_level ?? null,
    tags: ioc?.tags ?? [],
  };
}

async function scanIp(ip, signal) {
  const data = await query({ query: "search_ioc", search_term: ip }, signal);
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict: "malicious",
    malware: ioc?.malware ?? null,
    confidence: ioc?.confidence_level ?? null,
  };
}

async function scanUrl(url, signal) {
  const data = await query({ query: "search_ioc", search_term: url }, signal);
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict: "malicious",
    malware: ioc?.malware ?? null,
  };
}

async function scanDomain(domain, signal) { return scanUrl(domain, signal); }

module.exports = { scanHash, scanIp, scanUrl, scanDomain };
