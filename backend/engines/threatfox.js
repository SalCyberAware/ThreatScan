const axios = require("axios");
const BASE = "https://threatfox-api.abuse.ch/api/v1/";

async function query(body) {
  const res = await axios.post(BASE, body, {
    headers: { "Content-Type": "application/json" }
  });
  return res.data;
}

async function scanHash(hash) {
  const data = await query({ query: "search_hash", hash });
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict:    "malicious",
    malware:    ioc?.malware ?? null,
    type:       ioc?.ioc_type ?? null,
    confidence: ioc?.confidence_level ?? null,
    firstSeen:  ioc?.first_seen ?? null,
    tags:       ioc?.tags ?? [],
  };
}

async function scanIp(ip) {
  const data = await query({ query: "search_ioc", search_term: ip });
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict:    "malicious",
    malware:    ioc?.malware ?? null,
    confidence: ioc?.confidence_level ?? null,
    tags:       ioc?.tags ?? [],
  };
}

async function scanUrl(url) {
  const data = await query({ query: "search_ioc", search_term: url });
  if (data.query_status === "no_result") return { verdict: "clean" };
  const ioc = data.data?.[0];
  return {
    verdict:    "malicious",
    malware:    ioc?.malware ?? null,
    confidence: ioc?.confidence_level ?? null,
  };
}

async function scanDomain(domain) { return scanUrl(domain); }

module.exports = { scanHash, scanIp, scanUrl, scanDomain };
