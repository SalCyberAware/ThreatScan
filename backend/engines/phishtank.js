const axios = require("axios");
const BASE = "https://checkurl.phishtank.com/checkurl/";
const KEY  = () => process.env.PHISHTANK_KEY;

async function scanUrl(url) {
  const params = new URLSearchParams({
    url:    Buffer.from(url).toString("base64"),
    format: "json",
  });
  if (KEY()) params.append("app_key", KEY());

  const res = await axios.post(BASE, params, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent":   "phishtank/ThreatScan"
    }
  });
  const r = res.data.results;
  return {
    verdict:     r.in_database && r.verified ? "malicious" : "clean",
    inDatabase:  r.in_database,
    verified:    r.verified,
    phishId:     r.phish_id ?? null,
    phishDetail: r.phish_detail_url ?? null,
  };
}

async function scanDomain(domain) { return scanUrl(`https://${domain}`); }
async function scanIp()           { return { verdict: "info", detail: "URL-only engine" }; }
async function scanHash()         { return { verdict: "info", detail: "URL-only engine" }; }

module.exports = { scanUrl, scanDomain, scanIp, scanHash };
