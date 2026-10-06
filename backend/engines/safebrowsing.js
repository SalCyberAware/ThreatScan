const axios = require("axios");
const { DEFAULT_TIMEOUT } = require("../utils/upstream");
const KEY = () => process.env.GSB_KEY;

async function scanUrl(url, signal) {
  const body = {
    client: { clientId: "threatscan", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes:    ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries:    [{ url }],
    },
  };
  // The key goes in a header, not the query string, so it is never part of a
  // URL that an error message, proxy or request log might record.
  const res = await axios.post(
    "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    body,
    { headers: { "x-goog-api-key": KEY() }, timeout: DEFAULT_TIMEOUT, signal }
  );
  const matches = res.data.matches ?? [];
  if (matches.length === 0) return { verdict: "clean", threats: [] };
  return { verdict: "malicious", threats: matches.map(m => m.threatType) };
}

async function scanDomain(domain, signal) { return scanUrl(`https://${domain}`, signal); }
async function scanIp()           { return { verdict: "info", detail: "URL-only engine" }; }
async function scanHash()         { return { verdict: "info", detail: "URL-only engine" }; }

module.exports = { scanUrl, scanDomain, scanIp, scanHash };
