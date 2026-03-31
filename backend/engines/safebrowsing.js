const axios = require("axios");
const KEY = () => process.env.GSB_KEY;

async function scanUrl(url) {
  const body = {
    client: { clientId: "threatscan", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes:    ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries:    [{ url }],
    },
  };
  const res = await axios.post(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${KEY()}`,
    body
  );
  const matches = res.data.matches ?? [];
  if (matches.length === 0) return { verdict: "clean", threats: [] };
  return { verdict: "malicious", threats: matches.map(m => m.threatType) };
}

async function scanDomain(domain) { return scanUrl(`https://${domain}`); }
async function scanIp()           { return { verdict: "info", detail: "URL-only engine" }; }
async function scanHash()         { return { verdict: "info", detail: "URL-only engine" }; }

module.exports = { scanUrl, scanDomain, scanIp, scanHash };
