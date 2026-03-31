const axios = require("axios");
const BASE = "https://api.greynoise.io/v3";
const KEY  = () => process.env.GREYNOISE_KEY;

async function scanIp(ip) {
  try {
    const res = await axios.get(`${BASE}/community/${ip}`, {
      headers: { key: KEY() }
    });
    const d = res.data;
    return {
      verdict:        d.classification === "malicious" ? "malicious"
                    : d.classification === "benign"    ? "clean" : "info",
      classification: d.classification,
      name:           d.name,
      noise:          d.noise,
      riot:           d.riot,
      message:        d.message,
      link:           d.link,
    };
  } catch (err) {
    if (err.response?.status === 404)
      return { verdict: "clean", detail: "Not seen by GreyNoise" };
    throw err;
  }
}

async function scanUrl()    { return { verdict: "info", detail: "IP-only engine" }; }
async function scanHash()   { return { verdict: "info", detail: "IP-only engine" }; }
async function scanDomain() { return { verdict: "info", detail: "IP-only engine" }; }

module.exports = { scanIp, scanUrl, scanHash, scanDomain };
