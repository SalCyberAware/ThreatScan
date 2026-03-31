require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const helmet     = require("helmet");
const rateLimit  = require("express-rate-limit");
const { detectType } = require("./utils/detect");

const engines = {
  virustotal:    require("./engines/virustotal"),
  abuseipdb:     require("./engines/abuseipdb"),
  urlscan:       require("./engines/urlscan"),
  malwarebazaar: require("./engines/malwarebazaar"),
  otx:           require("./engines/otx"),
  greynoise:     require("./engines/greynoise"),
  ipinfo:        require("./engines/ipinfo"),
  phishtank:     require("./engines/phishtank"),
  safebrowsing:  require("./engines/safebrowsing"),
  threatfox:     require("./engines/threatfox"),
};

const ENGINE_KEYS = {
  virustotal:    "VT_API_KEY",
  abuseipdb:     "ABUSEIPDB_KEY",
  urlscan:       "URLSCAN_KEY",
  malwarebazaar: null,
  otx:           "OTX_KEY",
  greynoise:     "GREYNOISE_KEY",
  ipinfo:        "IPINFO_KEY",
  phishtank:     "PHISHTANK_KEY",
  safebrowsing:  "GSB_KEY",
  threatfox:     null,
};

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "*", methods: ["GET","POST"] }));
app.use(express.json());
app.use("/api/scan", rateLimit({ windowMs: 15*60*1000, max: 60,
  message: { error: "Too many requests, please try again later." } }));

app.get("/api/health", (req, res) => {
  const status = {};
  for (const [id, keyName] of Object.entries(ENGINE_KEYS)) {
    status[id] = keyName === null ? "active (no key needed)"
               : process.env[keyName] ? "active"
               : "inactive (no key set)";
  }
  res.json({ status: "ok", engines: status, uptime: process.uptime() });
});

app.post("/api/scan", async (req, res) => {
  const { query, type: userType } = req.body;
  if (!query || typeof query !== "string" || query.trim().length === 0)
    return res.status(400).json({ error: "query is required" });

  const q    = query.trim();
  const type = userType || detectType(q);
  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  const methodMap = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };
  const method    = methodMap[type];

  const enginePromises = Object.entries(engines).map(async ([id, engine]) => {
    const keyName = ENGINE_KEYS[id];
    if (keyName && !process.env[keyName])
      return { id, verdict:"skipped", detail:`No API key set for ${id}` };
    try {
      const result = await Promise.race([
        engine[method](q),
        new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 15000))
      ]);
      return { id, ...result };
    } catch (err) {
      return { id, verdict:"error", detail: err.message };
    }
  });

  const results = await Promise.allSettled(enginePromises);
  const data    = results.map(r => r.status==="fulfilled" ? r.value : { verdict:"error" });

  const active      = data.filter(r => !["skipped","error","info"].includes(r.verdict));
  const malCount    = active.filter(r => r.verdict==="malicious").length;
  const suspCount   = active.filter(r => r.verdict==="suspicious").length;
  const totalActive = active.length || 1;
  const score       = Math.min(100, Math.round((malCount/totalActive)*100 + (suspCount/totalActive)*30));
  const finalVerdict = score>=50 ? "malicious" : score>=20 ? "suspicious" : "clean";

  res.json({
    query: q, type, verdict: finalVerdict, score,
    malicious: malCount, suspicious: suspCount,
    clean: active.filter(r => r.verdict==="clean").length,
    engines: data, scannedAt: new Date().toISOString(),
  });
});

app.listen(PORT, () => {
  console.log(`✅ ThreatScan backend running on http://localhost:${PORT}`);
});
