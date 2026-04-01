require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const rateLimit = require("express-rate-limit");
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

const ENGINE_TIMEOUTS = {
  virustotal:    12000,
  abuseipdb:     5000,
  urlscan:       20000,
  malwarebazaar: 5000,
  otx:           8000,
  greynoise:     5000,
  ipinfo:        4000,
  phishtank:     6000,
  safebrowsing:  5000,
  threatfox:     5000,
};

const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000;

function getCached(key) {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL) { cache.delete(key); return null; }
  return entry.data;
}

function setCache(key, data) {
  if (cache.size >= 500) cache.delete(cache.keys().next().value);
  cache.set(key, { data, timestamp: Date.now() });
}

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || "*", methods: ["GET","POST"] }));
app.use(express.json());
app.use("/api/scan", rateLimit({
  windowMs: 15 * 60 * 1000, max: 60,
  message: { error: "Too many requests, please try again later." }
}));

app.get("/api/health", (req, res) => {
  const status = {};
  for (const [id, keyName] of Object.entries(ENGINE_KEYS)) {
    status[id] = keyName === null ? "active (no key needed)"
               : process.env[keyName] ? "active" : "inactive (no key set)";
  }
  res.json({ status: "ok", engines: status, uptime: process.uptime(), cacheSize: cache.size });
});

app.get("/api/cache/clear", (req, res) => {
  cache.clear();
  res.json({ status: "ok", message: "Cache cleared" });
});

app.post("/api/scan", async (req, res) => {
  const { query, type: userType } = req.body;
  if (!query || typeof query !== "string" || query.trim().length === 0)
    return res.status(400).json({ error: "query is required" });

  const q    = query.trim().toLowerCase();
  const type = userType || detectType(q);
  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  const cacheKey = `${type}:${q}`;
  const cached   = getCached(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  const methodMap = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };
  const method    = methodMap[type];

  const enginePromises = Object.entries(engines).map(async ([id, engine]) => {
    const keyName = ENGINE_KEYS[id];
    if (keyName && !process.env[keyName])
      return { id, verdict:"skipped", detail:`No API key set for ${id}` };
    const timeout = ENGINE_TIMEOUTS[id] || 10000;
    try {
      const result = await Promise.race([
        engine[method](q),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`${id} timeout`)), timeout))
      ]);
      return { id, ...result };
    } catch (err) {
      return { id, verdict:"error", detail: err.message };
    }
  });

  const settled = await Promise.allSettled(enginePromises);
  const data    = settled.map(r => r.status === "fulfilled" ? r.value : { verdict:"error" });

  const active      = data.filter(r => !["skipped","error","info"].includes(r.verdict));
  const malCount    = active.filter(r => r.verdict === "malicious").length;
  const suspCount   = active.filter(r => r.verdict === "suspicious").length;
  const totalActive = active.length || 1;
  const score       = Math.min(100, Math.round(
    (malCount / totalActive) * 100 + (suspCount / totalActive) * 30));
  const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";

  const result = {
    query: q, type, verdict: finalVerdict, score,
    malicious: malCount, suspicious: suspCount,
    clean: active.filter(r => r.verdict === "clean").length,
    engines: data, scannedAt: new Date().toISOString(), cached: false,
  };

  setCache(cacheKey, result);
  res.json(result);
});

app.listen(PORT, () => {
  console.log(`✅ ThreatScan backend running on http://localhost:${PORT}`);
});
