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
  virustotal:    25000, // includes cache-hit + up to 6 polls × 3s
  abuseipdb:     5000,
  urlscan:       22000,
  malwarebazaar: 5000,
  otx:           16000, // FIX: synced with otx.js internal timeout of 15s
  greynoise:     5000,
  ipinfo:        4000,
  phishtank:     6000,
  safebrowsing:  5000,
  threatfox:     5000,
};

// FIX: Weighted scoring — engines that aggregate many sub-engines
// or have high accuracy carry more weight in the final score.
const ENGINE_WEIGHTS = {
  virustotal:    5,  // aggregates 95 AV engines — highest signal
  safebrowsing:  4,  // Google's own blocklist — very reliable
  abuseipdb:     3,  // large community database
  urlscan:       3,  // deep URL analysis
  malwarebazaar: 3,  // malware-specific, high precision
  phishtank:     3,  // phishing-specific, high precision
  otx:           3,  // large threat intel community
  greynoise:     2,  // noise filtering, good but narrower scope
  threatfox:     2,  // IOC focused
  ipinfo:        1,  // geo/org info only, not a threat engine
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

// FIX: Weighted score calculation
// Malicious engine = full weight, suspicious = 40% weight
// Score is normalized to 0-100
function calcScore(results) {
  let weightedMal  = 0;
  let weightedSusp = 0;
  let totalWeight  = 0;

  for (const r of results) {
    if (["skipped","error","info"].includes(r.verdict)) continue;
    const w = ENGINE_WEIGHTS[r.id] || 1;
    totalWeight += w;
    if (r.verdict === "malicious")  weightedMal  += w;
    if (r.verdict === "suspicious") weightedSusp += w;
  }

  if (totalWeight === 0) return 0;
  const raw = ((weightedMal / totalWeight) * 100) +
              ((weightedSusp / totalWeight) * 40);
  return Math.min(100, Math.round(raw));
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
  res.json({ status:"ok", engines:status, uptime:process.uptime(), cacheSize:cache.size });
});

// ── SSE Streaming Scan Endpoint ───────────────────────────────────────────────
app.get("/api/scan/stream", async (req, res) => {
  const { query, type: userType } = req.query;

  if (!query || query.trim().length === 0)
    return res.status(400).json({ error: "query is required" });

  // FIX: Don't lowercase the full query — URLs have case-sensitive paths.
  // Only lowercase for type detection, keep original for actual scanning.
  const q    = query.trim();
  const qLow = q.toLowerCase();
  const type = userType || detectType(qLow);

  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  const send = (event, data) =>
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  // Use lowercased key for cache (case-insensitive cache lookup)
  const cacheKey = `${type}:${qLow}`;
  const cached   = getCached(cacheKey);
  if (cached) {
    send("start", { query: q, type, total: cached.engines.length, cached: true });
    for (const engine of cached.engines) send("engine", engine);
    send("done", {
      verdict:    cached.verdict,
      score:      cached.score,
      malicious:  cached.malicious,
      suspicious: cached.suspicious,
      clean:      cached.clean,
      cached:     true,
      scannedAt:  cached.scannedAt,
    });
    return res.end();
  }

  const methodMap  = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };
  const method     = methodMap[type];
  const engineList = Object.entries(engines);

  send("start", { query: q, type, total: engineList.length, cached: false });

  const allResults = [];

  await Promise.allSettled(
    engineList.map(async ([id, engine]) => {
      const keyName = ENGINE_KEYS[id];
      if (keyName && !process.env[keyName]) {
        const r = { id, verdict:"skipped", detail:`No API key set for ${id}` };
        allResults.push(r);
        send("engine", r);
        return;
      }
      const timeout = ENGINE_TIMEOUTS[id] || 10000;
      try {
        const result = await Promise.race([
          engine[method](q),  // pass original case query
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error(`${id} timeout`)), timeout))
        ]);
        const r = { id, ...result };
        allResults.push(r);
        send("engine", r);
      } catch (err) {
        const r = { id, verdict:"error", detail: err.message };
        allResults.push(r);
        send("engine", r);
      }
    })
  );

  const score        = calcScore(allResults);
  const active       = allResults.filter(r => !["skipped","error","info"].includes(r.verdict));
  const malCount     = active.filter(r => r.verdict === "malicious").length;
  const suspCount    = active.filter(r => r.verdict === "suspicious").length;
  const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";

  const summary = {
    verdict:    finalVerdict,
    score,
    malicious:  malCount,
    suspicious: suspCount,
    clean:      active.filter(r => r.verdict === "clean").length,
    cached:     false,
    scannedAt:  new Date().toISOString(),
  };

  setCache(cacheKey, { query: q, type, engines: allResults, ...summary });
  send("done", summary);
  res.end();
});

// ── Legacy JSON endpoint ──────────────────────────────────────────────────────
app.post("/api/scan", async (req, res) => {
  const { query, type: userType } = req.body;
  if (!query || typeof query !== "string" || query.trim().length === 0)
    return res.status(400).json({ error: "query is required" });

  const q    = query.trim();
  const qLow = q.toLowerCase();
  const type = userType || detectType(qLow);
  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  const cacheKey = `${type}:${qLow}`;
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

  const score        = calcScore(data);
  const active       = data.filter(r => !["skipped","error","info"].includes(r.verdict));
  const malCount     = active.filter(r => r.verdict === "malicious").length;
  const suspCount    = active.filter(r => r.verdict === "suspicious").length;
  const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";

  const result = {
    query: q, type, verdict: finalVerdict, score,
    malicious: malCount, suspicious: suspCount,
    clean:   active.filter(r => r.verdict === "clean").length,
    engines: data, scannedAt: new Date().toISOString(), cached: false,
  };

  setCache(cacheKey, result);
  res.json(result);
});

app.listen(PORT, () =>
  console.log(`✅ ThreatScan backend running on http://localhost:${PORT}`)
);
