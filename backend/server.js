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
  urlhaus:       require("./engines/urlhaus"),   // ← replaces PhishTank
  safebrowsing:  require("./engines/safebrowsing"),
  threatfox:     require("./engines/threatfox"),
  whois:         require("./engines/whois"),
};

const ENGINE_KEYS = {
  virustotal:    "VT_API_KEY",
  abuseipdb:     "ABUSEIPDB_KEY",
  urlscan:       "URLSCAN_KEY",
  malwarebazaar: "MALWAREBAZAAR_KEY",
  otx:           "OTX_KEY",
  greynoise:     "GREYNOISE_KEY",
  ipinfo:        "IPINFO_KEY",
  urlhaus:       null,   // ← free, no key needed
  safebrowsing:  "GSB_KEY",
  threatfox:     null,
  whois:         null,
};

const ENGINE_TIMEOUTS = {
  virustotal:    25000,
  abuseipdb:     5000,
  urlscan:       22000,
  malwarebazaar: 5000,
  otx:           16000,
  greynoise:     5000,
  ipinfo:        4000,
  urlhaus:       8000,
  safebrowsing:  5000,
  threatfox:     5000,
  whois:         10000,
};

const ENGINE_WEIGHTS = {
  virustotal:    5,
  safebrowsing:  4,
  abuseipdb:     3,
  urlscan:       3,
  malwarebazaar: 3,
  urlhaus:       3,   // ← same weight as malwarebazaar — high precision source
  otx:           3,
  greynoise:     2,
  threatfox:     2,
  ipinfo:        1,
  whois:         0,
};

const GLOBAL_SCAN_TIMEOUT = 30000;

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

function sanitizeQuery(raw) {
  if (!raw || typeof raw !== "string") return null;
  const q = raw.trim();
  if (q.length === 0 || q.length > 2048) return null;
  if (/[\x00\r\n]/.test(q)) return null;
  return q;
}

function safeError(err) {
  if (!err) return "Unknown error";
  const msg = err.message || String(err);
  return msg.replace(/\/[^\s]+/g, "[path]").slice(0, 200);
}

const app  = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 4000;

app.use(helmet());

const allowedOrigins = process.env.FRONTEND_URL
  ? [process.env.FRONTEND_URL]
  : ["http://localhost:5173"];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || process.env.NODE_ENV !== "production") {
      return callback(null, true);
    }
    return callback(new Error("CORS: origin not allowed"));
  },
  methods: ["GET", "POST"],
}));

app.use(express.json({ limit: "10kb" }));

const scanRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 60,
  message: { error: "Too many requests — please try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
});

const bulkRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: "Too many bulk scan requests — please try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
});

app.get("/api/health", (req, res) => {
  const status = {};
  for (const [id, keyName] of Object.entries(ENGINE_KEYS)) {
    status[id] = keyName === null ? "active (no key needed)"
               : process.env[keyName] ? "active" : "inactive (no key set)";
  }
  res.json({ status:"ok", engines:status, uptime:process.uptime(), cacheSize:cache.size });
});

// ── SSE Streaming Scan Endpoint ───────────────────────────────────────────────
app.get("/api/scan/stream", scanRateLimit, async (req, res) => {
  const q = sanitizeQuery(req.query.query);
  if (!q) return res.status(400).json({ error: "Invalid or missing query." });

  const { type: userType } = req.query;
  const qLow = q.toLowerCase();
  const type = userType || detectType(qLow);

  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", allowedOrigins[0] || "*");
  res.flushHeaders();

  const send = (event, data) => {
    if (!res.writableEnded)
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  let clientDisconnected = false;
  req.on("close", () => { clientDisconnected = true; });

  const cacheKey = `${type}:${qLow}`;
  const cached   = getCached(cacheKey);
  if (cached) {
    send("start", { query: q, type, total: cached.engines.length, cached: true });
    for (const engine of cached.engines) send("engine", engine);
    send("done", {
      verdict: cached.verdict, score: cached.score,
      malicious: cached.malicious, suspicious: cached.suspicious,
      clean: cached.clean, cached: true, scannedAt: cached.scannedAt,
    });
    return res.end();
  }

  const methodMap  = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };
  const method     = methodMap[type];
  const engineList = Object.entries(engines);

  send("start", { query: q, type, total: engineList.length, cached: false });

  const allResults = [];

  const globalTimeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("Global scan timeout")), GLOBAL_SCAN_TIMEOUT)
  );

  try {
    await Promise.race([
      Promise.allSettled(
        engineList.map(async ([id, engine]) => {
          if (clientDisconnected) return;
          const keyName = ENGINE_KEYS[id];
          if (keyName && !process.env[keyName]) {
            const r = { id, verdict:"skipped", detail:`No API key set for ${id}` };
            allResults.push(r); send("engine", r); return;
          }
          const timeout = ENGINE_TIMEOUTS[id] || 10000;
          try {
            const result = await Promise.race([
              engine[method](q),
              new Promise((_, reject) =>
                setTimeout(() => reject(new Error(`${id} timeout`)), timeout))
            ]);
            const r = { id, ...result };
            allResults.push(r);
            if (!clientDisconnected) send("engine", r);
          } catch (err) {
            const r = { id, verdict:"error", detail: safeError(err) };
            allResults.push(r);
            if (!clientDisconnected) send("engine", r);
          }
        })
      ),
      globalTimeout,
    ]);
  } catch {
    if (!clientDisconnected)
      send("engine", { id:"_timeout", verdict:"info", detail:"Some engines timed out" });
  }

  if (clientDisconnected) return res.end();

  const score        = calcScore(allResults);
  const active       = allResults.filter(r => !["skipped","error","info"].includes(r.verdict));
  const malCount     = active.filter(r => r.verdict === "malicious").length;
  const suspCount    = active.filter(r => r.verdict === "suspicious").length;
  const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";

  const summary = {
    verdict: finalVerdict, score,
    malicious: malCount, suspicious: suspCount,
    clean: active.filter(r => r.verdict === "clean").length,
    cached: false, scannedAt: new Date().toISOString(),
  };

  if (allResults.length > 0)
    setCache(cacheKey, { query: q, type, engines: allResults, ...summary });
  send("done", summary);
  res.end();
});

// ── Bulk Scan SSE Endpoint ────────────────────────────────────────────────────
app.get("/api/scan/bulk", bulkRateLimit, async (req, res) => {
  const raw = req.query.queries;
  if (!raw) return res.status(400).json({ error: "queries parameter required" });

  const queries = [...new Set(
    raw.split(/[\n,]+/).map(q => sanitizeQuery(q)).filter(Boolean)
  )].slice(0, 20);

  if (queries.length === 0)
    return res.status(400).json({ error: "No valid queries found" });

  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", allowedOrigins[0] || "*");
  res.flushHeaders();

  const send = (event, data) => {
    if (!res.writableEnded)
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  let clientDisconnected = false;
  req.on("close", () => { clientDisconnected = true; });

  const methodMap = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };
  send("start", { total: queries.length, queries });
  const results = [];

  for (let i = 0; i < queries.length; i++) {
    if (clientDisconnected) break;
    const q      = queries[i];
    const type   = detectType(q.toLowerCase()) || "domain";
    const method = methodMap[type];
    send("progress", { index: i, query: q, type, status: "scanning" });

    const cacheKey = `${type}:${q.toLowerCase()}`;
    const cached   = getCached(cacheKey);
    if (cached) {
      const result = { index: i, query: q, type, verdict: cached.verdict,
        score: cached.score, malicious: cached.malicious,
        suspicious: cached.suspicious, clean: cached.clean, cached: true };
      results.push(result); send("result", result); continue;
    }

    const allResults = [];
    await Promise.allSettled(
      Object.entries(engines).map(async ([id, engine]) => {
        const keyName = ENGINE_KEYS[id];
        if (keyName && !process.env[keyName]) {
          allResults.push({ id, verdict:"skipped" }); return;
        }
        const timeout = ENGINE_TIMEOUTS[id] || 10000;
        try {
          const engineResult = await Promise.race([
            engine[method](q),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error(`${id} timeout`)), timeout))
          ]);
          allResults.push({ id, ...engineResult });
        } catch (err) {
          allResults.push({ id, verdict:"error", detail: safeError(err) });
        }
      })
    );

    const score        = calcScore(allResults);
    const active       = allResults.filter(r => !["skipped","error","info"].includes(r.verdict));
    const malCount     = active.filter(r => r.verdict === "malicious").length;
    const suspCount    = active.filter(r => r.verdict === "suspicious").length;
    const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";
    const summary      = {
      verdict: finalVerdict, score, malicious: malCount,
      suspicious: suspCount,
      clean: active.filter(r => r.verdict === "clean").length,
      scannedAt: new Date().toISOString(),
    };

    setCache(cacheKey, { query: q, type, engines: allResults, ...summary });
    const result = { index: i, query: q, type, cached: false, ...summary };
    results.push(result); send("result", result);
  }

  if (!clientDisconnected) {
    send("done", {
      total: queries.length,
      malicious: results.filter(r => r.verdict === "malicious").length,
      suspicious: results.filter(r => r.verdict === "suspicious").length,
      clean: results.filter(r => r.verdict === "clean").length,
      results,
    });
  }
  res.end();
});

// ── Legacy JSON endpoint ──────────────────────────────────────────────────────
app.post("/api/scan", scanRateLimit, async (req, res) => {
  const q = sanitizeQuery(req.body.query);
  if (!q) return res.status(400).json({ error: "Invalid or missing query." });

  const qLow = q.toLowerCase();
  const type = req.body.type || detectType(qLow);
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
    } catch (err) { return { id, verdict:"error", detail: safeError(err) }; }
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
    clean: active.filter(r => r.verdict === "clean").length,
    engines: data, scannedAt: new Date().toISOString(), cached: false,
  };

  setCache(cacheKey, result);
  res.json(result);
});

app.listen(PORT, () =>
  console.log(`✅ ThreatScan backend running on http://localhost:${PORT}`)
);
