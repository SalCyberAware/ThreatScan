// dotenv's `quiet` still defaults to false, so without it config() writes an
// informational "injected env" line on every start (to stderr since dotenv 18;
// dotenv 17 sent it to stdout with a rotating tip). Log collectors and the test
// suite read this process's output; keep it clean.
require("dotenv").config({ quiet: true });
const net       = require("node:net");
const express   = require("express");
const cors      = require("cors");
const helmet    = require("helmet");
const { rateLimit, ipKeyGenerator } = require("express-rate-limit");
const { detectType } = require("./utils/detect");
const { withTimeout } = require("./utils/upstream");

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
  urlhaus:       "MALWAREBAZAAR_KEY",   // one abuse.ch key serves URLhaus, ThreatFox and MalwareBazaar
  safebrowsing:  "GSB_KEY",
  threatfox:     "MALWAREBAZAAR_KEY",
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

// The indicator types a caller may request. Each maps to the engine method
// that handles it. "auto" (what the frontend sends when its own detector found
// nothing) and an absent type both mean "detect it here".
const SCAN_METHODS = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };

// Returns the scan type to use, "unknown" if detection failed, or null if the
// caller supplied a type that is not on the allowlist.
function resolveType(userType, qLow) {
  if (userType === undefined || userType === "" || userType === "auto")
    return detectType(qLow);
  if (typeof userType !== "string" || !Object.hasOwn(SCAN_METHODS, userType))
    return null;
  return userType;
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

// CORS fails closed in production: the one allowed origin is FRONTEND_URL, and
// without it the process refuses to start rather than guessing. Outside
// production any origin is reflected so the Vite dev server works on any port.
// Read once at load; both are fixed for the life of a deployed process.
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const FRONTEND_URL  = (process.env.FRONTEND_URL || "").replace(/\/+$/, "");

if (IS_PRODUCTION && !FRONTEND_URL) {
  throw new Error("FRONTEND_URL must be set when NODE_ENV=production (the frontend origin allowed by CORS).");
}

// A foreign Origin gets a plain 403 before cors runs. Handing cors an Error
// instead sends it to the error handler as a 500, which reads as a server
// fault. Requests with no Origin (curl, health checks, same-origin GETs) pass.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!IS_PRODUCTION || !origin || origin === FRONTEND_URL) return next();
  res.status(403).json({ error: "Origin not allowed." });
});

app.use(cors({
  origin: IS_PRODUCTION ? FRONTEND_URL : true,
  methods: ["GET", "POST"],
}));

app.use(express.json({ limit: "10kb" }));

// Which client a request counts against. On Railway, req.ip under trust proxy
// 1 is an internal hop shared by every visitor, so production keys on
// X-Real-IP, which Railway's edge always sets and overwrites with the
// connecting address. A missing or non-IP value falls back to req.ip rather
// than becoming its own bucket. ipKeyGenerator groups IPv6 by /56 so one host
// cannot rotate through its own subnet. Outside production there is no edge to
// trust, so X-Real-IP is ignored.
function clientKey(req) {
  const realIp = IS_PRODUCTION ? req.get("x-real-ip") : undefined;
  return ipKeyGenerator(realIp && net.isIP(realIp) ? realIp : req.ip);
}

const scanRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 60, keyGenerator: clientKey,
  message: { error: "Too many requests — please try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
});

const bulkRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, keyGenerator: clientKey,
  message: { error: "Too many bulk scan requests — please try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
});

// The git commit this process is actually running. Railway sets
// RAILWAY_GIT_COMMIT_SHA on every deployment originating from a GitHub push and
// exposes it to the running container; GIT_COMMIT_SHA is a platform-neutral
// override. Neither is set locally, which is what "unknown" means — not an
// error. Read per request so tests can vary it; fixed per deployed process.
const buildCommit = () =>
  process.env.RAILWAY_GIT_COMMIT_SHA || process.env.GIT_COMMIT_SHA || "unknown";

app.get("/api/health", (req, res) => {
  const status = {};
  for (const [id, keyName] of Object.entries(ENGINE_KEYS)) {
    status[id] = keyName === null ? "active (no key needed)"
               : process.env[keyName] ? "active" : "inactive (no key set)";
  }
  // `commit` lets a post-deploy check prove the running build is the commit
  // that was just pushed. See PromptShield docs/AUTOMATION_PLAN.md.
  res.json({ status:"ok", commit:buildCommit(), engines:status, uptime:process.uptime(), cacheSize:cache.size });
});

// ── SSE Streaming Scan Endpoint ───────────────────────────────────────────────
app.get("/api/scan/stream", scanRateLimit, async (req, res) => {
  const q = sanitizeQuery(req.query.query);
  if (!q) return res.status(400).json({ error: "Invalid or missing query." });

  const qLow = q.toLowerCase();
  const type = resolveType(req.query.type, qLow);

  if (type === null)
    return res.status(400).json({ error: "Invalid type." });
  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
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

  const method     = SCAN_METHODS[type];
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
            const result = await withTimeout(id, signal => engine[method](q, signal), timeout);
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
  )];

  if (queries.length === 0)
    return res.status(400).json({ error: "No valid queries found" });

  if (queries.length > 20) {
    return res.status(400).json({
      error: `Maximum 20 queries per request (received ${queries.length})`
    });
  }

  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.flushHeaders();

  const send = (event, data) => {
    if (!res.writableEnded)
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  let clientDisconnected = false;
  req.on("close", () => { clientDisconnected = true; });

  send("start", { total: queries.length, queries });
  const results = [];

  for (let i = 0; i < queries.length; i++) {
    if (clientDisconnected) break;
    const q      = queries[i];
    const type   = detectType(q.toLowerCase());
    const method = SCAN_METHODS[type];
    send("progress", { index: i, query: q, type, status: "scanning" });

    // Input that matches no indicator type gets its own "invalid" row: no
    // engine calls, no score and no cache entry. The single-scan routes reject
    // the same input with 400; here the rest of the batch keeps running.
    if (!method) {
      const result = { index: i, query: q, type, verdict: "invalid",
        detail: "Could not detect input type.", cached: false };
      results.push(result); send("result", result); continue;
    }

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
          const engineResult = await withTimeout(id, signal => engine[method](q, signal), timeout);
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
      invalid: results.filter(r => r.verdict === "invalid").length,
      results,
    });
  }
  res.end();
});

// ── Legacy JSON endpoint ──────────────────────────────────────────────────────
app.post("/api/scan", scanRateLimit, async (req, res) => {
  // Express 5 leaves req.body undefined when no body parser matched the request;
  // Express 4 defaulted it to {}. Without the guard, a POST with no body (or a
  // non-JSON content-type) throws instead of returning the 400 below.
  const q = sanitizeQuery(req.body?.query);
  if (!q) return res.status(400).json({ error: "Invalid or missing query." });

  const qLow = q.toLowerCase();
  const type = resolveType(req.body.type, qLow);
  if (type === null)
    return res.status(400).json({ error: "Invalid type." });
  if (type === "unknown")
    return res.status(400).json({ error: "Could not detect input type." });

  const cacheKey = `${type}:${qLow}`;
  const cached   = getCached(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  const method    = SCAN_METHODS[type];

  const enginePromises = Object.entries(engines).map(async ([id, engine]) => {
    const keyName = ENGINE_KEYS[id];
    if (keyName && !process.env[keyName])
      return { id, verdict:"skipped", detail:`No API key set for ${id}` };
    const timeout = ENGINE_TIMEOUTS[id] || 10000;
    try {
      const result = await withTimeout(id, signal => engine[method](q, signal), timeout);
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

// ── Error handler ─────────────────────────────────────────────────────────────
// Express 5 forwards a rejected promise from an async handler to the error
// handling middleware; Express 4 left it as an unhandled rejection, so the
// request simply hung and nothing was ever rendered. Handler faults now reach
// the client, and Express's default handler renders the stack trace -- which on
// this app leaks absolute filesystem paths. Route them through safeError()
// instead, the same scrubbing already applied to engine failures.
//
// The headersSent branch is for the two SSE endpoints: once flushHeaders() has
// run, the response is a text/event-stream and a JSON error body cannot be
// written into it. Closing the stream is what the frontend already handles --
// EventSource.onerror surfaces "Connection error" and closes (App.jsx:534).
//
// Only err.message is logged. The whole object can carry a stack, request
// config or upstream response, none of which belongs in the host's log.
// Malformed JSON is the client's fault: a generic 400, not logged, because
// V8's JSON.parse message quotes the raw body back.

// Anything no route matched, including unknown /api paths.
app.use((req, res) => {
  res.status(404).json({ error: "Not found." });
});

// eslint-disable-next-line no-unused-vars -- Express needs the 4-arg signature
app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Malformed JSON in request body." });
  }
  if (err?.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large." });
  }
  console.error("Unhandled request error:", err instanceof Error ? err.message : String(err));
  if (res.headersSent) return res.end();
  res.status(500).json({ error: safeError(err) });
});

if (require.main === module) {
  app.listen(PORT, () =>
    console.log(`✅ ThreatScan backend running on http://localhost:${PORT}`)
  );
}

module.exports = { app, calcScore, _cache: cache };
