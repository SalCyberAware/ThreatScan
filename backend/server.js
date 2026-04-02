// ── ADD THIS to backend/server.js ────────────────────────────────────────────
// Paste this block BEFORE the app.listen() line at the bottom of server.js
//
// Bulk scan endpoint — accepts up to 20 queries, scans each one sequentially,
// streams progress as SSE events. No extra dependencies needed.
// ─────────────────────────────────────────────────────────────────────────────

app.get("/api/scan/bulk", async (req, res) => {
  const { queries: rawQueries } = req.query;

  if (!rawQueries) {
    return res.status(400).json({ error: "queries parameter required" });
  }

  // Parse newline or comma separated list, dedupe, limit to 20
  const queries = [...new Set(
    rawQueries.split(/[\n,]+/)
      .map(q => q.trim())
      .filter(q => q.length > 0)
  )].slice(0, 20);

  if (queries.length === 0) {
    return res.status(400).json({ error: "No valid queries found" });
  }

  // SSE headers
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders();

  const send = (event, data) =>
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  const methodMap = { url:"scanUrl", ip:"scanIp", hash:"scanHash", domain:"scanDomain" };

  send("start", { total: queries.length, queries });

  const results = [];

  for (let i = 0; i < queries.length; i++) {
    const q    = queries[i];
    const type = detectType(q.toLowerCase()) || "domain";
    const method = methodMap[type];

    send("progress", { index: i, query: q, type, status: "scanning" });

    // Check cache first
    const cacheKey = `${type}:${q.toLowerCase()}`;
    const cached   = getCached(cacheKey);

    if (cached) {
      const result = {
        index: i, query: q, type,
        verdict:    cached.verdict,
        score:      cached.score,
        malicious:  cached.malicious,
        suspicious: cached.suspicious,
        clean:      cached.clean,
        cached:     true,
      };
      results.push(result);
      send("result", result);
      continue;
    }

    // Run all engines for this query
    const engineList = Object.entries(engines);
    const allResults = [];

    await Promise.allSettled(
      engineList.map(async ([id, engine]) => {
        const keyName = ENGINE_KEYS[id];
        if (keyName && !process.env[keyName]) {
          allResults.push({ id, verdict:"skipped" });
          return;
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
          allResults.push({ id, verdict:"error", detail: err.message });
        }
      })
    );

    const score        = calcScore(allResults);
    const active       = allResults.filter(r => !["skipped","error","info"].includes(r.verdict));
    const malCount     = active.filter(r => r.verdict === "malicious").length;
    const suspCount    = active.filter(r => r.verdict === "suspicious").length;
    const finalVerdict = score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean";

    const summary = {
      verdict: finalVerdict, score,
      malicious: malCount, suspicious: suspCount,
      clean: active.filter(r => r.verdict === "clean").length,
      scannedAt: new Date().toISOString(),
    };

    // Cache it
    setCache(cacheKey, { query: q, type, engines: allResults, ...summary });

    const result = { index: i, query: q, type, cached: false, ...summary };
    results.push(result);
    send("result", result);
  }

  // Final summary
  const totalMal  = results.filter(r => r.verdict === "malicious").length;
  const totalSusp = results.filter(r => r.verdict === "suspicious").length;
  const totalClean = results.filter(r => r.verdict === "clean").length;

  send("done", {
    total: queries.length,
    malicious: totalMal,
    suspicious: totalSusp,
    clean: totalClean,
    results,
  });

  res.end();
});
