jest.mock("./engines/abuseipdb",    () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/greynoise",    () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/ipinfo",       () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/malwarebazaar",() => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/otx",          () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/safebrowsing", () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/threatfox",    () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/urlhaus",      () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/urlscan",      () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/virustotal",   () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));
jest.mock("./engines/whois",        () => ({ scanUrl: jest.fn(), scanIp: jest.fn(), scanHash: jest.fn(), scanDomain: jest.fn() }));

const request = require("supertest");

const ENGINE_NAMES = [
  "abuseipdb", "greynoise", "ipinfo", "malwarebazaar", "otx",
  "safebrowsing", "threatfox", "urlhaus", "urlscan", "virustotal", "whois",
];

const KEY_ENV_VARS = [
  "VT_API_KEY", "ABUSEIPDB_KEY", "URLSCAN_KEY", "MALWAREBAZAAR_KEY",
  "OTX_KEY", "GREYNOISE_KEY", "IPINFO_KEY", "GSB_KEY",
];

const savedEnv = {};
for (const k of KEY_ENV_VARS) {
  savedEnv[k] = process.env[k];
  process.env[k] = "test-key";
}

const { app, calcScore, _cache: cache } = require("./server");
const engines = Object.fromEntries(
  ENGINE_NAMES.map(name => [name, require(`./engines/${name}`)])
);

afterAll(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function resetEngines(defaultResult = { verdict: "clean" }) {
  for (const name of ENGINE_NAMES) {
    for (const method of ["scanUrl", "scanIp", "scanHash", "scanDomain"]) {
      engines[name][method].mockReset();
      engines[name][method].mockResolvedValue(defaultResult);
    }
  }
}

function parseSSE(text) {
  return text
    .split("\n\n")
    .map(block => block.trim())
    .filter(Boolean)
    .map(block => {
      let event = "message";
      let data = null;
      for (const line of block.split("\n")) {
        if (line.startsWith("event: ")) event = line.slice(7);
        else if (line.startsWith("data: ")) data = JSON.parse(line.slice(6));
      }
      return { event, data };
    });
}

beforeEach(() => {
  cache.clear();
  resetEngines();
  for (const k of KEY_ENV_VARS) process.env[k] = "test-key";
});

describe("POST /api/scan — input validation", () => {
  test("returns 400 when the query field is missing", async () => {
    const res = await request(app).post("/api/scan").send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid|missing/i);
  });

  test("returns 400 when the query is an empty string", async () => {
    const res = await request(app).post("/api/scan").send({ query: "" });
    expect(res.status).toBe(400);
  });

  test("returns 400 when the query exceeds the 2048-character limit", async () => {
    const res = await request(app).post("/api/scan").send({ query: "a".repeat(2049) });
    expect(res.status).toBe(400);
  });

  test("returns 400 when the type cannot be detected from the query", async () => {
    const res = await request(app).post("/api/scan").send({ query: "definitely-not-an-indicator" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/detect/i);
  });
});

describe("POST /api/scan — happy paths per detected type", () => {
  test("URL query calls every engine's scanUrl method", async () => {
    const res = await request(app).post("/api/scan").send({ query: "https://example.com" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("url");
    expect(res.body.engines).toHaveLength(11);
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanUrl).toHaveBeenCalledWith("https://example.com", expect.any(AbortSignal));
    }
  });

  test("IP query calls every engine's scanIp method", async () => {
    const res = await request(app).post("/api/scan").send({ query: "8.8.8.8" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("ip");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanIp).toHaveBeenCalledWith("8.8.8.8", expect.any(AbortSignal));
    }
  });

  test("Hash query calls every engine's scanHash method", async () => {
    const hash = "a".repeat(64);
    const res = await request(app).post("/api/scan").send({ query: hash });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("hash");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanHash).toHaveBeenCalledWith(hash, expect.any(AbortSignal));
    }
  });

  test("Domain query calls every engine's scanDomain method", async () => {
    const res = await request(app).post("/api/scan").send({ query: "example.com" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("domain");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanDomain).toHaveBeenCalledWith("example.com", expect.any(AbortSignal));
    }
  });
});

describe("POST /api/scan — cache behaviour", () => {
  test("a second identical request is served from cache without re-calling engines", async () => {
    const first = await request(app).post("/api/scan").send({ query: "https://example.com" });
    expect(first.body.cached).toBe(false);
    const callCount = engines.virustotal.scanUrl.mock.calls.length;
    expect(callCount).toBe(1);

    const second = await request(app).post("/api/scan").send({ query: "https://example.com" });
    expect(second.status).toBe(200);
    expect(second.body.cached).toBe(true);
    expect(engines.virustotal.scanUrl.mock.calls.length).toBe(callCount);
  });
});

describe("POST /api/scan — skipped engines when API key is absent", () => {
  test("virustotal returns verdict:'skipped' when VT_API_KEY is unset", async () => {
    delete process.env.VT_API_KEY;
    const res = await request(app).post("/api/scan").send({ query: "https://example.com" });
    const vt = res.body.engines.find(e => e.id === "virustotal");
    expect(vt.verdict).toBe("skipped");
    expect(engines.virustotal.scanUrl).not.toHaveBeenCalled();
  });
});

describe("POST /api/scan: abuse.ch engines without the shared key", () => {
  test("URLhaus and ThreatFox are skipped, not called, when MALWAREBAZAAR_KEY is unset", async () => {
    delete process.env.MALWAREBAZAAR_KEY;
    const res = await request(app).post("/api/scan").send({ query: "https://example.com" });
    for (const id of ["urlhaus", "threatfox"]) {
      const r = res.body.engines.find(e => e.id === id);
      expect(r.verdict).toBe("skipped");
      expect(engines[id].scanUrl).not.toHaveBeenCalled();
    }
  });
});

describe("POST /api/scan — score aggregation", () => {
  test("every engine malicious → score capped at 100, verdict 'malicious'", async () => {
    for (const name of ENGINE_NAMES) {
      engines[name].scanUrl.mockResolvedValue({ verdict: "malicious" });
    }
    const res = await request(app).post("/api/scan").send({ query: "https://example.com" });
    expect(res.body.score).toBe(100);
    expect(res.body.verdict).toBe("malicious");
    expect(res.body.malicious).toBeGreaterThan(0);
  });

  test("every engine clean → score 0, verdict 'clean'", async () => {
    const res = await request(app).post("/api/scan").send({ query: "https://example.com" });
    expect(res.body.score).toBe(0);
    expect(res.body.verdict).toBe("clean");
  });
});

describe("GET /api/health", () => {
  test("returns 200 with the expected payload shape", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(typeof res.body.engines).toBe("object");
    expect(typeof res.body.uptime).toBe("number");
    expect(res.body.uptime).toBeGreaterThan(0);
    expect(typeof res.body.cacheSize).toBe("number");
  });

  test("reports the Node major version only", async () => {
    const res = await request(app).get("/api/health");
    expect(res.body.node).toBe(process.versions.node.split(".")[0]);
    expect(res.body.node).toMatch(/^\d+$/);
  });

  test("per-engine status reflects API key presence", async () => {
    process.env.VT_API_KEY = "set";
    delete process.env.ABUSEIPDB_KEY;
    const res = await request(app).get("/api/health");
    expect(res.body.engines.virustotal).toBe("active");
    expect(res.body.engines.abuseipdb).toMatch(/inactive/);
    expect(res.body.engines.whois).toMatch(/no key/i);
  });

  test("URLhaus and ThreatFox report the shared abuse.ch key's status", async () => {
    process.env.MALWAREBAZAAR_KEY = "set";
    let res = await request(app).get("/api/health");
    expect(res.body.engines.urlhaus).toBe("active");
    expect(res.body.engines.threatfox).toBe("active");

    delete process.env.MALWAREBAZAAR_KEY;
    res = await request(app).get("/api/health");
    expect(res.body.engines.urlhaus).toMatch(/inactive/);
    expect(res.body.engines.threatfox).toMatch(/inactive/);
    expect(res.body.engines.malwarebazaar).toMatch(/inactive/);
  });

  test("cacheSize reflects actual cache state after a scan", async () => {
    const before = await request(app).get("/api/health");
    expect(before.body.cacheSize).toBe(0);
    await request(app).post("/api/scan").send({ query: "https://example.com" });
    const after = await request(app).get("/api/health");
    expect(after.body.cacheSize).toBe(1);
  });

  describe("build identity", () => {
    afterEach(() => {
      delete process.env.RAILWAY_GIT_COMMIT_SHA;
      delete process.env.GIT_COMMIT_SHA;
    });

    test("reports unknown when no platform variable is set", async () => {
      delete process.env.RAILWAY_GIT_COMMIT_SHA;
      delete process.env.GIT_COMMIT_SHA;
      const res = await request(app).get("/api/health");
      expect(res.body.commit).toBe("unknown");
    });

    test("reports the Railway commit SHA verbatim", async () => {
      process.env.RAILWAY_GIT_COMMIT_SHA = "a".repeat(40);
      const res = await request(app).get("/api/health");
      expect(res.body.commit).toBe("a".repeat(40));
    });

    test("falls back to GIT_COMMIT_SHA, but Railway's wins", async () => {
      process.env.GIT_COMMIT_SHA = "b".repeat(40);
      let res = await request(app).get("/api/health");
      expect(res.body.commit).toBe("b".repeat(40));

      process.env.RAILWAY_GIT_COMMIT_SHA = "c".repeat(40);
      res = await request(app).get("/api/health");
      expect(res.body.commit).toBe("c".repeat(40));
    });

    test("existing health fields survive alongside commit", async () => {
      // The uptime monitor reads these, so adding commit and node must stay additive.
      const res = await request(app).get("/api/health");
      expect(Object.keys(res.body).sort())
        .toEqual(["cacheSize", "commit", "engines", "node", "status", "uptime"]);
    });
  });
});

describe("calcScore", () => {
  test("returns 0 when every engine is clean", () => {
    expect(calcScore([
      { id: "virustotal", verdict: "clean" },
      { id: "urlhaus",    verdict: "clean" },
    ])).toBe(0);
  });

  test("returns 100 (capped) when every engine is malicious", () => {
    const results = ENGINE_NAMES.map(id => ({ id, verdict: "malicious" }));
    expect(calcScore(results)).toBe(100);
  });

  test("mixed verdicts produce the weighted-ratio score", () => {
    // VT (w=5) malicious + urlhaus (w=3) clean → 5/8 * 100 = 62.5 → 63
    expect(calcScore([
      { id: "virustotal", verdict: "malicious" },
      { id: "urlhaus",    verdict: "clean"     },
    ])).toBe(63);
  });

  test("returns 0 when every result is skipped/error/info (totalWeight = 0)", () => {
    expect(calcScore([
      { id: "virustotal", verdict: "skipped" },
      { id: "urlhaus",    verdict: "error"   },
      { id: "otx",        verdict: "info"    },
    ])).toBe(0);
  });

  test("yields exactly 50 at the malicious-threshold boundary", () => {
    // VT (5) malicious vs greynoise (2) + threatfox (2) + ipinfo (1) clean → 5/10 = 50
    expect(calcScore([
      { id: "virustotal", verdict: "malicious" },
      { id: "greynoise",  verdict: "clean"     },
      { id: "threatfox",  verdict: "clean"     },
      { id: "ipinfo",     verdict: "clean"     },
    ])).toBe(50);
  });
});

describe("GET /api/scan/stream — validation", () => {
  test("returns 400 when the query parameter is missing", async () => {
    const res = await request(app).get("/api/scan/stream");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid|missing/i);
  });

  test("returns 400 (before opening the stream) when the type cannot be detected", async () => {
    const res = await request(app).get("/api/scan/stream").query({ query: "not-an-indicator" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/detect/i);
  });
});

describe("GET /api/scan/stream — event sequence", () => {
  test("emits start → 11 engine events → done in that order", async () => {
    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    expect(res.status).toBe(200);

    const events = parseSSE(res.text);
    expect(events[0].event).toBe("start");
    expect(events[0].data).toMatchObject({
      query: "https://example.com",
      type: "url",
      total: 11,
      cached: false,
    });

    const engineEvents = events.filter(e => e.event === "engine");
    expect(engineEvents).toHaveLength(11);
    const ids = engineEvents.map(e => e.data.id);
    expect(new Set(ids)).toEqual(new Set(ENGINE_NAMES));

    const last = events[events.length - 1];
    expect(last.event).toBe("done");
  });

  test("each engine event carries an id and a verdict", async () => {
    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    const engineEvents = parseSSE(res.text).filter(e => e.event === "engine");
    for (const e of engineEvents) {
      expect(typeof e.data.id).toBe("string");
      expect(typeof e.data.verdict).toBe("string");
    }
  });

  test("done event payload includes verdict, score, counts, and scannedAt", async () => {
    for (const name of ENGINE_NAMES) {
      engines[name].scanUrl.mockResolvedValue({ verdict: "malicious" });
    }
    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    const doneEvent = parseSSE(res.text).find(e => e.event === "done");
    expect(doneEvent.data).toMatchObject({
      verdict: "malicious",
      score: 100,
      malicious: expect.any(Number),
      suspicious: expect.any(Number),
      clean: expect.any(Number),
      cached: false,
      scannedAt: expect.any(String),
    });
  });
});

describe("GET /api/scan/stream — cache replay", () => {
  test("second identical request replays from cache without re-calling engines", async () => {
    await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    const callCount = engines.virustotal.scanUrl.mock.calls.length;
    expect(callCount).toBe(1);

    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    const events = parseSSE(res.text);
    expect(events[0].data.cached).toBe(true);
    const doneEvent = events.find(e => e.event === "done");
    expect(doneEvent.data.cached).toBe(true);
    expect(events.filter(e => e.event === "engine")).toHaveLength(11);
    expect(engines.virustotal.scanUrl.mock.calls.length).toBe(callCount);
  });
});

describe("GET /api/scan/stream — engine error handling", () => {
  test("a rejecting engine produces an 'error' event; the stream still completes", async () => {
    engines.virustotal.scanUrl.mockRejectedValue(new Error("VT API down"));
    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });

    const events = parseSSE(res.text);
    const vtEvent = events.find(e => e.event === "engine" && e.data.id === "virustotal");
    expect(vtEvent.data.verdict).toBe("error");
    expect(typeof vtEvent.data.detail).toBe("string");

    const doneEvent = events.find(e => e.event === "done");
    expect(doneEvent).toBeDefined();
    expect(events.filter(e => e.event === "engine")).toHaveLength(11);
  });
});

// NOTE: the 30s GLOBAL_SCAN_TIMEOUT path is not exercised here.
// Driving fake timers through a flushed SSE response under supertest is flaky;
// the bail-out branch (lines 236-239 in server.js) is left for a dedicated unit test.

describe("GET /api/scan/bulk — validation", () => {
  test("returns 400 when the queries parameter is missing", async () => {
    const res = await request(app).get("/api/scan/bulk");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/queries parameter required/i);
  });

  test("returns 400 when no valid queries can be parsed from the input", async () => {
    const res = await request(app).get("/api/scan/bulk").query({ queries: ",,," });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/no valid queries/i);
  });
});

describe("GET /api/scan/bulk — event sequence", () => {
  test("emits start → progress+result per query → done", async () => {
    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com,b.com,c.com" });
    expect(res.status).toBe(200);

    const events = parseSSE(res.text);
    expect(events[0].event).toBe("start");
    expect(events[0].data).toEqual({ total: 3, queries: ["a.com", "b.com", "c.com"] });

    const progressEvents = events.filter(e => e.event === "progress");
    const resultEvents   = events.filter(e => e.event === "result");
    expect(progressEvents).toHaveLength(3);
    expect(resultEvents).toHaveLength(3);

    const doneEvent = events[events.length - 1];
    expect(doneEvent.event).toBe("done");
    expect(doneEvent.data.total).toBe(3);
    expect(doneEvent.data.results).toHaveLength(3);
  });

  test("each result event carries query, type, verdict, and score", async () => {
    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com" });
    const result = parseSSE(res.text).find(e => e.event === "result");
    expect(result.data).toMatchObject({
      index: 0,
      query: "a.com",
      type: "domain",
      verdict: expect.any(String),
      score: expect.any(Number),
    });
  });
});

describe("GET /api/scan/bulk — query parsing", () => {
  test("duplicate queries are de-duplicated before scanning", async () => {
    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com,a.com,b.com" });
    const events = parseSSE(res.text);
    expect(events[0].data.total).toBe(2);
    expect(events[0].data.queries).toEqual(["a.com", "b.com"]);
    expect(events.filter(e => e.event === "result")).toHaveLength(2);
  });

  test("returns 400 when more than 20 queries are submitted", async () => {
    const queries = Array.from({ length: 21 }, (_, i) => `q${i}.example`).join(",");
    const res = await request(app).get("/api/scan/bulk").query({ queries });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/maximum 20.*received 21/i);
  });
});

// Issue #31: detectType returns the truthy string "unknown", so the old
// `|| "domain"` fallback never fired. Every engine was called with an undefined
// method, all of them errored, calcScore returned 0 and the row was reported
// (and cached) as "clean" for input no engine ever looked at.
describe("GET /api/scan/bulk, undetectable input", () => {
  // Each request comes from its own client address so these tests do not spend
  // the bulk rate-limit budget (10 per 15 minutes) the later bulk tests rely on.
  let client = 0;
  const bulk = queries => request(app).get("/api/scan/bulk")
    .set("X-Forwarded-For", `198.51.100.${100 + client++}`).query({ queries });
  const allMethodCalls = () => ENGINE_NAMES.reduce((n, name) =>
    n + ["scanUrl","scanIp","scanHash","scanDomain"]
      .reduce((m, method) => m + engines[name][method].mock.calls.length, 0), 0);

  test.each(["=1+1", "@SUM(1)", "localhost"])(
    "%s yields an 'invalid' row with no score, no engine calls and no cache entry",
    async (query) => {
      const res = await bulk(query);
      expect(res.status).toBe(200);

      const result = parseSSE(res.text).find(e => e.event === "result");
      expect(result.data).toEqual({
        index: 0, query, type: "unknown", verdict: "invalid",
        detail: "Could not detect input type.", cached: false,
      });
      expect(result.data).not.toHaveProperty("score");
      expect(allMethodCalls()).toBe(0);
      expect(cache.size).toBe(0);
    }
  );

  test("invalid rows sit beside scanned ones and are tallied apart from clean", async () => {
    const res = await bulk("=1+1\n@SUM(1)\nlocalhost\nexample.com");
    const events  = parseSSE(res.text);
    const results = events.filter(e => e.event === "result").map(e => e.data);

    expect(results.map(r => r.verdict)).toEqual(["invalid", "invalid", "invalid", "clean"]);
    expect(results[3]).toMatchObject({ query: "example.com", type: "domain", score: expect.any(Number) });
    expect(engines.virustotal.scanDomain).toHaveBeenCalledTimes(1);
    expect(engines.virustotal.scanDomain).toHaveBeenCalledWith("example.com", expect.any(AbortSignal));

    const done = events.find(e => e.event === "done").data;
    expect(done).toMatchObject({ total: 4, malicious: 0, suspicious: 0, clean: 1, invalid: 3 });
    expect([...cache.keys()]).toEqual(["domain:example.com"]);
  });
});

// Production CORS (FRONTEND_URL only, 403 otherwise) is read at module load, so
// it is covered in cors.test.js, which loads server.js with that env. This
// suite runs outside production, where any origin is reflected.
describe("CORS on the SSE routes (outside production)", () => {
  beforeEach(() => { cache.clear(); resetEngines(); });

  // Both routes used to overwrite the cors header by hand with a fixed origin,
  // so a request from any other origin was answered for the wrong one.
  test("/api/scan/stream answers for the requesting origin", async () => {
    const res = await request(app)
      .get("/api/scan/stream?query=example.com")
      .set("Origin", "http://localhost:3000");
    expect(res.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
  });

  test("/api/scan/bulk answers for the requesting origin", async () => {
    const res = await request(app)
      .get("/api/scan/bulk?queries=example.com")
      .set("Origin", "http://localhost:3000");
    expect(res.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
  });
});

describe("GET /api/scan/stream — skipped engine when API key is absent", () => {
  test("missing VT_API_KEY emits a 'skipped' engine event and does not call the engine", async () => {
    delete process.env.VT_API_KEY;
    const res = await request(app).get("/api/scan/stream").query({ query: "https://example.com" });
    const vt = parseSSE(res.text).find(e => e.event === "engine" && e.data.id === "virustotal");
    expect(vt.data.verdict).toBe("skipped");
    expect(vt.data.detail).toMatch(/no api key/i);
    expect(engines.virustotal.scanUrl).not.toHaveBeenCalled();
  });
});

describe("GET /api/scan/bulk — per-engine outcomes captured in cache", () => {
  test("missing API key marks that engine 'skipped' for the bulk query", async () => {
    delete process.env.VT_API_KEY;
    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com" });
    expect(res.status).toBe(200);

    const cachedEngines = cache.get("domain:a.com").data.engines;
    const vt = cachedEngines.find(e => e.id === "virustotal");
    expect(vt.verdict).toBe("skipped");
    expect(engines.virustotal.scanDomain).not.toHaveBeenCalled();
  });

  test("a rejecting engine yields verdict 'error' for that engine in the bulk cache", async () => {
    engines.virustotal.scanDomain.mockRejectedValue(new Error("boom"));
    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com" });
    expect(res.status).toBe(200);

    const events = parseSSE(res.text);
    expect(events.find(e => e.event === "result")).toBeDefined();
    expect(events.find(e => e.event === "done")).toBeDefined();

    const cachedEngines = cache.get("domain:a.com").data.engines;
    const vt = cachedEngines.find(e => e.id === "virustotal");
    expect(vt.verdict).toBe("error");
    expect(vt.detail).toMatch(/boom/i);
  });
});

describe("GET /api/scan/bulk — cache reuse mid-batch", () => {
  test("a query primed in the cache is replayed (cached: true), others are scanned", async () => {
    await request(app).post("/api/scan").send({ query: "a.com" });
    const callCount = engines.virustotal.scanDomain.mock.calls.length;
    expect(callCount).toBe(1);

    const res = await request(app).get("/api/scan/bulk").query({ queries: "a.com,b.com" });
    const resultEvents = parseSSE(res.text).filter(e => e.event === "result");

    const a = resultEvents.find(r => r.data.query === "a.com");
    const b = resultEvents.find(r => r.data.query === "b.com");
    expect(a.data.cached).toBe(true);
    expect(b.data.cached).toBe(false);
    expect(engines.virustotal.scanDomain.mock.calls.length).toBe(callCount + 1);
    expect(engines.virustotal.scanDomain).toHaveBeenLastCalledWith("b.com", expect.any(AbortSignal));
  });
});

// ── Express 5 migration regressions ───────────────────────────────────────────
// Express 5 leaves req.body undefined when no body parser matched, where
// Express 4 defaulted it to {}. Unguarded, `req.body.query` threw a TypeError,
// which Express 5 (unlike 4) forwards to the error handler — turning what had
// been a clean 400 into a 500 whose default body rendered the stack trace and
// the server's absolute filesystem paths. These pin the 400 back down.
describe("POST /api/scan — requests that carry no parsed body", () => {
  test("returns 400 when the request has no body at all", async () => {
    const res = await request(app).post("/api/scan");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid|missing/i);
  });

  test("returns 400 when the content-type is not JSON", async () => {
    const res = await request(app)
      .post("/api/scan")
      .set("Content-Type", "text/plain")
      .send("query=example.com");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid|missing/i);
  });

  test("does not leak a stack trace or filesystem path on a bodyless POST", async () => {
    const res = await request(app).post("/api/scan");
    expect(res.text).not.toMatch(/TypeError|at Layer|node_modules/);
    expect(res.text).not.toMatch(/[A-Za-z]:\|\/home\/|\/Users\//);
  });
});

describe("error handler", () => {
  // Express 5 routes rejected promises from async handlers here. The response
  // must be scrubbed JSON, not Express's default stack-trace page.
  let errorSpy;

  beforeEach(() => {
    cache.clear();
    resetEngines();
    errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    cache.clear();
    errorSpy.mockRestore();
  });

  // A BigInt in an engine result makes res.json() throw inside the handler,
  // which is a genuine handler fault that Express forwards here.
  async function triggerHandlerFault() {
    engines.whois.scanDomain.mockResolvedValue({ verdict: "info", size: 1n });
    return request(app).post("/api/scan").send({ query: "example.com" });
  }

  test("renders a JSON error body rather than Express's HTML stack page", async () => {
    const res = await triggerHandlerFault();
    expect(res.status).toBe(500);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(typeof res.body.error).toBe("string");
    expect(res.text).not.toMatch(/<!DOCTYPE html>|at Layer/);
  });

  test("logs only the error message, never the error object", async () => {
    await triggerHandlerFault();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    const args = errorSpy.mock.calls[0];
    expect(args).toHaveLength(2);
    expect(typeof args[1]).toBe("string");
    expect(args[1]).toMatch(/BigInt/);
    expect(args.join(" ")).not.toMatch(/\n\s+at /);
  });

  test("malformed JSON gets a generic 400 that does not echo the body", async () => {
    const res = await request(app)
      .post("/api/scan")
      .set("Content-Type", "application/json")
      .send('{"query": "secret-looking-input');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "Malformed JSON in request body." });
    expect(res.text).not.toMatch(/secret-looking-input/);
    expect(errorSpy).not.toHaveBeenCalled();
  });

  test("a body over the 10kb limit gets a 413, not a 500", async () => {
    const res = await request(app)
      .post("/api/scan")
      .set("Content-Type", "application/json")
      .send(JSON.stringify({ query: "a".repeat(11 * 1024) }));
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ error: "Request body too large." });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  test.each([
    ["GET",  "/api/does-not-exist"],
    ["POST", "/api/health"],
    ["GET",  "/"],
  ])("%s %s returns a JSON 404", async (method, path) => {
    const res = await request(app)[method.toLowerCase()](path);
    expect(res.status).toBe(404);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.body).toEqual({ error: "Not found." });
  });
});

describe("type allowlist", () => {
  const REJECTED = ["__proto__", "constructor", "toString", "scanUrl", "URL", "file", "unknown"];

  test.each(REJECTED)("GET /api/scan/stream rejects type=%s with 400 before opening the stream", async (type) => {
    const res = await request(app).get("/api/scan/stream").query({ query: "8.8.8.8", type });
    expect(res.status).toBe(400);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.body.error).toMatch(/invalid type/i);
    for (const name of ENGINE_NAMES) expect(engines[name].scanIp).not.toHaveBeenCalled();
  });

  test("GET /api/scan/stream rejects a repeated type parameter (array)", async () => {
    const res = await request(app).get("/api/scan/stream?query=8.8.8.8&type=ip&type=url");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid type/i);
  });

  test.each([...REJECTED, 1, ["ip"], { a: 1 }, null])(
    "POST /api/scan rejects type=%p with 400", async (type) => {
      const res = await request(app).post("/api/scan").send({ query: "8.8.8.8", type });
      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/invalid type/i);
      for (const name of ENGINE_NAMES) expect(engines[name].scanIp).not.toHaveBeenCalled();
    });

  test("an allowed explicit type overrides detection", async () => {
    const res = await request(app).post("/api/scan").send({ query: "example.com", type: "url" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("url");
    expect(engines.virustotal.scanUrl).toHaveBeenCalledWith("example.com", expect.any(AbortSignal));
  });

  test.each(["auto", ""])("type=%p falls back to server-side detection", async (type) => {
    const res = await request(app).get("/api/scan/stream").query({ query: "8.8.8.8", type });
    expect(res.status).toBe(200);
    expect(parseSSE(res.text)[0].data.type).toBe("ip");
  });

  test("type=auto with an undetectable query still gets the detection 400", async () => {
    const res = await request(app).post("/api/scan").send({ query: "not-an-indicator", type: "auto" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/detect/i);
  });
});

describe("per-engine timeout cancels the upstream request", () => {
  // ipinfo has the shortest per-engine budget (4s). Real timers: see the note
  // above about fake timers under supertest.
  test("the engine's AbortSignal is aborted when its timeout fires", async () => {
    let seen;
    engines.ipinfo.scanIp.mockImplementation((_q, signal) => {
      seen = signal;
      return new Promise(() => {});
    });
    const res = await request(app).post("/api/scan").send({ query: "8.8.8.8" });
    expect(res.status).toBe(200);
    expect(res.body.engines.find(e => e.id === "ipinfo"))
      .toMatchObject({ verdict: "error", detail: "ipinfo timeout" });
    expect(seen).toBeInstanceOf(AbortSignal);
    expect(seen.aborted).toBe(true);
  }, 10000);

  test("engines that finish in time are not aborted", async () => {
    const signals = [];
    engines.virustotal.scanIp.mockImplementation(async (_q, signal) => {
      signals.push(signal);
      return { verdict: "clean" };
    });
    await request(app).get("/api/scan/stream").query({ query: "8.8.8.8" });
    expect(signals).toHaveLength(1);
    expect(signals[0].aborted).toBe(false);
  });
});
