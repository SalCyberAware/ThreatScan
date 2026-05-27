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
      expect(engines[name].scanUrl).toHaveBeenCalledWith("https://example.com");
    }
  });

  test("IP query calls every engine's scanIp method", async () => {
    const res = await request(app).post("/api/scan").send({ query: "8.8.8.8" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("ip");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanIp).toHaveBeenCalledWith("8.8.8.8");
    }
  });

  test("Hash query calls every engine's scanHash method", async () => {
    const hash = "a".repeat(64);
    const res = await request(app).post("/api/scan").send({ query: hash });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("hash");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanHash).toHaveBeenCalledWith(hash);
    }
  });

  test("Domain query calls every engine's scanDomain method", async () => {
    const res = await request(app).post("/api/scan").send({ query: "example.com" });
    expect(res.status).toBe(200);
    expect(res.body.type).toBe("domain");
    for (const name of ENGINE_NAMES) {
      expect(engines[name].scanDomain).toHaveBeenCalledWith("example.com");
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

  test("per-engine status reflects API key presence", async () => {
    process.env.VT_API_KEY = "set";
    delete process.env.ABUSEIPDB_KEY;
    const res = await request(app).get("/api/health");
    expect(res.body.engines.virustotal).toBe("active");
    expect(res.body.engines.abuseipdb).toMatch(/inactive/);
    expect(res.body.engines.urlhaus).toMatch(/no key/i);
  });

  test("cacheSize reflects actual cache state after a scan", async () => {
    const before = await request(app).get("/api/health");
    expect(before.body.cacheSize).toBe(0);
    await request(app).post("/api/scan").send({ query: "https://example.com" });
    const after = await request(app).get("/api/health");
    expect(after.body.cacheSize).toBe(1);
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
    expect(engines.virustotal.scanDomain).toHaveBeenLastCalledWith("b.com");
  });
});
