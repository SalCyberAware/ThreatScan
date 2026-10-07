// Production CORS. server.js reads NODE_ENV and FRONTEND_URL once at load, so
// each test loads a fresh copy of it with the env it needs.
const request = require("supertest");

const FRONTEND = "https://frontend.example";
const FOREIGN  = "https://evil.example";

const saved = { NODE_ENV: process.env.NODE_ENV, FRONTEND_URL: process.env.FRONTEND_URL };

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// An empty string rather than delete: dotenv never overrides a variable that
// is already present, so a local backend/.env cannot fill it back in.
function loadServer({ nodeEnv = "production", frontendUrl = FRONTEND } = {}) {
  process.env.NODE_ENV = nodeEnv;
  process.env.FRONTEND_URL = frontendUrl;
  let mod;
  jest.isolateModules(() => { mod = require("./server"); });
  return mod.app;
}

function preflight(app, origin) {
  return request(app)
    .options("/api/scan/stream")
    .set("Origin", origin)
    .set("Access-Control-Request-Method", "GET");
}

describe("startup", () => {
  test("refuses to start in production without FRONTEND_URL", () => {
    expect(() => loadServer({ frontendUrl: "" })).toThrow(/FRONTEND_URL must be set/);
  });

  test("starts without FRONTEND_URL outside production", () => {
    expect(() => loadServer({ nodeEnv: "development", frontendUrl: "" })).not.toThrow();
  });
});

describe("production origin allowlist", () => {
  test("allows a preflight from FRONTEND_URL", async () => {
    const res = await preflight(loadServer(), FRONTEND);
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(FRONTEND);
    expect(res.headers["access-control-allow-methods"]).toBe("GET,POST");
  });

  test("answers a GET from FRONTEND_URL", async () => {
    const res = await request(loadServer()).get("/api/health").set("Origin", FRONTEND);
    expect(res.status).toBe(200);
    expect(res.headers["access-control-allow-origin"]).toBe(FRONTEND);
  });

  test("rejects a foreign preflight with a JSON 403, not a 500", async () => {
    const res = await preflight(loadServer(), FOREIGN);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: "Origin not allowed." });
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  test.each([
    ["/api/health"],
    ["/api/scan/stream?query=example.com"],
    ["/api/scan/bulk?queries=example.com"],
  ])("rejects a foreign GET %s with 403 before the route runs", async (path) => {
    const res = await request(loadServer()).get(path).set("Origin", FOREIGN);
    expect(res.status).toBe(403);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  test("does not log a rejected origin as a server error", async () => {
    const spy = jest.spyOn(console, "error").mockImplementation(() => {});
    try {
      await request(loadServer()).get("/api/health").set("Origin", FOREIGN);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  test("lets requests with no Origin through (health checks, curl)", async () => {
    const res = await request(loadServer()).get("/api/health");
    expect(res.status).toBe(200);
  });

  test("matches FRONTEND_URL set with a trailing slash", async () => {
    const res = await preflight(loadServer({ frontendUrl: `${FRONTEND}/` }), FRONTEND);
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(FRONTEND);
  });
});
