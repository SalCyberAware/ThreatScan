// Rate-limit regression cover for server.js.
//
// Kept in its own file because the limiters are module-level in-memory stores:
// Jest gives each test file a fresh module registry, so the counters here start
// at zero and nothing in server.test.js can push them over (or be pushed over).
// Each test uses its own client IP via X-Forwarded-For so tests never share a
// bucket.
//
// Every request here is rejected by input validation (400) before any engine is
// reached. The limiter runs before the handler and counts the request either
// way, which is the behaviour being pinned: a client cannot dodge the limit by
// sending bad input.

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
const { app } = require("./server");

const WINDOW_SECONDS = 15 * 60;
const SCAN_LIMIT = 60;
const BULK_LIMIT = 10;
// The messages contain an em dash; spelled as an escape so the test file stays
// plain ASCII while still asserting the exact body clients receive.
const SCAN_MESSAGE = "Too many requests — please try again in 15 minutes.";
const BULK_MESSAGE = "Too many bulk scan requests — please try again in 15 minutes.";

const scan = ip =>
  request(app).post("/api/scan").set("X-Forwarded-For", ip).send({});
const stream = ip =>
  request(app).get("/api/scan/stream").set("X-Forwarded-For", ip);
const bulk = ip =>
  request(app).get("/api/scan/bulk").set("X-Forwarded-For", ip);

async function exhaust(send, ip, n) {
  for (let i = 0; i < n; i++) {
    const res = await send(ip);
    if (res.status === 429) throw new Error(`limited early, on request ${i + 1}`);
  }
}

function expectStandardHeaders(res, limit) {
  expect(res.headers["ratelimit-limit"]).toBe(String(limit));
  expect(res.headers["ratelimit-policy"]).toBe(`${limit};w=${WINDOW_SECONDS}`);
  const reset = Number(res.headers["ratelimit-reset"]);
  expect(reset).toBeGreaterThan(0);
  expect(reset).toBeLessThanOrEqual(WINDOW_SECONDS);
  // legacyHeaders: false
  expect(res.headers["x-ratelimit-limit"]).toBeUndefined();
  expect(res.headers["x-ratelimit-remaining"]).toBeUndefined();
}

function expect429(res, limit, message) {
  expect(res.status).toBe(429);
  expect(res.headers["content-type"]).toMatch(/^application\/json/);
  expect(res.body).toEqual({ error: message });
  expectStandardHeaders(res, limit);
  expect(res.headers["ratelimit-remaining"]).toBe("0");
  const retryAfter = Number(res.headers["retry-after"]);
  expect(retryAfter).toBeGreaterThan(0);
  expect(retryAfter).toBeLessThanOrEqual(WINDOW_SECONDS);
}

describe("scan rate limit (60 per 15 minutes)", () => {
  test("counts down from 60 with standard RateLimit headers", async () => {
    const first = await scan("198.51.100.1");
    expect(first.status).toBe(400);
    expectStandardHeaders(first, SCAN_LIMIT);
    expect(first.headers["ratelimit-remaining"]).toBe(String(SCAN_LIMIT - 1));
    expect(first.headers["retry-after"]).toBeUndefined();

    const second = await scan("198.51.100.1");
    expect(second.headers["ratelimit-remaining"]).toBe(String(SCAN_LIMIT - 2));
  });

  test("allows the 60th request and returns 429 with the JSON body on the 61st", async () => {
    await exhaust(scan, "198.51.100.2", SCAN_LIMIT - 1);
    const last = await scan("198.51.100.2");
    expect(last.status).toBe(400);
    expect(last.headers["ratelimit-remaining"]).toBe("0");

    expect429(await scan("198.51.100.2"), SCAN_LIMIT, SCAN_MESSAGE);
  });

  test("POST /api/scan and GET /api/scan/stream share one budget", async () => {
    await exhaust(scan, "198.51.100.3", SCAN_LIMIT / 2);
    await exhaust(stream, "198.51.100.3", SCAN_LIMIT / 2);
    expect429(await stream("198.51.100.3"), SCAN_LIMIT, SCAN_MESSAGE);
    expect429(await scan("198.51.100.3"), SCAN_LIMIT, SCAN_MESSAGE);
  });
});

describe("bulk rate limit (10 per 15 minutes)", () => {
  test("allows the 10th request and returns 429 with the bulk body on the 11th", async () => {
    const first = await bulk("198.51.100.20");
    expect(first.status).toBe(400);
    expectStandardHeaders(first, BULK_LIMIT);
    expect(first.headers["ratelimit-remaining"]).toBe(String(BULK_LIMIT - 1));

    await exhaust(bulk, "198.51.100.20", BULK_LIMIT - 1);
    expect429(await bulk("198.51.100.20"), BULK_LIMIT, BULK_MESSAGE);
  });

  test("is a separate budget from the scan limit", async () => {
    await exhaust(bulk, "198.51.100.21", BULK_LIMIT);
    expect((await bulk("198.51.100.21")).status).toBe(429);

    const res = await scan("198.51.100.21");
    expect(res.status).toBe(400);
    expect(res.headers["ratelimit-remaining"]).toBe(String(SCAN_LIMIT - 1));
  });
});

describe("trust proxy 1 (Railway's single edge proxy)", () => {
  test("keys on the client address the proxy reports, so clients do not share a bucket", async () => {
    await exhaust(bulk, "198.51.100.30", BULK_LIMIT);
    expect((await bulk("198.51.100.30")).status).toBe(429);

    const other = await bulk("198.51.100.31");
    expect(other.status).toBe(400);
    expect(other.headers["ratelimit-remaining"]).toBe(String(BULK_LIMIT - 1));
  });

  test("ignores client-supplied X-Forwarded-For entries left of the proxy's own", async () => {
    // With one trusted hop, only the rightmost entry (appended by the proxy) is
    // the client. A client that prepends a fresh fake address per request must
    // still land in its real bucket.
    await exhaust(bulk, "198.51.100.40", BULK_LIMIT);
    const spoofed = await request(app)
      .get("/api/scan/bulk")
      .set("X-Forwarded-For", "203.0.113.99, 198.51.100.40");
    expect429(spoofed, BULK_LIMIT, BULK_MESSAGE);
  });
});

describe("unlimited routes", () => {
  test("/api/health is not rate limited (deploy verification polls it)", async () => {
    const res = await request(app).get("/api/health").set("X-Forwarded-For", "198.51.100.50");
    expect(res.status).toBe(200);
    expect(res.headers["ratelimit-limit"]).toBeUndefined();
  });
});
