jest.mock("axios");
const axios = require("axios");
const sb = require("./safebrowsing");

describe("safebrowsing.scanUrl", () => {
  beforeEach(() => axios.post.mockReset());

  test("returns 'clean' when there are no matches", async () => {
    axios.post.mockResolvedValueOnce({ data: {} });
    const result = await sb.scanUrl("https://good.example.com");
    expect(result.verdict).toBe("clean");
    expect(result.threats).toEqual([]);
  });

  test("returns 'malicious' with threat types listed", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      matches: [
        { threatType: "MALWARE" },
        { threatType: "SOCIAL_ENGINEERING" },
      ],
    } });
    const result = await sb.scanUrl("https://bad.example.com");
    expect(result.verdict).toBe("malicious");
    expect(result.threats).toEqual(["MALWARE", "SOCIAL_ENGINEERING"]);
  });

  test("sends URL inside the threatEntries payload", async () => {
    axios.post.mockResolvedValueOnce({ data: {} });
    await sb.scanUrl("https://example.com/path");
    const body = axios.post.mock.calls[0][1];
    expect(body.threatInfo.threatEntries[0].url).toBe("https://example.com/path");
    expect(body.threatInfo.threatTypes).toContain("MALWARE");
  });

  test("sends GSB_KEY in the x-goog-api-key header, never in the URL", async () => {
    const original = process.env.GSB_KEY;
    process.env.GSB_KEY = "gsb-test-key";
    try {
      axios.post.mockResolvedValueOnce({ data: {} });
      await sb.scanUrl("https://example.com");
      const [url, , config] = axios.post.mock.calls[0];
      expect(url).toBe("https://safebrowsing.googleapis.com/v4/threatMatches:find");
      expect(url).not.toContain("gsb-test-key");
      expect(url).not.toContain("key=");
      expect(config.headers["x-goog-api-key"]).toBe("gsb-test-key");
    } finally {
      if (original === undefined) delete process.env.GSB_KEY;
      else process.env.GSB_KEY = original;
    }
  });

  test("propagates axios errors (no internal handler)", async () => {
    const err = new Error("Forbidden");
    err.response = { status: 403 };
    axios.post.mockRejectedValueOnce(err);
    await expect(sb.scanUrl("https://x.com")).rejects.toThrow("Forbidden");
  });
});

describe("safebrowsing.scanDomain", () => {
  beforeEach(() => axios.post.mockReset());

  test("prefixes 'https://' and delegates to scanUrl", async () => {
    axios.post.mockResolvedValueOnce({ data: {} });
    const result = await sb.scanDomain("example.com");
    expect(result.verdict).toBe("clean");
    const body = axios.post.mock.calls[0][1];
    expect(body.threatInfo.threatEntries[0].url).toBe("https://example.com");
  });
});

describe("safebrowsing non-URL methods", () => {
  test("scanIp and scanHash return 'URL-only engine' info", async () => {
    expect((await sb.scanIp()).verdict).toBe("info");
    expect((await sb.scanHash()).verdict).toBe("info");
  });
});
