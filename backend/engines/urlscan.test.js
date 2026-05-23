jest.mock("axios");
const axios = require("axios");
const urlscan = require("./urlscan");

async function tickPolls(times) {
  for (let i = 0; i < times; i++) {
    await jest.advanceTimersByTimeAsync(2500);
  }
}

describe("urlscan.scanUrl", () => {
  beforeEach(() => {
    axios.post.mockReset();
    axios.get.mockReset();
    jest.useFakeTimers();
  });
  afterEach(() => jest.useRealTimers());

  test("returns 'malicious' when overall score >= 70", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "https://urlscan.io/api/v1/result/abc" } });
    axios.get.mockResolvedValueOnce({ data: {
      verdicts: { overall: { score: 85, brands: ["BrandX"], malicious: true } },
      task: { screenshotURL: "https://urlscan.io/screenshots/abc.png" },
      page: { country: "US", server: "nginx" },
    } });
    const p = urlscan.scanUrl("http://bad.com");
    await tickPolls(1);
    const result = await p;
    expect(result.verdict).toBe("malicious");
    expect(result.score).toBe(85);
    expect(result.screenshot).toBe("https://urlscan.io/screenshots/abc.png");
    expect(result.country).toBe("US");
  });

  test("returns 'suspicious' when score in [30, 70)", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "x" } });
    axios.get.mockResolvedValueOnce({ data: { verdicts: { overall: { score: 50 } } } });
    const p = urlscan.scanUrl("http://x.com");
    await tickPolls(1);
    expect((await p).verdict).toBe("suspicious");
  });

  test("returns 'clean' when score < 30", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "x" } });
    axios.get.mockResolvedValueOnce({ data: { verdicts: { overall: { score: 5 } } } });
    const p = urlscan.scanUrl("http://good.com");
    await tickPolls(1);
    expect((await p).verdict).toBe("clean");
  });

  test("returns 'info' (urlscan timeout) when all 8 polls fail", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "x" } });
    axios.get.mockRejectedValue(new Error("not ready"));
    const p = urlscan.scanUrl("http://slow.com");
    await tickPolls(8);
    const result = await p;
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/timeout/i);
  });

  test("submits with visibility 'unlisted' (security fix)", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "x" } });
    axios.get.mockResolvedValueOnce({ data: { verdicts: { overall: { score: 0 } } } });
    const p = urlscan.scanUrl("http://x.com");
    await tickPolls(1);
    await p;
    expect(axios.post.mock.calls[0][1]).toEqual({ url: "http://x.com", visibility: "unlisted" });
  });

  test("propagates axios.post (submit) errors", async () => {
    const err = new Error("Unauthorized");
    err.response = { status: 401 };
    axios.post.mockRejectedValueOnce(err);
    await expect(urlscan.scanUrl("http://x.com")).rejects.toThrow("Unauthorized");
  });
});

describe("urlscan.scanDomain", () => {
  beforeEach(() => {
    axios.post.mockReset();
    axios.get.mockReset();
    jest.useFakeTimers();
  });
  afterEach(() => jest.useRealTimers());

  test("strips scheme and submits https://<domain>", async () => {
    axios.post.mockResolvedValueOnce({ data: { api: "x" } });
    axios.get.mockResolvedValueOnce({ data: { verdicts: { overall: { score: 0 } } } });
    const p = urlscan.scanDomain("http://example.com");
    await tickPolls(1);
    await p;
    expect(axios.post.mock.calls[0][1].url).toBe("https://example.com");
  });
});

describe("urlscan non-URL methods", () => {
  test("scanIp and scanHash return 'info'", async () => {
    expect((await urlscan.scanIp()).verdict).toBe("info");
    expect((await urlscan.scanHash()).verdict).toBe("info");
  });
});
