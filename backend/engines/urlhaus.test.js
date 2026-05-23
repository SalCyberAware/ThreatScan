jest.mock("axios");
const axios = require("axios");
const urlhaus = require("./urlhaus");

describe("urlhaus.scanUrl", () => {
  beforeEach(() => {
    axios.post.mockReset();
  });

  test("returns 'clean' when query_status is 'no_results'", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_results" } });
    const result = await urlhaus.scanUrl("http://example.com");
    expect(result.verdict).toBe("clean");
    expect(result.detail).toMatch(/not found/i);
  });

  test("returns 'malicious' when url_status is 'online'", async () => {
    axios.post.mockResolvedValueOnce({
      data: {
        query_status: "ok",
        url_status: "online",
        threat: "malware_download",
        tags: ["emotet", "trojan"],
        payloads: [{ filename: "evil.exe" }],
      },
    });
    const result = await urlhaus.scanUrl("http://bad.example.com");
    expect(result.verdict).toBe("malicious");
    expect(result.detail).toContain("online");
    expect(result.detail).toContain("malware_download");
    expect(result.tags).toEqual(["emotet", "trojan"]);
    expect(result.malware).toBe("evil.exe");
  });

  test("returns 'malicious' when query_status is 'is_page'", async () => {
    axios.post.mockResolvedValueOnce({
      data: { query_status: "is_page", tags: [], payloads: [] },
    });
    const result = await urlhaus.scanUrl("http://phish.example.com");
    expect(result.verdict).toBe("malicious");
  });

  test("returns 'suspicious' when url_status is 'offline'", async () => {
    axios.post.mockResolvedValueOnce({
      data: {
        query_status: "ok",
        url_status: "offline",
        tags: ["old-campaign"],
      },
    });
    const result = await urlhaus.scanUrl("http://offline.example.com");
    expect(result.verdict).toBe("suspicious");
    expect(result.detail).toMatch(/offline/i);
    expect(result.tags).toEqual(["old-campaign"]);
  });

  test("returns 'info' for unrecognised query_status values", async () => {
    axios.post.mockResolvedValueOnce({
      data: { query_status: "invalid_url" },
    });
    const result = await urlhaus.scanUrl("not-a-real-url");
    expect(result.verdict).toBe("info");
    expect(result.detail).toContain("invalid_url");
  });

  test("maps 403 responses to 'info' via the error handler", async () => {
    const err = new Error("Forbidden");
    err.response = { status: 403 };
    axios.post.mockRejectedValueOnce(err);
    const result = await urlhaus.scanUrl("http://example.com");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/temporarily unavailable/i);
  });
});

describe("urlhaus.scanHash", () => {
  beforeEach(() => {
    axios.post.mockReset();
  });

  test("rejects non-SHA256 hashes without calling axios", async () => {
    const md5 = "d41d8cd98f00b204e9800998ecf8427e";
    const result = await urlhaus.scanHash(md5);
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/sha256/i);
    expect(axios.post).not.toHaveBeenCalled();
  });

  test("returns 'clean' on no_results for a valid SHA256", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_results" } });
    const result = await urlhaus.scanHash("e".repeat(64));
    expect(result.verdict).toBe("clean");
    expect(result.detail).toMatch(/not found/i);
  });

  test("returns 'malicious' with file_type / signature / urls_count for a hit", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      file_type: "exe",
      signature: "Emotet",
      urls_count: 7,
      tags: ["emotet", "trojan"],
    } });
    const result = await urlhaus.scanHash("a".repeat(64));
    expect(result.verdict).toBe("malicious");
    expect(result.detail).toContain("exe");
    expect(result.detail).toContain("7");
    expect(result.malware).toBe("Emotet");
    expect(result.tags).toEqual(["emotet", "trojan"]);
  });
});

describe("urlhaus.scanDomain", () => {
  beforeEach(() => axios.post.mockReset());

  test("returns 'clean' on no_results", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_results" } });
    const result = await urlhaus.scanDomain("example.com");
    expect(result.verdict).toBe("clean");
    expect(result.detail).toMatch(/not found/i);
  });

  test("returns 'malicious' when at least one URL is online", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      urls: [
        { url_status: "online",  tags: ["phish"] },
        { url_status: "offline", tags: ["emotet"] },
        { url_status: "online",  tags: ["phish", "rat"] },
      ],
    } });
    const result = await urlhaus.scanDomain("evil.example.com");
    expect(result.verdict).toBe("malicious");
    expect(result.detail).toContain("3 malicious URLs");
    expect(result.detail).toContain("2 currently online");
    expect(result.tags).toEqual(expect.arrayContaining(["phish", "emotet", "rat"]));
  });

  test("returns 'suspicious' when host is listed but all URLs are offline", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      urls: [
        { url_status: "offline", tags: ["dormant"] },
        { url_status: "offline", tags: ["dormant"] },
      ],
    } });
    const result = await urlhaus.scanDomain("dormant.example.com");
    expect(result.verdict).toBe("suspicious");
    expect(result.detail).toContain("0 currently online");
  });
});

describe("urlhaus error handler", () => {
  beforeEach(() => axios.post.mockReset());

  test("maps ECONNABORTED to 'URLhaus timeout' info", async () => {
    const err = new Error("aborted");
    err.code = "ECONNABORTED";
    axios.post.mockRejectedValueOnce(err);
    const result = await urlhaus.scanUrl("http://x.com");
    expect(result.verdict).toBe("info");
    expect(result.detail).toBe("URLhaus timeout");
  });

  test("maps generic errors to 'URLhaus error: <message>' info", async () => {
    axios.post.mockRejectedValueOnce(new Error("DNS lookup failed"));
    const result = await urlhaus.scanUrl("http://x.com");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/^URLhaus error: /);
    expect(result.detail).toContain("DNS lookup failed");
  });
});

describe("urlhaus.scanIp", () => {
  test("returns 'info' (engine doesn't support IPs)", async () => {
    const result = await urlhaus.scanIp("1.2.3.4");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/URL\/domain\/hash/i);
  });
});
