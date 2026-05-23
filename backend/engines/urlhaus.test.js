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
});
