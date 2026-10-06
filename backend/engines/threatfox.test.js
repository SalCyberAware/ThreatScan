jest.mock("axios");
const axios = require("axios");
const tf = require("./threatfox");

describe("threatfox.scanHash", () => {
  beforeEach(() => axios.post.mockReset());

  test("returns 'clean' on 'no_result'", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    expect((await tf.scanHash("abc")).verdict).toBe("clean");
  });

  test("returns 'malicious' with malware + confidence + tags", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      data: [{ malware: "AsyncRAT", confidence_level: 80, tags: ["rat"] }],
    } });
    const result = await tf.scanHash("abc");
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBe("AsyncRAT");
    expect(result.confidence).toBe(80);
    expect(result.tags).toEqual(["rat"]);
  });

  test("propagates axios errors instead of reporting 'clean'", async () => {
    axios.post.mockRejectedValueOnce(new Error("network down"));
    await expect(tf.scanHash("abc")).rejects.toThrow("network down");
  });
});

describe("threatfox.scanIp", () => {
  beforeEach(() => axios.post.mockReset());

  test("returns 'clean' on 'no_result'", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    expect((await tf.scanIp("1.2.3.4")).verdict).toBe("clean");
  });

  test("returns 'malicious' on a hit", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      data: [{ malware: "Cobalt Strike", confidence_level: 90 }],
    } });
    const result = await tf.scanIp("1.2.3.4");
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBe("Cobalt Strike");
  });

  test("propagates axios errors instead of reporting 'clean'", async () => {
    axios.post.mockRejectedValueOnce(new Error("boom"));
    await expect(tf.scanIp("1.2.3.4")).rejects.toThrow("boom");
  });
});

describe("threatfox.scanUrl + scanDomain", () => {
  beforeEach(() => axios.post.mockReset());

  test("scanUrl returns 'clean' on 'no_result'", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    expect((await tf.scanUrl("http://x.com")).verdict).toBe("clean");
  });

  test("scanDomain delegates to scanUrl (malicious path)", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      data: [{ malware: "Emotet" }],
    } });
    const result = await tf.scanDomain("evil.com");
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBe("Emotet");
  });

  test("scanUrl returns malware=null when ioc has no malware field", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      data: [{ ioc: "http://x.com", confidence_level: 50 }],
    } });
    const result = await tf.scanUrl("http://x.com");
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBeNull();
  });
});

// Run fn with MALWAREBAZAAR_KEY set to value (undefined = unset), then restore.
async function withAbuseKey(value, fn) {
  const original = process.env.MALWAREBAZAAR_KEY;
  if (value === undefined) delete process.env.MALWAREBAZAAR_KEY;
  else process.env.MALWAREBAZAAR_KEY = value;
  try { return await fn(); }
  finally {
    if (original === undefined) delete process.env.MALWAREBAZAAR_KEY;
    else process.env.MALWAREBAZAAR_KEY = original;
  }
}

describe("threatfox authentication and failure handling", () => {
  beforeEach(() => axios.post.mockReset());

  test("sends the abuse.ch key in the Auth-Key header", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    await withAbuseKey("abuse-test-key", () => tf.scanUrl("http://x.com"));
    const [, body, config] = axios.post.mock.calls[0];
    expect(config.headers["Auth-Key"]).toBe("abuse-test-key");
    expect(config.headers["Content-Type"]).toBe("application/json");
    expect(body).not.toContain("abuse-test-key");
  });

  test("omits the Auth-Key header when MALWAREBAZAAR_KEY is unset", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    await withAbuseKey(undefined, () => tf.scanUrl("http://x.com"));
    expect(axios.post.mock.calls[0][2].headers).not.toHaveProperty("Auth-Key");
  });

  test("a 401 from abuse.ch is an error, not 'clean'", async () => {
    const err = new Error("Request failed with status code 401");
    err.response = { status: 401, data: { error: "Unauthorized" } };
    axios.post.mockRejectedValueOnce(err);
    await expect(tf.scanDomain("example.com")).rejects.toThrow("401");
  });

  test.each(["unknown_auth_key", "illegal_search_term"])(
    "query_status '%s' is an error, not a 'malicious' hit", async (status) => {
      axios.post.mockResolvedValueOnce({ data: { query_status: status, data: "explanation" } });
      await expect(tf.scanHash("abc")).rejects.toThrow(status);
    });

  test("a response with no query_status is an error", async () => {
    axios.post.mockResolvedValueOnce({ data: {} });
    await expect(tf.scanIp("1.2.3.4")).rejects.toThrow(/unexpected response/);
  });
});

describe("threatfox.scanHash looks the hash up as an indicator", () => {
  const SHA256 = "96af1d0c3ed78e44ac3f75665b7483e77ff451daa2ec01966299b0686bc3c49b";
  beforeEach(() => axios.post.mockReset());

  test("a hash found by search_ioc is 'malicious'", async () => {
    axios.post.mockResolvedValueOnce({ data: {
      query_status: "ok",
      data: [{ ioc: SHA256, ioc_type: "sha256_hash", malware_printable: "Unknown Loader",
               malware: "win.unknown_loader", confidence_level: 100, tags: ["loader"] }],
    } });
    const result = await tf.scanHash(SHA256);
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBe("win.unknown_loader");
    expect(result.confidence).toBe(100);
    expect(result.tags).toEqual(["loader"]);
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(JSON.parse(axios.post.mock.calls[0][1])).toEqual({ query: "search_ioc", search_term: SHA256 });
  });

  test("no_result from search_ioc is 'clean' with no search_hash fallback", async () => {
    axios.post.mockResolvedValueOnce({ data: { query_status: "no_result" } });
    expect((await tf.scanHash(SHA256)).verdict).toBe("clean");
    expect(axios.post).toHaveBeenCalledTimes(1);
    expect(JSON.parse(axios.post.mock.calls[0][1]).query).toBe("search_ioc");
  });

  test("errors from search_ioc still propagate", async () => {
    const err = new Error("Request failed with status code 403");
    err.response = { status: 403 };
    axios.post.mockRejectedValueOnce(err);
    await expect(tf.scanHash(SHA256)).rejects.toThrow("403");
  });
});
