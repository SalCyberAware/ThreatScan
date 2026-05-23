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

  test("swallows axios errors and returns 'clean'", async () => {
    axios.post.mockRejectedValueOnce(new Error("network down"));
    expect((await tf.scanHash("abc")).verdict).toBe("clean");
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

  test("swallows axios errors and returns 'clean'", async () => {
    axios.post.mockRejectedValueOnce(new Error("boom"));
    expect((await tf.scanIp("1.2.3.4")).verdict).toBe("clean");
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
