jest.mock("axios");
const axios = require("axios");
const vt = require("./virustotal");

describe("virustotal.scanUrl", () => {
  beforeEach(() => {
    axios.get.mockReset();
    axios.post.mockReset();
  });

  test("rejects non-URL input with 'info' and no axios call", async () => {
    const result = await vt.scanUrl("not-a-url");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/url/i);
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns 'malicious' from cached lookup when stats.malicious >= 1", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 5, suspicious: 0, harmless: 70, undetected: 10 },
    } } } });
    const result = await vt.scanUrl("https://bad.com");
    expect(result.verdict).toBe("malicious");
    expect(result.malicious).toBe(5);
    expect(result.engines).toBe(85);
  });

  test("returns 'suspicious' when only suspicious >= 1", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 2, harmless: 70, undetected: 10 },
    } } } });
    expect((await vt.scanUrl("https://x.com")).verdict).toBe("suspicious");
  });

  test("returns 'clean' when nothing is flagged", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 10 },
    } } } });
    expect((await vt.scanUrl("https://good.com")).verdict).toBe("clean");
  });

  test("propagates non-404 errors from cached lookup", async () => {
    const err = new Error("Unauthorized");
    err.response = { status: 401 };
    axios.get.mockRejectedValueOnce(err);
    await expect(vt.scanUrl("https://x.com")).rejects.toThrow("Unauthorized");
  });
});

describe("virustotal.scanHash", () => {
  beforeEach(() => axios.get.mockReset());

  test("rejects non-hex / wrong-length input with 'info'", async () => {
    expect((await vt.scanHash("zzz")).verdict).toBe("info");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns 'malicious' when stats.malicious >= 1", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 3, suspicious: 0, harmless: 60, undetected: 5 },
    } } } });
    const result = await vt.scanHash("e".repeat(64));
    expect(result.verdict).toBe("malicious");
    expect(result.engines).toBe(68);
    expect(result.flagged).toBe(3);
  });

  test("returns 'clean' when no detections", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 60, undetected: 5 },
    } } } });
    expect((await vt.scanHash("a".repeat(32))).verdict).toBe("clean");
  });
});

describe("virustotal.scanDomain", () => {
  beforeEach(() => axios.get.mockReset());

  test("rejects URL input by routing to 'info'", async () => {
    const result = await vt.scanDomain("https://x.com");
    expect(result.verdict).toBe("info");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("rejects IPv4 input by routing to 'info'", async () => {
    const result = await vt.scanDomain("1.2.3.4");
    expect(result.verdict).toBe("info");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns 'clean' on no detections", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 80, undetected: 10 },
    } } } });
    expect((await vt.scanDomain("example.com")).verdict).toBe("clean");
  });
});

describe("virustotal.scanIp", () => {
  beforeEach(() => axios.get.mockReset());

  test("rejects non-IP input with 'info'", async () => {
    expect((await vt.scanIp("not.an.ip")).verdict).toBe("info");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns 'malicious' for IPv4 with malicious detections", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { attributes: {
      last_analysis_stats: { malicious: 2, suspicious: 0, harmless: 80, undetected: 5 },
    } } } });
    expect((await vt.scanIp("1.2.3.4")).verdict).toBe("malicious");
  });
});
