jest.mock("axios");
const axios = require("axios");
const otx = require("./otx");

describe("otx.scanIp", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'malicious' when general pulses > 5", async () => {
    axios.get
      .mockResolvedValueOnce({ data: {
        pulse_info: { count: 10, pulses: [{ name: "Campaign A" }] },
        country_name: "US",
      } })
      .mockResolvedValueOnce({ data: { reputation: { threat_score: 30 } } });
    const result = await otx.scanIp("1.2.3.4");
    expect(result.verdict).toBe("malicious");
    expect(result.pulses).toBe(10);
    expect(result.score).toBe(30);
    expect(result.country).toBe("US");
    expect(result.indicators).toEqual(["Campaign A"]);
  });

  test("returns 'suspicious' when pulses in (0, 5]", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { pulse_info: { count: 2 } } })
      .mockResolvedValueOnce({ data: { reputation: { threat_score: 5 } } });
    expect((await otx.scanIp("1.2.3.4")).verdict).toBe("suspicious");
  });

  test("returns 'clean' when pulses == 0", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { pulse_info: { count: 0 } } })
      .mockResolvedValueOnce({ data: { reputation: {} } });
    expect((await otx.scanIp("1.2.3.4")).verdict).toBe("clean");
  });

  test("tolerates failed /reputation — falls back to score 0", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { pulse_info: { count: 0 } } })
      .mockRejectedValueOnce(new Error("rep timeout"));
    const result = await otx.scanIp("1.2.3.4");
    expect(result.verdict).toBe("clean");
    expect(result.score).toBe(0);
  });

  test("returns 'error' when /general fails (ECONNABORTED → 'otx timeout')", async () => {
    const e = new Error("aborted");
    e.code = "ECONNABORTED";
    axios.get
      .mockRejectedValueOnce(e)
      .mockResolvedValueOnce({ data: {} });
    const result = await otx.scanIp("1.2.3.4");
    expect(result.verdict).toBe("error");
    expect(result.detail).toBe("otx timeout");
  });

  test("returns 'error' with 'otx error' on generic /general failure", async () => {
    axios.get
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce({ data: {} });
    const result = await otx.scanIp("1.2.3.4");
    expect(result.verdict).toBe("error");
    expect(result.detail).toBe("otx error");
  });
});

describe("otx.scanDomain", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'malicious' when pulses > 5", async () => {
    axios.get.mockResolvedValueOnce({ data: {
      pulse_info: { count: 8, pulses: [{ name: "Phish kit" }] },
    } });
    expect((await otx.scanDomain("evil.com")).verdict).toBe("malicious");
  });

  test("returns 'clean' when pulses == 0", async () => {
    axios.get.mockResolvedValueOnce({ data: { pulse_info: { count: 0 } } });
    expect((await otx.scanDomain("good.com")).verdict).toBe("clean");
  });

  test("returns 'error' verdict on axios failure", async () => {
    axios.get.mockRejectedValueOnce(new Error("nope"));
    expect((await otx.scanDomain("x.com")).verdict).toBe("error");
  });
});

describe("otx.scanUrl", () => {
  beforeEach(() => axios.get.mockReset());

  test("extracts hostname and delegates to scanDomain", async () => {
    axios.get.mockResolvedValueOnce({ data: { pulse_info: { count: 0 } } });
    const result = await otx.scanUrl("https://safe.com/path");
    expect(result.verdict).toBe("clean");
  });

  test("returns 'error' for malformed URLs", async () => {
    const result = await otx.scanUrl("not-a-url");
    expect(result.verdict).toBe("error");
    expect(axios.get).not.toHaveBeenCalled();
  });
});

describe("otx.scanHash", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'malicious' when pulses > 0 (any count)", async () => {
    axios.get.mockResolvedValueOnce({ data: {
      pulse_info: { count: 1 },
      malware_families: [{ display_name: "Emotet" }],
    } });
    const result = await otx.scanHash("abc");
    expect(result.verdict).toBe("malicious");
    expect(result.malware).toBe("Emotet");
  });

  test("returns 'clean' when pulses == 0", async () => {
    axios.get.mockResolvedValueOnce({ data: { pulse_info: { count: 0 } } });
    expect((await otx.scanHash("abc")).verdict).toBe("clean");
  });

  test("returns 'error' verdict on axios failure", async () => {
    axios.get.mockRejectedValueOnce(new Error("x"));
    expect((await otx.scanHash("abc")).verdict).toBe("error");
  });
});
