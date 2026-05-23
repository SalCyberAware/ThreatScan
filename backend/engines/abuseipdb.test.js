jest.mock("axios");
const axios = require("axios");
const abuseipdb = require("./abuseipdb");

describe("abuseipdb.scanIp", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'info' for non-IP input without calling axios", async () => {
    const result = await abuseipdb.scanIp("not.an.ip");
    expect(result.verdict).toBe("info");
    expect(result.detail).toBe("IP-only engine");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("rejects out-of-range IPv4 octets as 'info'", async () => {
    const result = await abuseipdb.scanIp("999.999.999.999");
    expect(result.verdict).toBe("info");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns 'malicious' when abuseConfidenceScore >= 75", async () => {
    axios.get.mockResolvedValueOnce({
      data: { data: {
        abuseConfidenceScore: 90, totalReports: 50, countryCode: "RU",
        isp: "BadCo", domain: "bad.example", lastReportedAt: "2024-01-01",
        isWhitelisted: false,
      } },
    });
    const result = await abuseipdb.scanIp("1.2.3.4");
    expect(result.verdict).toBe("malicious");
    expect(result.confidence).toBe(90);
    expect(result.reports).toBe(50);
    expect(result.country).toBe("RU");
  });

  test("returns 'suspicious' when score is in [25, 75)", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { abuseConfidenceScore: 50 } } });
    const result = await abuseipdb.scanIp("1.2.3.4");
    expect(result.verdict).toBe("suspicious");
  });

  test("returns 'clean' when score is below 25", async () => {
    axios.get.mockResolvedValueOnce({ data: { data: { abuseConfidenceScore: 5 } } });
    const result = await abuseipdb.scanIp("8.8.8.8");
    expect(result.verdict).toBe("clean");
  });

  test("propagates axios errors (no internal handler)", async () => {
    const err = new Error("Unauthorized");
    err.response = { status: 401 };
    axios.get.mockRejectedValueOnce(err);
    await expect(abuseipdb.scanIp("1.2.3.4")).rejects.toThrow("Unauthorized");
  });
});

describe("abuseipdb non-IP methods", () => {
  test("scanUrl / scanHash / scanDomain return 'IP-only engine' info", async () => {
    expect((await abuseipdb.scanUrl()).verdict).toBe("info");
    expect((await abuseipdb.scanHash()).verdict).toBe("info");
    expect((await abuseipdb.scanDomain()).verdict).toBe("info");
  });
});
