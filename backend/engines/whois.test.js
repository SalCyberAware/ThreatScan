jest.mock("axios");
const axios = require("axios");
const whois = require("./whois");

describe("whois.scanDomain", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns combined WHOIS + DNS info when all three calls succeed", async () => {
    axios.get
      .mockResolvedValueOnce({ data: {
        registrar: "GoDaddy",
        creation_date: "2010-01-15T00:00:00Z",
        expiration_date: "2030-01-15T00:00:00Z",
        registrant_country: "US",
        name_servers: ["ns1.x.com", "ns2.x.com", "ns3.x.com", "ns4.x.com"],
      } })
      .mockResolvedValueOnce({ data: { Answer: [{ data: "93.184.216.34" }] } })
      .mockResolvedValueOnce({ data: { Answer: [{ data: "10 mail.example.com" }] } });
    const result = await whois.scanDomain("example.com");
    expect(result.verdict).toBe("info");
    expect(result.registrar).toBe("GoDaddy");
    expect(result.created).toBe("2010-01-15");
    expect(result.expires).toBe("2030-01-15");
    expect(result.country).toBe("US");
    expect(result.nameservers).toHaveLength(3);
    expect(result.aRecords).toEqual(["93.184.216.34"]);
    expect(result.mxRecords).toEqual(["10 mail.example.com"]);
  });

  test("returns 'WHOIS/DNS lookup failed' when all three calls reject", async () => {
    axios.get
      .mockRejectedValueOnce(new Error("whois down"))
      .mockRejectedValueOnce(new Error("dns A failed"))
      .mockRejectedValueOnce(new Error("dns MX failed"));
    const result = await whois.scanDomain("example.com");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/lookup failed/i);
  });

  test("partial success — whois fails, DNS succeeds", async () => {
    axios.get
      .mockRejectedValueOnce(new Error("whois down"))
      .mockResolvedValueOnce({ data: { Answer: [{ data: "1.2.3.4" }] } })
      .mockResolvedValueOnce({ data: { Answer: [] } });
    const result = await whois.scanDomain("example.com");
    expect(result.verdict).toBe("info");
    expect(result.aRecords).toEqual(["1.2.3.4"]);
    expect(result.mxRecords).toEqual([]);
    expect(result.registrar).toBeUndefined();
  });

  test("partial success — whois succeeds, DNS A fails, MX succeeds", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { registrar: "Namecheap" } })
      .mockRejectedValueOnce(new Error("dns A timeout"))
      .mockResolvedValueOnce({ data: { Answer: [{ data: "5 mx.example.com" }] } });
    const result = await whois.scanDomain("example.com");
    expect(result.verdict).toBe("info");
    expect(result.registrar).toBe("Namecheap");
    expect(result.aRecords).toBeUndefined();
    expect(result.mxRecords).toEqual(["5 mx.example.com"]);
  });

  test("DNS responses with no Answer field default to empty arrays", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { registrar: "X" } })
      .mockResolvedValueOnce({ data: {} })
      .mockResolvedValueOnce({ data: {} });
    const result = await whois.scanDomain("example.com");
    expect(result.aRecords).toEqual([]);
    expect(result.mxRecords).toEqual([]);
  });

  test("calls are sequential in the documented order (whois → A → MX)", async () => {
    axios.get
      .mockResolvedValueOnce({ data: {} })
      .mockResolvedValueOnce({ data: { Answer: [] } })
      .mockResolvedValueOnce({ data: { Answer: [] } });
    await whois.scanDomain("example.com");
    expect(axios.get.mock.calls[0][0]).toContain("whoisjson.com");
    expect(axios.get.mock.calls[1][0]).toContain("type=A");
    expect(axios.get.mock.calls[2][0]).toContain("type=MX");
  });
});

describe("whois.scanUrl", () => {
  beforeEach(() => axios.get.mockReset());

  test("extracts hostname and delegates to scanDomain", async () => {
    axios.get
      .mockResolvedValueOnce({ data: { registrar: "X" } })
      .mockResolvedValueOnce({ data: { Answer: [] } })
      .mockResolvedValueOnce({ data: { Answer: [] } });
    const result = await whois.scanUrl("https://example.com/path");
    expect(result.verdict).toBe("info");
    expect(result.registrar).toBe("X");
    expect(axios.get.mock.calls[0][0]).toContain("example.com");
  });

  test("returns 'Invalid URL' info for malformed input without calling axios", async () => {
    const result = await whois.scanUrl("not-a-url");
    expect(result.verdict).toBe("info");
    expect(result.detail).toMatch(/invalid/i);
    expect(axios.get).not.toHaveBeenCalled();
  });
});

describe("whois.scanIp and whois.scanHash", () => {
  test("scanIp returns 'info' redirecting to domain/URL", async () => {
    expect((await whois.scanIp()).verdict).toBe("info");
  });

  test("scanHash returns 'info' (N/A for hashes)", async () => {
    expect((await whois.scanHash()).verdict).toBe("info");
  });
});
