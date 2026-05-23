jest.mock("axios");
const axios = require("axios");
const ipinfo = require("./ipinfo");

describe("ipinfo.scanIp", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'info' with geo / org / abuse fields populated", async () => {
    axios.get.mockResolvedValueOnce({ data: {
      org: "AS15169 Google LLC", country: "US", region: "California",
      city: "Mountain View", timezone: "America/Los_Angeles",
      hostname: "dns.google", abuse: { email: "network-abuse@google.com" },
    } });
    const result = await ipinfo.scanIp("8.8.8.8");
    expect(result.verdict).toBe("info");
    expect(result.org).toContain("Google");
    expect(result.country).toBe("US");
    expect(result.abuse).toBe("network-abuse@google.com");
  });

  test("handles missing abuse contact gracefully", async () => {
    axios.get.mockResolvedValueOnce({ data: { org: "Cloudflare" } });
    const result = await ipinfo.scanIp("1.1.1.1");
    expect(result.abuse).toBeNull();
  });

  test("propagates axios errors", async () => {
    axios.get.mockRejectedValueOnce(new Error("network down"));
    await expect(ipinfo.scanIp("1.2.3.4")).rejects.toThrow("network down");
  });
});

describe("ipinfo.scanUrl", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns hostname hint for valid URL without calling axios", async () => {
    const result = await ipinfo.scanUrl("https://example.com/path?x=1");
    expect(result.verdict).toBe("info");
    expect(result.detail).toContain("example.com");
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("returns plain 'info' for malformed URL", async () => {
    const result = await ipinfo.scanUrl("not-a-real-url");
    expect(result.verdict).toBe("info");
  });
});

describe("ipinfo non-applicable methods", () => {
  test("scanHash and scanDomain return 'IP-only engine' info", async () => {
    expect((await ipinfo.scanHash()).verdict).toBe("info");
    expect((await ipinfo.scanDomain()).verdict).toBe("info");
  });
});
