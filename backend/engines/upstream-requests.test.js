// Cross-engine guarantees for outbound requests: every axios call carries a
// finite timeout and the caller's AbortSignal, and user-supplied values placed
// in an upstream URL are encoded.
jest.mock("axios");
const axios = require("axios");

const abuseipdb     = require("./abuseipdb");
const greynoise     = require("./greynoise");
const ipinfo        = require("./ipinfo");
const malwarebazaar = require("./malwarebazaar");
const otx           = require("./otx");
const safebrowsing  = require("./safebrowsing");
const threatfox     = require("./threatfox");
const urlhaus       = require("./urlhaus");
const urlscan       = require("./urlscan");
const virustotal    = require("./virustotal");
const whois         = require("./whois");

const HASH = "d41d8cd98f00b204e9800998ecf8427e";

// axios.get(url, config) and axios.post(url, body, config)
function allCalls() {
  return [
    ...axios.get.mock.calls.map(([url, config]) => ({ url, config })),
    ...axios.post.mock.calls.map(([url, , config]) => ({ url, config })),
  ];
}

beforeEach(() => {
  axios.get.mockReset();
  axios.post.mockReset();
});

describe("every upstream call has a timeout and the caller's signal", () => {
  const cases = [
    ["abuseipdb.scanIp",      () => abuseipdb.scanIp("8.8.8.8", signal),
      () => axios.get.mockResolvedValue({ data: { data: { abuseConfidenceScore: 0 } } })],
    ["greynoise.scanIp",      () => greynoise.scanIp("8.8.8.8", signal),
      () => axios.get.mockResolvedValue({ data: { classification: "benign" } })],
    ["ipinfo.scanIp",         () => ipinfo.scanIp("8.8.8.8", signal),
      () => axios.get.mockResolvedValue({ data: {} })],
    ["malwarebazaar.scanHash", () => malwarebazaar.scanHash(HASH, signal),
      () => axios.post.mockResolvedValue({ data: { query_status: "hash_not_found" } })],
    ["otx.scanIp",            () => otx.scanIp("8.8.8.8", signal),
      () => axios.get.mockResolvedValue({ data: { pulse_info: { count: 0 } } })],
    ["otx.scanUrl",           () => otx.scanUrl("https://example.com/x", signal),
      () => axios.get.mockResolvedValue({ data: { pulse_info: { count: 0 } } })],
    ["otx.scanHash",          () => otx.scanHash(HASH, signal),
      () => axios.get.mockResolvedValue({ data: { pulse_info: { count: 0 } } })],
    ["safebrowsing.scanDomain", () => safebrowsing.scanDomain("example.com", signal),
      () => axios.post.mockResolvedValue({ data: {} })],
    ["threatfox.scanDomain",  () => threatfox.scanDomain("example.com", signal),
      () => axios.post.mockResolvedValue({ data: { query_status: "no_result" } })],
    ["threatfox.scanHash",    () => threatfox.scanHash(HASH, signal),
      () => axios.post.mockResolvedValue({ data: { query_status: "no_result" } })],
    ["urlhaus.scanDomain",    () => urlhaus.scanDomain("example.com", signal),
      () => axios.post.mockResolvedValue({ data: { query_status: "no_results" } })],
    ["virustotal.scanIp",     () => virustotal.scanIp("8.8.8.8", signal),
      () => axios.get.mockResolvedValue({ data: { data: { attributes: { last_analysis_stats: { harmless: 1 } } } } })],
    ["whois.scanUrl",         () => whois.scanUrl("https://example.com/x", signal),
      () => axios.get.mockResolvedValue({ data: {} })],
  ];
  let signal;

  test.each(cases)("%s", async (_name, run, arrange) => {
    signal = new AbortController().signal;
    arrange();
    await run();
    const calls = allCalls();
    expect(calls.length).toBeGreaterThan(0);
    for (const { config } of calls) {
      expect(Number.isFinite(config?.timeout)).toBe(true);
      expect(config.timeout).toBeGreaterThan(0);
      expect(config.signal).toBe(signal);
    }
  });
});

// The two polling engines sleep between attempts, so they run on fake timers.
describe("polling engines", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test("urlscan: submit and result polls carry a timeout and the signal", async () => {
    const signal = new AbortController().signal;
    axios.post.mockResolvedValue({ data: { api: "https://urlscan.io/api/v1/result/abc/" } });
    axios.get.mockResolvedValue({ data: { verdicts: { overall: { score: 0 } } } });
    const p = urlscan.scanUrl("https://example.com", signal);
    await jest.advanceTimersByTimeAsync(2500);
    await p;
    for (const { config } of allCalls()) {
      expect(Number.isFinite(config?.timeout)).toBe(true);
      expect(config.signal).toBe(signal);
    }
    expect(axios.get).toHaveBeenCalledTimes(1);
  });

  test("urlscan: stops polling once the signal is aborted", async () => {
    const controller = new AbortController();
    axios.post.mockResolvedValue({ data: { api: "https://urlscan.io/api/v1/result/abc/" } });
    const p = urlscan.scanUrl("https://example.com", controller.signal);
    await jest.advanceTimersByTimeAsync(0);
    controller.abort();
    await jest.advanceTimersByTimeAsync(2500 * 8);
    await p;
    expect(axios.get).not.toHaveBeenCalled();
  });

  test("virustotal: URL submission carries a timeout and the signal", async () => {
    const signal = new AbortController().signal;
    const notFound = Object.assign(new Error("Not Found"), { response: { status: 404 } });
    axios.get
      .mockRejectedValueOnce(notFound)
      .mockResolvedValue({ data: { data: { attributes: { status: "completed", stats: { harmless: 1 } } } } });
    axios.post.mockResolvedValue({ data: { data: { id: "analysis-1" } } });
    const p = virustotal.scanUrl("https://example.com", signal);
    await jest.advanceTimersByTimeAsync(3000);
    await p;
    expect(axios.post).toHaveBeenCalledTimes(1);
    for (const { config } of allCalls()) {
      expect(Number.isFinite(config?.timeout)).toBe(true);
      expect(config.signal).toBe(signal);
    }
  });

  test("virustotal: stops polling for the analysis once the signal is aborted", async () => {
    const controller = new AbortController();
    const notFound = Object.assign(new Error("Not Found"), { response: { status: 404 } });
    axios.get.mockRejectedValueOnce(notFound);
    axios.post.mockResolvedValue({ data: { data: { id: "analysis-1" } } });
    const p = virustotal.scanUrl("https://example.com", controller.signal);
    await jest.advanceTimersByTimeAsync(0);
    controller.abort();
    await jest.advanceTimersByTimeAsync(3000 * 6);
    await p;
    expect(axios.get).toHaveBeenCalledTimes(1); // only the initial cache lookup
  });
});

describe("user-supplied values are encoded in upstream URLs", () => {
  const hostile = "1.2.3.4/../../admin?x=1#y";
  const encoded = "1.2.3.4%2F..%2F..%2Fadmin%3Fx%3D1%23y";

  test("greynoise", async () => {
    axios.get.mockResolvedValue({ data: {} });
    await greynoise.scanIp(hostile);
    expect(axios.get.mock.calls[0][0]).toBe(`https://api.greynoise.io/v3/community/${encoded}`);
  });

  test("ipinfo", async () => {
    axios.get.mockResolvedValue({ data: {} });
    await ipinfo.scanIp(hostile);
    expect(axios.get.mock.calls[0][0]).toBe(`https://ipinfo.io/${encoded}/json`);
  });

  test("otx ip, domain and hash", async () => {
    axios.get.mockResolvedValue({ data: { pulse_info: { count: 0 } } });
    await otx.scanIp(hostile);
    await otx.scanDomain(hostile);
    await otx.scanHash(hostile);
    const urls = axios.get.mock.calls.map(c => c[0]);
    expect(urls).toEqual([
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${encoded}/general`,
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${encoded}/reputation`,
      `https://otx.alienvault.com/api/v1/indicators/domain/${encoded}/general`,
      `https://otx.alienvault.com/api/v1/indicators/file/${encoded}/general`,
    ]);
  });

  test("virustotal domain", async () => {
    axios.get.mockResolvedValue({ data: { data: { attributes: { last_analysis_stats: {} } } } });
    await virustotal.scanDomain("evil.com/../../users");
    expect(axios.get.mock.calls[0][0])
      .toBe("https://www.virustotal.com/api/v3/domains/evil.com%2F..%2F..%2Fusers");
  });

  test("virustotal ip keeps IPv6 colons literal", async () => {
    axios.get.mockResolvedValue({ data: { data: { attributes: { last_analysis_stats: {} } } } });
    await virustotal.scanIp("2001:db8::1");
    expect(axios.get.mock.calls[0][0]).toBe("https://www.virustotal.com/api/v3/ip_addresses/2001:db8::1");
  });

  test("whois cannot inject extra query parameters", async () => {
    axios.get.mockResolvedValue({ data: {} });
    await whois.scanDomain("example.com&type=TXT");
    const urls = axios.get.mock.calls.map(c => c[0]);
    expect(urls).toEqual([
      "https://whoisjson.com/api/v1/whois?domain=example.com%26type%3DTXT",
      "https://dns.google/resolve?name=example.com%26type%3DTXT&type=A",
      "https://dns.google/resolve?name=example.com%26type%3DTXT&type=MX",
    ]);
  });

  test("a bare dot segment never reaches the network", async () => {
    await expect(greynoise.scanIp("..")).rejects.toThrow("Invalid indicator");
    await expect(otx.scanIp("..")).rejects.toThrow("Invalid indicator");
    expect(axios.get).not.toHaveBeenCalled();
  });
});
