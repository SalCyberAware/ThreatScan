const { detectType } = require("./detect");

describe("detectType", () => {
  test("classifies http and https URLs as 'url'", () => {
    expect(detectType("http://example.com/path")).toBe("url");
    expect(detectType("https://example.com")).toBe("url");
  });

  test("classifies IPv4 addresses as 'ip'", () => {
    expect(detectType("8.8.8.8")).toBe("ip");
    expect(detectType("192.168.1.1")).toBe("ip");
  });

  test("classifies IPv6 addresses as 'ip'", () => {
    expect(detectType("2001:4860:4860::8888")).toBe("ip");
  });

  test("classifies MD5 / SHA1 / SHA256 as 'hash'", () => {
    expect(detectType("d41d8cd98f00b204e9800998ecf8427e")).toBe("hash");
    expect(detectType("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toBe("hash");
    expect(detectType("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toBe("hash");
  });

  test("classifies bare hostnames as 'domain'", () => {
    expect(detectType("example.com")).toBe("domain");
    expect(detectType("sub.example.co.uk")).toBe("domain");
  });

  test("returns 'unknown' for inputs that match nothing", () => {
    expect(detectType("not a real input")).toBe("unknown");
    expect(detectType("")).toBe("unknown");
    expect(detectType("123")).toBe("unknown");
  });
});
