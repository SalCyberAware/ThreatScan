// Pure-logic specs: no DOM, no network, no React.
//
// detectInputType decides which indicator type the UI sends to the backend, and
// hashFile produces the SHA256 that the file-drop flow scans instead of the file
// itself. Both are the highest-value things to pin down, because every scan
// starts with one of them.
import { describe, it, expect } from "vitest";
import { detectInputType, hashFile, ENGINE_ORDER, ENGINE_META, TYPES } from "./App.jsx";

describe("detectInputType", () => {
  it("falls back to auto for empty or whitespace-only input", () => {
    expect(detectInputType("")).toBe("auto");
    expect(detectInputType("   ")).toBe("auto");
    expect(detectInputType(null)).toBe("auto");
    expect(detectInputType(undefined)).toBe("auto");
  });

  it.each([
    ["https://example.com", "url"],
    ["http://example.com/path?q=1", "url"],
    ["HTTPS://EXAMPLE.COM", "url"],
    ["https://8.8.8.8/payload.bin", "url"],
  ])("classifies %s as a URL", (input, expected) => {
    expect(detectInputType(input)).toBe(expected);
  });

  it.each([
    ["8.8.8.8", "ip"],
    ["192.168.1.1", "ip"],
    ["0.0.0.0", "ip"],
    ["2001:db8::1", "ip"],
    ["fe80:0000:0000:0000:0202:b3ff:fe1e:8329", "ip"],
  ])("classifies %s as an IP", (input, expected) => {
    expect(detectInputType(input)).toBe(expected);
  });

  it.each([
    ["44d88612fea8a8f36de82e1278abb02f", "hash"], // MD5, 32 hex
    ["3395856ce81f2b7382dee72602f798b642f14140", "hash"], // SHA1, 40 hex
    ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "hash"], // SHA256
    ["44D88612FEA8A8F36DE82E1278ABB02F", "hash"], // case-insensitive
  ])("classifies %s as a hash", (input, expected) => {
    expect(detectInputType(input)).toBe(expected);
  });

  it.each([
    ["malware.xyz", "domain"],
    ["sub.domain.example.com", "domain"],
    ["xn--80ak6aa92e.com", "domain"],
    ["a-b.co", "domain"],
  ])("classifies %s as a domain", (input, expected) => {
    expect(detectInputType(input)).toBe(expected);
  });

  it.each([
    ["hello world"],
    ["1234"],
    ["example"],
    ["zzz.1"], // TLD must be alphabetic
    ["44d88612fea8a8f36de82e1278abb02"], // 31 hex: no hash length matches
  ])("returns auto for unrecognised input %s", (input) => {
    expect(detectInputType(input)).toBe("auto");
  });

  it("trims surrounding whitespace before matching", () => {
    expect(detectInputType("  8.8.8.8  ")).toBe("ip");
    expect(detectInputType("\n malware.xyz \t")).toBe("domain");
  });

  it("prefers the URL match over the host inside it", () => {
    // URL_RE is tested first, so a URL wrapping an IP or domain stays a URL.
    expect(detectInputType("https://malware.xyz")).toBe("url");
    expect(detectInputType("http://8.8.8.8")).toBe("url");
  });

  it("is deliberately lenient about octet ranges", () => {
    // The regex checks shape, not value, and the backend re-detects server-side.
    // Pinned so a future tightening of IP_RE is a conscious change, not a surprise.
    expect(detectInputType("999.999.999.999")).toBe("ip");
  });
});

describe("hashFile", () => {
  it("returns the SHA256 of the file contents as lowercase hex", async () => {
    const file = new File(["hello"], "greeting.txt", { type: "text/plain" });
    await expect(hashFile(file)).resolves.toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("hashes an empty file to the well-known empty digest", async () => {
    const file = new File([], "empty.bin");
    await expect(hashFile(file)).resolves.toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("hashes binary content and always emits 64 zero-padded hex chars", async () => {
    // Bytes below 0x10 are the ones a missing padStart would truncate.
    const file = new File([new Uint8Array([0, 1, 2, 15, 255])], "bin");
    const digest = await hashFile(file);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("depends only on content, not on file name or type", async () => {
    const a = new File(["same"], "a.txt", { type: "text/plain" });
    const b = new File(["same"], "b.exe", { type: "application/octet-stream" });
    expect(await hashFile(a)).toBe(await hashFile(b));
  });
});

describe("engine + type metadata", () => {
  it("orders the ten engines the scan grid renders", () => {
    expect(ENGINE_ORDER).toHaveLength(10);
    expect(ENGINE_ORDER).toEqual(Object.keys(ENGINE_META));
  });

  it("gives every engine a display name and icon", () => {
    for (const id of ENGINE_ORDER) {
      expect(ENGINE_META[id].name).toBeTruthy();
      expect(ENGINE_META[id].icon).toBeTruthy();
    }
  });

  it("offers a selectable chip for every type detectInputType can return", () => {
    const ids = TYPES.map((t) => t.id);
    expect(ids).toContain("auto");
    for (const probe of ["https://a.com", "8.8.8.8", "44d88612fea8a8f36de82e1278abb02f", "a.com"]) {
      expect(ids).toContain(detectInputType(probe));
    }
  });

  it("gives every type chip a placeholder for the search input", () => {
    for (const type of TYPES) {
      expect(type.label).toBeTruthy();
      expect(type.placeholder).toBeTruthy();
    }
  });
});
