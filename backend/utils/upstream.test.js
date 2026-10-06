const { DEFAULT_TIMEOUT, pathSegment, withTimeout } = require("./upstream");

describe("pathSegment", () => {
  test("leaves ordinary indicators unchanged", () => {
    expect(pathSegment("8.8.8.8")).toBe("8.8.8.8");
    expect(pathSegment("example.com")).toBe("example.com");
    expect(pathSegment("d41d8cd98f00b204e9800998ecf8427e")).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });

  test("keeps IPv6 colons literal so IPv6 lookups are unchanged", () => {
    expect(pathSegment("2001:db8::1")).toBe("2001:db8::1");
  });

  test("encodes characters that would change the upstream path or query", () => {
    expect(pathSegment("1.2.3.4/../../admin")).toBe("1.2.3.4%2F..%2F..%2Fadmin");
    expect(pathSegment("a.com?x=1#frag")).toBe("a.com%3Fx%3D1%23frag");
    expect(pathSegment("a b")).toBe("a%20b");
  });

  test("refuses dot segments, which encoding alone does not neutralise", () => {
    expect(() => pathSegment(".")).toThrow("Invalid indicator");
    expect(() => pathSegment("..")).toThrow("Invalid indicator");
  });
});

describe("withTimeout", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  test("aborts the signal handed to the engine when the timeout fires", async () => {
    let seen;
    const p = withTimeout("slow", signal => { seen = signal; return new Promise(() => {}); }, 1000);
    const assertion = expect(p).rejects.toThrow("slow timeout");
    expect(seen.aborted).toBe(false);
    await jest.advanceTimersByTimeAsync(1000);
    await assertion;
    expect(seen.aborted).toBe(true);
  });

  test("resolves with the engine result and never aborts when it finishes first", async () => {
    let seen;
    const result = await withTimeout("fast", signal => { seen = signal; return Promise.resolve({ verdict: "clean" }); }, 1000);
    expect(result).toEqual({ verdict: "clean" });
    expect(jest.getTimerCount()).toBe(0);
    await jest.advanceTimersByTimeAsync(5000);
    expect(seen.aborted).toBe(false);
  });

  test("propagates an engine error without aborting", async () => {
    let seen;
    await expect(withTimeout("bad", signal => { seen = signal; return Promise.reject(new Error("boom")); }, 1000))
      .rejects.toThrow("boom");
    expect(seen.aborted).toBe(false);
  });

  test("DEFAULT_TIMEOUT is a finite, positive number", () => {
    expect(Number.isFinite(DEFAULT_TIMEOUT)).toBe(true);
    expect(DEFAULT_TIMEOUT).toBeGreaterThan(0);
  });
});
