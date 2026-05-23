jest.mock("axios");
const axios = require("axios");
const greynoise = require("./greynoise");

describe("greynoise.scanIp", () => {
  beforeEach(() => axios.get.mockReset());

  test("returns 'malicious' when classification is 'malicious'", async () => {
    axios.get.mockResolvedValueOnce({ data: {
      classification: "malicious", name: "Mirai", noise: true, riot: false,
    } });
    const result = await greynoise.scanIp("1.2.3.4");
    expect(result.verdict).toBe("malicious");
    expect(result.classification).toBe("malicious");
    expect(result.name).toBe("Mirai");
  });

  test("returns 'clean' when classification is 'benign'", async () => {
    axios.get.mockResolvedValueOnce({ data: { classification: "benign" } });
    expect((await greynoise.scanIp("8.8.8.8")).verdict).toBe("clean");
  });

  test("returns 'info' when classification is unknown/other", async () => {
    axios.get.mockResolvedValueOnce({ data: { classification: "unknown" } });
    expect((await greynoise.scanIp("1.1.1.1")).verdict).toBe("info");
  });

  test("maps 404 to 'clean' with 'Not seen by GreyNoise'", async () => {
    const err = new Error("Not Found");
    err.response = { status: 404 };
    axios.get.mockRejectedValueOnce(err);
    const result = await greynoise.scanIp("9.9.9.9");
    expect(result.verdict).toBe("clean");
    expect(result.detail).toMatch(/not seen/i);
  });

  test("rethrows non-404 errors", async () => {
    const err = new Error("Server boom");
    err.response = { status: 500 };
    axios.get.mockRejectedValueOnce(err);
    await expect(greynoise.scanIp("1.2.3.4")).rejects.toThrow("Server boom");
  });
});

describe("greynoise non-IP methods", () => {
  test("scanUrl / scanHash / scanDomain return 'info'", async () => {
    expect((await greynoise.scanUrl()).verdict).toBe("info");
    expect((await greynoise.scanHash()).verdict).toBe("info");
    expect((await greynoise.scanDomain()).verdict).toBe("info");
  });
});
