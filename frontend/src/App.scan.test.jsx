// Single-scan flow: input handling, the SSE loading state, streamed results and
// the error path. Every test drives the real component through the fake
// EventSource, so the assertions describe what a user would see.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, within, fireEvent } from "@testing-library/react";
import App, { ENGINE_ORDER } from "./App.jsx";
import {
  installEventSource,
  resetEventSources,
  lastEventSource,
  allEventSources,
  lastParams,
} from "./test/eventSource.js";

const scanButton = () => screen.getByRole("button", { name: /SCAN NOW|SCANNING/ });
// The placeholder tracks the detected type, so the textbox role is the stable
// handle; the scan tab renders exactly one.
const searchInput = () => screen.getByRole("textbox");

/** The card for one engine, positioned by ENGINE_ORDER inside the results grid. */
const engineCard = (id) =>
  document.querySelectorAll(".ts-engine-grid > div")[ENGINE_ORDER.indexOf(id)];

// Scoped to the results grid: the scan button and the live-verdict badge also
// read "SCANNING…", and neither is an engine card.
const scanningBadges = () =>
  within(document.querySelector(".ts-engine-grid")).getAllByText("SCANNING…", {
    selector: "span",
  });

/** The number drawn inside the threat gauge. */
const gaugeScore = () => document.querySelector(".ts-summary-inner svg text").textContent;

function typeQuery(value) {
  fireEvent.change(searchInput(), { target: { value } });
}

/** Enter a query and start a scan, returning the opened connection. */
function startScan(query = "8.8.8.8") {
  typeQuery(query);
  fireEvent.click(scanButton());
  return lastEventSource();
}

/** A representative `engine` event; the backend sends one per engine. */
function engineEvent(id, verdict, extra = {}) {
  return { id, verdict, ...extra };
}

beforeEach(() => {
  installEventSource();
  resetEventSources();
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("initial render", () => {
  it("shows the empty state until a scan starts", () => {
    render(<App />);
    expect(screen.getByText(/ENTER A URL, IP, HASH OR DOMAIN/)).toBeInTheDocument();
    expect(screen.queryByText("FINAL VERDICT")).not.toBeInTheDocument();
    expect(allEventSources()).toHaveLength(0);
  });

  it("disables the scan button while the query is empty", () => {
    render(<App />);
    expect(scanButton()).toBeDisabled();
  });

  it("fills the input from an example chip", () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: "8.8.8.8" }));
    expect(searchInput()).toHaveValue("8.8.8.8");
    expect(scanButton()).toBeEnabled();
  });
});

describe("input handling", () => {
  it("highlights the auto-detected type as the user types", () => {
    render(<App />);
    typeQuery("44d88612fea8a8f36de82e1278abb02f");
    expect(screen.getByRole("button", { name: "File Hash" })).toHaveStyle({
      background: "var(--green)",
    });
  });

  it("sends the detected type with the scan request", () => {
    render(<App />);
    startScan("malware.xyz");
    expect(lastParams()).toEqual({ query: "malware.xyz", type: "domain" });
  });

  it("lets a manual type override the detected one", () => {
    render(<App />);
    typeQuery("8.8.8.8");
    fireEvent.click(screen.getByRole("button", { name: "Domain" }));
    fireEvent.click(scanButton());
    expect(lastParams().type).toBe("domain");
  });

  it("resolves an unrecognised query to auto-detection at scan time", () => {
    render(<App />);
    startScan("hello world");
    expect(lastParams().type).toBe("auto");
  });

  it("trims the query before scanning", () => {
    render(<App />);
    startScan("   8.8.8.8   ");
    expect(lastParams()).toEqual({ query: "8.8.8.8", type: "ip" });
  });

  it("starts a scan on Enter", () => {
    render(<App />);
    typeQuery("8.8.8.8");
    fireEvent.keyDown(searchInput(), { key: "Enter" });
    expect(allEventSources()).toHaveLength(1);
  });

  it("ignores a scan request while the query is blank", () => {
    render(<App />);
    typeQuery("   ");
    fireEvent.keyDown(searchInput(), { key: "Enter" });
    expect(allEventSources()).toHaveLength(0);
  });

  it("opens the stream against the configured backend path", () => {
    render(<App />);
    const source = startScan("8.8.8.8");
    expect(source.url).toContain("/api/scan/stream?");
  });
});

describe("loading state", () => {
  it("shows a scanning card for every engine as soon as the scan starts", () => {
    render(<App />);
    startScan();
    expect(scanningBadges()).toHaveLength(10);
    expect(screen.getByText("VirusTotal")).toBeInTheDocument();
    expect(screen.getByText("ThreatFox")).toBeInTheDocument();
  });

  it("disables the button and swaps its label while scanning", () => {
    render(<App />);
    startScan();
    expect(scanButton()).toBeDisabled();
    expect(scanButton()).toHaveTextContent("SCANNING…");
  });

  it("does not open a second connection while one is in flight", () => {
    render(<App />);
    startScan();
    fireEvent.click(scanButton());
    expect(allEventSources()).toHaveLength(1);
  });

  it("tracks progress against the engine total from the start event", () => {
    render(<App />);
    const source = startScan();
    source.emit("start", { total: 10 });
    source.emit("engine", engineEvent("virustotal", "clean"));
    source.emit("engine", engineEvent("abuseipdb", "clean"));
    expect(screen.getByText("SCANNING 2/10 ENGINES…")).toBeInTheDocument();
    expect(screen.getByText("20%")).toBeInTheDocument();
  });

  it("falls back to ten engines when the start event omits a total", () => {
    render(<App />);
    const source = startScan();
    source.emit("start", {});
    source.emit("engine", engineEvent("virustotal", "clean"));
    expect(screen.getByText("SCANNING 1/10 ENGINES…")).toBeInTheDocument();
  });

  it("shows a live verdict before the scan finishes", () => {
    render(<App />);
    const source = startScan();
    source.emit("start", { total: 10 });
    source.emit("engine", engineEvent("virustotal", "malicious"));
    expect(screen.getByText("LIVE VERDICT")).toBeInTheDocument();
    expect(screen.queryByText("FINAL VERDICT")).not.toBeInTheDocument();
  });

  it("closes the previous connection when a new scan starts", () => {
    render(<App />);
    const first = startScan("8.8.8.8");
    first.emit("done", { verdict: "clean", score: 0 });
    expect(first.closed).toBe(true);
    startScan("1.1.1.1");
    expect(allEventSources()).toHaveLength(2);
  });
});

describe("results rendering", () => {
  it("replaces an engine's spinner with its verdict as the event arrives", () => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("virustotal", "malicious", { engines: 70, flagged: 12 }));

    const card = within(engineCard("virustotal"));
    expect(card.getByText("MALICIOUS")).toBeInTheDocument();
    expect(card.getByText("12/70")).toBeInTheDocument();
    expect(scanningBadges()).toHaveLength(9);
  });

  it("renders the per-engine detail fields the backend supplies", () => {
    render(<App />);
    const source = startScan();
    source.emit(
      "engine",
      engineEvent("abuseipdb", "suspicious", {
        confidence: 42,
        reports: 7,
        country: "US",
        city: "Ashburn",
      }),
    );
    expect(screen.getByText("42%")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("Ashburn, US")).toBeInTheDocument();
  });

  it("joins list-valued fields such as tags", () => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("threatfox", "malicious", { tags: ["cobaltstrike", "c2"] }));
    expect(screen.getByText("cobaltstrike, c2")).toBeInTheDocument();
  });

  it("links the URLScan screenshot when one is returned", () => {
    render(<App />);
    const source = startScan("https://example.com");
    source.emit(
      "engine",
      engineEvent("urlscan", "clean", { screenshot: "https://urlscan.io/shot.png" }),
    );
    expect(screen.getByAltText("URLScan screenshot")).toHaveAttribute(
      "src",
      "https://urlscan.io/shot.png",
    );
  });

  it("shows the final verdict and per-verdict counts when done", () => {
    render(<App />);
    const source = startScan();
    source.emit("start", { total: 10 });
    source.emit("engine", engineEvent("virustotal", "malicious"));
    source.emit("engine", engineEvent("urlhaus", "malicious"));
    source.emit("engine", engineEvent("abuseipdb", "suspicious"));
    source.emit("engine", engineEvent("ipinfo", "clean"));
    source.emit("done", { verdict: "malicious", score: 88 });

    expect(screen.getByText("FINAL VERDICT")).toBeInTheDocument();
    expect(screen.getByText("COMPLETE — 10 ENGINES")).toBeInTheDocument();

    const counts = document.querySelector(".ts-counts");
    const tally = Object.fromEntries(
      ["MALICIOUS", "SUSPICIOUS", "CLEAN"].map((label) => [
        label,
        within(counts).getByText(label).previousSibling.textContent,
      ]),
    );
    expect(tally).toEqual({ MALICIOUS: "2", SUSPICIOUS: "1", CLEAN: "1" });
  });

  it.each([
    [0, "LOW RISK"],
    [29, "LOW RISK"],
    [30, "MODERATE"],
    [69, "MODERATE"],
    [70, "HIGH RISK"],
    [100, "HIGH RISK"],
  ])("labels a score of %i as %s on the gauge", (score, label) => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("virustotal", "clean"));
    source.emit("done", { verdict: "clean", score });
    expect(screen.getByText(label)).toBeInTheDocument();
    expect(gaugeScore()).toBe(String(score));
  });

  it("closes the stream once the done event arrives", () => {
    render(<App />);
    const source = startScan();
    source.emit("done", { verdict: "clean", score: 0 });
    expect(source.closed).toBe(true);
    expect(scanButton()).toHaveTextContent("SCAN NOW");
  });

  it("clears previous results when a new scan starts", () => {
    render(<App />);
    const first = startScan("8.8.8.8");
    first.emit("engine", engineEvent("virustotal", "malicious", { engines: 70, flagged: 12 }));
    first.emit("done", { verdict: "malicious", score: 90 });
    expect(screen.getByText("12/70")).toBeInTheDocument();

    startScan("1.1.1.1");
    expect(screen.queryByText("12/70")).not.toBeInTheDocument();
    expect(screen.queryByText("FINAL VERDICT")).not.toBeInTheDocument();
    expect(scanningBadges()).toHaveLength(10);
  });
});

describe("error state", () => {
  it("surfaces a connection failure and re-enables the button", () => {
    render(<App />);
    const source = startScan();
    source.fail();
    expect(screen.getByText(/Connection error — please try again./)).toBeInTheDocument();
    expect(source.closed).toBe(true);
    expect(scanButton()).toBeEnabled();
  });

  it("clears a previous error when the next scan starts", () => {
    render(<App />);
    startScan("8.8.8.8").fail();
    expect(screen.getByText(/Connection error/)).toBeInTheDocument();
    startScan("1.1.1.1");
    expect(screen.queryByText(/Connection error/)).not.toBeInTheDocument();
  });

  it("keeps engine cards rendered so partial results survive the failure", () => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("virustotal", "clean", { engines: 70, flagged: 0 }));
    source.fail();
    expect(screen.getByText("0/70")).toBeInTheDocument();
  });

  it("renders an engine-level error verdict without breaking the grid", () => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("otx", "error", { detail: "upstream timeout" }));
    expect(within(engineCard("otx")).getByText("ERROR")).toBeInTheDocument();
    expect(screen.getByText("upstream timeout")).toBeInTheDocument();
  });

  it("renders a skipped engine for indicator types it does not support", () => {
    render(<App />);
    const source = startScan("44d88612fea8a8f36de82e1278abb02f");
    source.emit("engine", engineEvent("ipinfo", "skipped"));
    expect(within(engineCard("ipinfo")).getByText("SKIPPED")).toBeInTheDocument();
  });
});

describe("JSON export", () => {
  it("exports the completed scan as JSON", async () => {
    const blobs = [];
    URL.createObjectURL = vi.fn((blob) => {
      blobs.push(blob);
      return "blob:threatscan";
    });
    URL.revokeObjectURL = vi.fn();
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    render(<App />);
    const source = startScan("8.8.8.8");
    source.emit("engine", engineEvent("virustotal", "malicious", { engines: 70, flagged: 12 }));
    source.emit("done", {
      verdict: "malicious",
      score: 88,
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    fireEvent.click(screen.getByRole("button", { name: /EXPORT JSON/ }));

    expect(click).toHaveBeenCalled();
    const payload = JSON.parse(await blobs[0].text());
    expect(payload).toMatchObject({
      query: "8.8.8.8",
      type: "ip",
      verdict: "malicious",
      score: 88,
      scannedAt: "2026-01-01T00:00:00.000Z",
      fileName: null,
    });
    expect(payload.engines).toEqual([
      { id: "virustotal", verdict: "malicious", engines: 70, flagged: 12 },
    ]);
  });

  it("offers no export button until a scan completes", () => {
    render(<App />);
    const source = startScan();
    source.emit("engine", engineEvent("virustotal", "clean"));
    expect(screen.queryByRole("button", { name: /EXPORT JSON/ })).not.toBeInTheDocument();
  });
});
