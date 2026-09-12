// Bulk scan flow, reached through the `bulk` tab: the 20-query cap, the streamed
// results table, the summary bar and the CSV export.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, within, fireEvent } from "@testing-library/react";
import App from "./App.jsx";
import {
  installEventSource,
  resetEventSources,
  lastEventSource,
  allEventSources,
  lastParams,
} from "./test/eventSource.js";

const bulkInput = () => screen.getByRole("textbox");
const bulkButton = () => screen.getByRole("button", { name: /SCAN ALL|SCANNING/ });
const rows = () => within(screen.getByRole("table")).getAllByRole("row").slice(1);

/** Open the bulk tab on a freshly rendered App. */
function renderBulk() {
  render(<App />);
  fireEvent.click(screen.getByRole("button", { name: "bulk" }));
}

/** Paste queries and start the bulk scan, returning the opened connection. */
function startBulk(queries) {
  fireEvent.change(bulkInput(), { target: { value: queries.join("\n") } });
  fireEvent.click(bulkButton());
  return lastEventSource();
}

beforeEach(() => {
  installEventSource();
  resetEventSources();
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("bulk input", () => {
  it("starts empty with the scan button disabled", () => {
    renderBulk();
    expect(screen.getByText("⚡ BULK SCAN")).toBeInTheDocument();
    expect(bulkButton()).toBeDisabled();
    expect(screen.getByText("0/20")).toBeInTheDocument();
  });

  it("counts only non-blank lines", () => {
    renderBulk();
    fireEvent.change(bulkInput(), { target: { value: "8.8.8.8\n\n  \n1.1.1.1\n" } });
    expect(screen.getByText("2/20")).toBeInTheDocument();
  });

  it("accepts exactly twenty queries", () => {
    renderBulk();
    const queries = Array.from({ length: 20 }, (_, i) => `10.0.0.${i}`);
    fireEvent.change(bulkInput(), { target: { value: queries.join("\n") } });
    expect(screen.getByText("20/20")).toBeInTheDocument();
    expect(screen.queryByText(/Maximum 20 queries/)).not.toBeInTheDocument();
    expect(bulkButton()).toBeEnabled();
  });

  it("blocks the scan past twenty queries and says how many to remove", () => {
    renderBulk();
    const queries = Array.from({ length: 23 }, (_, i) => `10.0.0.${i}`);
    fireEvent.change(bulkInput(), { target: { value: queries.join("\n") } });
    expect(screen.getByText(/Maximum 20 queries — remove 3 lines/)).toBeInTheDocument();
    expect(bulkButton()).toBeDisabled();

    fireEvent.click(bulkButton());
    expect(allEventSources()).toHaveLength(0);
  });

  it("uses the singular when exactly one line is over the cap", () => {
    renderBulk();
    const queries = Array.from({ length: 21 }, (_, i) => `10.0.0.${i}`);
    fireEvent.change(bulkInput(), { target: { value: queries.join("\n") } });
    expect(screen.getByText(/remove 1 line$/)).toBeInTheDocument();
  });

  it("sends the pasted queries to the bulk endpoint", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz"]);
    expect(source.url).toContain("/api/scan/bulk?");
    expect(lastParams()).toEqual({ queries: "8.8.8.8\nmalware.xyz" });
  });
});

describe("bulk loading state", () => {
  it("pre-populates a scanning row per query from the start event", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz"]);
    source.emit("start", { queries: ["8.8.8.8", "malware.xyz"] });

    expect(rows()).toHaveLength(2);
    expect(within(rows()[0]).getByText("8.8.8.8")).toBeInTheDocument();
    expect(within(rows()[1]).getByText("malware.xyz")).toBeInTheDocument();
    expect(screen.getAllByText("SCANNING…", { selector: "span" })).toHaveLength(2);
    // Type and score both show a dash until the result lands.
    expect(within(rows()[0]).getAllByText("—", { selector: "td" })).toHaveLength(2);
  });

  it("disables the button and hides the export while scanning", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    expect(bulkButton()).toBeDisabled();
    expect(screen.queryByRole("button", { name: /EXPORT CSV/ })).not.toBeInTheDocument();
  });

  it("ignores a second click while a bulk scan is running", () => {
    renderBulk();
    startBulk(["8.8.8.8"]);
    fireEvent.click(bulkButton());
    expect(allEventSources()).toHaveLength(1);
  });
});

describe("bulk results", () => {
  it("fills each row in place as its result streams back", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz"]);
    source.emit("start", { queries: ["8.8.8.8", "malware.xyz"] });
    source.emit("result", { index: 1, type: "domain", verdict: "malicious", score: 91 });

    const second = within(rows()[1]);
    expect(second.getByText("MALICIOUS")).toBeInTheDocument();
    expect(second.getByText("DOMAIN")).toBeInTheDocument();
    expect(second.getByText("91")).toBeInTheDocument();
    // The untouched row keeps its spinner.
    expect(within(rows()[0]).getByText("SCANNING…")).toBeInTheDocument();
  });

  it("renders a zero score when the result omits one", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    source.emit("result", { index: 0, type: "ip", verdict: "clean" });
    expect(within(rows()[0]).getByText("0")).toBeInTheDocument();
  });

  it("shows the summary tallies and offers the export when done", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz", "1.1.1.1"]);
    source.emit("start", { queries: ["8.8.8.8", "malware.xyz", "1.1.1.1"] });
    source.emit("result", { index: 0, type: "ip", verdict: "clean", score: 0 });
    source.emit("result", { index: 1, type: "domain", verdict: "malicious", score: 91 });
    source.emit("result", { index: 2, type: "ip", verdict: "suspicious", score: 44 });
    source.emit("done", { total: 3, malicious: 1, suspicious: 1, clean: 1 });

    expect(screen.getByText("SCAN COMPLETE — 3 QUERIES")).toBeInTheDocument();
    expect(source.closed).toBe(true);
    expect(bulkButton()).toBeEnabled();
    expect(screen.getByRole("button", { name: /EXPORT CSV/ })).toBeInTheDocument();
  });

  it("keeps rows from the previous run out of a new one", () => {
    renderBulk();
    const first = startBulk(["8.8.8.8"]);
    first.emit("start", { queries: ["8.8.8.8"] });
    first.emit("result", { index: 0, type: "ip", verdict: "clean", score: 0 });
    first.emit("done", { total: 1, malicious: 0, suspicious: 0, clean: 1 });

    const second = startBulk(["malware.xyz"]);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText(/SCAN COMPLETE/)).not.toBeInTheDocument();
    second.emit("start", { queries: ["malware.xyz"] });
    expect(rows()).toHaveLength(1);
  });
});

describe("bulk error state", () => {
  it("surfaces a connection failure and re-enables the button", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.fail();
    expect(screen.getByText(/Connection error — please try again./)).toBeInTheDocument();
    expect(source.closed).toBe(true);
    expect(bulkButton()).toBeEnabled();
  });

  it("keeps already-streamed rows visible after a failure", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz"]);
    source.emit("start", { queries: ["8.8.8.8", "malware.xyz"] });
    source.emit("result", { index: 0, type: "ip", verdict: "clean", score: 0 });
    source.fail();
    expect(rows()).toHaveLength(2);
    expect(screen.getByRole("button", { name: /EXPORT CSV/ })).toBeInTheDocument();
  });
});

describe("CSV export", () => {
  function captureDownload() {
    const blobs = [];
    URL.createObjectURL = vi.fn((blob) => {
      blobs.push(blob);
      return "blob:threatscan";
    });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    return blobs;
  }

  it("writes a header row plus one row per completed query", async () => {
    const blobs = captureDownload();
    renderBulk();
    const source = startBulk(["8.8.8.8", "malware.xyz"]);
    source.emit("start", { queries: ["8.8.8.8", "malware.xyz"] });
    source.emit("result", {
      index: 0,
      query: "8.8.8.8",
      type: "ip",
      verdict: "clean",
      score: 0,
      malicious: 0,
      suspicious: 0,
      clean: 8,
      cached: false,
    });
    source.emit("done", { total: 2, malicious: 0, suspicious: 0, clean: 1 });

    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    const csv = await blobs[0].text();
    const lines = csv.split("\n");

    expect(lines[0]).toBe("Query,Type,Verdict,Score,Malicious,Suspicious,Clean,Cached");
    // Only the finished query is exported; the still-scanning row is skipped.
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe("8.8.8.8,ip,clean,0,0,0,8,false");
  });

  it("exports as text/csv", async () => {
    const blobs = captureDownload();
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    source.emit("result", { index: 0, query: "8.8.8.8", type: "ip", verdict: "clean", score: 0 });
    source.emit("done", { total: 1, malicious: 0, suspicious: 0, clean: 1 });

    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    expect(blobs[0].type).toBe("text/csv");
  });
});
