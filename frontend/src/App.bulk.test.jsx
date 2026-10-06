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

// Issue #31: input matching no indicator type comes back as an "invalid" row
// with no score. It must never render or export as clean.
const INVALID = ["=1+1", "@SUM(1)", "localhost"];
const invalidRow = (index, query) => ({
  index, query, type: "unknown", verdict: "invalid",
  detail: "Could not detect input type.", cached: false,
});

/** Stream the three undetectable queries plus one scanned domain, then finish. */
function streamMixedBatch() {
  const queries = [...INVALID, "example.com"];
  const source = startBulk(queries);
  source.emit("start", { queries });
  INVALID.forEach((q, i) => source.emit("result", invalidRow(i, q)));
  source.emit("result", {
    index: 3, query: "example.com", type: "domain", verdict: "clean",
    score: 0, malicious: 0, suspicious: 0, clean: 7, cached: false,
  });
  source.emit("done", { total: 4, malicious: 0, suspicious: 0, clean: 1, invalid: 3 });
  return source;
}

describe("bulk invalid rows", () => {
  it.each(INVALID.map((q, i) => [q, i]))(
    "%s shows an INVALID badge, the reason and no score",
    (query, i) => {
      renderBulk();
      streamMixedBatch();
      const row = within(rows()[i]);
      expect(row.getByText(query)).toBeInTheDocument();
      expect(row.getByText("INVALID")).toBeInTheDocument();
      expect(row.getByText("Could not detect input type.")).toBeInTheDocument();
      expect(row.getByText("UNKNOWN")).toBeInTheDocument();
      expect(row.queryByText("CLEAN")).not.toBeInTheDocument();
      expect(row.queryByText("0")).not.toBeInTheDocument();
      expect(row.getByText("—", { selector: "td" })).toBeInTheDocument();
    }
  );

  it("keeps the scanned row normal and tallies invalid apart from clean", () => {
    renderBulk();
    streamMixedBatch();
    const last = within(rows()[3]);
    expect(last.getByText("CLEAN")).toBeInTheDocument();
    expect(last.getByText("0")).toBeInTheDocument();
    expect(last.queryByText("Could not detect input type.")).not.toBeInTheDocument();

    const bar = within(screen.getByText("SCAN COMPLETE — 4 QUERIES").parentElement);
    const tally = label => bar.getByText(label).previousSibling.textContent;
    expect(tally("CLEAN")).toBe("1");
    expect(tally("INVALID")).toBe("3");
  });

  it("omits the INVALID tally when every query was scannable", () => {
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    source.emit("result", { index: 0, type: "ip", verdict: "clean", score: 0 });
    source.emit("done", { total: 1, malicious: 0, suspicious: 0, clean: 1, invalid: 0 });
    expect(screen.queryByText("INVALID")).not.toBeInTheDocument();
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

  // Issue #3: fields were written bare, so one comma in a query shifted every
  // later column in that row -- a corrupted export rather than a failed one.
  it("quotes fields containing a comma, a quote or a newline (RFC 4180)", async () => {
    const blobs = captureDownload();
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    source.emit("result", {
      index: 0,
      query: 'evil.com/a,b"c\nd',
      type: "domain",
      verdict: "malicious",
      score: 90,
      malicious: 3,
      suspicious: 1,
      clean: 0,
      cached: false,
    });
    source.emit("done", { total: 1, malicious: 1, suspicious: 0, clean: 0 });

    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    const csv = await blobs[0].text();

    // The query is wrapped in quotes and its embedded quote is doubled; the
    // other fields need no quoting and stay bare, which RFC 4180 §2.5 allows.
    expect(csv).toBe(
      "Query,Type,Verdict,Score,Malicious,Suspicious,Clean,Cached\n" +
      '"evil.com/a,b""c\nd",domain,malicious,90,3,1,0,false'
    );
  });

  it("round-trips a comma-bearing query without shifting columns", async () => {
    const blobs = captureDownload();
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    const query = 'evil.com/a,b"c\nd';
    source.emit("result", {
      index: 0, query, type: "domain", verdict: "malicious",
      score: 90, malicious: 3, suspicious: 1, clean: 0, cached: false,
    });
    source.emit("done", { total: 1, malicious: 1, suspicious: 0, clean: 0 });

    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    const records = parseCSV(await blobs[0].text());

    // Two records, and the data row still has exactly its eight columns with the
    // query intact -- the column shift this issue reported cannot happen.
    expect(records).toHaveLength(2);
    expect(records[1]).toEqual([
      query, "domain", "malicious", "90", "3", "1", "0", "false",
    ]);
  });

  // Formula injection: a cell starting with =, +, -, @, tab or CR is run as a
  // formula by spreadsheets. The bulk endpoint echoes undetectable input such
  // as "=1+1" back as a result row, so the query column is attacker text.
  async function exportQuery(query) {
    const blobs = captureDownload();
    renderBulk();
    const source = startBulk(["8.8.8.8"]);
    source.emit("start", { queries: ["8.8.8.8"] });
    source.emit("result", {
      index: 0, query, type: "unknown", verdict: "clean",
      score: 0, malicious: 0, suspicious: 0, clean: 0, cached: false,
    });
    source.emit("done", { total: 1, malicious: 0, suspicious: 0, clean: 1 });
    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    return blobs[0].text();
  }

  it.each([
    ["=", '=HYPERLINK("http://evil.example","x")'],
    ["+", "+1+cmd|' /C calc'!A0"],
    ["-", "-2+3"],
    ["@", "@SUM(1+1)"],
    ["tab", "\t=1+1"],
    ["carriage return", "\r=1+1"],
  ])("neutralizes a cell starting with %s: apostrophe prefix and quoted", async (_label, query) => {
    const csv = await exportQuery(query);
    const dataLine = csv.slice(csv.indexOf("\n") + 1);
    expect(dataLine.startsWith(`"'${query.replace(/"/g, '""')}"`)).toBe(true);
    // Parsed back, the cell is the original text behind one apostrophe, and the
    // row keeps its eight columns.
    const records = parseCSV(csv);
    expect(records).toHaveLength(2);
    expect(records[1]).toHaveLength(8);
    expect(records[1][0]).toBe(`'${query}`);
  });

  it("leaves ordinary fields and mid-string formula characters untouched", async () => {
    const csv = await exportQuery("evil-site.com");
    expect(csv.split("\n")[1]).toBe("evil-site.com,unknown,clean,0,0,0,0,false");
  });
});

describe("CSV export of invalid rows", () => {
  it("writes verdict invalid with empty score and counts, and neutralizes formulas", async () => {
    const blobs = [];
    URL.createObjectURL = vi.fn((blob) => { blobs.push(blob); return "blob:threatscan"; });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    renderBulk();
    streamMixedBatch();
    fireEvent.click(screen.getByRole("button", { name: /EXPORT CSV/ }));
    const csv = await blobs[0].text();

    expect(csv).toBe(
      "Query,Type,Verdict,Score,Malicious,Suspicious,Clean,Cached\n" +
      `"'=1+1",unknown,invalid,,,,,false\n` +
      `"'@SUM(1)",unknown,invalid,,,,,false\n` +
      "localhost,unknown,invalid,,,,,false\n" +
      "example.com,domain,clean,0,0,0,7,false"
    );
    const records = parseCSV(csv);
    expect(records.slice(1, 4).map(r => [r[0], r[2], r[3]])).toEqual([
      ["'=1+1", "invalid", ""], ["'@SUM(1)", "invalid", ""], ["localhost", "invalid", ""],
    ]);
  });
});

/** Minimal RFC 4180 reader, so the export is checked by parsing rather than by
 *  splitting on commas -- which is the very assumption the bug broke. */
function parseCSV(text) {
  const records = [[""]];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const rec = records[records.length - 1];
    if (inQuotes) {
      if (c === '"' && text[i + 1] === '"') { rec[rec.length - 1] += '"'; i++; }
      else if (c === '"') inQuotes = false;
      else rec[rec.length - 1] += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") rec.push("");
    else if (c === "\n") records.push([""]);
    else rec[rec.length - 1] += c;
  }
  return records;
}
