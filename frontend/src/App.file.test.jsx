// File drop (local SHA256 hashing), scan history persistence, the trends
// ranking and tab navigation.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, within, fireEvent, waitFor } from "@testing-library/react";
import App from "./App.jsx";
import { installEventSource, resetEventSources, lastEventSource } from "./test/eventSource.js";

const HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
// 1536 bytes, so the dropzone reports a non-zero "1.5 KB".
const SIZED_BODY = "a".repeat(1536);
const SIZED_SHA256 = "eeb66bf335f247ae90ee2eb780c21a12725c5f3724c9b0c8378f6fee84a9d13c";

const searchInput = () => screen.getByRole("textbox");
const dropzone = () => document.querySelector(".ts-dropzone");
const fileInput = () => document.querySelector('input[type="file"]');
const tab = (name) => screen.getByRole("button", { name });

function dropFile(file) {
  fireEvent.drop(dropzone(), { dataTransfer: { files: [file] } });
}

/** Run a scan to completion so it lands in history. */
function completeScan(query, { verdict = "clean", score = 0 } = {}) {
  fireEvent.change(searchInput(), { target: { value: query } });
  fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
  lastEventSource().emit("done", { verdict, score });
}

beforeEach(() => {
  installEventSource();
  resetEventSources();
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("file drop", () => {
  it("hashes a dropped file locally and puts the digest in the query box", async () => {
    render(<App />);
    dropFile(new File(["hello"], "sample.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(HELLO_SHA256));
  });

  it("never opens a connection while hashing — the file stays on the device", async () => {
    render(<App />);
    dropFile(new File(["hello"], "sample.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(HELLO_SHA256));
    expect(lastEventSource()).toBeUndefined();
  });

  it("scans the hash rather than the file", async () => {
    render(<App />);
    dropFile(new File(["hello"], "sample.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(HELLO_SHA256));

    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    const params = Object.fromEntries(
      new URLSearchParams(lastEventSource().url.split("?")[1]),
    );
    expect(params).toEqual({ query: HELLO_SHA256, type: "hash" });
  });

  it("accepts a file chosen through the hidden file input", async () => {
    render(<App />);
    fireEvent.change(fileInput(), { target: { files: [new File(["hello"], "picked.bin")] } });
    await waitFor(() => expect(searchInput()).toHaveValue(HELLO_SHA256));
  });

  it("ignores a drop that carries no file", () => {
    render(<App />);
    dropFile(undefined);
    expect(searchInput()).toHaveValue("");
  });

  it("reports a hashing failure instead of scanning", async () => {
    vi.spyOn(crypto.subtle, "digest").mockRejectedValue(new Error("no subtle crypto"));
    render(<App />);
    dropFile(new File(["hello"], "sample.bin"));
    expect(
      await screen.findByText(/Could not hash file — try a different file./),
    ).toBeInTheDocument();
    expect(searchInput()).toHaveValue("");
  });

  it("shows the dropped file name, size and digest in the dropzone", async () => {
    render(<App />);
    dropFile(new File([SIZED_BODY], "payload.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(SIZED_SHA256));

    const card = within(dropzone());
    expect(card.getByText("📄 payload.bin (1.5 KB)")).toBeInTheDocument();
    expect(card.getByText(`SHA256: ${SIZED_SHA256}`)).toBeInTheDocument();
    expect(card.getByText(/Click or drop another file to replace/)).toBeInTheDocument();
    expect(card.queryByText("DROP A FILE TO SCAN")).not.toBeInTheDocument();
  });

  it("keeps the file card visible while the hash scans", async () => {
    render(<App />);
    dropFile(new File([SIZED_BODY], "payload.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(SIZED_SHA256));

    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    lastEventSource().emit("engine", { id: "virustotal", verdict: "malicious" });
    expect(within(dropzone()).getByText("📄 payload.bin (1.5 KB)")).toBeInTheDocument();
    // The summary names the file and keeps the digest underneath it.
    const summary = within(document.querySelector(".ts-summary-inner"));
    expect(summary.getByText("payload.bin")).toBeInTheDocument();
    expect(summary.getByText(SIZED_SHA256)).toBeInTheDocument();
  });

  it("clears the file card once the user types a different query", async () => {
    render(<App />);
    dropFile(new File([SIZED_BODY], "payload.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(SIZED_SHA256));

    fireEvent.change(searchInput(), { target: { value: "8.8.8.8" } });
    expect(within(dropzone()).getByText("DROP A FILE TO SCAN")).toBeInTheDocument();
    expect(screen.queryByText(/payload.bin/)).not.toBeInTheDocument();
  });

  it("toggles the drag-over styling while a file hovers the dropzone", () => {
    render(<App />);
    fireEvent.dragOver(dropzone());
    expect(dropzone().className).toContain("drag-over");
    fireEvent.dragLeave(dropzone());
    expect(dropzone().className).not.toContain("drag-over");
  });
});

describe("scan history", () => {
  it("records a completed scan in localStorage", () => {
    render(<App />);
    completeScan("8.8.8.8", { verdict: "clean", score: 4 });

    const stored = JSON.parse(localStorage.getItem("ts_history"));
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({
      query: "8.8.8.8",
      label: "8.8.8.8",
      type: "ip",
      verdict: "clean",
      score: 4,
    });
    expect(stored[0].time).toEqual(expect.any(String));
  });

  it("does not record a scan that never finished", () => {
    render(<App />);
    fireEvent.change(searchInput(), { target: { value: "8.8.8.8" } });
    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    lastEventSource().fail();
    expect(localStorage.getItem("ts_history")).toBeNull();
  });

  it("puts the newest scan first and keeps at most twenty", () => {
    render(<App />);
    for (let i = 0; i < 21; i++) {
      completeScan(`10.0.0.${i}`, { score: i });
    }
    const stored = JSON.parse(localStorage.getItem("ts_history"));
    expect(stored).toHaveLength(20);
    expect(stored[0].query).toBe("10.0.0.20");
  });

  it("lists stored scans on the history tab", () => {
    localStorage.setItem(
      "ts_history",
      JSON.stringify([
        { query: "malware.xyz", label: "malware.xyz", type: "domain", verdict: "malicious", score: 91, time: "10:00:00" },
      ]),
    );
    render(<App />);
    fireEvent.click(tab("history"));
    expect(screen.getByText("malware.xyz")).toBeInTheDocument();
    expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
    expect(screen.getByText("91/100")).toBeInTheDocument();
    expect(screen.getByText("DOMAIN")).toBeInTheDocument();
  });

  it("shows an empty state when nothing has been scanned", () => {
    render(<App />);
    fireEvent.click(tab("history"));
    expect(screen.getByText("NO SCANS YET")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "CLEAR" })).not.toBeInTheDocument();
  });

  it("re-runs a history entry back on the scan tab", () => {
    render(<App />);
    completeScan("malware.xyz", { verdict: "malicious", score: 91 });
    fireEvent.click(tab("history"));
    fireEvent.click(screen.getByText("malware.xyz"));
    expect(searchInput()).toHaveValue("malware.xyz");
  });

  it("clears history from both the list and localStorage", () => {
    render(<App />);
    completeScan("8.8.8.8");
    fireEvent.click(tab("history"));
    fireEvent.click(screen.getByRole("button", { name: "CLEAR" }));
    expect(screen.getByText("NO SCANS YET")).toBeInTheDocument();
    expect(localStorage.getItem("ts_history")).toBeNull();
  });

  it("starts empty when the stored history is corrupt", () => {
    localStorage.setItem("ts_history", "{not json");
    render(<App />);
    fireEvent.click(tab("history"));
    expect(screen.getByText("NO SCANS YET")).toBeInTheDocument();
  });
});

describe("trends", () => {
  it("ranks session scans by score, highest first", () => {
    localStorage.setItem(
      "ts_history",
      JSON.stringify([
        { query: "low.example", label: "low.example", type: "domain", verdict: "clean", score: 3, time: "10:02:00" },
        { query: "high.example", label: "high.example", type: "domain", verdict: "malicious", score: 97, time: "10:00:00" },
        { query: "mid.example", label: "mid.example", type: "domain", verdict: "suspicious", score: 40, time: "10:01:00" },
      ]),
    );
    render(<App />);
    fireEvent.click(tab("trends"));

    const ranked = screen
      .getAllByText(/\.example$/)
      .map((node) => node.textContent);
    expect(ranked).toEqual(["high.example", "mid.example", "low.example"]);
  });

  it("treats a missing score as zero rather than dropping the entry", () => {
    localStorage.setItem(
      "ts_history",
      JSON.stringify([{ query: "noscore.example", label: "noscore.example", verdict: "clean", time: "10:00:00" }]),
    );
    render(<App />);
    fireEvent.click(tab("trends"));
    expect(screen.getByText("noscore.example")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.getByText("AUTO")).toBeInTheDocument();
  });

  it("prompts for a scan when there is no history", () => {
    render(<App />);
    fireEvent.click(tab("trends"));
    expect(screen.getByText("NO SCANS YET — RUN SOME SCANS FIRST")).toBeInTheDocument();
  });
});

describe("tab navigation", () => {
  it("switches between the five tabs", () => {
    render(<App />);
    fireEvent.click(tab("bulk"));
    expect(screen.getByText("⚡ BULK SCAN")).toBeInTheDocument();

    fireEvent.click(tab("about"));
    expect(screen.getByText("ℹ ABOUT THREATSCAN")).toBeInTheDocument();
    expect(screen.getByText("🔍 What is ThreatScan?")).toBeInTheDocument();

    fireEvent.click(tab("trends"));
    expect(screen.getByText("🔥 TRENDING THREATS")).toBeInTheDocument();

    fireEvent.click(tab("history"));
    expect(screen.getByText("📋 SCAN HISTORY")).toBeInTheDocument();

    fireEvent.click(tab("scan"));
    expect(screen.getByRole("button", { name: /SCAN NOW/ })).toBeInTheDocument();
  });

  it("keeps in-flight scan results when the user leaves and returns", () => {
    render(<App />);
    fireEvent.change(searchInput(), { target: { value: "8.8.8.8" } });
    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    lastEventSource().emit("engine", { id: "virustotal", verdict: "malicious", engines: 70, flagged: 12 });

    fireEvent.click(tab("about"));
    fireEvent.click(tab("scan"));
    expect(screen.getByText("12/70")).toBeInTheDocument();
  });

  it("marks the active tab", () => {
    render(<App />);
    fireEvent.click(tab("bulk"));
    expect(tab("bulk")).toHaveStyle({ color: "var(--green)" });
    expect(tab("scan")).toHaveStyle({ color: "var(--text2)" });
  });
});

describe("history rendering details", () => {
  it("shows the file name for a hash scanned from a dropped file", async () => {
    render(<App />);
    dropFile(new File(["hello"], "sample.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(HELLO_SHA256));

    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    lastEventSource().emit("done", { verdict: "clean", score: 0 });

    const stored = JSON.parse(localStorage.getItem("ts_history"));
    expect(stored[0].query).toBe(HELLO_SHA256);
    expect(stored[0].type).toBe("hash");
  });

  it("labels a file scan with the file name instead of the digest", async () => {
    render(<App />);
    dropFile(new File([SIZED_BODY], "payload.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(SIZED_SHA256));

    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    lastEventSource().emit("done", { verdict: "malicious", score: 91 });

    const stored = JSON.parse(localStorage.getItem("ts_history"));
    expect(stored[0]).toMatchObject({
      query: SIZED_SHA256,
      label: "payload.bin",
      type: "hash",
      verdict: "malicious",
    });

    // And the history list shows that name rather than 64 hex characters.
    fireEvent.click(tab("history"));
    expect(screen.getByText("payload.bin")).toBeInTheDocument();
    expect(screen.queryByText(SIZED_SHA256)).not.toBeInTheDocument();
  });

  it("names the file in the exported JSON", async () => {
    const blobs = [];
    URL.createObjectURL = vi.fn((blob) => {
      blobs.push(blob);
      return "blob:threatscan";
    });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    render(<App />);
    dropFile(new File([SIZED_BODY], "payload.bin"));
    await waitFor(() => expect(searchInput()).toHaveValue(SIZED_SHA256));

    fireEvent.click(screen.getByRole("button", { name: /SCAN NOW/ }));
    // The summary, and with it the export button, appears once an engine reports.
    lastEventSource().emit("engine", { id: "virustotal", verdict: "malicious" });
    lastEventSource().emit("done", { verdict: "malicious", score: 91 });
    fireEvent.click(screen.getByRole("button", { name: /EXPORT JSON/ }));

    const payload = JSON.parse(await blobs[0].text());
    expect(payload).toMatchObject({ fileName: "payload.bin", query: SIZED_SHA256, type: "hash" });
  });

  it("falls back to the raw query when an entry has no label", () => {
    localStorage.setItem(
      "ts_history",
      JSON.stringify([{ query: "8.8.8.8", verdict: "clean", score: 0, time: "10:00:00" }]),
    );
    render(<App />);
    fireEvent.click(tab("history"));
    const list = screen.getByText("📋 SCAN HISTORY").closest("div").parentElement;
    expect(within(list).getByText("8.8.8.8")).toBeInTheDocument();
  });
});
