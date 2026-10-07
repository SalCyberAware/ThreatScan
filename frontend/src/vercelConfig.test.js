// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// vercel.json is the only thing that sets the frontend's security headers, and
// nothing else in the build reads it, so a typo or an ignore rule would ship
// silently. Deploy verification only proves the commit, not the headers.
const configPath = fileURLToPath(new URL("../vercel.json", import.meta.url));
const config = JSON.parse(readFileSync(configPath, "utf8"));

const API_ORIGIN = "https://threatscan-production.up.railway.app";

const headersFor = source => {
  const rule = config.headers.find(h => h.source === source);
  return Object.fromEntries(rule.headers.map(h => [h.key.toLowerCase(), h.value]));
};

const cspDirectives = csp => Object.fromEntries(
  csp.split(";").map(d => d.trim()).filter(Boolean).map(d => {
    const [name, ...values] = d.split(/\s+/);
    return [name, values];
  })
);

describe("frontend/vercel.json security headers", () => {
  const headers = headersFor("/(.*)");

  it("sets the static hardening headers on every path", () => {
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["referrer-policy"]).toBeTruthy();
    expect(headers["strict-transport-security"]).toMatch(/max-age=\d{8,}/);
    expect(headers["permissions-policy"]).toMatch(/camera=\(\)/);
  });

  it("ships the CSP in report-only mode, not enforcing", () => {
    expect(headers["content-security-policy-report-only"]).toBeTruthy();
    expect(headers["content-security-policy"]).toBeUndefined();
  });

  it("allows what the app actually loads", () => {
    const csp = cspDirectives(headers["content-security-policy-report-only"]);
    // EventSource to the Railway API (VITE_API_URL in the Vercel project).
    expect(csp["connect-src"]).toContain(API_ORIGIN);
    // URLScan screenshots render as <img src="https://urlscan.io/screenshots/...">.
    expect(csp["img-src"]).toContain("https://urlscan.io");
    // App.jsx @imports Google Fonts from an inline <style>.
    expect(csp["style-src"]).toEqual(expect.arrayContaining(["'unsafe-inline'", "https://fonts.googleapis.com"]));
    expect(csp["font-src"]).toContain("https://fonts.gstatic.com");
    expect(csp["frame-ancestors"]).toEqual(["'none'"]);
    expect(csp["script-src"]).not.toContain("'unsafe-inline'");
  });

  it("is not ignored by git", () => {
    // git check-ignore exits 1 when the path is not ignored.
    let status = 0;
    try {
      execFileSync("git", ["check-ignore", "-q", configPath]);
    } catch (err) {
      status = err.status;
    }
    expect(status).toBe(1);
  });
});
