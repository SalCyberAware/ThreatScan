# Security Policy

ThreatScan is a portfolio / personal project, not a hardened commercial product. That said, security issues are taken seriously and fixed when reported.

## Supported Versions

Only the `main` branch receives security fixes. There are no maintenance branches for older releases.

| Version | Supported |
|---------|-----------|
| `main`  | ✅        |
| Tagged releases prior to `main` | ❌ |

## Reporting a Vulnerability

Please report security issues privately via **[GitHub Security Advisories](https://github.com/SalCyberAware/ThreatScan/security/advisories/new)** — do not open a public issue, and do not include exploit details in a PR description.

When reporting, please include:

- A clear description of the issue and its impact
- Reproduction steps or a minimal proof of concept
- Affected commit SHA or branch
- Any relevant logs, request/response samples, or screenshots

## Response Timeline

This is a single-maintainer project, so response times are best-effort, not contractual:

- **Initial acknowledgement:** within 5 business days
- **Triage and severity assessment:** within 10 business days of acknowledgement
- **Fix and disclosure:** depends on severity; you'll be kept in the loop

If you don't hear back within 5 business days, please ping the advisory thread.

## In Scope

Issues that meaningfully affect the security of the backend or frontend:

- Remote code execution in the backend
- Server-side request forgery (SSRF) — particularly via the engine clients
- Authentication or authorization issues on any future protected endpoints
- Information disclosure (API keys, environment data, internal paths) via the API
- Cross-site scripting (XSS) or other injection in the frontend
- Cross-origin issues that bypass the CORS allowlist in production
- Prototype pollution or unsafe deserialization
- Dependency vulnerabilities with a working exploit against this repo

## Out of Scope

These are known limitations of a portfolio project running on free hosting tiers:

- **Rate-limit bypass on the public demo** — the demo runs on shared infrastructure with modest limits; bypass techniques are not a security finding
- **Denial of service via API-key exhaustion** — the upstream engines have their own quotas; burning through them on the public demo is expected behavior, not a vulnerability
- **Brute force or DoS against the live demo's hosting tier**
- **Missing security headers on third-party assets** outside this project's control
- **Self-XSS** that requires the victim to paste attacker-supplied content into their own dev console
- **Outdated browser compatibility** — only modern evergreen browsers are supported
- **Reports from automated scanners** with no manual validation or proof of exploitability

## Safe Harbor

Good-faith security research that follows this policy will not be pursued legally. Specifically: testing against a local clone of the repo is always fine; testing against the public demo at [threat-scan.vercel.app](https://threat-scan.vercel.app) is fine if you avoid disrupting other users and don't attempt to access data that isn't yours.

## Disclosure

Once a fix is merged, the advisory will be published with credit to the reporter (unless anonymity is requested).
