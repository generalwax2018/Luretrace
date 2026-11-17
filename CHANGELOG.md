# Changelog

All notable changes to this project are documented here. This project is pre-1.0; expect breaking
changes between minor versions.

## [0.1.0b1] - 2026-11-17

First public **beta**. Not production-validated: the features are built and unit-tested, but
detection efficacy is unproven and APIs may change before 0.1.0 final (see the status note in the
README). Stays in beta until validated against real phishing samples.

### Added
- Link extraction from `.eml` bodies and HTML parts, with refanging.
- Gateway-rewrite unwrapping: Microsoft Safe Links, Proofpoint URL Defense (v2/v3), Mimecast (API).
- Isolated detonation worker (Playwright/Chromium) that follows the lure chain to its end,
  capturing redirects, screenshots, HTML, a HAR, and download hashes.
- SSRF guard (`netguard`) refusing non-public addresses; egress-proxy aware.
- Heuristic scoring with the AiTM signal set; incomplete chains are never scored clean.
- CLI: `url`, `eml`, `watch`, `beacon`, `rescan`.
- Login-page beacon receiver, rescan queue, IOC/blocklist export, and an opt-in honeytoken
  (disabled by default).
- Mail sources: IMAP and Microsoft Graph (Graph path experimental).
- Web console (FastAPI): dashboard, scan list, per-link forensics, sources, on-demand submit.
- Ingest connectors: Mimecast and a vendor-neutral data-lake/SIEM connector (both experimental).
- Click-time gate: `/check` decision API and `/go` interstitial, with phishing-simulation
  passthrough; enforcement-agnostic.
- Docs: deployment, identity hardening, detection rules, inline agent, and a tool-agnostic
  architecture diagram.

### Known limitations
- Detection efficacy is unproven against real phishing; tests are unit-level plus a local fake lure.
- The Graph, Mimecast, data-lake, and gate paths have not been run against a live tenant.
- Links inside PDF/Office/image viewers are not followed; no CAPTCHA solving.
