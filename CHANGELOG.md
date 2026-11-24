# Changelog

All notable changes to this project are documented here. This project is pre-1.0; expect breaking
changes between minor versions.

## [Unreleased]

### Security
- Egress guard rewritten as a local forward proxy (`guardproxy`). The previous Playwright route
  guard was bypassed by HTTP redirects (a public page could 302 the worker to an internal or
  metadata address), never saw WebSockets, and checked a cached DNS answer Chromium re-resolved.
  The proxy sees every request, tunnel and redirect hop, and connects only to the address it
  checked. WebRTC is confined to proxied paths and Chromium cannot resolve names itself.
- The honeytoken submission now runs behind the same guard (it previously had none), and it
  refuses to run without a configured, seeded canary instead of inventing a random one.
- `docker-compose.egress.yml` + `deploy/squid.conf`: opt-in network boundary (internal-only
  network, squid egress that refuses private destinations).

- `graph_purge` put the attacker-controlled Message-ID into an OData `$filter` unescaped, so a
  crafted header could widen the purge. Values are now quoted, malformed IDs are refused, and a
  message is moved only when exactly one message matches.
- The gate's simulation passthrough accepted a forgeable header or From: domain. It now needs the
  vendor's landing domain, or simulation mail your mail system authenticated (DMARC/aligned DKIM).
- The gate's `/healthz` published its policy (allowlist, simulation domains). It no longer does.
- The gate redirected to any allowed URL; non-http(s) schemes are now blocked.
- Console `/submit` had no CSRF protection; it now requires a form token and rejects cross-site
  posts. Console and gate responses carry a strict CSP, `nosniff`, and `no-referrer`.
- Blocklists could include shared platforms (the SharePoint/Dropbox lure, `pages.dev`, brand
  domains); only attacker-owned domains, or the exact hostile host on shared platforms, are listed.

- A link whose domain did not resolve was labelled `skipped`, which the gate allows: a domain
  registered after delivery would pass. It is now `suspicious` (`does_not_resolve`) and queued.

### Fixed
- Brand detection flagged 7 of 10 real SaaS logins (Dropbox, Atlassian, Zoom, Notion, Slack,
  LinkedIn, Box) as phishing: Google's sign-in widget loads from `accounts.google.com`, and SSO
  buttons named the brand. It now weighs evidence that the page *is* the brand's sign-in (asset
  host and path rules, sign-in page source markers for AiTM proxies, title and flow wording) and
  ignores SSO menus and legal notices. Measured: 0 of 28 real logins flagged; cloned Microsoft and
  Google sign-in pages still score malicious. Pages record `idp_requests` for the path rules.
- A name with no usable DNS answer (e.g. IPv6-only on an IPv4 host) was reported as an internal
  address probe (+40); only names that resolve to non-public addresses are now.
- The rescan queue was never filled, so `luretrace rescan` never had work; mail scans now queue
  their links (`rescan_auto`), and rescans that worsen are reported and notified.
- Clean gate verdicts never expired; they are now trusted for `LURETRACE_CLEAN_MAX_AGE_H` (24 h).
- Every unknown link at the gate re-parsed every report on disk; the cache is now incremental and
  forced refreshes are rate-limited. Lookups fall back to the URL without its fragment.
- IMAP fetch marked mail read before it was scanned (a crash lost it) and a failing Graph message
  was retried forever; messages are now acknowledged after the scan, with `max_attempts`.
- Mimecast decoding fetched a new token per link and decoded each link twice; tokens and results
  are cached.
- Two scans of one URL in the same second shared a directory; scan ids are now unique.
- Scan ids from the URL are validated before touching the filesystem.
- Meta-refresh URLs were lowercased during extraction, breaking case-sensitive paths and tokens.
- Legitimate SaaS logins offering "Sign in with Google/Microsoft" buttons were scored as brand
  impersonation (`brand_login_off_domain`); button-only lines are now ignored.

### Added
- `luretrace eval labels.csv`: precision, recall and false-positive rate over labelled links.
- File-backed job inbox (`inbox_dir` / `LURETRACE_INBOX`) so the console queues work for the
  isolated worker; `luretrace drain`, and `watch` drains it every poll.
- `luretrace ingest` runs the Mimecast / data-lake connectors (now in `luretrace.ingest`;
  `webapp.ingest` re-exports them) and flags links the gateway passed that luretrace failed.
- `luretrace blocklist <file>` builds a blocklist from the scans on disk.
- Response actions wired into the pipeline and recorded in each report: `blocklist_path`,
  `purge_on_malicious` (from the recipients' mailboxes), and the honeytoken.
- Signed (`webhook_secret`, HMAC-SHA256) and retried (`webhook_retries`) webhooks.
- `concurrency` for detonating a message's links in parallel.
- Attachment extraction: HTML/SVG (anchors, script URLs, base64-hidden URLs), `.ics`, PDF link
  annotations, and QR codes in images (`[attachments]` extra). Each URL records its origin.
- Signals: `recipient_in_url`, `email_in_url`, `qr_code_link`, `markup_attachment_link`,
  `young_domain` (RDAP, opt-in).
- Detonation follows popup windows and script-driven lure buttons, hides common automation
  tells, and derives the user agent from the real browser version.
- `${VAR}` / `${VAR:-default}` environment interpolation in the config file.
- CI installs the web and attachment extras (gate and console tests previously skipped in CI),
  runs ruff, and Dependabot watches pip, Actions and the Docker base image.

### Changed
- `proxy` must be an `http://` proxy when the guard is on. `playwright>=1.49`; the Docker image
  pins `playwright==1.49.0` to match its base image.

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
