# luretrace

A second-opinion link scanner for email. It opens each emailed link in an isolated
headless browser, **follows the lure chain to its end**, and flags credential-phishing
pages, including adversary-in-the-middle (AiTM) kits that sit behind a legitimate
file-share link.

Most gateways scan the link in the email. In a typical AiTM attack that link is a real
SharePoint, OneDrive or Dropbox page, and it scans clean. The phishing page is one click
further in. luretrace makes that click.

> **Status: Beta (`0.1.0b1`) — not production-validated.** This is a beta release: the features
> are built and unit-tested, but expect bugs and changing APIs, and it will stay in beta until it
> has been validated against real phishing samples. The tests are unit-level and the
> end-to-end test uses a local fake lure; the detonation worker has **not** been evaluated against
> real phishing, and the Microsoft Graph, Mimecast, data-lake, and click-time gate paths have
> **not** been run against a live tenant. Treat verdicts as heuristic, validate in a lab before
> you rely on it, and read [Safety](#safety-read-before-running) first. This software detonates
> live hostile content and ships opt-in deception features ([honeytoken](#honeytoken-off-by-default)).

```
email -> extract links -> unwrap gateway rewrites -> triage -> detonate + follow -> score -> webhook
```

The full picture — detect, trace, contain, and prevent at click time, with the identity-layer
backstop — is in [`docs/architecture.md`](docs/architecture.md) (every external box is a role, not
a product, so it stays vendor-neutral).

## What it does

- **Extracts** links from `.eml` bodies, HTML/SVG attachments (including URLs hidden in script
  and base64, as HTML-smuggling lures do), calendar invites, PDF link annotations, and **QR codes**
  in images (`pip install -e ".[attachments]"`). Refangs `hxxp://` / `[.]` forms.
- **Unwraps** Microsoft Safe Links and Proofpoint URL Defense (v2, v3) offline, and Mimecast
  links through the Mimecast API.
- **Detonates** in Chromium (Playwright): records every redirect, a screenshot and the HTML of
  each hop, a HAR of the whole chain, and the SHA-256 of any download.
- **Follows** the most lure-like external link on each page ("View Document", "Review file")
  for up to `max_hops` pages, across iframes, including script-driven buttons and popup windows.
- **Guards egress**: every browser connection (redirects, WebSockets, popups) goes through a local
  guard proxy that refuses private, loopback and metadata addresses and connects only to the
  address it checked. Common automation tells are hidden so kits are less likely to serve a decoy.
- **Scores** the chain. The main signal is a branded sign-in page (Microsoft, Google, Okta,
  DocuSign, Dropbox) served from a domain that brand does not own.
- **Fails closed**: a chain it could not finish (CAPTCHA gate, error, hop limit) is reported as
  `suspicious`, never `clean`.
- **Notifies** any JSON webhook (ServiceNow, Sentinel, SOAR, Slack), signed with HMAC-SHA256
  when `webhook_secret` is set and retried with backoff, and writes a `report.json`.
- **Responds** (each opt-in, each recorded in the report): IOC files, a blocklist that never
  blocks shared platforms whole, a Graph purge from the recipients' mailboxes, and the honeytoken.

## Quick start

```bash
pip install -e ".[dev]"
playwright install chromium

luretrace url "https://example.org/"
luretrace eml suspicious.eml
luretrace -c config.yaml watch        # poll a mailbox (IMAP or Graph) and drain the job inbox
luretrace -c config.yaml drain        # run queued jobs (console submissions) once
luretrace -c config.yaml ingest       # pull links from Mimecast / a data lake and scan them
luretrace -c config.yaml beacon       # run the login-page proxying tripwire
luretrace -c config.yaml rescan       # re-detonate queued links (run on a cron)
luretrace -c config.yaml blocklist blocked.txt   # domains from every malicious scan on disk
luretrace -c config.yaml eval labels.csv --out eval.json   # precision / recall on labelled links
```

Mail scanned by `watch`, `eml`, `ingest` and the inbox is queued for rescan automatically
(`rescan_auto`), because a clean first scan is not durable; a rescan that comes back worse is
reported and sent to the webhook. A mailbox message is marked read only after it was scanned; one
that keeps failing is given up on after `max_attempts` instead of blocking the mailbox.

Exit code is `0` clean, `1` suspicious, `2` malicious, so it drops into scripts and SOAR steps.

## Web console

A read-only forensics GUI for analysts: a dashboard, a scan list with pass/fail, and a
full hop-by-hop forensics page for every failed link (signals, redirects, credential-form
flags, screenshots, downloadable report/HAR). Ingest connectors (Mimecast, data lake / SIEM)
feed links in from where your org already keeps them.

```bash
pip install -e ".[web]"
export LURETRACE_SCANS=./scans
uvicorn webapp.server:app --port 8099
```

Set `LURETRACE_INBOX` to a directory the isolated worker drains and the console's on-demand
submissions are queued there instead of being detonated on the console host. See
`webapp/README.md`.

## Click-time gate (inline)

An optional enforcement layer that moves the check to the moment of the click: the navigation is
held, luretrace's verdict is consulted, and the click is allowed, blocked, or sent to isolation —
before any credential is entered. Phishing-simulation clicks pass straight through, so training
exercises are never blocked — but only on evidence an attacker cannot type (the vendor's landing
domain, or simulation mail your mail system authenticated); a simulation header alone never
passes. It never detonates in the hot path (it reads a verdict cache the pre-scan fills), an
unknown link fails safe to isolation, and a clean verdict older than 24 h is no longer trusted.

```bash
export LURETRACE_SCANS=./scans
uvicorn webapp.gate:gate_app --port 8090
# POST /check {"url":"..."} -> allow|block|isolate ; GET /go?u=<link> -> redirect/block/isolate
```

It's enforcement-agnostic — the same decision drives a Netskope inline + RBI policy, a link-rewrite
service, or a managed browser extension. See `docs/inline-agent.md`.

Docker:

```bash
cp config.example.yaml config.yaml    # edit it
docker compose up --build
docker compose --profile pcap up      # also write hourly pcap files
```

## Deploying behind a mail gateway

luretrace does not sit inline. Copy mail to a mailbox it can read:

1. Create a dedicated mailbox, e.g. `linkscan@yourcompany.com`.
2. Add a transport rule that BCCs inbound external mail containing links to it, or point your
   "report phish" button at it.
3. Configure `imap` or `graph` in `config.yaml` and run `luretrace watch`.
4. Point `webhook_url` at whatever should act on a verdict (ticket, purge, blocklist).

## Signals

| Signal | Score | Meaning |
| --- | --- | --- |
| `brand_login_off_domain` | 45-80 | Branded sign-in page on a domain the brand does not own |
| `internal_address_probe` | 40 | Page tried to reach a private or metadata address |
| `credential_form_after_hop` | 30 | Unbranded password form reached by following a link |
| `chain_incomplete` | 30 | Chain could not be followed to an end |
| `download_triggered` | 25 | The chain delivered a file |
| `fileshare_lure_to_login` | 20 | File-share link ended at a credential form elsewhere |
| `recipient_in_url` | 20 | Link carries the recipient's address (plain, encoded or base64) |
| `young_domain` | 20 | Credential/final domain registered under `young_domain_days` ago (`rdap: true`) |
| `captcha_gate` | 15 | Turnstile / hCaptcha / reCAPTCHA in the chain |
| `cross_domain_form_post` | 15 | Login form posts to a different domain |
| `qr_code_link` | 15 | Link was delivered as a QR code |
| `long_redirect_chain` | 10 | More than three HTTP redirects |
| `email_in_url` | 10 | Link carries some email address |
| `markup_attachment_link` | 10 | Link came from an HTML/SVG attachment |

`brand_login_off_domain` asks whether a page claims to *be* a brand's sign-in, not whether it
mentions one (every SaaS login with a "Sign in with Microsoft" button does). Decisive evidence is
the brand's own login-UI assets (by host and path, so Google's sign-in widgets at
`accounts.google.com/gsi/*` don't count) or the brand's sign-in page source served from another
domain, as an AiTM proxy does. Otherwise it needs the brand's sign-in title or flow wording, with
SSO-button menus and third-party notices ignored. On 28 real SaaS login pages it fired on none
(three still come out `suspicious` as *unverified*: two behind a Cloudflare challenge the scanner
could not pass, one whose domain no longer exists); saved copies of the real Microsoft and Google
sign-in pages served from another domain score malicious.

| Signal | Score | Meaning |
| --- | --- | --- |
| `does_not_resolve` | 30 | The link's domain does not resolve from the scanner: unverified (never "skipped", which the gate allows), queued for rescan |

Scores add up, capped at 100. Defaults: 70 and above is `malicious`, 30 and above is `suspicious`.

## Safety: read before running

This tool visits hostile pages on purpose.

- **Isolate it.** Run on a disposable host or VM in a segment with its own internet egress and
  no route to corporate networks or cloud metadata endpoints. The built-in guard proxy refuses
  non-public addresses, but it is defence in depth, not the boundary. When `proxy` (an
  `http://` egress proxy) is set, names that do not resolve locally are passed to it, so its ACLs
  must deny internal destinations. `docker-compose.egress.yml` ships such a boundary: an
  internal-only network whose one way out is a squid proxy that refuses private destinations.
- **Opening a link is an action.** One-time links, approve/unsubscribe links and phishing
  simulation trackers will fire. Put those domains in `allowlist_domains`.
- **Attackers can see the visit.** Detonation may confirm the mailbox is live. Egress from
  addresses not tied to your organisation.
- **Evasion is real.** Kits that gate on IP reputation, geography or a CAPTCHA may show the
  scanner a decoy. That is why incomplete chains are never marked clean.
- **Treat artifacts as hostile.** Saved HTML and downloads are live malicious content.

## Honeytoken (off by default)

luretrace can submit a pre-seeded **fake** account to a page it has already judged malicious, so
any later use of that canary exposes the attacker's replay infrastructure. This is active
deception and it is **disabled by default and intentionally undocumented in config beyond this
note.** Before enabling it you are responsible for: creating the canary as a disabled, monitored
identity in your own tenant; authorisation to run active deception; and compliance with local law
and the destination's terms. It only ever fires on a verdict already labelled `malicious` and only
submits the one configured canary. If any of that is unclear, leave it off — every other part of
luretrace works without it.

## Limits in this beta

- Links drawn inside a PDF or image viewer (not real anchors) are not followed.
- No CAPTCHA solving; a gate ends the chain as `suspicious`.
- The Graph source and the Mimecast decoder are written to the public API docs and have not
  been run against a live tenant yet.
- Scoring is heuristic. Expect to tune `trusted_login_domains` and the allowlist.

## Beyond detection: stopping the attack

Detection is half the job; a scanner cannot be the wall. The repo ships the defensive
other half:

- **`docs/identity-hardening.md`** — the Entra / Conditional Access controls that stop AiTM
  even when a user clicks: phishing-resistant MFA, compliant-device requirements, and locking
  down device and MFA registration (the persistence step from the incident this was built for).
- **`docs/detection-rules.md`** — KQL to catch the *replay* and *persistence* stages a link
  scanner never sees: a new device/MFA method after a risky sign-in, a session replayed from a
  hosting ASN, and token reuse from a second IP.
- **Login-page beacon** (`luretrace beacon`) — a 1x1 image referenced from your sign-in
  branding. Loaded normally it reports your login host; proxied by a kit it reports the
  attacker's domain, live. It never sees a credential.
- **Rescan** (`luretrace rescan`) — re-detonates links later, because a clean first scan is not
  durable: attackers arm links after delivery. A worsened verdict is flagged.
- **IOC export + blocklist** — every malicious verdict yields the phishing domain, URLs and
  hashes, ready to push to Netskope and the mail gateway.
- **Honeytoken** (opt-in, malicious-only) — submits a pre-seeded fake account to a confirmed
  phishing page so any later use of it exposes the attacker's replay infrastructure. You seed
  and authorise the canary; it is off by default.

## Roadmap

- Certificate age (CT logs) and reputation lookups (domain age via RDAP is in)
- Links inside Office attachments, and QR codes rendered inside PDFs
- Visual brand matching (logo/favicon hash or a vision model) instead of text patterns
- Direct API push of the blocklist to Netskope and Mimecast (today: a file you push)
- A durable queue (Service Bus / Redis) behind the file inbox and the rescan queue
- Hand-off of downloads to a malware sandbox (CAPEv2)

## Development

```bash
pytest
```

The end-to-end tests spin up a local two-site lure chain and run it through the real browser
worker; they skip automatically if Chromium is not installed.

## License

MIT
