# luretrace

A second-opinion link scanner for email. It opens each emailed link in an isolated
headless browser, **follows the lure chain to its end**, and flags credential-phishing
pages, including adversary-in-the-middle (AiTM) kits that sit behind a legitimate
file-share link.

Most gateways scan the link in the email. In a typical AiTM attack that link is a real
SharePoint, OneDrive or Dropbox page, and it scans clean. The phishing page is one click
further in. luretrace makes that click.

```
email -> extract links -> unwrap gateway rewrites -> triage -> detonate + follow -> score -> webhook
```

## What it does

- **Extracts** links from `.eml` bodies and HTML parts, and refangs `hxxp://` / `[.]` forms.
- **Unwraps** Microsoft Safe Links and Proofpoint URL Defense (v2, v3) offline, and Mimecast
  links through the Mimecast API.
- **Detonates** in Chromium (Playwright): records every redirect, a screenshot and the HTML of
  each hop, a HAR of the whole chain, and the SHA-256 of any download.
- **Follows** the most lure-like external link on each page ("View Document", "Review file")
  for up to `max_hops` pages, across iframes.
- **Scores** the chain. The main signal is a branded sign-in page (Microsoft, Google, Okta,
  DocuSign, Dropbox) served from a domain that brand does not own.
- **Fails closed**: a chain it could not finish (CAPTCHA gate, error, hop limit) is reported as
  `suspicious`, never `clean`.
- **Notifies** any JSON webhook (ServiceNow, Sentinel, SOAR, Slack) and writes a `report.json`.

## Quick start

```bash
pip install -e ".[dev]"
playwright install chromium

luretrace url "https://example.org/"
luretrace eml suspicious.eml
luretrace -c config.yaml watch        # poll a mailbox (IMAP or Microsoft Graph)
luretrace -c config.yaml beacon       # run the login-page proxying tripwire
luretrace -c config.yaml rescan       # re-detonate queued links (run on a cron)
```

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

See `webapp/README.md`.

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
| `captcha_gate` | 15 | Turnstile / hCaptcha / reCAPTCHA in the chain |
| `cross_domain_form_post` | 15 | Login form posts to a different domain |
| `long_redirect_chain` | 10 | More than three HTTP redirects |

Scores add up, capped at 100. Defaults: 70 and above is `malicious`, 30 and above is `suspicious`.

## Safety: read before running

This tool visits hostile pages on purpose.

- **Isolate it.** Run on a disposable host or VM in a segment with its own internet egress and
  no route to corporate networks or cloud metadata endpoints. The built-in guard refuses
  non-public addresses, but it is defence in depth, not the boundary. When `proxy` is set,
  names that do not resolve locally are passed to the proxy, so the proxy's ACLs must deny
  internal destinations.
- **Opening a link is an action.** One-time links, approve/unsubscribe links and phishing
  simulation trackers will fire. Put those domains in `allowlist_domains`.
- **Attackers can see the visit.** Detonation may confirm the mailbox is live. Egress from
  addresses not tied to your organisation.
- **Evasion is real.** Kits that gate on IP reputation, geography or a CAPTCHA may show the
  scanner a decoy. That is why incomplete chains are never marked clean.
- **Treat artifacts as hostile.** Saved HTML and downloads are live malicious content.

## Limits in 0.1

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

- Domain and certificate age (RDAP, CT logs), and reputation lookups
- QR codes and links inside PDF and Office attachments
- Rescan schedule for links armed after delivery
- Opt-in canary credentials submitted to confirmed phishing pages
- Vision-model check of screenshots for brand impersonation
- Response actions: Graph message purge, Netskope and Mimecast blocklist push
- Hand-off of downloads to a malware sandbox (CAPEv2)

## Development

```bash
pytest
```

The end-to-end tests spin up a local two-site lure chain and run it through the real browser
worker; they skip automatically if Chromium is not installed.

## License

MIT
