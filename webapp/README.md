# luretrace web console

> **Beta (`0.1.0b1`), not production-validated.** Run it in a lab; keep it behind your SSO.

A read-only forensics console over the scan output. It reads the `report.json` files the
engine writes (one per scan directory) — no database — and presents them for a SOC analyst:

- **Dashboard** — counts (scanned, malicious, suspicious, clean, fail rate), a "needs analysis"
  queue, and recent scans.
- **Scans** — every link with its verdict, filterable by status; failed links are flagged.
- **Forensics** (per failed link) — the scored signals, the full hop-by-hop chain (redirects,
  credential-form flags, where forms post, resource hosts, downloads with SHA-256), per-hop
  screenshots, and downloadable `report.json` / `chain.har`.
- **Sources** — the ingest connectors (Mimecast, data lake / SIEM) and the find-to-verdict flow.

It shares the shell and design language of the other apps, in luretrace's own ultraviolet theme.

## Run

```bash
pip install -e ".[web]"
export LURETRACE_SCANS=./scans        # where the engine writes report.json dirs
uvicorn webapp.server:app --host 127.0.0.1 --port 8099
```

Open http://127.0.0.1:8099. The console is server-rendered and works without JavaScript.

## How it gets its data

The console is a reader. Links are scanned by the engine (CLI, mailbox watcher, or an ingest
connector) which writes a scan directory containing `report.json` and the captured artifacts.
Point `LURETRACE_SCANS` at that directory and the console reflects it.

## Ingest connectors (`ingest.py`)

At work you rarely point luretrace at a raw mailbox — the URLs already live in a data lake/SIEM
or can be pulled from Mimecast. Connectors yield `(url, context)` for the pipeline to detonate,
authenticating with OAuth2 client-credentials:

- **mimecast** — pulls TTP URL logs (API 2.0) and carries Mimecast's own verdict, so a link the
  gateway passed that luretrace fails stands out.
- **datalake** — runs a query against an OAuth2-protected endpoint (Snowflake, Databricks SQL,
  Azure Data Explorer, Elastic, or a custom gateway) and maps result fields to URLs. Configure,
  don't code.

These are seams written to published docs; validate against your tenant before relying on them.

## Safety

- Captured HTML and HAR are live hostile content: the console serves them as downloads and never
  renders them. Only PNG screenshots display inline.
- The artifact route only serves whitelisted filenames from inside a scan directory; path
  traversal is rejected.
- **On-demand submission does not have to detonate here.** With `LURETRACE_INBOX` set (or
  `LURETRACE_SUBMIT_MODE=queue`) the console only writes a job file; the isolated worker runs it
  (`luretrace watch` / `luretrace drain` with `inbox_dir` pointing at the same directory).
  `LURETRACE_SUBMIT_MODE=off` disables submission; `local` keeps the old in-process detonation.
- `/submit` requires a form token and rejects cross-site posts, so a page an analyst happens to
  visit cannot trigger scans. Set `LURETRACE_CONSOLE_SECRET` to keep tokens valid across restarts
  or replicas.
- Every response carries a strict Content-Security-Policy (no inline script, no framing),
  `nosniff`, and `Referrer-Policy: no-referrer`, so phishing hosts named on a page never learn
  about the console through Referer.
- Run the console on an internal network. It exposes scan data and should sit behind your SSO /
  reverse proxy; it has no login of its own by design (front it with what you have).
