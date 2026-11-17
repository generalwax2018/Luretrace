# Integration tests

These exercise the paths the unit suite deliberately doesn't: real detonation in a browser, and
the live Microsoft Graph and Mimecast integrations. They are **skipped by default** — they need a
browser, network egress, real credentials, or a sample URL, none of which belong in CI-by-default.

This directory is where the **real-world validation** happens. Passing unit tests prove the
decision logic; these prove the tool actually works against live services and real pages. Run them
in a lab before trusting verdicts in production.

## Running

```bash
pip install -e ".[dev,web]"
python -m playwright install chromium

# enable the integration marker, then provide what each test needs:
pytest tests/integration --run-integration -v
```

Each test skips itself if its inputs aren't set, so you can run just the ones you have creds for.

## What each needs

| Test | Environment it needs |
| --- | --- |
| `test_detonation_live.py` | `LURETRACE_TEST_URL` (a sample to detonate); optional `LURETRACE_TEST_EXPECT` = clean/suspicious/malicious. Chromium installed. Run on an isolated host — this opens the real page. |
| `test_graph_live.py` | `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`, `GRAPH_MAILBOX` (app registration with `Mail.ReadWrite`). |
| `test_mimecast_live.py` | `MIMECAST_CLIENT_ID`, `MIMECAST_CLIENT_SECRET`, and `MIMECAST_TEST_URL` (a real rewritten link). |

## Building a detection corpus

The most valuable use of this directory is a labelled set of real samples. Suggested approach:

1. Collect recent confirmed-phishing URLs (from your own reports, or a feed like PhishTank/URLhaus)
   and a set of known-good links, each with an expected label.
2. Detonate each on an isolated host and compare the verdict to the label.
3. Track precision/recall over time; tune `signals.py` thresholds against the misses.

Keep the corpus and any captured artifacts **out of this repo** — they are live malicious content.
Store them where your malware-handling policy allows, and reference them by path/env, not by commit.
