"""luretrace: follow emailed links to the end of the lure chain and flag credential phishing."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from .config import Config
from .models import Verdict
from .pipeline import RANK, scan_message, scan_url
from .sources import build_source

EXIT = {"skipped": 0, "clean": 0, "suspicious": 1, "malicious": 2}


def _print(verdict: Verdict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(verdict.to_dict(), indent=2))
        return
    print(f"\n[{verdict.label.upper()}] score={verdict.score}  {verdict.url}")
    if verdict.original_url != verdict.url:
        print(f"  unwrapped from: {verdict.original_url}")
    if verdict.origin != "body":
        print(f"  found in: {verdict.origin}")
    for hop in verdict.hops:
        arrow = f'  via "{hop.followed_link_text}"' if hop.followed_link_text else ""
        print(f"  hop {hop.index}: {hop.final_url or hop.requested_url}{arrow}")
        if hop.error:
            print(f"         error: {hop.error}")
    for sig in verdict.signals:
        print(f"  +{sig.score:<3} {sig.name}: {sig.detail}")
    for action in verdict.actions:
        print(f"  action: {action}")
    if verdict.artifacts_dir:
        print(f"  artifacts: {verdict.artifacts_dir}")


def _rescan(cfg, as_json: bool) -> int:
    from .rescan import RescanQueue
    queue = RescanQueue(cfg.rescan_queue)
    due = queue.due()
    if not due:
        print("[luretrace] nothing due to rescan")
        return 0
    worst = 0
    for item, offset in due:
        verdict = asyncio.run(scan_url(item.url, cfg, item.message_id, origin=item.origin,
                                       rescan_of=item.first_label or "clean"))
        before = item.first_label or "clean"
        if RANK[verdict.label] > RANK.get(before, 0):
            print(f"[luretrace] VERDICT WORSENED {before} -> {verdict.label} at +{offset}m "
                  f"(armed after delivery?) {item.url}")
        elif verdict.label != before:
            print(f"[luretrace] verdict changed {before} -> {verdict.label} at +{offset}m {item.url}")
        _print(verdict, as_json)
        queue.mark_done(item, offset)
        worst = max(worst, EXIT[verdict.label])
    return worst


def _drain(cfg, as_json: bool) -> list[Verdict]:
    """Run every job waiting in the inbox (queued by the console or other front ends)."""
    from . import inbox
    if not cfg.inbox_dir:
        return []
    verdicts: list[Verdict] = []
    for job in inbox.claim(cfg.inbox_dir):
        try:
            if job.kind == "eml":
                got = asyncio.run(scan_message(job.raw, cfg))
            else:
                got = [asyncio.run(scan_url(job.url, cfg, rescan=cfg.rescan_auto))]
        except Exception as exc:
            print(f"[luretrace] inbox job failed ({job.path.name}): {exc}", file=sys.stderr)
            inbox.fail(job)
            continue
        inbox.done(job)
        for v in got:
            _print(v, as_json)
        verdicts += got
    return verdicts


def _ingest(cfg, as_json: bool) -> list[Verdict]:
    from .ingest import build_connector
    opts = dict(cfg.ingest)
    kind = opts.pop("kind", None)
    if not kind:
        raise SystemExit("No ingest connector configured: set `ingest: {kind: ...}` in the config.")
    verdicts = []
    seen: set[str] = set()
    for item in build_connector(kind, opts).fetch():
        if item.url in seen:
            continue
        seen.add(item.url)
        v = asyncio.run(scan_url(item.url, cfg, item.message_id,
                                 recipients=[item.recipient] if item.recipient else (),
                                 rescan=cfg.rescan_auto))
        if item.gateway_verdict and v.label in ("suspicious", "malicious"):
            print(f"[luretrace] {item.source} said '{item.gateway_verdict}', "
                  f"luretrace says {v.label}: {item.url}")
        _print(v, as_json)
        verdicts.append(v)
    return verdicts


def _watch(cfg, as_json: bool) -> int:
    source = build_source(cfg) if (cfg.imap or cfg.graph) else None
    if source is None and not cfg.inbox_dir:
        build_source(cfg)  # raises the "no mail source configured" error
    attempts: dict[str, int] = {}
    print(f"[luretrace] watching every {cfg.poll_seconds}s"
          + (f" (and draining inbox {cfg.inbox_dir})" if cfg.inbox_dir else ""))
    while True:
        try:
            if source is not None:
                for msg in source.fetch():
                    key = getattr(msg, "key", None)
                    try:
                        for verdict in asyncio.run(scan_message(bytes(msg), cfg)):
                            _print(verdict, as_json)
                    except Exception as exc:
                        n = attempts.get(key, 0) + 1 if key else cfg.max_attempts
                        attempts[key] = n
                        print(f"[luretrace] scan failed ({n}/{cfg.max_attempts}) {key}: {exc}",
                              file=sys.stderr)
                        if n < cfg.max_attempts:
                            continue  # stays unread; retried next poll
                        print(f"[luretrace] giving up on {key}; marking it processed",
                              file=sys.stderr)
                    attempts.pop(key, None)
                    if hasattr(msg, "ack"):
                        msg.ack()
            _drain(cfg, as_json)
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"[luretrace] poll failed: {exc}", file=sys.stderr)
        try:
            time.sleep(cfg.poll_seconds)
        except KeyboardInterrupt:
            return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="luretrace", description=__doc__)
    parser.add_argument("-c", "--config", help="Path to a YAML config file")
    parser.add_argument("--json", action="store_true", help="Print full JSON reports")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("url", help="Detonate one URL").add_argument("target")
    sub.add_parser("eml", help="Scan every link in a .eml file").add_argument("path")
    sub.add_parser("watch", help="Poll the configured mailbox (and inbox) and scan new mail")
    sub.add_parser("drain", help="Run the jobs waiting in inbox_dir once, then exit")
    sub.add_parser("ingest", help="Pull links from the configured ingest connector and scan them")
    sub.add_parser("beacon", help="Run the login-page beacon receiver")
    sub.add_parser("rescan", help="Re-detonate queued links as their offsets come due")
    bl = sub.add_parser("blocklist", help="Write a domain blocklist from malicious scans on disk")
    bl.add_argument("out", help="File to write (one domain per line)")
    ev = sub.add_parser("eval", help="Measure precision/recall against a labelled CSV of links")
    ev.add_argument("labels", help="CSV with url,label columns (label: phish|benign)")
    ev.add_argument("--out", help="Write the full evaluation report here (JSON)")
    ev.add_argument("--flag-at", choices=["suspicious", "malicious"], default="suspicious",
                    help="Lowest verdict counted as a detection (default: suspicious)")
    ev.add_argument("--concurrency", type=int, default=1)
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)

    if args.cmd == "beacon":
        from .beacon import run_receiver
        run_receiver(cfg)
        return 0
    if args.cmd == "rescan":
        return _rescan(cfg, args.json)
    if args.cmd == "blocklist":
        from .actions import verdicts_from_reports, write_blocklist
        n = write_blocklist(verdicts_from_reports(cfg.output_dir), args.out, cfg.allowlist_domains)
        print(f"[luretrace] wrote {n} domain(s) to {args.out}")
        return 0
    if args.cmd == "eval":
        from .evaluate import run
        report = asyncio.run(run(args.labels, cfg, args.out, args.flag_at, args.concurrency))
        print(json.dumps(report["summary"], indent=2))
        return 0
    if args.cmd == "watch":
        return _watch(cfg, args.json)

    if args.cmd == "url":
        verdicts = [asyncio.run(scan_url(args.target, cfg))]
    elif args.cmd == "eml":
        verdicts = asyncio.run(scan_message(Path(args.path).read_bytes(), cfg))
    elif args.cmd == "drain":
        if not cfg.inbox_dir:
            raise SystemExit("No inbox configured: set `inbox_dir` in the config file.")
        return max((EXIT.get(v.label, 0) for v in _drain(cfg, args.json)), default=0)
    else:  # ingest
        verdicts = _ingest(cfg, args.json)
        return max((EXIT[v.label] for v in verdicts), default=0)

    for verdict in verdicts:
        _print(verdict, args.json)
    return max((EXIT[v.label] for v in verdicts), default=0)


if __name__ == "__main__":
    raise SystemExit(main())
