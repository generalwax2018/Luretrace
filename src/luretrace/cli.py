from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from .config import Config
from .models import Verdict
from .pipeline import scan_message, scan_url
from .sources import build_source

EXIT = {"skipped": 0, "clean": 0, "suspicious": 1, "malicious": 2}


def _print(verdict: Verdict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(verdict.to_dict(), indent=2))
        return
    print(f"\n[{verdict.label.upper()}] score={verdict.score}  {verdict.url}")
    if verdict.original_url != verdict.url:
        print(f"  unwrapped from: {verdict.original_url}")
    for hop in verdict.hops:
        arrow = f'  via "{hop.followed_link_text}"' if hop.followed_link_text else ""
        print(f"  hop {hop.index}: {hop.final_url or hop.requested_url}{arrow}")
        if hop.error:
            print(f"         error: {hop.error}")
    for sig in verdict.signals:
        print(f"  +{sig.score:<3} {sig.name}: {sig.detail}")
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
        verdict = asyncio.run(scan_url(item.url, cfg, item.message_id))
        if item.first_label and verdict.label != item.first_label:
            print(f"[luretrace] VERDICT CHANGED {item.first_label} -> {verdict.label} "
                  f"(armed after delivery?) {item.url}")
        _print(verdict, as_json)
        queue.mark_done(item, offset)
        worst = max(worst, EXIT[verdict.label])
    return worst


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="luretrace", description=__doc__)
    parser.add_argument("-c", "--config", help="Path to a YAML config file")
    parser.add_argument("--json", action="store_true", help="Print full JSON reports")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("url", help="Detonate one URL").add_argument("target")
    sub.add_parser("eml", help="Scan every link in a .eml file").add_argument("path")
    sub.add_parser("watch", help="Poll the configured mailbox and scan new mail")
    sub.add_parser("beacon", help="Run the login-page beacon receiver")
    sub.add_parser("rescan", help="Re-detonate queued links as their offsets come due")
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)

    if args.cmd == "beacon":
        from .beacon import run_receiver
        run_receiver(cfg)
        return 0
    if args.cmd == "rescan":
        return _rescan(cfg, args.json)

    if args.cmd == "url":
        verdicts = [asyncio.run(scan_url(args.target, cfg))]
    elif args.cmd == "eml":
        verdicts = asyncio.run(scan_message(Path(args.path).read_bytes(), cfg))
    else:
        source = build_source(cfg)
        print(f"[luretrace] watching mailbox every {cfg.poll_seconds}s")
        while True:
            try:
                for raw in source.fetch():
                    for verdict in asyncio.run(scan_message(raw, cfg)):
                        _print(verdict, args.json)
            except KeyboardInterrupt:
                return 0
            except Exception as exc:
                print(f"[luretrace] poll failed: {exc}", file=sys.stderr)
            time.sleep(cfg.poll_seconds)

    for verdict in verdicts:
        _print(verdict, args.json)
    return max((EXIT[v.label] for v in verdicts), default=0)


if __name__ == "__main__":
    raise SystemExit(main())
