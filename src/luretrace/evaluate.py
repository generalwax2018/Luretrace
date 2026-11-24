"""Measure detection quality against a labelled set of links.

    luretrace eval labels.csv --out eval.json

labels.csv has a header row with at least `url` and `label`; label is phish/malicious/1 for a
known-bad link and benign/clean/0 for a known-good one. Every link is detonated (in the same
isolated worker, with all response actions and the webhook switched off) and the verdicts are
compared to the labels. Feed it fresh links from a phishing feed plus a benign corpus (top
sites, your own mail's links) in a lab; precision/recall per release is what takes luretrace
out of beta.
"""
from __future__ import annotations

import asyncio
import csv
import dataclasses
import json
from pathlib import Path

POSITIVE = {"phish", "phishing", "malicious", "bad", "1", "true", "yes"}
NEGATIVE = {"benign", "clean", "good", "legit", "0", "false", "no"}


def load_labels(path: str) -> list[tuple[str, bool]]:
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            url, label = (row.get("url") or "").strip(), (row.get("label") or "").strip().lower()
            if not url or label not in POSITIVE | NEGATIVE:
                continue
            rows.append((url, label in POSITIVE))
    return rows


def score(results: list[dict], flag_at: str = "suspicious") -> dict:
    """flag_at: the lowest label counted as a detection (suspicious or malicious)."""
    flagged = {"suspicious", "malicious"} if flag_at == "suspicious" else {"malicious"}
    tp = fp = tn = fn = 0
    for r in results:
        hit = r["label"] in flagged
        if r["expected_bad"]:
            tp, fn = tp + hit, fn + (not hit)
        else:
            fp, tn = fp + hit, tn + (not hit)

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "flag_at": flag_at, "total": len(results),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "incomplete": sum(1 for r in results if not r["complete"]),
        "skipped": sum(1 for r in results if r["label"] == "skipped"),
    }


async def run(labels_path: str, cfg, out: str | None = None, flag_at: str = "suspicious",
              concurrency: int = 1) -> dict:
    from .pipeline import scan_url

    quiet = dataclasses.replace(
        cfg, webhook_url=None, ioc_dir=None, blocklist_path=None, purge_on_malicious=False,
        honeytoken={}, rescan_auto=False,
    )
    rows = load_labels(labels_path)
    gate = asyncio.Semaphore(max(1, concurrency))

    async def one(url: str, bad: bool) -> dict:
        async with gate:
            try:
                v = await scan_url(url, quiet)
                return {"url": url, "expected_bad": bad, "label": v.label, "score": v.score,
                        "complete": v.complete, "signals": [s.name for s in v.signals],
                        "scan": Path(v.artifacts_dir).name if v.artifacts_dir else None}
            except Exception as exc:
                return {"url": url, "expected_bad": bad, "label": "error", "score": 0,
                        "complete": False, "signals": [], "error": str(exc).splitlines()[0]}

    results = list(await asyncio.gather(*(one(u, b) for u, b in rows)))
    report = {"summary": score(results, flag_at), "results": results}
    if out:
        Path(out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
