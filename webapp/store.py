"""Read verdicts the engine wrote (one report.json per scan dir) and summarise them.

The GUI is deliberately a reader over the same artifacts the CLI/worker produce, so it
works the same whether a scan was triggered by hand, by the mailbox watcher, or by an
ingest connector. No database required; point it at the scans directory.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

LABEL_ORDER = {"malicious": 0, "suspicious": 1, "skipped": 2, "clean": 3}
FAIL_LABELS = {"malicious", "suspicious"}


def scans_dir() -> Path:
    return Path(os.environ.get("LURETRACE_SCANS", "./scans")).expanduser()


def _scan_id(report_path: Path) -> str:
    return report_path.parent.name


_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def valid_scan_id(scan_id: str) -> bool:
    return bool(_SCAN_ID.match(scan_id or "")) and ".." not in scan_id


def _row(report: Path) -> dict | None:
    try:
        v = json.loads(report.read_text(encoding="utf-8"))
    except Exception:
        return None
    hops = v.get("hops", [])
    final = ""
    for h in hops:
        final = h.get("final_url") or h.get("requested_url") or final
    return {
        "id": _scan_id(report),
        "label": v.get("label", "skipped"),
        "score": v.get("score", 0),
        "complete": v.get("complete", True),
        "url": v.get("url", ""),
        "original_url": v.get("original_url", ""),
        "final_url": final,
        "hops": len(hops),
        "signals": len(v.get("signals", [])),
        "message_id": v.get("message_id"),
        "origin": v.get("origin", "body"),
        "started_at": v.get("started_at", ""),
    }


def load_index() -> list[dict]:
    """Every scan as a lightweight row, newest first."""
    root = scans_dir()
    if not root.exists():
        return []
    rows = [r for r in (_row(p) for p in root.glob("*/report.json")) if r]
    rows.sort(key=lambda r: r["started_at"], reverse=True)
    return rows


class IncrementalIndex:
    """Yields rows only for report.json files that are new (or rewritten) since the last call.

    Scan directories are written once, so after the first pass each refresh costs a directory
    listing and a stat per scan, not a JSON parse per scan.
    """

    def __init__(self):
        self._seen: dict[str, float] = {}
        self._root: Path | None = None

    def new_rows(self) -> list[dict]:
        root = scans_dir()
        if root != self._root:  # LURETRACE_SCANS changed (tests, reconfiguration)
            self._seen, self._root = {}, root
        if not root.exists():
            return []
        rows = []
        for report in root.glob("*/report.json"):
            key = str(report)
            try:
                mtime = report.stat().st_mtime
            except OSError:
                continue
            if self._seen.get(key) == mtime:
                continue
            row = _row(report)
            if row is not None:
                self._seen[key] = mtime
                rows.append(row)
        return rows


def load_scan(scan_id: str) -> dict | None:
    if not valid_scan_id(scan_id):
        return None
    report = scans_dir() / scan_id / "report.json"
    if not report.is_file():
        return None
    try:
        return json.loads(report.read_text())
    except Exception:
        return None


def stats(rows: list[dict]) -> dict:
    by_label = {k: 0 for k in ("malicious", "suspicious", "clean", "skipped")}
    for r in rows:
        by_label[r["label"]] = by_label.get(r["label"], 0) + 1
    scanned = len(rows)
    failed = by_label["malicious"] + by_label["suspicious"]
    incomplete = sum(1 for r in rows if not r["complete"])
    return {
        "scanned": scanned,
        "failed": failed,
        "passed": by_label["clean"],
        "malicious": by_label["malicious"],
        "suspicious": by_label["suspicious"],
        "skipped": by_label["skipped"],
        "incomplete": incomplete,
        "fail_rate": round(100 * failed / scanned) if scanned else 0,
    }


def recent_fails(rows: list[dict], limit: int = 8) -> list[dict]:
    return [r for r in rows if r["label"] in FAIL_LABELS][:limit]


def fmt_time(iso: str) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso
