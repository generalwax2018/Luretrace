"""A file-backed job queue between front ends (console, ingest) and the isolated worker.

The console should not detonate: that would make the console host a detonation host. It drops
a job file here instead, and the worker (`luretrace watch` or `luretrace drain`) claims and runs
it. A directory is the whole contract, so it works over a shared volume with no broker.

Each job is written to a temp name and renamed into place (atomic), and claimed by renaming it
to *.claimed, so two workers never run the same job.
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


@dataclass
class Job:
    kind: str                 # "url" | "eml"
    path: Path                # the claimed file
    url: str | None = None
    raw: bytes | None = None
    source: str = "inbox"
    context: dict | None = None


def _name(suffix: str) -> str:
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%f}-{secrets.token_hex(4)}{suffix}"


def _write_atomic(target: Path, data: bytes) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    return target


def enqueue_url(inbox: str | Path, url: str, source: str = "console", context=None) -> Path:
    payload = {"url": url, "source": source, "context": context or {},
               "submitted_at": datetime.now(timezone.utc).isoformat()}
    return _write_atomic(Path(inbox) / _name(".url.json"), json.dumps(payload).encode())


def enqueue_eml(inbox: str | Path, raw: bytes) -> Path:
    return _write_atomic(Path(inbox) / _name(".eml"), raw)


def claim(inbox: str | Path, limit: int = 50) -> Iterator[Job]:
    root = Path(inbox)
    if not root.is_dir():
        return
    for path in sorted(root.iterdir())[: limit * 4]:
        if not path.is_file() or not path.name.endswith((".url.json", ".eml")):
            continue
        claimed = path.with_name(path.name + ".claimed")
        try:
            os.replace(path, claimed)  # first worker to rename it owns it
        except OSError:
            continue
        try:
            if path.name.endswith(".eml"):
                yield Job("eml", claimed, raw=claimed.read_bytes())
            else:
                d = json.loads(claimed.read_text(encoding="utf-8"))
                yield Job("url", claimed, url=str(d["url"]), source=d.get("source", "inbox"),
                          context=d.get("context") or {})
        except Exception:
            fail(Job("url", claimed))
        limit -= 1
        if limit <= 0:
            return


def done(job: Job) -> None:
    try:
        job.path.unlink()
    except OSError:
        pass


def fail(job: Job) -> None:
    """Park a job that could not be run so it is visible, not retried forever."""
    failed = job.path.parent / "failed"
    failed.mkdir(exist_ok=True)
    try:
        os.replace(job.path, failed / job.path.name.removesuffix(".claimed"))
    except OSError:
        pass
