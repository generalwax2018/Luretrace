"""Rescan queue: re-detonate a link at later offsets to catch links armed after delivery.

A clean first scan is not a durable verdict. Attackers commonly point a link at a benign
page through delivery and the first security scan, then swap in the phishing page. This
queue re-runs the same URL at configured offsets and flags any verdict that worsens.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class RescanItem:
    url: str
    created_at: str
    offsets_minutes: list[int]
    message_id: str | None = None
    done_offsets: list[int] = field(default_factory=list)
    first_label: str | None = None
    origin: str = "body"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def next_due_offset(item: RescanItem, now: datetime | None = None) -> int | None:
    """Return the earliest offset that is due and not yet run, else None."""
    now = now or _now()
    created = datetime.fromisoformat(item.created_at)
    elapsed_min = (now - created).total_seconds() / 60
    pending = sorted(o for o in item.offsets_minutes if o not in item.done_offsets)
    for offset in pending:
        if elapsed_min >= offset:
            return offset
    return None


class RescanQueue:
    """Tiny JSON-backed queue. One process polls it; concurrency is not a goal here."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.items: list[RescanItem] = []
        if self.path.exists():
            known = set(RescanItem.__dataclass_fields__)
            self.items = [RescanItem(**{k: v for k, v in d.items() if k in known})
                          for d in json.loads(self.path.read_text(encoding="utf-8"))]

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps([asdict(i) for i in self.items], indent=2), encoding="utf-8")
        os.replace(tmp, self.path)  # a crash mid-write never leaves a truncated queue

    def add(self, url: str, offsets: list[int], message_id=None, first_label=None,
            origin: str = "body") -> None:
        if any(i.url == url and i.message_id == message_id for i in self.items):
            return
        self.items.append(RescanItem(
            url=url, created_at=_now().isoformat(), offsets_minutes=sorted(offsets),
            message_id=message_id, first_label=first_label, origin=origin,
        ))
        self._save()

    def due(self, now: datetime | None = None) -> list[tuple[RescanItem, int]]:
        return [(i, o) for i in self.items if (o := next_due_offset(i, now)) is not None]

    def mark_done(self, item: RescanItem, offset: int) -> None:
        if offset not in item.done_offsets:
            item.done_offsets.append(offset)
        # Drop items that have completed every offset.
        self.items = [i for i in self.items
                      if set(i.done_offsets) != set(i.offsets_minutes)]
        self._save()
