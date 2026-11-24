"""Click-time decision engine: given a URL, return allow / block / isolate / scan, fast.

This is enforcement-agnostic. An inline web-gateway policy, a redirect/interstitial service, or a
managed browser extension all make the same call and act on the same decision. The engine itself
holds no browser and never blocks on a detonation — it answers from a verdict cache that the
pre-scan (delivery-time) pipeline fills. An unknown link fails SAFE (isolate), not open.

Decision model:
  non-http(s)   -> block
  sim           -> allow   (never block a training exercise; log it)
  allowlisted   -> allow
  cache: clean  -> allow   (until clean_max_age_h: links are armed after delivery)
  cache: stale clean -> unknown action
  cache: skipped-> allow   (internal / non-public)
  cache: susp.  -> isolate (policy: may be block)
  cache: malic. -> block
  cache miss    -> isolate (policy: may be scan/allow/block)
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from luretrace import simcheck
from luretrace.domains import in_domains
from luretrace.unwrap import unwrap

from . import store


@dataclass
class Policy:
    suspicious_action: str = "isolate"     # isolate | block | allow
    unknown_action: str = "isolate"        # isolate | block | allow | scan
    sim_action: str = "allow"              # allow | isolate
    allowlist_domains: list[str] = field(default_factory=list)
    sim_domains: list[str] = field(default_factory=list)
    sim_headers: list[str] = field(default_factory=list)
    sim_trust_unauthenticated: bool = False  # accept sim mail without DMARC/DKIM pass
    isolation_url: str | None = None       # RBI base; the gate appends ?url=<target>
    clean_max_age_h: float = 24.0          # a clean verdict older than this is re-treated as unknown
    cache_ttl_s: int = 5

    @classmethod
    def from_env(cls) -> "Policy":
        def lst(name):
            return [x for x in os.environ.get(name, "").split(",") if x]
        return cls(
            suspicious_action=os.environ.get("LURETRACE_SUSPICIOUS_ACTION", "isolate"),
            unknown_action=os.environ.get("LURETRACE_UNKNOWN_ACTION", "isolate"),
            sim_action=os.environ.get("LURETRACE_SIM_ACTION", "allow"),
            allowlist_domains=lst("LURETRACE_ALLOWLIST"),
            sim_domains=lst("LURETRACE_SIM_DOMAINS"),
            sim_headers=lst("LURETRACE_SIM_HEADERS"),
            sim_trust_unauthenticated=os.environ.get(
                "LURETRACE_SIM_TRUST_UNAUTHENTICATED", "") in ("1", "true", "yes"),
            isolation_url=os.environ.get("LURETRACE_ISOLATION_URL") or None,
            clean_max_age_h=float(os.environ.get("LURETRACE_CLEAN_MAX_AGE_H", "24")),
        )


@dataclass
class Decision:
    action: str            # allow | block | isolate | scan
    reason: str
    url: str               # unwrapped target
    label: str | None = None
    score: int | None = None
    scan_id: str | None = None
    sim: bool = False

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _without_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(parts._replace(fragment=""))


class VerdictCache:
    """url -> latest verdict row, refreshed incrementally from the scans directory.

    Only report.json files not seen before are parsed, and a forced refresh on a cache miss is
    rate-limited, so a flood of unknown links cannot turn every click into a full disk scan.
    """

    def __init__(self, ttl_s: int = 5, miss_refresh_s: float = 1.0):
        self.ttl_s = ttl_s
        self.miss_refresh_s = miss_refresh_s
        self._index = store.IncrementalIndex()
        self._by_url: dict[str, dict] = {}
        self._loaded = float("-inf")

    def _refresh(self, force: bool = False) -> None:
        now = time.monotonic()
        wait = self.miss_refresh_s if force else self.ttl_s
        if (now - self._loaded) < wait:
            return
        for row in self._index.new_rows():
            for key in {row["url"], _without_fragment(row["url"])}:
                current = self._by_url.get(key)
                if current is None or row["started_at"] >= current["started_at"]:
                    self._by_url[key] = row
        self._loaded = now

    def _lookup(self, url: str) -> dict | None:
        return self._by_url.get(url) or self._by_url.get(_without_fragment(url))

    def get(self, url: str) -> dict | None:
        self._refresh()
        hit = self._lookup(url)
        if hit is None:
            self._refresh(force=True)  # a just-delivered pre-scan may have landed
            hit = self._lookup(url)
        return hit


_cache = VerdictCache()


def _age_hours(iso: str) -> float | None:
    try:
        when = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 3600


def decide(raw_url: str, policy: Policy, headers: dict | None = None,
           cache: VerdictCache | None = None, mimecast_cfg: dict | None = None) -> Decision:
    cache = cache or _cache
    url = unwrap(raw_url, mimecast_cfg)

    if urlsplit(url).scheme.lower() not in ("http", "https"):
        return Decision("block", "unsupported_scheme", url)

    if simcheck.is_sim_url(url, policy.sim_domains) or simcheck.is_sim_email(
        headers, policy.sim_headers, policy.sim_domains, policy.sim_trust_unauthenticated
    ):
        act = "isolate" if policy.sim_action == "isolate" else "allow"
        return Decision(act, "phishing_simulation", url, sim=True)

    if in_domains(url, policy.allowlist_domains):
        return Decision("allow", "allowlisted", url)

    row = cache.get(url)
    if row is None:
        act = policy.unknown_action
        return Decision(act, "not_yet_scanned", url)

    label = row.get("label")
    base = {"url": url, "label": label, "score": row.get("score"), "scan_id": row.get("id")}
    if label == "malicious":
        return Decision("block", "malicious_verdict", **base)
    if label == "suspicious":
        return Decision(policy.suspicious_action, "suspicious_verdict", **base)
    if label == "clean":
        age = _age_hours(row.get("started_at", ""))
        if policy.clean_max_age_h > 0 and (age is None or age > policy.clean_max_age_h):
            return Decision(policy.unknown_action, "stale_clean_verdict", **base)
        return Decision("allow", "clean_verdict", **base)
    if label == "skipped":
        return Decision("allow", "skipped_verdict", **base)
    return Decision(policy.unknown_action, "unknown_label", **base)
