"""Click-time decision engine: given a URL, return allow / block / isolate / scan, fast.

This is enforcement-agnostic. A Netskope inline policy, a redirect/interstitial service, or a
managed browser extension all make the same call and act on the same decision. The engine itself
holds no browser and never blocks on a detonation — it answers from a verdict cache that the
pre-scan (delivery-time) pipeline fills. An unknown link fails SAFE (isolate), not open.

Decision model:
  sim           -> allow   (never block a training exercise; log it)
  allowlisted   -> allow
  cache: clean  -> allow
  cache: skipped-> allow   (internal / non-public)
  cache: susp.  -> isolate (policy: may be block)
  cache: malic. -> block
  cache miss    -> isolate (policy: may be scan/allow/block)
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

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
    isolation_url: str | None = None       # RBI base; the gate appends ?url=<target>
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
            isolation_url=os.environ.get("LURETRACE_ISOLATION_URL") or None,
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
        return self.__dict__


class VerdictCache:
    """In-memory map url -> verdict row, refreshed from the scans index on a short TTL."""

    def __init__(self, ttl_s: int = 5):
        self.ttl_s = ttl_s
        self._by_url: dict[str, dict] = {}
        self._loaded = 0.0

    def _refresh(self, force: bool = False) -> None:
        if not force and (time.monotonic() - self._loaded) < self.ttl_s:
            return
        rows = store.load_index()
        # Newest first from load_index; keep the first (latest) verdict per URL.
        by_url: dict[str, dict] = {}
        for r in rows:
            by_url.setdefault(r["url"], r)
        self._by_url = by_url
        self._loaded = time.monotonic()

    def get(self, url: str) -> dict | None:
        self._refresh()
        hit = self._by_url.get(url)
        if hit is None:
            self._refresh(force=True)  # a just-delivered pre-scan may have landed
            hit = self._by_url.get(url)
        return hit


_cache = VerdictCache()


def decide(raw_url: str, policy: Policy, headers: dict | None = None,
           cache: VerdictCache | None = None, mimecast_cfg: dict | None = None) -> Decision:
    cache = cache or _cache
    url = unwrap(raw_url, mimecast_cfg)

    if simcheck.is_sim_url(url, policy.sim_domains) or simcheck.is_sim_email(
        headers, policy.sim_headers, policy.sim_domains
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
    if label in ("clean", "skipped"):
        return Decision("allow", f"{label}_verdict", **base)
    return Decision(policy.unknown_action, "unknown_label", **base)
