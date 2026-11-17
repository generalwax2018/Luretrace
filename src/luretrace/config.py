from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


@dataclass
class Config:
    output_dir: str = "./scans"
    # Detonation
    max_hops: int = 5
    nav_timeout_ms: int = 30000
    settle_timeout_ms: int = 8000
    user_agent: str = DEFAULT_UA
    locale: str = "en-US"
    timezone: str = "America/New_York"
    proxy: str | None = None  # e.g. http://user:pass@egress-proxy:8080
    allow_private_networks: bool = False  # tests only; never enable in production
    record_har: bool = True
    # Triage
    allowlist_domains: list[str] = field(default_factory=list)  # never detonated
    trusted_login_domains: list[str] = field(default_factory=list)  # your real IdP / SSO
    # Scoring
    malicious_threshold: int = 70
    suspicious_threshold: int = 30
    # Link unwrapping
    mimecast: dict = field(default_factory=dict)  # client_id, client_secret, base_url
    # Mail sources
    imap: dict = field(default_factory=dict)
    graph: dict = field(default_factory=dict)
    poll_seconds: int = 60
    # Actions
    webhook_url: str | None = None
    webhook_headers: dict = field(default_factory=dict)
    notify_on: list[str] = field(default_factory=lambda: ["suspicious", "malicious"])
    ioc_dir: str | None = None  # write an IOC file per malicious/suspicious verdict
    # Rescan: links are often armed after delivery, so re-detonate at these offsets.
    rescan_offsets_minutes: list[int] = field(default_factory=lambda: [15, 60, 240])
    rescan_queue: str = "./rescan-queue.json"
    # Login-page beacon receiver (detects proxying of your own sign-in page).
    beacon: dict = field(default_factory=dict)  # listen_host, listen_port, trusted_login_hosts, webhook_url
    # Opt-in honeytoken submitted ONLY to verdicts already labelled malicious.
    # You must own or be authorised to run this and comply with local law.
    honeytoken: dict = field(default_factory=dict)  # enabled, username, password

    @classmethod
    def load(cls, path: str | None) -> "Config":
        if not path:
            return cls()
        data = yaml.safe_load(Path(path).read_text()) or {}
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config keys: {sorted(unknown)}")
        return cls(**data)
