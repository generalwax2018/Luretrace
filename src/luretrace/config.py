from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

# {major} is filled from the launched browser's real version so UA and engine agree.
UA_TEMPLATE = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
)

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value):
    """Replace ${VAR} / ${VAR:-default} in every string, so secrets can stay out of the file."""
    if isinstance(value, str):
        def sub(m: re.Match) -> str:
            name, default = m.group(1), m.group(2)
            if name in os.environ:
                return os.environ[name]
            if default is not None:
                return default
            raise ValueError(f"Config references ${{{name}}} but it is not set in the environment")
        return _ENV_REF.sub(sub, value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


@dataclass
class Config:
    output_dir: str = "./scans"
    # Detonation
    max_hops: int = 5
    nav_timeout_ms: int = 30000
    settle_timeout_ms: int = 8000
    user_agent: str = ""  # empty: match the launched Chromium's real version
    locale: str = "en-US"
    timezone: str = "America/New_York"  # keep in line with where your egress IP geolocates
    proxy: str | None = None  # http:// egress proxy, e.g. http://user:pass@egress-proxy:8080
    allow_private_networks: bool = False  # tests only; never enable in production
    record_har: bool = True
    stealth: bool = True  # hide common automation tells (navigator.webdriver, automation flag)
    browser_channel: str | None = "chromium"  # full Chromium's new headless; None = headless shell
    # Triage
    allowlist_domains: list[str] = field(default_factory=list)  # never detonated
    trusted_login_domains: list[str] = field(default_factory=list)  # your real IdP / SSO
    # Extraction
    scan_attachments: bool = True  # HTML/SVG attachments, QR codes in images (needs [qr] extra)
    max_attachment_bytes: int = 10_000_000
    # Enrichment
    rdap: bool = False  # look up domain registration age (network call to the RDAP registry)
    young_domain_days: int = 30
    # Scoring
    malicious_threshold: int = 70
    suspicious_threshold: int = 30
    # Link unwrapping
    mimecast: dict = field(default_factory=dict)  # client_id, client_secret, base_url
    # Mail sources
    imap: dict = field(default_factory=dict)
    graph: dict = field(default_factory=dict)
    poll_seconds: int = 60
    max_attempts: int = 3  # a message that keeps failing is marked processed after this many
    concurrency: int = 1  # links of one message detonated in parallel (one browser each)
    # Job inbox drained by `watch` / `drain` (the console and ingest queue work here).
    inbox_dir: str | None = None
    # Ingest connector for `luretrace ingest`: {kind: mimecast|datalake, ...connector settings}
    ingest: dict = field(default_factory=dict)
    # Actions
    webhook_url: str | None = None
    webhook_headers: dict = field(default_factory=dict)
    webhook_secret: str | None = None  # signs the body: X-Luretrace-Signature: sha256=<hmac>
    webhook_retries: int = 3
    notify_on: list[str] = field(default_factory=lambda: ["suspicious", "malicious"])
    ioc_dir: str | None = None  # write an IOC file per malicious/suspicious verdict
    blocklist_path: str | None = None  # append malicious domains (one per line) for Netskope etc.
    purge_on_malicious: bool = False  # soft-delete the message from recipients' mailboxes (Graph)
    # Rescan: links are often armed after delivery, so re-detonate at these offsets.
    rescan_auto: bool = True  # queue links from scanned mail; run `luretrace rescan` on a cron
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
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config keys: {sorted(unknown)}")
        return cls(**_expand_env(data))
