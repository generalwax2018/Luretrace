from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Hop:
    """One page visited while following a link chain."""

    index: int
    requested_url: str
    final_url: str = ""
    status: int | None = None
    title: str = ""
    redirects: list[str] = field(default_factory=list)
    followed_link_text: str = ""
    has_password_field: bool = False
    has_email_field: bool = False
    form_actions: list[str] = field(default_factory=list)
    resource_hosts: list[str] = field(default_factory=list)
    blocked_requests: list[str] = field(default_factory=list)
    text_excerpt: str = ""
    captcha: str | None = None
    downloads: list[dict] = field(default_factory=list)
    screenshot: str | None = None
    html_path: str | None = None
    error: str | None = None


@dataclass
class Signal:
    name: str
    score: int
    detail: str
    hop: int | None = None


@dataclass
class Verdict:
    url: str
    original_url: str
    label: str  # clean | suspicious | malicious | skipped
    score: int
    complete: bool
    signals: list[Signal] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    started_at: str = ""
    artifacts_dir: str | None = None
    message_id: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
