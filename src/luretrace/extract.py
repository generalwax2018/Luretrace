"""Pull URLs out of an email message (bodies and text/html attachments)."""
from __future__ import annotations

import email
import re
from email import policy
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b(?:https?|hxxps?)://[^\s<>"'\)\]]+""")
TRAILING = ".,;:!?>"


def refang(url: str) -> str:
    url = re.sub(r"(?i)^hxxp", "http", url.strip())
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")
    return url


class _HrefParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value and key in ("href", "src", "action", "formaction") and tag in (
                "a", "area", "form", "iframe", "button", "meta"
            ):
                self.urls.append(value)
            if tag == "meta" and key == "content" and value and "url=" in value.lower():
                self.urls.append(value.lower().split("url=", 1)[1].strip(" '\""))

    def handle_data(self, data):
        self.text.append(data)


def urls_from_html(html: str) -> list[str]:
    parser = _HrefParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.urls + urls_from_text(" ".join(parser.text))


def urls_from_text(text: str) -> list[str]:
    return [m.group(0).rstrip(TRAILING) for m in URL_RE.finditer(refang_text(text))]


def refang_text(text: str) -> str:
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def extract_urls(raw: bytes) -> tuple[dict, list[str]]:
    """Return (message metadata, de-duplicated http(s) URLs) from raw RFC 822 bytes."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    found: list[str] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        try:
            body = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            body = payload.decode("utf-8", "replace")
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        found += urls_from_html(body) if ctype == "text/html" else urls_from_text(body)

    seen, urls = set(), []
    for u in found:
        u = refang(u)
        if not u.lower().startswith(("http://", "https://")) or u in seen:
            continue
        seen.add(u)
        urls.append(u)
    meta = {
        "message_id": str(msg.get("Message-ID", "")).strip(),
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
    }
    return meta, urls
