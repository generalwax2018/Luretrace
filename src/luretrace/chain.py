"""Decide which link on a lure page to follow next."""
from __future__ import annotations

import re

from .domains import in_domains, registrable

FILE_SHARE_DOMAINS = {
    "sharepoint.com", "1drv.ms", "onedrive.live.com", "dropbox.com", "dropboxusercontent.com",
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "box.com",
    "docusign.net", "docusign.com", "wetransfer.com", "we.tl", "canva.com", "notion.site",
    "notion.so", "evernote.com", "adobe.com", "acrobat.com", "egnyte.com", "sharefile.com",
    "smartsheet.com", "figma.com", "padlet.com", "linktr.ee", "github.io", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "blob.core.windows.net", "amazonaws.com",
}

# Footer/boilerplate destinations that are never the next step of a lure.
BORING_DOMAINS = {
    "microsoft.com", "office.com", "live.com", "google.com", "gstatic.com", "apple.com",
    "w3.org", "aka.ms", "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "instagram.com", "mozilla.org", "cloudflare.com",
}

LURE_WORDS = re.compile(
    r"(?i)\b(view|open|review|access|download|read|see|preview|continue|proceed|sign|verify|"
    r"document|file|pdf|invoice|statement|message|voicemail|fax|proposal|contract|click here)\b"
)


def is_file_share(url: str) -> bool:
    return in_domains(url, FILE_SHARE_DOMAINS)


def pick_next(links: list[dict], current_url: str, seen: set[str]) -> dict | None:
    """Choose the most lure-like external link from a page, or None to stop.

    links: [{"href": str, "text": str}, ...] gathered from every frame on the page.
    """
    here = registrable(current_url)
    candidates = []
    for link in links:
        href = (link.get("href") or "").strip()
        if not href.lower().startswith(("http://", "https://")) or href in seen:
            continue
        reg = registrable(href)
        if reg == here or reg in BORING_DOMAINS:
            continue
        text = link.get("text") or ""
        score = 2 * len(LURE_WORDS.findall(text)) + (1 if LURE_WORDS.search(href) else 0)
        candidates.append((score, href, text))
    if not candidates:
        return None
    candidates.sort(key=lambda c: -c[0])
    best = candidates[0]
    distinct = {registrable(c[1]) for c in candidates}
    # Follow a keyword match, or the only external destination on a sparse page.
    if best[0] > 0 or len(distinct) == 1:
        return {"href": best[1], "text": best[2]}
    return None
