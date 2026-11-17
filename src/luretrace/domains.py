from __future__ import annotations

from urllib.parse import urlsplit

import tldextract

# Use the suffix list bundled with tldextract; never fetch at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=())


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def registrable(url_or_host: str) -> str:
    """Return the registrable domain (eTLD+1), e.g. login.evil.co.uk -> evil.co.uk."""
    host = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower()
    ext = _extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def in_domains(url_or_host: str, domains) -> bool:
    """True if the host equals or is a subdomain of any entry in domains."""
    host = host_of(url_or_host) if "://" in url_or_host else url_or_host.lower()
    return any(host == d or host.endswith("." + d) for d in (x.lower() for x in domains))
