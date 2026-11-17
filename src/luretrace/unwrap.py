"""Decode links rewritten by email security gateways back to the real destination."""
from __future__ import annotations

import re
import string
from base64 import urlsafe_b64decode
from urllib.parse import parse_qs, unquote, urlsplit

from .domains import host_of

_PP_V3 = re.compile(r"v3/__(?P<url>.+?)__;(?P<enc>.*?)!")
_PP_V3_TOKEN = re.compile(r"\*(\*.)?")
_PP_V3_SLASH = re.compile(r"^([a-z0-9+.-]+:/)([^/].*)", re.I)
_RUN_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_PP_V3_RUNS = {c: i + 2 for i, c in enumerate(_RUN_CHARS)}


def _safelinks(url: str) -> str | None:
    if not host_of(url).endswith("safelinks.protection.outlook.com"):
        return None
    target = parse_qs(urlsplit(url).query).get("url")
    return target[0] if target else None


def _proofpoint_v2(url: str) -> str | None:
    parts = urlsplit(url)
    if not (parts.hostname or "").endswith("urldefense.proofpoint.com") or "/v2/" not in parts.path:
        return None
    u = parse_qs(parts.query).get("u")
    if not u:
        return None
    return unquote(u[0].replace("-", "%").replace("_", "/"))


def _proofpoint_v3(url: str) -> str | None:
    if "urldefense" not in host_of(url):
        return None
    m = _PP_V3.search(url)
    if not m:
        return None
    encoded = unquote(m.group("url"))
    try:
        replacements = urlsafe_b64decode(m.group("enc") + "==").decode("utf-8", "replace")
    except Exception:
        replacements = ""
    pos = 0

    def sub(match: re.Match) -> str:
        nonlocal pos
        token = match.group(0)
        length = 1 if token == "*" else _PP_V3_RUNS.get(token[-1], 0)
        chunk = replacements[pos:pos + length]
        pos += length
        return chunk

    decoded = _PP_V3_TOKEN.sub(sub, encoded)
    fixed = _PP_V3_SLASH.match(decoded)
    return f"{fixed.group(1)}/{fixed.group(2)}" if fixed else decoded


def is_mimecast(url: str) -> bool:
    host = host_of(url)
    return host.endswith("mimecastprotect.com") or (
        host.endswith("mimecast.com") and host.startswith(("protect", "url", "secure"))
    )


def _mimecast(url: str, cfg: dict) -> str | None:
    """Decode through the Mimecast API. Needs API 2.0 client credentials.

    Endpoint paths follow Mimecast's published API 2.0 docs; verify against your tenant.
    """
    if not is_mimecast(url) or not cfg.get("client_id"):
        return None
    import httpx

    base = cfg.get("base_url", "https://api.services.mimecast.com")
    with httpx.Client(timeout=20) as client:
        token = client.post(
            f"{base}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
        ).json()["access_token"]
        resp = client.post(
            f"{base}/api/ttp/url/decode-url",
            headers={"Authorization": f"Bearer {token}"},
            json={"data": [{"url": url}]},
        ).json()
    data = resp.get("data") or []
    return data[0].get("url") if data and data[0].get("success", True) else None


def unwrap(url: str, mimecast_cfg: dict | None = None, max_layers: int = 5) -> str:
    """Peel rewriting layers until the URL stops changing."""
    for _ in range(max_layers):
        decoded = _safelinks(url) or _proofpoint_v2(url) or _proofpoint_v3(url)
        if not decoded and mimecast_cfg:
            try:
                decoded = _mimecast(url, mimecast_cfg)
            except Exception:
                decoded = None
        if not decoded or decoded == url:
            break
        url = decoded
    return url
