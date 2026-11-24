"""Optional enrichment that needs the network: domain registration age over RDAP.

Phishing domains are usually days old. RDAP (the successor to WHOIS) returns the registration
date as JSON. rdap.org redirects each query to the authoritative registry. Off by default
(`rdap: true` to enable); the lookup is about the attacker's domain only, never your data.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .domains import in_domains, registrable
from .models import Hop, Signal

RDAP_URL = "https://rdap.org/domain/{domain}"
_cache: dict[str, int | None] = {}


def registration_age_days(payload: dict, now: datetime | None = None) -> int | None:
    now = now or datetime.now(timezone.utc)
    for event in payload.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                when = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0, (now - when).days)
    return None


async def domain_age_days(domain: str, client: httpx.AsyncClient) -> int | None:
    if domain in _cache:
        return _cache[domain]
    age = None
    try:
        resp = await client.get(RDAP_URL.format(domain=domain), follow_redirects=True,
                                headers={"Accept": "application/rdap+json"})
        if resp.status_code == 200:
            age = registration_age_days(resp.json())
    except Exception:
        age = None
    _cache[domain] = age
    return age


def _domains_of_interest(hops: list[Hop], skip=()) -> list[str]:
    """Where credentials are asked for, plus where the chain ended."""
    picked: list[str] = []
    for hop in hops:
        url = hop.final_url or hop.requested_url
        if (hop.has_password_field or hop.has_email_field or hop is hops[-1]) and url:
            reg = registrable(url)
            if reg and reg not in picked and not in_domains(url, skip):
                picked.append(reg)
    return picked


async def age_signals(hops: list[Hop], cfg, skip=()) -> list[Signal]:
    if not cfg.rdap or not hops:
        return []
    signals: list[Signal] = []
    async with httpx.AsyncClient(timeout=10, proxy=cfg.proxy or None) as client:
        for domain in _domains_of_interest(hops, skip):
            age = await domain_age_days(domain, client)
            if age is not None and age < cfg.young_domain_days:
                signals.append(Signal("young_domain", 20,
                                      f"{domain} was registered {age} day(s) ago"))
    return signals
