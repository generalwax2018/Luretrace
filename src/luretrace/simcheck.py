"""Recognise phishing-simulation traffic so the gate never blocks a training exercise.

A click-time gate that blocks real phishing must *pass through* your own awareness-training
campaigns — the teachable landing page is the whole point, and blocking it corrupts the metrics
and the lesson. Simulation platforms are identifiable by their sending/landing domains and by
headers they stamp on the mail (the same signals Microsoft's "Advanced Delivery" allow-list uses).

These default lists are a seed. Maintain them for your vendors and campaigns via config —
treat them as an allowlist you own, not a guarantee.
"""
from __future__ import annotations

from .domains import in_domains

# Headers simulation platforms commonly stamp. Case-insensitive match on the key.
SIM_HEADERS = {
    "x-phishtest",
    "x-phish-test",
    "x-knowbe4",
    "x-kb4",
    "x-ms-exchange-organization-phishing-simulation",
    "x-proofpoint-psat",
    "x-cofense-phishme",
}

# Seed domains. Add your sim vendor's sending and landing domains in config.
SIM_DOMAINS = {
    "knowbe4.com",
    "phishedu.com",
    "cofense.com",
    "phishme.com",
}


def is_sim_url(url: str, extra_domains=()) -> bool:
    domains = set(SIM_DOMAINS) | {d.lower() for d in extra_domains}
    return in_domains(url, domains)


def is_sim_email(headers: dict | None, extra_headers=(), extra_domains=()) -> bool:
    """headers: a mapping of mail header name -> value (e.g. from email.message)."""
    if not headers:
        return False
    keys = {k.lower() for k in headers}
    if keys & (SIM_HEADERS | {h.lower() for h in extra_headers}):
        return True
    for field in ("from", "return-path", "sender"):
        value = ""
        for k, v in headers.items():
            if k.lower() == field:
                value = v or ""
                break
        if value and is_sim_url("http://" + value.split("@")[-1].strip(" <>"), extra_domains):
            return True
    return False
