"""Recognise phishing-simulation traffic so the gate never blocks a training exercise.

A click-time gate that blocks real phishing must *pass through* your own awareness-training
campaigns — the teachable landing page is the whole point, and blocking it corrupts the metrics
and the lesson. But a passthrough is also a bypass: anything that looks like a simulation is
allowed. So the evidence has to be something an attacker cannot simply type:

* Landing URLs on your simulation vendor's domains (an attacker cannot host there).
* Mail whose sender domain is a simulation domain AND that your own mail system authenticated
  (DMARC pass, or a DKIM pass aligned with that domain, in Authentication-Results).

A simulation header (X-PhishTest and friends) or a From: domain on its own is trivially forged
and never suffices. This mirrors why Microsoft's "Advanced Delivery" for simulations needs both
the sending domain and the sending IP. If your vendor cannot produce authenticated mail, set
trust_unauthenticated=True knowingly (LURETRACE_SIM_TRUST_UNAUTHENTICATED=1 for the gate).

These default lists are a seed. Maintain them for your vendors and campaigns via config.
"""
from __future__ import annotations

import re
from email.utils import parseaddr

from .domains import in_domains

# Headers simulation platforms commonly stamp. Supporting evidence only, never sufficient.
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

_DMARC_PASS = re.compile(r"\bdmarc\s*=\s*pass\b[^;]*?\bheader\.from\s*=\s*([^\s;]+)", re.I)
_DKIM_PASS = re.compile(r"\bdkim\s*=\s*pass\b[^;]*?\bheader\.(?:d|i)\s*=\s*@?([^\s;]+)", re.I)


def is_sim_url(url: str, extra_domains=()) -> bool:
    domains = set(SIM_DOMAINS) | {d.lower() for d in extra_domains}
    return in_domains(url, domains)


def _header(headers: dict, name: str) -> list[str]:
    return [str(v or "") for k, v in headers.items() if k.lower() == name]


def _sender_domain(headers: dict) -> str:
    for field in ("from", "sender", "return-path"):
        for value in _header(headers, field):
            addr = parseaddr(value)[1]
            if "@" in addr:
                return addr.rsplit("@", 1)[1].strip(" <>").lower()
    return ""


def authenticated_domains(headers: dict) -> set[str]:
    """Domains your receiving mail system reported as DMARC- or DKIM-authenticated."""
    domains: set[str] = set()
    for value in _header(headers, "authentication-results"):
        domains |= {d.lower().strip(".") for d in _DMARC_PASS.findall(value)}
        domains |= {d.lower().strip(".").split("@")[-1] for d in _DKIM_PASS.findall(value)}
    return domains


def is_sim_email(headers: dict | None, extra_headers=(), extra_domains=(),
                 trust_unauthenticated: bool = False) -> bool:
    """headers: a mapping of mail header name -> value (e.g. from email.message).

    extra_headers is accepted for compatibility; headers are never sufficient evidence.
    """
    if not headers:
        return False
    sim_domains = set(SIM_DOMAINS) | {d.lower() for d in extra_domains}
    sender = _sender_domain(headers)
    if not sender or not in_domains(sender, sim_domains):
        return False
    if trust_unauthenticated:
        return True
    return any(sender == d or sender.endswith("." + d) or d.endswith("." + sender)
               for d in authenticated_domains(headers))
