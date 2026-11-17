"""Turn a captured chain into scored signals and a verdict label."""
from __future__ import annotations

import re

from .chain import is_file_share
from .domains import in_domains, registrable
from .models import Hop, Signal

BRANDS = {
    "Microsoft": {
        "legit": {
            "microsoft.com", "microsoftonline.com", "microsoftonline.us", "live.com", "office.com",
            "office365.com", "sharepoint.com", "outlook.com", "onedrive.com", "msauth.net",
            "msftauth.net", "azure.com", "windows.net", "microsoft365.com", "cloud.microsoft",
        },
        "resources": {
            "aadcdn.msauth.net", "aadcdn.msftauth.net", "logincdn.msauth.net",
            "login.microsoftonline.com", "login.live.com", "aadcdn.msauthimages.net",
        },
        "text": [r"sign in to your account", r"microsoft\s*365", r"\boutlook\b", r"\bonedrive\b",
                 r"\bsharepoint\b", r"can.t access your account", r"\bmicrosoft\b"],
    },
    "Google": {
        "legit": {"google.com", "gstatic.com", "googleusercontent.com", "youtube.com", "withgoogle.com"},
        "resources": {"accounts.google.com", "ssl.gstatic.com"},
        "text": [r"sign in.{0,40}google", r"google account", r"\bgmail\b", r"google workspace"],
    },
    "Okta": {
        "legit": {"okta.com", "oktacdn.com", "okta-emea.com", "oktapreview.com"},
        "resources": {"ok1static.oktacdn.com", "ok12static.oktacdn.com"},
        "text": [r"\bokta\b"],
    },
    "DocuSign": {
        "legit": {"docusign.com", "docusign.net"},
        "resources": {"docucdn-a.akamaihd.net"},
        "text": [r"\bdocusign\b"],
    },
    "Dropbox": {
        "legit": {"dropbox.com", "dropboxstatic.com", "dropboxusercontent.com"},
        "resources": {"cfl.dropboxstatic.com"},
        "text": [r"\bdropbox\b"],
    },
}


def detect_brand(hop: Hop) -> tuple[str, str] | None:
    """Return (brand, strength) where strength is 'resource' or 'text'."""
    hosts = set(hop.resource_hosts)
    haystack = f"{hop.title}\n{hop.text_excerpt}"
    text_hit = None
    for brand, spec in BRANDS.items():
        if hosts & spec["resources"]:
            return brand, "resource"
        if text_hit is None and any(re.search(p, haystack, re.I) for p in spec["text"]):
            text_hit = brand
    return (text_hit, "text") if text_hit else None


def evaluate(hops: list[Hop], complete: bool, trusted_login_domains=()) -> list[Signal]:
    signals: list[Signal] = []
    if not hops:
        return [Signal("no_capture", 30, "Nothing could be captured for this link")]

    first, last = hops[0], hops[-1]
    started_on_share = is_file_share(first.requested_url) or is_file_share(first.final_url)

    for hop in hops:
        has_creds = hop.has_password_field or hop.has_email_field
        url = hop.final_url or hop.requested_url
        if has_creds and not in_domains(url, trusted_login_domains):
            brand = detect_brand(hop)
            if brand and not in_domains(url, BRANDS[brand[0]]["legit"]):
                name, strength = brand
                score = 80 if strength == "resource" else 60
                if not hop.has_password_field:
                    score -= 15  # email-only first step: common in AiTM kits, but weaker evidence
                signals.append(Signal(
                    "brand_login_off_domain", score,
                    f"{name} sign-in page served from {registrable(url)} ({strength} match)", hop.index,
                ))
            elif not brand and hop.has_password_field and hop.index > 0:
                signals.append(Signal(
                    "credential_form_after_hop", 30,
                    f"Password form on {registrable(url)} reached by following a link", hop.index,
                ))
            for action in hop.form_actions:
                if action.startswith("http") and registrable(action) != registrable(url):
                    signals.append(Signal(
                        "cross_domain_form_post", 15,
                        f"Form posts to {registrable(action)}", hop.index,
                    ))
                    break
        if hop.captcha:
            signals.append(Signal("captcha_gate", 15, f"{hop.captcha} challenge in the chain", hop.index))
        for dl in hop.downloads:
            signals.append(Signal(
                "download_triggered", 25,
                f"Download {dl.get('filename')} sha256={dl.get('sha256')}", hop.index,
            ))
        if hop.blocked_requests:
            signals.append(Signal(
                "internal_address_probe", 40,
                f"Page tried to reach non-public address {hop.blocked_requests[0]}", hop.index,
            ))

    creds_at_end = last.has_password_field or last.has_email_field
    if started_on_share and len(hops) > 1 and creds_at_end:
        end = last.final_url or last.requested_url
        if registrable(end) != registrable(first.final_url or first.requested_url):
            signals.append(Signal(
                "fileshare_lure_to_login", 20,
                f"File-share link led to a credential form on {registrable(end)}", last.index,
            ))

    redirect_count = sum(len(h.redirects) for h in hops)
    if redirect_count > 3:
        signals.append(Signal("long_redirect_chain", 10, f"{redirect_count} HTTP redirects"))

    if not complete:
        signals.append(Signal(
            "chain_incomplete", 30,
            "Could not reach the end of the chain (error, gate or hop limit); treat as unverified",
        ))
    return signals


def label_for(score: int, malicious: int = 70, suspicious: int = 30) -> str:
    if score >= malicious:
        return "malicious"
    if score >= suspicious:
        return "suspicious"
    return "clean"


def total(signals: list[Signal]) -> int:
    return min(100, sum(s.score for s in signals))
