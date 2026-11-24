"""Turn a captured chain into scored signals and a verdict label."""
from __future__ import annotations

import re

from .chain import is_file_share
from .domains import in_domains, registrable
from .models import Hop, Signal

# Brand-impersonation model.
#
# The question is not "does this page mention Microsoft?" — every SaaS login with a "Sign in
# with Microsoft" button does — but "does this page claim to BE Microsoft's sign-in?". Evidence:
#
#   resources  the brand's own login-UI assets (decisive). Each host can carry path rules,
#              because some hosts also serve embeddable widgets: "Sign in with Google" loads
#              accounts.google.com/gsi/* on thousands of legitimate sites.
#   markers    strings only the brand's real sign-in page source contains (decisive). An AiTM
#              reverse proxy (Evilginx, Tycoon2FA...) serves that source from its own domain.
#   titles     the brand's exact sign-in title, or the brand named in the title (+2).
#   phrases    wording particular to the brand's sign-in flow (+1 each, at most +2).
#   names      the brand named in the body once SSO-button lines are removed (+1).
#
# Text evidence counts only at >= 2 points and with a title or flow phrase among it, so a page
# that merely names a brand ("Sync with Microsoft Outlook") is not an impersonation.
BRANDS = {
    "Microsoft": {
        "legit": {
            "microsoft.com", "microsoftonline.com", "microsoftonline.us", "live.com", "office.com",
            "office365.com", "sharepoint.com", "outlook.com", "onedrive.com", "msauth.net",
            "msftauth.net", "azure.com", "windows.net", "microsoft365.com", "cloud.microsoft",
        },
        "resources": {
            "aadcdn.msauth.net": None, "aadcdn.msftauth.net": None, "logincdn.msauth.net": None,
            "aadcdn.msauthimages.net": None, "login.microsoftonline.com": None,
            "login.live.com": None,
        },
        "markers": [r"\$Config\s*=\s*\{.{0,4000}?\"(?:urlMsaSignUp|sCtx|arrSessions|"
                    r"urlGetCredentialType)\"", r"\"urlGetCredentialType\"\s*:"],
        "titles": [r"^\s*sign in to your account\s*$", r"\bmicrosoft\b|\boutlook\b|\bonedrive\b|"
                   r"\bsharepoint\b|\boffice\s*365\b|\bmicrosoft\s*365\b"],
        "phrases": [r"can.t access your account", r"no account\?\s*create one",
                    r"\bsign in to your account\b", r"stay signed in\?", r"\bsign-in options\b",
                    r"\b(?:work|school)(?:\s+or\s+school)?\s+account\b",
                    r"\bmicrosoft\s+account\b", r"\bpick an account\b"],
        "names": [r"\bmicrosoft\b", r"\boutlook\b", r"\bonedrive\b", r"\bsharepoint\b",
                  r"\boffice\s*365\b", r"\bmicrosoft\s*365\b"],
    },
    "Google": {
        "legit": {"google.com", "gstatic.com", "googleusercontent.com", "youtube.com", "withgoogle.com"},
        # The real Google sign-in UI; widgets (/gsi/, One Tap, OAuth iframes) are excluded.
        "resources": {
            "accounts.google.com": {"exclude": ("/gsi/", "/o/oauth2/", "/_/idpiframehttp",
                                                "/rotatecookiespage", "/listaccounts",
                                                "/checkcookie", "/servicelogin/webreauth")},
            "ssl.gstatic.com": {"include": ("/accounts/",)},
        },
        "markers": [r"\bGlifWebSignIn\b", r"identity-boq|boq-identity"],
        "titles": [r"sign in\s*[-–|]\s*google accounts", r"\bgoogle\s+accounts?\b", r"\bgmail\b"],
        "phrases": [r"use your google account", r"\bforgot email\?", r"\bgoogle account\b",
                    r"\bto continue to (?:gmail|google|drive|docs)\b"],
        "names": [r"\bgoogle\b", r"\bgmail\b", r"\bgoogle\s+workspace\b"],
    },
    "Okta": {
        "legit": {"okta.com", "oktacdn.com", "okta-emea.com", "oktapreview.com"},
        "resources": {"ok1static.oktacdn.com": None, "ok12static.oktacdn.com": None},
        "markers": [r"okta-sign-in\.min\.js", r"\bOktaSignIn\b"],
        "titles": [r"\bokta\b"],
        "phrases": [r"\bpowered by okta\b", r"\bokta verify\b"],
        "names": [r"\bokta\b"],
    },
    "DocuSign": {
        "legit": {"docusign.com", "docusign.net"},
        "resources": {"docucdn-a.akamaihd.net": None},
        "markers": [],
        "titles": [r"\bdocusign\b"],
        "phrases": [r"\breview (?:the )?document\b", r"\bplease review and sign\b"],
        "names": [r"\bdocusign\b"],
    },
    "Dropbox": {
        "legit": {"dropbox.com", "dropboxstatic.com", "dropboxusercontent.com"},
        "resources": {"cfl.dropboxstatic.com": None},
        "markers": [],
        "titles": [r"\bdropbox\b"],
        "phrases": [r"\bshared (?:a )?(?:file|folder) with you\b.{0,80}\bdropbox\b"],
        "names": [r"\bdropbox\b"],
    },
}

# Every host whose request paths the worker records (for the path rules above).
IDP_ASSET_HOSTS = {h for spec in BRANDS.values() for h in spec["resources"]}

# Federated sign-in providers offered as buttons on ordinary logins.
_PROVIDER = (r"microsoft|google|apple|facebook|github|gitlab|okta|slack|linkedin|sso|passkey|"
             r"chatgpt|openai|amazon|yahoo|x|twitter|dropbox|docusign|saml|email|phone")
_SSO_WORDS = re.compile(rf"(?i)^(?:{_PROVIDER}|sign|log|in|on|up|with|using|via|continue|or|"
                        r"your|account|work|school|single|the|a|an|365|workspace|id|login|"
                        r"another|way|choose|other|options?)$")
_PROVIDER_WORD = re.compile(rf"(?i)^(?:{_PROVIDER})$")
_SSO_PHRASE = re.compile(
    r"(?i)^\s*(?:(?:sign|log)\s*(?:in|on|up)|continue|connect|register)\s+(?:with|using|via)\s+"
    rf"(?:your\s+)?(?:{_PROVIDER}|work\s+account|school\s+account)"
    r"(?:\s+(?:account|365|workspace))?\s*$"
)
# Third-party legal notices that name a brand without the page claiming to be it.
_BOILERPLATE = re.compile(
    r"(?is)protected by recaptcha and the google\s+privacy policy and terms of service apply\.?"
    r"|this site is protected by recaptcha[^\n]{0,200}"
)


def _strip_sso_buttons(text: str) -> str:
    """Drop SSO-button lines ("Continue with Microsoft", or a bare "Google" in a menu of
    providers). A bare brand line is only dropped when the page offers two or more providers:
    a lone "Microsoft" heading on a login page is how a cloned Microsoft sign-in reads."""
    lines = _BOILERPLATE.sub(" ", text).splitlines()

    def provider_only(line: str) -> bool:
        words = re.findall(r"[A-Za-z0-9]+", line)
        return (0 < len(words) <= 5 and all(_SSO_WORDS.match(w) for w in words)
                and any(_PROVIDER_WORD.match(w) for w in words))

    menu = sum(1 for ln in lines if provider_only(ln)) >= 2
    kept = [ln for ln in lines
            if not _SSO_PHRASE.match(ln) and not (menu and provider_only(ln))]
    return "\n".join(kept)


def _resource_hit(hop: Hop, spec: dict) -> bool:
    rules = spec["resources"]
    if hop.idp_requests:
        for item in hop.idp_requests:
            host, _, path = item.partition("/")
            if host not in rules:
                continue
            rule = rules[host] or {}
            path = "/" + path.lower()
            if rule.get("include") and not path.startswith(rule["include"]):
                continue
            if rule.get("exclude") and path.startswith(rule["exclude"]):
                continue
            return True
        return False
    # Reports from before paths were recorded: host-level match, unrestricted hosts only.
    return any(h in rules and not rules[h] for h in hop.resource_hosts)


def _page_source(hop: Hop) -> str:
    if not hop.html_path:
        return ""
    try:
        from pathlib import Path
        return Path(hop.html_path).read_text(encoding="utf-8", errors="replace")[:600_000]
    except OSError:
        return ""


def brand_evidence(hop: Hop, source: str | None = None) -> dict[str, dict]:
    """Per-brand evidence for one page: {"Microsoft": {"points", "strength", "why"}, ...}."""
    title = hop.title or ""
    body = _strip_sso_buttons(hop.text_excerpt or "")
    source = _page_source(hop) if source is None else source
    out: dict[str, dict] = {}
    for brand, spec in BRANDS.items():
        why: list[str] = []
        if _resource_hit(hop, spec):
            out[brand] = {"points": 99, "strength": "resource", "why": ["login-UI assets"]}
            continue
        if source and any(re.search(m, source, re.S) for m in spec["markers"]):
            out[brand] = {"points": 99, "strength": "resource",
                          "why": ["sign-in page source (AiTM proxy or copy)"]}
            continue
        points, anchored = 0, False
        if any(re.search(t, title, re.I) for t in spec["titles"]):
            points, anchored = 2, True
            why.append("title")
        flow = sum(1 for p in spec["phrases"] if re.search(p, body, re.I))
        if flow:
            points += min(flow, 2)
            anchored = True
            why.append(f"{flow} sign-in phrase(s)")
        if any(re.search(n, body, re.I) for n in spec["names"]):
            points += 1
            why.append("named on page")
        if points >= 2 and anchored:
            out[brand] = {"points": points, "strength": "text", "why": why}
    return out


def detect_brand(hop: Hop, source: str | None = None) -> tuple[str, str] | None:
    """Return (brand, strength) for the brand this page impersonates, if any.

    strength is 'resource' (assets or page source: decisive) or 'text'.
    """
    evidence = brand_evidence(hop, source)
    if not evidence:
        return None
    brand = max(evidence, key=lambda b: evidence[b]["points"])
    return brand, evidence[brand]["strength"]


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")


def emails_in_url(url: str) -> set[str]:
    """Email addresses carried in a URL: plain, percent-encoded, or base64-encoded.

    AiTM kits personalise each link with the victim's address so the fake sign-in page is
    pre-filled; a link that carries an address is a strong sign of a targeted lure.
    """
    from base64 import b64decode, urlsafe_b64decode
    from urllib.parse import unquote

    text = unquote(unquote(url))
    found = {m.lower() for m in _EMAIL.findall(text)}
    for token in _B64_TOKEN.findall(text):
        for decoder in (b64decode, urlsafe_b64decode):
            try:
                decoded = decoder(token + "=" * (-len(token) % 4)).decode("utf-8")
            except Exception:
                continue
            found |= {m.lower() for m in _EMAIL.findall(decoded)}
            break
    return found


def _origin_signals(origin: str) -> list[Signal]:
    if origin.startswith("qr:"):
        return [Signal("qr_code_link", 15,
                       f"Link was delivered as a QR code ({origin[3:]}), moving the click to an "
                       "unmanaged phone", 0)]
    if origin.startswith("attachment:"):
        name = origin.split(":", 1)[1]
        if name.lower().endswith((".htm", ".html", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")):
            return [Signal("markup_attachment_link", 10,
                           f"Link came from an HTML/SVG attachment ({name})", 0)]
    return []


def _url_identity_signals(hops: list[Hop], recipients) -> list[Signal]:
    recipients = {r.lower() for r in recipients or ()}
    for hop in hops:
        for url in (hop.requested_url, hop.final_url, *hop.redirects):
            if not url:
                continue
            hits = emails_in_url(url)
            if hits & recipients:
                return [Signal("recipient_in_url", 20,
                               "Link is personalised with the recipient's address", hop.index)]
            if hits:
                return [Signal("email_in_url", 10, "Link carries an email address", hop.index)]
    return []


def evaluate(hops: list[Hop], complete: bool, trusted_login_domains=(), recipients=(),
             origin: str = "body") -> list[Signal]:
    signals: list[Signal] = _origin_signals(origin)
    if not hops:
        return signals + [Signal("no_capture", 30, "Nothing could be captured for this link")]
    signals += _url_identity_signals(hops, recipients)

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
