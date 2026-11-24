"""Response actions: turn a verdict into IOCs, blocklists, and (optionally) a mail purge."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from .domains import in_domains, registrable
from .models import Verdict


def export_iocs(verdict: Verdict, allowlist=()) -> dict:
    """Collect indicators from a scanned chain: final domains, every URL, download hashes."""
    domains, urls, hashes = set(), set(), set()
    for hop in verdict.hops:
        for u in [hop.requested_url, hop.final_url, *hop.redirects]:
            if not u:
                continue
            urls.add(u)
            reg = registrable(u)
            if reg and not in_domains(u, allowlist):
                domains.add(reg)
        for dl in hop.downloads:
            if dl.get("sha256"):
                hashes.add(dl["sha256"])
    # The credential-harvesting host is the most useful single indicator.
    phish_host = None
    for hop in verdict.hops:
        if hop.has_password_field or hop.has_email_field:
            phish_host = registrable(hop.final_url or hop.requested_url)
    return {
        "label": verdict.label,
        "score": verdict.score,
        "phishing_domain": phish_host,
        "domains": sorted(domains),
        "block": blockable(verdict, allowlist),
        "urls": sorted(urls),
        "sha256": sorted(hashes),
        "message_id": verdict.message_id,
    }


def _shared_infrastructure() -> set[str]:
    """Domains many unrelated parties serve from: never block the whole registrable domain."""
    from .chain import BORING_DOMAINS, FILE_SHARE_DOMAINS
    from .signals import BRANDS

    shared = set(FILE_SHARE_DOMAINS) | set(BORING_DOMAINS)
    for spec in BRANDS.values():
        shared |= spec["legit"]
    return shared


def blockable(verdict: Verdict, allowlist=()) -> list[str]:
    """What is safe to push to a blocklist for this chain.

    Attacker-owned domains are blocked whole. On shared infrastructure (SharePoint, Dropbox,
    pages.dev, a brand's own domains...) only the exact host that served the credential form
    or the download is blocked, never the platform, and never the file-share lure page
    itself, which is often a compromised but legitimate tenant.
    """
    shared = _shared_infrastructure()
    out: set[str] = set()
    for hop in verdict.hops:
        hostile = hop.has_password_field or hop.has_email_field or bool(hop.downloads)
        for u in [hop.requested_url, hop.final_url, *hop.redirects]:
            if not u or in_domains(u, allowlist):
                continue
            host = urlsplit(u).hostname or ""
            if not host:
                continue
            if in_domains(host, shared):
                if hostile and not any(host == d for d in shared):
                    out.add(host.lower())
                continue
            out.add(registrable(u))
    return sorted(d for d in out if d)


def write_iocs(verdict: Verdict, ioc_dir: str, allowlist=()) -> str | None:
    if verdict.label not in ("suspicious", "malicious"):
        return None
    out = Path(ioc_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = Path(verdict.artifacts_dir).name if verdict.artifacts_dir else "verdict"
    path = out / f"{name}.ioc.json"
    path.write_text(json.dumps(export_iocs(verdict, allowlist), indent=2), encoding="utf-8")
    return str(path)


def blocklist_domains(verdicts, allowlist=()) -> list[str]:
    """Domains to load into a web gateway's custom URL category, a DNS filter, or a blocklist."""
    domains: set[str] = set()
    for v in verdicts:
        if v.label == "malicious":
            domains.update(blockable(v, allowlist))
    return sorted(domains)


def write_blocklist(verdicts, path: str, allowlist=()) -> int:
    domains = blocklist_domains(verdicts, allowlist)
    Path(path).write_text("\n".join(domains) + ("\n" if domains else ""))
    return len(domains)


def append_blocklist(verdict: Verdict, path: str, allowlist=()) -> int:
    """Add a malicious verdict's domains to a one-per-line blocklist file; returns how many."""
    if verdict.label != "malicious":
        return 0
    target = Path(path)
    existing = set()
    if target.exists():
        existing = {line.strip() for line in target.read_text(encoding="utf-8").splitlines()}
    new = [d for d in blockable(verdict, allowlist) if d not in existing]
    if new:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as fh:
            fh.write("".join(d + "\n" for d in new))
    return len(new)


def verdicts_from_reports(scans_dir: str) -> list[Verdict]:
    """Load every report.json under a scans directory back into Verdict objects."""
    from .models import Hop, Signal

    out: list[Verdict] = []
    for report in sorted(Path(scans_dir).glob("*/report.json")):
        try:
            d = json.loads(report.read_text(encoding="utf-8"))
            hop_fields = set(Hop.__dataclass_fields__)
            sig_fields = set(Signal.__dataclass_fields__)
            v_fields = set(Verdict.__dataclass_fields__)
            v = Verdict(**{k: d[k] for k in v_fields if k in d and k not in ("hops", "signals")})
            v.hops = [Hop(**{k: h[k] for k in hop_fields if k in h}) for h in d.get("hops", [])]
            v.signals = [Signal(**{k: s[k] for k in sig_fields if k in s})
                         for s in d.get("signals", [])]
            out.append(v)
        except Exception:
            continue
    return out


def odata_quote(value: str) -> str:
    """Quote a value for an OData string literal: single quotes are doubled.

    The Message-ID header is attacker-controlled; unescaped, a crafted one such as
    x' or isRead eq false or internetMessageId eq 'y  would widen the filter.
    """
    return "'" + value.replace("'", "''") + "'"


def graph_purge(message_id: str, graph_cfg: dict, mailboxes=None) -> bool:
    """Soft-delete a message via Microsoft Graph (move to Deleted Items; recoverable).

    mailboxes: where to purge it (usually the recipients); defaults to graph_cfg["mailbox"].
    Moves a message only when the filter matches exactly one message in that mailbox.

    EXPERIMENTAL: written to the Graph v1.0 docs; needs Mail.ReadWrite (application) and
    an application access policy. Validate against your tenant before trusting it.
    """
    if not message_id or not graph_cfg.get("tenant_id"):
        return False
    if not message_id.startswith("<") or not message_id.endswith(">") or len(message_id) > 998:
        return False  # not a well-formed Message-ID: refuse rather than guess
    base = graph_cfg.get("base_url", "https://graph.microsoft.com/v1.0")
    login = graph_cfg.get("login_url", "https://login.microsoftonline.com")
    targets = list(mailboxes or [graph_cfg["mailbox"]])
    with httpx.Client(timeout=30) as client:
        token = client.post(
            f"{login}/{graph_cfg['tenant_id']}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": graph_cfg["client_id"],
                "client_secret": graph_cfg["client_secret"],
                "scope": "https://graph.microsoft.com/.default",
            },
        ).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        ok = False
        for mailbox in targets:
            mbox = quote(mailbox, safe="@.")
            found = client.get(
                f"{base}/users/{mbox}/messages",
                params={"$filter": f"internetMessageId eq {odata_quote(message_id)}",
                        "$select": "id,internetMessageId", "$top": "2"},
                headers=headers,
            ).json().get("value", [])
            # Exactly one exact match, or nothing is touched.
            found = [m for m in found if m.get("internetMessageId") == message_id]
            if len(found) != 1:
                continue
            resp = client.post(
                f"{base}/users/{mbox}/messages/{quote(found[0]['id'], safe='')}/move",
                json={"destinationId": "deleteditems"}, headers=headers,
            )
            ok = ok or resp.status_code < 300
        return ok
