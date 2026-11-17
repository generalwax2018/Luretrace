"""Response actions: turn a verdict into IOCs, blocklists, and (optionally) a mail purge."""
from __future__ import annotations

import json
from pathlib import Path

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
        "urls": sorted(urls),
        "sha256": sorted(hashes),
        "message_id": verdict.message_id,
    }


def write_iocs(verdict: Verdict, ioc_dir: str, allowlist=()) -> str | None:
    if verdict.label not in ("suspicious", "malicious"):
        return None
    out = Path(ioc_dir)
    out.mkdir(parents=True, exist_ok=True)
    name = Path(verdict.artifacts_dir).name if verdict.artifacts_dir else "verdict"
    path = out / f"{name}.ioc.json"
    path.write_text(json.dumps(export_iocs(verdict, allowlist), indent=2))
    return str(path)


def netskope_url_list(verdicts, allowlist=()) -> list[str]:
    """Domains to push into a Netskope custom URL category / blocklist."""
    domains: set[str] = set()
    for v in verdicts:
        if v.label == "malicious":
            domains.update(export_iocs(v, allowlist)["domains"])
    return sorted(domains)


def write_blocklist(verdicts, path: str, allowlist=()) -> int:
    domains = netskope_url_list(verdicts, allowlist)
    Path(path).write_text("\n".join(domains) + ("\n" if domains else ""))
    return len(domains)


def graph_purge(message_id: str, graph_cfg: dict) -> bool:
    """Soft-delete a message from a mailbox via Microsoft Graph (move to Deleted Items).

    EXPERIMENTAL: written to the Graph v1.0 docs; needs Mail.ReadWrite (application) and
    an application access policy. Validate against your tenant before trusting it.
    """
    if not message_id or not graph_cfg.get("tenant_id"):
        return False
    base = graph_cfg.get("base_url", "https://graph.microsoft.com/v1.0")
    login = graph_cfg.get("login_url", "https://login.microsoftonline.com")
    mailbox = graph_cfg["mailbox"]
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
        found = client.get(
            f"{base}/users/{mailbox}/messages",
            params={"$filter": f"internetMessageId eq '{message_id}'", "$select": "id"},
            headers=headers,
        ).json().get("value", [])
        ok = False
        for msg in found:
            resp = client.post(
                f"{base}/users/{mailbox}/messages/{msg['id']}/move",
                json={"destinationId": "deleteditems"}, headers=headers,
            )
            ok = ok or resp.status_code < 300
        return ok
