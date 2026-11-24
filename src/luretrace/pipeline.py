from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .config import Config
from .detonate import detonate
from .domains import host_of, in_domains
from .enrich import age_signals
from .extract import extract_urls
from .models import Signal, Verdict
from .netguard import classify_host, is_public_host
from .signals import evaluate, label_for, total
from .unwrap import unwrap

RANK = {"skipped": 0, "clean": 0, "suspicious": 1, "malicious": 2}


async def scan_url(original: str, cfg: Config, message_id: str | None = None,
                   origin: str = "body", recipients=(), rescan: bool = False,
                   rescan_of: str | None = None) -> Verdict:
    """Detonate one link and act on the verdict.

    origin:    where the link was found ("body", "attachment:<name>", "qr:<name>").
    rescan:    queue the link for re-detonation at cfg.rescan_offsets_minutes.
    rescan_of: the earlier label when this run *is* a rescan (reported if it worsened).
    """
    started = datetime.now(timezone.utc)
    url = unwrap(original, cfg.mimecast or None)
    verdict = Verdict(
        url=url, original_url=original, label="skipped", score=0, complete=True,
        started_at=started.isoformat(), message_id=message_id, origin=origin,
        rescan_of=rescan_of,
    )
    if in_domains(url, cfg.allowlist_domains):
        return verdict
    # Intranet and other non-public links are not detonated: the worker must not reach them.
    if not cfg.allow_private_networks and not is_public_host(host_of(url), bool(cfg.proxy)):
        if classify_host(host_of(url)) == "unresolved":
            # Not internal, just not resolvable from here. Never "skipped" (the gate allows
            # skipped): a domain registered after delivery would walk straight through.
            verdict.label, verdict.score, verdict.complete = "suspicious", 30, False
            verdict.signals = [Signal("does_not_resolve", 30,
                                      f"{host_of(url)} does not resolve from the scanner; "
                                      "unverified, queued for rescan")]
            if rescan and cfg.rescan_offsets_minutes:
                from .rescan import RescanQueue
                RescanQueue(cfg.rescan_queue).add(url, cfg.rescan_offsets_minutes, message_id,
                                                  "suspicious", origin=origin)
            if verdict.label in cfg.notify_on and rescan_of is None:
                await notify(verdict, cfg)
            return verdict
        verdict.signals = [Signal("not_public", 0, "Link target is not a public address; not detonated")]
        return verdict

    digest = hashlib.sha1(url.encode()).hexdigest()[:8]
    scan_id = f"{started:%Y%m%dT%H%M%S}-{digest}-{secrets.token_hex(2)}"  # unique per run
    outdir = Path(cfg.output_dir) / scan_id
    hops, complete = await detonate(url, cfg, outdir)
    signals = evaluate(hops, complete, cfg.trusted_login_domains, recipients, origin)
    skip = [*cfg.allowlist_domains, *cfg.trusted_login_domains]
    signals += await age_signals(hops, cfg, skip)
    score = total(signals)
    verdict.hops, verdict.signals, verdict.complete = hops, signals, complete
    verdict.score = score
    verdict.label = label_for(score, cfg.malicious_threshold, cfg.suspicious_threshold)
    verdict.artifacts_dir = str(outdir)

    await respond(verdict, cfg, recipients)
    (outdir / "report.json").write_text(json.dumps(verdict.to_dict(), indent=2), encoding="utf-8")
    if rescan and cfg.rescan_offsets_minutes and verdict.label in ("clean", "suspicious"):
        from .rescan import RescanQueue
        RescanQueue(cfg.rescan_queue).add(url, cfg.rescan_offsets_minutes, message_id,
                                          verdict.label, origin=origin)
    if rescan_of is not None or verdict.label in cfg.notify_on:
        if rescan_of is None or RANK[verdict.label] > RANK.get(rescan_of, 0):
            await notify(verdict, cfg)
    return verdict


async def respond(verdict: Verdict, cfg: Config, recipients=()) -> None:
    """Automatic response actions. Each is opt-in and recorded on the verdict."""
    if verdict.label in ("suspicious", "malicious") and cfg.ioc_dir:
        from .actions import write_iocs
        path = write_iocs(verdict, cfg.ioc_dir, cfg.allowlist_domains)
        verdict.actions.append({"action": "ioc_export", "path": path})
    if verdict.label != "malicious":
        return
    if cfg.blocklist_path:
        from .actions import append_blocklist
        added = append_blocklist(verdict, cfg.blocklist_path, cfg.allowlist_domains)
        verdict.actions.append({"action": "blocklist", "path": cfg.blocklist_path, "added": added})
    if cfg.purge_on_malicious and cfg.graph and verdict.message_id:
        from .actions import graph_purge
        loop = asyncio.get_running_loop()
        try:
            ok = await loop.run_in_executor(
                None, graph_purge, verdict.message_id, cfg.graph, list(recipients) or None)
        except Exception as exc:
            ok = False
            print(f"[luretrace] purge failed: {exc}", file=sys.stderr)
        verdict.actions.append({"action": "graph_purge", "ok": ok,
                                "mailboxes": list(recipients) or [cfg.graph.get("mailbox")]})
    if cfg.honeytoken.get("enabled"):
        from .honeytoken import submit
        try:
            record = await submit(verdict, cfg.honeytoken, cfg)
        except Exception as exc:
            record = {"submitted": False, "error": str(exc).splitlines()[0][:200]}
        if record is not None:
            verdict.actions.append({"action": "honeytoken", **record})


async def scan_message(raw: bytes, cfg: Config) -> list[Verdict]:
    meta, urls = extract_urls(raw, cfg.scan_attachments, cfg.max_attachment_bytes)
    targets, seen = [], set()
    for original in urls:
        target = unwrap(original, cfg.mimecast or None)
        if target in seen:
            continue
        seen.add(target)
        targets.append(original)

    gate = asyncio.Semaphore(max(1, cfg.concurrency))

    async def one(original: str) -> Verdict:
        async with gate:
            return await scan_url(
                original, cfg, meta.get("message_id"),
                origin=meta["origins"].get(original, "body"), recipients=meta["recipients"],
                rescan=cfg.rescan_auto,
            )

    return list(await asyncio.gather(*(one(u) for u in targets)))


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def notify(verdict: Verdict, cfg: Config) -> bool:
    """POST the verdict to the webhook. Signed when webhook_secret is set; retried on failure."""
    if not cfg.webhook_url:
        return False
    payload = {
        "source": "luretrace",
        "label": verdict.label,
        "score": verdict.score,
        "url": verdict.url,
        "original_url": verdict.original_url,
        "final_url": verdict.hops[-1].final_url if verdict.hops else None,
        "message_id": verdict.message_id,
        "origin": verdict.origin,
        "rescan_of": verdict.rescan_of,
        "signals": [s.__dict__ for s in verdict.signals],
        "actions": verdict.actions,
        "artifacts_dir": verdict.artifacts_dir,
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", **cfg.webhook_headers}
    if cfg.webhook_secret:
        # Receivers verify HMAC-SHA256 of the raw body, like GitHub/Stripe webhooks.
        headers["X-Luretrace-Signature"] = sign(body, cfg.webhook_secret)
        headers["X-Luretrace-Timestamp"] = verdict.started_at
    delay = 0.5
    for attempt in range(max(1, cfg.webhook_retries + 1)):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(cfg.webhook_url, content=body, headers=headers)
            if resp.status_code < 300:
                return True
            if resp.status_code < 500 and resp.status_code != 429:
                print(f"[luretrace] webhook rejected: HTTP {resp.status_code}", file=sys.stderr)
                return False
        except Exception as exc:
            if attempt == cfg.webhook_retries:
                print(f"[luretrace] webhook failed: {exc}", file=sys.stderr)
        if attempt < cfg.webhook_retries:
            await asyncio.sleep(delay)
            delay *= 2
    return False
