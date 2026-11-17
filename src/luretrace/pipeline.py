from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from .config import Config
from .detonate import detonate
from .domains import host_of, in_domains
from .extract import extract_urls
from .models import Signal, Verdict
from .netguard import is_public_host
from .signals import evaluate, label_for, total
from .unwrap import unwrap


async def scan_url(original: str, cfg: Config, message_id: str | None = None) -> Verdict:
    started = datetime.now(timezone.utc)
    url = unwrap(original, cfg.mimecast or None)
    verdict = Verdict(
        url=url, original_url=original, label="skipped", score=0, complete=True,
        started_at=started.isoformat(), message_id=message_id,
    )
    if in_domains(url, cfg.allowlist_domains):
        return verdict
    # Intranet and other non-public links are not detonated: the worker must not reach them.
    if not cfg.allow_private_networks and not is_public_host(host_of(url), bool(cfg.proxy)):
        verdict.signals = [Signal("not_public", 0, "Link target is not a public address; not detonated")]
        return verdict

    scan_id = f"{started:%Y%m%dT%H%M%S}-{hashlib.sha1(url.encode()).hexdigest()[:8]}"
    outdir = Path(cfg.output_dir) / scan_id
    hops, complete = await detonate(url, cfg, outdir)
    signals = evaluate(hops, complete, cfg.trusted_login_domains)
    score = total(signals)
    verdict.hops, verdict.signals, verdict.complete = hops, signals, complete
    verdict.score = score
    verdict.label = label_for(score, cfg.malicious_threshold, cfg.suspicious_threshold)
    verdict.artifacts_dir = str(outdir)
    (outdir / "report.json").write_text(json.dumps(verdict.to_dict(), indent=2))
    if cfg.ioc_dir:
        from .actions import write_iocs
        write_iocs(verdict, cfg.ioc_dir, cfg.allowlist_domains)
    await notify(verdict, cfg)
    return verdict


async def scan_message(raw: bytes, cfg: Config) -> list[Verdict]:
    meta, urls = extract_urls(raw)
    verdicts, seen = [], set()
    for original in urls:
        target = unwrap(original, cfg.mimecast or None)
        if target in seen:
            continue
        seen.add(target)
        verdicts.append(await scan_url(original, cfg, meta.get("message_id")))
    return verdicts


async def notify(verdict: Verdict, cfg: Config) -> None:
    if not cfg.webhook_url or verdict.label not in cfg.notify_on:
        return
    payload = {
        "source": "luretrace",
        "label": verdict.label,
        "score": verdict.score,
        "url": verdict.url,
        "original_url": verdict.original_url,
        "final_url": verdict.hops[-1].final_url if verdict.hops else None,
        "message_id": verdict.message_id,
        "signals": [s.__dict__ for s in verdict.signals],
        "artifacts_dir": verdict.artifacts_dir,
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            await client.post(cfg.webhook_url, json=payload, headers=cfg.webhook_headers)
    except Exception as exc:
        print(f"[luretrace] webhook failed: {exc}")
