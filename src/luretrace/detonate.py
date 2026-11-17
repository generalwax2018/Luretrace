"""Open a URL in an isolated headless browser and follow the lure chain to its end."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from .chain import pick_next
from .config import Config
from .models import Hop
from .netguard import is_public_host

EMAIL_SEL = (
    "input[type=email], input[name=loginfmt], input[name=identifier], "
    "input[autocomplete=username], input[name=username], input[name=email]"
)
CAPTCHA_HOSTS = {
    "challenges.cloudflare.com": "Cloudflare Turnstile",
    "hcaptcha.com": "hCaptcha",
    "www.recaptcha.net": "reCAPTCHA",
    "recaptcha.net": "reCAPTCHA",
}
LINKS_JS = """els => els.map(e => ({
    href: e.href,
    text: (e.innerText || e.getAttribute('aria-label') || e.title || '').trim().slice(0, 120)
}))"""


def _captcha_for(urls: list[str]) -> str | None:
    for url in urls:
        parts = urlsplit(url)
        host = parts.hostname or ""
        for needle, name in CAPTCHA_HOSTS.items():
            if host == needle or host.endswith("." + needle):
                return name
        if host.endswith("google.com") and "/recaptcha/" in parts.path:
            return "reCAPTCHA"
    return None


async def detonate(url: str, cfg: Config, outdir: Path) -> tuple[list[Hop], bool]:
    """Return (hops, complete). complete is False when the chain could not be followed to an end."""
    from playwright.async_api import async_playwright

    outdir.mkdir(parents=True, exist_ok=True)
    hops: list[Hop] = []
    requests: list[str] = []
    blocked: list[str] = []
    downloads: list[dict] = []
    tasks: list[asyncio.Task] = []
    loop = asyncio.get_running_loop()

    async def guard(route):
        req_url = route.request.url
        parts = urlsplit(req_url)
        if parts.scheme not in ("http", "https"):
            await route.continue_()
            return
        ok = cfg.allow_private_networks or await loop.run_in_executor(
            None, is_public_host, parts.hostname, bool(cfg.proxy)
        )
        if ok:
            await route.continue_()
        else:
            blocked.append(f"{parts.hostname}:{parts.port or ''}".rstrip(":"))
            await route.abort("blockedbyclient")

    async def save_download(download):
        target = outdir / f"download_{len(downloads)}.bin"
        try:
            await download.save_as(target)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
        except Exception:
            digest = None
        downloads.append({
            "filename": download.suggested_filename, "url": download.url,
            "sha256": digest, "path": str(target),
        })

    async with async_playwright() as p:
        launch = {"headless": True, "args": ["--disable-dev-shm-usage"]}
        if cfg.proxy:
            launch["proxy"] = {"server": cfg.proxy}
        browser = await p.chromium.launch(**launch)
        ctx_args = dict(
            user_agent=cfg.user_agent, locale=cfg.locale, timezone_id=cfg.timezone,
            viewport={"width": 1366, "height": 768}, accept_downloads=True,
            service_workers="block",
        )
        if cfg.record_har:
            ctx_args["record_har_path"] = str(outdir / "chain.har")
        context = await browser.new_context(**ctx_args)
        await context.route("**/*", guard)
        page = await context.new_page()
        page.on("request", lambda r: requests.append(r.url))
        page.on("download", lambda d: tasks.append(asyncio.create_task(save_download(d))))

        complete = False
        seen: set[str] = {url}
        current, link_text = url, ""
        try:
            for index in range(cfg.max_hops):
                hop = Hop(index=index, requested_url=current, followed_link_text=link_text)
                requests.clear()
                blocked.clear()
                n_downloads = len(downloads)
                try:
                    resp = await page.goto(
                        current, wait_until="domcontentloaded", timeout=cfg.nav_timeout_ms
                    )
                    if resp is not None:
                        hop.status = resp.status
                        chain, req = [], resp.request
                        while req.redirected_from:
                            req = req.redirected_from
                            chain.append(req.url)
                        hop.redirects = list(reversed(chain))
                except Exception as exc:  # navigation failed, or turned into a download
                    if "Download is starting" not in str(exc):
                        hop.error = str(exc).splitlines()[0][:300]
                try:
                    await page.wait_for_load_state("networkidle", timeout=cfg.settle_timeout_ms)
                except Exception:
                    pass
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks.clear()

                links = await _snapshot(page, hop, outdir)
                hop.resource_hosts = sorted({urlsplit(u).hostname or "" for u in requests} - {""})
                hop.blocked_requests = sorted(set(blocked))
                hop.captcha = _captcha_for(requests)
                hop.downloads = downloads[n_downloads:]
                hops.append(hop)

                if hop.error and not hop.downloads:
                    break
                if hop.has_password_field or hop.has_email_field or hop.downloads:
                    complete = True
                    break
                nxt = pick_next(links, hop.final_url or current, seen)
                if not nxt:
                    # A challenge page with nowhere to go means we were stopped, not finished.
                    complete = hop.captcha is None
                    break
                seen.add(nxt["href"])
                current, link_text = nxt["href"], nxt["text"]
        finally:
            await context.close()  # flushes the HAR
            await browser.close()
    return hops, complete


async def _snapshot(page, hop: Hop, outdir: Path) -> list[dict]:
    hop.final_url = page.url
    try:
        hop.title = (await page.title())[:300]
    except Exception:
        pass
    links: list[dict] = []
    passwords = emails = 0
    actions: list[str] = []
    for frame in page.frames:
        try:
            passwords += await frame.locator("input[type=password]").count()
            emails += await frame.locator(EMAIL_SEL).count()
            actions += await frame.eval_on_selector_all("form[action]", "els => els.map(e => e.action)")
            links += await frame.eval_on_selector_all("a[href], area[href]", LINKS_JS)
        except Exception:
            continue
    hop.has_password_field = passwords > 0
    hop.has_email_field = emails > 0
    hop.form_actions = sorted({a for a in actions if isinstance(a, str) and a})[:10]
    try:
        hop.text_excerpt = (await page.inner_text("body", timeout=3000))[:2000]
    except Exception:
        pass
    try:
        shot = outdir / f"hop_{hop.index}.png"
        await page.screenshot(path=str(shot), timeout=10000)
        hop.screenshot = str(shot)
    except Exception:
        pass
    try:
        html = outdir / f"hop_{hop.index}.html"
        html.write_text(await page.content(), encoding="utf-8")
        hop.html_path = str(html)
    except Exception:
        pass
    return links
