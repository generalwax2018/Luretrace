"""Open a URL in an isolated headless browser and follow the lure chain to its end."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from .chain import LURE_WORDS, pick_next
from .config import UA_TEMPLATE, Config
from .guardproxy import BLOCK_HEADER, egress
from .models import Hop

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
# Lures increasingly use script-driven buttons instead of anchors.
BUTTON_SEL = "button, [role=button], input[type=button], input[type=submit], [onclick]"
BUTTONS_JS = """els => els.map((e, i) => ({
    i,
    text: (e.innerText || e.value || e.getAttribute('aria-label') || e.title || '').trim().slice(0, 120),
    visible: !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length),
})).filter(x => x.visible && x.text)"""
# Hide the most common automation tells; kits that see them serve a decoy.
STEALTH_JS = """
Object.defineProperty(Navigator.prototype, 'webdriver', {get: () => undefined});
if (!window.chrome) { window.chrome = {runtime: {}}; }
"""


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


def _idp_requests(urls: list[str], limit: int = 60) -> list[str]:
    from .signals import IDP_ASSET_HOSTS
    out: list[str] = []
    for u in urls:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower()
        if host in IDP_ASSET_HOSTS:
            item = host + (parts.path or "/")
            if item not in out:
                out.append(item)
                if len(out) >= limit:
                    break
    return out


def user_agent_for(cfg: Config, browser) -> str:
    """The configured UA, or one that matches the real browser build (a mismatch is a tell)."""
    if cfg.user_agent:
        return cfg.user_agent
    major = (getattr(browser, "version", "") or "131").split(".")[0]
    return UA_TEMPLATE.format(major=major)


async def launch_browser(p, cfg: Config, launch: dict):
    """Launch Chromium, preferring the full build's new headless mode (fewer headless tells)."""
    opts = dict(launch)
    if cfg.stealth:
        opts["args"] = [*opts.get("args", []), "--disable-blink-features=AutomationControlled"]
        opts["ignore_default_args"] = ["--enable-automation"]
    if cfg.browser_channel:
        try:
            return await p.chromium.launch(channel=cfg.browser_channel, **opts)
        except Exception:
            pass  # channel not installed: fall back to the default headless build
    return await p.chromium.launch(**opts)


async def new_context(browser, cfg: Config, **extra):
    context = await browser.new_context(
        user_agent=user_agent_for(cfg, browser), locale=cfg.locale, timezone_id=cfg.timezone,
        viewport={"width": 1366, "height": 768}, service_workers="block", **extra,
    )
    if cfg.stealth:
        await context.add_init_script(STEALTH_JS)
    return context


async def detonate(url: str, cfg: Config, outdir: Path) -> tuple[list[Hop], bool]:
    """Return (hops, complete). complete is False when the chain could not be followed to an end."""
    from playwright.async_api import async_playwright

    outdir.mkdir(parents=True, exist_ok=True)
    hops: list[Hop] = []
    requests: list[str] = []
    blocked: list[str] = []
    downloads: list[dict] = []
    tasks: list[asyncio.Task] = []
    opened: list = []  # every page the context opened, in order (main page first)

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

    def on_page(pg):
        opened.append(pg)
        pg.on("download", lambda d: tasks.append(asyncio.create_task(save_download(d))))

    async with egress(cfg, on_block=blocked.append) as launch, async_playwright() as p:
        browser = await launch_browser(p, cfg, launch)
        extra = {"accept_downloads": True}
        if cfg.record_har:
            extra["record_har_path"] = str(outdir / "chain.har")
        context = await new_context(browser, cfg, **extra)
        context.on("page", on_page)
        context.on("request", lambda r: requests.append(r.url))
        page = await context.new_page()

        complete = False
        seen: set[str] = {url}
        current, link_text, preloaded = url, "", False
        try:
            for index in range(cfg.max_hops):
                hop = Hop(index=index, requested_url=current, followed_link_text=link_text)
                if not preloaded:
                    requests.clear()
                    blocked.clear()
                n_downloads, n_pages = len(downloads), len(opened)
                if not preloaded:
                    try:
                        resp = await page.goto(
                            current, wait_until="domcontentloaded", timeout=cfg.nav_timeout_ms
                        )
                        if resp is not None:
                            hop.status = resp.status
                            if resp.headers.get(BLOCK_HEADER):
                                where = urlsplit(resp.url).hostname or resp.url
                                hop.error = f"Blocked by egress guard: non-public destination {where}"
                            chain, req = [], resp.request
                            while req.redirected_from:
                                req = req.redirected_from
                                chain.append(req.url)
                            hop.redirects = list(reversed(chain))
                    except Exception as exc:  # navigation failed, or turned into a download
                        if "Download is starting" not in str(exc):
                            hop.error = str(exc).splitlines()[0][:300]
                await _settle(page, cfg)
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks.clear()

                links = await _snapshot(page, hop, outdir)
                hop.resource_hosts = sorted({urlsplit(u).hostname or "" for u in requests} - {""})
                hop.idp_requests = _idp_requests(requests)
                hop.blocked_requests = sorted(set(blocked))
                hop.captcha = _captcha_for(requests)
                hop.downloads = downloads[n_downloads:]
                hops.append(hop)

                if hop.error and not hop.downloads:
                    break
                if hop.has_password_field or hop.has_email_field or hop.downloads:
                    complete = True
                    break

                requests.clear()
                blocked.clear()
                # 1) the page opened a new window (window.open / target=_blank): follow it.
                popup = await _adopt_popup(opened[n_pages:], page, cfg)
                if popup is not None:
                    page, current, link_text, preloaded = popup, popup.url, "(popup window)", True
                    seen.add(current)
                    continue
                # 2) the most lure-like anchor.
                nxt = pick_next(links, hop.final_url or current, seen)
                if nxt:
                    seen.add(nxt["href"])
                    current, link_text, preloaded = nxt["href"], nxt["text"], False
                    continue
                # 3) a script-driven lure button ("View Document" with an onclick).
                n_pages = len(opened)
                before = page.url
                clicked = await _click_lure_button(page, cfg)
                if clicked:
                    # The popup's "page" event can land after the opener is already idle.
                    await _wait_until(
                        lambda n=n_pages, pg=page, b=before: len(opened) > n or pg.url != b, cfg)
                    popup = await _adopt_popup(opened[n_pages:], page, cfg)
                    if popup is not None:
                        page = popup
                    if popup is not None or page.url != before:
                        current, link_text, preloaded = page.url, clicked, True
                        seen.add(current)
                        continue
                # A challenge page with nowhere to go means we were stopped, not finished.
                complete = hop.captcha is None
                break
        finally:
            await context.close()  # flushes the HAR
            await browser.close()
    return hops, complete


async def _settle(page, cfg: Config) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=cfg.settle_timeout_ms)
    except Exception:
        pass


async def _wait_until(condition, cfg: Config, step_s: float = 0.1) -> bool:
    deadline = min(cfg.settle_timeout_ms, 5000) / 1000
    waited = 0.0
    while not condition():
        if waited >= deadline:
            return False
        await asyncio.sleep(step_s)
        waited += step_s
    return True


async def _adopt_popup(new_pages: list, current_page, cfg: Config):
    """Return the newest page opened since the hop began, once it has a real URL."""
    for pg in reversed(new_pages):
        if pg is current_page or pg.is_closed():
            continue
        try:
            await pg.wait_for_load_state("domcontentloaded", timeout=cfg.nav_timeout_ms)
        except Exception:
            pass
        if pg.url.lower().startswith(("http://", "https://")):
            return pg
    return None


async def _click_lure_button(page, cfg: Config) -> str | None:
    """Click the most lure-like visible button. Returns its text, or None if none qualified."""
    best = None
    for frame in page.frames:
        try:
            items = await frame.eval_on_selector_all(BUTTON_SEL, BUTTONS_JS)
        except Exception:
            continue
        for item in items:
            score = len(LURE_WORDS.findall(item["text"]))
            if score and (best is None or score > best[0]):
                best = (score, frame, item["i"], item["text"])
    if best is None:
        return None
    _, frame, i, text = best
    try:
        await frame.locator(BUTTON_SEL).nth(i).click(timeout=5000)
    except Exception:
        return None
    await _settle(page, cfg)
    return text


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
