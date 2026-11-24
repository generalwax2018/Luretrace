"""Opt-in honeytoken (canary credentials).

When a chain is confirmed malicious, optionally submit a FAKE, pre-seeded account to the
phishing form. The account never works for anything; its only purpose is detection. Any
later sign-in attempt with it is proof the kit replayed the capture, and the attempt
reveals the attacker's replay infrastructure in your identity logs.

Guardrails baked in:
  * Runs only on a verdict already labelled "malicious" (never clean/suspicious/unknown).
  * Submits only the single configured canary identity, nothing real.
  * Off unless honeytoken.enabled is true.

You are responsible for creating the canary account as a disabled/monitored identity in
your own tenant, for authorisation to run active deception, and for compliance with local
law. This module does not solve CAPTCHAs or evade anything.
"""
from __future__ import annotations

import secrets

from .models import Verdict


def generate_canary(prefix: str = "svc-reports") -> dict:
    """A recognisable fake credential. Seed the username in your IdP as a monitored account."""
    tag = secrets.token_hex(3)
    return {
        "username": f"{prefix}-{tag}@example-canary.invalid",
        "password": "Canary!" + secrets.token_urlsafe(12),
        "marker": tag,
    }


def should_submit(verdict: Verdict, honeytoken_cfg: dict) -> bool:
    return bool(honeytoken_cfg.get("enabled")) and verdict.label == "malicious"


async def submit(verdict: Verdict, honeytoken_cfg: dict, cfg) -> dict | None:
    """Fill the final credential form with the canary. Returns a record, or None if skipped."""
    if not should_submit(verdict, honeytoken_cfg):
        return None
    target_hop = next(
        (h for h in reversed(verdict.hops) if h.has_password_field or h.has_email_field), None
    )
    if target_hop is None:
        return None

    # A canary only detects anything if it is seeded and monitored in your IdP, so never
    # invent one on the fly: require the configured identity.
    if not honeytoken_cfg.get("username") or not honeytoken_cfg.get("password"):
        return None
    canary = {"username": honeytoken_cfg["username"], "password": honeytoken_cfg["password"]}
    from playwright.async_api import async_playwright

    from .detonate import EMAIL_SEL, launch_browser, new_context
    from .guardproxy import egress

    url = target_hop.final_url or target_hop.requested_url
    submitted = False
    # Same egress guard as detonation: the submission must not be steerable to internal hosts.
    async with egress(cfg) as launch, async_playwright() as p:
        browser = await launch_browser(p, cfg, launch)
        context = await new_context(browser, cfg)
        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=cfg.nav_timeout_ms)
            email = page.locator(EMAIL_SEL).first
            if await email.count():
                await email.fill(canary["username"])
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(1500)
            pw = page.locator("input[type=password]").first
            if await pw.count():
                await pw.fill(canary["password"])
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(1500)
                submitted = True
        except Exception:
            pass
        finally:
            await context.close()
            await browser.close()
    return {"submitted": submitted, "username": canary["username"], "url": url}
