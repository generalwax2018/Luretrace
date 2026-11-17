"""Login-page beacon: detect when your own sign-in page is served through a proxy.

Add a tiny image reference to your Entra ID (or Okta) sign-in branding via custom CSS.
When a victim loads the real page, the browser fetches the beacon with a Referer/Origin
on *your* login host. When an adversary-in-the-middle kit proxies that page, the same
fetch arrives with the attacker's domain in Referer/Origin instead. Any hit whose origin
is not one of your trusted login hosts is a live proxying event, and its host is the
phishing domain, in real time.

Kits that rewrite or strip custom CSS will defeat this; many do not. It is one tripwire,
not a control. It never sees or touches a credential.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx

from .domains import in_domains

# 1x1 transparent GIF.
PIXEL = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000"
                      "0100010000020144003b")


def css_snippet(beacon_url: str) -> str:
    """CSS to paste into Entra Company Branding (Sign-in page > Custom CSS)."""
    return (
        "/* luretrace beacon - paste into Entra admin > Company Branding > "
        "Sign-in page > Custom CSS. Harmless background image on a server you run. */\n"
        ".ext-sign-in-box, .login-paginated-page {\n"
        f'  background-image: url("{beacon_url.rstrip("/")}/b.gif");\n'
        "}\n"
    )


def classify_hit(headers, trusted_login_hosts) -> tuple[str, str]:
    """Return (verdict, origin_host). verdict is legit | proxied | unknown."""
    ref = ""
    for name in ("Origin", "Referer"):
        value = headers.get(name)
        if value:
            ref = value
            break
    host = (urlsplit(ref).hostname or "").lower()
    if not host:
        return "unknown", ""
    if in_domains(host, trusted_login_hosts):
        return "legit", host
    return "proxied", host


class _Handler(BaseHTTPRequestHandler):
    trusted: list[str] = []
    webhook: str | None = None

    def do_GET(self):
        if urlsplit(self.path).path != "/b.gif":
            self.send_response(404)
            self.end_headers()
            return
        verdict, host = classify_hit(self.headers, self.trusted)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(PIXEL)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "origin_host": host,
            "client_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
        }
        print(f"[beacon] {json.dumps(record)}")
        if verdict == "proxied" and self.webhook:
            try:
                httpx.post(self.webhook, json={"source": "luretrace-beacon", **record}, timeout=10)
            except Exception as exc:
                print(f"[beacon] webhook failed: {exc}")

    def log_message(self, *args):
        pass


def run_receiver(cfg) -> None:
    opts = cfg.beacon or {}
    _Handler.trusted = [h.lower() for h in opts.get("trusted_login_hosts", [
        "login.microsoftonline.com", "login.microsoft.com", "login.live.com",
    ])]
    _Handler.webhook = opts.get("webhook_url") or cfg.webhook_url
    host = opts.get("listen_host", "0.0.0.0")
    port = int(opts.get("listen_port", 8088))
    server = ThreadingHTTPServer((host, port), _Handler)
    print(f"[beacon] listening on {host}:{port}; trusted login hosts: {_Handler.trusted}")
    print(f"[beacon] add this to your sign-in branding:\n{css_snippet(opts.get('public_url', f'http://{host}:{port}'))}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
