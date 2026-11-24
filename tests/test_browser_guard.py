"""Real-browser tests for the egress guard and the new chain-following behaviour.

Skipped automatically when no Playwright Chromium is installed.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import luretrace.guardproxy as guardproxy
from luretrace.config import Config
from luretrace.detonate import detonate
from luretrace.signals import evaluate

LOGIN = b"""<html><head><title>Sign in to your account</title></head><body><h1>Microsoft</h1>
<form action="/post" method="post"><input type="email" name="loginfmt">
<input type="password" name="passwd"></form></body></html>"""


@pytest.fixture
def site():
    pages, hits = {}, []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.headers.get("Host", ""), self.path))
            if self.path in redirects:
                self.send_response(302)
                self.send_header("Location", redirects[self.path])
                self.end_headers()
                return
            body = pages.get(self.path)
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body or b"not found")

        def log_message(self, *args):
            pass

    redirects: dict[str, str] = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    yield port, pages, redirects, hits
    server.shutdown()


@pytest.fixture
def localhost_is_public(monkeypatch):
    # "localhost" plays a public site; the literal 127.0.0.1 plays an internal/metadata target.
    monkeypatch.setattr(guardproxy, "resolve_public",
                        lambda host: ["127.0.0.1"] if host == "localhost" else None)


async def _run(url, tmp_path, **overrides):
    cfg = Config(output_dir=str(tmp_path), settle_timeout_ms=1500, record_har=False, **overrides)
    try:
        return await detonate(url, cfg, tmp_path / "scan")
    except Exception as exc:
        if "Executable doesn't exist" in str(exc) or "playwright install" in str(exc):
            pytest.skip("Playwright Chromium not installed")
        raise


async def test_redirect_to_internal_address_is_refused(site, tmp_path, localhost_is_public):
    port, pages, redirects, hits = site
    redirects["/r"] = f"http://127.0.0.1:{port}/secret"
    hops, complete = await _run(f"http://localhost:{port}/r", tmp_path)
    assert ("127.0.0.1:" + str(port), "/secret") not in hits
    assert not any(path == "/secret" for _, path in hits)
    assert not complete and "egress guard" in (hops[0].error or "")
    assert f"127.0.0.1:{port}" in hops[0].blocked_requests
    assert any(s.name == "internal_address_probe" for s in evaluate(hops, complete))


async def test_websocket_to_internal_address_is_refused(site, tmp_path, localhost_is_public):
    port, pages, redirects, hits = site
    pages["/ws"] = (f"<html><title>x</title><body>hi<script>"
                    f"try {{ new WebSocket('ws://127.0.0.1:{port}/sock'); }} catch (e) {{}}"
                    f"</script></body></html>").encode()
    hops, complete = await _run(f"http://localhost:{port}/ws", tmp_path)
    assert f"127.0.0.1:{port}" in hops[0].blocked_requests
    assert not any(path == "/sock" for _, path in hits)


async def test_follows_script_button_into_popup(site, tmp_path):
    port, pages, redirects, hits = site
    pages["/login"] = LOGIN
    pages["/doc"] = (f"<html><title>Invoice.pdf</title><body><p>A file was shared.</p>"
                     f"<button onclick=\"window.open('http://localhost:{port}/login')\">"
                     f"View Document</button></body></html>").encode()
    hops, complete = await _run(f"http://127.0.0.1:{port}/doc", tmp_path,
                                allow_private_networks=True)
    assert complete and len(hops) == 2
    assert hops[1].followed_link_text == "View Document"  # the button that opened the popup
    assert hops[1].final_url.endswith("/login") and hops[1].has_password_field


async def test_follows_popup_opened_on_load(site, tmp_path):
    port, pages, redirects, hits = site
    pages["/login"] = LOGIN
    pages["/auto"] = (f"<html><title>Loading</title><body>Please wait<script>"
                      f"window.open('http://localhost:{port}/login')</script></body></html>").encode()
    hops, complete = await _run(f"http://127.0.0.1:{port}/auto", tmp_path,
                                allow_private_networks=True)
    assert complete and len(hops) == 2
    assert hops[1].followed_link_text == "(popup window)" and hops[1].has_password_field


async def test_follows_script_button_navigation(site, tmp_path):
    port, pages, redirects, hits = site
    pages["/login"] = LOGIN
    pages["/doc"] = (f"<html><title>Invoice.pdf</title><body>"
                     f"<div role=button onclick=\"location.href='http://localhost:{port}/login'\">"
                     f"Review File</div></body></html>").encode()
    hops, complete = await _run(f"http://127.0.0.1:{port}/doc", tmp_path,
                                allow_private_networks=True)
    assert complete and len(hops) == 2 and hops[1].followed_link_text == "Review File"


async def test_stealth_hides_webdriver_and_matches_ua(site, tmp_path):
    port, pages, redirects, hits = site
    pages["/fp"] = (b"<html><body><script>document.title = String(navigator.webdriver) + '|' +"
                    b" navigator.userAgent;</script>x</body></html>")
    hops, _ = await _run(f"http://127.0.0.1:{port}/fp", tmp_path, allow_private_networks=True)
    webdriver, ua = hops[0].title.split("|", 1)
    assert webdriver in ("undefined", "false")
    assert "Headless" not in ua and "Chrome/" in ua
