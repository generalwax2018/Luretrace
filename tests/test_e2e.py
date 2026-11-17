"""End-to-end: a local two-site lure chain run through the real browser worker.

Skipped automatically when no Playwright Chromium is installed.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from luretrace.config import Config
from luretrace.detonate import detonate
from luretrace.signals import evaluate, label_for, total

LOGIN = b"""<html><head><title>Sign in to your account</title></head><body>
<h1>Microsoft</h1><form action="/post" method="post">
<input type="email" name="loginfmt"><input type="password" name="passwd">
<button>Sign in</button></form></body></html>"""


def _serve(pages):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = pages.get(self.path)
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body or b"not found")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def chain():
    pages = {"/login": LOGIN}
    server = _serve(pages)
    port = server.server_address[1]
    # Lure is on 127.0.0.1, login on "localhost": two different registrable names.
    pages["/doc"] = (
        f'<html><title>Invoice.pdf</title><body><p>A file was shared with you.</p>'
        f'<a href="http://localhost:{port}/login">View Document</a></body></html>'
    ).encode()
    pages["/plain"] = b"<html><title>Hello</title><body>Nothing here</body></html>"
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


async def _run(url, tmp_path, **overrides):
    cfg = Config(output_dir=str(tmp_path), settle_timeout_ms=2000, **overrides)
    try:
        return await detonate(url, cfg, tmp_path / "scan")
    except Exception as exc:
        if "Executable doesn't exist" in str(exc) or "playwright install" in str(exc):
            pytest.skip("Playwright Chromium not installed")
        raise


async def test_follows_lure_to_fake_login(chain, tmp_path):
    hops, complete = await _run(f"{chain}/doc", tmp_path, allow_private_networks=True)
    assert complete and len(hops) == 2
    assert hops[1].followed_link_text == "View Document"
    assert hops[1].has_password_field and hops[1].has_email_field
    assert (tmp_path / "scan" / "hop_1.png").exists()
    assert (tmp_path / "scan" / "chain.har").exists()
    signals = evaluate(hops, complete)
    assert label_for(total(signals)) in ("suspicious", "malicious")
    assert any(s.name == "brand_login_off_domain" for s in signals)


async def test_plain_page_is_clean(chain, tmp_path):
    hops, complete = await _run(f"{chain}/plain", tmp_path, allow_private_networks=True)
    assert complete and len(hops) == 1
    assert total(evaluate(hops, complete)) == 0


async def test_guard_blocks_private_targets(chain, tmp_path):
    hops, complete = await _run(f"{chain}/doc", tmp_path)  # guard on: loopback is refused
    assert not complete and hops[0].error
    assert hops[0].blocked_requests
    assert label_for(total(evaluate(hops, complete))) != "clean"


async def test_pipeline_skips_non_public_links(chain, tmp_path):
    from luretrace.pipeline import scan_url

    verdict = await scan_url(f"{chain}/doc", Config(output_dir=str(tmp_path)))
    assert verdict.label == "skipped" and not verdict.hops
