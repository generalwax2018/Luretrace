import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _seed(scans: str):
    import os
    from pathlib import Path
    root = Path(scans)
    # a malicious scan with a two-hop chain and a screenshot artifact
    mal = root / "20261117T090000-abcd1234"
    mal.mkdir(parents=True)
    verdict = {
        "url": "https://contoso-my.sharepoint.com/:b:/doc",
        "original_url": "https://nam02.safelinks.protection.outlook.com/?url=...",
        "label": "malicious", "score": 85, "complete": True,
        "started_at": "2026-11-17T09:00:00+00:00", "message_id": "<m1@x>",
        "artifacts_dir": str(mal),
        "signals": [
            {"name": "brand_login_off_domain", "score": 80,
             "detail": "Microsoft sign-in page served from evil.com (resource match)", "hop": 1},
            {"name": "fileshare_lure_to_login", "score": 20,
             "detail": "File-share link led to a credential form on evil.com", "hop": 1},
        ],
        "hops": [
            {"index": 0, "requested_url": "https://contoso-my.sharepoint.com/:b:/doc",
             "final_url": "https://contoso-my.sharepoint.com/:b:/doc", "status": 200,
             "title": "Invoice.pdf", "redirects": [], "followed_link_text": "",
             "has_password_field": False, "has_email_field": False, "form_actions": [],
             "resource_hosts": ["sharepoint.com"], "blocked_requests": [], "downloads": []},
            {"index": 1, "requested_url": "https://login.evil.com/",
             "final_url": "https://login.evil.com/common", "status": 200,
             "title": "Sign in to your account", "redirects": ["https://evil.com/r"],
             "followed_link_text": "View Document", "has_password_field": True,
             "has_email_field": True, "form_actions": ["https://evil.com/collect"],
             "resource_hosts": ["aadcdn.msauth.net", "login.evil.com"],
             "blocked_requests": [], "downloads": [{"filename": "x.html", "sha256": "a" * 64}]},
        ],
    }
    (mal / "report.json").write_text(json.dumps(verdict))
    (mal / "hop_1.png").write_bytes(b"\x89PNG\r\n\x1a\n fake")
    (mal / "chain.har").write_text("{}")
    # a clean scan
    clean = root / "20261117T080000-0000aaaa"
    clean.mkdir(parents=True)
    (clean / "report.json").write_text(json.dumps({
        "url": "https://example.org/", "original_url": "https://example.org/",
        "label": "clean", "score": 0, "complete": True,
        "started_at": "2026-11-17T08:00:00+00:00", "signals": [],
        "hops": [{"index": 0, "requested_url": "https://example.org/",
                  "final_url": "https://example.org/", "status": 200, "title": "Example",
                  "redirects": [], "has_password_field": False, "has_email_field": False}],
    }))
    os.environ["LURETRACE_SCANS"] = scans


@pytest.fixture
def client(tmp_path, monkeypatch):
    _seed(str(tmp_path / "scans"))
    from webapp import server
    return TestClient(server.app)


def test_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text
    assert "brand_login_off_domain" not in r.text  # signals only on detail
    assert "evil.com" in r.text  # failed destination surfaced


def test_scans_list_and_filter(client):
    assert client.get("/scans").status_code == 200
    r = client.get("/scans", params={"status": "malicious"})
    assert "login.evil.com" in r.text  # final destination column
    assert "example.org" not in r.text
    r2 = client.get("/scans", params={"status": "clean"})
    assert "example.org" in r2.text and "login.evil.com" not in r2.text


def test_forensics_detail(client):
    r = client.get("/scans/20261117T090000-abcd1234")
    assert r.status_code == 200
    assert "brand_login_off_domain" in r.text
    assert "View Document" in r.text           # followed link text
    assert "password field" in r.text          # credential flag
    assert "a" * 64 in r.text                   # download hash
    assert "hop_1.png" in r.text                # screenshot referenced


def test_artifact_png_inline_and_html_download(client):
    r = client.get("/scans/20261117T090000-abcd1234/artifact/hop_1.png")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/")
    h = client.get("/scans/20261117T090000-abcd1234/artifact/chain.har")
    assert h.status_code == 200
    assert h.headers["content-type"] == "application/octet-stream"  # never rendered


def test_artifact_rejects_traversal_and_unknown(client):
    assert client.get("/scans/20261117T090000-abcd1234/artifact/secret.txt").status_code == 404
    assert client.get("/scans/..%2f..%2fetc/artifact/report.json").status_code in (404, 400)


def test_sources_and_health(client):
    assert client.get("/sources").status_code == 200
    assert "Mimecast" in client.get("/sources").text
    assert client.get("/healthz").text == "ok"


def test_missing_scan(client):
    r = client.get("/scans/nope")
    assert r.status_code == 200 and "not found" in r.text.lower()


def test_submit_form(client):
    r = client.get("/submit")
    assert r.status_code == 200 and "Submit a link" in r.text


def _token(client) -> str:
    import re
    page = client.get("/submit").text
    return re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)


def test_submit_private_url_is_skipped_without_browser(client, monkeypatch):
    monkeypatch.delenv("LURETRACE_INBOX", raising=False)
    # A non-public target is skipped before any browser launches, so this is hermetic.
    r = client.post("/submit", data={"url": "http://10.0.0.1/secret", "csrf": _token(client)})
    assert r.status_code == 200
    assert "No detonation" in r.text or "skipped" in r.text.lower()


def test_submit_empty_shows_error(client):
    r = client.post("/submit", data={"url": "", "csrf": _token(client)})
    assert r.status_code == 200
    assert "enter a URL" in r.text or "enter a url" in r.text.lower()


def test_submit_requires_form_token(client):
    assert client.post("/submit", data={"url": "https://x.example/"}).status_code == 403
    assert client.post("/submit", data={"url": "https://x.example/", "csrf": "0" * 64}
                       ).status_code == 403


def test_submit_rejects_cross_site_posts(client):
    r = client.post("/submit", data={"url": "https://x.example/", "csrf": _token(client)},
                    headers={"Origin": "https://attacker.example"})
    assert r.status_code == 403


def test_submit_rejects_non_http_links(client):
    r = client.post("/submit", data={"url": "file:///etc/passwd", "csrf": _token(client)})
    assert "only http(s)" in r.text


def test_submit_queue_mode_hands_work_to_the_worker(client, tmp_path, monkeypatch):
    inbox_dir = tmp_path / "inbox"
    monkeypatch.setenv("LURETRACE_INBOX", str(inbox_dir))
    r = client.post("/submit", data={"url": "https://lure.example.com/x", "csrf": _token(client)})
    assert r.status_code == 200 and "Queued" in r.text
    jobs = list(inbox_dir.glob("*.url.json"))
    assert len(jobs) == 1 and json.loads(jobs[0].read_text())["url"] == "https://lure.example.com/x"


def test_security_headers(client):
    r = client.get("/")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_scan_ids_are_validated(client, tmp_path):
    from webapp import store
    # A report.json one level above the scans dir must not be reachable as a "scan".
    (store.scans_dir().parent / "report.json").write_text("{}")
    for bad in ("..", ".", "../x", "a/b", "a\\b", "", "x" * 200):
        assert not store.valid_scan_id(bad), bad
        assert store.load_scan(bad) is None
    assert store.valid_scan_id("20261117T090000-abcd1234-0f3a")
    assert client.get("/scans/%2E%2E").status_code == 200  # renders not-found, no traversal
