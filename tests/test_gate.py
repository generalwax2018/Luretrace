import json
import os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from luretrace import simcheck  # noqa: E402


def _ago(hours: float) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def _put(scans, sid, url, label, score=0, complete=True, started_at=None):
    from pathlib import Path
    d = Path(scans) / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / "report.json").write_text(json.dumps({
        "url": url, "original_url": url, "label": label, "score": score,
        "complete": complete, "started_at": started_at or _ago(1),
        "signals": [], "hops": [],
    }))


def _seed(scans):
    _put(scans, "s-mal", "https://login.evil.com/common", "malicious", 85)
    _put(scans, "s-clean", "https://docs.google.com/d/1", "clean", 0)
    _put(scans, "s-old-clean", "https://old.example.com/doc", "clean", 0, started_at=_ago(72))
    _put(scans, "s-susp", "https://verify-portal.app/", "suspicious", 45, complete=False)
    _put(scans, "s-frag", "https://lure.example.net/p#dmljdGltQGNvcnAuZXhhbXBsZQ", "malicious", 90)
    os.environ["LURETRACE_SCANS"] = scans


@pytest.fixture
def policy(tmp_path):
    _seed(str(tmp_path / "scans"))
    from webapp.gate_core import Policy, VerdictCache
    return Policy(allowlist_domains=["yourco.com"], sim_domains=["phishdrill.test"]), VerdictCache(ttl_s=0)


# --- simcheck ---------------------------------------------------------------
AUTH_OK = "mx.yourco.com; spf=pass; dkim=pass header.d=knowbe4.com; dmarc=pass header.from=knowbe4.com"


def test_simcheck_url_and_headers():
    assert simcheck.is_sim_url("https://training.knowbe4.com/x")
    assert not simcheck.is_sim_url("https://login.evil.com/")
    assert simcheck.is_sim_url("https://x.phishdrill.test/", extra_domains=["phishdrill.test"])
    # Authenticated mail from a simulation domain is a simulation.
    assert simcheck.is_sim_email({"From": "Coach <coach@knowbe4.com>",
                                  "Authentication-Results": AUTH_OK})
    assert not simcheck.is_sim_email({"From": "attacker@evil.com"})


def test_simcheck_rejects_forgeable_evidence():
    # A simulation header alone is trivially forged by any attacker.
    assert not simcheck.is_sim_email({"X-PHISHTEST": "1", "From": "a@b.com"})
    # So is a From: domain without authentication...
    assert not simcheck.is_sim_email({"From": "coach@knowbe4.com", "X-KB4": "1"})
    # ...or with authentication results for a different domain.
    assert not simcheck.is_sim_email({
        "From": "coach@knowbe4.com",
        "Authentication-Results": "mx; dkim=pass header.d=evil.com; dmarc=pass header.from=evil.com"})
    assert not simcheck.is_sim_email({
        "From": "coach@knowbe4.com",
        "Authentication-Results": "mx; dkim=fail header.d=knowbe4.com; dmarc=fail header.from=knowbe4.com"})
    # Explicit, documented opt-out for vendors that cannot authenticate.
    assert simcheck.is_sim_email({"From": "coach@knowbe4.com"}, trust_unauthenticated=True)


# --- decision engine --------------------------------------------------------
def test_decide_cached_verdicts(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    assert decide("https://login.evil.com/common", pol, cache=cache).action == "block"
    assert decide("https://docs.google.com/d/1", pol, cache=cache).action == "allow"
    assert decide("https://verify-portal.app/", pol, cache=cache).action == "isolate"


def test_decide_unknown_fails_safe(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    d = decide("https://brand-new-domain.test/x", pol, cache=cache)
    assert d.action == "isolate" and d.reason == "not_yet_scanned"


def test_decide_sim_passes_through(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    d = decide("https://x.phishdrill.test/landing", pol, cache=cache)
    assert d.action == "allow" and d.sim is True


def test_decide_allowlist(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    assert decide("https://mail.yourco.com/x", pol, cache=cache).action == "allow"


def test_decide_unwraps_before_checking(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    wrapped = ("https://nam02.safelinks.protection.outlook.com/?url="
               "https%3A%2F%2Flogin.evil.com%2Fcommon&data=1")
    assert decide(wrapped, pol, cache=cache).action == "block"


def test_stale_clean_verdict_is_not_trusted(policy):
    from webapp.gate_core import Policy, VerdictCache, decide
    pol, cache = policy
    d = decide("https://old.example.com/doc", pol, cache=cache)
    assert d.action == "isolate" and d.reason == "stale_clean_verdict"
    forever = Policy(clean_max_age_h=0)
    assert decide("https://old.example.com/doc", forever,
                  cache=VerdictCache(ttl_s=0)).action == "allow"


def test_non_http_schemes_are_blocked(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    for url in ("javascript:alert(1)", "data:text/html,<b>x</b>", "file:///etc/passwd"):
        assert decide(url, pol, cache=cache).action == "block"


def test_lookup_falls_back_to_url_without_fragment(policy):
    from webapp.gate_core import decide
    pol, cache = policy
    # Same lure, different per-recipient fragment: still the malicious verdict.
    assert decide("https://lure.example.net/p#b3RoZXJAY29ycC5leGFtcGxl", pol,
                  cache=cache).action == "block"


def test_cache_picks_up_new_scans_incrementally(policy, tmp_path):
    from webapp.gate_core import decide
    pol, cache = policy
    assert decide("https://late.example.org/x", pol, cache=cache).reason == "not_yet_scanned"
    _put(os.environ["LURETRACE_SCANS"], "s-late", "https://late.example.org/x", "malicious", 80)
    cache.miss_refresh_s = 0
    assert decide("https://late.example.org/x", pol, cache=cache).action == "block"


def test_policy_can_block_on_unknown(policy):
    from webapp.gate_core import Policy, VerdictCache, decide
    _, _ = policy
    pol = Policy(unknown_action="block")
    assert decide("https://nope.test/", pol, cache=VerdictCache(ttl_s=0)).action == "block"


# --- gate API ---------------------------------------------------------------
@pytest.fixture
def client(tmp_path, monkeypatch):
    _seed(str(tmp_path / "scans"))
    monkeypatch.setenv("LURETRACE_ALLOWLIST", "yourco.com")
    import importlib

    from webapp import gate
    importlib.reload(gate)  # re-read policy from env
    return TestClient(gate.gate_app)


def test_check_endpoint(client):
    r = client.post("/check", json={"url": "https://login.evil.com/common"})
    assert r.status_code == 200 and r.json()["action"] == "block"
    r2 = client.post("/check", json={"url": "https://docs.google.com/d/1"})
    assert r2.json()["action"] == "allow"
    assert client.post("/check", json={"url": ""}).status_code == 400


def test_go_allow_redirects(client):
    r = client.get("/go", params={"u": "https://docs.google.com/d/1"}, follow_redirects=False)
    assert r.status_code == 302 and "docs.google.com" in r.headers["location"]


def test_go_block_page(client):
    r = client.get("/go", params={"u": "https://login.evil.com/common"})
    assert r.status_code == 200 and "blocked" in r.text.lower()


def test_go_unknown_isolates(client):
    r = client.get("/go", params={"u": "https://brand-new.test/x"})
    assert r.status_code == 200 and "Checking this link" in r.text


def test_go_never_redirects_to_script_urls(client):
    r = client.get("/go", params={"u": "javascript:alert(1)"}, follow_redirects=False)
    assert r.status_code == 200 and "location" not in r.headers


def test_healthz_does_not_leak_policy(client):
    r = client.get("/healthz")
    assert r.json() == {"ok": True}
    assert "yourco.com" not in r.text


def test_check_rejects_non_object_bodies(client):
    assert client.post("/check", json=["https://x"]).status_code == 400
    assert client.post("/check", content=b"not json",
                       headers={"content-type": "application/json"}).status_code == 400


def test_check_sim_header_alone_does_not_pass(client):
    r = client.post("/check", json={"url": "https://login.evil.com/common",
                                    "headers": {"X-PhishTest": "1", "From": "x@evil.com"}})
    assert r.json()["action"] == "block"
