import json
import os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from luretrace import simcheck  # noqa: E402


def _seed(scans):
    from pathlib import Path
    root = Path(scans)
    def put(sid, url, label, score=0, complete=True):
        d = root / sid
        d.mkdir(parents=True, exist_ok=True)
        (d / "report.json").write_text(json.dumps({
            "url": url, "original_url": url, "label": label, "score": score,
            "complete": complete, "started_at": "2026-11-17T09:00:00+00:00",
            "signals": [], "hops": [],
        }))
    put("s-mal", "https://login.evil.com/common", "malicious", 85)
    put("s-clean", "https://docs.google.com/d/1", "clean", 0)
    put("s-susp", "https://verify-portal.app/", "suspicious", 45, complete=False)
    os.environ["LURETRACE_SCANS"] = scans


@pytest.fixture
def policy(tmp_path):
    _seed(str(tmp_path / "scans"))
    from webapp.gate_core import Policy, VerdictCache
    return Policy(allowlist_domains=["yourco.com"], sim_domains=["phishdrill.test"]), VerdictCache(ttl_s=0)


# --- simcheck ---------------------------------------------------------------
def test_simcheck_url_and_headers():
    assert simcheck.is_sim_url("https://training.knowbe4.com/x")
    assert not simcheck.is_sim_url("https://login.evil.com/")
    assert simcheck.is_sim_email({"X-PHISHTEST": "1", "From": "a@b.com"})
    assert simcheck.is_sim_email({"From": "coach@knowbe4.com"})
    assert not simcheck.is_sim_email({"From": "attacker@evil.com"})
    assert simcheck.is_sim_url("https://x.phishdrill.test/", extra_domains=["phishdrill.test"])


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
