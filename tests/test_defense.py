from datetime import datetime, timedelta, timezone

from luretrace.actions import export_iocs, netskope_url_list, write_blocklist, write_iocs
from luretrace.beacon import classify_hit, css_snippet
from luretrace.honeytoken import generate_canary, should_submit
from luretrace.models import Hop, Verdict
from luretrace.rescan import RescanItem, RescanQueue, next_due_offset


class H(dict):
    """Case-insensitive header stand-in like http.client's message object."""

    def get(self, k, default=None):
        for key, val in self.items():
            if key.lower() == k.lower():
                return val
        return default


def _malicious_verdict(tmp_path):
    lure = Hop(0, "https://contoso-my.sharepoint.com/:b:/doc",
               final_url="https://contoso-my.sharepoint.com/:b:/doc")
    phish = Hop(1, "https://login.evil.com/", final_url="https://login.evil.com/common",
                has_email_field=True, has_password_field=True,
                downloads=[{"filename": "x.html", "sha256": "a" * 64}])
    v = Verdict(url="https://contoso-my.sharepoint.com/:b:/doc",
                original_url="https://contoso-my.sharepoint.com/:b:/doc",
                label="malicious", score=85, complete=True, hops=[lure, phish],
                artifacts_dir=str(tmp_path / "scan1"), message_id="<m@x>")
    return v


# --- beacon -----------------------------------------------------------------
def test_beacon_detects_proxied_login():
    trusted = ["login.microsoftonline.com", "login.live.com"]
    assert classify_hit(H(Referer="https://login.microsoftonline.com/x"), trusted) == (
        "legit", "login.microsoftonline.com")
    assert classify_hit(H(Origin="https://login.evil-proxy.ru"), trusted) == (
        "proxied", "login.evil-proxy.ru")
    assert classify_hit(H(), trusted) == ("unknown", "")
    # Origin wins over Referer when both present.
    assert classify_hit(H(Origin="https://attacker.test", Referer="https://login.live.com/"),
                        trusted)[0] == "proxied"


def test_css_snippet_contains_beacon_url():
    css = css_snippet("https://beacon.example")
    assert "https://beacon.example/b.gif" in css and "background-image" in css


# --- rescan -----------------------------------------------------------------
def test_next_due_offset():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    item = RescanItem(url="u", created_at=(now - timedelta(minutes=20)).isoformat(),
                      offsets_minutes=[15, 60, 240])
    assert next_due_offset(item, now) == 15  # 20 min elapsed: 15 is due, 60 is not
    item.done_offsets = [15]
    assert next_due_offset(item, now) is None
    later = now + timedelta(minutes=60)
    assert next_due_offset(item, later) == 60


def test_rescan_queue_roundtrip(tmp_path):
    path = tmp_path / "q.json"
    q = RescanQueue(str(path))
    q.add("https://evil.example/x", [15, 60], message_id="<m>", first_label="clean")
    q.add("https://evil.example/x", [15, 60], message_id="<m>")  # dedup
    assert len(q.items) == 1
    old = datetime.now(timezone.utc) - timedelta(minutes=16)
    q.items[0].created_at = old.isoformat()
    due = q.due()
    assert due and due[0][1] == 15
    q.mark_done(due[0][0], 15)
    assert RescanQueue(str(path)).items[0].done_offsets == [15]


# --- actions ----------------------------------------------------------------
def test_export_iocs_picks_phishing_host(tmp_path):
    iocs = export_iocs(_malicious_verdict(tmp_path))
    assert iocs["phishing_domain"] == "evil.com"
    assert "evil.com" in iocs["domains"]
    assert "a" * 64 in iocs["sha256"]


def test_iocs_respect_allowlist(tmp_path):
    iocs = export_iocs(_malicious_verdict(tmp_path), allowlist=["sharepoint.com"])
    assert "sharepoint.com" not in iocs["domains"]
    assert "evil.com" in iocs["domains"]


def test_blocklist_only_malicious(tmp_path):
    mal = _malicious_verdict(tmp_path)
    clean = Verdict(url="https://ok.example/", original_url="https://ok.example/",
                    label="clean", score=0, complete=True,
                    hops=[Hop(0, "https://ok.example/", final_url="https://ok.example/")])
    assert netskope_url_list([mal, clean], ["sharepoint.com"]) == ["evil.com"]
    path = tmp_path / "block.txt"
    assert write_blocklist([mal, clean], str(path), ["sharepoint.com"]) == 1
    assert path.read_text().strip() == "evil.com"


def test_write_iocs_skips_clean(tmp_path):
    clean = Verdict(url="u", original_url="u", label="clean", score=0, complete=True)
    assert write_iocs(clean, str(tmp_path)) is None
    assert write_iocs(_malicious_verdict(tmp_path), str(tmp_path)) is not None


# --- honeytoken -------------------------------------------------------------
def test_honeytoken_gate_is_malicious_only(tmp_path):
    mal = _malicious_verdict(tmp_path)
    assert should_submit(mal, {"enabled": True})
    assert not should_submit(mal, {"enabled": False})
    assert not should_submit(mal, {})
    for label in ("clean", "suspicious", "skipped"):
        mal.label = label
        assert not should_submit(mal, {"enabled": True})


def test_canary_is_fake_and_unique():
    a, b = generate_canary(), generate_canary()
    assert a["username"].endswith("@example-canary.invalid")
    assert a["username"] != b["username"]
