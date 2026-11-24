"""Hermetic tests for response actions, the job inbox, rescan wiring, webhooks, the CLI
commands added for ingest/drain/blocklist/eval, and mail-source acknowledgement."""
import hashlib
import hmac
import json

import httpx
import pytest

import luretrace.pipeline as pipeline
from luretrace import actions, inbox
from luretrace.config import Config
from luretrace.models import Hop, Verdict

PHISH = [Hop(0, "https://contoso-my.sharepoint.com/:b:/doc",
             final_url="https://contoso-my.sharepoint.com/:b:/doc", title="Invoice.pdf"),
         Hop(1, "https://login.evil-login.com/", final_url="https://login.evil-login.com/common",
             title="Sign in to your account", has_email_field=True, has_password_field=True,
             resource_hosts=["aadcdn.msauth.net"], followed_link_text="View Document")]
CLEAN = [Hop(0, "https://plain.example.org/", final_url="https://plain.example.org/", title="Hi")]


@pytest.fixture
def fake_worker(monkeypatch):
    """Replace the browser with canned chains, and treat every host as public."""
    calls = []

    async def detonate(url, cfg, outdir):
        outdir.mkdir(parents=True, exist_ok=True)
        calls.append(url)
        return ([Hop(**h.__dict__) for h in (PHISH if "lure" in url else CLEAN)], True)

    monkeypatch.setattr(pipeline, "detonate", detonate)
    monkeypatch.setattr(pipeline, "is_public_host", lambda host, unresolved_ok=False: True)
    return calls


def _mock_client(monkeypatch, module, handler, async_=False):
    real = httpx.AsyncClient if async_ else httpx.Client
    name = "AsyncClient" if async_ else "Client"
    monkeypatch.setattr(module.httpx, name,
                        lambda *a, **kw: real(*a, transport=httpx.MockTransport(handler), **kw))


# --- Graph purge ---------------------------------------------------------------
def test_odata_quote_doubles_quotes():
    evil = "<x' or isRead eq false or internetMessageId eq 'y>"
    assert actions.odata_quote(evil) == "'<x'' or isRead eq false or internetMessageId eq ''y>'"


def test_graph_purge_escapes_and_requires_exactly_one_match(monkeypatch):
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t"})
        if request.method == "GET":
            box = request.url.path.split("/users/")[1].split("/")[0]
            mid = "<a'b@x>"
            if box == "one@corp.example":
                return httpx.Response(200, json={"value": [{"id": "M1", "internetMessageId": mid}]})
            # two matches: ambiguous, must not be touched
            return httpx.Response(200, json={"value": [{"id": "M2", "internetMessageId": mid},
                                                       {"id": "M3", "internetMessageId": mid}]})
        return httpx.Response(201, json={})

    _mock_client(monkeypatch, actions, handler)
    cfg = {"tenant_id": "t", "client_id": "c", "client_secret": "s", "mailbox": "scan@corp.example"}
    assert actions.graph_purge("<a'b@x>", cfg, ["one@corp.example", "two@corp.example"])
    gets = [r for r in seen if r.method == "GET"]
    assert all("'<a''b@x>'" in r.url.params["$filter"] for r in gets)
    moves = [r for r in seen if r.method == "POST" and r.url.path.endswith("/move")]
    assert len(moves) == 1 and "/messages/M1/move" in moves[0].url.path
    assert not actions.graph_purge("not-a-message-id", cfg)  # malformed: refused, no calls


# --- blocklists --------------------------------------------------------------------
def _verdict(hops, label="malicious"):
    return Verdict(url=hops[0].requested_url, original_url=hops[0].requested_url, label=label,
                   score=90, complete=True, hops=hops, message_id="<m@x>")


def test_blocklist_never_blocks_shared_platforms():
    assert actions.blockable(_verdict(PHISH)) == ["evil-login.com"]
    hosted = [Hop(0, "https://share.dropbox.com/x", final_url="https://share.dropbox.com/x"),
              Hop(1, "https://kit-1.pages.dev/", final_url="https://kit-1.pages.dev/login",
                  has_password_field=True)]
    # The attacker's subdomain on shared hosting is blocked; the platform and the lure are not.
    assert actions.blockable(_verdict(hosted)) == ["kit-1.pages.dev"]


def test_append_blocklist_dedupes(tmp_path):
    path = tmp_path / "bl.txt"
    assert actions.append_blocklist(_verdict(PHISH), str(path)) == 1
    assert actions.append_blocklist(_verdict(PHISH), str(path)) == 0
    assert actions.append_blocklist(_verdict(CLEAN, "clean"), str(path)) == 0
    assert path.read_text().splitlines() == ["evil-login.com"]


# --- pipeline: actions, rescan, webhook ----------------------------------------------
async def test_scan_records_actions_and_queues_rescan(fake_worker, tmp_path, monkeypatch):
    purged = []
    monkeypatch.setattr(actions, "graph_purge",
                        lambda mid, cfg, boxes=None: purged.append((mid, boxes)) or True)
    cfg = Config(output_dir=str(tmp_path / "scans"), blocklist_path=str(tmp_path / "bl.txt"),
                 purge_on_malicious=True, graph={"tenant_id": "t", "mailbox": "scan@corp"},
                 honeytoken={"enabled": True}, rescan_queue=str(tmp_path / "q.json"))
    bad = await pipeline.scan_url("https://lure.example.com/x", cfg, "<m@x>",
                                  recipients=["victim@corp.example"], rescan=True)
    assert bad.label == "malicious"
    kinds = [a["action"] for a in bad.actions]
    assert kinds == ["blocklist", "graph_purge"]  # honeytoken skipped: no seeded canary
    assert purged == [("<m@x>", ["victim@corp.example"])]
    report = json.loads((tmp_path / "scans" / bad.artifacts_dir.split("\\")[-1].split("/")[-1]
                         / "report.json").read_text())
    assert [a["action"] for a in report["actions"]] == kinds

    ok = await pipeline.scan_url("https://plain.example.org/", cfg, "<m@x>", rescan=True)
    queue = json.loads((tmp_path / "q.json").read_text())
    assert [i["url"] for i in queue] == ["https://plain.example.org/"]  # malicious is not re-queued
    assert queue[0]["first_label"] == "clean" and ok.label == "clean"


async def test_unresolvable_link_is_suspicious_and_queued_not_skipped(tmp_path):
    # The gate allows "skipped"; a domain registered after delivery must not ride on that.
    cfg = Config(output_dir=str(tmp_path), rescan_queue=str(tmp_path / "q.json"))
    v = await pipeline.scan_url("https://not-registered-yet.invalid/login", cfg, rescan=True)
    assert v.label == "suspicious" and not v.complete
    assert [s.name for s in v.signals] == ["does_not_resolve"]
    queued = json.loads((tmp_path / "q.json").read_text())
    assert queued[0]["url"] == "https://not-registered-yet.invalid/login"
    private = await pipeline.scan_url("http://10.0.0.1/x", cfg)
    assert private.label == "skipped"


async def test_scan_ids_are_unique_per_run(fake_worker, tmp_path):
    cfg = Config(output_dir=str(tmp_path), rescan_auto=False)
    a = await pipeline.scan_url("https://plain.example.org/", cfg)
    b = await pipeline.scan_url("https://plain.example.org/", cfg)
    assert a.artifacts_dir != b.artifacts_dir


async def test_rescan_notifies_only_when_worse(fake_worker, tmp_path, monkeypatch):
    sent = []

    async def notify(v, cfg):
        sent.append((v.label, v.rescan_of))
        return True

    monkeypatch.setattr(pipeline, "notify", notify)
    cfg = Config(output_dir=str(tmp_path), webhook_url="https://hook.example/")
    await pipeline.scan_url("https://plain.example.org/", cfg, rescan_of="clean")
    await pipeline.scan_url("https://lure.example.com/", cfg, rescan_of="clean")
    await pipeline.scan_url("https://lure.example.com/", cfg, rescan_of="malicious")
    assert sent == [("malicious", "clean")]


async def test_webhook_is_signed_and_retried(monkeypatch):
    bodies = []

    def handler(request: httpx.Request):
        bodies.append(request)
        return httpx.Response(503 if len(bodies) == 1 else 200)

    _mock_client(monkeypatch, pipeline, handler, async_=True)
    monkeypatch.setattr(pipeline.asyncio, "sleep", _no_sleep)
    cfg = Config(webhook_url="https://hook.example/x", webhook_secret="k3y", webhook_retries=2)
    v = _verdict(PHISH)
    v.started_at = "2026-11-24T00:00:00+00:00"
    assert await pipeline.notify(v, cfg)
    assert len(bodies) == 2  # 503 retried once
    req = bodies[-1]
    expected = "sha256=" + hmac.new(b"k3y", req.content, hashlib.sha256).hexdigest()
    assert req.headers["x-luretrace-signature"] == expected
    assert json.loads(req.content)["label"] == "malicious"


async def test_webhook_does_not_retry_client_errors(monkeypatch):
    calls = []
    _mock_client(monkeypatch, pipeline, lambda r: calls.append(r) or httpx.Response(400),
                 async_=True)
    monkeypatch.setattr(pipeline.asyncio, "sleep", _no_sleep)
    assert not await pipeline.notify(_verdict(PHISH), Config(webhook_url="https://hook.example/"))
    assert len(calls) == 1


async def _no_sleep(_):
    return None


# --- inbox ---------------------------------------------------------------------------
def test_inbox_claim_is_exclusive(tmp_path):
    inbox.enqueue_url(tmp_path, "https://a.example/")
    inbox.enqueue_eml(tmp_path, b"Subject: x\r\n\r\nhi")
    jobs = list(inbox.claim(tmp_path))
    assert sorted(j.kind for j in jobs) == ["eml", "url"]
    assert list(inbox.claim(tmp_path)) == []  # already claimed by the first worker
    inbox.done(jobs[0])
    inbox.fail(jobs[1])
    assert len(list((tmp_path / "failed").iterdir())) == 1


def test_cli_drain_runs_queued_jobs(fake_worker, tmp_path, monkeypatch, capsys):
    from luretrace import cli
    monkeypatch.setattr(cli, "scan_url", pipeline.scan_url)
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text(f"output_dir: {tmp_path / 'scans'}\ninbox_dir: {tmp_path / 'in'}\n"
                       f"rescan_auto: false\n".replace("\\", "/"))
    inbox.enqueue_url(tmp_path / "in", "https://lure.example.com/q")
    assert cli.main(["-c", str(cfgfile), "drain"]) == 2  # malicious exit code
    assert "MALICIOUS" in capsys.readouterr().out
    assert not [p for p in (tmp_path / "in").iterdir() if p.is_file()]


# --- watch: ack only after a scan, bounded retries --------------------------------------
def test_watch_acks_after_scan_and_gives_up_on_poison(tmp_path, monkeypatch):
    from luretrace import cli
    from luretrace.sources import Message

    acked = []
    msgs = lambda: [Message(b"poison", "k-poison", lambda: acked.append("poison")),  # noqa: E731
                    Message(b"good", "k-good", lambda: acked.append("good"))]

    class Source:
        def fetch(self):
            yield from msgs()

    async def scan_message(raw, cfg):
        if raw == b"poison":
            raise RuntimeError("boom")
        return []

    sleeps = []

    def sleep(_):
        sleeps.append(1)
        if len(sleeps) >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli, "build_source", lambda cfg: Source())
    monkeypatch.setattr(cli, "scan_message", scan_message)
    monkeypatch.setattr(cli.time, "sleep", sleep)
    cfg = Config(imap={"host": "h"}, max_attempts=2, poll_seconds=0)
    assert cli._watch(cfg, False) == 0
    # poll 1: good acked, poison left unread; poll 2: poison hits max_attempts and is acked.
    assert acked == ["good", "poison", "good"]


# --- ingest / blocklist / eval CLI ------------------------------------------------------
def test_cli_ingest_scans_connector_items(fake_worker, tmp_path, monkeypatch, capsys):
    from luretrace import cli, ingest
    monkeypatch.setattr(cli, "scan_url", pipeline.scan_url)

    class Conn:
        def fetch(self):
            yield ingest.IngestItem(url="https://lure.example.com/i", source="mimecast",
                                    gateway_verdict="clean", recipient="v@corp.example")
            yield ingest.IngestItem(url="https://lure.example.com/i", source="mimecast")

    monkeypatch.setattr(ingest, "build_connector", lambda kind, opts: Conn())
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text(f"output_dir: {tmp_path / 'scans'}\nrescan_auto: false\n"
                       f"ingest: {{kind: mimecast}}\n".replace("\\", "/"))
    assert cli.main(["-c", str(cfgfile), "ingest"]) == 2
    out = capsys.readouterr().out
    assert "mimecast said 'clean', luretrace says malicious" in out
    assert fake_worker == ["https://lure.example.com/i"]  # duplicate item not re-detonated


async def test_blocklist_command_reads_reports(fake_worker, tmp_path):
    from luretrace import cli
    cfg = Config(output_dir=str(tmp_path / "scans"), rescan_auto=False)
    await pipeline.scan_url("https://lure.example.com/b", cfg)
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text(f"output_dir: {tmp_path / 'scans'}\n".replace("\\", "/"))
    assert cli.main(["-c", str(cfgfile), "blocklist", str(tmp_path / "out.txt")]) == 0
    assert (tmp_path / "out.txt").read_text().split() == ["evil-login.com"]


def test_eval_scores_against_labels(fake_worker, tmp_path, capsys):
    from luretrace import cli
    labels = tmp_path / "labels.csv"
    labels.write_text("url,label\nhttps://lure.example.com/1,phish\nhttps://plain.example.org/,"
                      "benign\nhttps://plain.example.org/missed,phish\nbad-row,unknown\n")
    cfgfile = tmp_path / "c.yaml"
    cfgfile.write_text(f"output_dir: {tmp_path / 'scans'}\nwebhook_url: https://hook.invalid/\n"
                       .replace("\\", "/"))
    out = tmp_path / "eval.json"
    assert cli.main(["-c", str(cfgfile), "eval", str(labels), "--out", str(out)]) == 0
    summary = json.loads(out.read_text())["summary"]
    assert (summary["tp"], summary["fp"], summary["tn"], summary["fn"]) == (1, 0, 1, 1)
    assert summary["precision"] == 1.0 and summary["recall"] == 0.5


# --- Mimecast decode caching ---------------------------------------------------------
def test_mimecast_token_and_results_are_cached(monkeypatch):
    from luretrace import unwrap as uw
    uw._MC_TOKENS.clear()
    uw._MC_DECODED.clear()
    calls = []

    def handler(request: httpx.Request):
        calls.append(request.url.path)
        if request.url.path.endswith("/oauth/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
        url = json.loads(request.content)["data"][0]["url"]
        return httpx.Response(200, json={"data": [{"url": url.replace(
            "https://protect-eu.mimecast.com/s/", "https://real.example/"), "success": True}]})

    real = httpx.Client
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **kw: real(*a, transport=httpx.MockTransport(handler), **kw))
    cfg = {"client_id": "c", "client_secret": "s"}
    assert uw.unwrap("https://protect-eu.mimecast.com/s/a", cfg) == "https://real.example/a"
    assert uw.unwrap("https://protect-eu.mimecast.com/s/b", cfg) == "https://real.example/b"
    assert uw.unwrap("https://protect-eu.mimecast.com/s/a", cfg) == "https://real.example/a"
    assert calls.count("/oauth/token") == 1
    assert len([c for c in calls if c.endswith("decode-url")]) == 2
