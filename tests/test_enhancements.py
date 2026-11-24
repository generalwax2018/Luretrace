"""Hermetic tests for the extraction, signal, config and enrichment enhancements."""
import base64
import io
from email.message import EmailMessage

import pytest

from luretrace import enrich
from luretrace.config import Config
from luretrace.extract import extract_urls, urls_from_html
from luretrace.models import Hop
from luretrace.signals import emails_in_url, evaluate, label_for, total


# --- confirmed-bug regressions ------------------------------------------------
def test_meta_refresh_keeps_case():
    html = '<meta http-equiv="refresh" content="0; URL=\'https://x.test/AbC?Tok=XyZ\'">'
    assert urls_from_html(html) == ["https://x.test/AbC?Tok=XyZ"]


def _login(text, title="Sign in", url="https://app.saas.test/login"):
    return Hop(0, url, final_url=url, title=title, text_excerpt=text,
               has_password_field=True, has_email_field=True)


def test_sso_buttons_on_legit_saas_login_are_not_impersonation():
    hop = _login("Welcome back\nSign in with Google\nContinue with Microsoft\nEmail\nPassword")
    signals = evaluate([hop], True)
    assert not any(s.name == "brand_login_off_domain" for s in signals)
    assert label_for(total(signals)) == "clean"


def test_kit_prose_naming_the_brand_is_still_flagged():
    hop = _login("Sign in with your Microsoft account to view the shared document\nPassword")
    assert any(s.name == "brand_login_off_domain" for s in evaluate([hop], True))
    kit = _login("Microsoft\nSign in\nCan't access your account?", title="Sign in to your account")
    assert any(s.name == "brand_login_off_domain" for s in evaluate([kit], True))


# --- recipient / email in URL ---------------------------------------------------
def test_emails_in_url_plain_encoded_and_base64():
    b64 = base64.b64encode(b"victim@corp.example").decode()
    assert emails_in_url("https://e.test/x?u=victim@corp.example") == {"victim@corp.example"}
    assert emails_in_url("https://e.test/x?u=victim%40corp.example") == {"victim@corp.example"}
    assert emails_in_url(f"https://e.test/#{b64}") == {"victim@corp.example"}
    assert emails_in_url("https://e.test/plain/path") == set()


def test_recipient_in_url_signal():
    b64 = base64.urlsafe_b64encode(b"victim@corp.example").decode().rstrip("=")
    hop = Hop(0, f"https://lure.test/#{b64}", final_url="https://lure.test/")
    names = {s.name: s.score for s in evaluate([hop], True, recipients=["Victim@corp.example"])}
    assert names.get("recipient_in_url") == 20
    other = {s.name for s in evaluate([hop], True, recipients=["someone@else.example"])}
    assert "email_in_url" in other and "recipient_in_url" not in other


def test_origin_signals():
    hop = Hop(0, "https://x.test/", final_url="https://x.test/")
    assert any(s.name == "qr_code_link" for s in evaluate([hop], True, origin="qr:scan.png"))
    assert any(s.name == "markup_attachment_link"
               for s in evaluate([hop], True, origin="attachment:Invoice.svg"))
    assert not any(s.name == "markup_attachment_link"
                   for s in evaluate([hop], True, origin="attachment:notes.txt"))


# --- attachments --------------------------------------------------------------
def _message(**attachments) -> bytes:
    msg = EmailMessage()
    msg["From"] = "a@sender.example"
    msg["To"] = "Victim <victim@corp.example>"
    msg["Cc"] = "other@corp.example"
    msg["Subject"] = "Doc"
    msg["Message-ID"] = "<m1@sender.example>"
    msg.set_content("Please see attached.")
    for name, (data, maintype, subtype) in attachments.items():
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name.replace("_", "."))
    return msg.as_bytes()


def test_svg_and_html_attachments_and_smuggled_urls():
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
           b'<script>window.location.href = "https://evil.example/svg";</script>'
           b'<a xlink:href="https://evil.example/anchor"><text>Open</text></a></svg>')
    hidden = base64.b64encode(b"https://evil.example/smuggled").decode()
    html = f"<html><script>location = atob('{hidden}')</script></html>".encode()
    raw = _message(Invoice_svg=(svg, "image", "svg+xml"), Remit_html=(html, "text", "html"))
    meta, urls = extract_urls(raw)
    assert {"https://evil.example/svg", "https://evil.example/anchor",
            "https://evil.example/smuggled"} <= set(urls)
    assert not any("w3.org" in u for u in urls)
    assert meta["origins"]["https://evil.example/svg"] == "attachment:Invoice.svg"
    assert meta["origins"]["https://evil.example/smuggled"] == "attachment:Remit.html"
    assert meta["recipients"] == ["victim@corp.example", "other@corp.example"]


def test_attachments_can_be_turned_off():
    svg = b'<svg><script>location="https://evil.example/svg"</script></svg>'
    _, urls = extract_urls(_message(a_svg=(svg, "image", "svg+xml")), scan_attachments=False)
    assert urls == []


def test_calendar_and_pdf_attachments():
    ics = b"BEGIN:VCALENDAR\r\nDESCRIPTION:Join https://evil.example/meet\r\nEND:VCALENDAR\r\n"
    pdf = b"%PDF-1.4\n1 0 obj << /Type /Annot /A << /S /URI /URI (https://evil.example/pdf) >> >>\n"
    _, urls = extract_urls(_message(invite_ics=(ics, "text", "calendar"),
                                    scan_pdf=(pdf, "application", "pdf")))
    assert "https://evil.example/meet" in urls and "https://evil.example/pdf" in urls


def test_qr_code_in_image_attachment():
    qrcode = pytest.importorskip("qrcode")
    pytest.importorskip("zxingcpp")
    buf = io.BytesIO()
    qrcode.make("https://evil.example/qr").save(buf, format="PNG")
    meta, urls = extract_urls(_message(scan_png=(buf.getvalue(), "image", "png")))
    assert urls == ["https://evil.example/qr"]
    assert meta["origins"][urls[0]] == "qr:scan.png"


# --- config -------------------------------------------------------------------
def test_config_expands_env_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("LT_SECRET", "s3cret")
    path = tmp_path / "c.yaml"
    path.write_text("mimecast:\n  client_secret: ${LT_SECRET}\n  base_url: ${LT_BASE:-https://d}\n")
    cfg = Config.load(str(path))
    assert cfg.mimecast == {"client_secret": "s3cret", "base_url": "https://d"}
    path.write_text("webhook_url: ${LT_MISSING}\n")
    with pytest.raises(ValueError, match="LT_MISSING"):
        Config.load(str(path))


# --- RDAP ---------------------------------------------------------------------
def test_registration_age_parsing():
    from datetime import datetime, timezone
    now = datetime(2026, 11, 24, tzinfo=timezone.utc)
    payload = {"events": [{"eventAction": "last changed", "eventDate": "2026-11-23T00:00:00Z"},
                          {"eventAction": "registration", "eventDate": "2026-11-20T08:00:00Z"}]}
    assert enrich.registration_age_days(payload, now) == 3
    assert enrich.registration_age_days({}, now) is None


async def test_young_domain_signal(monkeypatch):
    async def fake_age(domain, client):
        return {"evil-login.com": 2}.get(domain, 4000)

    monkeypatch.setattr(enrich, "domain_age_days", fake_age)
    hops = [Hop(0, "https://share.old-files.com/", final_url="https://share.old-files.com/"),
            Hop(1, "https://login.evil-login.com/", final_url="https://login.evil-login.com/",
                has_password_field=True)]
    assert await enrich.age_signals(hops, Config()) == []  # off by default
    signals = await enrich.age_signals(hops, Config(rdap=True))
    assert [(s.name, s.detail) for s in signals] == [
        ("young_domain", "evil-login.com was registered 2 day(s) ago")]


# --- honeytoken -----------------------------------------------------------------
async def test_honeytoken_requires_a_seeded_canary():
    from luretrace.honeytoken import submit
    from luretrace.models import Verdict
    v = Verdict(url="https://x", original_url="https://x", label="malicious", score=90,
                complete=True, hops=[Hop(0, "https://x", has_password_field=True)])
    assert await submit(v, {"enabled": True}, Config()) is None  # no browser launched
