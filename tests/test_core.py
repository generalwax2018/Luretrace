from luretrace.chain import is_file_share, pick_next
from luretrace.domains import in_domains, registrable
from luretrace.extract import extract_urls, refang
from luretrace.models import Hop
from luretrace.netguard import is_public_host
from luretrace.signals import evaluate, label_for, total
from luretrace.unwrap import unwrap


# --- unwrap -----------------------------------------------------------------
def test_safelinks():
    wrapped = (
        "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fdoc"
        "&data=05%7C01&sdata=abc&reserved=0"
    )
    assert unwrap(wrapped) == "https://evil.example/doc"


def test_proofpoint_v2():
    wrapped = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_a_b-3Fx-3D1&d=Dw&c=x"
    assert unwrap(wrapped) == "https://evil.example/a/b?x=1"


def test_proofpoint_v3_plain_and_tokens():
    assert unwrap("https://urldefense.com/v3/__https://evil.example/path__;!!AbC!xyz$") == (
        "https://evil.example/path"
    )
    # "Iw" is base64 for "#": the * token is replaced by the next decoded character.
    assert unwrap("https://urldefense.com/v3/__https://evil.example/a*frag__;Iw!!AbC!xyz$") == (
        "https://evil.example/a#frag"
    )


def test_nested_layers_and_passthrough():
    inner = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_x&d=Dw"
    from urllib.parse import quote

    outer = f"https://eur01.safelinks.protection.outlook.com/?url={quote(inner, safe='')}&data=1"
    assert unwrap(outer) == "https://evil.example/x"
    assert unwrap("https://example.com/plain") == "https://example.com/plain"


# --- extract ----------------------------------------------------------------
EML = b"""From: a@example.com
To: b@example.com
Subject: Shared file
Message-ID: <abc@example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="x"

--x
Content-Type: text/plain; charset="utf-8"

Open hxxps://contoso-my.sharepoint[.]com/:b:/g/personal/doc now.
--x
Content-Type: text/html; charset="utf-8"

<html><body><a href="https://contoso-my.sharepoint.com/:b:/g/personal/doc">View</a>
<a href="mailto:x@example.com">mail</a>
<a href="https://second.example/x">Other</a></body></html>
--x--
"""


def test_extract_dedupes_and_refangs():
    meta, urls = extract_urls(EML)
    assert meta["message_id"] == "<abc@example.com>"
    assert urls == [
        "https://contoso-my.sharepoint.com/:b:/g/personal/doc",
        "https://second.example/x",
    ]
    assert refang("hxxp://a[.]b/c") == "http://a.b/c"


# --- domains / guard --------------------------------------------------------
def test_registrable_and_membership():
    assert registrable("https://login.evil.co.uk/x") == "evil.co.uk"
    assert in_domains("https://a.b.sharepoint.com/x", {"sharepoint.com"})
    assert not in_domains("https://sharepoint.com.evil.example/", {"sharepoint.com"})


def test_netguard_blocks_non_public():
    for host in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "::1",
                 "::ffff:10.0.0.1", "100.64.0.1", "localhost", "", None):
        assert not is_public_host(host), host
    assert is_public_host("8.8.8.8")
    assert is_public_host("2606:4700:4700::1111")


# --- chain ------------------------------------------------------------------
def test_pick_next_prefers_lure_link_and_skips_boilerplate():
    links = [
        {"href": "https://www.microsoft.com/privacy", "text": "Privacy"},
        {"href": "https://contoso.sharepoint.com/other", "text": "View all"},
        {"href": "https://ad.example/banner", "text": "Sponsored"},
        {"href": "https://evil.example/login", "text": "View Document"},
    ]
    nxt = pick_next(links, "https://contoso.sharepoint.com/doc", set())
    assert nxt["href"] == "https://evil.example/login"
    assert pick_next(links[:2], "https://contoso.sharepoint.com/doc", set()) is None
    assert is_file_share("https://contoso-my.sharepoint.com/x")


# --- signals ----------------------------------------------------------------
def _aitm_chain():
    lure = Hop(0, "https://contoso-my.sharepoint.com/:b:/doc",
               final_url="https://contoso-my.sharepoint.com/:b:/doc", title="Invoice.pdf")
    phish = Hop(1, "https://login.evil.example/", final_url="https://login.evil.example/common",
                title="Sign in to your account", has_email_field=True, has_password_field=True,
                resource_hosts=["aadcdn.msauth.net", "login.evil.example"],
                followed_link_text="View Document")
    return [lure, phish]


def test_aitm_chain_is_malicious():
    signals = evaluate(_aitm_chain(), complete=True)
    names = {s.name for s in signals}
    assert {"brand_login_off_domain", "fileshare_lure_to_login"} <= names
    assert label_for(total(signals)) == "malicious"


def test_real_microsoft_login_is_clean():
    hop = Hop(0, "https://login.microsoftonline.com/",
              final_url="https://login.microsoftonline.com/common/oauth2/authorize",
              title="Sign in to your account", has_email_field=True,
              resource_hosts=["aadcdn.msauth.net", "login.microsoftonline.com"])
    assert label_for(total(evaluate([hop], complete=True))) == "clean"


def test_trusted_idp_is_not_flagged():
    hop = Hop(0, "https://sso.corp.example/", final_url="https://sso.corp.example/adfs/ls",
              title="Sign in to your account", has_password_field=True, has_email_field=True)
    assert label_for(total(evaluate([hop], True, ["sso.corp.example"]))) == "clean"
    assert label_for(total(evaluate([hop], True))) != "clean"


def test_incomplete_chain_is_never_clean():
    gate = Hop(0, "https://x.example/", final_url="https://x.example/", captcha="Cloudflare Turnstile")
    signals = evaluate([gate], complete=False)
    assert label_for(total(signals)) == "suspicious"
    assert label_for(total(evaluate([], complete=False))) == "suspicious"


def test_plain_page_is_clean():
    hop = Hop(0, "https://example.org/", final_url="https://example.org/", title="Example")
    assert total(evaluate([hop], complete=True)) == 0


def test_netguard_proxy_mode_still_blocks_literals():
    assert not is_public_host("10.0.0.5", True)
    assert not is_public_host("localhost", True)
    assert is_public_host("name-that-will-not-resolve.invalid", True)
    assert not is_public_host("name-that-will-not-resolve.invalid")
