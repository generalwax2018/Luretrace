"""Live Mimecast URL decode. Needs API 2.0 client credentials and a real rewritten link.

Set MIMECAST_CLIENT_ID, MIMECAST_CLIENT_SECRET, and MIMECAST_TEST_URL (a mimecastprotect.com or
mimecast.com rewritten link). Asserts the link decodes to a different, real destination.
"""
import os

import pytest

pytestmark = pytest.mark.integration


def test_mimecast_decode():
    cid = os.environ.get("MIMECAST_CLIENT_ID")
    csec = os.environ.get("MIMECAST_CLIENT_SECRET")
    url = os.environ.get("MIMECAST_TEST_URL")
    if not (cid and csec and url):
        pytest.skip("set MIMECAST_CLIENT_ID/SECRET and MIMECAST_TEST_URL to run")

    from luretrace.unwrap import is_mimecast, unwrap

    assert is_mimecast(url), "MIMECAST_TEST_URL is not a recognised Mimecast rewrite"
    cfg = {"client_id": cid, "client_secret": csec}
    if os.environ.get("MIMECAST_BASE_URL"):
        cfg["base_url"] = os.environ["MIMECAST_BASE_URL"]

    decoded = unwrap(url, cfg)
    assert decoded and decoded != url, "expected the link to decode to its real destination"
    assert decoded.lower().startswith(("http://", "https://"))
