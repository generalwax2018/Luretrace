"""Live Microsoft Graph mail source. Needs an app registration with Mail.ReadWrite.

This hits the real tenant: it authenticates and lists unread messages in the mailbox. It does not
modify anything except marking fetched messages read (Graph's default for this flow), so point it
at a dedicated test mailbox.
"""
import os

import pytest

pytestmark = pytest.mark.integration

REQUIRED = ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "GRAPH_MAILBOX")


def _cfg_or_skip():
    env = {k: os.environ.get(k) for k in REQUIRED}
    if not all(env.values()):
        pytest.skip("set GRAPH_TENANT_ID/CLIENT_ID/CLIENT_SECRET/MAILBOX to run")
    return {
        "tenant_id": env["GRAPH_TENANT_ID"],
        "client_id": env["GRAPH_CLIENT_ID"],
        "client_secret": env["GRAPH_CLIENT_SECRET"],
        "mailbox": env["GRAPH_MAILBOX"],
    }


def test_graph_auth_and_fetch_smoke():
    from luretrace.sources import GraphSource

    src = GraphSource(_cfg_or_skip())
    # Should authenticate and return an iterable of raw messages (possibly empty) without error.
    messages = list(src.fetch())
    assert isinstance(messages, list)
    for raw in messages:
        assert isinstance(raw, (bytes, bytearray))
