"""Hermetic coverage for the wiring that needs no network or browser:
CLI dispatch, mail-source selection, ingest-connector selection, and guard clauses.
"""
import pytest

from luretrace.config import Config


# --- CLI --------------------------------------------------------------------
def test_cli_rescan_empty_queue(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    from luretrace.cli import main
    assert main(["rescan"]) == 0
    assert "nothing due" in capsys.readouterr().out.lower()


def test_cli_url_private_is_skipped_without_browser(tmp_path, monkeypatch, capsys):
    # A non-public target returns "skipped" before any browser launches: exit code 0.
    monkeypatch.chdir(tmp_path)
    from luretrace.cli import main
    assert main(["url", "http://10.0.0.1/secret"]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_cli_requires_subcommand(capsys):
    from luretrace.cli import main
    with pytest.raises(SystemExit):
        main([])


# --- mail sources -----------------------------------------------------------
def test_build_source_selects_by_config():
    from luretrace.sources import GraphSource, ImapSource, build_source
    imap = build_source(Config(imap={"host": "h", "username": "u", "password": "p"}))
    assert isinstance(imap, ImapSource) and imap.host == "h"
    graph = build_source(Config(graph={
        "tenant_id": "t", "client_id": "c", "client_secret": "s", "mailbox": "m@x"}))
    assert isinstance(graph, GraphSource) and graph.mailbox == "m@x"


def test_build_source_errors_when_unconfigured():
    from luretrace.sources import build_source
    with pytest.raises(SystemExit):
        build_source(Config())


# --- ingest connectors ------------------------------------------------------
def test_build_connector_dispatch_and_items():
    from luretrace.simcheck import SIM_DOMAINS  # noqa: F401  (import smoke)
    from webapp.ingest import (DataLakeConnector, IngestItem, MimecastConnector,
                               build_connector)
    mc = build_connector("mimecast", {"client_id": "c", "client_secret": "s"})
    assert isinstance(mc, MimecastConnector) and mc.name == "mimecast"
    dl = build_connector("datalake", {"query_url": "https://q", "query": "select 1",
                                      "client_id": "c", "client_secret": "s", "token_url": "https://t"})
    assert isinstance(dl, DataLakeConnector) and dl.name == "datalake"
    item = IngestItem(url="https://x", source="datalake", gateway_verdict="passed")
    assert item.url == "https://x" and item.gateway_verdict == "passed"


def test_build_connector_rejects_unknown():
    from webapp.ingest import build_connector
    with pytest.raises(ValueError):
        build_connector("telepathy", {})


# --- action guards ----------------------------------------------------------
def test_graph_purge_guard_returns_false_without_config():
    from luretrace.actions import graph_purge
    assert graph_purge("", {}) is False
    assert graph_purge("<m@x>", {}) is False  # no tenant_id -> no network attempt
