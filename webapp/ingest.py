"""Ingest connectors: pull links to check from the places your org already keeps them.

At work you rarely want to point luretrace at a raw mailbox. The URLs (and the gateway's
own pass/fail on them) usually already land in a data lake or SIEM, or can be pulled from
Mimecast's API. A connector's job is narrow: yield (url, context) pairs for the pipeline to
detonate. The GUI then shows which passed and, for the failed ones, the full forensics.

Each connector implements `fetch() -> Iterable[IngestItem]`. Auth is OAuth2 client-credentials
by default (what most enterprise data lakes and Mimecast API 2.0 use). These are seams with
working request shapes written to published docs; wire your tenant's specifics and validate
before relying on them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol

import httpx


@dataclass
class IngestItem:
    url: str
    source: str                      # "mimecast", "datalake", ...
    message_id: str | None = None
    recipient: str | None = None
    gateway_verdict: str | None = None  # what the upstream control already decided, if known
    context: dict = field(default_factory=dict)


class Connector(Protocol):
    name: str

    def fetch(self) -> Iterable[IngestItem]: ...


def _oauth_token(cfg: dict) -> str:
    """OAuth2 client-credentials token. Works for Mimecast API 2.0 and most data lakes."""
    with httpx.Client(timeout=30) as client:
        data = {
            "grant_type": "client_credentials",
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
        }
        if cfg.get("scope"):
            data["scope"] = cfg["scope"]
        resp = client.post(cfg["token_url"], data=data)
        resp.raise_for_status()
        return resp.json()["access_token"]


class MimecastConnector:
    """Pull click/URL logs from Mimecast and queue their targets.

    Uses Mimecast API 2.0 (OAuth2 client-credentials). The TTP URL logs endpoint returns
    clicked/scanned URLs with the gateway's own scan result, which we carry as
    gateway_verdict so the GUI can show "Mimecast passed it, we failed it".
    EXPERIMENTAL: endpoint/field names follow Mimecast's published API 2.0 docs.
    """

    name = "mimecast"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.base = cfg.get("base_url", "https://api.services.mimecast.com")
        self.token_url = cfg.setdefault("token_url", f"{self.base}/oauth/token")

    def fetch(self) -> Iterable[IngestItem]:
        token = _oauth_token(self.cfg)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        body = {"meta": {"pagination": {"pageSize": self.cfg.get("page_size", 100)}},
                "data": [{"scanResult": "all"}]}
        with httpx.Client(timeout=60) as client:
            resp = client.post(f"{self.base}/api/ttp/url/get-logs", headers=headers, json=body)
            resp.raise_for_status()
            payload = resp.json()
        for block in payload.get("data", []):
            for click in block.get("clickLogs", []):
                url = click.get("url")
                if not url:
                    continue
                yield IngestItem(
                    url=url, source=self.name,
                    recipient=click.get("userEmailAddress"),
                    gateway_verdict=click.get("scanResult"),
                    context={"action": click.get("action"), "category": click.get("category")},
                )


class DataLakeConnector:
    """Pull URL events from a data lake / SIEM over an OAuth2-protected query API.

    Vendor-neutral: you provide a query endpoint that returns rows, and a small mapping of
    which fields hold the URL, message id, recipient, and (optionally) the upstream verdict.
    Works with anything exposing an OAuth2 + JSON query endpoint (Snowflake SQL API, Databricks
    SQL, Azure Data Explorer, Elastic, a custom gateway). Configure, don't code.
    """

    name = "datalake"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.query_url = cfg["query_url"]
        self.query = cfg["query"]                    # SQL/KQL/DSL your endpoint expects
        self.map = cfg.get("field_map", {
            "url": "url", "message_id": "message_id",
            "recipient": "recipient", "gateway_verdict": "gateway_verdict",
        })

    def fetch(self) -> Iterable[IngestItem]:
        token = _oauth_token(self.cfg)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        with httpx.Client(timeout=120) as client:
            resp = client.post(self.query_url, headers=headers,
                               json={self.cfg.get("query_field", "query"): self.query})
            resp.raise_for_status()
            payload = resp.json()
        rows = payload.get(self.cfg.get("rows_field", "rows"), payload.get("data", []))
        for row in rows:
            get = row.get if isinstance(row, dict) else (lambda k: None)
            url = get(self.map["url"])
            if not url:
                continue
            yield IngestItem(
                url=url, source=self.name,
                message_id=get(self.map.get("message_id", "")),
                recipient=get(self.map.get("recipient", "")),
                gateway_verdict=get(self.map.get("gateway_verdict", "")),
            )


CONNECTORS = {"mimecast": MimecastConnector, "datalake": DataLakeConnector}


def build_connector(kind: str, cfg: dict) -> Connector:
    if kind not in CONNECTORS:
        raise ValueError(f"Unknown connector '{kind}'. Known: {sorted(CONNECTORS)}")
    return CONNECTORS[kind](cfg)
