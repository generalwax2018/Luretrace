"""Mail sources. Each yields raw RFC 822 messages that have not been scanned yet.

The simplest deployment is provider-agnostic: add a transport/journal rule that copies
inbound external mail (or user-reported phish) to a dedicated mailbox, and point one of
these sources at it.
"""
from __future__ import annotations

import imaplib
from typing import Iterator

import httpx


class ImapSource:
    """Poll a mailbox over IMAPS and yield unseen messages, marking them seen."""

    def __init__(self, cfg: dict):
        self.host = cfg["host"]
        self.port = int(cfg.get("port", 993))
        self.user = cfg["username"]
        self.password = cfg["password"]
        self.folder = cfg.get("folder", "INBOX")

    def fetch(self) -> Iterator[bytes]:
        conn = imaplib.IMAP4_SSL(self.host, self.port)
        try:
            conn.login(self.user, self.password)
            conn.select(self.folder)
            _, data = conn.search(None, "UNSEEN")
            for num in data[0].split():
                _, parts = conn.fetch(num, "(RFC822)")
                if parts and parts[0]:
                    yield parts[0][1]
        finally:
            try:
                conn.logout()
            except Exception:
                pass


class GraphSource:
    """Poll a Microsoft 365 mailbox through Microsoft Graph (app-only auth).

    Needs an Entra app registration with the Mail.ReadWrite application permission,
    ideally scoped to the one mailbox with an application access policy.
    EXPERIMENTAL: written against the Graph v1.0 docs, not yet run against a live tenant.
    """

    def __init__(self, cfg: dict):
        self.tenant = cfg["tenant_id"]
        self.client_id = cfg["client_id"]
        self.secret = cfg["client_secret"]
        self.mailbox = cfg["mailbox"]
        self.base = cfg.get("base_url", "https://graph.microsoft.com/v1.0")
        self.login = cfg.get("login_url", "https://login.microsoftonline.com")

    def _token(self, client: httpx.Client) -> str:
        resp = client.post(
            f"{self.login}/{self.tenant}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def fetch(self) -> Iterator[bytes]:
        with httpx.Client(timeout=30) as client:
            headers = {"Authorization": f"Bearer {self._token(client)}"}
            root = f"{self.base}/users/{self.mailbox}"
            listing = client.get(
                f"{root}/mailFolders/inbox/messages",
                params={"$filter": "isRead eq false", "$select": "id", "$top": "25"},
                headers=headers,
            )
            listing.raise_for_status()
            for item in listing.json().get("value", []):
                mime = client.get(f"{root}/messages/{item['id']}/$value", headers=headers)
                if mime.status_code == 200:
                    yield mime.content
                    client.patch(
                        f"{root}/messages/{item['id']}", json={"isRead": True}, headers=headers
                    )


def build_source(cfg):
    if cfg.graph:
        return GraphSource(cfg.graph)
    if cfg.imap:
        return ImapSource(cfg.imap)
    raise SystemExit("No mail source configured: set `imap` or `graph` in the config file.")
