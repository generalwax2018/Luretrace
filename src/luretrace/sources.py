"""Mail sources. Each yields raw RFC 822 messages that have not been scanned yet.

The simplest deployment is provider-agnostic: add a transport/journal rule that copies
inbound external mail (or user-reported phish) to a dedicated mailbox, and point one of
these sources at it.

Messages are yielded *unacknowledged*: they stay unread until the caller has scanned them and
calls `message.ack()`. A crash mid-scan therefore loses nothing; the message is fetched again on
the next poll. The caller bounds retries (Config.max_attempts) so one poison message cannot
block the mailbox forever.
"""
from __future__ import annotations

import imaplib
from typing import Callable, Iterator

import httpx


class Message(bytes):
    """Raw RFC 822 bytes plus a stable key and an ack() that marks the message processed."""

    key: str
    _ack: Callable[[], None]

    def __new__(cls, raw: bytes, key: str, ack: Callable[[], None]):
        obj = super().__new__(cls, raw)
        obj.key = key
        obj._ack = ack
        return obj

    def ack(self) -> None:
        self._ack()


class ImapSource:
    """Poll a mailbox over IMAPS and yield unseen messages; ack() sets \\Seen."""

    def __init__(self, cfg: dict):
        self.host = cfg["host"]
        self.port = int(cfg.get("port", 993))
        self.user = cfg["username"]
        self.password = cfg["password"]
        self.folder = cfg.get("folder", "INBOX")

    def fetch(self) -> Iterator[Message]:
        conn = imaplib.IMAP4_SSL(self.host, self.port)
        try:
            conn.login(self.user, self.password)
            conn.select(self.folder)
            _, data = conn.uid("SEARCH", None, "UNSEEN")
            for uid in data[0].split():
                # BODY.PEEK[] does not set \Seen: only a successful scan does (via ack).
                _, parts = conn.uid("FETCH", uid, "(BODY.PEEK[])")
                if parts and parts[0] and isinstance(parts[0], tuple):
                    def ack(u=uid):
                        conn.uid("STORE", u, "+FLAGS", "(\\Seen)")
                    yield Message(parts[0][1], f"imap:{self.folder}:{uid.decode()}", ack)
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

    def fetch(self) -> Iterator[Message]:
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
                    def ack(mid=item["id"]):
                        client.patch(f"{root}/messages/{mid}", json={"isRead": True},
                                     headers=headers)
                    yield Message(mime.content, f"graph:{item['id']}", ack)


def build_source(cfg):
    if cfg.graph:
        return GraphSource(cfg.graph)
    if cfg.imap:
        return ImapSource(cfg.imap)
    raise SystemExit("No mail source configured: set `imap` or `graph` in the config file.")
