"""Egress guard: a local forward proxy that every detonation browser connection goes through.

Why a proxy and not a Playwright route handler: route handlers only see the first URL of a
redirect chain, never see WebSocket traffic, and check a DNS answer that Chromium then looks up
again on its own (DNS rebinding). The proxy sees every HTTP request, CONNECT tunnel (HTTPS and
WebSockets) and redirect hop, resolves the name once, and connects to the address it checked.

With an upstream egress proxy configured, names that do not resolve locally are passed on and
the upstream's ACLs decide; literal and locally-resolvable private addresses are still refused.

This is defence in depth. It does not replace running the worker on an isolated network segment.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
from typing import Awaitable, Callable
from urllib.parse import unquote, urlsplit

from .netguard import classify_host, is_public_host, resolve_public

_HOP_HEADERS = {b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"}
# Plain-HTTP refusals reach the page as a normal response, so they carry a marker header the
# worker turns into a hop error (CONNECT refusals already surface as a tunnel failure).
BLOCK_HEADER = "x-luretrace-blocked"
_BLOCK_BODY = b"Blocked by the luretrace egress guard: non-public destination."
_FORBIDDEN = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
              + BLOCK_HEADER.encode() + b": 1\r\nContent-Length: "
              + str(len(_BLOCK_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + _BLOCK_BODY)
_BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BAD_REQUEST = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

# A checker returns the addresses to connect to, [] to let the upstream proxy connect, None to
# refuse (non-public: recorded as a probe), or UNRESOLVED (no usable DNS answer: the request
# fails like a DNS error and is NOT recorded as a probe).
UNRESOLVED = "unresolved"
Checker = Callable[[str], Awaitable["list[str] | str | None"]]


def browser_args() -> list[str]:
    """Chromium flags that keep every connection on the proxy path."""
    return [
        # WebRTC can open UDP straight to an address; keep it on the proxied path only.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        # Chromium must never resolve names itself: anything not sent to the proxy fails.
        '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1',
    ]


class GuardProxy:
    def __init__(self, upstream: str | None = None, on_block: Callable[[str], None] | None = None,
                 checker: Checker | None = None, connect_timeout: float = 20.0):
        self.upstream = urlsplit(upstream) if upstream else None
        if self.upstream and self.upstream.scheme != "http":
            raise ValueError("proxy must be an http:// egress proxy when the guard is on")
        self.on_block = on_block or (lambda target: None)
        self.checker = checker or self._default_check
        self.connect_timeout = connect_timeout
        self._server: asyncio.base_events.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task] = set()
        self._prev_handler = None
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def start(self) -> "GuardProxy":
        loop = asyncio.get_running_loop()
        self._prev_handler = loop.get_exception_handler()

        def quiet_resets(lp, context):
            # Windows' Proactor logs a traceback when it closes a socket the peer already reset
            # (hostile sites do this constantly). Harmless; keep it out of the operator's output.
            if isinstance(context.get("exception"), ConnectionResetError):
                return
            if self._prev_handler is not None:
                self._prev_handler(lp, context)
            else:
                lp.default_exception_handler(context)

        loop.set_exception_handler(quiet_resets)
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def close(self) -> None:
        """Stop listening and tear down every tunnel still open (keep-alive outlives the page)."""
        if self._server is None:
            return
        self._server.close()
        for w in list(self._writers):
            with contextlib.suppress(Exception):
                w.transport.abort()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        # Python 3.12+ wait_closed() waits for all connections; never let that hang the worker.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._server.wait_closed(), 5)
        self._server = None
        # Late transport callbacks still run after close; leave the filter on for this loop
        # only if nobody else had installed a handler, otherwise hand theirs back.
        if self._prev_handler is not None:
            asyncio.get_running_loop().set_exception_handler(self._prev_handler)

    async def __aenter__(self) -> "GuardProxy":
        return await self.start()

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def _default_check(self, host: str) -> list[str] | str | None:
        loop = asyncio.get_running_loop()
        if self.upstream:
            ok = await loop.run_in_executor(None, is_public_host, host, True)
            return [] if ok else None
        addrs = await loop.run_in_executor(None, resolve_public, host)
        if addrs is not None:
            return addrs
        kind = await loop.run_in_executor(None, classify_host, host)
        return UNRESOLVED if kind == "unresolved" else None

    def _upstream_auth(self) -> bytes:
        up = self.upstream
        if not up or not up.username:
            return b""
        creds = f"{unquote(up.username)}:{unquote(up.password or '')}".encode()
        return b"Proxy-Authorization: Basic " + base64.b64encode(creds) + b"\r\n"

    async def _open(self, addrs: list[str], port: int):
        if self.upstream:
            return await asyncio.wait_for(asyncio.open_connection(
                self.upstream.hostname, self.upstream.port or 8080), self.connect_timeout)
        last: Exception | None = None
        for addr in addrs:  # connect to the address that was checked, never re-resolve
            try:
                return await asyncio.wait_for(asyncio.open_connection(addr, port),
                                              self.connect_timeout)
            except Exception as exc:
                last = exc
        raise last or OSError("no address")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self._writers.add(writer)
        try:
            await self._serve(reader, writer, self._writers.add)
        except asyncio.CancelledError:
            pass
        finally:
            self._writers.discard(writer)
            if task is not None:
                self._tasks.discard(task)
            with contextlib.suppress(Exception):
                writer.close()

    async def _serve(self, reader, writer, track) -> None:
        upstream_writer = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except Exception:
                return
            line, _, header_block = head.partition(b"\r\n")
            try:
                method, target, version = line.decode("latin-1").split(" ", 2)
            except ValueError:
                writer.write(_BAD_REQUEST)
                return
            if method.upper() == "CONNECT":
                parts = urlsplit("//" + target)
                default_port = 443
            else:
                parts = urlsplit(target)
                default_port = 80
                if parts.scheme.lower() != "http":
                    writer.write(_BAD_REQUEST)
                    return
            host = (parts.hostname or "").strip("[]")
            try:
                port = parts.port or default_port
            except ValueError:
                writer.write(_BAD_REQUEST)
                return
            if not host:
                writer.write(_BAD_REQUEST)
                return

            addrs = await self.checker(host)
            if addrs == UNRESOLVED:
                writer.write(_BAD_GATEWAY)
                return
            if addrs is None:
                self.on_block(f"{host}:{port}")
                writer.write(_FORBIDDEN)
                return
            try:
                up_reader, upstream_writer = await self._open(addrs, port)
            except Exception:
                writer.write(_BAD_GATEWAY)
                return
            track(upstream_writer)

            if method.upper() == "CONNECT":
                if self.upstream:
                    upstream_writer.write(
                        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n".encode()
                        + self._upstream_auth() + b"\r\n")
                    await upstream_writer.drain()
                    reply = await asyncio.wait_for(up_reader.readuntil(b"\r\n\r\n"), 30)
                    if b" 200" not in reply.split(b"\r\n", 1)[0]:
                        writer.write(_BAD_GATEWAY)
                        return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                request_target = target if self.upstream else path
                headers = [h for h in header_block.split(b"\r\n") if h and
                           h.split(b":", 1)[0].strip().lower() not in _HOP_HEADERS]
                # One request per connection so a reused client connection cannot be steered
                # to a different, unchecked host.
                headers.append(b"Connection: close")
                out = f"{method} {request_target} {version}\r\n".encode("latin-1")
                out += b"\r\n".join(headers) + b"\r\n" + self._upstream_auth() + b"\r\n"
                upstream_writer.write(out)
                await upstream_writer.drain()

            await asyncio.gather(_pipe(reader, upstream_writer), _pipe(up_reader, writer))
        finally:
            if upstream_writer is not None:
                self._writers.discard(upstream_writer)
                with contextlib.suppress(Exception):
                    upstream_writer.close()


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


@contextlib.asynccontextmanager
async def egress(cfg, on_block: Callable[[str], None] | None = None):
    """Yield Playwright launch kwargs whose traffic is guarded (unless the guard is disabled)."""
    launch: dict = {"headless": True, "args": ["--disable-dev-shm-usage"]}
    if cfg.allow_private_networks:  # tests only
        if cfg.proxy:
            launch["proxy"] = {"server": cfg.proxy}
        yield launch
        return
    async with GuardProxy(upstream=cfg.proxy, on_block=on_block) as proxy:
        # Chromium sends loopback straight out unless told otherwise: "<-loopback>" removes
        # that implicit bypass so 127.0.0.1 / localhost / [::1] also go through the guard.
        launch["proxy"] = {"server": proxy.url, "bypass": "<-loopback>"}
        launch["args"] += browser_args()
        yield launch
