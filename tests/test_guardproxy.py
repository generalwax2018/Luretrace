"""Egress guard proxy: hermetic tests over raw sockets (no browser needed)."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from luretrace.guardproxy import BLOCK_HEADER, GuardProxy
from luretrace.netguard import resolve_public


@pytest.fixture
def origin():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            hits.append(self.path)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], hits
    server.shutdown()


async def allow_localhost_only(host):
    # "localhost" plays the public site; the literal 127.0.0.1 plays the internal target.
    return ["127.0.0.1"] if host == "localhost" else None


async def _exchange(proxy_port, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(payload)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 10)  # proxy forces Connection: close -> EOF
    writer.close()
    return data


async def test_plain_http_allowed_and_blocked(origin):
    port, hits = origin
    blocked = []
    async with GuardProxy(checker=allow_localhost_only, on_block=blocked.append) as proxy:
        ok = await _exchange(proxy.port, f"GET http://localhost:{port}/ok HTTP/1.1\r\n"
                                         f"Host: localhost:{port}\r\n\r\n".encode())
        assert ok.startswith(b"HTTP/1.1 200") and ok.endswith(b"ok")
        denied = await _exchange(proxy.port, f"GET http://127.0.0.1:{port}/secret HTTP/1.1\r\n"
                                             f"Host: 127.0.0.1:{port}\r\n\r\n".encode())
    assert denied.startswith(b"HTTP/1.1 403") and BLOCK_HEADER.encode() in denied.lower()
    assert hits == ["/ok"]
    assert blocked == [f"127.0.0.1:{port}"]


async def test_connect_tunnel_allowed_and_blocked(origin):
    port, hits = origin
    async with GuardProxy(checker=allow_localhost_only) as proxy:
        denied = await _exchange(proxy.port, f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n".encode())
        assert denied.startswith(b"HTTP/1.1 403")

        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        assert (await reader.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
        writer.write("GET /tunnel HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 10)
        writer.close()
    assert reply.startswith(b"HTTP/1.1 200") and hits == ["/tunnel"]


async def test_chains_to_upstream_proxy(origin):
    port, hits = origin

    async def defer(host):
        return []  # let the upstream decide

    async with GuardProxy(checker=allow_localhost_only) as upstream:
        async with GuardProxy(upstream=upstream.url, checker=defer) as front:
            ok = await _exchange(front.port, f"GET http://localhost:{port}/via HTTP/1.1\r\n"
                                             f"Host: localhost:{port}\r\n\r\n".encode())
            denied = await _exchange(front.port, f"GET http://127.0.0.1:{port}/no HTTP/1.1\r\n"
                                                 f"Host: 127.0.0.1\r\n\r\n".encode())
    assert ok.startswith(b"HTTP/1.1 200") and denied.startswith(b"HTTP/1.1 403")
    assert hits == ["/via"]


async def test_unresolvable_names_fail_without_counting_as_probes(origin):
    from luretrace.guardproxy import UNRESOLVED
    port, hits = origin
    blocked = []

    async def nothing_resolves(host):
        return UNRESOLVED

    async with GuardProxy(checker=nothing_resolves, on_block=blocked.append) as proxy:
        reply = await _exchange(proxy.port, b"CONNECT v6only.example.com:443 HTTP/1.1\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 502")
    assert blocked == []  # a DNS failure is not an internal-address probe


def test_classify_host():
    from luretrace.netguard import classify_host
    assert classify_host("10.0.0.1") == "private"
    assert classify_host("intranet") == "private"
    assert classify_host("localhost") == "private"
    assert classify_host("8.8.8.8") == "public"
    assert classify_host("name-that-will-not-resolve.invalid") == "unresolved"


def test_only_http_upstream_is_accepted():
    with pytest.raises(ValueError):
        GuardProxy(upstream="socks5://proxy:1080")


def test_resolve_public_refuses_private():
    for host in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "localhost", "", None):
        assert resolve_public(host) is None, host
    assert resolve_public("8.8.8.8") == ["8.8.8.8"]
