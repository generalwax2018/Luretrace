"""SSRF guard: the detonation browser must never reach non-public addresses.

This is defence in depth. It does not replace running the worker on an isolated
network segment with its own egress.
"""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global) and not ip.is_multicast


@lru_cache(maxsize=4096)
def is_public_host(host: str | None, unresolved_ok: bool = False) -> bool:
    """unresolved_ok: allow names that do not resolve locally (egress proxy does the DNS)."""
    if not host:
        return False
    host = host.strip("[]")
    try:
        return _ip_is_public(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except UnicodeError:
        return False
    except socket.gaierror:
        return unresolved_ok and "." in host and host != "localhost"
    addrs = {info[4][0].split("%")[0] for info in infos}
    return bool(addrs) and all(_ip_is_public(ipaddress.ip_address(a)) for a in addrs)
