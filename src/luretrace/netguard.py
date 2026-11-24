"""SSRF guard: the detonation browser must never reach non-public addresses.

This is defence in depth. It does not replace running the worker on an isolated
network segment with its own egress. Enforcement happens in `guardproxy`, which
connects only to the addresses `resolve_public` returned (no second lookup).
Nothing here is cached: a cached "public" answer is exactly what DNS rebinding abuses.
"""
from __future__ import annotations

import ipaddress
import socket


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(ip.is_global) and not ip.is_multicast


def _literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def classify_host(host: str | None) -> str:
    """'public', 'private' (resolves to a non-public address), or 'unresolved'.

    'unresolved' is not 'private': a name with no usable records (NXDOMAIN, or only IPv6 on an
    IPv4-only host) is not an internal address, and treating it as one fakes a probe signal.
    """
    if not host:
        return "private"
    host = host.strip("[]")
    ip = _literal(host)
    if ip is not None:
        return "public" if _ip_is_public(ip) else "private"
    if host == "localhost" or host.endswith(".localhost") or "." not in host:
        return "private"  # single-label names are intranet names by definition
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except UnicodeError:
        return "private"
    except socket.gaierror:
        return "unresolved"
    addrs = {info[4][0].split("%")[0] for info in infos}
    if not addrs:
        return "unresolved"
    return "public" if all(_ip_is_public(ipaddress.ip_address(a)) for a in addrs) else "private"


def resolve_public(host: str | None) -> list[str] | None:
    """Resolve host and return its addresses if every one is public, else None."""
    if not host:
        return None
    host = host.strip("[]")
    ip = _literal(host)
    if ip is not None:
        return [str(ip)] if _ip_is_public(ip) else None
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (UnicodeError, socket.gaierror):
        return None
    addrs = list(dict.fromkeys(info[4][0].split("%")[0] for info in infos))
    if not addrs or not all(_ip_is_public(ipaddress.ip_address(a)) for a in addrs):
        return None
    return addrs


def is_public_host(host: str | None, unresolved_ok: bool = False) -> bool:
    """unresolved_ok: allow names that do not resolve locally (egress proxy does the DNS)."""
    if not host:
        return False
    host = host.strip("[]")
    ip = _literal(host)
    if ip is not None:
        return _ip_is_public(ip)
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except UnicodeError:
        return False
    except socket.gaierror:
        return unresolved_ok and "." in host and host != "localhost"
    addrs = {info[4][0].split("%")[0] for info in infos}
    return bool(addrs) and all(_ip_is_public(ipaddress.ip_address(a)) for a in addrs)
