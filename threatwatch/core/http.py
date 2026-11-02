"""Shared outbound HTTP client factory."""

from __future__ import annotations

import httpx

from ..config import get_settings


def client(
    *,
    timeout: float | None = None,
    tor: bool = False,
    verify: bool = True,
    follow_redirects: bool = True,
    headers: dict | None = None,
) -> httpx.AsyncClient:
    """Return an AsyncClient with the platform User-Agent, timeouts and proxy settings applied.

    ``tor=True`` routes through ``TW_TOR_PROXY`` (required for .onion sources).
    """
    s = get_settings()
    proxy = s.tor_proxy if tor else s.http_proxy
    if tor and proxy and proxy.startswith("socks5://"):
        # socks5h-equivalent: let the proxy resolve .onion names
        proxy = "socks5h://" + proxy[len("socks5://") :]
    h = {"User-Agent": s.user_agent, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout or s.http_timeout, connect=min(10.0, timeout or s.http_timeout)),
        headers=h,
        proxy=proxy or None,
        verify=verify,
        follow_redirects=follow_redirects,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )
