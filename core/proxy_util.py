"""
core/proxy_util.py — Shared proxy plumbing for HTTP-based senders.

Used by core.api_sender, core.owa_sender, core.crm_sender so the
campaign loop can route SendGrid / Mailgun / OWA / CRM webhook calls
through the same SOCKS5 / HTTP proxy pool that core.smtp_sender already
honours via PySocks.

Design notes
------------
* HTTP / HTTPS proxies are wired in via urllib.request.ProxyHandler —
  no extra deps required.
* SOCKS5 / SOCKS4 proxies require PySocks (already a runtime
  dependency of core.smtp_sender). When PySocks isn't importable we
  raise a RuntimeError with a clear message so the caller can surface
  it; we do NOT silently bypass the proxy (would leak the VPS IP).
* Every call returns a fresh opener — no shared state between
  concurrent sends.

Usage
-----
    from core.proxy_util import proxied_urlopen
    resp = proxied_urlopen(req, proxy_cfg=proxy_cfg, timeout=30)

`proxy_cfg` is the same dict shape produced by
core.campaign.CampaignOptions._build_proxy_cfg() — keys: type, host,
port, username, password.
"""

from __future__ import annotations

import logging
import urllib.request
from typing import Optional

log = logging.getLogger("synthtel.proxy_util")


def _esc(v: str) -> str:
    """URL-encode the userinfo portion of a proxy URL."""
    from urllib.parse import quote
    return quote(str(v or ""), safe="")


def build_opener(proxy_cfg: Optional[dict]) -> urllib.request.OpenerDirector:
    """Return a urllib opener configured for the given proxy.

    If ``proxy_cfg`` is None / empty / has no host, returns a plain
    direct opener (same behaviour as urllib.request.build_opener()).

    Supported proxy types: ``http``, ``https``, ``socks4``, ``socks5``.
    SOCKS proxies require PySocks; if missing, RuntimeError is raised
    (we do NOT silently fall back to direct — that would leak the VPS
    IP, which is the whole reason the user configured a proxy).
    """
    if not proxy_cfg or not isinstance(proxy_cfg, dict) or not proxy_cfg.get("host"):
        return urllib.request.build_opener()

    ptype = (proxy_cfg.get("type") or "http").lower().strip()
    host  = str(proxy_cfg["host"]).strip()
    try:
        port = int(proxy_cfg.get("port") or 0)
    except Exception:
        port = 0
    if not port:
        raise RuntimeError(f"proxy_util: missing port for proxy {host!r}")

    user = proxy_cfg.get("username") or ""
    pw   = proxy_cfg.get("password") or ""
    auth = f"{_esc(user)}:{_esc(pw)}@" if (user or pw) else ""

    # ── HTTP / HTTPS via stdlib ─────────────────────────────────
    if ptype in ("http", "https"):
        url = f"{ptype}://{auth}{host}:{port}"
        ph  = urllib.request.ProxyHandler({"http": url, "https": url})
        opener = urllib.request.build_opener(ph)
        return opener

    # ── SOCKS via PySocks ───────────────────────────────────────
    if ptype in ("socks4", "socks5"):
        try:
            import socks  # PySocks
        except ImportError as exc:
            raise RuntimeError(
                "SOCKS proxy requires PySocks — "
                "run `pip install pysocks --break-system-packages`"
            ) from exc

        # Prefer the official handler from sockshandler if it's installed
        # (PySocks ships it in the contrib subpackage on most distros).
        try:
            from sockshandler import SocksiPyHandler  # type: ignore
            level = socks.SOCKS5 if ptype == "socks5" else socks.SOCKS4
            h = SocksiPyHandler(
                level, host, port,
                username=user or None,
                password=pw or None,
            )
            return urllib.request.build_opener(h)
        except ImportError:
            # Fall back to a small inline subclass that does the same job.
            return urllib.request.build_opener(
                _make_inline_socks_handler(ptype, host, port, user, pw)
            )

    raise RuntimeError(f"proxy_util: unsupported proxy type {ptype!r}")


def proxied_urlopen(req, *, proxy_cfg: Optional[dict] = None,
                     timeout: float = 30):
    """Drop-in replacement for ``urllib.request.urlopen()`` with optional proxy.

    Behaviour is identical to ``urlopen()`` when ``proxy_cfg`` is empty.
    Otherwise the request is routed through the configured proxy.
    """
    return build_opener(proxy_cfg).open(req, timeout=timeout)


# ── Inline SOCKS handler fallback (used when sockshandler missing) ────────

def _make_inline_socks_handler(ptype: str, host: str, port: int,
                                user: str, pw: str):
    """Return a urllib.request.HTTPHandler subclass that opens its
    underlying socket through PySocks. Works for both http:// and
    https:// requests (we install the same class for HTTPSHandler too).
    """
    import http.client as _httplib
    import ssl as _ssl
    import socks as _socks

    level = _socks.SOCKS5 if ptype == "socks5" else _socks.SOCKS4

    class _SocksHTTPConn(_httplib.HTTPConnection):
        def connect(self):
            s = _socks.socksocket()
            s.set_proxy(level, host, port,
                        username=user or None,
                        password=pw or None)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            self.sock = s

    class _SocksHTTPSConn(_httplib.HTTPSConnection):
        def connect(self):
            s = _socks.socksocket()
            s.set_proxy(level, host, port,
                        username=user or None,
                        password=pw or None)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            ctx = self._context or _ssl.create_default_context()
            self.sock = ctx.wrap_socket(s, server_hostname=self.host)

    class _Handler(urllib.request.HTTPSHandler, urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_SocksHTTPConn, req)
        def https_open(self, req):
            return self.do_open(_SocksHTTPSConn, req)

    return _Handler()
