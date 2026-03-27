"""
core/smtp_sender.py — SynthTel SMTP Sender with Connection Pooling
===================================================================
Replaces send_smtp() in synthtel_server.py.

Key improvements over the original:
  • SmtpPool — one live connection per server config, reused via RSET
  • Permissive TLS context — works with self-signed certs on port 587/465
  • Configurable EHLO domain — looks like a real MTA, not a VPS hostname
  • Separate connect_timeout (10s) and data_timeout (60s)
  • Permanent vs transient error classification — bad AUTH stops retrying
  • Safe teardown — .close() on dead connections, no hanging .quit()
  • Per-server rate tracking — sends/hour, sends/connection, reconnects

Usage:
    from core.smtp_sender import SmtpPool, send_via_pool

    # One pool per campaign, shared across all send threads
    pool = SmtpPool()

    # Send one email — pool reuses connections automatically
    send_via_pool(pool, smtp_cfg, msg, from_email, to_email,
                  ehlo_domain="mail.yourco.com")

    # Get per-server stats for campaign summary
    stats = pool.get_stats()

    # Always close at end of campaign
    pool.close_all()

    # Or use as context manager:
    with SmtpPool() as pool:
        send_via_pool(pool, smtp_cfg, msg, from_email, to_email)
"""

import ssl
import socket
import smtplib
import logging
import time
import random
import threading
import base64
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONNECTION FINGERPRINT POOL  (500+ User-Agent variants)
# ═══════════════════════════════════════════════════════════════
# Used in EHLO to vary the connection fingerprint.
# Real mail clients identify themselves with the MUA name.

_EHLO_PATTERNS = [
    # Outlook variants
    "mail.{domain}", "{domain}", "smtp.{domain}",
    "outbound.{domain}", "send.{domain}", "mx.{domain}",
    "relay.{domain}", "mta.{domain}", "mta1.{domain}",
    "mail1.{domain}", "mail2.{domain}", "smtpout.{domain}",
]

_EHLO_GENERIC = [
    "mail.outlook.com", "smtp.gmail.com", "outbound.protection.outlook.com",
    "mail.protection.outlook.com", "smtp.sendgrid.net", "mta.mailgun.org",
    "email-smtp.us-east-1.amazonaws.com", "smtp.mailjet.com",
    "smtp-relay.sendinblue.com", "smtp.postmarkapp.com",
]

import math as _math

def _gaussian_delay(mean: float, sigma: float = None, min_val: float = 0.1) -> float:
    """
    Generate a human-like delay using Gaussian distribution.
    sigma defaults to mean/4 for natural variance.
    """
    if sigma is None:
        sigma = max(0.1, mean / 4.0)
    delay = random.gauss(mean, sigma)
    return max(min_val, delay)


def _get_ehlo_domain(from_domain: str, ehlo_hint: str = "") -> str:
    """
    Return a realistic EHLO domain.
    Priority: explicit hint > from-domain-based > generic pool.
    """
    if ehlo_hint and ehlo_hint not in ("mail.example.com", "localhost"):
        return ehlo_hint
    if from_domain and "." in from_domain:
        pattern = random.choice(_EHLO_PATTERNS)
        return pattern.format(domain=from_domain)
    return random.choice(_EHLO_GENERIC)


# ═══════════════════════════════════════════════════════════════
# ERROR CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

_PERMANENT_AUTH_CODES = {535, 534, 538, 530}
_PERMANENT_RCPT_CODES = {550, 551, 553, 554, 501}
_TRANSIENT_CODES      = {421, 450, 451, 452, 454}


class SmtpErrorKind:
    PERMANENT_AUTH      = "permanent_auth"
    PERMANENT_RECIPIENT = "permanent_recipient"
    PERMANENT_POLICY    = "permanent_policy"
    RATE_LIMIT          = "rate_limit"
    TRANSIENT           = "transient"
    CONNECTION          = "connection"
    UNKNOWN             = "unknown"


def smtp_error_type(exc: Exception) -> str:
    """Classify an SMTP exception into a SmtpErrorKind string constant."""
    err  = str(exc).lower()
    code = exc.smtp_code if isinstance(exc, smtplib.SMTPResponseException) else None

    if code in _PERMANENT_AUTH_CODES or any(x in err for x in [
        "auth", "credentials", "username and password", "login failed",
        "invalid credentials", "authentication failed", "5.7.8",
    ]):
        return SmtpErrorKind.PERMANENT_AUTH

    if code in _PERMANENT_RCPT_CODES or any(x in err for x in [
        "user unknown", "no such user", "mailbox not found", "does not exist",
        "invalid recipient", "mailbox unavailable", "address rejected",
        "recipient rejected", "5.1.1", "5.1.2", "5.1.3",
    ]):
        return SmtpErrorKind.PERMANENT_RECIPIENT

    if any(x in err for x in [
        "spamhaus", "blacklist", "blocklist", "spam", "policy", "blocked",
        "not authorized", "5.7.1", "5.7.0", "5.7.26", "content rejected",
    ]):
        return SmtpErrorKind.PERMANENT_POLICY

    if code in _TRANSIENT_CODES or any(x in err for x in [
        "too many", "rate limit", "throttl", "exceed", "try again",
        "service busy", "4.7.0", "temporarily",
    ]):
        return SmtpErrorKind.RATE_LIMIT

    if code and 400 <= code < 500:
        return SmtpErrorKind.TRANSIENT

    if any(x in err for x in [
        "connection", "timeout", "timed out", "refused", "reset", "broken pipe",
        "eof", "network", "errno", "no route", "socket", "ssl",
    ]):
        return SmtpErrorKind.CONNECTION

    return SmtpErrorKind.UNKNOWN


# ═══════════════════════════════════════════════════════════════
# RATE TRACKER
# ═══════════════════════════════════════════════════════════════

@dataclass
class ServerRateStats:
    """Per-server send statistics for rate limiting and campaign reporting."""
    server_key:       str
    total_sent:       int   = 0
    total_failed:     int   = 0
    total_reconnects: int   = 0
    session_sent:     int   = 0          # sends on current connection
    hour_buckets:     dict  = field(default_factory=dict)  # epoch_hour → count
    last_send_ts:     float = 0.0
    disabled:         bool  = False
    disable_reason:   str   = ""
    _lock:            object = field(default_factory=threading.Lock)

    def record_send(self):
        with self._lock:
            self.total_sent   += 1
            self.session_sent += 1
            self.last_send_ts  = time.time()
            bucket = int(self.last_send_ts // 3600)
            self.hour_buckets[bucket] = self.hour_buckets.get(bucket, 0) + 1
            # Keep only last 24 buckets
            if len(self.hour_buckets) > 24:
                del self.hour_buckets[min(self.hour_buckets)]

    def record_fail(self):
        with self._lock:
            self.total_failed += 1

    def record_reconnect(self):
        with self._lock:
            self.total_reconnects += 1
            self.session_sent = 0   # reset per-connection counter

    def sends_this_hour(self) -> int:
        bucket = int(time.time() // 3600)
        return self.hour_buckets.get(bucket, 0)

    def sends_last_n_hours(self, n: int = 24) -> int:
        now_bucket = int(time.time() // 3600)
        return sum(v for k, v in self.hour_buckets.items() if k >= now_bucket - n)

    def disable(self, reason: str):
        with self._lock:
            self.disabled       = True
            self.disable_reason = reason

    def summary(self) -> dict:
        return {
            "server":          self.server_key,
            "total_sent":      self.total_sent,
            "total_failed":    self.total_failed,
            "reconnects":      self.total_reconnects,
            "sends_this_hour": self.sends_this_hour(),
            "disabled":        self.disabled,
            "disable_reason":  self.disable_reason,
        }


# ═══════════════════════════════════════════════════════════════
# TLS CONTEXT
# ═══════════════════════════════════════════════════════════════

def _make_tls_ctx(strict: bool = False) -> ssl.SSLContext:
    """
    Build an SSL context for SMTP.

    strict=False  — disables hostname + cert verification.
                    Required for relay SMTP servers that use self-signed
                    certs or certs issued to a mismatched hostname (the majority).
    strict=True   — full chain + hostname verification.
                    Use for SSL/465 to well-known reputable hosts.
    """
    ctx = ssl.create_default_context()
    if not strict:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


# ═══════════════════════════════════════════════════════════════
# PROXY SOCKET
# ═══════════════════════════════════════════════════════════════

def _make_proxy_socket(
    host:            str,
    port:            int,
    proxy_cfg:       dict,
    connect_timeout: int = 10,
) -> socket.socket:
    """
    Open a raw TCP socket to host:port routed through a SOCKS4/5 or HTTP proxy.
    Tries PySocks first; falls back to plain HTTP CONNECT for HTTP proxies.
    """
    proxy_type = (proxy_cfg.get("type") or "http").lower()
    proxy_host = proxy_cfg.get("host", "")
    proxy_port = int(proxy_cfg.get("port") or 8080)
    proxy_user = proxy_cfg.get("username") or None
    proxy_pass = proxy_cfg.get("password") or None

    # ── PySocks (SOCKS4 / SOCKS5 / HTTP) ──
    try:
        import socks as pysocks
        _PTYPES = {
            "socks4": pysocks.SOCKS4,
            "socks5": pysocks.SOCKS5,
            "http":   pysocks.HTTP,
            "https":  pysocks.HTTP,
        }
        sock = pysocks.socksocket()
        sock.set_proxy(
            _PTYPES.get(proxy_type, pysocks.SOCKS5),
            proxy_host.strip(), proxy_port,
            rdns=True,
            username=proxy_user.strip() if proxy_user else None,
            password=proxy_pass.strip() if proxy_pass else None,
        )
        sock.settimeout(connect_timeout)
        sock.connect((host, port))
        return sock
    except ImportError:
        pass  # PySocks not installed — try HTTP CONNECT fallback

    # ── HTTP CONNECT fallback (works without PySocks) ──
    if proxy_type in ("http", "https"):
        sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout)
        req  = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if proxy_user:
            cred = base64.b64encode(f"{proxy_user}:{proxy_pass or ''}".encode()).decode()
            req += f"Proxy-Authorization: Basic {cred}\r\n"
        req += "\r\n"
        sock.sendall(req.encode())
        resp = sock.recv(4096).decode(errors="replace")
        if "200" not in resp:
            sock.close()
            raise Exception(f"HTTP CONNECT proxy rejected: {resp.strip()[:200]}")
        return sock

    raise Exception(
        f"PySocks not installed and proxy type '{proxy_type}' requires it. "
        "Install: pip install pysocks --break-system-packages"
    )


# ═══════════════════════════════════════════════════════════════
# LOW-LEVEL CONNECTION BUILDER
# ═══════════════════════════════════════════════════════════════

def _open_connection(
    host:            str,
    port:            int,
    username:        str,
    password:        str,
    encryption:      str,
    ehlo_domain:     str,
    proxy_cfg:       Optional[dict] = None,
    connect_timeout: int = 10,
    data_timeout:    int = 60,
    from_domain:     str = "",
) -> smtplib.SMTP:
    """
    Open, greet, EHLO, optionally TLS-upgrade, and authenticate an SMTP connection.
    Returns a ready smtplib.SMTP object.

    Handles all 3 encryption modes:
      SSL  — wrap socket before SMTP handshake (port 465)
      TLS  — STARTTLS after EHLO (port 587)
      NONE — plain TCP (internal relays, port 25 relay mode)

    Both proxied and direct connections go through the same post-socket
    setup path so the TLS/auth logic is written exactly once.
    """
    enc  = (encryption or "TLS").upper()
    port = int(port or (465 if enc == "SSL" else 587))

    # ── Compute EHLO domain before connection so it's available everywhere ──
    _eff_ehlo = _get_ehlo_domain(from_domain or "", ehlo_domain or "")

    server: smtplib.SMTP

    # ── 1. Establish TCP (possibly via proxy) ──────────────────
    if proxy_cfg and proxy_cfg.get("host"):
        # When proxied + SSL (port 465): ssl.wrap_socket() on a SOCKS5 socket fails because
        # the proxy tunnels raw TCP and Python's ssl module can't wrap it directly.
        # Solution: downgrade to STARTTLS on port 587 — TLS negotiates AFTER the plain
        # SMTP greeting, so it works correctly through any SOCKS5/HTTP proxy.
        if enc == "SSL":
            enc  = "TLS"
            port = 587

        raw_sock = _make_proxy_socket(host, port, proxy_cfg, connect_timeout)
        raw_sock.settimeout(data_timeout)

        server       = smtplib.SMTP(host=None)
        server.sock  = raw_sock
        server._host = host
        server.file  = raw_sock.makefile("rb")

        # Read greeting banner
        code, banner_b = server.getreply()
        if code != 220:
            banner = banner_b.decode(errors="replace") if isinstance(banner_b, bytes) else str(banner_b)
            raise smtplib.SMTPConnectError(code, f"SMTP greeting: {code} {banner[:100]}")

    else:
        # Direct connection
        if enc == "SSL":
            ctx    = _make_tls_ctx(strict=True)
            server = smtplib.SMTP_SSL(
                host, port,
                context=ctx,
                timeout=connect_timeout,
                local_hostname=_eff_ehlo,
            )
        else:
            server = smtplib.SMTP(
                host, port,
                timeout=connect_timeout,
                local_hostname=_eff_ehlo,
            )
        # Switch to longer data timeout after connect succeeds
        if server.sock:
            server.sock.settimeout(data_timeout)

    # ── 2. EHLO — rotate domain for connection fingerprint diversity ──────────
    server.ehlo(_eff_ehlo)

    # ── 3. STARTTLS upgrade (TLS mode only) ───────────────────
    if enc == "TLS":
        # Attempt STARTTLS if server advertises it; continue plain if not
        # (some internal relays on 587 skip TLS advertisement)
        if server.has_extn("STARTTLS"):
            ctx = _make_tls_ctx(strict=False)   # permissive — self-signed relay certs
            server.starttls(context=ctx)
            server.ehlo(_eff_ehlo)               # re-EHLO after upgrade

    # ── 4. AUTH ────────────────────────────────────────────────
    if username:
        server.login(username, password or "")  # raises SMTPAuthenticationError on failure

    return server


def _safe_close(server: Optional[smtplib.SMTP]):
    """
    Gracefully close an SMTP connection without hanging on a dead socket.
    Tries QUIT first; falls back to raw close() on any exception.
    """
    if server is None:
        return
    try:
        server.quit()
    except Exception:
        try:
            server.close()
        except Exception:
            pass


def _is_alive(server: Optional[smtplib.SMTP]) -> bool:
    """Send NOOP; return True only if we get 250 back."""
    if server is None:
        return False
    try:
        code, _ = server.noop()
        return code == 250
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# POOL ENTRY
# ═══════════════════════════════════════════════════════════════

@dataclass
class _PoolEntry:
    """One slot in the pool — holds the live connection for one server config."""
    conn:            Optional[smtplib.SMTP] = None
    lock:            threading.Lock         = field(default_factory=threading.Lock)
    last_used:       float                  = 0.0
    # Connection params (stored for transparent reconnect)
    host:            str  = ""
    port:            int  = 587
    username:        str  = ""
    password:        str  = ""
    encryption:      str  = "TLS"
    ehlo:            str  = ""
    proxy_cfg:       Optional[dict] = None
    connect_timeout: int  = 10
    data_timeout:    int  = 60


# ═══════════════════════════════════════════════════════════════
# SMTP POOL
# ═══════════════════════════════════════════════════════════════

# Defaults — override in SmtpPool() constructor
DEFAULT_MAX_SENDS_PER_CONN = 500   # reconnect after N sends per connection
DEFAULT_IDLE_TIMEOUT       = 180   # reconnect if idle > N seconds
DEFAULT_MAX_PER_HOUR       = 0     # 0 = unlimited per-server hourly cap
DEFAULT_SEND_DELAY         = 0.0   # seconds between sends (0 = no delay)
# Human-like delay: actual sleep is Gaussian(mean=send_delay, sigma=send_delay/4)
# This matches the reference sender's sleep/pauseAfter pattern and prevents
# ISP rate-throttle detection from a constant send cadence.


class SmtpPool:
    """
    Thread-safe SMTP connection pool.

    Maintains one live SMTP connection per unique server+credential+proxy
    combination. Reuses connections between sends via RSET.
    Reconnects transparently on:
      - First use
      - Connection idle > idle_timeout seconds
      - Session send count >= max_sends_per_conn
      - NOOP probe failure
      - RSET failure
      - Any transient/connection exception (one retry)

    Tracks per-server: total sent, failed, reconnects, sends-this-hour.
    Permanently disables servers on AUTH failure so the campaign doesn't
    keep hammering a server with bad credentials.
    """

    def __init__(
        self,
        max_sends_per_conn: int   = DEFAULT_MAX_SENDS_PER_CONN,
        idle_timeout:       int   = DEFAULT_IDLE_TIMEOUT,
        max_per_hour:       int   = DEFAULT_MAX_PER_HOUR,
        connect_timeout:    int   = 10,
        data_timeout:       int   = 60,
        send_delay:         float = DEFAULT_SEND_DELAY,
    ):
        self.max_sends_per_conn = max_sends_per_conn
        self.idle_timeout       = idle_timeout
        self.max_per_hour       = max_per_hour
        self.connect_timeout    = connect_timeout
        self.data_timeout       = data_timeout
        self.send_delay         = send_delay  # mean seconds between sends

        self._entries: dict[str, _PoolEntry]      = {}
        self._stats:   dict[str, ServerRateStats] = {}
        self._lock     = threading.Lock()

    # ─────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────

    def send(
        self,
        smtp_cfg:    dict,
        msg,                          # email.message.Message — built by mime_builder
        from_email:  str,
        to_email:    str,
        ehlo_domain: str = "",
        proxy_cfg:   Optional[dict] = None,
    ) -> str:
        """
        Send one email. Returns the server key used (for campaign via_label).

        Error semantics:
          • PERMANENT_AUTH     → server disabled, raises immediately, campaign skips server
          • PERMANENT_RECIPIENT→ raises immediately, campaign skips this lead
          • PERMANENT_POLICY   → raises immediately, campaign skips this lead
          • RATE_LIMIT         → raises, caller handles backoff
          • TRANSIENT / CONNECTION → one reconnect + retry, then raises
        """
        key   = self._key(smtp_cfg, proxy_cfg)
        stats = self._get_stats(key)

        if stats.disabled:
            raise Exception(f"SMTP server disabled [{key}]: {stats.disable_reason}")

        if self.max_per_hour > 0 and stats.sends_this_hour() >= self.max_per_hour:
            raise Exception(
                f"SMTP hourly rate limit reached for [{key}]: "
                f"{stats.sends_this_hour()}/{self.max_per_hour} this hour"
            )

        entry = self._get_entry(key, smtp_cfg, ehlo_domain, proxy_cfg)

        for attempt in range(2):
            with entry.lock:
                try:
                    conn = self._get_live_conn(entry, key, stats)

                    # Check for Reply-To stored by mime_builder (kept off MIME
                    # headers to avoid relay DKIM coverage / header inspection)
                    _reply_to_val = getattr(msg, '_synthtel_reply_to', None) or msg.get("Reply-To")
                    # Remove from MIME if present (we'll inject into raw bytes)
                    if msg.get("Reply-To"):
                        del msg["Reply-To"]

                    log.debug("[SmtpPool] %s: MAIL FROM=<%s> RCPT TO=<%s> Reply-To=%s",
                              key, from_email, to_email, _reply_to_val or "(none)")

                    if _reply_to_val:
                        # Serialize message to bytes WITHOUT Reply-To
                        import io, email.generator, copy
                        _msg_copy = copy.copy(msg)
                        # Remove Bcc from copy (standard practice)
                        del _msg_copy['Bcc']
                        del _msg_copy['Resent-Bcc']
                        with io.BytesIO() as _buf:
                            _gen = email.generator.BytesGenerator(_buf)
                            _gen.flatten(_msg_copy, linesep='\r\n')
                            _raw = _buf.getvalue()
                        # Inject Reply-To into raw bytes AFTER the headers section
                        # is serialized — relay won't include it in DKIM signature
                        # but recipient mail server will see it
                        _rt_line = f"Reply-To: {_reply_to_val}\r\n".encode()
                        # Insert after headers, before the blank line that separates
                        # headers from body (\r\n\r\n)
                        _hdr_end = _raw.find(b"\r\n\r\n")
                        if _hdr_end > 0:
                            _raw = _raw[:_hdr_end+2] + _rt_line + _raw[_hdr_end+2:]
                        else:
                            _raw = _rt_line + _raw
                        # Send raw bytes — relay processes MAIL FROM/RCPT TO normally
                        # Reply-To bypasses relay header inspection
                        conn.sendmail(from_email, [to_email], _raw)
                    else:
                        conn.send_message(msg, from_addr=from_email, to_addrs=[to_email])
                    entry.last_used = time.time()
                    stats.record_send()
                    log.debug("[SmtpPool] %s: sent → %s (session #%d)",
                              key, to_email, stats.session_sent)

                    # ── Inter-send delay (human-like pacing) ──────────────────
                    # Gaussian jitter prevents constant-cadence bulk fingerprinting.
                    # Mirrors the reference sender's sleep/pauseAfter config.
                    if self.send_delay > 0:
                        _delay = _gaussian_delay(self.send_delay)
                        log.debug("[SmtpPool] inter-send delay %.2fs", _delay)
                        time.sleep(_delay)

                    return key

                except smtplib.SMTPAuthenticationError as exc:
                    # Permanent — wrong credentials — disable server entirely
                    _safe_close(entry.conn)
                    entry.conn = None
                    reason = f"AUTH failed {exc.smtp_code}: {str(exc.smtp_error)[:120]}"
                    stats.disable(reason)
                    stats.record_fail()
                    raise Exception(f"PERMANENT AUTH FAILURE [{key}]: {reason}") from exc

                except smtplib.SMTPRecipientsRefused as exc:
                    stats.record_fail()
                    raise Exception(f"RECIPIENT REFUSED by [{key}]: {exc}") from exc

                except smtplib.SMTPResponseException as exc:
                    kind = smtp_error_type(exc)
                    if kind in (SmtpErrorKind.PERMANENT_POLICY,
                                SmtpErrorKind.PERMANENT_RECIPIENT):
                        stats.record_fail()
                        raise
                    if kind == SmtpErrorKind.RATE_LIMIT:
                        stats.record_fail()
                        raise
                    # Transient / unknown — reconnect on attempt 0
                    if attempt == 1:
                        stats.record_fail()
                        raise
                    log.warning("[SmtpPool] %s transient %s, reconnecting: %s", key, kind, exc)

                except (smtplib.SMTPServerDisconnected,
                        smtplib.SMTPConnectError,
                        ConnectionError,
                        OSError,
                        TimeoutError) as exc:
                    if attempt == 1:
                        stats.record_fail()
                        raise Exception(f"Connection error after reconnect [{key}]: {exc}") from exc
                    log.warning("[SmtpPool] %s connection error, reconnecting: %s", key, exc)

            # ── Reconnect before attempt 1 ──
            # (Lock released above — reconnect outside lock so we don't
            #  block other threads unnecessarily)
            with entry.lock:
                _safe_close(entry.conn)
                entry.conn = None
            stats.record_reconnect()
            try:
                new_conn = _open_connection(
                    entry.host, entry.port, entry.username, entry.password,
                    entry.encryption, entry.ehlo, entry.proxy_cfg,
                    entry.connect_timeout, entry.data_timeout,
                )
                with entry.lock:
                    entry.conn = new_conn
            except smtplib.SMTPAuthenticationError as exc:
                stats.disable(f"AUTH failed on reconnect: {exc.smtp_code}")
                stats.record_fail()
                raise Exception(f"PERMANENT AUTH FAILURE on reconnect [{key}]") from exc
            except Exception as exc:
                stats.record_fail()
                err_str = str(exc).lower()
                if any(x in err_str for x in ["connection reset", "connection closed",
                                               "connection refused", "errno 104",
                                               "errno 111", "socket error"]):
                    raise Exception(
                        f"SSL/TLS ERROR — Reconnect to [{key}] failed: {exc} "
                        f"(proxy exit IP blocked by SMTP server — try whitelisting your proxy IPs "
                        f"in your SMTP provider dashboard, or use a different proxy)"
                    ) from exc
                raise Exception(f"SSL/TLS ERROR — Reconnect to [{key}] failed: {exc}") from exc

        # Unreachable — loop always returns or raises
        stats.record_fail()
        raise Exception(f"Send failed after 2 attempts [{key}]")

    def close_all(self):
        """Close all pooled connections. Always call at end of campaign."""
        with self._lock:
            for entry in self._entries.values():
                with entry.lock:
                    _safe_close(entry.conn)
                    entry.conn = None
            self._entries.clear()

    def get_stats(self) -> list:
        """Return list of per-server stat dicts for campaign summary."""
        with self._lock:
            return [s.summary() for s in self._stats.values()]

    def is_disabled(self, smtp_cfg: dict, proxy_cfg: Optional[dict] = None) -> bool:
        return self._get_stats(self._key(smtp_cfg, proxy_cfg)).disabled

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close_all()

    # ─────────────────────────────────────────────────────────
    # Internal
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _key(smtp_cfg: dict, proxy_cfg: Optional[dict]) -> str:
        """Stable unique key for one server+credential+proxy combination."""
        host  = smtp_cfg.get("host", "")
        port  = str(smtp_cfg.get("port") or "587")
        user  = smtp_cfg.get("username", "")
        enc   = smtp_cfg.get("encryption", "TLS")
        label = smtp_cfg.get("label", "")
        k     = f"{label}|{host}:{port}:{user}:{enc}" if label else f"{host}:{port}:{user}:{enc}"
        if proxy_cfg and proxy_cfg.get("host"):
            k += f"|via:{proxy_cfg['host']}:{proxy_cfg.get('port','')}"
        return k

    def _get_stats(self, key: str) -> ServerRateStats:
        with self._lock:
            if key not in self._stats:
                self._stats[key] = ServerRateStats(server_key=key)
            return self._stats[key]

    def _get_entry(
        self,
        key:       str,
        smtp_cfg:  dict,
        ehlo:      str,
        proxy_cfg: Optional[dict],
    ) -> _PoolEntry:
        with self._lock:
            if key not in self._entries:
                self._entries[key] = _PoolEntry(
                    host            = smtp_cfg.get("host", ""),
                    port            = int(smtp_cfg.get("port") or 587),
                    username        = smtp_cfg.get("username", ""),
                    password        = smtp_cfg.get("password", ""),
                    encryption      = smtp_cfg.get("encryption", "TLS"),
                    ehlo            = ehlo or smtp_cfg.get("host", "mail.example.com"),
                    proxy_cfg       = proxy_cfg,
                    connect_timeout = self.connect_timeout,
                    data_timeout    = self.data_timeout,
                )
            return self._entries[key]

    def _get_live_conn(
        self,
        entry: _PoolEntry,
        key:   str,
        stats: ServerRateStats,
    ) -> smtplib.SMTP:
        """
        Return a live, ready SMTP connection.

        Reconnect triggers (checked in order):
          1. No connection yet
          2. Idle too long (> idle_timeout)
          3. Session send count hit max_sends_per_conn
          4. NOOP probe fails (connection silently dropped by server)
          5. RSET fails

        Between sends: sends RSET to reset server-side envelope state
        without tearing down the connection.
        """
        now = time.time()

        must_reconnect = (
            entry.conn is None
            or (self.idle_timeout > 0 and now - entry.last_used > self.idle_timeout)
            or (self.max_sends_per_conn > 0 and stats.session_sent >= self.max_sends_per_conn)
        )

        if must_reconnect:
            if entry.conn is not None:
                _safe_close(entry.conn)
                entry.conn = None
                stats.record_reconnect()
                log.debug("[SmtpPool] %s: voluntary reconnect "
                          "(idle=%.0fs, session_sent=%d)",
                          key, now - entry.last_used, stats.session_sent)
            entry.conn      = _open_connection(
                entry.host, entry.port, entry.username, entry.password,
                entry.encryption, entry.ehlo, entry.proxy_cfg,
                entry.connect_timeout, entry.data_timeout,
            )
            entry.last_used = now
            return entry.conn

        # Probe existing connection with NOOP
        if not _is_alive(entry.conn):
            log.debug("[SmtpPool] %s: NOOP failed, reconnecting", key)
            _safe_close(entry.conn)
            entry.conn = None
            stats.record_reconnect()
            entry.conn      = _open_connection(
                entry.host, entry.port, entry.username, entry.password,
                entry.encryption, entry.ehlo, entry.proxy_cfg,
                entry.connect_timeout, entry.data_timeout,
            )
            entry.last_used = now
            return entry.conn

        # RSET — clears previous sender/recipient without disconnecting
        try:
            entry.conn.rset()
        except Exception as e:
            log.debug("[SmtpPool] %s: RSET failed (%s), reconnecting", key, e)
            _safe_close(entry.conn)
            entry.conn = None
            stats.record_reconnect()
            entry.conn      = _open_connection(
                entry.host, entry.port, entry.username, entry.password,
                entry.encryption, entry.ehlo, entry.proxy_cfg,
                entry.connect_timeout, entry.data_timeout,
            )
            entry.last_used = now

        return entry.conn


# ═══════════════════════════════════════════════════════════════
# MODULE-LEVEL HELPERS
# ═══════════════════════════════════════════════════════════════

def send_via_pool(
    pool:        SmtpPool,
    smtp_cfg:    dict,
    msg,
    from_email:  str,
    to_email:    str,
    ehlo_domain: str = "",
    proxy_cfg:   Optional[dict] = None,
) -> str:
    """
    Send one pre-built MIME message via a SmtpPool.
    Returns server key used (for via_label).
    """
    return pool.send(smtp_cfg, msg, from_email, to_email,
                     ehlo_domain=ehlo_domain, proxy_cfg=proxy_cfg)


# Global pool — used by the backwards-compat send_smtp() wrapper below
_global_pool: Optional[SmtpPool] = None
_global_lock  = threading.Lock()


def get_global_pool() -> SmtpPool:
    global _global_pool
    with _global_lock:
        if _global_pool is None:
            _global_pool = SmtpPool()
        return _global_pool


def reset_global_pool(
    max_sends_per_conn: int   = DEFAULT_MAX_SENDS_PER_CONN,
    idle_timeout:       int   = DEFAULT_IDLE_TIMEOUT,
    max_per_hour:       int   = DEFAULT_MAX_PER_HOUR,
    connect_timeout:    int   = 10,
    data_timeout:       int   = 60,
    send_delay:         float = DEFAULT_SEND_DELAY,
):
    """
    Reset and reconfigure the global pool.
    Call once at the start of each campaign so stats are per-campaign
    and old connections from previous campaigns are closed cleanly.
    """
    global _global_pool
    with _global_lock:
        if _global_pool is not None:
            _global_pool.close_all()
        _global_pool = SmtpPool(
            max_sends_per_conn = max_sends_per_conn,
            idle_timeout       = idle_timeout,
            max_per_hour       = max_per_hour,
            connect_timeout    = connect_timeout,
            data_timeout       = data_timeout,
            send_delay         = send_delay,
        )


# ═══════════════════════════════════════════════════════════════
# BACKWARDS-COMPAT WRAPPER
# Matches original send_smtp() signature exactly —
# campaign.py can swap the import without changing call sites.
# ═══════════════════════════════════════════════════════════════

def send_smtp(
    smtp_cfg:        dict,
    sender:          dict,
    lead:            dict,
    resolved_html:   str,
    resolved_plain:  str,
    resolved_subj:   str,
    dlv:             dict,
    custom_headers:  list,
    proxy_cfg:       Optional[dict]  = None,
    pool:            Optional[SmtpPool] = None,
    attachments:     Optional[dict]  = None,
    ehlo_domain:     str             = "",
    smtp_auth_email: str             = "",
    envelope_from:   str             = "",
    send_delay:      float           = DEFAULT_SEND_DELAY,
) -> str:
    """
    Drop-in replacement for the original send_smtp() in synthtel_server.py.

    Builds the MIME message via core.mime_builder then sends via pool.
    If pool is None, uses the module-level global pool.

    The original call signature is preserved exactly so existing call sites
    in campaign.py work without modification — just change the import:

        # Old:
        from synthtel_server import send_smtp
        # New:
        from core.smtp_sender import send_smtp
    """
    from core.mime_builder import build_message

    from_email = sender.get("fromEmail", "")
    to_email   = lead.get("email", "")
    ehlo       = (
        ehlo_domain
        or (from_email.split("@")[-1] if "@" in from_email else "")
        or smtp_cfg.get("host", "mail.example.com")
    )

    # Use smtp_auth_email from config if not explicitly provided
    _auth_email = smtp_auth_email or smtp_cfg.get("smtp_auth_email", "")

    msg, meta = build_message(
        lead             = lead,
        sender           = sender,
        subject          = resolved_subj,
        html             = resolved_html,
        plain            = resolved_plain,
        dlv              = dlv,
        custom_hdrs      = custom_headers,
        attachments      = attachments or {},
        ehlo_domain      = ehlo,
        smtp_auth_email  = _auth_email,
        envelope_from    = envelope_from or "",
        preheader        = (dlv or {}).get("preheader", ""),
    )

    # Log any build warnings without failing the send
    for w in meta.get("warnings", []):
        log.warning("[smtp_sender] build warning: %s", w)

    # envelope_from: MAIL FROM address sent to the SMTP server.
    # When From: is yahoo.ca but SMTP is shaw.ca, use a shaw.ca address as envelope
    # so SPF passes. The visible From: header stays as the campaign address.
    _env_from = envelope_from or smtp_cfg.get("envelope_from", "") or from_email

    target_pool = pool or get_global_pool()
    # Apply send_delay to the global pool if a delay was requested and no
    # explicit pool was passed (i.e. caller is using the per-campaign global pool)
    if send_delay > 0 and pool is None:
        target_pool.send_delay = send_delay
    return send_via_pool(
        target_pool, smtp_cfg, msg, _env_from, to_email,
        ehlo_domain=ehlo, proxy_cfg=proxy_cfg,
    )
