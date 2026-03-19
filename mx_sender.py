"""
core/mx_sender.py — SynthTel Direct-to-MX Sender
==================================================
Replaces send_direct_mx() in synthtel_server.py.

Improvements over the original:
  • MxCache  — TTL-based MX record cache, one DNS lookup per domain
               across the entire campaign (not per email)
  • DomainRateTracker — per-domain and per-MX-host send counters with
               hourly buckets, greylisting detection + retry delay,
               and Microsoft/strict-domain throttle aware
  • Robust SOCKS5 error messages preserved from original (all 4 error codes)
  • Opportunistic STARTTLS with permissive context (same fix as smtp_sender)
  • Separate connect (10s) and data (60s) timeouts
  • Greylisting auto-retry — waits configured seconds then retries same MX
  • Per-domain consecutive failure tracking — skips domain after N failures
  • Clean separation: resolve_mx() → connect_mx() → send_direct_mx()
  • Drop-in send_direct_mx() wrapper matches original call signature

Usage:
    from core.mx_sender import MxSenderContext, send_direct_mx

    # One context per campaign — holds the cache and rate tracker
    ctx = MxSenderContext()

    # Send one email
    mx_used = send_direct_mx(
        lead_email       = "john@acme.com",
        sender           = sender_dict,
        msg              = mime_message,       # built by mime_builder
        ehlo_domain      = "mail.yourco.com",
        socks_proxy      = None,
        ctx              = ctx,
    )

    # Get rate stats for campaign summary
    stats = ctx.get_stats()
    ctx.close()
"""

import ssl
import socket
import smtplib
import logging
import time
import threading
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ── dnspython auto-install (mirrors original behaviour) ──────────
try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "dnspython",
             "--break-system-packages", "-q"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=60,
        )
        import dns.resolver
        _HAS_DNSPYTHON = True
    except Exception:
        _HAS_DNSPYTHON = False


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

# Domains that rate-limit aggressively — require extra inter-send delay
STRICT_DOMAINS = frozenset({
    "gmail.com", "googlemail.com",
    "yahoo.com", "ymail.com", "yahoo.co.uk", "yahoo.ca",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "outlook.com", "outlook.co.uk",
    "live.com", "live.ca",
    "msn.com",
    "icloud.com", "me.com", "mac.com",
    "aol.com",
})

# Microsoft domains that hit rate limits especially hard
MS_DOMAINS = frozenset({
    "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "outlook.com", "outlook.co.uk",
    "live.com", "live.ca",
    "msn.com",
})

# Error substrings that indicate greylisting (temporary deferral)
_GREYLIST_SIGNALS = (
    "greylisted", "greylist", "temporarily deferred",
    "try again later", "4.2.0", "421 4.7.0",
    "please try again", "come back later",
)

# Error substrings that mean the MX server is temporarily unavailable
# (try next MX priority, not a fatal failure)
_MX_TRANSIENT_SIGNALS = (
    "connection refused", "connection reset", "timed out", "timeout",
    "no route", "network unreachable", "errno 111", "errno 110",
    "service unavailable", "421",
)

# Error substrings that are permanent for THIS recipient — don't try next MX
_RCPT_PERMANENT_SIGNALS = (
    "user unknown", "no such user", "mailbox not found", "does not exist",
    "invalid recipient", "mailbox unavailable", "5.1.1", "5.1.2", "550",
    "551", "553", "address rejected",
)

# MX record TTL — cache for 30 minutes (most MX records are stable for hours)
MX_CACHE_TTL = 1800

# After this many consecutive failures for a domain, skip MX lookup
# MS/strict domains get a higher threshold since they're flaky with residential IPs
MAX_CONSECUTIVE_DOMAIN_FAILURES = 25

# Greylist retry delay (seconds) — wait then retry the same MX host
GREYLIST_RETRY_DELAY = 60

# Default inter-send delay for strict/MS domains when no explicit throttle set
STRICT_DOMAIN_MIN_DELAY = 3.0  # seconds between sends to same domain
MS_DOMAIN_MIN_DELAY     = 5.0


# ═══════════════════════════════════════════════════════════════
# MX RECORD CACHE
# ═══════════════════════════════════════════════════════════════

@dataclass
class _MxEntry:
    records:    list        # [(priority, host), ...]
    fetched_at: float       # time.time() when cached
    error:      str = ""    # if resolution failed, reason stored here


class MxCache:
    """
    Thread-safe TTL cache for MX records.
    Resolves each domain at most once per TTL window for the whole campaign.

    resolve(domain) → list of (priority, host) sorted by priority
    Raises Exception if domain has no MX and no A fallback.
    """

    def __init__(self, ttl: int = MX_CACHE_TTL):
        self._ttl     = ttl
        self._entries: dict[str, _MxEntry] = {}
        self._lock    = threading.Lock()
        # Stats
        self.hits     = 0
        self.misses   = 0

    def resolve(self, domain: str) -> list:
        domain = domain.strip().lower()
        with self._lock:
            entry = self._entries.get(domain)
            now   = time.time()
            if entry and (now - entry.fetched_at) < self._ttl:
                self.hits += 1
                if entry.error:
                    raise Exception(entry.error)
                return list(entry.records)

        # Cache miss — resolve outside lock so other threads aren't blocked
        self.misses += 1
        try:
            records = _resolve_mx_all_methods(domain)
            with self._lock:
                self._entries[domain] = _MxEntry(records=records, fetched_at=time.time())
            return list(records)
        except Exception as exc:
            msg = str(exc)
            with self._lock:
                # Cache the failure for TTL/4 — avoids hammering DNS on dead domains
                self._entries[domain] = _MxEntry(
                    records=[], fetched_at=time.time() - self._ttl * 0.75, error=msg,
                )
            raise

    def invalidate(self, domain: str):
        """Force re-resolution of a domain on next request."""
        with self._lock:
            self._entries.pop(domain.strip().lower(), None)

    def stats(self) -> dict:
        return {
            "cached_domains": len(self._entries),
            "cache_hits":     self.hits,
            "cache_misses":   self.misses,
            "hit_rate":       f"{100*self.hits/max(1,self.hits+self.misses):.1f}%",
        }


# ═══════════════════════════════════════════════════════════════
# DOMAIN RATE TRACKER
# ═══════════════════════════════════════════════════════════════

@dataclass
class _DomainStats:
    domain:              str
    total_sent:          int   = 0
    total_failed:        int   = 0
    greylisted_count:    int   = 0
    consecutive_fails:   int   = 0
    hour_buckets:        dict  = field(default_factory=dict)
    last_send_ts:        float = 0.0
    disabled:            bool  = False
    disable_reason:      str   = ""
    _lock:               object = field(default_factory=threading.Lock)

    def record_send(self):
        with self._lock:
            self.total_sent       += 1
            self.consecutive_fails = 0
            self.last_send_ts      = time.time()
            b = int(self.last_send_ts // 3600)
            self.hour_buckets[b]   = self.hour_buckets.get(b, 0) + 1
            if len(self.hour_buckets) > 24:
                del self.hour_buckets[min(self.hour_buckets)]

    def record_fail(self):
        with self._lock:
            self.total_failed      += 1
            self.consecutive_fails += 1

    def record_greylist(self):
        with self._lock:
            self.greylisted_count += 1

    def sends_this_hour(self) -> int:
        b = int(time.time() // 3600)
        return self.hour_buckets.get(b, 0)

    def seconds_since_last_send(self) -> float:
        return time.time() - self.last_send_ts if self.last_send_ts else 9999.0

    def disable(self, reason: str):
        with self._lock:
            self.disabled       = True
            self.disable_reason = reason

    def summary(self) -> dict:
        return {
            "domain":           self.domain,
            "total_sent":       self.total_sent,
            "total_failed":     self.total_failed,
            "greylisted":       self.greylisted_count,
            "sends_this_hour":  self.sends_this_hour(),
            "disabled":         self.disabled,
            "disable_reason":   self.disable_reason,
        }


class DomainRateTracker:
    """
    Per-recipient-domain rate tracking.

    Tracks:
      - Sends and failures per domain
      - Hourly send buckets (for per-domain rate limits)
      - Consecutive failure count (disables dead domains)
      - Greylisting detections
      - Minimum inter-send delay for strict/MS domains

    call_allowed(domain) → bool  — check before sending
    record_send(domain)
    record_fail(domain, error_str)
    enforce_delay(domain)        — sleep if needed before sending
    """

    def __init__(
        self,
        max_consecutive_failures: int   = MAX_CONSECUTIVE_DOMAIN_FAILURES,
        strict_delay:             float = STRICT_DOMAIN_MIN_DELAY,
        ms_delay:                 float = MS_DOMAIN_MIN_DELAY,
        max_per_hour:             int   = 0,   # 0 = unlimited
    ):
        self.max_consecutive_failures = max_consecutive_failures
        self.strict_delay             = strict_delay
        self.ms_delay                 = ms_delay
        self.max_per_hour             = max_per_hour

        self._domains: dict[str, _DomainStats] = {}
        self._lock = threading.Lock()

    def _get(self, domain: str) -> _DomainStats:
        domain = domain.lower()
        with self._lock:
            if domain not in self._domains:
                self._domains[domain] = _DomainStats(domain=domain)
            return self._domains[domain]

    def is_allowed(self, domain: str) -> tuple:
        """Return (allowed: bool, reason: str)."""
        stats = self._get(domain)
        if stats.disabled:
            return False, f"domain disabled: {stats.disable_reason}"
        if self.max_per_hour > 0 and stats.sends_this_hour() >= self.max_per_hour:
            return False, f"hourly limit {self.max_per_hour} reached for {domain}"
        return True, ""

    def enforce_delay(self, domain: str):
        """Sleep the minimum required delay for this domain if needed."""
        stats = self._get(domain)
        elapsed = stats.seconds_since_last_send()
        if domain in MS_DOMAINS:
            needed = self.ms_delay
        elif domain in STRICT_DOMAINS:
            needed = self.strict_delay
        else:
            return
        gap = needed - elapsed
        if gap > 0:
            log.debug("[MxSender] %s: domain throttle — sleeping %.1fs", domain, gap)
            time.sleep(gap)

    def record_send(self, domain: str):
        self._get(domain).record_send()

    def record_fail(self, domain: str, error: str = ""):
        stats = self._get(domain)
        stats.record_fail()
        if stats.consecutive_fails >= self.max_consecutive_failures:
            stats.disable(f">{self.max_consecutive_failures} consecutive failures")
            log.warning("[MxSender] %s disabled after %d consecutive failures",
                        domain, self.max_consecutive_failures)

    def record_greylist(self, domain: str):
        self._get(domain).record_greylist()

    def get_all_stats(self) -> list:
        with self._lock:
            return [s.summary() for s in self._domains.values()]


# ═══════════════════════════════════════════════════════════════
# MX RESOLUTION — all methods, identical to original
# ═══════════════════════════════════════════════════════════════

def _resolve_mx_all_methods(domain: str) -> list:
    """
    Resolve MX records for domain using 5 methods in priority order.
    Returns [(priority, host), ...] sorted ascending by priority.
    Raises Exception if all methods fail.

    Methods:
      1. dnspython (system resolver, then explicit 8.8.8.8/1.1.1.1)
      2. dig subprocess
      3. host subprocess
      4. nslookup subprocess
      5. A record fallback (domain itself as mail host)
    """
    # ── Method 1: dnspython ─────────────────────────────────
    if _HAS_DNSPYTHON:
        for attempt in range(2):
            try:
                if attempt == 0:
                    resolver = dns.resolver.Resolver()
                else:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "208.67.222.222"]
                resolver.timeout  = 10
                resolver.lifetime = 15
                answers = resolver.resolve(domain, "MX")
                mx = [(int(r.preference), str(r.exchange).rstrip(".")) for r in answers]
                if mx:
                    return sorted(mx)
            except dns.resolver.NXDOMAIN:
                raise Exception(f"Domain {domain} does not exist (NXDOMAIN)")
            except dns.resolver.NoAnswer:
                break       # no MX records — fall through to A record fallback
            except dns.resolver.NoNameservers:
                if attempt == 0:
                    continue
                break
            except Exception as exc:
                name = type(exc).__name__
                if "NoResolverConfiguration" in name or "no nameservers" in str(exc).lower():
                    if attempt == 0:
                        continue
                break

    # ── Method 2: dig ──────────────────────────────────────
    try:
        r = subprocess.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            mx = []
            for line in r.stdout.strip().split("\n"):
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        mx.append((int(parts[0]), parts[1].rstrip(".")))
                    except ValueError:
                        pass
            if mx:
                return sorted(mx)
    except Exception:
        pass

    # ── Method 3: host ─────────────────────────────────────
    try:
        r = subprocess.run(
            ["host", "-t", "MX", domain],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            mx = []
            for line in r.stdout.split("\n"):
                if "mail is handled by" in line:
                    parts = line.split("mail is handled by")
                    if len(parts) == 2:
                        ph = parts[1].strip().split(None, 1)
                        if len(ph) == 2:
                            try:
                                mx.append((int(ph[0]), ph[1].rstrip(".")))
                            except ValueError:
                                pass
            if mx:
                return sorted(mx)
    except Exception:
        pass

    # ── Method 4: nslookup ─────────────────────────────────
    try:
        r = subprocess.run(
            ["nslookup", "-type=mx", domain],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            mx = []
            for line in r.stdout.split("\n"):
                if "mail exchanger" in line.lower():
                    parts = line.split("=")
                    if len(parts) == 2:
                        ph = parts[1].strip().split(None, 1)
                        if len(ph) == 2:
                            try:
                                mx.append((int(ph[0]), ph[1].rstrip(".")))
                            except ValueError:
                                pass
            if mx:
                return sorted(mx)
    except Exception:
        pass

    # ── Method 5: A record fallback ────────────────────────
    if _HAS_DNSPYTHON:
        for attempt in range(2):
            try:
                if attempt == 0:
                    resolver = dns.resolver.Resolver()
                else:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
                resolver.timeout  = 10
                resolver.lifetime = 15
                answers = resolver.resolve(domain, "A")
                if answers:
                    return [(10, domain)]   # domain itself accepts mail
            except Exception:
                if attempt == 0:
                    continue
                break

    raise Exception(f"Could not resolve MX records for {domain}")


# ═══════════════════════════════════════════════════════════════
# SOCKS5 SOCKET — with detailed error mapping
# ═══════════════════════════════════════════════════════════════

def _make_socks5_socket(
    mx_host:         str,
    proxy_cfg:       dict,
    connect_timeout: int = 10,
) -> socket.socket:
    """
    Create a raw TCP socket connected to mx_host:25 via SOCKS5 proxy.
    All 4 SOCKS5 error codes translated to actionable messages (preserved
    verbatim from the original send_direct_mx).
    """
    proxy_host = proxy_cfg.get("host", "127.0.0.1")
    proxy_port = int(proxy_cfg.get("port") or 1080)
    proxy_user = proxy_cfg.get("username") or None
    proxy_pass = proxy_cfg.get("password") or None

    try:
        import socks as pysocks
    except ImportError:
        raise Exception(
            "PySocks not installed — required for SOCKS5 proxy.\n"
            "Install with: pip install pysocks --break-system-packages"
        )

    sock = pysocks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    sock.set_proxy(
        pysocks.SOCKS5, proxy_host, proxy_port,
        username=proxy_user, password=proxy_pass,
    )
    sock.settimeout(connect_timeout)

    try:
        sock.connect((mx_host, 25))
        return sock

    except pysocks.SOCKS5Error as exc:
        s = str(exc)
        if "0x02" in s or "not allowed by ruleset" in s.lower():
            raise Exception(
                f"SOCKS5 proxy {proxy_host}:{proxy_port} BLOCKS port 25 outbound "
                f"(error 0x02: connection not allowed by ruleset). "
                f"Your proxy/VPS firewall blocks SMTP. "
                f"Fix: ask your provider to allow outbound port 25, or route through SMTP relay on 587."
            )
        if "0x05" in s or "connection refused" in s.lower():
            raise Exception(
                f"MX server {mx_host}:25 refused connection via SOCKS5 {proxy_host}:{proxy_port}. "
                f"The mail server is rejecting connections from your proxy IP."
            )
        if "0x01" in s or "general failure" in s.lower():
            raise Exception(
                f"SOCKS5 proxy {proxy_host}:{proxy_port} general failure connecting to "
                f"{mx_host}:25 — proxy may be overloaded or misconfigured."
            )
        if "0x04" in s or "host unreachable" in s.lower():
            raise Exception(
                f"MX host {mx_host} unreachable via SOCKS5 {proxy_host}:{proxy_port} — "
                f"DNS resolution may have failed on the proxy."
            )
        raise Exception(f"SOCKS5 proxy {proxy_host}:{proxy_port} → {mx_host}:25 — {exc}")

    except pysocks.GeneralProxyError as exc:
        s = str(exc)
        if "auth" in s.lower() or "0x01" in s:
            raise Exception(
                f"SOCKS5 proxy {proxy_host}:{proxy_port} authentication failed — "
                f"check username/password."
            )
        raise Exception(
            f"SOCKS5 proxy {proxy_host}:{proxy_port} error — {exc}. "
            f"Check proxy is running and credentials are correct."
        )

    except (socket.timeout, TimeoutError):
        raise Exception(
            f"Timeout connecting to {mx_host}:25 via SOCKS5 proxy {proxy_host}:{proxy_port}. "
            f"Port 25 is likely blocked outbound."
        )
    except ConnectionRefusedError:
        raise Exception(
            f"Connection refused to {mx_host}:25 via SOCKS5 {proxy_host}:{proxy_port}. "
            f"Port 25 blocked or MX server is down."
        )
    except OSError as exc:
        raise Exception(f"Network error connecting to {mx_host}:25 via SOCKS5 — {exc}")


# ═══════════════════════════════════════════════════════════════
# SMTP SUBCLASS — injects SOCKS5 socket at the connection level
# This avoids the fragile smtp.sock / smtp.file manual assignment
# which breaks in Python 3.9+ when pysocks makefile() behaves oddly
# ═══════════════════════════════════════════════════════════════

class _SmtpViaSocks(smtplib.SMTP):
    """
    SMTP subclass that overrides _get_socket() to route the connection
    through a SOCKS5 proxy.  Works with any Python 3.x version because
    it uses the officially supported extension point instead of patching
    internal attributes (smtp.sock / smtp.file).
    """

    def __init__(self, proxy_cfg: dict, mx_host: str,
                 connect_timeout: int = 10, data_timeout: int = 60,
                 ehlo_domain: str = ""):
        self._proxy_cfg       = proxy_cfg
        self._data_timeout    = data_timeout
        self._connect_timeout = connect_timeout
        # Call parent with the real target host/port so it sets self._host
        # and calls _get_socket → our override below
        super().__init__(
            mx_host, 25,
            timeout=connect_timeout,
            local_hostname=ehlo_domain or "mail.server.local",
        )

    def _get_socket(self, host: str, port: int, timeout: float):
        """Override: return a connected SOCKS5 socket instead of a plain one."""
        return _make_socks5_socket(host, self._proxy_cfg, int(timeout or self._connect_timeout))


# ═══════════════════════════════════════════════════════════════
# MX CONNECTION
# ═══════════════════════════════════════════════════════════════

def _connect_mx(
    mx_host:         str,
    ehlo_domain:     str,
    socks_proxy:     Optional[dict] = None,
    connect_timeout: int            = 10,
    data_timeout:    int            = 60,
) -> smtplib.SMTP:
    """
    Open an SMTP connection to mx_host:25, optionally via SOCKS5.
    Performs EHLO and opportunistic STARTTLS with a permissive TLS context.

    Returns a ready smtplib.SMTP object (not authenticated — MX servers
    don't use AUTH; they verify via SPF/DKIM/DMARC instead).

    Raises on any connection or EHLO failure.
    STARTTLS failure is treated as fatal for this MX host.
    """
    smtp: smtplib.SMTP
    ehlo = ehlo_domain or "mail.server.local"

    if socks_proxy and socks_proxy.get("host"):
        # ── SOCKS5 path — use subclass so _get_socket() is overridden ──
        # This is the correct way; avoids manually patching smtp.sock/smtp.file
        # which is unreliable across Python versions and pysocks versions.
        try:
            smtp = _SmtpViaSocks(
                proxy_cfg       = socks_proxy,
                mx_host         = mx_host,
                connect_timeout = connect_timeout,
                data_timeout    = data_timeout,
                ehlo_domain     = ehlo,
            )
        except smtplib.SMTPConnectError as exc:
            raise Exception(
                f"Failed to connect to {mx_host}:25 via SOCKS5 "
                f"{socks_proxy.get('host')}:{socks_proxy.get('port')} — {exc}"
            )
        except Exception as exc:
            raise Exception(
                f"SOCKS5 connection to {mx_host}:25 failed — {exc}. "
                f"Proxy: {socks_proxy.get('host')}:{socks_proxy.get('port')}"
            )
        # Extend timeout for data phase
        if smtp.sock:
            smtp.sock.settimeout(data_timeout)
    else:
        # ── Direct path ─────────────────────────────────────
        try:
            smtp = smtplib.SMTP(mx_host, 25, timeout=connect_timeout,
                                local_hostname=ehlo)
        except Exception as exc:
            raise Exception(f"Direct connect to {mx_host}:25 failed — {exc}")
        if smtp.sock:
            smtp.sock.settimeout(data_timeout)

    # EHLO after connect (smtplib does it but re-run to be safe after sock adjustment)
    try:
        smtp.ehlo(ehlo)
    except Exception as exc:
        try:
            smtp.close()
        except Exception:
            pass
        raise Exception(f"EHLO failed on {mx_host} — {exc}")

    # ── Opportunistic STARTTLS ───────────────────────────────
    # CRITICAL: permissive context required — MX servers almost never
    # have a TLS cert matching their hostname. Without check_hostname=False
    # the starttls() call sends the STARTTLS command (server enters TLS mode)
    # then Python fails cert verification, leaving the channel CORRUPTED.
    if smtp.has_extn("STARTTLS"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            smtp.starttls(context=ctx)
            smtp.ehlo(ehlo)          # re-EHLO mandatory after TLS upgrade
        except smtplib.SMTPNotSupportedError:
            pass   # STARTTLS advertised but not actually supported — continue plaintext
        except Exception as exc:
            try:
                smtp.close()
            except Exception:
                pass
            raise Exception(
                f"STARTTLS failed on {mx_host} — connection corrupted, try next MX. ({exc})"
            )

    return smtp


# ═══════════════════════════════════════════════════════════════
# CAMPAIGN CONTEXT
# ═══════════════════════════════════════════════════════════════

class MxSenderContext:
    """
    Per-campaign context object — holds the shared MX cache and
    domain rate tracker. Create one per campaign, pass to send_direct_mx().

    ctx = MxSenderContext()
    ...send all emails...
    print(ctx.get_stats())
    ctx.close()

    Or use as context manager:
    with MxSenderContext() as ctx:
        ...
    """

    def __init__(
        self,
        mx_cache_ttl:             int   = MX_CACHE_TTL,
        max_consecutive_failures: int   = MAX_CONSECUTIVE_DOMAIN_FAILURES,
        strict_delay:             float = STRICT_DOMAIN_MIN_DELAY,
        ms_delay:                 float = MS_DOMAIN_MIN_DELAY,
        max_per_hour_per_domain:  int   = 0,
        connect_timeout:          int   = 10,
        data_timeout:             int   = 60,
        greylist_retry_delay:     int   = GREYLIST_RETRY_DELAY,
    ):
        self.cache   = MxCache(ttl=mx_cache_ttl)
        self.tracker = DomainRateTracker(
            max_consecutive_failures = max_consecutive_failures,
            strict_delay             = strict_delay,
            ms_delay                 = ms_delay,
            max_per_hour             = max_per_hour_per_domain,
        )
        self.connect_timeout      = connect_timeout
        self.data_timeout         = data_timeout
        self.greylist_retry_delay = greylist_retry_delay

    def get_stats(self) -> dict:
        return {
            "mx_cache":    self.cache.stats(),
            "domains":     self.tracker.get_all_stats(),
        }

    def close(self):
        pass  # nothing to close for now — placeholder for future connection pooling

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ═══════════════════════════════════════════════════════════════
# CORE SENDER
# ═══════════════════════════════════════════════════════════════

def send_direct_mx(
    lead_email:   str,
    sender:       dict,
    msg,                             # email.message.Message — built by mime_builder
    ehlo_domain:  str  = "",
    socks_proxy:  Optional[dict] = None,
    ctx:          Optional[MxSenderContext] = None,
) -> str:
    """
    Send an email directly to the recipient's MX server on port 25.
    No SMTP authentication — delivery verified via SPF/DKIM/DMARC.

    Args:
        lead_email:   Recipient email address
        sender:       Sender dict (fromEmail, fromName, replyTo)
        msg:          Pre-built MIME message (from mime_builder.build_message)
        ehlo_domain:  EHLO/HELO domain — should match sender's domain
        socks_proxy:  Optional SOCKS5 proxy dict (host, port, username, password)
        ctx:          MxSenderContext — shared cache + rate tracker.
                      If None, a fresh one is created per call (no caching).

    Returns:
        mx_host — the MX hostname that successfully accepted the message.

    Raises:
        Exception with an actionable message on all failure modes.
    """
    if "@" not in lead_email:
        raise Exception(f"Invalid email address: {lead_email}")

    domain = lead_email.split("@")[-1].strip().lower()
    if not domain or "." not in domain:
        raise Exception(f"Invalid domain in email address: {lead_email}")

    from_email  = sender.get("fromEmail", "")
    ehlo        = ehlo_domain or (from_email.split("@")[-1] if "@" in from_email else "") or "mail.server.local"

    # Create a throw-away context if caller didn't provide one
    own_ctx = ctx is None
    if own_ctx:
        ctx = MxSenderContext()

    tracker = ctx.tracker
    cache   = ctx.cache

    # ── Rate / domain checks ─────────────────────────────────
    allowed, reason = tracker.is_allowed(domain)
    if not allowed:
        raise Exception(f"DOMAIN SKIPPED [{domain}]: {reason}")

    # Enforce per-domain inter-send delay for strict/MS domains
    tracker.enforce_delay(domain)

    # ── MX resolution (cached) ──────────────────────────────
    try:
        mx_records = cache.resolve(domain)
    except Exception as exc:
        tracker.record_fail(domain, str(exc))
        raise

    # ── Try each MX in priority order ──────────────────────
    errors_detail:  list  = []
    permanent_error: bool = False

    for priority, mx_host in mx_records:
        smtp = None
        try:
            smtp = _connect_mx(
                mx_host, ehlo,
                socks_proxy      = socks_proxy,
                connect_timeout  = ctx.connect_timeout,
                data_timeout     = ctx.data_timeout,
            )
            smtp.send_message(msg, from_addr=from_email, to_addrs=[lead_email])
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

            tracker.record_send(domain)
            log.debug("[MxSender] %s → %s via MX %s (pri %d)", lead_email, domain, mx_host, priority)
            return mx_host

        except smtplib.SMTPRecipientsRefused as exc:
            # Permanent recipient error — no point trying other MX hosts
            permanent_error = True
            errors_detail.append(f"{mx_host}: RECIPIENT REFUSED — {exc}")
            tracker.record_fail(domain, str(exc))
            break

        except smtplib.SMTPResponseException as exc:
            err_str = str(exc)
            code    = exc.smtp_code

            # Permanent recipient errors — stop trying other MX
            if code in (550, 551, 553, 554, 501) or any(s in err_str.lower() for s in _RCPT_PERMANENT_SIGNALS):
                permanent_error = True
                errors_detail.append(f"{mx_host}: {code} {err_str[:120]}")
                tracker.record_fail(domain, err_str)
                break

            # Greylisting — wait and retry same MX once
            if any(s in err_str.lower() for s in _GREYLIST_SIGNALS):
                tracker.record_greylist(domain)
                delay = ctx.greylist_retry_delay
                log.info("[MxSender] %s greylisted by %s — waiting %ds then retrying",
                         domain, mx_host, delay)
                time.sleep(delay)
                try:
                    if smtp:
                        try:
                            smtp.close()
                        except Exception:
                            pass
                    smtp = _connect_mx(
                        mx_host, ehlo,
                        socks_proxy     = socks_proxy,
                        connect_timeout = ctx.connect_timeout,
                        data_timeout    = ctx.data_timeout,
                    )
                    smtp.send_message(msg, from_addr=from_email, to_addrs=[lead_email])
                    try:
                        smtp.quit()
                    except Exception:
                        try:
                            smtp.close()
                        except Exception:
                            pass
                    tracker.record_send(domain)
                    return mx_host
                except Exception as retry_exc:
                    errors_detail.append(f"{mx_host}(greylist-retry): {str(retry_exc)[:120]}")
                    tracker.record_fail(domain, str(retry_exc))

            else:
                # Other transient SMTP error — try next MX priority
                errors_detail.append(f"{mx_host}: {code} {err_str[:120]}")
                tracker.record_fail(domain, err_str)

        except Exception as exc:
            err_str = str(exc)
            errors_detail.append(f"{mx_host}: {err_str[:120]}")
            # Permanent recipient signal in generic exception
            if any(s in err_str.lower() for s in _RCPT_PERMANENT_SIGNALS):
                permanent_error = True
                tracker.record_fail(domain, err_str)
                break
            tracker.record_fail(domain, err_str)

        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    try:
                        smtp.close()
                    except Exception:
                        pass

    detail = "; ".join(errors_detail) if errors_detail else "Unknown error"
    prefix = "RECIPIENT REJECTED" if permanent_error else f"All MX servers failed for {domain}"
    raise Exception(f"{prefix} — {detail}")


# ═══════════════════════════════════════════════════════════════
# BACKWARDS-COMPAT WRAPPER
# Matches the original send_direct_mx() signature exactly.
# ═══════════════════════════════════════════════════════════════

# Module-level shared context — used when callers don't manage their own
_global_ctx:  Optional[MxSenderContext] = None
_global_lock  = threading.Lock()


def get_global_ctx() -> MxSenderContext:
    global _global_ctx
    with _global_lock:
        if _global_ctx is None:
            _global_ctx = MxSenderContext()
        return _global_ctx


def reset_global_ctx(**kwargs):
    """
    Reset and reconfigure the global MxSenderContext.
    Call once at the start of each campaign for clean per-campaign stats
    and a fresh MX cache (in case MX records changed since last campaign).
    Accepts all MxSenderContext __init__ kwargs.
    """
    global _global_ctx
    with _global_lock:
        if _global_ctx is not None:
            _global_ctx.close()
        _global_ctx = MxSenderContext(**kwargs)


def send_direct_mx_compat(
    lead_email:   str,
    sender:       dict,
    resolved_html:  str,
    resolved_plain: str,
    resolved_subject: str,
    dlv:          dict,
    custom_headers: list,
    socks_proxy:  Optional[dict] = None,
    ehlo_domain:  str = "",
    ctx:          Optional[MxSenderContext] = None,
    attachments:  Optional[dict] = None,
) -> str:
    """
    Drop-in replacement for the original send_direct_mx() call signature.

    Builds the MIME message via core.mime_builder then delegates to the
    new send_direct_mx(). Campaign.py can swap the import and keep the
    existing call sites unchanged:

        # Old:
        from synthtel_server import send_direct_mx
        mx_used = send_direct_mx(lead_email, sender, html, plain, subj, dlv, hdrs, socks, ehlo)

        # New:
        from core.mx_sender import send_direct_mx_compat as send_direct_mx
        mx_used = send_direct_mx(lead_email, sender, html, plain, subj, dlv, hdrs, socks, ehlo)
    """
    from core.mime_builder import build_message

    from_email = sender.get("fromEmail", "")
    ehlo       = (
        ehlo_domain
        or (from_email.split("@")[-1] if "@" in from_email else "")
        or "mail.server.local"
    )

    msg, meta = build_message(
        lead         = {"email": lead_email},
        sender       = sender,
        subject      = resolved_subject,
        html         = resolved_html,
        plain        = resolved_plain,
        dlv          = dlv,
        custom_hdrs  = custom_headers,
        attachments  = attachments or {},
        ehlo_domain  = ehlo,
    )

    for w in meta.get("warnings", []):
        log.warning("[mx_sender] build warning: %s", w)

    target_ctx = ctx or get_global_ctx()
    return send_direct_mx(
        lead_email  = lead_email,
        sender      = sender,
        msg         = msg,
        ehlo_domain = ehlo,
        socks_proxy = socks_proxy,
        ctx         = target_ctx,
    )
