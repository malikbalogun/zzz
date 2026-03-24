"""
core/mx_sender.py — SynthTel Direct-to-MX Sender
==================================================
Changes in this revision
─────────────────────────
FIX-K  send_direct_mx_compat(): no longer injects X-MS-Exchange-Organization-SCL:-1
       into the dlv dict before passing to build_message().
       Same reason as smtp_sender FIX-J — EOP header firewall strips it.

All other MX resolution, connection, greylisting, AUP retry, sender health,
and SOCKS5 proxy logic is unchanged from the previous version.
"""

import ssl
import socket
import smtplib
import logging
import re
import time
import threading
import subprocess
import sys
from typing import Optional, List

log = logging.getLogger(__name__)

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

MS_DOMAINS = frozenset({
    "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "outlook.com", "outlook.co.uk",
    "live.com", "live.ca",
    "msn.com",
})

_GREYLIST_SIGNALS = (
    "greylisted", "greylist", "temporarily deferred",
    "try again later", "4.2.0", "421 4.7.0",
    "please try again", "come back later",
)

_TRANSIENT_RETRY_SIGNALS = (
    "aup#mxrt", "server temporarily unavailable",
    "service temporarily unavailable",
    "temporarily unable to accept",
    "try again later", "temporarily unavailable",
    "please try again later",
    "451", "450",
)

_SENDER_POLICY_SIGNALS = (
    "aup#pol", "sender rejected", "sender not authorized",
    "sender address rejected", "sender policy violation",
    "envelope sender", "mail from.*rejected",
    "your email address has been blocked",
    "mail from not allowed",
)

_MX_TRANSIENT_SIGNALS = (
    "connection refused", "connection reset", "timed out", "timeout",
    "no route", "network unreachable", "errno 111", "errno 110",
    "service unavailable", "421",
)

_RCPT_PERMANENT_SIGNALS = (
    "user unknown", "no such user", "mailbox not found", "does not exist",
    "invalid recipient", "mailbox unavailable", "5.1.1", "5.1.2", "550",
    "551", "553", "address rejected",
)

_CONTENT_BLOCK_SIGNALS = (
    "spam", "content filter", "content rejected", "message content",
    "banned content", "spamhaus", "blacklist", "blocklist", "dnsbl",
    "5.7.1", "policy violation", "phish", "suspicious",
)

MX_CACHE_TTL                    = 1800
MAX_CONSECUTIVE_DOMAIN_FAILURES = 20
GREYLIST_RETRY_DELAY            = 90
STRICT_DOMAIN_MIN_DELAY         = 3.0
MS_DOMAIN_MIN_DELAY             = 8.0

TRANSIENT_MAX_RETRIES  = 2
TRANSIENT_BACKOFF_BASE = 8

SENDER_MAX_CONSECUTIVE_FAILS = 3


# ═══════════════════════════════════════════════════════════════
# SENDER HEALTH TRACKER
# ═══════════════════════════════════════════════════════════════

class SenderHealthTracker:
    def __init__(self, max_fails: int = SENDER_MAX_CONSECUTIVE_FAILS):
        self._max_fails  = max_fails
        self._fails:  dict = {}
        self._totals: dict = {}
        self._lock = threading.Lock()
        self.dead_senders: set = set()

    def _is_from_address_error(self, error_str: str) -> bool:
        err = error_str.lower()
        infra_signals = (
            "connection refused", "connection reset", "timed out", "timeout",
            "network unreachable", "no route", "errno", "socks",
            "proxy", "aup#mxrt", "temporarily unavailable",
            "greylisted", "greylist", "temporarily deferred",
        )
        if any(s in err for s in infra_signals):
            return False
        if any(s in err for s in _CONTENT_BLOCK_SIGNALS):
            return False
        from_signals = (
            "aup#pol", "sender rejected", "sender not authorized",
            "sender address rejected", "mail from",
            "your email address", "sender policy",
            "spf", "dkim", "dmarc", "5.7.1", "5.7.26",
        )
        return any(s in err for s in from_signals)

    def record_fail(self, from_email: str, error_str: str):
        if not self._is_from_address_error(error_str):
            return
        with self._lock:
            count = self._fails.get(from_email, 0) + 1
            self._fails[from_email] = count
            if count >= self._max_fails:
                self.dead_senders.add(from_email)
                log.warning("[SenderHealth] %s marked dead after %d consecutive from-address failures",
                            from_email, count)

    def record_success(self, from_email: str):
        with self._lock:
            self._fails[from_email] = 0

    def is_dead(self, from_email: str) -> bool:
        return from_email in self.dead_senders


# ═══════════════════════════════════════════════════════════════
# MX CACHE
# ═══════════════════════════════════════════════════════════════

class MxCache:
    def __init__(self, ttl: int = MX_CACHE_TTL):
        self._cache: dict = {}
        self._ttl   = ttl
        self._lock  = threading.Lock()

    def get(self, domain: str) -> Optional[List[str]]:
        with self._lock:
            entry = self._cache.get(domain)
            if entry and time.time() - entry[0] < self._ttl:
                return entry[1]
        return None

    def set(self, domain: str, mx_hosts: List[str]):
        with self._lock:
            self._cache[domain] = (time.time(), mx_hosts)


# ═══════════════════════════════════════════════════════════════
# DOMAIN RATE TRACKER
# ═══════════════════════════════════════════════════════════════

class DomainRateTracker:
    def __init__(self):
        self._sends:     dict = {}
        self._fails:     dict = {}
        self._greylist:  dict = {}
        self._lock = threading.Lock()

    def record_send(self, domain: str):
        with self._lock:
            self._sends[domain] = self._sends.get(domain, 0) + 1
            self._fails[domain] = 0   # reset on success

    def record_fail(self, domain: str, error: str = ""):
        with self._lock:
            self._fails[domain] = self._fails.get(domain, 0) + 1

    def record_greylist(self, domain: str):
        with self._lock:
            self._greylist[domain] = time.time()

    def consecutive_fails(self, domain: str) -> int:
        return self._fails.get(domain, 0)

    def should_skip(self, domain: str) -> bool:
        return self.consecutive_fails(domain) >= MAX_CONSECUTIVE_DOMAIN_FAILURES


# ═══════════════════════════════════════════════════════════════
# MX SENDER CONTEXT
# ═══════════════════════════════════════════════════════════════

class MxSenderContext:
    def __init__(
        self,
        connect_timeout:    int   = 10,
        data_timeout:       int   = 60,
        greylist_retry_delay: int = GREYLIST_RETRY_DELAY,
    ):
        self.connect_timeout      = connect_timeout
        self.data_timeout         = data_timeout
        self.greylist_retry_delay = greylist_retry_delay
        self.mx_cache    = MxCache()
        self.tracker     = DomainRateTracker()
        self.health      = SenderHealthTracker()
        self._lock       = threading.Lock()

    def get_stats(self) -> dict:
        return {
            "dead_senders": list(self.health.dead_senders),
        }

    def close(self):
        pass   # no persistent connections to close in MX sender


# ═══════════════════════════════════════════════════════════════
# DNS / MX RESOLUTION
# ═══════════════════════════════════════════════════════════════

def _resolve_mx_all_methods(domain: str) -> List[str]:
    mx_hosts = []

    if _HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(domain, 'MX', lifetime=8)
            sorted_answers = sorted(answers, key=lambda r: r.preference)
            mx_hosts = [str(r.exchange).rstrip('.') for r in sorted_answers]
        except Exception:
            pass

    if not mx_hosts:
        import subprocess as _sp
        try:
            out = _sp.check_output(
                ["nslookup", "-type=MX", domain],
                timeout=8, stderr=_sp.DEVNULL
            ).decode(errors="replace")
            for line in out.splitlines():
                if "mail exchanger" in line.lower():
                    parts = line.split()
                    if parts:
                        mx_hosts.append(parts[-1].rstrip('.'))
        except Exception:
            pass

    if not mx_hosts:
        try:
            mx_hosts = [socket.getfqdn(domain)]
        except Exception:
            pass

    return [h for h in mx_hosts if h and h != domain]


def _connect_mx(
    mx_host:         str,
    ehlo:            str,
    socks_proxy:     Optional[dict] = None,
    connect_timeout: int = 10,
    data_timeout:    int = 60,
) -> smtplib.SMTP:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    if socks_proxy and socks_proxy.get("host"):
        try:
            import socks as pysocks
            ptype = {
                "socks4": pysocks.SOCKS4,
                "socks5": pysocks.SOCKS5,
                "http":   pysocks.HTTP,
            }.get((socks_proxy.get("type") or "socks5").lower(), pysocks.SOCKS5)

            sock = pysocks.socksocket()
            sock.set_proxy(
                ptype,
                socks_proxy["host"],
                int(socks_proxy.get("port", 1080)),
                rdns=True,
                username=socks_proxy.get("username"),
                password=socks_proxy.get("password"),
            )
            sock.settimeout(connect_timeout)
            sock.connect((mx_host, 25))
            sock.settimeout(data_timeout)

            smtp       = smtplib.SMTP(host=None)
            smtp.sock  = sock
            smtp._host = mx_host
            smtp.file  = sock.makefile("rb")

            code, msg_b = smtp.getreply()
            if code != 220:
                msg_str = msg_b.decode(errors="replace") if isinstance(msg_b, bytes) else str(msg_b)
                raise smtplib.SMTPConnectError(code, f"SMTP banner: {code} {msg_str[:80]}")
        except ImportError:
            raise Exception(
                "SOCKS5 proxy requires PySocks: pip install pysocks --break-system-packages"
            )
    else:
        smtp = smtplib.SMTP(mx_host, 25, timeout=connect_timeout,
                            local_hostname=ehlo)
        if smtp.sock:
            smtp.sock.settimeout(data_timeout)

    smtp.ehlo(ehlo)

    if smtp.has_extn("STARTTLS"):
        try:
            smtp.starttls(context=ctx)
            smtp.ehlo(ehlo)
        except Exception:
            pass  # Some MX servers advertise STARTTLS but fail — continue plain

    return smtp


def _close_smtp(smtp: Optional[smtplib.SMTP]):
    if smtp is None:
        return
    try:
        smtp.quit()
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# MAIN SEND FUNCTION
# ═══════════════════════════════════════════════════════════════

def send_direct_mx(
    lead_email:       str,
    sender:           dict,
    msg,
    ehlo_domain:      str                = "",
    socks_proxy:      Optional[dict]     = None,
    ctx:              Optional[MxSenderContext] = None,
    extra_senders:    Optional[List[dict]] = None,
    resolved_subject: str                = "",
    resolved_html:    str                = "",
    resolved_plain:   str                = "",
) -> str:
    """
    Send a pre-built MIME message directly to the recipient's MX server.
    Returns the MX host used on success.
    Raises descriptive Exception on failure.
    """
    if not lead_email or "@" not in lead_email:
        raise Exception(f"INVALID EMAIL — bad address format ({lead_email})")

    target_ctx = ctx or MxSenderContext()
    tracker    = target_ctx.tracker
    health     = target_ctx.health
    mx_cache   = target_ctx.mx_cache

    from_email = sender.get("fromEmail", "")
    domain     = lead_email.split("@")[-1].lower()
    ehlo       = ehlo_domain or (from_email.split("@")[-1] if "@" in from_email else "mail.server.local")

    if tracker.should_skip(domain):
        raise Exception(f"Domain {domain} skipped — too many consecutive failures")

    if health.is_dead(from_email):
        raise Exception(f"Sender {from_email} is dead — too many from-address rejections")

    # Resolve MX
    mx_hosts = mx_cache.get(domain)
    if not mx_hosts:
        try:
            mx_hosts = _resolve_mx_all_methods(domain)
        except Exception as e:
            raise Exception(f"Could not resolve MX for {domain}: {e}")
        if not mx_hosts:
            raise Exception(f"NXDOMAIN — no MX records found for {domain}")
        mx_cache.set(domain, mx_hosts)

    errors_detail   = []
    permanent_error = False
    sender_policy_hit = False

    # Per-domain throttle
    if domain in STRICT_DOMAINS:
        min_delay = MS_DOMAIN_MIN_DELAY if domain in MS_DOMAINS else STRICT_DOMAIN_MIN_DELAY
        time.sleep(min_delay)

    for mx_host in mx_hosts:
        smtp = None
        try:
            smtp = _connect_mx(
                mx_host, ehlo,
                socks_proxy     = socks_proxy,
                connect_timeout = target_ctx.connect_timeout,
                data_timeout    = target_ctx.data_timeout,
            )
            smtp.send_message(msg, from_addr=from_email, to_addrs=[lead_email])
            _close_smtp(smtp)
            tracker.record_send(domain)
            health.record_success(from_email)
            return mx_host

        except smtplib.SMTPResponseException as exc:
            code    = exc.smtp_code
            err_str = exc.smtp_error.decode(errors="replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
            err_low = err_str.lower()

            if any(s in err_low for s in _RCPT_PERMANENT_SIGNALS):
                permanent_error = True
                errors_detail.append(f"{mx_host}: {code} {err_str[:120]}")
                tracker.record_fail(domain, err_str)
                break

            elif any(s in err_low for s in _CONTENT_BLOCK_SIGNALS):
                errors_detail.append(f"{mx_host}(content_block): {code} {err_str[:120]}")
                tracker.record_fail(domain, err_str)
                break

            elif any(re.search(s, err_low) for s in _SENDER_POLICY_SIGNALS):
                sender_policy_hit = True
                errors_detail.append(f"{mx_host}(sender_policy): {code} {err_str[:120]}")
                health.record_fail(from_email, err_str)

                # Try extra senders if available
                if extra_senders:
                    for alt_sender in extra_senders:
                        alt_email = alt_sender.get("fromEmail", "")
                        if not alt_email or health.is_dead(alt_email):
                            continue
                        try:
                            smtp2 = _connect_mx(mx_host, ehlo, socks_proxy=socks_proxy,
                                                connect_timeout=target_ctx.connect_timeout,
                                                data_timeout=target_ctx.data_timeout)
                            smtp2.send_message(msg, from_addr=alt_email, to_addrs=[lead_email])
                            _close_smtp(smtp2)
                            tracker.record_send(domain)
                            health.record_success(alt_email)
                            log.info("[MxSender] fallback sender %s succeeded for %s", alt_email, domain)
                            return mx_host
                        except Exception as alt_exc:
                            health.record_fail(alt_email, str(alt_exc))
                            continue
                break

            elif any(s in err_low for s in _TRANSIENT_RETRY_SIGNALS):
                # AUP#MXRT — exponential backoff retry
                for retry in range(TRANSIENT_MAX_RETRIES):
                    delay = TRANSIENT_BACKOFF_BASE * (2 ** retry)
                    log.info("[MxSender] %s transient on %s — retry %d in %ds",
                             domain, mx_host, retry + 1, delay)
                    time.sleep(delay)
                    try:
                        smtp2 = _connect_mx(mx_host, ehlo, socks_proxy=socks_proxy,
                                            connect_timeout=target_ctx.connect_timeout,
                                            data_timeout=target_ctx.data_timeout)
                        smtp2.send_message(msg, from_addr=from_email, to_addrs=[lead_email])
                        _close_smtp(smtp2)
                        tracker.record_send(domain)
                        health.record_success(from_email)
                        return mx_host
                    except Exception:
                        pass
                errors_detail.append(f"{mx_host}(aup_retry_exhausted): {code} {err_str[:80]}")
                tracker.record_fail(domain, err_str)

            elif any(s in err_low for s in _GREYLIST_SIGNALS):
                tracker.record_greylist(domain)
                delay = target_ctx.greylist_retry_delay
                log.info("[MxSender] %s greylisted by %s — waiting %ds", domain, mx_host, delay)
                time.sleep(delay)
                _close_smtp(smtp)
                smtp = None
                try:
                    smtp2 = _connect_mx(mx_host, ehlo, socks_proxy=socks_proxy,
                                        connect_timeout=target_ctx.connect_timeout,
                                        data_timeout=target_ctx.data_timeout)
                    smtp2.send_message(msg, from_addr=from_email, to_addrs=[lead_email])
                    _close_smtp(smtp2)
                    tracker.record_send(domain)
                    health.record_success(from_email)
                    return mx_host
                except Exception as retry_exc:
                    errors_detail.append(f"{mx_host}(greylist-retry): {str(retry_exc)[:120]}")
                    tracker.record_fail(domain, str(retry_exc))

            else:
                errors_detail.append(f"{mx_host}: {code} {err_str[:120]}")
                tracker.record_fail(domain, err_str)

        except Exception as exc:
            err_str = str(exc)
            errors_detail.append(f"{mx_host}: {err_str[:120]}")
            if any(s in err_str.lower() for s in _RCPT_PERMANENT_SIGNALS):
                permanent_error = True
                tracker.record_fail(domain, err_str)
                break
            tracker.record_fail(domain, err_str)

        finally:
            _close_smtp(smtp)

    detail = "; ".join(errors_detail) if errors_detail else "Unknown error"
    if permanent_error:
        prefix = "RECIPIENT REJECTED"
    elif sender_policy_hit:
        prefix = "SENDER POLICY BLOCK"
    else:
        prefix = f"All MX servers failed for {domain}"
    raise Exception(f"{prefix} — {detail}")


# ═══════════════════════════════════════════════════════════════
# MX PREFLIGHT CHECK
# ═══════════════════════════════════════════════════════════════

def preflight_check_senders(
    senders:       list,
    threshold_pct: float = 25.0,
) -> dict:
    import concurrent.futures as _pf_cf

    cache: dict = {}
    ok_senders  = []
    bad_senders = []
    errors      = {}

    domain_set = set()
    for s in senders:
        email = s.get("fromEmail", "") if isinstance(s, dict) else str(s)
        if email and "@" in email:
            domain_set.add(email.split("@")[-1].lower())

    def _check_domain(domain):
        try:
            mx = _resolve_mx_all_methods(domain)
            return domain, (bool(mx), "")
        except Exception as exc:
            return domain, (False, str(exc)[:120])

    with _pf_cf.ThreadPoolExecutor(max_workers=min(len(domain_set), 20)) as ex:
        futs = {ex.submit(_check_domain, d): d for d in domain_set}
        for fut in _pf_cf.as_completed(futs, timeout=30):
            try:
                dom, result = fut.result(timeout=0)
                cache[dom] = result
            except Exception:
                cache[futs[fut]] = (False, "timeout")

    for s in senders:
        email = s.get("fromEmail", "") if isinstance(s, dict) else str(s)
        if not email or "@" not in email:
            bad_senders.append(email)
            errors[email] = "Invalid format"
            continue
        domain = email.split("@")[-1].lower()
        mx_ok, mx_err = cache.get(domain, (False, "not checked"))
        if mx_ok:
            ok_senders.append(email)
        else:
            bad_senders.append(email)
            errors[email] = mx_err or "No MX records found"

    total   = len(senders)
    bad_pct = 100.0 * len(bad_senders) / max(1, total)

    return {
        "ok":                      ok_senders,
        "bad":                     bad_senders,
        "bad_pct":                 round(bad_pct, 1),
        "warn_threshold_exceeded": bad_pct > threshold_pct,
        "errors":                  errors,
    }


# ═══════════════════════════════════════════════════════════════
# BACKWARDS-COMPAT WRAPPER
# ═══════════════════════════════════════════════════════════════

_global_ctx:  Optional[MxSenderContext] = None
_global_lock  = threading.Lock()


def get_global_ctx() -> MxSenderContext:
    global _global_ctx
    with _global_lock:
        if _global_ctx is None:
            _global_ctx = MxSenderContext()
        return _global_ctx


def reset_global_ctx(**kwargs):
    global _global_ctx
    with _global_lock:
        if _global_ctx is not None:
            _global_ctx.close()
        _global_ctx = MxSenderContext(**kwargs)


def send_direct_mx_compat(
    lead_email:       str,
    sender:           dict,
    resolved_html:    str,
    resolved_plain:   str,
    resolved_subject: str,
    dlv:              dict,
    custom_headers:   list,
    socks_proxy:      Optional[dict] = None,
    ehlo_domain:      str = "",
    ctx:              Optional[MxSenderContext] = None,
    attachments:      Optional[dict] = None,
    extra_senders:    Optional[List[dict]] = None,
) -> str:
    """
    Drop-in replacement for the original send_direct_mx() call signature.
    FIX-K: No longer injects X-MS-Exchange-Organization-SCL:-1 into dlv.
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
        preheader    = (dlv or {}).get("preheader", ""),
    )

    for w in meta.get("warnings", []):
        log.warning("[mx_sender] build warning: %s", w)

    target_ctx = ctx or get_global_ctx()
    return send_direct_mx(
        lead_email        = lead_email,
        sender            = sender,
        msg               = msg,
        ehlo_domain       = ehlo,
        socks_proxy       = socks_proxy,
        ctx               = target_ctx,
        extra_senders     = extra_senders or [],
        resolved_subject  = resolved_subject,
        resolved_html     = resolved_html,
        resolved_plain    = resolved_plain,
    )
