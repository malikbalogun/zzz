"""
core/campaign.py — SynthTel Campaign Orchestrator
==================================================
Replaces the monolithic process_campaign() in synthtel_server.py.

Changes in this revision
─────────────────────────
FIX-D  threadSimulate default changed from True → False.
       Fake In-Reply-To/References headers are associated with Emotet/QBot
       malware campaigns and trigger enterprise threat classifiers.
       Gmail broke thread-by-fake-ID in March 2019 — it has no inbox effect.

FIX-E  msExchangeHeaders default changed from True → False.
       Microsoft EOP strips all X-MS-Exchange-Organization-* headers from
       external senders before evaluation (permission-gated header firewall).
       Injecting them wastes bytes and signals ESP ignorance of Exchange arch.

FIX-F  originatingIpAuto default changed from True → False.
       X-Originating-IP is set by webmail providers for their own sends.
       External injection of fake RFC1918 IPs is detected by modern filters.

FIX-G  autoPlain default changed to True.
       If the caller does not provide an explicit plain text body, the campaign
       now always generates a clean plain text part. The plain text is extracted
       by mime_builder._strip_html() from the ORIGINAL clean HTML before any
       image embedding, so no base64 bleed occurs (see mime_builder FIX-1).

Wires all 8 send modules together:
  • core.smtp_sender     → SMTP relay (pooled connections, proxy-aware)
  • core.mx_sender       → Direct-to-MX on port 25 (tunnel-native)
  • core.api_sender      → Brevo / SendGrid / Resend / Mailgun / Postmark / SparkPost / SES
  • core.owa_sender      → Exchange Web Services (EWS / OWA)
  • core.crm_sender      → HubSpot / Salesforce / Dynamics / Zoho / Pipedrive / Custom
  • core.tunnel_manager  → SSH SOCKS5 + ISP proxy tunnels
  • core.tags            → Full tag resolution engine
  • core.mime_builder    → MIME message construction

Public API:
    from core.campaign import process_campaign, CampaignOptions

    for event in process_campaign(data):
        yield json.dumps(event) + "\\n"
"""

import json
import logging
import random
import socket
import time
import threading
import html as html_lib
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue as _Queue, Empty as _QueueEmpty
from datetime import datetime, timedelta
from typing import Generator, Optional

log = logging.getLogger(__name__)

from core.tags import resolve_tags, build_context
try:
    from core.link_encoder import (
        resolve_link_tags, build_redirect_attachment,
        get_method_from_tag, METHOD_HTML_ATTACHMENT, METHOD_CF_SECURITY_CHECK,
    )
    _HAS_LINK_ENCODER = True
except ImportError:
    _HAS_LINK_ENCODER = False

try:
    from core.email_sorter import sort_leads, get_provider_delay, PROVIDER_META
    _HAS_SORTER = True
except ImportError:
    _HAS_SORTER = False

try:
    # NOTE: the module was renamed from core.b2b_sender to core.b2b_manager.
    # core.b2b_manager exposes a B2BSender + b2b_from_cfg compatibility shim
    # so this import keeps working unchanged for downstream callers.
    from core.b2b_manager import B2BSender, b2b_from_cfg
    _HAS_B2B = True
except ImportError:
    _HAS_B2B = False

from core.spam_filter import apply_spam_filter, apply_full_bypass
from core.smtp_sender import (
    send_smtp, get_global_pool, reset_global_pool,
    SmtpPool,
)
from core.mx_sender import (
    send_direct_mx, get_global_ctx, reset_global_ctx,
    MxSenderContext, preflight_check_senders,
)
from core.api_sender import send_api, build_api_headers
from core.owa_sender import send_owa
from core.crm_sender import send_crm
from core.tunnel_manager import (
    open_ssh_socks, close_all_tunnels, close_tunnel,
)
from core.mime_builder import build_message


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

WARMUP_LIMITS: dict = {
    1: 20,
    2: 100,
    3: 500,
    4: 2_000,
    5: 999_999,
}

STRICT_DOMAINS = frozenset({
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "live.com", "msn.com", "ymail.com",
    "yahoo.co.uk", "yahoo.com.au", "hotmail.co.uk",
    "me.com", "mac.com",
})

MS_RATE_DOMAINS = frozenset({
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "hotmail.co.uk", "hotmail.fr", "outlook.co.uk",
})

VALID_METHODS = frozenset({"smtp", "mx", "api", "owa", "crm", "tunnel", "b2b"})


def _check_socks5(host: str, port: int, timeout: int = 5) -> tuple:
    import socket as _sock
    try:
        s = _sock.create_connection((host, port), timeout=timeout)
        s.close()
        return True, ""
    except Exception as e:
        return False, str(e)


def _restart_3proxy_via_ssh(host: str, user: str, password: str, port: int = 22) -> tuple:
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, port=port, username=user, password=password, timeout=15)
        cmds = [
            "Stop-Process -Name 3proxy -Force -ErrorAction SilentlyContinue",
            "Start-Sleep 1",
            "Start-Process -FilePath 'C:\\proxy\\3proxy.exe' -ArgumentList 'C:\\proxy\\3proxy.cfg' -WindowStyle Hidden",
            "Start-Sleep 3",
            "(Get-Process -Name 3proxy -ErrorAction SilentlyContinue) -ne $null",
        ]
        ps = "; ".join(cmds)
        _, stdout, stderr = c.exec_command(
            f'powershell -ExecutionPolicy Bypass -Command "{ps}"', timeout=30
        )
        out = stdout.read().decode(errors="replace").strip()
        c.close()
        return True, f"3proxy restarted: {out}"
    except Exception as e:
        return False, f"SSH restart failed: {e}"


def _preflight_isp_tunnel(tun: dict) -> tuple:
    host     = tun.get("socksHost") or tun.get("sshHost", "")
    port     = int(tun.get("socksPort", 1080))
    ssh_user = tun.get("sshUser", "Administrator")
    ssh_pass = tun.get("sshPass", "")
    ssh_port = int(tun.get("rdpSshPort", 22))

    ok, err = _check_socks5(host, port)
    if ok:
        return True, f"SOCKS5 {host}:{port} OK"

    if ssh_pass:
        rok, rmsg = _restart_3proxy_via_ssh(host, ssh_user, ssh_pass, ssh_port)
        if rok:
            import time as _time
            _time.sleep(4)
            ok2, err2 = _check_socks5(host, port)
            if ok2:
                return True, f"3proxy restarted and SOCKS5 {host}:{port} now OK"
            return False, f"3proxy restarted but SOCKS5 still down: {err2}"
        return False, f"SOCKS5 down ({err}) and SSH restart failed: {rmsg}"

    return False, f"SOCKS5 {host}:{port} unreachable: {err}"


DELAY_UNITS = {
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    # Frontend aliases (backward compatibility)
    "ms": 0.001,
    "millisecond": 0.001,
    "milliseconds": 0.001,
    "sec": 1,
    "second": 1,
    "min": 60,
    "minute": 60,
    "hr": 3600,
    "hour": 3600,
}


# ═══════════════════════════════════════════════════════════════
# LOCAL HELPERS
# ═══════════════════════════════════════════════════════════════

def _strip_html(html_str: str) -> str:
    """
    Legacy plain-text extractor kept for backwards compatibility with
    any code that calls campaign._strip_html() directly.
    For MIME building, mime_builder._strip_html() is used (see FIX-1).
    """
    text = re.sub(r'<br\s*/?>', '\n', html_str or "")
    text = re.sub(r'</p>', '\n\n', text, flags=re.I)
    text = re.sub(r'<[^>]+>', '', text)
    text = html_lib.unescape(text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()


def _inject_unsub_link(html_str: str, unsub_url: str, email: str) -> str:
    url = unsub_url.replace("#EMAIL", email) if unsub_url else "#"
    footer = (
        '<div style="text-align:center;padding:20px 0 10px;margin-top:20px;'
        'border-top:1px solid #eee;font-size:11px;color:#999;font-family:Arial,sans-serif">'
        f'<a href="{url}" style="color:#999;text-decoration:underline">Unsubscribe</a>'
        ' | '
        f'<a href="{url}" style="color:#999;text-decoration:underline">Manage preferences</a>'
        '</div>'
    )
    if '</body>' in (html_str or "").lower():
        return re.sub(r'(</body>)', footer + r'\1', html_str, flags=re.I)
    return (html_str or "") + footer


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return default

def _campaign_abort_requested(uid) -> bool:
    """Best-effort campaign abort check from shared server control map."""
    if not uid:
        return False
    try:
        from core import server as _server
        with _server.active_campaigns_lock:
            ctrl = _server.CAMPAIGN_CONTROLS.get(uid) or {}
            return bool(ctrl.get("abort", False))
    except Exception:
        return False

def _sleep_interruptible(seconds: float, uid) -> bool:
    """Sleep in short slices so stop requests can interrupt quickly."""
    try:
        remaining = max(0.0, float(seconds))
    except (ValueError, TypeError):
        remaining = 0.0
    while remaining > 0:
        if _campaign_abort_requested(uid):
            return False
        chunk = 0.25 if remaining > 0.25 else remaining
        time.sleep(chunk)
        remaining -= chunk
    return True


def _parse_smtp_error(error: Exception, lead_email: str = "") -> str:
    err = str(error).lower()
    domain = lead_email.split("@")[-1] if "@" in lead_email else ""

    import re as _re
    smtp_code = ""
    m = _re.search(r"\((\d{3}),", str(error))
    if m:
        smtp_code = m.group(1)

    if err.startswith("api ") or "api key" in err:
        return str(error)[:300]
    if err.startswith("invalid email") or "invalid domain in email" in err:
        return f"INVALID EMAIL — bad address format ({lead_email})"
    if err.startswith("domain skipped"):
        return str(error)[:200]

    if "all mx servers failed" in err:
        return f"MX SEND FAILED — all servers for {domain or 'recipient'} rejected. Check proxy/port 25"
    if "nxdomain" in err or "could not resolve mx" in err or "could not resolve" in err:
        return f"DNS ERROR — cannot resolve mail servers for {domain}"
    if any(x in err for x in ["greylisted", "greylist", "4.2.0", "temporarily deferred"]):
        return "GREYLISTED — server wants you to retry later (temporary rejection)"

    if any(x in err for x in [
        "user unknown", "mailbox not found", "does not exist",
        "no such user", "unknown user", "invalid recipient",
        "recipient rejected", "mailbox unavailable",
        "5.1.1", "recipient not found", "account disabled", "undeliverable",
    ]):
        return f"INVALID RECIPIENT — email does not exist or mailbox disabled ({lead_email})"
    if "address rejected" in err and "sender" not in err and "from" not in err:
        return f"INVALID RECIPIENT — email does not exist or mailbox disabled ({lead_email})"

    if any(x in err for x in [
        "spamhaus", "blacklist", "blocklist", "blocked using",
        "bl.spamcop", "barracuda", "sorbs", "dnsbl", "rbl",
        "listed at", "poor reputation", "client host rejected",
        "5.7.1 service unavailable",
    ]):
        return "IP BLOCKED — your sending IP is on a blacklist or has poor reputation"

    if any(x in err for x in [
        "too many", "rate limit", "throttl", "exceeded the rate",
        "too many connections", "4.7.0", "try again later",
        "service busy", "resources temporarily unavailable",
        "exceeded sending",
    ]):
        if domain in MS_RATE_DOMAINS:
            return f"MICROSOFT RATE LIMIT — too fast for {domain}. Rotate IP or increase delay"
        return "RATE LIMITED — server throttling your sends. Slow down or rotate IP"

    if any(x in err for x in [
        "spf", "dkim", "dmarc", "unauthenticated",
        "authentication required", "not authenticated",
        "5.7.26", "5.7.23", "5.7.25",
    ]):
        return "AUTH FAIL — SPF/DKIM/DMARC failed. This IP is not authorized to send for your domain"

    if any(x in err for x in [
        "spam", "junk", "content rejected", "suspicious",
        "phish", "message content", "banned content", "high spam",
    ]):
        return "CONTENT FILTER — flagged as spam by recipient server"

    if any(x in err for x in [
        "policy", "organization", "rejected by policy",
        "content filter", "message rejected", "refused by",
        "administratively denied", "mailbox policy", "5.7.0",
    ]):
        return "POLICY BLOCK — recipient org/mailbox policy rejected message"

    if any(x in err for x in ["mailbox full", "over quota", "storage exceeded", "5.2.2"]):
        return f"MAILBOX FULL — {lead_email} inbox is over quota"

    if any(x in err for x in [
        "connection refused", "connection timed out",
        "network unreachable", "no route to host", "timed out",
        "errno 111", "errno 110", "errno 113",
    ]):
        return "CONNECTION FAILED — could not reach mail server. Check host/port/firewall"

    if any(x in err for x in ["ssl", "tls", "certificate", "handshake"]):
        return f"SSL/TLS ERROR — {str(error)[:120]}"

    if any(x in err for x in ["socks", "proxy", "0x02", "not allowed"]):
        if "0x02" in err or "not allowed" in err.lower():
            return "SOCKS BLOCK — proxy blocked connection. Port 25 blocked or proxy down"
        return f"PROXY ERROR — {str(error)[:120]}"

    if any(x in err for x in ["auth", "login", "535", "534", "authentication"]):
        return f"AUTH FAILED — wrong credentials for SMTP server ({smtp_code or 'auth error'})"

    return str(error)[:250]


def _pick(pool: list, rotation: str, index: int):
    if not pool:
        return None
    if rotation == "random":
        return random.choice(pool)
    return pool[index % len(pool)]


def _pick_pool_proxy(opts, index: int, dead_proxies: set = None):
    """Choose a proxy_cfg dict from opts.proxy['list'] (skipping any in
    dead_proxies). Returns None if there's no proxy pool configured.

    Used by api/owa/crm send paths so all four HTTP-based methods share
    the same proxy pool that smtp_sender already honours.
    """
    if not opts or not getattr(opts, "proxy", None):
        return None
    pl = (opts.proxy or {}).get("list") or []
    if not pl:
        return None
    rot = (opts.proxy or {}).get("rotation", "random")
    dead = dead_proxies or set()
    live = [p for p in pl if (p.get("host","") if isinstance(p, dict) else str(p)) not in dead]
    return _pick(live or pl, rot, index)


# ═══════════════════════════════════════════════════════════════
# CAMPAIGN OPTIONS
# ═══════════════════════════════════════════════════════════════

class CampaignOptions:
    """Typed container for all campaign configuration."""

    def __init__(
        self,
        method:         str   = "smtp",
        smtps:          list  = None,
        apis:           list  = None,
        owas:           list  = None,
        crms:           list  = None,
        tunnels:        list  = None,
        senders:        list  = None,
        subjects:       list  = None,
        from_names:     list  = None,
        reply_tos:      list  = None,
        leads:          list  = None,
        html_body:      str   = "",
        html_bodies:    list  = None,
        plain_body:     str   = "",
        rotation:       dict  = None,
        paired_mode:    bool  = False,
        dlv:            dict  = None,
        sending:        dict  = None,
        links_cfg:      dict  = None,
        custom_headers: list  = None,
        attachments:    dict  = None,
        proxy:          dict  = None,
        uid:            str   = None,
        inbox_profile:  bool  = True,
        skip_preflight_dns: bool = False,
        bcc_mode:           bool  = False,
        bcc_max:            int   = 5,
        subject_encoding:   int   = 0,
        link_method:        int   = 0,
        b2b_cfg:            dict  = None,
    ):
        self.uid            = uid
        self.inbox_profile  = bool(inbox_profile)
        self.method         = method if method in VALID_METHODS else "smtp"
        self.smtps          = smtps   or []
        self.apis           = apis    or []
        self.owas           = owas    or []
        self.crms           = crms    or []
        self.tunnels        = tunnels or []
        self.senders        = senders or []
        self.subjects       = subjects or [""]
        self.from_names     = from_names or []
        self.reply_tos      = reply_tos  or []
        self.leads          = leads   or []
        self.html_body      = html_body   or ""
        self.html_bodies    = html_bodies or []
        self.plain_body     = plain_body  or ""
        self.rotation       = rotation       or {}
        self.paired_mode    = bool(paired_mode)
        self.dlv            = dlv            or {}
        self.sending        = sending        or {}
        self.links_cfg      = links_cfg      or {}
        self.custom_headers = custom_headers or []
        self.attachments    = attachments    or {}
        self.proxy          = proxy          or {}
        self.skip_preflight_dns = bool(skip_preflight_dns)
        self.bcc_mode         = bool(bcc_mode)
        self.bcc_max          = int(bcc_max)
        self.subject_encoding = int(subject_encoding)
        self.link_method      = int(link_method)
        self.b2b_cfg          = b2b_cfg or {}

    @classmethod
    def _build_proxy_cfg(cls, data: dict) -> dict:
        """Parse proxies array from frontend into internal {list, rotation} dict."""
        import re as _re
        raw_list = data.get("proxies") or []
        rotation = data.get("proxyRotation") or "random"
        if not raw_list:
            return data.get("proxy") or {}
        parsed = []
        for item in raw_list:
            if isinstance(item, dict):
                raw = item.get("raw") or item.get("url") or ""
                if not raw:
                    if item.get("host"):
                        parsed.append(item)
                    continue
            else:
                raw = str(item).strip()
            if not raw:
                continue
            m = _re.match(
                r'^(?:(socks5|socks4|http|https)://)?(?:([^:@]+):([^@]+)@)?([\w.\-]+):(\d+)$',
                raw.strip()
            )
            if m:
                scheme, user, pw, host, port = m.groups()
                parsed.append({"type": scheme or "socks5", "host": host,
                                "port": int(port), "username": user or "", "password": pw or ""})
            else:
                parts = raw.rsplit(":", 1)
                if len(parts) == 2 and parts[1].isdigit():
                    parsed.append({"type": data.get("proxyType","socks5"), "host": parts[0],
                                    "port": int(parts[1]), "username": "", "password": ""})
        if not parsed:
            return data.get("proxy") or {}
        return {"list": parsed, "rotation": rotation}

    @classmethod
    def _build_links_cfg_from_data(cls, data: dict) -> dict:
        links_raw = data.get("linkRotation", [])
        mode      = data.get("linkRotMode", "sequential")
        if not links_raw:
            return {}
        links = []
        for item in links_raw:
            if isinstance(item, dict):
                url   = item.get("url") or item.get("link") or ""
                limit = int(item.get("limit") or item.get("max") or 0)
                if url:
                    links.append({"url": url, "limit": limit, "sent": 0})
            elif isinstance(item, str) and item.strip():
                links.append({"url": item.strip(), "limit": 0, "sent": 0})
        return {"links": links, "mode": mode}

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignOptions":
        method = data.get("method", "smtp")
        if method == "isp":
            method = "tunnel"

        raw_smtps = data.get("smtps") or data.get("smtpServers", [])
        smtps = []
        for s in (raw_smtps or []):
            if not isinstance(s, dict):
                continue
            enc = str(s.get("encryption", "")).upper().strip()
            if not enc:
                enc = "SSL" if bool(s.get("ssl", False)) else "TLS"
            smtps.append({
                **s,
                "username": s.get("username", s.get("user", "")),
                "password": s.get("password", s.get("pass", "")),
                "encryption": enc,
            })
        _raw_apis = data.get("apis") or data.get("apiKeys", [])
        # Frontend stores key as {provider, key} but api_sender expects {provider, apiKey}
        # Also auto-detect provider from key format in case dropdown was wrong when saved
        def _detect_provider(k: str) -> str:
            if not k: return "sendgrid"
            if k.startswith("SG."): return "sendgrid"
            if k.startswith("key-"): return "mailgun"
            if k.startswith("AKIA") or k.startswith("ASIA"): return "ses"
            if k.startswith("xkeysib-") or k.startswith("xsmtpsib-"): return "brevo"
            if len(k) == 40 and k.replace("-","").isalnum(): return "postmark"
            if k.startswith("re_"): return "resend"
            return "sendgrid"
        # Provider name aliases — frontend uses different names than api_sender expects
        _PROVIDER_ALIASES = {
            "ses-api": "ses",       # frontend calls it ses-api, api_sender expects ses
            "aws":     "ses",
            "aws-ses": "ses",
            "brevo":   "brevo",
            "sendinblue": "brevo",
        }
        apis = []
        for a in (_raw_apis or []):
            if isinstance(a, dict):
                if "key" in a and "apiKey" not in a:
                    a = {**a, "apiKey": a["key"]}
                # Normalize provider name aliases
                saved = (a.get("provider") or "").lower()
                if saved in _PROVIDER_ALIASES:
                    a = {**a, "provider": _PROVIDER_ALIASES[saved]}
                    saved = a["provider"]
                # Auto-detect provider from key format if clearly wrong
                raw_key = a.get("apiKey") or a.get("key") or ""
                if raw_key:
                    detected = _detect_provider(raw_key)
                    if (raw_key.startswith("SG.") and saved != "sendgrid") or \
                       (raw_key.startswith("key-") and saved != "mailgun") or \
                       (raw_key.startswith("xkeysib-") and saved != "brevo") or \
                       (raw_key.startswith("re_") and saved != "resend"):
                        a = {**a, "provider": detected}
                apis.append(a)
        _raw_owas = data.get("owas") or ([data["owa"]] if isinstance(data.get("owa"), dict) else data.get("owa", []))
        owas = []
        for o in (_raw_owas or []):
            if not isinstance(o, dict):
                continue
            owas.append({
                **o,
                "ewsUrl": o.get("ewsUrl", o.get("url", "")),
                "email": o.get("email", o.get("username", "")),
                "oauthToken": o.get("oauthToken", o.get("token", "")),
            })

        _raw_crms = data.get("crms") or ([data["crm"]] if isinstance(data.get("crm"), dict) else data.get("crm", []))
        crms = []
        for c in (_raw_crms or []):
            if not isinstance(c, dict):
                continue
            crms.append({
                **c,
                "endpoint": c.get("endpoint", c.get("url", "")),
                "apiKey": c.get("apiKey", c.get("token", "")),
            })
        tunnels = data.get("tunnels") or data.get("ispTunnels") or []
        tunnels = [t for t in (tunnels or []) if isinstance(t, dict)]

        raw_senders = data.get("senders") or data.get("fromEmails", [])
        senders     = []
        from_name   = data.get("fromName", "")
        from_names  = data.get("fromNames", []) or ([from_name] if from_name else [])
        reply_to    = data.get("replyTo", "")
        reply_tos_raw = data.get("replyTos", [])
        if isinstance(reply_tos_raw, str):
            reply_tos_raw = [r.strip() for r in reply_tos_raw.split("\n") if r.strip()]
        reply_tos = reply_tos_raw or ([reply_to] if reply_to else [])

        for idx_s, s in enumerate(raw_senders or []):
            fname = from_names[0] if from_names else from_name
            if isinstance(s, dict):
                if not s.get("fromName"):
                    s = {**s, "fromName": fname}
                senders.append(s)
            elif isinstance(s, str) and "@" in s:
                senders.append({"fromEmail": s, "fromName": fname, "replyTo": reply_to})

        raw_leads = data.get("leads", [])
        leads = []
        for l in raw_leads:
            if isinstance(l, dict):
                leads.append(l)
            elif isinstance(l, str):
                leads.append({"email": l, "name": "", "company": ""})

        return cls(
            method         = method,
            smtps          = smtps,
            apis           = apis,
            owas           = owas,
            crms           = crms,
            tunnels        = tunnels,
            senders        = senders,
            subjects       = data.get("subjects") or ([data["subject"]] if data.get("subject") else [""]),
            leads          = leads,
            html_body      = data.get("htmlBody") or data.get("html", ""),
            html_bodies    = data.get("htmlBodies") or [],
            plain_body     = data.get("plainBody") or data.get("plain", ""),
            reply_tos      = reply_tos,
            rotation       = data.get("rotation", None) or {
                "sender": data.get("rotationMode", "random"),
                "smtp":   data.get("rotationMode", "random"),
                "mx":     data.get("rotationMode", "random"),
            },
            paired_mode    = bool(data.get("pairedMode", False)),
            dlv            = data.get("deliverability") or {
                "injectUnsub":  data.get("autoInjectUnsub", False),
                "unsubUrl":     data.get("unsubUrl", ""),
                "unsubEmail":   data.get("unsubEmail", ""),
                "listUnsub":    data.get("listUnsub", False),
                "oneClickUnsub":data.get("oneClickUnsub", False),
                # FIX-G: autoPlain now defaults True — always generate clean plain text
                "autoPlain":         data.get("autoPlainText", True),
                "spamFilter":        data.get("spamFilter", False),
                # FIX-3 note: hideFromEmail no longer injects zero-width chars
                "hideFromEmail":     data.get("hideFromEmail", False),
                "autoFlagEmail":     data.get("autoFlagEmail", False),
                "antiDetect":        data.get("antiDetect", False),
                "allowSyntheticHeaders": bool(data.get("allowSyntheticHeaders", False)),
                "allowRiskyBypass": bool(data.get("allowRiskyBypass", False)),
                "priority":          data.get("emailPriority", "normal"),
                # FIX-D: threadSimulate default changed True → False
                "threadSimulate":    data.get("threadSimulate", False),
                # FIX-E: msExchangeHeaders default changed True → False
                "msExchangeHeaders": data.get("msExchangeHeaders", False),
                "feedbackIdAuto":    data.get("feedbackIdAuto", False),
                "listIdAuto":        data.get("listIdAuto", False),
                "xMailer":           data.get("xMailer", "outlook16"),
                "sensitivity":       data.get("sensitivity", ""),
                # FIX-F: originatingIpAuto default changed True → False
                "originatingIpAuto": data.get("originatingIpAuto", False),
                "gmailDelay":        data.get("gmailDelay", 5),
                "msDelay":           data.get("msDelay", 8),
                "preheader":         data.get("preheader", ""),
                "delayJitter":       bool(data.get("jitter", 0)),
                "jitterRange":       float(data.get("jitter", 0) or 0),
                "domainThrottle":    data.get("domainThrottle", True),
                "rateLimitPause":    data.get("rateLimitPause", True),
                "embedImages":       data.get("embedImages", True),
            },
            sending        = data.get("sending") or {
                "delay":          data.get("delay", 0),
                "delayUnit":      data.get("delayUnit", "seconds"),
                "batchSize":      data.get("batchSize", 0),
                "batchDelay":     data.get("batchDelay", 0),
                "batchDelayUnit": data.get("batchDelayUnit", "seconds"),
                "threads":        data.get("threads", 1),
                "maxConnections": data.get("maxConnections") or data.get("concurrent") or 1,
                "sendsPerSec":    data.get("sendsPerSec", 0),
                "resumeFrom":     data.get("resumeFrom", 0),
                "cooldownEvery":  data.get("cooldownEvery", 0),
                "cooldownSecs":   data.get("cooldownSecs", 60),
                "batchPauseSecs": data.get("batchPauseSecs", 0),
                "htmlRotateMode": data.get("htmlRotateMode", "random"),
            },
            links_cfg      = cls._build_links_cfg_from_data(data),
            custom_headers = data.get("customHeaders") or data.get("headers", []),
            attachments    = data.get("attachments") or {},
            proxy          = cls._build_proxy_cfg(data),
            uid            = data.get("_uid"),
            inbox_profile  = bool(data.get("inboxProfile", True)),
            skip_preflight_dns = bool(data.get("skipPreflightDns", False)),
            bcc_mode           = bool(data.get("bccMode", False)),
            bcc_max            = int(data.get("bccMax", 5)),
            subject_encoding   = int(data.get("subjectEncoding", 0)),
            link_method        = int(data.get("linkMethod", 0)),
            b2b_cfg            = data.get("b2bConfig") or data.get("b2b") or {},
        )


# ═══════════════════════════════════════════════════════════════
# CAMPAIGN RUNNER  (unchanged from original — imports updated above)
# ═══════════════════════════════════════════════════════════════
# The run_campaign() and _send_one() functions from the original
# campaign.py are preserved unchanged here — all fixes above are in
# CampaignOptions.from_dict() defaults and module-level imports.
# Import the original run_campaign body from the shipped campaign.py
# and paste below this comment in your deployment.
#
# The key change callers will notice:
#   • Plain text is always generated when not supplied (FIX-G)
#   • threadSimulate, msExchangeHeaders, originatingIpAuto are off by default
#   • spam_filter.inject_invisible_chars() uses safe entropy, not ZWSP


def _is_rate_limit(error_str: str) -> bool:
    e = error_str.lower()
    return any(x in e for x in [
        "too many", "rate limit", "throttl", "4.7.0",
        "try again later", "service busy", "resources temporarily unavailable",
    ])


def _is_sender_policy_error(error_str: str) -> bool:
    """True if the failure is specifically about the FROM address being rejected."""
    e = error_str.lower()
    return any(x in e for x in [
        "aup#pol", "sender rejected", "sender not authorized",
        "sender address rejected", "sender policy",
        "mail from not allowed", "your email address has been blocked",
        "envelope sender",
    ])


def _is_infrastructure_error(error_str: str) -> bool:
    """True if the failure is a proxy/network/transient issue (not sender-specific)."""
    e = error_str.lower()
    return any(x in e for x in [
        "connection refused", "connection reset", "connection closed",
        "connection unexpectedly closed", "socket error", "socket closed",
        "timed out", "timeout", "eof occurred", "broken pipe",
        "network unreachable", "no route", "socks", "proxy",
        "aup#mxrt", "temporarily unavailable", "greylisted", "greylist",
        "domain skipped", "sender removed",
        "ip blocked", "blacklist", "poor reputation",  # proxy IP issues — not sender faults
        "ssl/tls error",  # proxy TLS negotiation failure — not sender's fault
    ])


# ═══════════════════════════════════════════════════════════════
# CAMPAIGN OPTIONS


def _preflight_tunnels(opts: CampaignOptions) -> Generator:
    """
    Open SSH/ISP SOCKS5 tunnels and test connectivity.
    Yields info/error events.
    Returns list of opened local ports via side-effect on opts (opts._opened_ports).
    """
    import socket as _socket

    # For ISP tunnels, smtp is provided via the tunnel ispSmtpHost
    isp_tunnels = [t for t in opts.tunnels if t.get("tunnelType") == "isp"]
    has_smtp    = bool(opts.smtps) or bool(isp_tunnels)
    opened: list = []
    opts._opened_ports = opened  # type: ignore[attr-defined]

    if isp_tunnels:
        # Distinguish direct niceproxy from legacy RDP→3proxy path
        _direct = [t for t in isp_tunnels if t.get("proxyHost")]
        _rdp    = [t for t in isp_tunnels if not t.get("proxyHost") and t.get("sshHost")]
        if _direct and not _rdp:
            mode_msg = f"Mode: ISP Proxy (direct) — {len(_direct)} proxy → ISP SMTP"
        elif _rdp and not _direct:
            mode_msg = f"Mode: ISP Proxy (via RDP) — {len(_rdp)} RDP → ISP SMTP"
        else:
            mode_msg = f"Mode: ISP Proxy — {len(isp_tunnels)} connection(s) → ISP SMTP"
    elif opts.smtps:
        mode_msg = f"Mode: SMTP relay via SSH tunnel — {len(opts.smtps)} SMTP server(s)"
    else:
        mode_msg = "Mode: Direct-to-MX — sending on port 25 via tunnel."
    yield {"type": "info", "msg": mode_msg}

    # Check PySocks is available
    try:
        import socks as _socks
    except ImportError:
        yield {
            "type": "error",
            "msg": "FATAL: PySocks not installed. Run: pip install pysocks --break-system-packages",
        }
        return

    for t in opts.tunnels:
        tt = t.get("tunnelType", "ssh")
        label = t.get("label", t.get("sshHost", "?"))

        if tt == "ssh" and t.get("sshHost"):
            # ── Open SSH SOCKS5 ──
            try:
                lp = open_ssh_socks(t)
                opened.append(lp)
                yield {
                    "type": "info",
                    "msg": f"✓ SSH SOCKS5 opened: 127.0.0.1:{lp} via {t.get('sshHost')} — traffic exits from tunnel IP",
                }
            except Exception as exc:
                yield {"type": "error", "msg": f"SSH SOCKS failed ({label}): {exc}"}
                continue

            proxy_h, proxy_p = "127.0.0.1", lp

        elif tt == "isp":
            # Use niceproxy.io directly if credentials available, else fall back to RDP 3proxy
            if t.get("proxyHost"):
                proxy_h = t.get("proxyHost", "")
                proxy_p = _safe_int(t.get("proxyPort", "17521"), 17521)
            elif t.get("sshHost"):
                proxy_h = t.get("sshHost", "")
                proxy_p = _safe_int(t.get("socksPort", "1080"), 1080)
            else:
                continue
        else:
            continue

        # ── Test SOCKS5 connectivity ──
        try:
            import socks as _tsocks
            _ts = _tsocks.socksocket(_socket.AF_INET, _socket.SOCK_STREAM)
            _ts.set_proxy(
                _tsocks.SOCKS5, proxy_h, proxy_p,
                username=t.get("proxyUser") or t.get("sshUser") or None,
                password=t.get("proxyPass") or t.get("sshKey") or None,
            )
            _ts.settimeout(12)
            _ts.connect(("httpbin.org", 80))
            _ts.close()
            yield {
                "type": "info",
                "msg": f"✓ SOCKS5 connectivity OK through {proxy_h}",
            }
        except Exception as exc:
            es = str(exc)
            if "0x02" in es or "not allowed" in es.lower():
                msg = f"✗ SOCKS5 BLOCKED on {label} (0x02). Check: username format, subscription, host:port"
            elif "auth" in es.lower():
                msg = f"✗ SOCKS5 auth FAILED on {label} — {es[:100]}"
            else:
                msg = f"✗ SOCKS5 FAILED on {label} — {es[:120]}"
            yield {"type": "error", "msg": msg}

        # ── Test port 25 if direct-to-MX mode ──
        if not has_smtp:
            try:
                import socks as _psocks
                _p = _psocks.socksocket(_socket.AF_INET, _socket.SOCK_STREAM)
                _p.set_proxy(
                    _psocks.SOCKS5, proxy_h, proxy_p,
                    username=t.get("proxyUser") or t.get("sshUser") or None,
                    password=t.get("proxyPass") or t.get("sshKey") or None,
                )
                _p.settimeout(12)
                _p.connect(("gmail-smtp-in.l.google.com", 25))
                banner = _p.recv(1024).decode("utf-8", errors="replace").strip()[:80]
                _p.close()
                yield {"type": "info", "msg": f"✓ Port 25 OK via {label} — {banner}"}
            except Exception as p25exc:
                p25s = str(p25exc)
                if "0x02" in p25s or "not allowed" in p25s.lower():
                    msg = (
                        f"✗ Port 25 BLOCKED via {label} (0x02). "
                        "VPS provider blocks outbound SMTP. "
                        "Add SMTP relay servers to use port 587 mode instead."
                    )
                else:
                    msg = (
                        f"✗ Port 25 FAILED via {label} — {p25s[:100]}. "
                        "Add SMTP relay servers to use port 587 mode instead."
                    )
                yield {"type": "error", "msg": msg}


# ═══════════════════════════════════════════════════════════════
# SEND DISPATCH
# ═══════════════════════════════════════════════════════════════

def _send_one(
    opts:    CampaignOptions,
    i:       int,
    lead:    dict,
    sender:  dict,
    server:  dict,
    subject: str,
    html:    str,
    plain:   str,
    pool:    SmtpPool,
    mx_ctx:  MxSenderContext,
    override_proxy: dict = None,
    dead_proxies:   set  = None,
) -> tuple:
    """
    Dispatch a single send through the appropriate module.

    Returns:
        (True,  "", via_label)  on success
        (False, error_msg, via_label) on failure
    """
    method = opts.method
    dlv    = opts.dlv
    hdrs   = opts.custom_headers

    # Default via label — overridden below per method
    via = server.get("label", server.get("provider",
                     server.get("host", method)))

    # ─── SMTP ────────────────────────────────────────────────
    if method == "smtp":
        proxy_cfg = None
        if override_proxy:
            proxy_cfg = override_proxy
            via += f" via {proxy_cfg.get('type','socks5')}:{proxy_cfg.get('host','')}"
        elif opts.proxy:
            pl  = opts.proxy.get("list", [])
            rot = opts.proxy.get("rotation", "random")
            if pl:
                _live_pl = [p for p in pl if (p.get("host","") if isinstance(p,dict) else str(p)) not in (dead_proxies or set())]
                proxy_cfg = _pick(_live_pl or pl, rot, i)
                if proxy_cfg:
                    via += f" via {proxy_cfg.get('type','proxy')}:{proxy_cfg.get('host','')}"
        # Note: SSL (port 465) connections through SOCKS5 are auto-downgraded to STARTTLS/587
        # in smtp_sender._open_connection — so proxy works transparently with all encryption modes.
        try:
            via_used = send_smtp(
                smtp_cfg        = server,
                sender          = sender,
                lead            = lead,
                resolved_html   = html,
                resolved_plain  = plain,
                resolved_subj   = subject,
                dlv             = dlv,
                custom_headers  = hdrs,
                proxy_cfg       = proxy_cfg,
                pool            = pool,
                attachments     = opts.attachments or {},
                envelope_from   = server.get("envelope_from", ""),
                smtp_auth_email = server.get("smtp_auth_email", ""),
            )
            return True, "", via_used or via
        except Exception as exc:
            return False, _parse_smtp_error(exc, lead.get("email", "")), via

    # ─── MX-direct ──────────────────────────────────────────
    # Send straight to the recipient's MX records on port 25, optionally
    # through a SOCKS5/HTTP proxy from the normal pool. No SMTP relay.
    elif method == "mx":
        proxy_cfg = None
        if override_proxy:
            proxy_cfg = override_proxy
        else:
            proxy_cfg = _pick_pool_proxy(opts, i, dead_proxies)
        from_email  = sender.get("fromEmail", "")
        ehlo_domain = (
            (dlv or {}).get("ehloDomain", "")
            or (from_email.split("@")[-1] if "@" in from_email else "")
            or "mail.local"
        )
        try:
            msg, _ = build_message(
                lead        = lead,
                sender      = sender,
                subject     = subject,
                html        = html,
                plain       = plain,
                dlv         = dlv,
                custom_hdrs = hdrs,
                ehlo_domain = ehlo_domain,
                preheader   = (dlv or {}).get("preheader", ""),
                attachments = opts.attachments or {},
            )
            mx_host = send_direct_mx(
                lead_email  = lead["email"],
                sender      = sender,
                msg         = msg,
                ehlo_domain = ehlo_domain,
                socks_proxy = proxy_cfg,
                ctx         = mx_ctx,
            )
            via_label = f"MX:{mx_host}"
            if proxy_cfg:
                via_label = f"{proxy_cfg.get('type','proxy')}:{proxy_cfg.get('host','')} → MX:{mx_host}"
            return True, "", via_label
        except Exception as exc:
            return False, _parse_smtp_error(exc, lead.get("email", "")), (
                f"{proxy_cfg.get('host','')} → MX" if proxy_cfg else "MX")

    # ─── TUNNEL ─────────────────────────────────────────────
    elif method == "tunnel":
        tun = server     # server IS the tunnel config in tunnel method
        tt  = tun.get("tunnelType", "ssh")

        if tt == "isp":
            # Use niceproxy.io (ISP proxy) directly as SOCKS5 if credentials present
            # Fall back to RDP's 3proxy if no direct proxy credentials
            proxy_host = tun.get("proxyHost", "")
            proxy_port = int(tun.get("proxyPort", 17521))
            proxy_user = tun.get("proxyUser") or None
            proxy_pass = tun.get("proxyPass") or None

            if proxy_host:
                # Direct mode: VPS → niceproxy.io (SOCKS5) → smtp.shaw.ca:25
                if dead_proxies and proxy_host in dead_proxies:
                    return False, f"IP BLOCKED — proxy {proxy_host} is blacklisted (skipping)", f"ISP {proxy_host}"
                sock_ok, sock_msg = _check_socks5(proxy_host, proxy_port, timeout=8)
                if not sock_ok:
                    return False, f"ISP proxy {proxy_host}:{proxy_port} unreachable — {sock_msg}. Check proxy credentials.", f"ISP {proxy_host}"
                proxy = {
                    "type":     "socks5",
                    "host":     proxy_host,
                    "port":     str(proxy_port),
                    "username": proxy_user,
                    "password": proxy_pass,
                }
                proxy_label = f"ISP {tun.get('label', proxy_host)} via {proxy_host}"
            else:
                # Legacy mode: VPS → RDP:1080 (3proxy) → ISP → smtp
                socks_host = tun.get("socksHost") or tun.get("sshHost", "")
                socks_port = int(tun.get("socksPort", 1080))
                sock_ok, sock_msg = _check_socks5(socks_host, socks_port, timeout=5)
                if not sock_ok:
                    ssh_pass   = tun.get("sshPass") or tun.get("rdpPass", "")
                    ssh_user   = tun.get("sshUser") or tun.get("rdpUser", "Administrator")
                    ssh_port_n = int(tun.get("rdpSshPort", 22))
                    if ssh_pass:
                        _restart_3proxy_via_ssh(socks_host, ssh_user, ssh_pass, ssh_port_n)
                        import time as _t; _t.sleep(4)
                        sock_ok, sock_msg = _check_socks5(socks_host, socks_port, timeout=5)
                    if not sock_ok:
                        return False, f"SOCKS5 {socks_host}:{socks_port} unreachable — {sock_msg}. 3proxy may be down.", f"ISP {socks_host}"
                proxy = {
                    "type":     "socks5",
                    "host":     socks_host,
                    "port":     str(socks_port),
                    "username": None,
                    "password": None,
                }
                proxy_label = f"ISP {tun.get('label', socks_host)}"
        else:
            lp = _safe_int(tun.get("localPort", 1080), 1080)
            proxy = {
                "type": "socks5",
                "host": "127.0.0.1",
                "port": str(lp),
            }
            proxy_label = f"SSH {tun.get('label', '')} ({tun.get('sshHost', '')})"

        # Primary: route SMTP relay through tunnel
        # For ISP tunnels: build smtp config from tunnel's ISP SMTP settings
        smtp_pool = opts.smtps

        # ISP-specific: EHLO domain should be the ISP domain (e.g. shaw.ca), not the From domain.
        # fromDomain is auto-filled by the SMTP probe (e.g. "shaw.ca" from "smtp.shaw.ca").
        _isp_ehlo   = tun.get("fromDomain") or tun.get("ehloDomain") or ""
        # smtpFromEmail: a shaw.ca account to use as the MAIL FROM envelope sender.
        # When set, overrides the campaign From for the envelope (fixes SPF).
        _isp_auth_email = tun.get("smtpFromEmail") or tun.get("smtpUser") or ""

        if not smtp_pool and tt == "isp" and tun.get("ispSmtpHost"):
            smtp_pool = [{
                "host":            tun["ispSmtpHost"],
                "port":            int(tun.get("ispSmtpPort", 25)),
                "username":        tun.get("smtpUser", ""),
                "password":        tun.get("smtpPass", ""),
                "encryption":      "NONE",
                "label":           f"ISP SMTP ({tun['ispSmtpHost']})",
                "smtp_auth_email": _isp_auth_email,
                "ehlo_override":   _isp_ehlo,
                # envelope_from: if set, overrides MAIL FROM to match ISP-authorized address
                "envelope_from":   _isp_auth_email,
            }]
        if smtp_pool:
            rot      = opts.rotation.get("smtp", "random")
            smtp_srv = _pick(smtp_pool, rot, i)
            srv_lbl  = smtp_srv.get("label", smtp_srv.get("host", "SMTP"))
            import logging as _sl
            _sl.getLogger("synthtel").info(
                "[ISP SEND] SOCKS5=%s:%s (user=%s) → SMTP=%s:%s enc=%s",
                proxy["host"], proxy["port"], proxy.get("username","none"),
                smtp_srv.get("host"), smtp_srv.get("port"), smtp_srv.get("encryption")
            )
            try:
                via_used = send_smtp(
                    smtp_cfg        = smtp_srv,
                    sender          = sender,
                    lead            = lead,
                    resolved_html   = html,
                    resolved_plain  = plain,
                    smtp_auth_email = smtp_srv.get("smtp_auth_email", ""),
                    ehlo_domain     = smtp_srv.get("ehlo_override", ""),
                    envelope_from   = smtp_srv.get("envelope_from", ""),
                    resolved_subj  = subject,
                    dlv            = dlv,
                    custom_headers = hdrs,
                    proxy_cfg      = proxy,
                    pool           = pool,
                    attachments    = opts.attachments or {},
                )
                return True, "", f"{srv_lbl} via {proxy_label}"
            except Exception as exc:
                return False, _parse_smtp_error(exc, lead.get("email", "")), f"{srv_lbl} via {proxy_label}"

        # Fallback: direct-to-MX through tunnel (needs port 25)
        else:
            from_email  = sender.get("fromEmail", "")
            ehlo_domain = (
                tun.get("ehloDomain", "")
                or (from_email.split("@")[-1] if "@" in from_email else "")
                or "mail.local"
            )
            socks_cfg = {
                "host":     proxy["host"],
                "port":     proxy["port"],
                "username": proxy.get("username"),
                "password": proxy.get("password"),
            }
            try:
                msg, _ = build_message(
                    lead        = lead,
                    sender      = sender,
                    subject     = subject,
                    html        = html,
                    plain       = plain,
                    dlv         = dlv,
                    custom_hdrs = hdrs,
                    ehlo_domain = ehlo_domain,
                    preheader   = (dlv or {}).get("preheader", ""),
                    attachments = opts.attachments or {},
                )
                mx_host = send_direct_mx(
                    lead_email  = lead["email"],
                    sender      = sender,
                    msg         = msg,
                    ehlo_domain = ehlo_domain,
                    socks_proxy = socks_cfg,
                    ctx         = mx_ctx,
                )
                return True, "", f"{proxy_label} → MX:{mx_host}"
            except Exception as exc:
                return False, _parse_smtp_error(exc, lead.get("email", "")), f"{proxy_label} → MX"

    # ─── API ────────────────────────────────────────────────
    elif method == "api":
        proxy_cfg = _pick_pool_proxy(opts, i, dead_proxies)
        if proxy_cfg:
            via += f" via {proxy_cfg.get('type','proxy')}:{proxy_cfg.get('host','')}"
        try:
            extra_h = build_api_headers(
                dlv            = dlv,
                lead           = lead,
                custom_headers = hdrs,
                sender         = sender,
            )
            send_api(
                api_cfg          = server,
                sender           = sender,
                lead             = lead,
                resolved_html    = html,
                resolved_subject = subject,
                extra_headers    = extra_h,
                resolved_plain   = plain,
                proxy_cfg        = proxy_cfg,
            )
            return True, "", server.get("label", server.get("provider", "API")) + (
                f" via {proxy_cfg.get('host','')}" if proxy_cfg else "")
        except Exception as exc:
            return False, _parse_smtp_error(exc, lead.get("email", "")), via

    # ─── OWA ─────────────────────────────────────────────────
    elif method == "owa":
        proxy_cfg = _pick_pool_proxy(opts, i, dead_proxies)
        if proxy_cfg:
            via += f" via {proxy_cfg.get('type','proxy')}:{proxy_cfg.get('host','')}"
        try:
            send_owa(
                owa_cfg          = server,
                sender           = sender,
                lead             = lead,
                resolved_html    = html,
                resolved_plain   = plain,
                resolved_subject = subject,
                dlv              = dlv,
                custom_headers   = hdrs,
                proxy_cfg        = proxy_cfg,
            )
            return True, "", server.get("label", server.get("email", "OWA")) + (
                f" via {proxy_cfg.get('host','')}" if proxy_cfg else "")
        except Exception as exc:
            return False, _parse_smtp_error(exc, lead.get("email", "")), via

    # ─── CRM ─────────────────────────────────────────────────
    elif method == "crm":
        proxy_cfg = _pick_pool_proxy(opts, i, dead_proxies)
        if proxy_cfg:
            via += f" via {proxy_cfg.get('type','proxy')}:{proxy_cfg.get('host','')}"
        try:
            send_crm(
                crm_cfg          = server,
                sender           = sender,
                lead             = lead,
                resolved_html    = html,
                resolved_subject = subject,
                i                = i,
                resolved_plain   = plain,
                proxy_cfg        = proxy_cfg,
            )
            return True, "", server.get("label", server.get("provider", "CRM")) + (
                f" via {proxy_cfg.get('host','')}" if proxy_cfg else "")
        except Exception as exc:
            return False, _parse_smtp_error(exc, lead.get("email", "")), via

    # ─── B2B ─────────────────────────────────────────────────
    # B2B is handled in run_campaign directly via B2BSender.
    # _send_one is not called for b2b — the generator handles it.
    return False, f"Unknown send method: {method}", via


# ═══════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════



def run_campaign(opts: CampaignOptions) -> Generator:
    """
    Generator — orchestrates a full sending campaign.
    Yields JSON-serialisable event dicts.
    """
    method  = opts.method
    dlv     = opts.dlv
    sending = opts.sending
    campaign_uid = getattr(opts, "uid", None)
    inbox_profile = bool(getattr(opts, "inbox_profile", True))

    # Safety clamp: keep risky synthetic/bypass behavior off by default unless
    # explicitly enabled by expert flags in the payload.
    if not dlv.get("allowSyntheticHeaders", False):
        dlv["threadSimulate"] = False
        dlv["arcSimulate"] = False
        dlv["msExchangeHeaders"] = False
        dlv["hideFromEmail"] = False
        dlv["antiDetect"] = False
    if not dlv.get("allowRiskyBypass", False):
        dlv["bypassMode"] = False
        dlv["bypassZeroFont"] = False
        dlv["bypassComments"] = False
        dlv["bypassInnat"] = False
        dlv["bypassNoisePixel"] = False
        dlv["bypassStyleVariation"] = False

    # Inbox profile: enforce conservative defaults that favor placement over tricks.
    if inbox_profile:
        dlv["autoPlain"] = True
        dlv["domainThrottle"] = True
        dlv["rateLimitPause"] = True
        dlv["priority"] = "normal"
        dlv["autoFlagEmail"] = False
        dlv["spamFilter"] = False
        dlv["antiDetect"] = False
        dlv["hideFromEmail"] = False
        dlv["threadSimulate"] = False
        dlv["arcSimulate"] = False
        dlv["msExchangeHeaders"] = False
        if dlv.get("unsubUrl") or dlv.get("unsubEmail"):
            dlv["listUnsub"] = True
            if dlv.get("unsubUrl"):
                dlv["oneClickUnsub"] = True
        else:
            dlv["oneClickUnsub"] = False
        if opts.skip_preflight_dns:
            opts.skip_preflight_dns = False

    # ── Parse timing config ──────────────────────────────────
    delay      = _safe_float(sending.get("delay", 0), 0.0)
    delay_unit = sending.get("delayUnit", "seconds")
    base_delay = delay * DELAY_UNITS.get(delay_unit, 1)
    batch_size = _safe_int(sending.get("batchSize", 50), 50)
    cooldown_every   = _safe_int(sending.get("cooldownEvery", 0), 0)
    cooldown_secs    = _safe_float(sending.get("cooldownSecs", 60), 60.0)
    batch_pause_secs = _safe_float(sending.get("batchPauseSecs", 0), 0.0)
    html_rotate_mode = sending.get("htmlRotateMode", "random")
    max_connections  = _safe_int(sending.get("maxConnections", 1), 1)
    sends_per_sec    = _safe_float(sending.get("sendsPerSec", 0), 0.0)
    resume_from      = _safe_int(sending.get("resumeFrom", 0), 0)
    proxy_list_raw   = opts.proxy.get("list", []) if opts.proxy else []
    if proxy_list_raw and max_connections > len(proxy_list_raw):
        max_connections = len(proxy_list_raw)
    max_connections  = max(1, min(max_connections, 50))

    jitter_range = _safe_float(dlv.get("jitterRange", 3), 3.0)

    # ── Warmup cap ───────────────────────────────────────────
    warmup_day = _safe_int(dlv.get("warmupDay", 1), 1)
    if dlv.get("warmup"):
        max_emails = WARMUP_LIMITS.get(warmup_day, WARMUP_LIMITS[5])
        yield {
            "type": "warmup",
            "msg": (
                f"Warmup day {warmup_day}: "
                f"sending up to {max_emails:,} emails "
                f"out of {len(opts.leads):,} leads"
            ),
        }
    else:
        max_emails = len(opts.leads)

    if inbox_profile:
        yield {"type": "info", "msg": "🛡 Inbox profile enabled — enforcing safe headers, plain-text MIME, and conservative pacing"}
        if len(opts.leads) >= 500 and not (dlv.get("unsubUrl") or dlv.get("unsubEmail")):
            yield {"type": "warn", "msg": "⚠ Bulk send without unsubscribe URL/email can reduce Gmail/Yahoo inbox placement"}

    total_cap = min(len(opts.leads), max_emails) if dlv.get("warmup") else len(opts.leads)

    # ── Server pool ──────────────────────────────────────────
    # ── B2B shortcut — handled entirely separately via B2BSender ─────────────
    if method == "b2b":
        if not _HAS_B2B:
            yield {"type": "error", "msg": "B2B module not available — core.b2b_manager could not be imported (run `pip install msal requests`)"}
            return
        if not opts.b2b_cfg:
            yield {"type": "error", "msg": "B2B: no mailbox configured — add B2B credentials in Method → B2B tab"}
            return
        _b2b = b2b_from_cfg(opts.b2b_cfg)
        tok_ok = bool(_b2b._tm.get_token())
        if not tok_ok:
            yield {"type": "error", "msg": "B2B: invalid or expired token — re-authenticate in B2B settings"}
            return
        # List threads from the configured folder
        _b2b_folder = opts.b2b_cfg.get("folder", "Inbox")
        _b2b_limit  = opts.b2b_cfg.get("threadLimit", 200)
        try:
            threads = _b2b.list_threads(folder=_b2b_folder, limit=_b2b_limit)
        except Exception as _be:
            yield {"type": "error", "msg": f"B2B: failed to list threads — {_be}"}
            return
        if not threads:
            yield {"type": "warn", "msg": f"B2B: no threads found in {_b2b_folder}"}
            return
        yield {"type": "info", "msg": f"B2B: {len(threads)} threads loaded from {_b2b_folder}"}
        _b2b_html = opts.html_body or (opts.html_bodies[0] if opts.html_bodies else "")
        _b2b_delay = (
            float(opts.b2b_cfg.get("delayMin", 3)),
            float(opts.b2b_cfg.get("delayMax", 8)),
        )
        # Pick a proxy from the normal pool (if any) — same path used by
        # SMTP/MX/API/OWA/CRM. B2B doesn't rotate per-send (single
        # account-bound session), so we pick once at the start.
        _b2b_proxy = _pick_pool_proxy(opts, 0, set())
        if _b2b_proxy:
            yield {"type": "info",
                   "msg": f"B2B: routing through {_b2b_proxy.get('type','proxy')}:{_b2b_proxy.get('host','')}"}
        yield from _b2b.run_campaign(
            threads     = threads,
            html        = _b2b_html,
            leads       = opts.leads,
            delay_range = _b2b_delay,
            max_sends   = min(len(opts.leads), len(threads)) if opts.leads else 0,
            proxy_cfg   = _b2b_proxy,
        )
        return

    # MX-direct has no per-server pool (it sends straight to recipient
    # MX records). Use a single placeholder "server" so the iteration
    # loop works the same way as every other method.
    _mx_placeholder = [{"label": "MX-direct", "host": "mx"}]
    pool_map = {
        "smtp":   opts.smtps,
        "mx":     _mx_placeholder,
        "api":    opts.apis,
        "owa":    opts.owas,
        "crm":    opts.crms,
        "tunnel": opts.tunnels,
    }
    servers = pool_map.get(method, opts.smtps) or []

    # ISP/tunnel info — use correct label for what the user actually configured
    if method == "tunnel":
        _is_isp_direct = any(t.get("proxyHost") for t in opts.tunnels if t.get("tunnelType") == "isp")
        _method_label  = "ISP proxies" if _is_isp_direct else "SSH tunnels"
        yield {"type": "info", "msg": f"{_method_label} loaded: {len(opts.tunnels)} — {'ready' if opts.tunnels else 'NONE FOUND — add proxies in ISP tab'}"}

    if method == "mx":
        _mx_proxy_count = len((opts.proxy or {}).get("list") or [])
        yield {
            "type": "info",
            "msg": (
                f"MX direct: {_mx_proxy_count} proxy(ies) loaded — sending straight to recipient MX:25"
                if _mx_proxy_count > 0 else
                "MX direct (no proxy): sending straight to recipient MX:25 — only works if your VPS allows outbound port 25"
            ),
        }

    if not servers and method not in ("smtp", "mx"):
        if method == "tunnel":
            yield {
                "type": "error",
                "msg": "No ISP proxies configured — add proxies in the ISP tab and try again",
            }
        else:
            yield {
                "type": "error",
                "msg": f"No {method.upper()} servers configured — campaign cannot start",
            }
        return

    if not servers and method == "smtp":
        yield {
            "type": "error",
            "msg": "No SMTP servers configured — add one in Method → SMTP tab first",
        }
        return

    # ── Sender/server pairing ────────────────────────────────
    sender_rot = opts.rotation.get("sender", "random")
    srv_rot    = opts.rotation.get(method, opts.rotation.get("smtp", "random"))

    pairs: Optional[list] = None
    if opts.paired_mode and opts.senders and servers:
        pairs = [
            {"sender": opts.senders[j], "server": servers[j % len(servers)]}
            for j in range(len(opts.senders))
        ]

    # ── Tunnel preflight ─────────────────────────────────────
    if method == "tunnel":
        yield from _preflight_tunnels(opts)

    # ── Reset per-campaign state in pooled modules ───────────
    # ISP method (Shaw/ISP SMTP): limit to 50 sends per connection.
    # Shaw and most ISP SMTPs throttle or 421 after ~50–100 msgs on one session.
    # Forcing a reconnect every 50 msgs avoids that entirely.
    _isp_tunnels_active = [t for t in opts.tunnels if t.get("tunnelType") == "isp"]
    if _isp_tunnels_active:
        reset_global_pool(max_sends_per_conn=50, idle_timeout=120)
    else:
        reset_global_pool()
    pool   = get_global_pool()
    reset_global_ctx()
    mx_ctx = get_global_ctx()

    # ── Pre-resolve #RANDOMSTR in sender fromEmails ──────────────
    # Must happen before preflight DNS so domains are real before MX lookup.
    import re as _re_rstr, random as _rnd_rstr, string as _str_rstr
    def _mk_rstr(n=8): return "".join(_rnd_rstr.choices(_str_rstr.ascii_lowercase + _str_rstr.digits, k=n))
    for _s in opts.senders:
        if isinstance(_s, dict):
            fe = _s.get("fromEmail", "")
            if "#RANDOMSTR" in fe:
                _s["fromEmail"] = _re_rstr.sub(r"#RANDOMSTR", lambda _m: _mk_rstr(8), fe)

    # ── Sender MX preflight (tunnel/MX methods only) ─────────
    # Resolve MX records for all sender domains before sending starts.
    # Removes senders with no MX (they'll never work).
    # If >25% are bad, warns and suggests running the From Mail Validator.
    if method == "tunnel" and opts.senders and not opts.skip_preflight_dns:
        _pf = preflight_check_senders(opts.senders, threshold_pct=25.0)
        if _pf["bad"]:
            _removed = len(_pf["bad"])
            _total_s = len(opts.senders)
            _bad_set  = set(_pf["bad"])
            # Remove senders with no MX — ISPs (Shaw etc.) issue AUP#DNS for every send,
            # burning the lead with no chance of delivery. Keep only DNS-verified senders.
            if _pf["ok"]:
                opts.senders[:] = [s for s in opts.senders
                                   if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _bad_set]
                yield {
                    "type": "warn",
                    "msg": (
                        f"⚠ Pre-flight DNS: removed {_removed}/{_total_s} sender domain(s) with no MX records "
                        f"(ISPs reject these as AUP#DNS — enable Skip Preflight DNS to keep them): "
                        f"{', '.join(_pf['bad'][:5])}"
                        + (f" (+{_removed-5} more)" if _removed > 5 else "")
                    ),
                }
            else:
                # ALL senders failed DNS — keep them all and warn, since removing everything
                # would abort the campaign. Could be a transient DNS issue.
                yield {
                    "type": "warn",
                    "msg": (
                        f"⚠ Pre-flight DNS: all {_total_s} sender domain(s) failed MX lookup — "
                        f"keeping all senders (may be transient DNS issue). Enable Skip Preflight DNS to suppress."
                    ),
                }
            if _pf["warn_threshold_exceeded"] and _pf["ok"]:
                yield {
                    "type": "warn",
                    "msg": (
                        f"⚠ {_pf['bad_pct']:.0f}% of your From emails had DNS issues and were removed — "
                        f"run them through the From Mail Validator to clean your sender list."
                    ),
                }
        else:
            yield {"type": "info", "msg": f"✓ Pre-flight DNS: all {len(opts.senders)} sender domain(s) resolved OK"}

    # ── Per-sender consecutive failure tracker ────────────────
    # Tracks from-address errors (not proxy/network errors).
    # After 3 consecutive from-address failures, removes sender from rotation.
    _sender_fail_counts: dict = {}   # fromEmail → consecutive from-address fail count
    _dead_senders: set = set()       # fromEmails removed mid-campaign (AUP#POL or 3 strikes)
    _demoted_senders: list = []      # fromEmails demoted to end of list (AUP#MXRT)

    def _is_aup_pol(err_str: str) -> bool:
        """True for AUP/policy rejections that warrant trying a different sender."""
        s = (err_str or "").lower()
        return any(x in s for x in [
            "aup#pol",
            "aup#dns",        # sender domain has no MX/A — rotate to a valid sender domain
            "policy violation",
            "sending policy",
            "sender policy",
            "5.7.1 sender",   # 5.7.1 specifically about the sender address
            "address rejected",
            "from address rejected",
            "sender address rejected",
            "sender rejected",  # Shaw/ISP envelope rejection of bad sender domain
        ])

    def _is_aup_mxrt(err_str: str) -> bool:
        return "aup#mxrt" in (err_str or "").lower() or "temporarily unavailable" in (err_str or "").lower()

    # Sender health: score-based (not simple strike count)
    # Score starts at 100. Auth/policy errors = -100 (instant kill).
    # Soft/unknown errors = -25. Success = +10 (capped at 100).
    # Dead threshold: score <= 0. Demote threshold: score <= 40.
    _sender_scores:  dict = {}   # fromEmail → health score (0–100)

    def _get_score(fe: str) -> int:
        return _sender_scores.get(fe, 100)

    def _is_auth_error(err_str: str) -> bool:
        """True for hard sender-credential failures — instant kill appropriate."""
        s = (err_str or "").lower()
        # Core SMTP auth failures — credentials are definitely wrong
        cred_fail = any(x in s for x in [
            "authentication", "535", "530", "username", "password",
            "relay denied", "relay not permitted",
        ])
        if cred_fail:
            return True
        # AUP/policy blocks — sender account suspended/banned at the provider level
        if "aup#pol" in s:
            return True
        # 5.7.0/5.7.1 can be auth OR content — only treat as auth if "relaying" or "not authorized"
        if ("5.7.0" in s or "5.7.1" in s) and any(x in s for x in ["relay", "not authorized", "not permitted to send"]):
            return True
        # "access denied" / "banned" — only if explicitly about the sender, not IP
        if any(x in s for x in ["account suspended", "account banned", "account blocked", "mailbox disabled"]):
            return True
        # NOTE: "sender rejected", "not permitted", "banned", "access denied" alone are NOT auth errors —
        # they can be content-based (spam filter) or IP-based blocks. Don't instant-kill for those.
        return False

    def _is_soft_error(err_str: str) -> bool:
        s = (err_str or "").lower()
        return any(x in s for x in [
            "quota", "over limit", "too many", "message limit",
            "aup#mxrt", "temporarily unavailable",
        ])

    def _record_sender_fail(from_email: str, err_str: str) -> bool:
        """Deduct health score. Returns True if sender just died."""
        if not from_email or _is_infrastructure_error(err_str):
            return False
        if from_email in _dead_senders:
            return False
        cur = _get_score(from_email)
        if _is_auth_error(err_str):
            deduct = 100   # instant kill
        elif _is_soft_error(err_str):
            deduct = 15    # soft — demote but keep alive longer
        else:
            deduct = 30    # unknown SMTP error
        new_score = max(0, cur - deduct)
        _sender_scores[from_email] = new_score
        if new_score <= 0:
            # Never remove the last remaining live sender — campaign would immediately stop.
            # Keep it with score=1 so it stays in rotation and the user sees failures per-lead
            # rather than a sudden "all senders removed" abort.
            _live_count = len([s for s in opts.senders
                               if (s.get("fromEmail","") if isinstance(s,dict) else s)
                               not in _dead_senders])
            if _live_count <= 1:
                _sender_scores[from_email] = 1  # floor at 1 — keep alive
                return False
            _dead_senders.add(from_email)
            return True
        return False

    def _demote_sender(from_email: str):
        """Move sender to end of opts.senders when score is low."""
        if not from_email or from_email in _dead_senders or from_email in _demoted_senders:
            return
        _demoted_senders.append(from_email)
        non_dem = [s for s in opts.senders if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _demoted_senders]
        dem     = [s for s in opts.senders if (s.get("fromEmail","") if isinstance(s,dict) else s) in _demoted_senders]
        opts.senders = non_dem + dem

    def _record_sender_ok(from_email: str):
        old = _get_score(from_email)
        _sender_scores[from_email] = min(100, old + 10)
        if from_email in _demoted_senders and _get_score(from_email) > 40:
            _demoted_senders.remove(from_email)  # recover from demotion on sustained success

    # ── Real-time failed lead writer ─────────────────────────────────────────
    # Failed leads are appended to a single file immediately on failure,
    # so if the campaign is stopped mid-run the file is always up to date.
    import datetime as _dt2, uuid as _uuid2, re as _re2, sqlite3 as _sql3
    _fail_ts       = _dt2.datetime.now().strftime("%Y%m%d_%H%M%S")
    _fail_name     = f"failed_leads_{_fail_ts}.txt"
    _fail_uid      = getattr(opts, "uid", None) or ""
    _fail_file_id  = None
    _failed_count  = 0
    _fail_fpath    = None

    def _init_fail_file():
        nonlocal _fail_file_id, _fail_fpath
        if _fail_file_id or not _fail_uid:
            return
        try:
            from core.server import DB_PATH, FILES_DIR
            _safe     = _re2.sub(r'[^\w\.\-]', '_', _fail_name)
            _filename = f"{_uuid2.uuid4().hex[:8]}_{_safe}"
            _user_dir = os.path.join(FILES_DIR, str(_fail_uid), "leads")
            os.makedirs(_user_dir, exist_ok=True)
            _fpath_l  = os.path.join(_user_dir, _filename)
            with open(_fpath_l, "w") as _ff:
                _ff.write("email\n")
            _conn = _sql3.connect(DB_PATH)
            cur   = _conn.execute(
                "INSERT INTO user_files (user_id,category,filename,orig_name,mime_type,size_bytes) VALUES (?,?,?,?,?,?)",
                (_fail_uid, "leads", _filename, _fail_name, "text/plain", 6)
            )
            _fail_file_id = cur.lastrowid
            _conn.commit(); _conn.close()
            _fail_fpath = _fpath_l
        except Exception:
            pass

    def _append_fail(email_addr: str):
        nonlocal _failed_count
        _failed_count += 1
        _init_fail_file()
        if _fail_fpath:
            try:
                with open(_fail_fpath, "a") as _ff:
                    _ff.write(email_addr + "\n")
                # Update file size in DB
                from core.server import DB_PATH
                _sz = os.path.getsize(_fail_fpath)
                _c2 = _sql3.connect(DB_PATH)
                _c2.execute("UPDATE user_files SET size_bytes=? WHERE id=?", (_sz, _fail_file_id))
                _c2.commit(); _c2.close()
            except Exception:
                pass

    # ── Email sorter: group leads by provider for targeted header tuning ───────
    # When sorter available, pre-classify leads so we can apply per-provider
    # delays and header tuning (e.g. slower delay for O365, Gmail-specific headers).
    _provider_map: dict = {}   # email → provider string
    if _HAS_SORTER and opts.leads:
        try:
            _sorted_buckets = sort_leads(opts.leads, workers=10, timeout=20)
            for _prov, _pleads in _sorted_buckets.items():
                for _pl in _pleads:
                    _e = (_pl.get("email") or "").lower()
                    if _e:
                        _provider_map[_e] = _prov
            if _provider_map:
                _counts = {p: len(v) for p, v in _sorted_buckets.items()}
                yield {"type": "info", "msg": "Provider breakdown: " +
                       ", ".join(f"{p}={n}" for p, n in sorted(_counts.items(), key=lambda x: -x[1]))}
        except Exception as _se:
            pass  # sorter failure is non-fatal

    def _get_provider_delay(email: str) -> float:
        """Return extra delay for this email's provider on top of base_delay."""
        if not _provider_map or not dlv.get("domainThrottle"):
            return 0.0
        _prov = _provider_map.get((email or "").lower(), "generic")
        # Per-provider extra delay (on top of base_delay)
        _extras = {"o365": 3.0, "outlook": 2.0, "gmail": 1.0,
                   "mimecast": 4.0, "proofpoint": 4.0, "barracuda": 2.0}
        return _extras.get(_prov, 0.0)

    # ── Run ──────────────────────────────────────────────────
    success = fail = skip = 0
    stopped = False
    opened_ports: list = getattr(opts, "_opened_ports", [])

    # Dead proxy blacklist — proxies that failed are removed from rotation
    _dead_proxies: set = set()

    # Resume support — skip already-processed leads
    effective_start = min(resume_from, total_cap)
    if effective_start > 0:
        yield {"type": "info", "msg": f"▶ Resuming from email #{effective_start+1} ({total_cap - effective_start} remaining)"}

    # ── Concurrent send setup ────────────────────────────────
    # Thread pool workers:
    # - tunnel/isp: one worker per proxy connection (maxConnections)
    # - smtp: concurrent sends to multiple SMTP servers in pool (maxConnections)
    #   The SmtpPool handles connection reuse per-server, so N workers =
    #   N simultaneous sends across N server slots (not N new connections)
    # - api/owa/crm: follow maxConnections too (HTTP is stateless, safe to parallelize)
    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    import threading as _threading
    _workers = max(1, min(max_connections, 128))  # cap at 128 — beyond that adds overhead
    _send_lock = _threading.Lock()   # protects shared counters/state

    # ── Build the full work queue upfront (skip blanks, resolve senders) ──────
    # We pre-build work items so the thread pool can pull from a queue without
    # needing the generator to be re-entered. State-mutating operations
    # (sender removal, counters, yielding) happen in the main thread after
    # each future completes.

    def _pick_sender_locked(i):
        """Pick a live sender under the send lock (thread-safe rotation)."""
        if pairs:
            pair = _pick(pairs, sender_rot, i)
            return pair["sender"], pair["server"]
        _live = [s for s in opts.senders if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders]
        if not _live:
            return None, None
        return _pick(_live, sender_rot, i), (_pick(servers, srv_rot, i) if servers else {})

    def _execute_send(work_item):
        """
        Run in a thread. Does ONLY the network IO — no state mutation.
        Returns (i, lead, ok, err, via, resolved_sender, link_url).
        """
        i, lead, sender, server, subj, html, plain, link_url = work_item
        try:
            ok, err, via = _send_one(
                opts=opts, i=i, lead=lead, sender=sender,
                server=server or {}, subject=subj,
                html=html, plain=plain,
                pool=pool, mx_ctx=mx_ctx,
                dead_proxies=_dead_proxies,
            )
        except Exception as exc:
            ok, err, via = False, f"network error: {exc}", ""
        return (i, lead, ok, err, via, sender, link_url)

    try:
        _executor = ThreadPoolExecutor(max_workers=_workers)
        _pending_futures = {}   # future → work_item
        _work_queue = []        # pre-built work items for leads not yet submitted

        for i, lead in enumerate(opts.leads[:total_cap]):
            if i < effective_start:
                continue
            email_addr = (lead.get("email") or "").strip()
            if not email_addr:
                skip += 1
                yield {"type":"skip","index":i+1,"total":total_cap,"email":"(empty)","msg":"Lead has no email address"}
                continue
            lead.setdefault("name","")
            lead.setdefault("company","")
            _work_queue.append((i, lead))

        # ── Stream results from thread pool ──────────────────────────────────
        def _submit_next(i, lead):
            """Resolve sender + build message, submit to executor."""
            with _send_lock:
                sender, server = _pick_sender_locked(i)
                if sender is None:
                    return None  # no live senders

            # ── Pick subject ──────────────────────────────────
            subj_raw = _pick(opts.subjects, sender_rot, i) or ""

            # ── Rotate from-name independently ────────────────
            # from_names rotates per-send across all leads, not per-sender.
            # This means if you have 3 names and 1 sender email, each lead
            # gets a different display name in the inbox.
            if opts.from_names:
                picked_name = _pick(opts.from_names, sender_rot, i)
            else:
                picked_name = None  # use whatever is baked into the sender dict

            # ── Resolve tags ──────────────────────────────────
            tag_ctx_pre = build_context(lead=lead, sender=sender, subject=subj_raw,
                                        counter=i+1, links_cfg=opts.links_cfg)
            resolved_sender = dict(sender)
            resolved_sender["fromEmail"] = resolve_tags(sender.get("fromEmail",""), tag_ctx_pre)
            # Apply rotated name if available, else fall back to sender's baked name
            resolved_sender["fromName"]  = resolve_tags(
                picked_name if picked_name is not None else sender.get("fromName",""),
                tag_ctx_pre
            )
            # Rotate reply-to independently if multiple provided
            picked_reply = (_pick(opts.reply_tos, sender_rot, i)
                            if opts.reply_tos else sender.get("replyTo",""))
            resolved_sender["replyTo"]   = resolve_tags(picked_reply or "", tag_ctx_pre)
            tag_ctx = build_context(lead=lead, sender=resolved_sender, subject=subj_raw,
                                    counter=i+1, links_cfg=opts.links_cfg)
            resolved_subject = resolve_tags(subj_raw, tag_ctx)

            # Apply subject encoding (method 0 = none, 1-11 = various encodings)
            if opts.subject_encoding and opts.subject_encoding != 0:
                try:
                    from core.spam_filter import encode_subject
                    resolved_subject = encode_subject(resolved_subject, opts.subject_encoding)
                except Exception:
                    pass

            all_bodies = opts.html_bodies if opts.html_bodies else ([opts.html_body] if opts.html_body else [""])
            if len(all_bodies)==1:
                chosen_body = all_bodies[0]
            else:
                # html_rotate_mode can override global rotation; default follows sender_rot
                _body_rot = html_rotate_mode if html_rotate_mode else sender_rot
                chosen_body = _pick(all_bodies, _body_rot, i)
            resolved_html = resolve_tags(chosen_body, tag_ctx)

            if dlv.get("spamFilter"):
                _bypass_mode = dlv.get("bypassMode", False)
                if _bypass_mode:
                    resolved_html, resolved_subject, _rplain = apply_full_bypass(
                        resolved_html, resolved_subject, resolved_plain,
                        word_replace    = True,
                        zero_font       = dlv.get("bypassZeroFont", False),
                        comments        = dlv.get("bypassComments", False),
                        homoglyphs      = dlv.get("bypassHomoglyphs", False),
                        font_rand       = dlv.get("bypassFontRand", False),
                        innat           = dlv.get("bypassInnat", False),
                        noise_pixel     = dlv.get("bypassNoisePixel", False),
                        style_variation = dlv.get("bypassStyleVariation", False),
                        shuffle         = True,
                        homoglyph_rate  = float(dlv.get("bypassHomoglyphRate", 0.35)),
                        zero_intensity  = int(dlv.get("bypassZeroIntensity", 2)),
                    )
                    if _rplain:
                        resolved_plain = _rplain
                else:
                    resolved_html, resolved_subject = apply_spam_filter(resolved_html, resolved_subject)

            import re as _re
            resolved_html = _re.sub(r'href=["\'][#][A-Z][A-Z0-9_]*["\']', 'href="#"', resolved_html)
            # injectUnsub: campaign-level footer injection.
            # Skip if listUnsub is also on — mime_builder._inject_unsub_footer handles that path,
            # and both firing produces a double footer in the email.
            if dlv.get("injectUnsub") and dlv.get("unsubUrl") and not dlv.get("listUnsub"):
                resolved_html = _inject_unsub_link(resolved_html, dlv["unsubUrl"], lead.get("email",""))

            # For API sends (SendGrid, Mailgun, etc.) both html and plain MUST be
            # non-empty strings — the API rejects empty content with a 400 error.
            # Always derive plain from HTML for API method regardless of autoPlain setting.
            if method == "api" or dlv.get("autoPlain") or not opts.plain_body:
                resolved_plain = _strip_html(resolved_html) or resolved_html or " "
            else:
                resolved_plain = resolve_tags(opts.plain_body, tag_ctx)
            # Final safety net — never send empty plain or html to any API
            if method == "api":
                if not resolved_plain or not resolved_plain.strip():
                    resolved_plain = " "
                if not resolved_html or not resolved_html.strip():
                    resolved_html = f"<p>{resolved_plain}</p>"

            link_url = ""
            if opts.links_cfg and opts.links_cfg.get("links"):
                # Filter to links that haven't hit their usage limit
                all_links = opts.links_cfg["links"]
                available = [
                    lk for lk in all_links
                    if lk.get("url") and (not lk.get("limit") or lk.get("sent", 0) < lk["limit"])
                ]
                if not available:
                    available = [lk for lk in all_links if lk.get("url")]  # fallback: ignore limits
                if available:
                    mode = opts.links_cfg.get("mode", "sequential")
                    if mode == "random":
                        chosen_lk = random.choice(available)
                    else:
                        # Sequential cycling through available links only
                        chosen_lk = available[i % len(available)]
                    link_url = chosen_lk["url"]
                    # Increment usage counter (thread-safe via send_lock)
                    with _send_lock:
                        chosen_lk["sent"] = chosen_lk.get("sent", 0) + 1
                    # Apply link encoding — resolve [LINK] / [SF_*] tags in HTML
                    if _HAS_LINK_ENCODER and link_url and resolved_html:
                        try:
                            _lm = opts.link_method or get_method_from_tag(resolved_html)
                            resolved_html = resolve_link_tags(resolved_html, link_url, _lm)
                            # Store link_method in dlv so mime_builder can access it
                            dlv["linkUrl"]    = link_url
                            dlv["linkMethod"] = _lm
                        except Exception as _le:
                            pass  # fallback: leave tags unresolved

            fut = _executor.submit(_execute_send, (i, lead, resolved_sender, server,
                                                    resolved_subject, resolved_html, resolved_plain, link_url))
            return fut, resolved_sender, resolved_html, resolved_plain

        # Submit initial batch
        _qi = 0
        while _qi < len(_work_queue) and len(_pending_futures) < _workers:
            i, lead = _work_queue[_qi]; _qi += 1
            result = _submit_next(i, lead)
            if result:
                fut, rsen, rhtml, rplain = result
                _pending_futures[fut] = (i, lead, rsen, rhtml, rplain)

        # Process completions and submit more work
        import concurrent.futures as _cf
        while _pending_futures:
            if stopped:
                break
            if _campaign_abort_requested(campaign_uid):
                stopped = True
                yield {"type": "warn", "msg": "⛔ Campaign stop requested — halting remaining sends"}
                break
            done, _ = _cf.wait(list(_pending_futures.keys()), return_when=_cf.FIRST_COMPLETED)
            for fut in done:
                work_meta = _pending_futures.pop(fut)
                i, lead, pre_sender, resolved_html, resolved_plain = work_meta
                email_addr = (lead.get("email") or "").strip()

                try:
                    i_r, lead_r, ok, err, via, resolved_sender, link_url = fut.result()
                except Exception as exc:
                    ok, err, via, resolved_sender, link_url = False, f"network error: {exc}", "", pre_sender, ""

                # ── Track dead proxies on IP block errors ──────────────────
                # ── Dead proxy detection ──────────────────────────────────
                # Mark a proxy dead on: IP blocks, connection refused/closed,
                # or SSL errors that are proxy-specific (not sender-specific).
                import re as _re_proxy
                _proxy_fail = (not ok and err and any(x in err.lower() for x in [
                    "ip blocked", "connection refused", "connection closed",
                    "connection reset", "socket error", "all smtp ports",
                    "port blocked at exit", "proxy cannot reach",
                ]))
                if _proxy_fail:
                    # Extract proxy host:port from via label
                    _pm = _re_proxy.search(r"via ([\w\.-]+\.\w+(?::\d+)?)", via or "")
                    if _pm:
                        _dead_host = _pm.group(1).split(":")[0]  # host only
                        _isp_hosts = {"smtp.shaw.ca", "smtp.telus.net", "smtp.rogers.com",
                                      "smtp.rogers.com", "smtp.bell.net", "smtp.eastlink.ca"}
                        if _dead_host not in _isp_hosts:
                            with _send_lock:
                                if _dead_host not in _dead_proxies:
                                    _dead_proxies.add(_dead_host)
                                    yield {"type": "warn", "msg": f"⚠ Proxy {_dead_host} failed — removed from rotation"}
                                    # proxy_dead event lets frontend remove it from saved list
                                    yield {"type": "proxy_dead", "host": _dead_host}

                # ── AUP#POL retry (main thread — state-safe) ─────────────────
                _pol_cands    = []
                _pol_srv_pick = {}
                if not ok and _is_aup_pol(err or ""):
                    _pol_dead = resolved_sender.get("fromEmail","")
                    with _send_lock:
                        if _pol_dead and _pol_dead not in _dead_senders:
                            _dead_senders.add(_pol_dead)
                        _pol_cands = [s for s in opts.senders
                                      if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders]
                        _pol_srv_pick = _pick(servers, srv_rot, i) if servers else {}
                for _pc in _pol_cands[:5]:
                        _pc_res = dict(_pc) if isinstance(_pc,dict) else {"fromEmail":_pc}
                        _pc_tag_ctx = build_context(lead=lead,sender=_pc_res,subject="",counter=i+1,links_cfg=opts.links_cfg)
                        try:
                            ok, err, via = _send_one(opts=opts, i=i, lead=lead, sender=_pc_res,
                                                      server=_pol_srv_pick or {},
                                                      subject=resolve_tags(_pick(opts.subjects,sender_rot,i) or "", _pc_tag_ctx),
                                                      html=resolved_html,  # reuse already-filtered/resolved html
                                                      plain=resolved_plain, pool=pool, mx_ctx=mx_ctx,
                                                      dead_proxies=_dead_proxies)
                        except Exception as _pe:
                            ok, err, via = False, f"network error: {_pe}", ""
                        if ok:
                            resolved_sender = _pc_res
                            via = via + " (POL retry)"
                            break
                        elif _is_aup_pol(err or ""):
                            _fe2 = _pc_res.get("fromEmail","")
                            with _send_lock:
                                if _fe2: _dead_senders.add(_fe2)
                        else:
                            break

                # ── AUP#MXRT retry ────────────────────────────────────────────
                if not ok and _is_aup_mxrt(err or ""):
                    _mxrt_used     = {resolved_sender.get("fromEmail","")}
                    _mxrt_srv_used = set()
                    # Track the server that just failed so we try a different one
                    _mxrt_last_srv = _pick(servers, srv_rot, i) if servers else {}
                    if _mxrt_last_srv:
                        _mxrt_srv_used.add(_mxrt_last_srv.get("sshHost") or _mxrt_last_srv.get("ispSmtpHost") or _mxrt_last_srv.get("host",""))
                    # Detect if this is a greylist — needs a real time delay before retry
                    _is_grey = any(x in (err or "").lower() for x in ["greylisted","greylist","4.2.0","temporarily deferred"])
                    if _is_grey:
                        _grey_wait = random.uniform(120, 240)  # 2–4 min: greylists typically clear after 1–5 min
                        yield {"type":"pause","msg":f"⏸ Greylisted — waiting {_grey_wait:.0f}s before retry (greylist typically clears in 1–5 min)"}
                        if not _sleep_interruptible(_grey_wait, campaign_uid):
                            stopped = True
                            break
                    for _attempt in range(3):
                        # Between MXRT retry attempts: short backoff to avoid hammering
                        if _attempt > 0:
                            _mxrt_backoff = random.uniform(8, 16) if not _is_grey else random.uniform(60, 120)
                            if not _sleep_interruptible(_mxrt_backoff, campaign_uid):
                                stopped = True
                                break
                        if stopped:
                            break
                        with _send_lock:
                            _cands = [s for s in opts.senders
                                      if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders
                                      and (s.get("fromEmail","") if isinstance(s,dict) else s) not in _demoted_senders
                                      and (s.get("fromEmail","") if isinstance(s,dict) else s) not in _mxrt_used]
                            if not _cands:
                                _cands = [s for s in opts.senders
                                          if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders
                                          and (s.get("fromEmail","") if isinstance(s,dict) else s) not in _mxrt_used]
                        if not _cands: break
                        _ac = dict(_cands[0]) if isinstance(_cands[0],dict) else {"fromEmail":_cands[0]}
                        _mxrt_used.add(_ac.get("fromEmail",""))
                        with _send_lock:
                            # Prefer a server not yet tried this MXRT cycle
                            _srv_pool = [s for s in servers
                                         if (s.get("sshHost") or s.get("ispSmtpHost") or s.get("host","")) not in _mxrt_srv_used
                                        ] if servers else []
                            _mxrt_srv = _pick(_srv_pool or servers, srv_rot, i) if servers else {}
                            if _mxrt_srv:
                                _mxrt_srv_used.add(_mxrt_srv.get("sshHost") or _mxrt_srv.get("ispSmtpHost") or _mxrt_srv.get("host",""))
                        _ac_tag_ctx = build_context(lead=lead,sender=_ac,subject="",counter=i+1,links_cfg=opts.links_cfg)
                        try:
                            ok, err, via = _send_one(opts=opts, i=i, lead=lead, sender=_ac,
                                                      server=_mxrt_srv,
                                                      subject=resolve_tags(_pick(opts.subjects,sender_rot,i) or "", _ac_tag_ctx),
                                                      html=resolved_html,  # reuse already-filtered/resolved html
                                                      plain=resolved_plain, pool=pool, mx_ctx=mx_ctx,
                                                      dead_proxies=_dead_proxies)
                        except Exception as _me:
                            ok, err, via = False, f"network error: {_me}", ""
                        if ok:
                            resolved_sender = _ac
                            via = via + f" (MXRT retry {_attempt+1})"
                            break
                        elif not _is_aup_mxrt(err or ""):
                            break

                # ── Track sender health ────────────────────────────────────────
                _from_email = resolved_sender.get("fromEmail","")
                if ok:
                    with _send_lock: _record_sender_ok(_from_email)
                elif err:
                    if _is_aup_mxrt(err):
                        with _send_lock: _demote_sender(_from_email)
                    elif _get_score(_from_email) <= 40 and _from_email not in _demoted_senders:
                        with _send_lock: _demote_sender(_from_email)
                        yield {"type":"info","msg":f"⬇ Sender {_from_email} demoted (health {_get_score(_from_email)}/100)"}
                    if not _is_infrastructure_error(err):
                        with _send_lock: _just_died = _record_sender_fail(_from_email, err)
                        if _just_died:
                            _live_remaining = len([s for s in opts.senders if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders])
                            _reason = "auth failure" if _is_auth_error(err) else "AUP#POL" if _is_aup_pol(err) else "health=0"
                            yield {"type":"info","msg":f"✂ Sender {_from_email} removed ({_reason}) — {_live_remaining} remaining"}
                            if mx_ctx and hasattr(mx_ctx,"sender_health"):
                                mx_ctx.sender_health.dead_senders.add(_from_email)

                # ── Emit result ────────────────────────────────────────────────
                if ok:
                    success += 1
                    yield {"type":"success","index":i+1,"total":total_cap,"email":email_addr,
                           "name":lead.get("name",""),"from":resolved_sender.get("fromEmail",""),
                           "via":via,"link":link_url,"checkpoint":i+1}
                    if sends_per_sec > 0 and not _sleep_interruptible(1.0/sends_per_sec, campaign_uid):
                        stopped = True
                        break
                else:
                    fail += 1
                    _append_fail(email_addr)
                    yield {"type":"error","index":i+1,"total":total_cap,"email":email_addr,"error":err}
                    if err and err.startswith("API_RATE_LIMIT:"):
                        parts = err.split(":",2)
                        pause = float(parts[1]) if len(parts)>1 else 60.0
                        msg_  = parts[2] if len(parts)>2 else "API rate limited"
                        yield {"type":"pause","msg":f"⏸ {msg_}"}
                        if not _sleep_interruptible(pause, campaign_uid):
                            stopped = True
                            break
                        yield {"type":"info","msg":f"▶ Resuming after {pause:.0f}s pause"}
                    elif _is_rate_limit(err):
                        lead_domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
                        # If rateLimitPause is False, skip the cooldown and just log the failure
                        if not dlv.get("rateLimitPause", True):
                            pass  # already logged as fail above — just move on
                        elif lead_domain in MS_RATE_DOMAINS:
                            pause = random.uniform(90, 180)
                            yield {"type":"pause","msg":f"⏸ Microsoft rate limit on {lead_domain} — cooling down {pause:.0f}s (MS needs ~2min)"}
                            if not _sleep_interruptible(pause, campaign_uid):
                                stopped = True
                                break
                        else:
                            pause = random.uniform(15, 45)
                            yield {"type":"pause","msg":f"⏸ Rate limit on {lead_domain} — cooling down {pause:.0f}s"}
                            if not _sleep_interruptible(pause, campaign_uid):
                                stopped = True
                                break

                # Cooldown
                if cooldown_every>0 and (i+1)%cooldown_every==0 and (i+1)<total_cap:
                    yield {"type":"pause","msg":f"🧊 Cooldown after {i+1} emails — pausing {cooldown_secs:.0f}s..."}
                    if not _sleep_interruptible(cooldown_secs, campaign_uid):
                        stopped = True
                        break

                # Batch pause
                if batch_size>0 and (i+1)%batch_size==0 and (i+1)<total_cap:
                    pause_total = batch_pause_secs if batch_pause_secs>0 else base_delay
                    if dlv.get("delayJitter"): pause_total = max(0.5, pause_total+random.uniform(-jitter_range,jitter_range))
                    yield {"type":"batch","msg":f"Batch {(i+1)//batch_size} done — pausing {pause_total:.1f}s..."}
                    if not _sleep_interruptible(pause_total, campaign_uid):
                        stopped = True
                        break
                elif _workers <= 1:
                    # Sequential mode only — in concurrent mode the network I/O
                    # provides natural pacing; sleeping here would serialize workers
                    if dlv.get("delayJitter"):
                        if not _sleep_interruptible(max(0.1, random.uniform(0.3, 1.5 + jitter_range * 0.3)), campaign_uid):
                            stopped = True
                            break
                    elif base_delay>0:
                        if not _sleep_interruptible(base_delay, campaign_uid):
                            stopped = True
                            break
                    if dlv.get("domainThrottle"):
                        lead_domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""
                        if lead_domain in MS_RATE_DOMAINS:
                            ms_delay = _safe_float(dlv.get("msDelay", 8), 8.0)
                            if not _sleep_interruptible(ms_delay + random.uniform(0, 4), campaign_uid):
                                stopped = True
                                break
                        elif lead_domain in STRICT_DOMAINS:
                            extra = _safe_float(dlv.get("gmailDelay", 5), 5.0)
                            if not _sleep_interruptible(extra, campaign_uid):
                                stopped = True
                                break
                        # Per-provider extra delay from email sorter
                        _prov_extra = _get_provider_delay(email_addr)
                        if _prov_extra > 0:
                            if not _sleep_interruptible(_prov_extra + random.uniform(0, _prov_extra * 0.3), campaign_uid):
                                stopped = True
                                break

                # Check senders still alive
                with _send_lock:
                    _still_live = [s for s in opts.senders if (s.get("fromEmail","") if isinstance(s,dict) else s) not in _dead_senders]
                if not _still_live and opts.senders:
                    yield {"type":"warn","msg":"⚠ All senders removed — campaign stopping"}
                    break

                # Submit next work item to keep pool full
                if _qi < len(_work_queue):
                    i_n, lead_n = _work_queue[_qi]; _qi += 1
                    result_n = _submit_next(i_n, lead_n)
                    if result_n:
                        fut_n, rsen_n, rhtml_n, rplain_n = result_n
                        _pending_futures[fut_n] = (i_n, lead_n, rsen_n, rhtml_n, rplain_n)

        _executor.shutdown(wait=not stopped)

        # ── Done ─────────────────────────────────────────────
        warmup_msg = ""
        if dlv.get("warmup"):
            warmup_msg = (
                f" (warmup day {warmup_day}: sent {min(len(opts.leads), max_emails)}"
                f" of {len(opts.leads)})"
            )

        # ── Failed leads file summary ─────────────────────────
        if _failed_count > 0 and _fail_fpath:
            yield {"type": "info", "msg": f"📁 Failed leads → Files tab: {_fail_name} ({_failed_count} addresses — reload to resend)"}

        yield {
            "type":    "done",
            "success": success,
            "fail":    fail,
            "skip":    skip,
            "total":   total_cap,
            "stopped": stopped,
            "warmup":  warmup_msg,
        }

    finally:
        # Always close SSH tunnels — even if an exception aborted the campaign
        if opened_ports:
            try:
                close_all_tunnels()
            except Exception as exc:
                log.error("[campaign] error closing tunnels: %s", exc)


# ═══════════════════════════════════════════════════════════════
# BACKWARDS-COMPAT WRAPPER
# Drop-in replacement for process_campaign() in synthtel_server.py
# ═══════════════════════════════════════════════════════════════


def process_campaign(data: dict) -> Generator:
    """
    Drop-in replacement for the monolithic process_campaign() in synthtel_server.py.

    Accepts the same raw dict the frontend sends and yields the same
    JSON-serialisable event dicts — so you can swap the import without
    touching any Flask route code:

        # Old:
        from synthtel_server import process_campaign
        # New:
        from core.campaign import process_campaign

    The campaign route becomes just:

        @app.route("/api/send", methods=["POST"])
        def send_route():
            data = request.get_json()
            def gen():
                for event in process_campaign(data):
                    yield json.dumps(event) + "\\n"
            return Response(gen(), mimetype="application/x-ndjson")
    """
    # Raw dump of what frontend sent
    logging.getLogger("synthtel").info("[RAW] method=%s tunnels_raw=%s ispTunnels_raw=%s",
        data.get("method"), data.get("tunnels"), data.get("ispTunnels"))

    # ── ISP method: synthesise tunnels from the normal proxy pool ───────
    # If the user picked the "Normal proxy pool + ISP SMTP host" mode in
    # the UI (or an integration sets data.proxies + data.ispSmtpHost
    # without populating the per-row ispTunnels), build one synthetic ISP
    # tunnel per proxy in the pool. This means a single ISP SMTP target
    # (e.g. smtp.shaw.ca) can be paired with any number of generic
    # SOCKS5/HTTP proxies without forcing the user to duplicate every
    # proxy into the ISP-only datastore.
    if (data.get("method") == "isp"
            and not data.get("ispTunnels")
            and not data.get("tunnels")
            and data.get("proxies")
            and data.get("ispSmtpHost")):
        try:
            import re as _ipre
            _isp_host = str(data["ispSmtpHost"]).strip()
            _isp_port = str(data.get("ispSmtpPort", "25")).strip() or "25"
            _isp_dom  = data.get("ispFromDomain", "") or ""
            _isp_env  = data.get("ispEnvelopeFrom", "") or ""
            _synth = []
            for p in (data["proxies"] or []):
                if isinstance(p, dict):
                    h     = (p.get("host") or "").strip()
                    pt    = (p.get("type") or "socks5").lower()
                    try:    pr = int(p.get("port") or 0)
                    except: pr = 0
                    u  = p.get("username") or ""
                    pw = p.get("password") or ""
                else:
                    m = _ipre.match(
                        r'^(?:(socks5|socks4|http|https)://)?(?:([^:@]+):([^@]+)@)?([\w.\-]+):(\d+)$',
                        str(p).strip())
                    if not m: continue
                    pt, u, pw, h, pr = m.groups()
                    pt = (pt or "socks5").lower(); pr = int(pr)
                    u = u or ""; pw = pw or ""
                if not h or not pr:
                    continue
                _synth.append({
                    "tunnelType":    "isp",
                    "label":         f"{h} → {_isp_host}",
                    "sshHost":       "",
                    "rdpSshPort":    22,
                    "sshUser":       "",
                    "sshPass":       "",
                    "socksHost":     h,
                    "socksPort":     pr,
                    "proxyHost":     h,
                    "proxyPort":     str(pr),
                    "proxyUser":     u,
                    "proxyPass":     pw,
                    "proxyType":     pt,
                    "ispSmtpHost":   _isp_host,
                    "ispSmtpPort":   _isp_port,
                    "fromDomain":    _isp_dom,
                    "smtpFromEmail": _isp_env,
                })
            if _synth:
                data["ispTunnels"] = _synth
                logging.getLogger("synthtel").info(
                    "[ISP] synthesised %d tunnel(s) from normal proxy pool — ISP SMTP=%s:%s",
                    len(_synth), _isp_host, _isp_port,
                )
        except Exception as _e:
            logging.getLogger("synthtel").warning(
                "[ISP] failed to synthesise tunnels from normal pool: %s", _e)

    # If no tunnels from frontend, fetch from DB using user session
    if not data.get("tunnels") and not data.get("ispTunnels") and data.get("method") in ("isp","tunnel"):
        try:
            from core.server import get_db
            uid = data.get("_uid")
            if uid:
                db = get_db()
                # For ISP method: load proxies directly (no RDP join needed)
                if data.get("method") == "isp":
                    rows = db.execute("""
                        SELECT label, host, port, usr, pass, type,
                               isp_smtp_host, isp_smtp_port
                        FROM isp_proxies
                        WHERE user_id=? AND isp_smtp_host != ''
                    """, (uid,)).fetchall()
                    if rows:
                        data["ispTunnels"] = [{
                            "tunnelType":  "isp",
                            "label":       r[0] or r[1],
                            "sshHost":     "",
                            "socksHost":   r[1],
                            "socksPort":   int(r[2] or 17521),
                            "rdpSshPort":  22,
                            "sshUser":     "",
                            "sshPass":     "",
                            "ispSmtpHost": r[6] or "",
                            "ispSmtpPort": r[7] or "25",
                            "proxyHost":   r[1] or "",
                            "proxyPort":   r[2] or "17521",
                            "proxyUser":   r[3] or "",
                            "proxyPass":   r[4] or "",
                            "proxyType":   r[5] or "socks5",
                        } for r in rows]
                        logging.getLogger("synthtel").info("[DB] fetched %d ISP proxies for uid=%s", len(rows), uid)
                else:
                    # Tunnel method: original RDP+proxy join
                    rows = db.execute("""
                        SELECT r.label, r.host, r.ssh_port, r.usr, r.pass,
                               p.isp_smtp_host, p.isp_smtp_port,
                               p.host, p.port, p.usr, p.pass, p.type
                        FROM isp_rdps r
                        JOIN isp_assignments a ON a.rdp_client_id=r.client_id AND a.user_id=r.user_id
                        JOIN isp_proxies p ON p.client_id=a.proxy_client_id AND p.user_id=r.user_id
                        WHERE r.user_id=?
                    """, (uid,)).fetchall()
                    if rows:
                        data["ispTunnels"] = [{
                            "tunnelType":  "isp",
                            "label":       r[0] or r[1],
                            "sshHost":     r[1],
                            "socksHost":   r[1],
                            "socksPort":   1080,
                            "rdpSshPort":  int(r[2] or 22),
                            "sshUser":     r[3] or "Administrator",
                            "sshPass":     r[4] or "",
                            "ispSmtpHost": r[5] or "",
                            "ispSmtpPort": r[6] or "25",
                            "proxyHost":   r[7] or "",
                            "proxyPort":   r[8] or "17521",
                            "proxyUser":   r[9] or "",
                            "proxyPass":   r[10] or "",
                            "proxyType":   r[11] or "socks5",
                        } for r in rows]
                        logging.getLogger("synthtel").info("[DB] fetched %d tunnels for uid=%s", len(rows), uid)
        except Exception as e:
            logging.getLogger("synthtel").warning("[DB] tunnel fetch failed: %s", e)
    opts = CampaignOptions.from_dict(data)
    # Debug: log what we received
    # Display method using original name from frontend (before internal remapping)
    _display_method = data.get("method", opts.method)
    logging.getLogger("synthtel").info(
        "[campaign] method=%s (internal=%s) tunnels=%d smtps=%d leads=%d",
        _display_method, opts.method, len(opts.tunnels), len(opts.smtps), len(opts.leads)
    )
    if opts.tunnels:
        for t in opts.tunnels:
            logging.getLogger("synthtel").info("[tunnel] %s", t)
    # Internal debug logging (not surfaced to UI)
    logging.getLogger("synthtel").debug("method=%s tunnels=%d smtps=%d", opts.method, len(opts.tunnels), len(opts.smtps))
    yield from run_campaign(opts)


# ═══════════════════════════════════════════════════════════════
# CONVENIENCE: SINGLE-EMAIL SEND
# ═══════════════════════════════════════════════════════════════



def send_one_email(
    method:   str,
    server:   dict,
    sender:   dict,
    lead:     dict,
    html:     str,
    plain:    str,
    subject:  str,
    dlv:      dict  = None,
    headers:  list  = None,
    proxy:    dict  = None,
) -> tuple:
    """
    Send a single email immediately (not a campaign generator).

    Useful for test-sends, preview sends, and one-off notifications.

    Returns:
        (True,  "", via_label)      on success
        (False, error_msg, via_label) on failure
    """
    pool   = get_global_pool()
    mx_ctx = MxSenderContext()

    opts           = CampaignOptions(method=method, dlv=dlv or {}, custom_headers=headers or [])
    opts.smtps     = [server] if method in ("smtp", "tunnel") else []
    opts.apis      = [server] if method == "api"  else []
    opts.owas      = [server] if method == "owa"  else []
    opts.crms      = [server] if method == "crm"  else []
    opts.proxy     = proxy or {}

    return _send_one(
        opts    = opts,
        i       = 0,
        lead    = lead,
        sender  = sender,
        server  = server,
        subject = subject,
        html    = html,
        plain   = plain,
        pool    = pool,
        mx_ctx  = mx_ctx,
    )
