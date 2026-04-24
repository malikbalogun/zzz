"""
core/b2b_manager.py — SynthTel B2B Inbox Sender
=================================================
Login into your own email accounts, extract existing contacts
from received mail, deduplicate intelligently, and send back —
either as new emails or as threaded replies.

Primary targets:
  • Office 365 / Exchange Online  (user@corp.com using O365)
  • Outlook.com / Hotmail / Live  (personal Microsoft accounts)
  • Google Workspace / GSuite     (user@corp.com using Google)
  • Gmail                         (personal @gmail.com)
  • GoDaddy / Workspace Email     (IMAP via secureserver.net)
  • Yahoo, AOL, iCloud, Zoho, Fastmail, ProtonMail Bridge, any IMAP

Login methods (auto-cascade until one works):
  Method 1 — Username + Password
    Microsoft → ROPC silent (tries 5 app IDs × 3 authorities)
                → on MFA/federated error: falls back to Method 2
    IMAP/SMTP → SSL port 993 → STARTTLS port 143 → alt hostnames
    Google Workspace → IMAP via app password or direct

  Method 2 — Browser Popup / Device Code
    Microsoft OAuth device code flow — opens microsoft.com/devicelogin,
    user enters the displayed code, back-end polls until confirmed.
    Works even with MFA, conditional access, ADFS federation.

  Method 3 — Cookie / Pre-obtained Token
    Caller passes a raw Bearer token (grabbed from browser cookies
    or any other OAuth flow). Stored as ms_token, used directly.
    login_token(email, token) → instantly authenticated.

Pipeline:
  1. detect()       — detect provider from domain / MX / autodiscover
  2. login_*()      — authenticate via chosen method
  3. list_folders() — list all folders with message counts
  4. extract()      — pull From addresses, subjects, message IDs
  5. sanitize()     — remove no-reply/bots/ESPs, dedup by domain
  6. send()         — send via Graph API (MS) or SMTP (IMAP)
                      reply mode: In-Reply-To + Re: subject prefix
                      new mode:   fresh message

HTTP API endpoints (register in synthtel_server.py):
  POST /api/b2b/detect
  POST /api/b2b/auth/password
  POST /api/b2b/auth/token
  POST /api/b2b/device-start
  GET  /api/b2b/device-poll
  GET  /api/b2b/folders
  POST /api/b2b/extract      (SSE stream)
  POST /api/b2b/sanitize
  POST /api/b2b/send         (SSE stream)
  POST /api/b2b/reset
  GET  /api/b2b/status
"""

import re
import ssl
import base64
import email
import email.utils
import imaplib
import smtplib
import logging
import random
import string
import socket
import subprocess
import sys
import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.header import decode_header as _decode_hdr
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders as _enc
from typing import Optional, Generator

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
# AUTO-INSTALL
# ─────────────────────────────────────────────────────────────────
def _ensure(pkg, pip_name=None):
    try:
        __import__(pkg)
    except ImportError:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", pip_name or pkg,
                 "-q", "--break-system-packages", "--disable-pip-version-check"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
            )
        except Exception:
            pass

for _pkg in [("msal", "msal"), ("requests", "requests"), ("dns.resolver", "dnspython")]:
    try:
        _ensure(*_pkg)
    except Exception:
        pass

try:
    import msal as _msal
    _HAS_MSAL = True
    _MSAL_ERR = None
except Exception as _e:
    _HAS_MSAL = False
    _MSAL_ERR = str(_e)

try:
    import requests as _req
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import dns.resolver as _dns
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


# ── Proxy helpers ────────────────────────────────────────────────────────
# Convert a proxy_cfg dict (the same shape produced by
# core.campaign.CampaignOptions._build_proxy_cfg) into the structures each
# downstream library wants. Mirrors what core.smtp_sender / core.proxy_util
# already do for the other senders.

def _b2b_requests_proxies(proxy_cfg: Optional[dict]) -> Optional[dict]:
    """Return a dict suitable for ``requests.post(proxies=...)`` or
    ``requests.Session.proxies``. None when no proxy.

    SOCKS proxies require the ``requests[socks]`` extra (which is just
    PySocks — already a runtime dep). HTTP/HTTPS work natively.
    """
    if not proxy_cfg or not isinstance(proxy_cfg, dict) or not proxy_cfg.get("host"):
        return None
    from urllib.parse import quote
    ptype = (proxy_cfg.get("type") or "http").lower().strip()
    host  = str(proxy_cfg["host"]).strip()
    try:
        port = int(proxy_cfg.get("port") or 0)
    except Exception:
        port = 0
    if not port:
        return None
    user = quote(str(proxy_cfg.get("username") or ""), safe="")
    pw   = quote(str(proxy_cfg.get("password") or ""), safe="")
    auth = f"{user}:{pw}@" if (user or pw) else ""
    if ptype not in ("http", "https", "socks4", "socks5", "socks5h"):
        ptype = "http"
    if ptype == "socks5":
        # socks5h delegates DNS to the proxy (avoids leaking lookups).
        ptype = "socks5h"
    url = f"{ptype}://{auth}{host}:{port}"
    return {"http": url, "https": url}


def _b2b_smtp_socket(host: str, port: int, proxy_cfg: Optional[dict],
                      timeout: float = 30):
    """Open a TCP socket to ``host:port`` either directly or through the
    given SOCKS5 / HTTP proxy. Used by _send_via_smtp.
    """
    if not proxy_cfg or not proxy_cfg.get("host"):
        import socket as _sock
        return _sock.create_connection((host, port), timeout=timeout)
    try:
        import socks as _pysocks  # PySocks
    except ImportError:
        raise RuntimeError(
            "B2B SMTP proxy requires PySocks — "
            "run `pip install pysocks --break-system-packages`")
    ptype = (proxy_cfg.get("type") or "socks5").lower()
    pmap  = {
        "socks5":  _pysocks.SOCKS5,
        "socks5h": _pysocks.SOCKS5,
        "socks4":  _pysocks.SOCKS4,
        "http":    _pysocks.HTTP,
        "https":   _pysocks.HTTP,
    }
    s = _pysocks.socksocket()
    s.set_proxy(
        pmap.get(ptype, _pysocks.SOCKS5),
        str(proxy_cfg["host"]),
        int(proxy_cfg.get("port") or 1080),
        username=proxy_cfg.get("username") or None,
        password=proxy_cfg.get("password") or None,
    )
    s.settimeout(timeout)
    s.connect((host, port))
    return s


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

GRAPH = "https://graph.microsoft.com/v1.0"

# Consumer Microsoft domains — use /consumers authority
MS_CONSUMER_DOMAINS = frozenset({
    "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "live.com", "live.ca", "live.co.uk", "live.fr", "live.com.au",
    "msn.com", "passport.com",
})

# Microsoft Graph scopes needed for read + send
MS_SCOPES_FULL = [
    "https://graph.microsoft.com/.default",  # Works on all tenants incl. Conditional Access
]

MS_SCOPES_FALLBACK = [
    "Mail.Read",
    "Mail.Send",
    "User.Read",
    "offline_access",
]

# Public Microsoft app client IDs — tried in order, first success wins
MS_APPS = [
    ("Microsoft Office",       "d3590ed6-52b3-4102-aeff-aad2292ab01c"),  # pre-authorized for Graph
    ("Azure CLI",              "04b07795-8ddb-461a-bbee-02f9e1bf7b46"),  # fallback
]

# IMAP provider table: domain → (name, imap_host, imap_port,
#                                 needs_app_pw, app_pw_url,
#                                 smtp_host, smtp_port)
PROVIDERS: dict = {
    # Gmail / Google Workspace
    "gmail.com":       ("Gmail",       "imap.gmail.com",            993, True,
                        "https://myaccount.google.com/apppasswords",
                        "smtp.gmail.com", 587),
    "googlemail.com":  ("Gmail",       "imap.gmail.com",            993, True,
                        "https://myaccount.google.com/apppasswords",
                        "smtp.gmail.com", 587),

    # Yahoo
    "yahoo.com":       ("Yahoo",       "imap.mail.yahoo.com",       993, True,
                        "https://login.yahoo.com/account/security",
                        "smtp.mail.yahoo.com", 587),
    "ymail.com":       ("Yahoo",       "imap.mail.yahoo.com",       993, True,
                        "https://login.yahoo.com/account/security",
                        "smtp.mail.yahoo.com", 587),
    "yahoo.co.uk":     ("Yahoo UK",    "imap.mail.yahoo.com",       993, True,
                        "https://login.yahoo.com/account/security",
                        "smtp.mail.yahoo.com", 587),
    "yahoo.co.jp":     ("Yahoo JP",    "imap.mail.yahoo.com",       993, True,
                        "https://login.yahoo.com/account/security",
                        "smtp.mail.yahoo.com", 587),
    "yahoo.com.au":    ("Yahoo AU",    "imap.mail.yahoo.com",       993, True,
                        "https://login.yahoo.com/account/security",
                        "smtp.mail.yahoo.com", 587),

    # AOL
    "aol.com":         ("AOL",         "imap.aol.com",              993, True,
                        "https://login.aol.com/account/security",
                        "smtp.aol.com", 587),

    # Apple iCloud
    "icloud.com":      ("iCloud",      "imap.mail.me.com",          993, True,
                        "https://appleid.apple.com",
                        "smtp.mail.me.com", 587),
    "me.com":          ("iCloud",      "imap.mail.me.com",          993, True,
                        "https://appleid.apple.com",
                        "smtp.mail.me.com", 587),
    "mac.com":         ("iCloud",      "imap.mail.me.com",          993, True,
                        "https://appleid.apple.com",
                        "smtp.mail.me.com", 587),

    # Zoho
    "zoho.com":        ("Zoho",        "imap.zoho.com",             993, False, "",
                        "smtp.zoho.com", 587),
    "zoho.eu":         ("Zoho EU",     "imap.zoho.eu",              993, False, "",
                        "smtp.zoho.eu", 587),
    "zohomail.com":    ("Zoho",        "imap.zoho.com",             993, False, "",
                        "smtp.zoho.com", 587),

    # Fastmail
    "fastmail.com":    ("Fastmail",    "imap.fastmail.com",         993, True,
                        "https://app.fastmail.com/settings/security/devicekeys/new",
                        "smtp.fastmail.com", 587),
    "fastmail.fm":     ("Fastmail",    "imap.fastmail.com",         993, True,
                        "https://app.fastmail.com/settings/security/devicekeys/new",
                        "smtp.fastmail.com", 587),

    # GMX / Web.de
    "gmx.com":         ("GMX",         "imap.gmx.com",              993, False, "",
                        "mail.gmx.com", 587),
    "gmx.net":         ("GMX",         "imap.gmx.net",              993, False, "",
                        "mail.gmx.net", 587),
    "gmx.de":          ("GMX DE",      "imap.gmx.net",              993, False, "",
                        "mail.gmx.net", 587),
    "web.de":          ("Web.de",      "imap.web.de",               993, False, "",
                        "smtp.web.de", 587),

    # ProtonMail (requires Bridge running locally)
    "protonmail.com":  ("ProtonMail",  "127.0.0.1",                1143, False,
                        "https://account.proton.me/settings#import-export",
                        "127.0.0.1", 1025),
    "proton.me":       ("ProtonMail",  "127.0.0.1",                1143, False,
                        "https://account.proton.me/settings#import-export",
                        "127.0.0.1", 1025),
    "pm.me":           ("ProtonMail",  "127.0.0.1",                1143, False,
                        "https://account.proton.me/settings#import-export",
                        "127.0.0.1", 1025),

    # Microsoft consumer (also routed through IMAP if needed)
    "outlook.com":     ("Outlook",     "outlook.office365.com",     993, False, "",
                        "smtp.office365.com", 587),
    "hotmail.com":     ("Hotmail",     "outlook.office365.com",     993, False, "",
                        "smtp.office365.com", 587),
    "live.com":        ("Live",        "outlook.office365.com",     993, False, "",
                        "smtp.office365.com", 587),
    "hotmail.co.uk":   ("Hotmail UK",  "outlook.office365.com",     993, False, "",
                        "smtp.office365.com", 587),

    # GoDaddy / Workspace Email
    # GoDaddy routes mail through secureserver.net
    "secureserver.net":("GoDaddy",     "imap.secureserver.net",     993, False, "",
                        "smtpout.secureserver.net", 465),
}

# MX record hints → provider routing
# Key = substring to look for in joined MX records
# Value = "ms" (Office 365) or a domain key in PROVIDERS
MX_HINTS = {
    # Microsoft / O365
    "protection.outlook":      "ms",
    "mail.protection.outlook": "ms",
    "outlook.com":             "ms",
    "pphosted.com":            "ms",
    "microsoft":               "ms",
    "messagelabs.com":         "ms",
    "mimecast":                "ms",
    "barracuda":               "ms",
    "eo.outlook.com":          "ms",
    # Google
    "aspmx.l.google":          "gmail.com",
    "googlemail.com":          "gmail.com",
    "google.com":              "gmail.com",
    # Yahoo
    "yahoodns.net":            "yahoo.com",
    "yahoo.com":               "yahoo.com",
    # Other known providers
    "icloud.com":              "icloud.com",
    "fastmail":                "fastmail.com",
    "zoho.com":                "zoho.com",
    # GoDaddy
    "secureserver.net":        "secureserver.net",
}

# No-reply / generic / bot patterns
_GENERIC_PATTERNS = [
    r'^noreply',        r'^no-reply',        r'^no\.reply',
    r'^donotreply',     r'^do-not-reply',    r'^do\.not\.reply',
    r'^postmaster',     r'^mailer-daemon',   r'^bounced?@',
    r'^daemon@',        r'^notifications?@', r'^notify@',
    r'^alerts?@',       r'^newsletter',      r'^news@',
    r'^updates?@',      r'^digest@',         r'^automated',
    r'^auto-',          r'^system@',         r'^service@',
    r'^feedback@',      r'^survey',          r'^billing@',
    r'^receipt',        r'^invoice@',        r'^calendar-notification',
    r'^noreply-',       r'^microsoftexchange', r'^microsoft365',
    r'^msonlineservicesteam', r'^microsoft-noreply',
    r'^unsubscribe',    r'^bounce',          r'^reply-to-',
    r'@.+\.(mailchimp|sendgrid|amazonses|constantcontact|hubspot|'
    r'salesforce|marketo|mandrillapp|mailgun|campaign-archive|'
    r'createsend|klaviyo|brevo|sendinblue|mailerlite)\.com$',
]
_generic_re = [re.compile(p, re.I) for p in _GENERIC_PATTERNS]

def is_generic(addr: str) -> bool:
    """Return True if address looks like a no-reply / automated sender."""
    return any(r.search(addr) for r in _generic_re)


# ─────────────────────────────────────────────────────────────────
# LOCAL-PART RANDOMIZER
# ─────────────────────────────────────────────────────────────────
_RANDOM_STYLES = {
    "alpha":    lambda n: "".join(random.choices(string.ascii_lowercase, k=n)),
    "digits":   lambda n: "".join(random.choices(string.digits, k=n)),
    "alphanum": lambda n: "".join(random.choices(string.ascii_lowercase + string.digits, k=n)),
    "dotted":   lambda n: ".".join([
        "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))
        for _ in range(2)
    ]),
    "word": lambda n: random.choice([
        "sales", "hello", "info", "contact", "support", "team",
        "office", "admin", "mail", "hi", "hey", "reach", "business",
    ]) + random.choice(["", str(random.randint(1, 99))]),
    "name": lambda n: (
        random.choice(["john", "jane", "alex", "sam", "mike", "sarah", "david", "lisa"])
        + random.choice([".", "_", ""])
        + random.choice(["smith", "jones", "brown", "white", "harris", "clark", ""])
    ).strip("._ ") or "info",
}

def randomize_local(from_email: str, style: str = "alphanum", length: int = 8) -> str:
    """
    Replace the local part (before @) of from_email with a random string.

    Styles:
      "alpha"    — lowercase letters only
      "digits"   — digits only
      "alphanum" — mixed letters + digits (default)
      "dotted"   — two word-chunks joined by dot
      "word"     — common business word + optional number
      "name"     — firstname.lastname style
    """
    if "@" not in from_email:
        return from_email
    domain = from_email.split("@", 1)[1]
    fn     = _RANDOM_STYLES.get(style, _RANDOM_STYLES["alphanum"])
    local  = fn(length).strip("._ ") or "".join(random.choices(string.ascii_lowercase, k=6))
    return f"{local}@{domain}"


# ═══════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

@dataclass
class B2BLead:
    """One deduplicated contact extracted from an inbox."""
    email:         str
    name:          str
    last_subject:  str
    last_date:     str
    message_id:    str   # most recent Message-ID (for In-Reply-To)
    thread_ids:    list  # all Message-IDs from this sender (oldest first)
    folder:        str
    msg_count:     int   = 1
    is_html:       bool  = False
    has_att:       bool  = False
    score:         int   = 0   # 0-100 deliverability score

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}  # type: ignore


@dataclass
class B2BAccount:
    """Authenticated session — holds credentials for extraction + send."""
    email:      str
    provider:   dict
    ms_token:   Optional[str]            = None  # MS Graph Bearer token
    ms_token_expires: float              = 0.0   # epoch timestamp
    ms_refresh: Optional[str]            = None  # refresh token if available
    imap_conn:  Optional[imaplib.IMAP4]  = None
    smtp_host:  str  = ""
    smtp_port:  int  = 587
    smtp_user:  str  = ""
    smtp_pass:  str  = ""

    def ms_token_valid(self) -> bool:
        """True if we have a Graph token with >60 seconds remaining."""
        return bool(self.ms_token) and (time.time() + 60 < self.ms_token_expires)


# ═══════════════════════════════════════════════════════════════
# PROVIDER DETECTION
# ═══════════════════════════════════════════════════════════════

def detect(email_addr: str) -> dict:
    """
    Detect provider for an email address.

    Cascade:
      1. Consumer Microsoft domain list
      2. Known provider table
      3. MX lookup → hint matching
      4. O365 autodiscover probe (catches corporate O365 tenants)
      5. Common IMAP hostname probe (imap.domain, mail.domain)

    Returns dict with:
        type       "ms" | "imap" | "unknown"
        name       Human-friendly provider name
        domain     Domain part of the email
        imap_host  IMAP server hostname
        imap_port  993 or 143
        smtp_host  SMTP server hostname
        smtp_port  587 or 465
        needs_app_pw   bool
        app_pw_url     URL for app password instructions
        is_google  bool — True for Gmail / Google Workspace
        is_godaddy bool — True for GoDaddy hosted domains
    """
    domain = email_addr.split("@")[-1].lower().strip()

    def _ms_result(name, is_personal=False):
        return {
            "type": "ms",
            "provider": "microsoft365",
            "name": name, "domain": domain,
            "imap_host": "outlook.office365.com", "imap_port": 993,
            "smtp_host": "smtp.office365.com",    "smtp_port": 587,
            "needs_app_pw": False, "app_pw_url": "",
            "is_google": False, "is_godaddy": False,
            "auth_order": ["device_code", "token", "password"],
            "auth_hints": {
                "password": "Works if MFA is disabled. Use App Password if MFA is on (account.microsoft.com/security).",
                "token": "Paste a Bearer token from browser dev tools (F12 → Network → any graph.microsoft.com request → Authorization header).",
                "device_code": "Best for MFA/SSO — opens microsoft.com/devicelogin with a one-time code. No app password needed.",
                "cookie": "Paste Outlook web session cookies from browser dev tools for direct Graph API access.",
            }
        }

    def _imap_result(name, ih, ip, app_pw, app_url, sh, sp, **extra):
        is_g  = "gmail" in ih or "google" in ih or extra.get("is_google")
        is_gd = "secureserver" in ih or extra.get("is_godaddy")
        prov  = "google" if is_g else ("godaddy" if is_gd else "imap")
        hints_pw = "App Password required — " + (app_url if app_url else "check your provider security settings") if app_pw else "Use your regular email password."
        r = {
            "type": "imap",
            "provider": prov,
            "name": name, "domain": domain,
            "imap_host": ih, "imap_port": ip,
            "smtp_host": sh, "smtp_port": sp,
            "needs_app_pw": app_pw, "app_pw_url": app_url,
            "is_google": is_g, "is_godaddy": is_gd,
            "auth_order": ["password", "token"] if not is_g else ["password", "token"],
            "auth_hints": {
                "password": hints_pw,
                "token": "Paste OAuth Bearer token from browser dev tools.",
                "cookie": "Import IMAP session from browser cookies.",
            }
        }
        r.update(extra)
        return r

    # 1. Consumer Microsoft
    if domain in MS_CONSUMER_DOMAINS:
        return _ms_result(f"Microsoft ({domain})", is_personal=True)

    # 2. Known provider table
    if domain in PROVIDERS:
        n, ih, ip, app_pw, app_url, sh, sp = PROVIDERS[domain]
        is_g = "gmail" in ih or "google" in ih
        is_gd = "secureserver" in ih
        return _imap_result(n, ih, ip, app_pw, app_url, sh, sp,
                            is_google=is_g, is_godaddy=is_gd)

    # 3. MX lookup
    mx = _resolve_mx(domain)
    if mx:
        mx_str = " ".join(mx)
        for hint, key in MX_HINTS.items():
            if hint in mx_str:
                if key == "ms":
                    return _ms_result(f"Office 365 ({domain})")
                if key in PROVIDERS:
                    n, ih, ip, app_pw, app_url, sh, sp = PROVIDERS[key]
                    is_g = "gmail" in ih or "google" in ih
                    is_gd = "secureserver" in ih
                    return _imap_result(
                        f"{n} ({domain})", ih, ip, app_pw, app_url, sh, sp,
                        is_google=is_g, is_godaddy=is_gd,
                    )

    # 4. O365 autodiscover
    if _o365_autodiscover(domain):
        return _ms_result(f"Office 365 ({domain})")

    # 5. Probe common IMAP hostnames
    for candidate in [f"imap.{domain}", f"mail.{domain}", domain]:
        try:
            s = socket.create_connection((candidate, 993), timeout=4)
            s.close()
            smtp_cand = (candidate
                         .replace("imap.", "smtp.")
                         .replace("mail.", "smtp."))
            is_gd = "secureserver" in candidate
            return _imap_result(
                f"IMAP ({domain})", candidate, 993, False, "",
                smtp_cand, 587, is_godaddy=is_gd,
            )
        except Exception:
            continue

    # Unknown — return sensible defaults, user can override
    return {
        "type": "unknown", "provider": "generic",
        "name": f"Unknown ({domain})", "domain": domain,
        "imap_host": f"imap.{domain}", "imap_port": 993,
        "smtp_host": f"smtp.{domain}",  "smtp_port": 587,
        "needs_app_pw": False, "app_pw_url": "",
        "is_google": False, "is_godaddy": False,
        "auth_order": ["password", "token"],
        "auth_hints": {
            "password": "Try your email password or app-specific password",
            "token": "Paste a Bearer token from your email client",
            "cookie": "Import session cookies from browser dev tools",
        }
    }


def _resolve_mx(domain: str) -> list:
    if _HAS_DNS:
        try:
            return [str(r.exchange).lower().rstrip(".")
                    for r in _dns.resolve(domain, "MX")]
        except Exception:
            pass
    try:
        r = subprocess.run(
            ["nslookup", "-type=MX", domain],
            capture_output=True, text=True, timeout=8,
        )
        return [
            l.split("=")[-1].strip().rstrip(".")
            for l in r.stdout.splitlines()
            if "mail exchanger" in l.lower()
        ]
    except Exception:
        return []


def _o365_autodiscover(domain: str) -> bool:
    if not _HAS_REQUESTS:
        return False
    urls = [
        f"https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/{domain}?Protocol=Rest",
        f"https://autodiscover.{domain}/autodiscover/autodiscover.json/v1.0/{domain}?Protocol=Rest",
    ]
    for url in urls:
        try:
            r = _req.get(url, timeout=5, allow_redirects=False)
            if r.status_code in (200, 301, 302):
                return True
        except Exception:
            continue
    return False


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION — METHOD 1: USERNAME + PASSWORD
# ═══════════════════════════════════════════════════════════════

def login_ms_ropc(email_addr: str, password: str) -> tuple:
    """
    Silent Microsoft login via ROPC (Resource Owner Password Credential).
    Tries 6 app client IDs × 3 authority URLs until one returns a
    valid token with Mail scope.

    Returns:
        (access_token, refresh_token, expires_in, None)  on success
        (None, None, 0, error_string)                    on failure

    error_string values with special meaning:
        "wrong_password"  — 100% wrong password
        "mfa_required"    — MFA/Conditional Access — use device code
        "federated"       — ADFS/federated — use device code
        "account_locked"  — account temporarily locked
        "account_disabled"
        "password_expired"
    """
    if not _HAS_MSAL:
        return None, None, 0, "msal library not installed"
    if not _HAS_REQUESTS:
        return None, None, 0, "requests library not installed"

    domain = email_addr.split("@")[-1].lower()
    is_consumer = domain in MS_CONSUMER_DOMAINS

    authorities = (
        [
            "https://login.microsoftonline.com/consumers",
            "https://login.microsoftonline.com/common",
        ] if is_consumer else [
            "https://login.microsoftonline.com/organizations",
            f"https://login.microsoftonline.com/{domain}",
            "https://login.microsoftonline.com/common",
        ]
    )

    scopes   = ["https://graph.microsoft.com/.default"]
    last_err = ""

    for auth in authorities:
        for app_name, cid in MS_APPS:
            try:
                app = _msal.PublicClientApplication(cid, authority=auth)
                res = app.acquire_token_by_username_password(
                    username=email_addr, password=password, scopes=scopes,
                )
                if "access_token" in res:
                    token  = res["access_token"]
                    rtoken = res.get("refresh_token")
                    exp    = time.time() + int(res.get("expires_in", 3600))
                    # Verify the token actually has mail scope
                    h = {"Authorization": f"Bearer {token}"}
                    chk = _req.get(
                        f"{GRAPH}/me/mailFolders/Inbox?$select=totalItemCount",
                        headers=h, timeout=12,
                    )
                    if chk.status_code == 200:
                        log.info("[B2B] ROPC auth OK via %s for %s", app_name, email_addr)
                        return token, rtoken, exp, None
                    if chk.status_code == 403:
                        last_err = f"{app_name}: token valid but no mail scope"
                        continue
                    last_err = f"{app_name}: mail check {chk.status_code}"
                    continue

                e = res.get("error_description", res.get("error", ""))
                if "AADSTS50126" in e:
                    return None, None, 0, "wrong_password"
                if "AADSTS50034" in e:
                    return None, None, 0, "Account not found."
                if "AADSTS50053" in e:
                    return None, None, 0, "Account locked — too many attempts."
                if "AADSTS50057" in e:
                    return None, None, 0, "Account disabled."
                if "AADSTS50055" in e:
                    return None, None, 0, "Password expired — reset it first."
                if any(x in e for x in [
                    "AADSTS50076", "AADSTS50079",
                    "AADSTS50158", "AADSTS7000112",
                ]):
                    return None, None, 0, "mfa_required"
                if "AADSTS50020" in e:
                    # Personal account used on org tenant or vice versa — try next authority
                    last_err = f"{app_name}: wrong tenant ({e[:60]})"
                    continue
                last_err = f"{app_name}: {e[:80]}"

            except Exception as exc:
                s = str(exc)
                if any(x in s for x in ["no element", "XML", "pars"]):
                    return None, None, 0, "federated"
                last_err = f"{app_name}: {s[:60]}"

    return None, None, 0, f"login_failed: {last_err}"


def _ms_refresh_token(refresh_token: str, email_addr: str) -> tuple:
    """
    Use a refresh token to get a new access token.
    Returns (access_token, refresh_token, expires_in, None) or failure tuple.
    """
    if not _HAS_MSAL:
        return None, None, 0, "msal not available"
    domain      = email_addr.split("@")[-1].lower()
    is_consumer = domain in MS_CONSUMER_DOMAINS
    auth        = ("https://login.microsoftonline.com/consumers"
                   if is_consumer
                   else "https://login.microsoftonline.com/organizations")
    for app_name, cid in MS_APPS[:3]:
        try:
            app = _msal.PublicClientApplication(cid, authority=auth)
            res = app.acquire_token_by_refresh_token(
                refresh_token, scopes=["https://graph.microsoft.com/.default"],
            )
            if "access_token" in res:
                return (
                    res["access_token"],
                    res.get("refresh_token", refresh_token),
                    time.time() + int(res.get("expires_in", 3600)),
                    None,
                )
        except Exception:
            continue
    return None, None, 0, "refresh_failed"


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION — METHOD 2: DEVICE CODE (BROWSER POPUP)
# ═══════════════════════════════════════════════════════════════

def start_device_code(email_addr: str, state: dict,
                      custom_client_id: str = "", custom_tenant: str = "") -> Optional[dict]:
    """
    Start device code flow. If custom_client_id is provided, use that app instead of
    the built-in public app list. Required for tenants with admin consent enforcement.
    Returns {"user_code": ..., "verification_uri": ..., "app": ..., "expires_in": ...} or None.
    """
    if not _HAS_MSAL:
        return None

    domain      = email_addr.split("@")[-1].lower()
    is_consumer = domain in MS_CONSUMER_DOMAINS

    # If user provided their own registered Azure app, use it exclusively
    if custom_client_id:
        tenant = custom_tenant or domain
        auth   = f"https://login.microsoftonline.com/{tenant}"
        scopes = ["Mail.Read", "Mail.Send", "User.Read"]
        try:
            app  = _msal.PublicClientApplication(custom_client_id, authority=auth)
            flow = app.initiate_device_flow(scopes=scopes)
            if "user_code" not in flow:
                log.warning("[B2B] custom app device flow failed: %s", flow.get("error_description",""))
                return None
            state["device_flow"]  = flow
            state["device_app"]   = app
            state["device_email"] = email_addr
            flow["client_id"]     = custom_client_id
            flow["_tenant"]       = tenant
            log.info("[B2B] device code via custom app/%s for %s", tenant, email_addr)
            return {
                "user_code":        flow["user_code"],
                "verification_uri": flow.get("verification_uri", "https://microsoft.com/devicelogin"),
                "app":              "Custom App",
                "expires_in":       flow.get("expires_in", 900),
            }
        except Exception as e:
            log.warning("[B2B] custom app device flow error: %s", e)
            return None

    if is_consumer:
        authorities = [
            "https://login.microsoftonline.com/consumers",
            "https://login.microsoftonline.com/common",
        ]
    else:
        authorities = [
            "https://login.microsoftonline.com/organizations",
            "https://login.microsoftonline.com/common",
        ]

    # Short scope names work with Azure CLI + organizations authority
    # Full Graph URIs cause AADSTS65002 on tenant-specific authorities
    MS_SCOPES_GRAPH = [
        "Mail.Read",
        "Mail.Send",
        "User.Read",
    ]
    scope_sets = [MS_SCOPES_GRAPH]

    for app_name, cid in MS_APPS:
        for auth in authorities:
            for scopes in scope_sets:
                try:
                    app  = _msal.PublicClientApplication(cid, authority=auth)
                    flow = app.initiate_device_flow(scopes=scopes)
                    if "user_code" not in flow:
                        log.debug("[B2B] device code %s/%s no user_code, skipping", app_name, auth)
                        continue
                    state["device_flow"]  = flow
                    state["device_app"]   = app
                    state["device_email"] = email_addr
                    flow["client_id"]     = cid
                    flow["_tenant"]       = auth.split("/")[-1]  # "organizations" or "common" or "consumers"
                    log.info("[B2B] device code via %s/%s for %s", app_name, auth, email_addr)
                    return {
                        "user_code":        flow["user_code"],
                        "verification_uri": flow["verification_uri"],
                        "app":              app_name,
                        "expires_in":       flow.get("expires_in", 900),
                    }
                except Exception as exc:
                    log.debug("[B2B] device code %s/%s failed: %s", app_name, auth, exc)
                    continue
    return None


def poll_device_code(state: dict) -> dict:
    flow = state.get("device_flow")
    app  = state.get("device_app")
    if not flow or not app:
        if state.get("ms_token"):
            return {"ok": True, "token": state["ms_token"], "expires": state.get("ms_token_expires", 0)}
        return {"ok": False, "waiting": True}

    # Get client_id and device_code directly from flow dict
    client_id   = flow.get("client_id") or getattr(app, "_client_id", None) or getattr(app, "client_id", None)
    device_code = flow.get("device_code")
    # Get tenant from the verification_uri authority or stored in flow
    tenant      = flow.get("_tenant", "organizations")

    log.debug("[B2B] poll direct: client_id=%s device_code=%s tenant=%s", client_id, device_code[:8] if device_code else None, tenant)

    if not client_id or not device_code:
        log.warning("[B2B] poll: missing client_id or device_code — client_id=%s code=%s", client_id, bool(device_code))
        return {"ok": False, "waiting": True}

    try:
        import requests as _r
        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        resp = _r.post(token_url, data={
            "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
            "client_id":   client_id,
            "device_code": device_code,
        }, timeout=8)
        res = resp.json()
        log.debug("[B2B] poll token response: %s", {k:v for k,v in res.items() if k != "access_token"})
    except Exception as e:
        log.warning("[B2B] poll direct HTTP failed: %s", e)
        return {"ok": False, "waiting": True}

    if "access_token" in res:
        token  = res["access_token"]
        rtoken = res.get("refresh_token")
        exp    = time.time() + int(res.get("expires_in", 3600))
        granted_scopes = res.get("scope", "")
        log.info("[B2B] device code auth completed for %s — scopes: %s", state.get("device_email", "?"), granted_scopes)
        state["ms_token"]         = token
        state["ms_refresh_token"] = rtoken
        state["ms_token_expires"] = exp
        state["device_flow"]      = None
        state["device_app"]       = None
        return {"ok": True, "token": token, "expires": exp}

    err      = res.get("error", "")
    err_desc = res.get("error_description", err)

    if err in ("authorization_pending", "slow_down"):
        return {"ok": False, "waiting": True}
    if err in ("code_expired", "expired_token"):
        state["device_flow"] = None
        state["device_app"]  = None
        return {"ok": False, "error": "Code expired — start a new login"}
    if "54005" in err_desc or "already redeemed" in err_desc.lower():
        if state.get("ms_token"):
            return {"ok": True, "token": state["ms_token"], "expires": state.get("ms_token_expires", 0)}
        return {"ok": False, "waiting": True}

    log.warning("[B2B] device poll unexpected error: %s — %s", err, err_desc[:200])
    return {"ok": False, "error": err_desc[:200]}


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION — METHOD 4: OAUTH2 AUTH CODE (Azure App)
# ═══════════════════════════════════════════════════════════════

def build_oauth_url(client_id: str, redirect_uri: str, tenant: str = "organizations",
                    state: str = "") -> str:
    """
    Build the Microsoft OAuth2 authorize URL.
    User visits this URL, signs in (MFA fine), gets redirected back with ?code=...
    """
    from urllib.parse import urlencode
    scopes = " ".join([
        "https://graph.microsoft.com/Mail.Read",
        "https://graph.microsoft.com/Mail.Send",
        "https://graph.microsoft.com/User.Read",
        "offline_access",
    ])
    params = {
        "client_id":     client_id,
        "response_type": "code",
        "redirect_uri":  redirect_uri,
        "scope":         scopes,
        "response_mode": "query",
        "state":         state or "synthtel",
        "prompt":        "select_account",
    }
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


def exchange_oauth_code(client_id: str, client_secret: str, redirect_uri: str,
                        code: str, tenant: str = "organizations") -> dict:
    """
    Exchange auth code for access + refresh token.
    Returns {"access_token": ..., "refresh_token": ..., "expires_in": ...}
    or {"error": ..., "error_description": ...}
    """
    if not _HAS_REQUESTS:
        return {"error": "requests_missing", "error_description": "requests not installed"}
    from urllib.parse import urlencode
    scopes = " ".join([
        "https://graph.microsoft.com/Mail.Read",
        "https://graph.microsoft.com/Mail.Send",
        "https://graph.microsoft.com/User.Read",
        "offline_access",
    ])
    data = {
        "client_id":     client_id,
        "client_secret": client_secret,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
        "code":          code,
        "scope":         scopes,
    }
    try:
        resp = _req.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data=data, timeout=20
        )
        return resp.json()
    except Exception as e:
        return {"error": "request_failed", "error_description": str(e)}

# ═══════════════════════════════════════════════════════════════

def login_token(email_addr: str, token: str, state: dict,
                expires_in: int = 3600) -> dict:
    """
    Accept a pre-obtained Bearer token — e.g. grabbed from browser
    cookies, captured from another OAuth flow, or injected by the UI.

    Validates the token against Graph /me before accepting.

    Returns {"ok": True, "display_name": ..., "inbox_count": ...}
         or {"ok": False, "error": ...}
    """
    if not _HAS_REQUESTS:
        return {"ok": False, "error": "requests not installed"}
    try:
        # Strip "Bearer " prefix if user copied the full header value
        token = token.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        h   = {"Authorization": f"Bearer {token}"}
        me  = _req.get(f"{GRAPH}/me?$select=displayName,mail,userPrincipalName",
                       headers=h, timeout=10)
        if me.status_code == 401:
            return {"ok": False, "error": "Token rejected — invalid or expired"}
        if not me.ok:
            return {"ok": False, "error": f"Graph /me returned {me.status_code}"}
        info = me.json()
        # Verify mail access
        chk = _req.get(
            f"{GRAPH}/me/mailFolders/Inbox?$select=totalItemCount",
            headers=h, timeout=10,
        )
        if chk.status_code == 403:
            return {"ok": False, "error": "Token valid but missing Mail.Read scope"}
        count = chk.json().get("totalItemCount", 0) if chk.ok else 0

        state["ms_token"]         = token
        state["ms_refresh_token"] = None
        state["ms_token_expires"] = time.time() + expires_in
        state["email"]            = email_addr or info.get("mail") or info.get("userPrincipalName", "")
        log.info("[B2B] token login OK for %s", state["email"])
        return {
            "ok":           True,
            "display_name": info.get("displayName", ""),
            "inbox_count":  count,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION — IMAP LOGIN (Gmail / GoDaddy / any IMAP)
# ═══════════════════════════════════════════════════════════════

def login_imap(prov: dict, email_addr: str, password: str) -> tuple:
    """
    Authenticate via IMAP with a full fallback chain:
      1. SSL on provider's configured port (993 / 1143 for ProtonMail Bridge)
      2. Auth error on provider that needs app-pw → return ("needs_app_pw", ...)
      3. STARTTLS on port 143
      4. Alternate hostnames: imap.domain, mail.domain

    For GoDaddy: tries secureserver.net hosts with SSL.
    For Google Workspace: tries imap.gmail.com (requires app password or
      IMAP enabled in Google Admin console).

    Returns:
        (imaplib.IMAP4_instance, "")          on success
        (None, "needs_app_pw")                app password required
        (None, "auth_failed: ...")            wrong credentials
        (None, "connection_failed: ...")      can't reach server
    """
    host     = prov.get("imap_host", "")
    port     = int(prov.get("imap_port", 993))
    domain   = prov.get("domain", "")
    is_godaddy = prov.get("is_godaddy", False)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # permissive — some corp certs are self-signed

    def _try_ssl(h: str, p: int, user: str, pw: str):
        try:
            if p == 1143:
                m = imaplib.IMAP4(h, p)
            else:
                m = imaplib.IMAP4_SSL(h, p, ssl_context=ctx)
            m.login(user, pw)
            return m, ""
        except imaplib.IMAP4.error as exc:
            return None, str(exc)
        except ssl.SSLError as exc:
            return None, f"SSL error: {exc}"
        except OSError as exc:
            return None, f"Connection refused: {exc}"
        except Exception as exc:
            return None, str(exc)

    def _try_starttls(h: str, p: int, user: str, pw: str):
        try:
            m = imaplib.IMAP4(h, p)
            m.starttls(ssl_context=ctx)
            m.login(user, pw)
            return m, ""
        except Exception as exc:
            return None, str(exc)

    def _is_auth_error(e: str) -> bool:
        return any(x in e.lower() for x in [
            "authentication", "credentials", "auth", "login failed",
            "authenticationfailed", "[auth]", "too many login",
            "invalid password", "wrong password",
        ])

    # --- Attempt 1: primary host + SSL ---
    conn, err = _try_ssl(host, port, email_addr, password)
    if conn:
        log.info("[B2B] IMAP SSL OK: %s:%d for %s", host, port, email_addr)
        return conn, ""

    if _is_auth_error(err):
        if prov.get("needs_app_pw"):
            return None, "needs_app_pw"
        return None, f"auth_failed: {err}"

    # --- Attempt 2: STARTTLS on port 143 ---
    conn, err2 = _try_starttls(host, 143, email_addr, password)
    if conn:
        log.info("[B2B] IMAP STARTTLS OK: %s:143 for %s", host, email_addr)
        return conn, ""

    # --- Attempt 3: GoDaddy alternate host ---
    if is_godaddy:
        for gd_host in ["imap.secureserver.net", "imap.1and1.com"]:
            conn, _ = _try_ssl(gd_host, 993, email_addr, password)
            if conn:
                log.info("[B2B] GoDaddy IMAP OK via %s", gd_host)
                return conn, ""

    # --- Attempt 4: generic alternate hostnames ---
    for alt in [f"imap.{domain}", f"mail.{domain}"]:
        if alt == host:
            continue
        conn, _ = _try_ssl(alt, 993, email_addr, password)
        if conn:
            log.info("[B2B] Alt IMAP OK: %s for %s", alt, email_addr)
            return conn, ""
        conn, _ = _try_ssl(alt, 993, email_addr, password)
        if conn:
            return conn, ""

    return None, f"connection_failed: {err2 or err}"


# ═══════════════════════════════════════════════════════════════
# FOLDER LISTING
# ═══════════════════════════════════════════════════════════════

def list_folders_ms(token: str) -> list:
    """
    Return all MS Graph mail folders with message counts.
    Includes child folders (Inbox/sub-folders etc).
    """
    if not _HAS_REQUESTS:
        return []
    h       = {"Authorization": f"Bearer {token}"}
    folders = []
    url     = f"{GRAPH}/me/mailFolders?$select=displayName,totalItemCount,id&$top=50&$includeHiddenFolders=false"
    while url:
        try:
            r = _req.get(url, headers=h, timeout=15)
            if not r.ok:
                log.warning("[B2B] list_folders error: %d", r.status_code)
                break
            d = r.json()
            for f in d.get("value", []):
                folders.append({
                    "id":    f["id"],
                    "name":  f["displayName"],
                    "count": f.get("totalItemCount", 0),
                })
                # Fetch child folders
                child_url = f"{GRAPH}/me/mailFolders/{f['id']}/childFolders?$select=displayName,totalItemCount,id&$top=50"
                try:
                    cr = _req.get(child_url, headers=h, timeout=10)
                    if cr.ok:
                        for cf in cr.json().get("value", []):
                            folders.append({
                                "id":    cf["id"],
                                "name":  f"{f['displayName']} / {cf['displayName']}",
                                "count": cf.get("totalItemCount", 0),
                            })
                except Exception:
                    pass
            url = d.get("@odata.nextLink")
        except Exception as exc:
            log.warning("[B2B] list_folders_ms: %s", exc)
            break
    return folders


def list_folders_imap(conn: imaplib.IMAP4) -> list:
    """
    Return all IMAP folders with message counts.
    Handles various server LIST response formats.
    """
    folders = []
    try:
        status, lst = conn.list()
        if status != "OK":
            return []
        for item in lst:
            if not item:
                continue
            try:
                raw = (item.decode("utf-8", errors="replace")
                       if isinstance(item, bytes) else str(item))
                # IMAP LIST: (\Flag \Flag) "/" "Folder Name"
                # Name may or may not be quoted
                m = re.search(r'\s"([^"]+)"\s*$', raw)
                if not m:
                    m = re.search(r'\s(/|NIL)\s+(.+)$', raw)
                    name = m.group(2).strip('" ') if m else ""
                else:
                    name = m.group(1)
                name = name.strip()
                if not name or name.upper() in ("NIL",):
                    continue
                try:
                    s2, cnt_data = conn.status(f'"{name}"', "(MESSAGES)")
                    raw_cnt = (cnt_data[0] or b"").decode(errors="replace") if isinstance(cnt_data[0], bytes) else str(cnt_data[0] or "")
                    cnt_m = re.search(r"MESSAGES (\d+)", raw_cnt)
                    count = int(cnt_m.group(1)) if cnt_m else 0
                except Exception:
                    count = 0
                folders.append({"id": name, "name": name, "count": count,
                                 "displayName": name, "totalItemCount": count})
            except Exception:
                continue
    except Exception as exc:
        log.warning("[B2B] list_folders_imap: %s", exc)
    return folders


# Standard O365 folder names used as fallback when no token/conn available
_O365_STANDARD_FOLDERS = [
    ("Inbox",          "inbox",          "Inbox"),
    ("Sent Items",     "sentitems",      "SentItems"),
    ("Deleted Items",  "deleteditems",   "DeletedItems"),
    ("Junk Email",     "junkemail",      "JunkEmail"),
    ("Drafts",         "drafts",         "Drafts"),
    ("Archive",        "archive",        "Archive"),
    ("Clutter",        "clutter",        "Clutter"),
]


def list_folders_owa(session) -> list:
    """
    List O365 folders using an OWA HTTP session (cookie auth).
    First tries Graph API with the session cookies (works if cookies include
    access token hints), then tries EWS FindFolder SOAP, then returns
    standard O365 folder stubs.
    """
    if not _HAS_REQUESTS:
        return []

    h_base = {"User-Agent": _UA, "Accept": "application/json"}

    # Attempt 1 — Graph API directly with OWA session cookies
    try:
        r = session.get(
            f"{GRAPH}/me/mailFolders?$select=displayName,totalItemCount,id&$top=50",
            headers=h_base, timeout=15,
        )
        if r.ok:
            folders = []
            for f in r.json().get("value", []):
                folders.append({
                    "id":             f.get("id", f.get("displayName","")),
                    "name":           f.get("displayName",""),
                    "displayName":    f.get("displayName",""),
                    "totalItemCount": f.get("totalItemCount", 0),
                })
            if folders:
                log.info("[B2B] list_folders_owa: Graph returned %d folders", len(folders))
                return sorted(folders, key=lambda x: -x["totalItemCount"])
    except Exception as e:
        log.debug("[B2B] list_folders_owa Graph: %s", e)

    # Attempt 2 — EWS FindFolder SOAP with OWA session cookies
    ews_soap = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1"/>
  </soap:Header>
  <soap:Body>
    <m:FindFolder Traversal="Shallow">
      <m:FolderShape>
        <t:BaseShape>AllProperties</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="folder:TotalCount"/>
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="msgfolderroot"/>
      </m:ParentFolderIds>
    </m:FindFolder>
  </soap:Body>
</soap:Envelope>"""
    try:
        r = session.post(
            "https://outlook.office365.com/EWS/Exchange.asmx",
            data=ews_soap,
            headers={
                "User-Agent":   _UA,
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction":   '"http://schemas.microsoft.com/exchange/services/2006/messages/FindFolder"',
            },
            timeout=20,
        )
        if r.ok and "<m:FindFolderResponse" in r.text:
            folders = []
            for m in re.finditer(
                r'<t:DisplayName>([^<]+)</t:DisplayName>.*?<t:TotalCount>(\d+)</t:TotalCount>',
                r.text, re.DOTALL
            ):
                name  = m.group(1).strip()
                count = int(m.group(2))
                folders.append({
                    "id": name, "name": name,
                    "displayName": name, "totalItemCount": count,
                })
            if folders:
                log.info("[B2B] list_folders_owa: EWS returned %d folders", len(folders))
                return sorted(folders, key=lambda x: -x["totalItemCount"])
    except Exception as e:
        log.debug("[B2B] list_folders_owa EWS: %s", e)

    # Fallback — return standard O365 folder stubs with unknown counts
    log.info("[B2B] list_folders_owa: returning standard folder stubs")
    return [
        {"id": fid, "name": name, "displayName": name, "totalItemCount": -1}
        for name, fid, _ in _O365_STANDARD_FOLDERS
    ]


def extract_owa_session(
    session,
    folders:        list,
    limit:          int  = 2000,
    filter_generic: bool = True,
    only_domains:   set  = None,
    block_domains:  set  = None,
    days_back:      int  = 90,
) -> "Generator":
    """
    Extract sender emails using an OWA HTTP session (cookie auth).
    Tries multiple approaches in order:
      1. OWA internal REST (service.svc FindItem) — works with OWA session cookies
      2. EWS SOAP — works if tenant allows EWS with session cookies
      3. OWA search scrape — last resort
    """
    import datetime as _dt
    import json as _json

    date_after_dt = _dt.datetime.utcnow() - _dt.timedelta(days=days_back)
    date_after    = date_after_dt.strftime("%Y-%m-%dT00:00:00Z")
    seen:  set = set()
    total: int = 0

    GENERIC_RE = re.compile(
        r'^(noreply|no[-.]reply|donotreply|do-not-reply|info|admin|support|help|'
        r'contact|sales|billing|newsletter|notifications?|alerts?|automated|mailer|'
        r'bounce|postmaster|hostmaster|webmaster|abuse|unsubscribe)', re.I
    )

    folder_map = {
        "inbox": "inbox", "sent items": "sentitems", "sentitems": "sentitems",
        "deleted items": "deleteditems", "deleteditems": "deleteditems",
        "junk email": "junkemail", "junkemail": "junkemail",
        "drafts": "drafts", "archive": "archive",
    }

    def _keep(addr):
        addr = addr.strip().lower()
        if not addr or "@" not in addr or addr in seen: return False
        if filter_generic and GENERIC_RE.match(addr.split("@")[0]): return False
        if only_domains and addr.split("@")[-1] not in only_domains: return False
        if block_domains and addr.split("@")[-1] in block_domains: return False
        return True

    # ── Strategy 1: OWA internal service.svc REST API ─────────────
    # This is what the Outlook web app itself uses — works with session cookies
    yield {"type": "progress", "msg": "Trying OWA internal API…"}

    # First get the OWA canary token (CSRF) from the mail page
    canary = ""
    try:
        r_mail = session.get("https://outlook.office365.com/mail/",
                             headers={"User-Agent": _UA}, timeout=15)
        canary_m = re.search(r'"owaCanary"\s*:\s*"([^"]+)"', r_mail.text)
        if not canary_m:
            canary_m = re.search(r'X-OWA-Canary["\s]*:\s*["\s]*([A-Za-z0-9_\-+=/]{20,})', r_mail.text)
        if canary_m:
            canary = canary_m.group(1)
            yield {"type": "progress", "msg": f"OWA canary obtained ({len(canary)} chars)"}
        else:
            yield {"type": "progress", "msg": "No OWA canary found in page — cookies may not be authenticated"}
    except Exception as e:
        yield {"type": "progress", "msg": f"OWA page load: {e}"}

    owa_worked = False

    if canary:
        for folder_ref in (folders or ["inbox"]):
            if total >= limit:
                break
            folder_id  = folder_map.get(folder_ref.lower(), folder_ref)
            offset_owa = 0
            page_size  = 50
            folder_found = 0

            while total < limit:
                payload = {
                    "__type": "FindItemJsonRequest:#Exchange",
                    "Header": {
                        "__type": "JsonRequestHeaders:#Exchange",
                        "RequestServerVersion": "Exchange2013",
                        "TimeZoneContext": {
                            "__type": "TimeZoneContext:#Exchange",
                            "TimeZoneDefinition": {"__type": "TimeZoneDefinitionType:#Exchange", "Id": "UTC"}
                        }
                    },
                    "Body": {
                        "__type": "FindItemRequest:#Exchange",
                        "Traversal": "Shallow",
                        "ItemShape": {
                            "__type": "ItemResponseShape:#Exchange",
                            "BaseShape": "IdOnly",
                            "AdditionalProperties": [
                                {"__type": "PropertyUri:#Exchange", "FieldURI": "message:From"},
                                {"__type": "PropertyUri:#Exchange", "FieldURI": "message:Sender"},
                            ]
                        },
                        "IndexedPageItemView": {
                            "__type": "IndexedPageView:#Exchange",
                            "BasePoint": "Beginning",
                            "Offset": offset_owa,
                            "MaxEntriesReturned": page_size,
                        },
                        "ParentFolderIds": [
                            {"__type": "DistinguishedFolderId:#Exchange", "Id": folder_id}
                        ],
                        "SortOrder": [
                            {"__type": "FieldOrder:#Exchange", "Order": "Descending",
                             "Field": {"__type": "PropertyUri:#Exchange", "FieldURI": "item:DateTimeReceived"}}
                        ],
                        "Restriction": {
                            "__type": "RestrictionType:#Exchange",
                            "IsGreaterThan": {
                                "__type": "IsGreaterThan:#Exchange",
                                "Item": {"__type": "PropertyUri:#Exchange", "FieldURI": "item:DateTimeReceived"},
                                "FieldURIOrConstant": {
                                    "__type": "FieldURIOrConstant:#Exchange",
                                    "Constant": {"__type": "ConstantValueType:#Exchange", "Value": date_after}
                                }
                            }
                        }
                    }
                }
                try:
                    r = session.post(
                        "https://outlook.office365.com/owa/service.svc?action=FindItem&app=Mail",
                        json=payload,
                        headers={
                            "User-Agent":    _UA,
                            "Action":        "FindItem",
                            "X-OWA-Canary":  canary,
                            "X-Req-Source":  "Mail",
                            "Content-Type":  "application/json; charset=utf-8",
                            "Accept":        "application/json",
                            "Origin":        "https://outlook.office365.com",
                            "Referer":       "https://outlook.office365.com/mail/",
                        },
                        timeout=30,
                    )
                except Exception as e:
                    yield {"type": "progress", "msg": f"OWA svc.svc: {e}"}
                    break

                if not r.ok:
                    yield {"type": "progress", "msg": f"OWA svc {folder_id}: HTTP {r.status_code}"}
                    break

                try:
                    data = r.json()
                except Exception:
                    break

                # Navigate: Body.FindItemResponseMessage.RootFolder.Items[]
                items = []
                try:
                    body = data.get("Body", {})
                    resp = body.get("FindItemResponseMessage", body.get("ResponseMessages", {}).get("Items", [{}])[0] if isinstance(body.get("ResponseMessages",{}).get("Items"), list) else {})
                    root = resp.get("RootFolder", {})
                    items = root.get("Items", [])
                except Exception:
                    pass

                if not items:
                    break

                owa_worked = True
                page_found = 0
                for item in items:
                    for fld in ("From", "Sender"):
                        mbx = item.get(fld, {}).get("Mailbox", {})
                        addr = mbx.get("EmailAddress", "")
                        if _keep(addr):
                            seen.add(addr.lower())
                            total += 1
                            folder_found += 1
                            page_found += 1
                            yield {"type": "lead", "email": addr.lower()}
                            if total >= limit:
                                break
                    if total >= limit:
                        break

                yield {"type": "progress", "msg": f"{folder_id}: {folder_found} found so far",
                       "folder": folder_id, "found": page_found}

                if len(items) < page_size:
                    break
                offset_owa += page_size

    # ── Strategy 2: EWS SOAP fallback ─────────────────────────────
    if not owa_worked:
        yield {"type": "progress", "msg": "OWA API unavailable — trying EWS SOAP…"}
        for folder_ref in (folders or ["inbox"]):
            if total >= limit:
                break
            ews_id_map = {
                "inbox": "inbox", "sentitems": "sentitems", "deleteditems": "deleteditems",
                "junkemail": "junkemail", "drafts": "drafts", "archive": "archive",
            }
            ews_id = ews_id_map.get(folder_ref.lower(), None)
            folder_xml = f'<t:DistinguishedFolderId Id="{ews_id}"/>' if ews_id else f'<t:FolderId Id="{folder_ref}"/>'
            offset = 0
            page_size = 100
            folder_found = 0
            ews_folder_ok = False

            while total < limit:
                soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header><t:RequestServerVersion Version="Exchange2013_SP1"/></soap:Header>
  <soap:Body>
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="message:From"/>
          <t:FieldURI FieldURI="message:Sender"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="{page_size}" Offset="{offset}" BasePoint="Beginning"/>
      <m:Restriction>
        <t:IsGreaterThan>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
          <t:FieldURIOrConstant><t:Constant Value="{date_after}"/></t:FieldURIOrConstant>
        </t:IsGreaterThan>
      </m:Restriction>
      <m:ParentFolderIds>{folder_xml}</m:ParentFolderIds>
    </m:FindItem>
  </soap:Body>
</soap:Envelope>"""
                try:
                    r = session.post(
                        "https://outlook.office365.com/EWS/Exchange.asmx",
                        data=soap,
                        headers={
                            "User-Agent":   _UA,
                            "Content-Type": "text/xml; charset=utf-8",
                            "SOAPAction":   '"http://schemas.microsoft.com/exchange/services/2006/messages/FindItem"',
                        },
                        timeout=30,
                    )
                except Exception as e:
                    yield {"type": "progress", "msg": f"EWS error: {e}"}
                    break

                if not r.ok:
                    if r.status_code in (401, 403):
                        yield {"type": "error", "msg": f"SESSION_AUTH_FAILED: Cookie session rejected by EWS (HTTP {r.status_code}). Use Device Code flow instead."}
                        return
                    break

                if "<soap:Fault>" in r.text or "ErrorAccessDenied" in r.text:
                    err_m = re.search(r'<m:MessageText>([^<]+)</m:MessageText>', r.text)
                    yield {"type": "error", "msg": f"SESSION_AUTH_FAILED: EWS access denied — {err_m.group(1) if err_m else 'no token'}. Use Device Code flow."}
                    return

                emails_in_page = re.findall(
                    r'<t:(?:EmailAddress|Address)>([^<@\s]+@[^<\s]+)</t:(?:EmailAddress|Address)>',
                    r.text
                )
                more_m  = re.search(r'IncludesLastItemInRange="(true|false)"', r.text)
                is_last = (more_m.group(1) == "true") if more_m else True

                for addr in emails_in_page:
                    if _keep(addr):
                        seen.add(addr.lower())
                        total += 1
                        folder_found += 1
                        ews_folder_ok = True
                        yield {"type": "lead", "email": addr.lower()}
                        if total >= limit:
                            break

                yield {"type": "progress", "msg": f"EWS {folder_ref}: {folder_found} found",
                       "folder": folder_ref, "found": folder_found}

                if is_last or not emails_in_page:
                    break
                offset += page_size

    if total == 0 and not owa_worked:
        yield {"type": "error", "msg": "SESSION_AUTH_FAILED: Could not extract emails via session cookies. "
               "Microsoft restricts API access with browser session cookies. "
               "Please use Device Code flow for reliable extraction."}
        return

    yield {"type": "done", "total": total}


# ═══════════════════════════════════════════════════════════════
# EXTRACTION — IMAP
# ═══════════════════════════════════════════════════════════════

def _parse_from_header(raw: str) -> tuple:
    """
    Parse a From: / Sender: header into (email_addr, display_name).
    Handles RFC 2047 encoded-words, angle-bracket format, bare address.
    """
    parts = _decode_hdr(raw or "")
    s = ""
    for p, c in parts:
        s += (p.decode(c or "utf-8", errors="replace")
              if isinstance(p, bytes) else p)
    # Angle-bracket format: "Name <addr@domain>"
    m = re.search(r'<([^>]+@[^>]+)>', s)
    addr = m.group(1).strip().lower() if m else None
    if not addr:
        m2 = re.search(r'[\w.+%-]+@[\w.-]+\.\w+', s)
        addr = m2.group(0).strip().lower() if m2 else None
    name = re.sub(r'<[^>]+>', '', s).strip().strip('"').strip("'").strip()
    return addr, name


def extract_imap(
    conn:           imaplib.IMAP4,
    folders:        list,
    limit:          Optional[int]   = None,
    filter_generic: bool            = True,
    only_domains:   Optional[set]   = None,
    block_domains:  Optional[set]   = None,
    subject_kw:     Optional[str]   = None,
    date_after:     Optional[str]   = None,    # "YYYY-MM-DD"
) -> Generator:
    """
    Generator — reads each selected folder and yields progress events.

    Yields dicts:
        {"type": "log",      "msg": str}
        {"type": "progress", "done": int, "found": int, "folder": str}
        {"type": "extracted","total": int, "found": int, "results": list}
        {"type": "error",    "msg": str}

    Uses BODY.PEEK so messages stay unread.
    Fetches only headers + BODYSTRUCTURE (not body content) for speed.
    """
    raw_results = []
    total_done  = 0

    for folder_name in folders:
        try:
            # Some IMAP servers need the folder quoted
            for sel_name in [f'"{folder_name}"', folder_name]:
                status, _ = conn.select(sel_name, readonly=True)
                if status == "OK":
                    break
            else:
                yield {"type": "log", "msg": f"Cannot open folder: {folder_name}"}
                continue

            # Build search criteria
            if date_after:
                try:
                    dt = datetime.strptime(date_after, "%Y-%m-%d")
                    imap_date = dt.strftime("%d-%b-%Y")
                    crit = f"SINCE {imap_date}"
                except ValueError:
                    crit = "ALL"
            else:
                crit = "ALL"

            st, msgs = conn.search(None, crit)
            if st != "OK":
                continue
            ids = msgs[0].split()
            if not ids:
                continue
            if limit and len(ids) > limit:
                ids = ids[-limit:]  # most recent

            yield {"type": "log",
                   "msg": f"Reading {folder_name}: {len(ids):,} messages"}

            CHUNK = 50
            for i in range(0, len(ids), CHUNK):
                chunk = ids[i : i + CHUNK]
                id_str = b",".join(chunk).decode()
                try:
                    st2, data = conn.fetch(
                        id_str,
                        "(BODY.PEEK[HEADER.FIELDS (FROM DATE SUBJECT CONTENT-TYPE MESSAGE-ID)] BODYSTRUCTURE)",
                    )
                    if st2 != "OK" or not data:
                        continue
                except Exception as exc:
                    yield {"type": "log", "msg": f"Fetch error: {exc}"}
                    continue

                # IMAP fetch returns interleaved tuples and bytes
                current_hdr   = b""
                current_struct = b""
                for part in data:
                    if isinstance(part, tuple):
                        current_hdr += part[1] if isinstance(part[1], bytes) else b""
                    elif isinstance(part, bytes) and part.strip() not in (b")", b""):
                        current_struct += part

                    # When we hit a b")" or end — process what we have
                    if isinstance(part, bytes) and part.strip() == b")":
                        if current_hdr:
                            _process_imap_msg(
                                current_hdr, current_struct,
                                folder_name, filter_generic,
                                only_domains, block_domains, subject_kw,
                                raw_results,
                            )
                            total_done += 1
                            current_hdr   = b""
                            current_struct = b""

                # Process any remaining
                if current_hdr:
                    _process_imap_msg(
                        current_hdr, current_struct,
                        folder_name, filter_generic,
                        only_domains, block_domains, subject_kw,
                        raw_results,
                    )
                    total_done += len(chunk) - sum(
                        1 for _ in data if isinstance(_, bytes) and _.strip() == b")"
                    )
                    total_done = max(total_done, i + len(chunk))

                yield {
                    "type": "progress",
                    "done": min(total_done, i + len(chunk)),
                    "found": len(raw_results),
                    "folder": folder_name,
                }

        except Exception as exc:
            yield {"type": "error", "msg": f"Folder {folder_name}: {exc}"}

    yield {
        "type":    "extracted",
        "total":   total_done,
        "found":   len(raw_results),
        "results": raw_results,
    }


def _process_imap_msg(
    raw_header:   bytes,
    raw_struct:   bytes,
    folder_name:  str,
    filter_generic: bool,
    only_domains: Optional[set],
    block_domains: Optional[set],
    subject_kw:   Optional[str],
    out:          list,
) -> None:
    """Parse one IMAP message header block and append to out if it passes filters."""
    try:
        msg_hdr = email.message_from_bytes(raw_header)
        addr, name = _parse_from_header(msg_hdr.get("From", ""))
        if not addr or "@" not in addr:
            return

        if filter_generic and is_generic(addr):
            return

        edom = addr.split("@")[-1]
        if only_domains and edom not in only_domains:
            return
        if block_domains and edom in block_domains:
            return

        subj_raw = (msg_hdr.get("Subject", "") or "")
        if subject_kw and subject_kw.lower() not in subj_raw.lower():
            return

        ct         = (msg_hdr.get("Content-Type", "") or "").lower()
        struct_str = (raw_struct.decode("utf-8", errors="replace")
                      if raw_struct else "").upper()
        is_html    = "text/html" in ct or '"TEXT" "HTML"' in struct_str
        has_att    = any(x in struct_str for x in [
            ".PDF", ".DOC", ".XLS", ".PPT", ".ZIP", ".RAR",
            ".CSV", "APPLICATION/", "\"ATTACHMENT\"",
        ])

        message_id = (msg_hdr.get("Message-ID", "") or "").strip()
        date_raw   = (msg_hdr.get("Date", "") or "")[:30]

        out.append({
            "addr":       addr,
            "name":       name or "",
            "date":       date_raw,
            "subject":    subj_raw[:150],
            "message_id": message_id,
            "is_html":    is_html,
            "has_att":    has_att,
            "folder":     folder_name,
        })
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# EXTRACTION — MS GRAPH
# ═══════════════════════════════════════════════════════════════

def extract_graph(
    token:          str,
    folder_ids:     list,             # list of Graph folder IDs or ["Inbox"]
    limit:          Optional[int]   = None,
    filter_generic: bool            = True,
    only_domains:   Optional[set]   = None,
    block_domains:  Optional[set]   = None,
    subject_kw:     Optional[str]   = None,
    date_after:     Optional[str]   = None,
) -> Generator:
    """
    Generator — reads each folder via MS Graph API and yields progress events.
    Same event schema as extract_imap.
    """
    if not _HAS_REQUESTS:
        yield {"type": "error", "msg": "requests library not available"}
        return

    h           = {"Authorization": f"Bearer {token}"}
    raw_results = []
    total_done  = 0
    cap         = int(limit) if limit else 999999

    for folder_id in (folder_ids or ["Inbox"]):
        yield {"type": "log", "msg": f"Connecting to folder: {folder_id}"}

        # Build filter
        filters = []
        if date_after:
            # Ensure clean ISO format without duplicate timezone suffix
            date_str = date_after.replace("T00:00:00Z","").replace("T00:00:00","").strip()
            filters.append(f"receivedDateTime ge {date_str}T00:00:00Z")

        if folder_id == "Inbox" or folder_id.lower() == "inbox":
            base = f"{GRAPH}/me/mailFolders/Inbox/messages"
        else:
            base = f"{GRAPH}/me/mailFolders/{folder_id}/messages"

        params = {
            "$select":  "from,receivedDateTime,subject,hasAttachments,"
                        "internetMessageId,conversationId",
            "$top":     100,
        }
        if filters:
            params["$filter"] = " and ".join(filters)
        else:
            params["$orderby"] = "receivedDateTime desc"

        url  = base
        done = 0

        while url and (total_done + done) < cap:
            try:
                r = _req.get(url, headers=h, params=params, timeout=30)
                if r.status_code == 401:
                    yield {"type": "error", "msg": "Session expired — token invalid"}
                    return
                if not r.ok:
                    try:
                        err_detail = r.json().get("error",{}).get("message","")[:200]
                    except Exception:
                        err_detail = r.text[:200]
                    yield {"type": "error", "msg": f"Graph API {r.status_code}: {err_detail}"}
                    break
                data = r.json()
                msgs = data.get("value", [])
                if not msgs:
                    break

                for m in msgs:
                    if (total_done + done) >= cap:
                        break
                    done += 1
                    try:
                        frm   = (m.get("from") or {}).get("emailAddress") or {}
                        addr  = (frm.get("address") or "").strip().lower()
                        name  = (frm.get("name") or "").strip()
                        if not addr or "@" not in addr:
                            continue
                    except Exception:
                        continue

                    if filter_generic and is_generic(addr):
                        continue
                    edom = addr.split("@")[-1]
                    if only_domains and edom not in only_domains:
                        continue
                    if block_domains and edom in block_domains:
                        continue
                    subj = (m.get("subject", "") or "")
                    if subject_kw and subject_kw.lower() not in subj.lower():
                        continue

                    body_type = ((m.get("body") or {}).get("contentType") or "").lower()
                    has_att   = m.get("hasAttachments", False)
                    is_html   = body_type == "html"
                    msg_id    = (m.get("internetMessageId") or "").strip()
                    dt        = (m.get("receivedDateTime") or "")[:19].replace("T", " ")

                    raw_results.append({
                        "addr":       addr,
                        "name":       name,
                        "date":       dt,
                        "subject":    subj[:150],
                        "message_id": msg_id,
                        "is_html":    is_html,
                        "has_att":    has_att,
                        "folder":     folder_id,
                        "conv_id":    m.get("conversationId", ""),
                    })

                url    = data.get("@odata.nextLink")
                params = {}
                total_done += done
                done = 0
                yield {
                    "type":   "progress",
                    "done":   total_done,
                    "found":  len(raw_results),
                    "folder": folder_id,
                }

            except Exception as exc:
                yield {"type": "error", "msg": str(exc)}
                break

    yield {
        "type":    "extracted",
        "total":   total_done,
        "found":   len(raw_results),
        "results": raw_results,
    }


# ═══════════════════════════════════════════════════════════════
# SANITISE + DEDUPLICATE + SCORE
# ═══════════════════════════════════════════════════════════════

# Freemail domains — lower score (personal rather than business)
_FREEMAIL = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
    "yahoo.co.uk", "yahoo.co.jp", "yahoo.com.au",
    "hotmail.com", "hotmail.co.uk", "hotmail.fr",
    "outlook.com", "live.com", "live.ca", "live.co.uk",
    "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.net", "gmx.de", "web.de",
    "protonmail.com", "proton.me", "pm.me",
    "fastmail.com", "fastmail.fm",
    "zoho.com", "zohomail.com",
})


def sanitize_leads(
    raw_results:     list,
    filter_generic:  bool = True,
    dedup_domain:    bool = False,
    score_threshold: int  = 0,
) -> list:
    """
    Convert raw extraction results into sorted, deduplicated B2BLead objects.

    Deduplication:
      - Per email address: keeps the most recent message for reply threading
        and collects all message IDs across conversations.
      - If dedup_domain=True: keeps only the highest-scored lead per domain.

    Scoring (0-100):
      +20  Sent you 2+ emails (engaged repeat sender)
      +15  Has a real display name (not just email address)
      +10  Used HTML email (formatted, not plain-text auto-replies)
      +15  Included an attachment (strong B2B signal)
      +20  Business domain (not Gmail/Yahoo/Hotmail/etc.)
      +20  Email received within the last 90 days (still active)

    Returns list sorted by score descending.
    """
    if not raw_results:
        return []

    by_addr: dict = defaultdict(list)
    for r in raw_results:
        addr = (r.get("addr") or "").strip().lower()
        if not addr or "@" not in addr:
            continue
        if filter_generic and is_generic(addr):
            continue
        by_addr[addr].append(r)

    ninety_ago = datetime.utcnow() - timedelta(days=90)
    leads      = []

    for addr, msgs in by_addr.items():
        # Sort most recent first
        def _dt(r):
            raw = (r.get("date") or "")[:10]
            for fmt in ("%Y-%m-%d", "%d-%b-%Y"):
                try:
                    return datetime.strptime(raw, fmt)
                except ValueError:
                    continue
            return datetime.min
        msgs.sort(key=_dt, reverse=True)

        latest = msgs[0]
        domain = addr.split("@")[-1]
        count  = len(msgs)

        # Deduplicate message IDs (preserving order, most recent first)
        seen_mids : set = set()
        thread_ids: list = []
        for m in msgs:
            mid = (m.get("message_id") or "").strip()
            if mid and mid not in seen_mids:
                seen_mids.add(mid)
                thread_ids.append(mid)

        # Score
        score = 0
        if count > 1:
            score += 20
        if (latest.get("name") or "").strip():
            score += 15
        if latest.get("is_html"):
            score += 10
        if latest.get("has_att"):
            score += 15
        if domain not in _FREEMAIL:
            score += 20
        try:
            if _dt(latest) >= ninety_ago:
                score += 20
        except Exception:
            pass

        if score < score_threshold:
            continue

        leads.append(B2BLead(
            email        = addr,
            name         = (latest.get("name") or ""),
            last_subject = (latest.get("subject") or ""),
            last_date    = (latest.get("date") or ""),
            message_id   = thread_ids[0] if thread_ids else "",
            thread_ids   = thread_ids,
            folder       = (latest.get("folder") or "INBOX"),
            msg_count    = count,
            is_html      = bool(latest.get("is_html")),
            has_att      = bool(latest.get("has_att")),
            score        = score,
        ))

    # Domain dedup — keep highest-scored lead per domain
    if dedup_domain:
        by_dom: dict = {}
        for lead in leads:
            d = lead.email.split("@")[-1]
            if d not in by_dom or lead.score > by_dom[d].score:
                by_dom[d] = lead
        leads = list(by_dom.values())

    leads.sort(key=lambda x: x.score, reverse=True)
    return leads


# ═══════════════════════════════════════════════════════════════
# SEND ENGINE
# ═══════════════════════════════════════════════════════════════

def _make_reply_subject(original: str) -> str:
    s = (original or "").strip()
    return s if re.match(r'^re:\s*', s, re.I) else f"Re: {s}"


def _build_mime(
    from_email:   str,
    from_name:    str,
    to_email:     str,
    to_name:      str,
    subject:      str,
    html:         str,
    plain:        str,
    reply_to_mid: str  = "",
    attachments:  list = None,
) -> MIMEMultipart:
    """
    Build a properly structured MIME message.

    Structure:
      With attachments:  multipart/mixed
                           └── multipart/alternative
                                 ├── text/plain
                                 └── text/html
                           └── attachment(s)
      Without:           multipart/alternative
                           ├── text/plain
                           └── text/html

    Threading: In-Reply-To + References set when reply_to_mid provided.
    """
    if attachments:
        root = MIMEMultipart("mixed")
        alt  = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain or "", "plain", "utf-8"))
        alt.attach(MIMEText(html  or "", "html",  "utf-8"))
        root.attach(alt)
        for att in attachments:
            mime_type = att.get("mime", "application/octet-stream")
            mt, st = (mime_type.split("/", 1) if "/" in mime_type
                      else ("application", "octet-stream"))
            part = MIMEBase(mt, st)
            part.set_payload(att["data"])
            _enc.encode_base64(part)
            part.add_header("Content-Disposition", "attachment",
                            filename=att.get("filename", "attachment"))
            root.attach(part)
    else:
        root = MIMEMultipart("alternative")
        root.attach(MIMEText(plain or "", "plain", "utf-8"))
        root.attach(MIMEText(html  or "", "html",  "utf-8"))

    from_str = f'"{from_name}" <{from_email}>' if from_name else from_email
    to_str   = f'"{to_name}" <{to_email}>'     if to_name   else to_email

    root["From"]       = from_str
    root["To"]         = to_str
    root["Subject"]    = subject
    root["Date"]       = email.utils.formatdate(localtime=False)
    root["Message-ID"] = email.utils.make_msgid(
        domain=from_email.split("@")[-1] if "@" in from_email else "example.com"
    )
    root["MIME-Version"] = "1.0"

    if reply_to_mid:
        mid = reply_to_mid.strip()
        if not mid.startswith("<"):
            mid = f"<{mid}>"
        root["In-Reply-To"] = mid
        root["References"]  = mid

    return root


def _send_via_smtp(
    msg:       MIMEMultipart,
    from_email: str,
    to_email:   str,
    smtp_host:  str,
    smtp_port:  int,
    username:   str,
    password:   str,
    is_godaddy: bool = False,
    proxy_cfg:  Optional[dict] = None,
) -> tuple:
    """
    Send via authenticated SMTP.
    Port 465 → SMTP_SSL.
    Port 587 / other → STARTTLS.
    GoDaddy: uses smtpout.secureserver.net:465 (SSL only).
    If proxy_cfg is supplied, the underlying TCP socket is opened
    through the SOCKS5/HTTP proxy; SSL on port 465 is auto-downgraded
    to STARTTLS on port 587 to keep TLS handshakes working through SOCKS
    (matching the same logic in core.smtp_sender).

    Returns (True, "") or (False, error_string).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    # GoDaddy override
    if is_godaddy:
        smtp_host = "smtpout.secureserver.net"
        smtp_port = 465

    try:
        if proxy_cfg and proxy_cfg.get("host"):
            # Through-proxy: 465 SSL handshakes are unreliable through
            # SOCKS, so transparently downgrade to STARTTLS on 587 (same
            # behaviour as core.smtp_sender). For STARTTLS / plain ports
            # we open the SOCKS socket and hand it to smtplib.
            if smtp_port == 465:
                smtp_port = 587
            sock = _b2b_smtp_socket(smtp_host, smtp_port, proxy_cfg, timeout=30)
            server = smtplib.SMTP(timeout=30)
            server.sock = sock
            # smtplib expects a file-like object for line reads.
            server.file = server.sock.makefile("rb")
            # Read the SMTP banner so the next ehlo() picks up the
            # right initial state.
            try:
                code, _msg = server.getreply()
                if code != 220:
                    raise smtplib.SMTPConnectError(code, _msg)
            except Exception:
                pass
            server._host = smtp_host
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls(context=ctx)
                server.ehlo()
        elif smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port,
                                      context=ctx, timeout=30)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls(context=ctx)
                server.ehlo()

        if username:
            server.login(username, password or "")

        server.send_message(msg, from_addr=from_email, to_addrs=[to_email])
        try:
            server.quit()
        except Exception:
            try:
                server.close()
            except Exception:
                pass
        return True, ""

    except smtplib.SMTPAuthenticationError as exc:
        code = exc.smtp_code
        detail = (exc.smtp_error or b"").decode(errors="replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
        hint = ""
        if code == 535:
            hint = " — wrong password or app password required"
        elif code == 534:
            hint = " — enable 'Less secure app access' or use App Password"
        return False, f"SMTP AUTH {code}: {detail[:100]}{hint}"

    except smtplib.SMTPRecipientsRefused as exc:
        return False, f"Recipient refused: {exc}"

    except smtplib.SMTPSenderRefused as exc:
        return False, f"Sender refused — your From address may not match authenticated account: {exc}"

    except smtplib.SMTPDataError as exc:
        return False, f"SMTP data error {exc.smtp_code}: {exc.smtp_error}"

    except ConnectionRefusedError:
        return False, f"Connection refused: {smtp_host}:{smtp_port}"

    except ssl.SSLError as exc:
        return False, f"SSL error: {exc}"

    except Exception as exc:
        return False, str(exc)[:250]


def _send_via_graph(
    token:        str,
    to_email:     str,
    subject:      str,
    html:         str,
    plain:        str,
    from_name:    str        = "",
    reply_to_mid: str        = "",
    attachments:  list       = None,
    proxy_cfg:    Optional[dict] = None,
) -> tuple:
    """
    Send via Microsoft Graph API /me/sendMail.

    Uses the Graph JSON payload (not MIME upload) so we get proper:
      - toRecipients
      - replyTo / from display name
      - In-Reply-To thread header via singleValueExtendedProperties
      - Attachments as base64

    Returns (True, "") or (False, error_string).
    """
    if not _HAS_REQUESTS:
        return False, "requests library not installed"

    h = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    # Build body
    payload: dict = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "html",
                "content":     html or "",
            },
            "toRecipients": [
                {"emailAddress": {"address": to_email}}
            ],
            # Graph doesn't expose In-Reply-To via standard fields,
            # but we can set it via singleValueExtendedProperties (MAPI)
        },
        "saveToSentItems": True,
    }

    # From display name override (Graph uses the account's configured name
    # but we can override via from field if the account has SendAs permission)
    if from_name:
        payload["message"]["from"] = {
            "emailAddress": {"name": from_name}
        }

    # Reply threading via MAPI extended property
    if reply_to_mid:
        mid = reply_to_mid.strip()
        if not mid.startswith("<"):
            mid = f"<{mid}>"
        payload["message"]["singleValueExtendedProperties"] = [
            {
                "id":    "String 0x1042",   # PR_IN_REPLY_TO_ID
                "value": mid,
            },
        ]

    # Plain text alternative via body (Graph doesn't natively support multipart,
    # so we embed it as a second content item — but Graph will send HTML only;
    # the plain copy is best-effort via MIME upload path below)

    # Attachments
    if attachments:
        att_list = []
        for att in (attachments or []):
            data = att.get("data", b"")
            if isinstance(data, str):
                data = data.encode()
            att_list.append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name":         att.get("filename", "attachment"),
                "contentType":  att.get("mime", "application/octet-stream"),
                "contentBytes": base64.b64encode(data).decode("ascii"),
            })
        payload["message"]["attachments"] = att_list

    try:
        r = _req.post(f"{GRAPH}/me/sendMail", headers=h,
                      json=payload, timeout=45,
                      proxies=_b2b_requests_proxies(proxy_cfg))
        if r.status_code in (200, 202):
            return True, ""
        try:
            err_msg = r.json().get("error", {}).get("message", r.text[:300])
        except Exception:
            err_msg = r.text[:300]
        # Actionable error hints
        hint = ""
        if r.status_code == 401:
            hint = " — token expired, re-login"
        elif r.status_code == 403:
            hint = " — account missing Mail.Send permission"
        elif r.status_code == 429:
            hint = " — rate limited, slow down send rate"
        return False, f"Graph {r.status_code}: {err_msg}{hint}"

    except Exception as exc:
        return False, str(exc)[:250]


def send_b2b(
    account:     B2BAccount,
    leads:       list,
    html:        str,
    subject:     str,
    plain:       str          = "",
    mode:        str          = "new",       # "reply" | "new"
    from_name:   str          = "",
    from_email:  str          = "",
    attachments: list         = None,
    delay:       float        = 1.5,
    jitter:      float        = 1.0,
    batch_size:  int          = 0,
    batch_delay: float        = 30.0,
    max_sends:   int          = 0,
    proxy_cfg:   Optional[dict] = None,
) -> Generator:
    """
    Generator — sends to each B2BLead, yields progress events.

    Yields:
        {"type": "success",  "index": i, "total": N, "email": ..., "via": ...}
        {"type": "error",    "index": i, "total": N, "email": ..., "error": ...}
        {"type": "batch",    "msg": ...}
        {"type": "done",     "success": N, "fail": N, "total": N}

    Reply mode:
        In-Reply-To / References set to lead.message_id
        Subject prefixed with Re:  (skipped if already starts with Re:)

    New mode:
        Clean message, no threading headers
    """
    actual_from = from_email or account.email
    actual_name = from_name  or ""
    atts        = attachments or []
    cap         = max_sends if max_sends > 0 else len(leads)
    is_ms       = bool(account.ms_token) and account.provider.get("type") == "ms"
    is_godaddy  = account.provider.get("is_godaddy", False)

    success_cnt = fail_cnt = 0

    for i, lead in enumerate(leads[:cap]):
        subj = _make_reply_subject(lead.last_subject) if mode == "reply" else subject
        mid  = lead.message_id if mode == "reply" else ""

        # Build MIME (used for SMTP; Graph uses JSON payload)
        mime_msg = _build_mime(
            from_email   = actual_from,
            from_name    = actual_name,
            to_email     = lead.email,
            to_name      = lead.name,
            subject      = subj,
            html         = html,
            plain        = plain,
            reply_to_mid = mid,
            attachments  = atts,
        )

        ok  = False
        err = ""
        via = ""

        if is_ms:
            # Refresh token if expiring
            if account.ms_refresh and not account.ms_token_valid():
                new_tok, new_ref, new_exp, rerr = _ms_refresh_token(
                    account.ms_refresh, account.email,
                )
                if new_tok:
                    account.ms_token         = new_tok
                    account.ms_refresh       = new_ref
                    account.ms_token_expires = new_exp
                else:
                    yield {"type": "error", "index": i + 1, "total": cap,
                           "email": lead.email, "error": f"Token refresh failed: {rerr}"}
                    fail_cnt += 1
                    continue

            ok, err = _send_via_graph(
                token        = account.ms_token,
                to_email     = lead.email,
                subject      = subj,
                html         = html,
                plain        = plain,
                from_name    = actual_name,
                reply_to_mid = mid,
                attachments  = atts,
                proxy_cfg    = proxy_cfg,
            )
            via = "MS Graph"
            if proxy_cfg and proxy_cfg.get("host"):
                via += f" via {proxy_cfg.get('host')}"

        elif account.imap_conn:
            ok, err = _send_via_smtp(
                msg        = mime_msg,
                from_email = actual_from,
                to_email   = lead.email,
                smtp_host  = account.smtp_host,
                smtp_port  = account.smtp_port,
                username   = account.smtp_user or account.email,
                password   = account.smtp_pass,
                is_godaddy = is_godaddy,
                proxy_cfg  = proxy_cfg,
            )
            via = f"SMTP {account.smtp_host}"
            if proxy_cfg and proxy_cfg.get("host"):
                via += f" via {proxy_cfg.get('host')}"

        else:
            err = "No authenticated session — call login first"

        if ok:
            success_cnt += 1
            yield {
                "type":  "success",
                "index": i + 1,
                "total": cap,
                "email": lead.email,
                "via":   via,
                "score": lead.score,
            }
        else:
            fail_cnt += 1
            yield {
                "type":  "error",
                "index": i + 1,
                "total": cap,
                "email": lead.email,
                "error": err,
            }

        # Delay / batch pause
        if batch_size > 0 and (i + 1) % batch_size == 0 and (i + 1) < cap:
            yield {"type": "batch",
                   "msg": f"Batch {(i+1)//batch_size} done — pausing {batch_delay:.0f}s"}
            time.sleep(batch_delay)
        else:
            jit = random.uniform(-jitter, jitter)
            time.sleep(max(0.1, delay + jit))

    yield {
        "type":    "done",
        "success": success_cnt,
        "fail":    fail_cnt,
        "total":   min(cap, len(leads)),
    }


# ═══════════════════════════════════════════════════════════════
# HIGH-LEVEL SESSION WRAPPER
# ═══════════════════════════════════════════════════════════════

class B2BSession:
    """
    Stateful wrapper for one logged-in email account.
    Used directly by Flask API routes in synthtel_server.py.

    Typical lifecycle:
        sess = B2BSession()

        # Step 1 — detect
        prov = sess.detect("user@corp.com")

        # Step 2 — login (choose one method)
        ok, err = sess.login_password("user@corp.com", "pass123")
        # -- or --
        flow    = sess.start_device_code("user@corp.com")
        result  = sess.poll_device_code()         # call until ok=True or error
        # -- or --
        result  = sess.login_token("user@corp.com", "eyJ...")

        # Step 3 — list + extract
        folders = sess.list_folders()
        for event in sess.extract(folders=["Inbox"], filter_generic=True):
            stream_to_client(event)

        # Step 4 — sanitise
        leads = sess.sanitize(dedup_domain=True)

        # Step 5 — send
        for event in sess.send(leads, html="<b>Hi</b>", subject="Hello",
                               mode="reply", from_name="John"):
            stream_to_client(event)

        # Reset
        sess.reset()
    """

    def __init__(self):
        self._s = {
            "ms_token":         None,
            "ms_token_expires": 0.0,
            "ms_refresh":       None,
            "imap_conn":        None,
            "provider":         None,
            "email":            None,
            "smtp_host":        "",
            "smtp_port":        587,
            "smtp_pass":        "",
            "raw_results":      [],
            "leads":            [],
            "device_flow":      None,
            "device_app":       None,
            "device_email":     None,
        }

    # ── Provider detection ──────────────────────────────────────

    def detect(self, email_addr: str) -> dict:
        prov = detect(email_addr)
        self._s["provider"] = prov
        self._s["email"]    = email_addr
        return prov

    # ── Login: Method 1 — password ──────────────────────────────

    def login_password(self, email_addr: str, password: str) -> tuple:
        """
        Try password login.
        Returns (True, None) on success or (False, error_string) on failure.

        For Microsoft accounts: tries ROPC → on mfa_required/federated,
        returns the error so the UI can offer the browser popup.

        For IMAP: tries SSL → STARTTLS → alt hosts.
        """
        if not self._s.get("provider"):
            self._s["provider"] = detect(email_addr)
        prov = self._s["provider"]
        self._s["email"] = email_addr

        if prov["type"] in ("ms", "unknown"):
            tok, reftok, exp, err = login_ms_ropc(email_addr, password)
            if tok:
                self._s["ms_token"]         = tok
                self._s["ms_refresh"]       = reftok
                self._s["ms_token_expires"] = exp
                return True, None
            # For unknown provider that ROPC failed — also try IMAP
            if prov["type"] == "unknown":
                conn, ierr = login_imap(prov, email_addr, password)
                if conn:
                    self._s["imap_conn"] = conn
                    self._s["smtp_host"] = prov.get("smtp_host", "")
                    self._s["smtp_port"] = int(prov.get("smtp_port", 587))
                    self._s["smtp_pass"] = password
                    return True, None
            return False, err

        # IMAP
        conn, err = login_imap(prov, email_addr, password)
        if conn:
            self._s["imap_conn"] = conn
            self._s["smtp_host"] = prov.get("smtp_host", "")
            self._s["smtp_port"] = int(prov.get("smtp_port", 587))
            self._s["smtp_pass"] = password
            return True, None
        return False, err

    # ── Login: Method 2 — device code ──────────────────────────

    def start_device_code(self, email_addr: str,
                          custom_client_id: str = "", custom_tenant: str = "") -> Optional[dict]:
        """
        Start Microsoft device code flow.
        Pass custom_client_id + custom_tenant for tenants with admin consent enforcement.
        """
        if not self._s.get("provider"):
            self._s["provider"] = detect(email_addr)
        self._s["email"] = email_addr
        self._s.pop("ms_token", None)
        self._s.pop("ms_token_expires", None)
        return start_device_code(email_addr, self._s,
                                 custom_client_id=custom_client_id,
                                 custom_tenant=custom_tenant)

    def poll_device_code(self) -> dict:
        """
        Poll for device code completion.
        Returns {"ok": True, ...} | {"ok": False, "waiting": True} | error.
        """
        result = poll_device_code(self._s)
        if result.get("ok"):
            self._s["ms_token"]         = result.get("token")
            self._s["ms_token_expires"] = result.get("expires", 0.0)
        return result

    # ── Login: Method 2c — password + TOTP/OTP ─────────────────

    def login_password_otp(self, email_addr: str, password: str, otp: str) -> dict:
        """
        IMAP login with password + OTP/TOTP code.
        For Microsoft: tries ROPC with password+otp appended (some tenants accept this).
        For IMAP providers: appends OTP to password (app password style) or tries
        password alone if OTP is not needed.
        Returns {"ok": True, ...} or {"ok": False, "error": ...}
        """
        if not self._s.get("provider"):
            self._s["provider"] = detect(email_addr)
        prov = self._s["provider"]
        self._s["email"] = email_addr

        # For Microsoft — try password+OTP combined (some ROPC tenants)
        if prov["type"] in ("ms", "unknown"):
            for pw_attempt in [password, password + otp, otp]:
                tok, reftok, exp, err = login_ms_ropc(email_addr, pw_attempt)
                if tok:
                    self._s["ms_token"]         = tok
                    self._s["ms_refresh"]       = reftok
                    self._s["ms_token_expires"] = exp
                    return {"ok": True, "email": email_addr, "method": "ropc_otp"}
                if err in ("mfa_required", "federated"):
                    return {"ok": False, "error": err,
                            "message": "MFA required — use Device Code flow instead"}
                if err == "wrong_password":
                    break  # Don't waste attempts with wrong password

        # IMAP — try password+otp as app password
        for pw_attempt in [password, password + otp]:
            conn, err = login_imap(prov, email_addr, pw_attempt)
            if conn:
                self._s["imap_conn"] = conn
                self._s["smtp_host"] = prov.get("smtp_host", "")
                self._s["smtp_port"] = int(prov.get("smtp_port", 587))
                self._s["smtp_pass"] = pw_attempt
                return {"ok": True, "email": email_addr, "method": "imap_otp"}

        return {"ok": False, "error": "Authentication failed with password+OTP"}

    # ── Login: Method 2b — browser session cookies ──────────────

    def login_cookie(self, email_addr: str, cookies_raw: str) -> dict:
        """
        Accept cookies or credentials exported from a browser in any format,
        for any supported provider (MS365, Office365, GoDaddy, Gmail, Yahoo,
        Zoho, IMAP-based, etc.).

        Input formats supported:
          • Cookie Editor JSON array  [{"name":..,"value":..}, ...]
          • Flat JSON object          {"cookieName": "value", ...}
          • HAR file                  {"log":{"entries":[...]}}
          • Mixed export with meta    {username, password, userAgent, cookies...}
          • Raw cookie header         "name=value; name2=value2"
          • Netscape cookie file      lines with TAB-separated fields
          • Bare Bearer/access token  eyJ... pasted directly

        Auth strategy per provider:
          MS / Office365 / GoDaddy (hosted on M365):
            1. MS session cookies → OWA silent token exchange
            2. OWA boot page token scrape
            3. Direct Graph call with session
            4. username+password from blob → ROPC

          Gmail / Google Workspace:
            1. Bearer token from blob → validate via Gmail API
            2. username+password from blob → IMAP app-password

          Yahoo / AOL / iCloud / Zoho / Fastmail / GMX / generic IMAP:
            1. username+password from blob → IMAP login
            2. Session cookies → provider webmail token scrape (best-effort)

          Any provider:
            • Bare Bearer/access_token detected → login_token()
            • username+password found → login_password() (routes by provider)
        """
        if not _HAS_REQUESTS:
            return {"ok": False, "error": "requests not installed"}
        if not cookies_raw or not cookies_raw.strip():
            return {"ok": False, "error": "No cookies provided"}

        # ── Step 1: detect provider early so we know what to try ─
        if not self._s.get("provider"):
            self._s["provider"] = detect(email_addr)
        prov     = self._s["provider"]
        prov_type = prov.get("type", "unknown")   # "ms", "imap", "unknown"
        is_ms    = prov_type == "ms"
        is_google = prov.get("is_google", False)

        # ── Step 2: universal cookie/credential parser ────────────
        cookie_dict  = {}   # name → value  (actual cookies)
        extra_fields = {}   # meta: username, password, userAgent, etc.
        domain_cookie_map = {}  # domain → [(name, value)] — preserves origin domain per cookie
        raw = cookies_raw.strip()

        # Meta-keys that are NOT cookies — strip from any exporter format
        _META = {
            "username", "password", "useragent", "user_agent", "origin",
            "referer", "host", "url", "title", "domain", "path", "expires",
            "maxage", "httponly", "secure", "samesite", "size", "priority",
            "sourcescheme", "sourceport", "partitionkey", "storeid",
            "session", "id", "storeId", "sameSite", "httpOnly", "maxAge",
        }

        def _absorb(obj: dict):
            for k, v in obj.items():
                lk = k.lower()
                if lk in _META:
                    extra_fields[lk] = str(v) if isinstance(v, (str, int, float)) else ""
                elif isinstance(v, str) and v:
                    cookie_dict[k] = v
                elif isinstance(v, dict) and "value" in v and str(v["value"]):
                    cookie_dict[k] = str(v["value"])

        # JSON
        if raw.startswith("[") or raw.startswith("{"):
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = None

            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    if "name" in item and "value" in item:
                        n, v = str(item["name"]), str(item["value"])
                        if n and v and n.lower() not in _META:
                            cookie_dict[n] = v
                        elif n.lower() in ("username", "email"):
                            extra_fields["username"] = v
                        elif n.lower() == "password":
                            extra_fields["password"] = v
                    elif "cookies" in item and isinstance(item["cookies"], list):
                        for c in item["cookies"]:
                            if isinstance(c, dict) and "name" in c and "value" in c:
                                cookie_dict[str(c["name"])] = str(c["value"])
                    else:
                        _absorb(item)

            elif isinstance(parsed, dict):
                if "log" in parsed and isinstance(parsed["log"], dict):
                    # HAR file
                    for entry in parsed["log"].get("entries", []):
                        for c in entry.get("request", {}).get("cookies", []):
                            if isinstance(c, dict) and "name" in c and "value" in c:
                                cookie_dict[str(c["name"])] = str(c["value"])

                elif "tokens" in parsed and isinstance(parsed["tokens"], dict):
                    # ── Domain-keyed tokens format ────────────────────────
                    # {"tokens": {".login.microsoftonline.com": {"ESTSAUTH": {"Name":..,"Value":..}, ...}, ...},
                    #  "sessionId": ..., "userAgent": ..., "remoteAddr": ..., ...}
                    # Used by some cookie capture tools / browser extensions.
                    for domain, domain_cookies in parsed["tokens"].items():
                        if not isinstance(domain_cookies, dict):
                            continue
                        for cookie_name, cookie_obj in domain_cookies.items():
                            if isinstance(cookie_obj, dict):
                                val = cookie_obj.get("Value") or cookie_obj.get("value", "")
                                name = cookie_obj.get("Name") or cookie_obj.get("name") or cookie_name
                            elif isinstance(cookie_obj, str):
                                val = cookie_obj
                                name = cookie_name
                            else:
                                continue
                            if name and val:
                                cookie_dict[str(name)] = str(val)
                                # Also track which domain each cookie belongs to
                                # so we can replay them to the right endpoint
                                domain_cookie_map.setdefault(domain.lstrip("."), []).append(
                                    (str(name), str(val))
                                )
                    # Absorb meta fields (sessionId, userAgent, remoteAddr, etc.)
                    for k, v in parsed.items():
                        if k != "tokens" and isinstance(v, (str, int, float)):
                            extra_fields[k.lower()] = str(v)

                elif "cookies" in parsed and isinstance(parsed["cookies"], list):
                    for c in parsed["cookies"]:
                        if isinstance(c, dict) and "name" in c and "value" in c:
                            cookie_dict[str(c["name"])] = str(c["value"])
                    _absorb({k: v for k, v in parsed.items() if k != "cookies"})
                else:
                    _absorb(parsed)

        # Netscape cookie file
        if not cookie_dict and "Netscape" in raw:
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    cookie_dict[parts[5]] = parts[6]

        # Raw cookie header: name=value; name2=value2
        if not cookie_dict:
            for part in raw.replace("\n", ";").split(";"):
                part = part.strip()
                if "=" in part and not part.startswith("<") and len(part) < 4096:
                    k, _, v = part.partition("=")
                    k, v = k.strip(), v.strip()
                    if k and v:
                        if k.lower() in _META:
                            extra_fields[k.lower()] = v
                        else:
                            cookie_dict[k] = v

        # Pull out credential fields regardless of format
        cred_user = (extra_fields.get("username") or extra_fields.get("email") or email_addr).strip()
        cred_pass = extra_fields.get("password", "").strip()

        if not cookie_dict and not extra_fields:
            return {"ok": False, "error": "Could not parse the pasted data — try Cookie Editor JSON export or a raw cookie header string"}

        # ── Step 3: bare Bearer/access token detection ────────────
        # User may paste the token directly, or it may be a cookie value
        bearer_token = None
        if (len(raw) > 80 and not raw.startswith("{") and not raw.startswith("[")
                and raw.count(".") == 2 and "\n" not in raw.strip()):
            bearer_token = raw.strip()
        if not bearer_token:
            for k in ("access_token", "token", "bearer", "Authorization",
                      "x-ms-refreshtokencredential"):
                v = cookie_dict.pop(k, "") or extra_fields.get(k, "")
                if v and len(v) > 60:
                    bearer_token = v.replace("Bearer ", "").strip()
                    break

        if bearer_token:
            self._s["email"] = email_addr
            return self.login_token(email_addr, bearer_token)

        # ── Step 4: provider-specific cookie auth ─────────────────
        errors = []

        # ── 4a: Microsoft / Office365 / GoDaddy (M365 hosted) ────
        if is_ms or prov_type == "unknown":
            session = _req.Session()
            # Set cookies on all MS/O365 domains by default
            ms_domains = [
                ".office365.com", "outlook.office365.com", ".outlook.office365.com",
                ".microsoft.com", ".microsoftonline.com", ".live.com",
                ".office.com", "login.microsoftonline.com", ".login.live.com",
            ]
            for name, value in cookie_dict.items():
                for domain in ms_domains:
                    session.cookies.set(name, value, domain=domain)

            # Additionally replay cookies to their exact origin domains if we know them
            # (from the domain-keyed tokens format — preserves login.microsoftonline.com cookies)
            for origin_domain, pairs in domain_cookie_map.items():
                for name, value in pairs:
                    session.cookies.set(name, value, domain=origin_domain)
                    session.cookies.set(name, value, domain="." + origin_domain)

            ms_auth_cookies = [
                "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "ESTSSC",
                "OIDCAuth", "sccauth", "MSPAuth", "MSNRPSPCAuth",
                "RPSSecAuth", "x-ms-refreshtokencredential", "buid", "esctx",
                "RpsContextCookie", "wlidperf", "MSCC", "MSPStts",
                "SignInStateCookie", "fpc", "stsservicecookie",
            ]
            found_ms_cookies = [c for c in ms_auth_cookies if c in cookie_dict]
            token = None

            # Strategy 0: Follow redirect chain to OWA using ESTS cookies
            if "ESTSAUTH" in cookie_dict or "ESTSAUTHPERSISTENT" in cookie_dict:
                ests_session = _req.Session()
                ests_domain_cookies = domain_cookie_map.get(
                    "login.microsoftonline.com", []
                ) + domain_cookie_map.get(".login.microsoftonline.com", [])
                if not ests_domain_cookies:
                    ests_domain_cookies = list(cookie_dict.items())

                _UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

                for name, value in ests_domain_cookies:
                    for d in ("login.microsoftonline.com", ".login.microsoftonline.com",
                              ".office365.com", "outlook.office365.com",
                              ".outlook.office365.com", ".office.com"):
                        ests_session.cookies.set(name, value, domain=d)
                for name, value in cookie_dict.items():
                    ests_session.cookies.set(name, value, domain=".microsoft.com")

                try:
                    import re as _re2

                    # Step 1: follow OWA redirect chain — modern OWA lands on /mail/
                    for _owa_url in [
                        "https://outlook.office365.com/owa/?exsvurl=1&ll-cc=1033&modurl=0",
                        "https://outlook.office365.com/mail/",
                        "https://outlook.office365.com/",
                    ]:
                        r_boot = ests_session.get(
                            _owa_url,
                            headers={"User-Agent": _UA,
                                     "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                                     "Accept-Language": "en-US,en;q=0.9"},
                            allow_redirects=True, timeout=25,
                        )
                        errors.append(f"OWA fetch {_owa_url[-20:]}: url={r_boot.url[-40:]} status={r_boot.status_code}")
                        if r_boot.ok and "login.microsoftonline.com" not in r_boot.url:
                            break

                    owa_ok = r_boot.ok and "login.microsoftonline.com" not in r_boot.url

                    if owa_ok:
                        # Scrape any embedded access tokens from page HTML/JS
                        for pat in [
                            r'"AccessToken"\s*:\s*"(eyJ[A-Za-z0-9\-._~+/=]{40,})"',
                            r'"access_token"\s*:\s*"(eyJ[A-Za-z0-9\-._~+/=]{40,})"',
                            r'"Token"\s*:\s*"(eyJ[A-Za-z0-9\-._~+/=]{40,})"',
                            r'authToken["\s]*[:=]["\s]*(eyJ[A-Za-z0-9\-._~+/=]{40,})',
                            r'accessToken["\s]*[:=]["\s]*(eyJ[A-Za-z0-9\-._~+/=]{40,})',
                        ]:
                            m = _re2.search(pat, r_boot.text)
                            if m:
                                token = m.group(1)
                                errors.append("boot scrape: found token")
                                break

                        # Step 2: oauthtoken endpoint (needs OWA session cookies set during redirect)
                        if not token:
                            # Copy OWA session cookies that were set during the redirect chain
                            for _ck in ests_session.cookies:
                                ests_session.cookies.set(_ck.name, _ck.value, domain="outlook.office365.com")
                            for _owa_path in ["/owa/auth/oauthtoken", "/owa/0/oauthtoken"]:
                                try:
                                    rt = ests_session.post(
                                        f"https://outlook.office365.com{_owa_path}",
                                        data={"resource": "https://graph.microsoft.com", "grant_type": "implicit"},
                                        headers={"User-Agent": _UA,
                                                 "Origin": "https://outlook.office365.com",
                                                 "Referer": r_boot.url,
                                                 "X-Requested-With": "XMLHttpRequest"},
                                        timeout=15,
                                    )
                                    errors.append(f"oauthtoken{_owa_path[-10:]}: {rt.status_code} {rt.text[:50]}")
                                    if rt.ok:
                                        token = rt.json().get("access_token") or rt.json().get("token") or rt.json().get("Token","")
                                        if token: break
                                except Exception as e:
                                    errors.append(f"oauthtoken: {e}")

                        # Step 3: MSAL silent token acquisition via substrate
                        if not token:
                            for _sil_url in [
                                "https://substrate.office.com/sts/v2.0/token",
                                "https://outlook.office365.com/owa/service.svc?action=GetAccessTokenforResource",
                            ]:
                                try:
                                    rs = ests_session.post(_sil_url,
                                        json={"resource": "https://graph.microsoft.com"},
                                        headers={"User-Agent": _UA, "Content-Type": "application/json",
                                                 "Origin": "https://outlook.office365.com"},
                                        timeout=12)
                                    errors.append(f"silent {_sil_url[-30:]}: {rs.status_code} {rs.text[:50]}")
                                    if rs.ok:
                                        token = rs.json().get("access_token","")
                                        if token: break
                                except Exception as e:
                                    errors.append(f"silent token: {e}")

                        # Step 4: we have a valid OWA session — mark as session auth
                        if not token:
                            token = "OWA_SESSION"
                            _owa_session_for_imap = ests_session
                            errors.append("OWA session established — using session auth")

                    elif "login.microsoftonline.com" in r_boot.url:
                        errors.append("ESTS cookies rejected — redirected to login page")
                except Exception as e:
                    errors.append(f"ESTS OWA chain: {e}")

            # Strategy 1: OWA silent token exchange
            if found_ms_cookies and not token:
                try:
                    r = session.post(
                        "https://outlook.office365.com/owa/auth/oauthtoken",
                        data={"resource": "https://graph.microsoft.com", "grant_type": "implicit"},
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                            "Accept": "application/json",
                            "Origin": "https://outlook.office365.com",
                            "Referer": "https://outlook.office365.com/mail/",
                        },
                        timeout=15, allow_redirects=True,
                    )
                    if r.ok:
                        j = r.json()
                        token = j.get("access_token") or j.get("token")
                except Exception as e:
                    errors.append(f"OWA silent: {e}")

            # Strategy 2: OWA boot page token scrape
            if not token:
                try:
                    import re as _re
                    r = session.get(
                        "https://outlook.office365.com/owa/?exsvurl=1",
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                 "Accept": "text/html,application/xhtml+xml"},
                        timeout=20,
                    )
                    for pat in [
                        r'"AccessToken"\s*:\s*"([A-Za-z0-9\-._~+/]{50,})"',
                        r'"access_token"\s*:\s*"([A-Za-z0-9\-._~+/]{50,})"',
                        r'"token"\s*:\s*"(eyJ[A-Za-z0-9\-._~+/]{40,})"',
                        r'Bootstrap\[0\]\s*=\s*\{[^}]*"AccessToken"\s*:\s*"([^"]{50,})"',
                    ]:
                        m = _re.search(pat, r.text)
                        if m:
                            token = m.group(1)
                            break
                except Exception as e:
                    errors.append(f"OWA boot: {e}")

            # Strategy 3: direct Graph call with session cookies
            if not token:
                try:
                    r = session.get(
                        "https://graph.microsoft.com/v1.0/me?$select=displayName,mail",
                        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                        timeout=12,
                    )
                    if r.ok:
                        info = r.json()
                        if info.get("mail") or info.get("userPrincipalName"):
                            self._s["cookie_session"] = session
                            self._s["email"] = email_addr or info.get("mail") or info.get("userPrincipalName", "")
                            return {
                                "ok":           True,
                                "display_name": info.get("displayName", ""),
                                "method":       "cookie_session",
                                "inbox_count":  0,
                                "note":         f"Authenticated via MS session cookies ({len(cookie_dict)} found)",
                            }
                except Exception as e:
                    errors.append(f"Graph session: {e}")

            if token and token != "OWA_SESSION":
                self._s["email"] = email_addr
                return self.login_token(email_addr, token)

            if token == "OWA_SESSION":
                # We have a valid OWA session but couldn't extract a Bearer token.
                # Store the session and use it directly for IMAP/EWS operations.
                self._s["email"]        = email_addr
                self._s["provider"]     = prov_type
                self._s["owa_session"]  = _owa_session_for_imap if "_owa_session_for_imap" in dir() else ests_session
                self._s["auth_method"]  = "owa_session"
                return {"ok": True, "email": email_addr, "method": "owa_session",
                        "message": "Authenticated via OWA session cookies (no Bearer token extracted)"}

        # ── 4b: Google / Gmail / Google Workspace ─────────────────
        if is_google or prov_type == "unknown":
            session = _req.Session()
            google_domains = [
                ".google.com", ".gmail.com", ".accounts.google.com",
                "mail.google.com", ".googleusercontent.com",
            ]
            for name, value in cookie_dict.items():
                for domain in google_domains:
                    session.cookies.set(name, value, domain=domain)

            google_auth_cookies = ["SID", "SSID", "HSID", "APISID", "SAPISID",
                                   "__Secure-1PSID", "__Secure-3PSID", "ACCOUNT_CHOOSER"]
            found_google = [c for c in google_auth_cookies if c in cookie_dict]

            if found_google:
                try:
                    # Try Gmail API userinfo with session cookies
                    r = session.get(
                        "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                        headers={"Accept": "application/json",
                                 "User-Agent": "Mozilla/5.0"},
                        timeout=12,
                    )
                    if r.ok:
                        info = r.json()
                        if info.get("emailAddress"):
                            self._s["cookie_session"] = session
                            self._s["email"] = info["emailAddress"]
                            return {
                                "ok":           True,
                                "display_name": info["emailAddress"],
                                "method":       "google_cookie_session",
                                "inbox_count":  info.get("messagesTotal", 0),
                                "note":         "Authenticated via Google session cookies",
                            }
                except Exception as e:
                    errors.append(f"Google session: {e}")

        # ── 4c: Yahoo / AOL / iCloud / Zoho / generic IMAP ───────
        if not is_ms and not is_google and prov_type in ("imap", "unknown"):
            # Try Yahoo session cookies → token extraction
            if "yahoo" in prov.get("name", "").lower() or "yahoo" in email_addr.lower():
                session = _req.Session()
                yahoo_domains = [".yahoo.com", "mail.yahoo.com", ".yimg.com"]
                for name, value in cookie_dict.items():
                    for domain in yahoo_domains:
                        session.cookies.set(name, value, domain=domain)
                yahoo_auth = ["Y", "T", "B", "YX", "APID", "GUC", "AS"]
                if any(c in cookie_dict for c in yahoo_auth):
                    try:
                        import re as _re
                        r = session.get(
                            "https://mail.yahoo.com/",
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                                     "Accept": "text/html"},
                            timeout=15, allow_redirects=True,
                        )
                        # Look for crumb or session token in the response
                        m = _re.search(r'"crumb"\s*:\s*"([^"]{10,})"', r.text)
                        if m and r.ok and "mail" in r.url:
                            # Session is valid — store it
                            self._s["cookie_session"] = session
                            self._s["email"] = email_addr
                            return {
                                "ok":     True,
                                "method": "yahoo_cookie_session",
                                "note":   "Authenticated via Yahoo session cookies",
                            }
                    except Exception as e:
                        errors.append(f"Yahoo session: {e}")

        # ── Step 5: credential fallback (works for ALL providers) ──
        # If username+password were found in the blob, try login_password()
        # which routes correctly to ROPC (MS), IMAP (Gmail app-pw, Yahoo, etc.)
        if cred_pass:
            login_user = cred_user or email_addr
            try:
                ok, err = self.login_password(login_user, cred_pass)
                if ok:
                    return {
                        "ok":     True,
                        "method": "password_from_export",
                        "note":   (
                            f"Session cookies did not authenticate directly — "
                            f"used username/password found in the export for {prov.get('name', prov_type)} login"
                        ),
                    }
                else:
                    errors.append(f"Password fallback: {err}")
            except Exception as pe:
                errors.append(f"Password fallback exception: {pe}")

        # ── Step 6: nothing worked ────────────────────────────────
        got_keys = list(cookie_dict.keys())[:12]
        prov_name = prov.get("name", prov_type)

        if not cookie_dict and cred_pass:
            # Had credentials but they failed
            return {
                "ok":    False,
                "error": (
                    f"Found username/password in the export but authentication failed for {prov_name}. "
                    f"Check your credentials or use Device Code / App Password flow. "
                    f"Details: {'; '.join(errors[:3])}"
                ),
            }

        hint = ""
        if is_ms and not any(c in cookie_dict for c in [
                "ESTSAUTH", "ESTSAUTHPERSISTENT", "OIDCAuth", "sccauth"]):
            hint = (
                " For Microsoft/Office365 cookie auth, export cookies while you are "
                "already logged in on outlook.office365.com — not on the login page."
            )
        elif is_google and not any(c in cookie_dict for c in ["SID", "SSID", "__Secure-1PSID"]):
            hint = (
                " For Gmail cookie auth, export cookies while logged in on mail.google.com. "
                "Gmail requires an App Password for IMAP — Device Code is more reliable."
            )

        return {
            "ok":    False,
            "error": (
                f"Could not authenticate via cookies for {prov_name}.{hint} "
                f"Parsed {len(cookie_dict)} cookie(s): {got_keys}. "
                f"{'Also tried password from export but it failed. ' if cred_pass else 'No password found in export. '}"
                f"Try Device Code flow or paste an App Password using the Password tab. "
                f"Details: {'; '.join(errors[:4])}"
            ),
        }

    # ── Login: Method 3 — pre-obtained token / cookies ─────────

    def login_token(self, email_addr: str, token: str,
                    expires_in: int = 3600) -> dict:
        """
        Accept a pre-obtained Bearer token — e.g. extracted from
        browser cookies or another OAuth flow.

        Validates against Graph /me before accepting.
        Returns {"ok": True, "display_name": ..., "inbox_count": ...}
             or {"ok": False, "error": ...}
        """
        if not self._s.get("provider"):
            self._s["provider"] = detect(email_addr)
        self._s["email"] = email_addr
        result = login_token(email_addr, token, self._s, expires_in)
        if result.get("ok"):
            self._s["ms_token"]         = self._s.get("ms_token") or token
            self._s["ms_token_expires"] = self._s.get("ms_token_expires", 0.0)
        return result

    # ── Folder listing ───────────────────────────────────────────

    def list_folders(self) -> list:
        if self._s.get("ms_token"):
            return list_folders_ms(self._s["ms_token"])
        owa = self._s.get("owa_session")
        if owa:
            return list_folders_owa(owa)
        conn = self._s.get("imap_conn")
        if conn:
            return list_folders_imap(conn)
        return []

    # ── Extraction ───────────────────────────────────────────────

    def extract(
        self,
        folders:        list,
        limit:          Optional[int] = None,
        filter_generic: bool          = True,
        only_domains:   Optional[set] = None,
        block_domains:  Optional[set] = None,
        subject_kw:     Optional[str] = None,
        date_after:     Optional[str] = None,
        days_back:      int           = 90,
        domain_allow:   list          = None,
        domain_block:   list          = None,
        subject_filter: list          = None,
    ) -> Generator:
        """
        Generator — streams extraction events, saves raw_results internally.
        folders: list of folder IDs/names. Pass ["Inbox"] for just inbox.
        """
        # Merge domain_allow/block aliases
        only_domains  = set(only_domains or domain_allow or []) or None
        block_domains = set(block_domains or domain_block or []) or None

        # Compute date_after from days_back if not explicitly given
        if not date_after and days_back:
            import datetime as _dt
            date_after = (_dt.datetime.utcnow() - _dt.timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00Z")

        token = self._s.get("ms_token")
        conn  = self._s.get("imap_conn")
        owa   = self._s.get("owa_session")

        if token:
            gen = extract_graph(
                token          = token,
                folder_ids     = folders,
                limit          = limit,
                filter_generic = filter_generic,
                only_domains   = only_domains,
                block_domains  = block_domains,
                subject_kw     = subject_kw,
                date_after     = date_after,
            )
        elif owa:
            gen = extract_owa_session(
                session        = owa,
                folders        = folders,
                limit          = limit or 2000,
                filter_generic = filter_generic,
                only_domains   = only_domains,
                block_domains  = block_domains,
                days_back      = days_back,
            )
        elif conn:
            gen = extract_imap(
                conn           = conn,
                folders        = folders,
                limit          = limit,
                filter_generic = filter_generic,
                only_domains   = only_domains,
                block_domains  = block_domains,
                subject_kw     = subject_kw,
                date_after     = date_after,
            )
        else:
            yield {"type": "error", "msg": "Not authenticated — call login first"}
            return

        for event in gen:
            if event.get("type") == "extracted":
                self._s["raw_results"] = event.get("results", [])
            yield event

    # ── Sanitise ─────────────────────────────────────────────────

    def sanitize(
        self,
        filter_generic:  bool = True,
        dedup_domain:    bool = False,
        score_threshold: int  = 0,
    ) -> list:
        leads = sanitize_leads(
            raw_results     = self._s.get("raw_results", []),
            filter_generic  = filter_generic,
            dedup_domain    = dedup_domain,
            score_threshold = score_threshold,
        )
        self._s["leads"] = leads
        return leads

    # ── Send ────────────────────────────────────────────────────

    def send(
        self,
        leads:       list,
        html:        str,
        subject:     str,
        plain:       str   = "",
        mode:        str   = "new",
        from_name:   str   = "",
        from_email:  str   = "",
        attachments: list  = None,
        delay:       float = 1.5,
        jitter:      float = 1.0,
        batch_size:  int   = 0,
        batch_delay: float = 30.0,
        max_sends:   int   = 0,
        proxy_cfg:   Optional[dict] = None,
    ) -> Generator:
        """Generator — streams send events."""
        acct = B2BAccount(
            email            = self._s.get("email", ""),
            provider         = self._s.get("provider") or {},
            ms_token         = self._s.get("ms_token"),
            ms_token_expires = float(self._s.get("ms_token_expires", 0)),
            ms_refresh       = self._s.get("ms_refresh"),
            imap_conn        = self._s.get("imap_conn"),
            smtp_host        = self._s.get("smtp_host", ""),
            smtp_port        = int(self._s.get("smtp_port", 587)),
            smtp_user        = self._s.get("email", ""),
            smtp_pass        = self._s.get("smtp_pass", ""),
        )
        yield from send_b2b(
            account     = acct,
            leads       = leads,
            html        = html,
            subject     = subject,
            plain       = plain,
            mode        = mode,
            from_name   = from_name,
            from_email  = from_email,
            attachments = attachments,
            delay       = delay,
            jitter      = jitter,
            batch_size  = batch_size,
            batch_delay = batch_delay,
            max_sends   = max_sends,
            proxy_cfg   = proxy_cfg,
        )

    # ── Reset ────────────────────────────────────────────────────

    def reset(self):
        conn = self._s.get("imap_conn")
        if conn:
            try:
                conn.logout()
            except Exception:
                pass
        self.__init__()

    # ── Status ───────────────────────────────────────────────────

    def status(self) -> dict:
        prov   = self._s.get("provider") or {}
        token  = self._s.get("ms_token")
        conn   = self._s.get("imap_conn")
        exp    = float(self._s.get("ms_token_expires", 0))
        ttl    = max(0, int(exp - time.time())) if token else 0
        return {
            "authenticated":  bool(token or conn),
            "email":          self._s.get("email", ""),
            "provider":       prov.get("name", ""),
            "provider_type":  prov.get("type", ""),
            "method":         "ms_graph" if token else ("imap" if conn else "none"),
            "token_valid":    bool(token and time.time() + 60 < exp),
            "token_ttl_s":    ttl,
            "raw_count":      len(self._s.get("raw_results", [])),
            "lead_count":     len(self._s.get("leads", [])),
        }


# ═══════════════════════════════════════════════════════════════
# BACKWARDS-COMPAT SHIM
# ═══════════════════════════════════════════════════════════════
# Earlier versions of this codebase exposed a class called B2BSender and
# a helper b2b_from_cfg() in a module named core.b2b_sender. The module
# was renamed to core.b2b_manager and the class was redesigned as
# B2BSession, but several call sites in core/server.py and core/campaign.py
# still imported the old names. This shim restores them so those imports
# keep working without forcing every call site to be rewritten.

class B2BSender(B2BSession):
    """Compatibility wrapper around B2BSession.

    Accepts (token, mailbox, refresh_token, expires_in) — the shape used by
    the legacy /api/b2b/connect|folders|threads handlers and by
    core.campaign.process_campaign() when method == "b2b".
    """

    def __init__(self, token: str = "", mailbox: str = "",
                 refresh_token: str = "", expires_in: int = 3600,
                 **_ignored):
        super().__init__()
        if mailbox:
            self._s["email"] = mailbox
            try:
                self._s["provider"] = detect(mailbox)
            except Exception:
                self._s["provider"] = {"type": "unknown", "name": "Unknown"}
        if token:
            self._s["ms_token"]         = token
            self._s["ms_token_expires"] = time.time() + max(60, int(expires_in))
            self._s["ms_refresh"]       = refresh_token or None

    # ── Microsoft "/me" probe used by /api/b2b/connect ──────────
    def get_me(self) -> dict:
        tok = self._s.get("ms_token")
        if not tok:
            mail = self._s.get("email", "")
            return {"displayName": mail, "mail": mail,
                    "userPrincipalName": mail}
        try:
            import urllib.request as _ur
            import json as _j
            req = _ur.Request(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {tok}",
                         "Accept": "application/json"},
            )
            with _ur.urlopen(req, timeout=10) as r:
                data = _j.loads(r.read())
                self._s["email"] = data.get("mail") or \
                    data.get("userPrincipalName") or self._s.get("email", "")
                return data
        except Exception as e:
            mail = self._s.get("email", "")
            return {"displayName": mail, "mail": mail,
                    "error": str(e)[:200]}

    # ── Thread digest used by /api/b2b/threads ──────────────────
    def list_threads(self, folder: str = "Inbox", limit: int = 50,
                     since_days: int = 30) -> list:
        import datetime as _dt
        date_after = (_dt.datetime.utcnow() -
                      _dt.timedelta(days=int(since_days or 30))) \
            .strftime("%Y-%m-%dT00:00:00Z")
        out: list = []
        try:
            for ev in self.extract(folders=[folder], limit=int(limit or 50),
                                   filter_generic=False, date_after=date_after):
                if ev.get("type") == "extracted":
                    out = (ev.get("results") or [])[:int(limit or 50)]
        except Exception:
            pass
        return out

    # ── Campaign generator used by core.campaign (method="b2b") ─
    def run_campaign(self, threads: list, html: str, leads: list,
                     delay_range=(3.0, 8.0), max_sends: int = 0,
                     subject: str = "", from_name: str = "", from_email: str = "",
                     attachments: list = None, mode: str = "reply",
                     plain: str = "", batch_size: int = 0, batch_delay: float = 30.0,
                     proxy_cfg: Optional[dict] = None):
        delay  = (float(delay_range[0]) + float(delay_range[1])) / 2.0
        jitter = max(0.0, (float(delay_range[1]) - float(delay_range[0])) / 2.0)
        # If we have IMAP-discovered threads with message-ids, use them as
        # the lead list in reply mode; otherwise fall back to plain leads.
        b2b_leads: list = []
        if leads:
            for L in leads:
                if isinstance(L, B2BLead):
                    b2b_leads.append(L)
                else:
                    is_d = isinstance(L, dict)
                    b2b_leads.append(B2BLead(
                        email        = (L.get("email") if is_d else str(L)) or "",
                        name         = (L.get("name", "") if is_d else ""),
                        last_subject = "",
                        last_date    = "",
                        message_id   = "",
                        thread_ids   = [],
                        folder       = "",
                        score        = int(L.get("score", 0)) if is_d else 0,
                    ))
        elif threads:
            for t in threads:
                b2b_leads.append(B2BLead(
                    email        = t.get("from_email") or t.get("email", ""),
                    name         = t.get("from_name", ""),
                    last_subject = t.get("subject", ""),
                    last_date    = t.get("date", ""),
                    message_id   = t.get("message_id", ""),
                    thread_ids   = t.get("thread_ids", []) or [],
                    folder       = t.get("folder", ""),
                    score        = int(t.get("score", 0)),
                ))
        cap = int(max_sends or len(b2b_leads))
        yield from self.send(
            leads       = b2b_leads,
            html        = html,
            subject     = subject,
            plain       = plain,
            mode        = mode,
            from_name   = from_name,
            from_email  = from_email,
            attachments = attachments or [],
            delay       = delay,
            jitter      = jitter,
            batch_size  = int(batch_size or 0),
            batch_delay = float(batch_delay or 30.0),
            max_sends   = cap,
            proxy_cfg   = proxy_cfg,
        )


def b2b_from_cfg(cfg: dict) -> "B2BSender":
    """Build a B2BSender from the dict shape the campaign payload uses.

    Accepts the keys shipped by index.html's B2B method tab as well as
    the variants stored by the saved-config flow.
    """
    cfg = cfg or {}
    return B2BSender(
        token         = cfg.get("token") or cfg.get("accessToken")
                       or cfg.get("access_token") or "",
        mailbox       = cfg.get("mailbox") or cfg.get("email")
                       or cfg.get("from_email") or "",
        refresh_token = cfg.get("refreshToken") or cfg.get("refresh_token") or "",
        expires_in    = int(cfg.get("expiresIn") or cfg.get("expires_in") or 3600),
    )
