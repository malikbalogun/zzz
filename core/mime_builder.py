"""
core/mime_builder.py — SynthTel MIME Message Builder
======================================================
Single authoritative function that builds every email message object.
Called by smtp_sender, mx_sender, owa_sender — eliminates duplication.

Handles:
  - All core headers (From, To, Subject, Date, Message-ID, MIME-Version)
  - All deliverability headers (List-Unsubscribe, X-Mailer, Precedence, etc.)
  - 30+ advanced inboxing headers
  - Protected header enforcement
  - Attachment construction: QR codes, ICS, ZIP, EML, PDF, SVG, HTML2IMG
  - Multipart/mixed wrapping when attachments are present
  - Auto-generated plain text from HTML fallback

Usage:
    from core.mime_builder import build_message

    msg, qr_password = build_message(
        lead        = lead,
        sender      = sender,
        subject     = resolved_subject,
        html        = resolved_html,
        plain       = resolved_plain,
        dlv         = dlv_config,
        custom_hdrs = custom_headers_list,
        attachments = attachments_config,
        ehlo_domain = "mail.yourdomain.com",
    )
    # msg is a ready-to-send email.message.Message object
    # qr_password is set if a ZIP with password was generated (put in #ZIP_PASSWORD)
"""

import os
import re
import io
import sys
import uuid
import html as html_lib
import random
import string
import hashlib
import tempfile
import subprocess
import mimetypes
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email import encoders
from email.utils import formatdate, make_msgid

import logging
log = logging.getLogger(__name__)

# Optional link encoder — imported lazily to avoid circular import
try:
    from core.link_encoder import (
        resolve_link_tags, build_redirect_attachment,
        get_method_from_tag, METHOD_HTML_ATTACHMENT, METHOD_CF_SECURITY_CHECK,
    )
    _HAS_LINK_ENCODER = True
except ImportError:
    _HAS_LINK_ENCODER = False


# ═══════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════

# X-Mailer presets — realistic MUA version strings
X_MAILERS = {
    "outlook16":    "Microsoft Outlook 16.0.17928.20114",
    "outlook15":    "Microsoft Outlook 15.0.5589.1001",
    "outlook14":    "Microsoft Outlook 14.0.7269.5000",
    "thunderbird":  "Mozilla Thunderbird 115.8.1",
    "apple":        "Apple Mail (3774.400.10)",
    "appleios":     "iPhone Mail (21E236)",
    "gmail":        "Google Gmail",
    "evolution":    "Evolution 3.50.2",
    "mutt":         "Mutt/2.2.12",
    "lotus":        "Lotus Notes 9.0.1",
    "yahoomail":    "YahooMailBasic/1.0",
}

# ── Homoglyph substitution map ──────────────────────────────────────────────
# Visually identical Unicode lookalikes for ASCII letters.
# Applied to fromName and subject to break string-match spam filters.
# Same technique used by the reference inboxing sender (encryptMessageContent).
_HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α'],   # Cyrillic а, Latin alpha
    'c': ['с', 'ϲ'],         # Cyrillic с
    'e': ['е'],               # Cyrillic е
    'i': ['і'],               # Cyrillic і
    'o': ['о', 'ο'],          # Cyrillic о, Greek omicron
    'p': ['р'],               # Cyrillic р
    's': ['ѕ'],
    'x': ['х'],               # Cyrillic х
    'y': ['у'],               # Cyrillic у
    'A': ['А', 'Α'],          # Cyrillic А, Greek Alpha
    'B': ['В', 'Β'],
    'C': ['С', 'Ϲ'],
    'E': ['Е', 'Ε'],
    'H': ['Н', 'Η'],
    'I': ['І'],
    'K': ['К', 'Κ'],
    'M': ['М', 'Μ'],
    'O': ['О', 'Ο'],
    'P': ['Р', 'Ρ'],
    'T': ['Т', 'Τ'],
    'X': ['Х', 'Χ'],
    'Y': ['У', 'Υ'],
}

def _homoglyph_encode(text: str, density: float = 0.3) -> str:
    """
    Replace a random subset of substitutable chars with Unicode lookalikes.
    density=0.3 → ~30% of eligible characters are substituted.
    Visually identical but breaks exact string-match spam filters.
    Same technique as encryptMessageContent in the reference sender.
    """
    if not text:
        return text
    chars = list(text)
    eligible = [i for i, c in enumerate(chars) if c in _HOMOGLYPHS]
    n_sub = max(1, int(len(eligible) * density))
    for i in random.sample(eligible, min(n_sub, len(eligible))):
        chars[i] = random.choice(_HOMOGLYPHS[chars[i]])
    return ''.join(chars)


def _hash_fragment_links(html: str) -> str:
    """
    Move tracking query parameters into hash fragments so spam filter crawlers
    never see the tracking payload in the GET request.

    Transforms:
        https://domain.com/path?email=foo%40bar.com&id=abc
        → https://domain.com/path#email=foo%40bar.com&id=abc

    Only rewrites <a href> links that contain known tracking param names.
    Leaves mailto:, javascript:, and already-fragmented links untouched.
    """
    _TRACKING_PARAMS = re.compile(
        r'[?&]('
        r'email|mail|rcpt|recipient|uid|user|userid|id|lead|lid|'
        r'utm_source|utm_medium|utm_campaign|utm_content|utm_term|'
        r'ref|src|source|click|cid|tid|mid|sid|token|hash|'
        r'base64|b64|enc|encoded|data|payload'
        r')=[^&\s"\'>#]*',
        re.IGNORECASE,
    )

    def _rewrite_href(m):
        quote = m.group(1)
        href  = m.group(2)
        if not href.startswith(('http://', 'https://')):
            return m.group(0)
        if '?' not in href:
            return m.group(0)
        if not _TRACKING_PARAMS.search(href):
            return m.group(0)
        base, qs = href.split('?', 1)
        frag = ''
        if '#' in qs:
            qs, frag = qs.split('#', 1)
        new_href = base + '#' + qs + (('&' + frag) if frag else '')
        return f'href={quote}{new_href}{quote}'

    return re.sub(
        r'href=(["\'])([^"\']+)\1',
        _rewrite_href,
        html,
        flags=re.IGNORECASE,
    )


# Headers that users must NEVER be allowed to override via custom headers
# These are either security-critical or set precisely by the builder
_PROTECTED_HEADERS = frozenset({
    "from", "to", "cc", "bcc", "subject", "date", "message-id",
    "mime-version", "content-type", "content-transfer-encoding",
    "reply-to",   # set explicitly via sender config
    "received",   # set by servers, never by sender
    "return-path",# set by MTA
    "dkim-signature",  # set by signing layer
    "arc-seal",        # set by signing layer
})

# Smart MIME type map for common attachment extensions
_MIME_MAP = {
    ".pdf":  ("application", "pdf"),
    ".doc":  ("application", "msword"),
    ".docx": ("application", "vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ".xls":  ("application", "vnd.ms-excel"),
    ".xlsx": ("application", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ".ppt":  ("application", "vnd.ms-powerpoint"),
    ".pptx": ("application", "vnd.openxmlformats-officedocument.presentationml.presentation"),
    ".zip":  ("application", "zip"),
    ".rar":  ("application", "x-rar-compressed"),
    ".gz":   ("application", "gzip"),
    ".txt":  ("text", "plain"),
    ".csv":  ("text", "csv"),
    ".html": ("text", "html"),
    ".htm":  ("text", "html"),
    ".xml":  ("text", "xml"),
    ".json": ("application", "json"),
    ".ics":  ("text", "calendar"),
    ".eml":  ("message", "rfc822"),
    ".svg":  ("image", "svg+xml"),
    ".png":  ("image", "png"),
    ".jpg":  ("image", "jpeg"),
    ".jpeg": ("image", "jpeg"),
    ".gif":  ("image", "gif"),
    ".webp": ("image", "webp"),
    ".mp4":  ("video", "mp4"),
    ".mp3":  ("audio", "mpeg"),
}


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════

def _rand_digits(n):
    return ''.join(random.choices(string.digits, k=n))

def _rand_alphanum(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def _rand_alphanum_upper(n):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def _rand_hex(n):
    return ''.join(random.choices('0123456789abcdef', k=n))

def _zero_width_obfuscate(text: str) -> str:
    """
    Inject zero-width Unicode characters into a display name to break
    simple string-match filters, while remaining visually invisible.
    Uses: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM/ZWNBSP)
    Injects 1–3 chars at random positions within the string.
    """
    if not text or len(text) < 2:
        return text
    ZW_CHARS = ["​", "‌", "‍", "﻿"]
    chars = list(text)
    # Insert at 2-3 random interior positions (not first/last char)
    positions = sorted(random.sample(range(1, len(chars)), min(3, len(chars)-1)), reverse=True)
    for pos in positions:
        chars.insert(pos, random.choice(ZW_CHARS))
    return ''.join(chars)

def _strip_html(html_str):
    """Convert HTML to plain text for fallback plain part."""
    if not html_str:
        return ""
    text = re.sub(r'<br\s*/?>', '\n', html_str, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</div>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</h[1-6]>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<li>', '\n• ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html_lib.unescape(text)
    return re.sub(r'\n{3,}', '\n\n', text).strip()

def _inject_unsub_footer(html_str, unsub_url, unsub_email, lead_email):
    """Inject a compliant unsubscribe footer into the HTML body."""
    url = (unsub_url or "").replace("#EMAIL", lead_email)
    links = []
    if url:
        links.append(f'<a href="{url}" style="color:#999;text-decoration:underline">Unsubscribe</a>')
        links.append(f'<a href="{url}" style="color:#999;text-decoration:underline">Manage preferences</a>')
    if unsub_email:
        mailto = f"mailto:{unsub_email}?subject=Unsubscribe&body={lead_email}"
        links.append(f'<a href="{mailto}" style="color:#999;text-decoration:underline">Email to unsubscribe</a>')
    if not links:
        return html_str
    sep = ' <span style="color:#ccc">|</span> '
    footer = (
        '<div style="text-align:center;padding:20px 0 10px;margin-top:20px;'
        'border-top:1px solid #eee;font-size:11px;color:#999;font-family:Arial,sans-serif">'
        + sep.join(links) +
        '</div>'
    )
    if '</body>' in html_str.lower():
        return re.sub(r'(</body>)', footer + r'\1', html_str, flags=re.IGNORECASE)
    return html_str + footer

def _ensure_html_structure(html_str):
    """
    Ensure the HTML has a valid <html><head><body> structure.
    Adds a proper <head> with meta charset, viewport, and display-none preheader
    removal style if missing. Helps Gmail/Outlook rendering consistency.
    """
    html_lower = html_str.lower().strip()
    if html_lower.startswith('<!doctype') or html_lower.startswith('<html'):
        return html_str  # already structured, leave it
    return (
        '<!DOCTYPE html>\n'
        '<html lang="en">\n'
        '<head>\n'
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '<meta http-equiv="X-UA-Compatible" content="IE=edge">\n'
        '<style>*{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}'
        '.ExternalClass{width:100%}.ExternalClass,.ExternalClass p,'
        '.ExternalClass span,.ExternalClass font,.ExternalClass td,'
        '.ExternalClass div{line-height:100%}</style>\n'
        '</head>\n'
        '<body>\n'
        + html_str +
        '\n</body>\n</html>'
    )

def _inject_preheader(html_str, preheader_text):
    """
    Inject an invisible preheader span into the HTML.
    The preheader is the preview text shown in the inbox list before opening.
    Make it long enough (150+ chars) to push out the body content from preview.
    """
    if not preheader_text:
        return html_str
    # Pad to 200 chars with zero-width spaces to fill preview slot
    padded = preheader_text + '&zwnj;&nbsp;' * max(0, (200 - len(preheader_text)) // 2)
    # Use font-size:0 + height:0 instead of color:#ffffff (white-on-white is a
    # known spam fingerprint that filters specifically check for)
    span = (
        f'<div style="display:none;max-height:0;overflow:hidden;'
        f'mso-hide:all;font-size:0px;line-height:0;height:0;'
        f'max-width:0px;opacity:0">{padded}</div>'
    )
    if '<body' in html_str.lower():
        return re.sub(r'(<body[^>]*>)', r'\1' + span, html_str, flags=re.IGNORECASE, count=1)
    return span + html_str

def _get_mime_type(filename):
    ext = os.path.splitext(filename.lower())[1]
    if ext in _MIME_MAP:
        return _MIME_MAP[ext]
    guessed, _ = mimetypes.guess_type(filename)
    if guessed and '/' in guessed:
        main, sub = guessed.split('/', 1)
        return (main, sub)
    return ('application', 'octet-stream')

def _auto_install(package, import_name=None):
    """Auto-install a Python package if missing. Returns True on success."""
    name = import_name or package
    try:
        __import__(name)
        return True
    except ImportError:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", package, "--break-system-packages", "-q"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=60
            )
            __import__(name)
            return True
        except Exception:
            return False


# ═══════════════════════════════════════════════════════════
# ATTACHMENT BUILDERS
# Each returns a MIMEBase part ready to attach, or None on failure
# ═══════════════════════════════════════════════════════════

def _build_qr_attachment(qr_cfg, lead_email, resolved_html):
    """
    Build a QR code image attachment.
    Tries qrcode library first (local), falls back to QR server API.
    The QR URL has #EMAIL replaced with lead email.
    Returns (MIMEImage part, cid_string) — cid is for inline embedding via #QRCODE.
    """
    url = (qr_cfg.get("link") or qr_cfg.get("url") or "").replace("#EMAIL", lead_email)
    if not url:
        return None, None

    width  = max(100, min(int(qr_cfg.get("width", 200) or 200), 1000))
    height = max(100, min(int(qr_cfg.get("height", 200) or 200), 1000))
    dark   = (qr_cfg.get("darkColor") or "#000000").lstrip("#")
    light  = (qr_cfg.get("lightColor") or "#FFFFFF").lstrip("#")
    style  = qr_cfg.get("style", "square")   # square | dots | rounded
    logo   = qr_cfg.get("logo", "")          # base64 logo to embed (optional)
    fmt    = qr_cfg.get("type", "png").lower()
    fname  = f"qrcode.{fmt}"
    cid    = f"qr_{_rand_hex(8)}"

    img_data = None

    # Method 1: qrcode library (best quality, offline)
    if _auto_install("qrcode[pil]", "qrcode"):
        try:
            import qrcode
            from PIL import Image as PILImage

            if style == "dots":
                try:
                    from qrcode.image.styledimage import StyledPilImage
                    from qrcode.image.styles.moduledrawers import CircleModuleDrawer
                    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
                    qr.add_data(url)
                    qr.make(fit=True)
                    img = qr.make_image(image_factory=StyledPilImage,
                                        module_drawer=CircleModuleDrawer(),
                                        back_color=f"#{light}",
                                        fill_color=f"#{dark}")
                except Exception:
                    img = qrcode.make(url)
            elif style == "rounded":
                try:
                    from qrcode.image.styledimage import StyledPilImage
                    from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
                    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
                    qr.add_data(url)
                    qr.make(fit=True)
                    img = qr.make_image(image_factory=StyledPilImage,
                                        module_drawer=RoundedModuleDrawer(),
                                        back_color=f"#{light}",
                                        fill_color=f"#{dark}")
                except Exception:
                    img = qrcode.make(url)
            else:
                qr = qrcode.QRCode(
                    error_correction=qrcode.constants.ERROR_CORRECT_H,
                    box_size=10, border=4
                )
                qr.add_data(url)
                qr.make(fit=True)
                img = qr.make_image(fill_color=f"#{dark}", back_color=f"#{light}")

            # Embed logo if provided
            if logo:
                try:
                    import base64
                    logo_bytes = base64.b64decode(logo.split(',')[-1])
                    logo_img = PILImage.open(io.BytesIO(logo_bytes)).convert("RGBA")
                    qr_size = img.size if hasattr(img, 'size') else (width, height)
                    logo_size = (qr_size[0] // 4, qr_size[1] // 4)
                    logo_img = logo_img.resize(logo_size, PILImage.LANCZOS)
                    pos = ((qr_size[0] - logo_size[0]) // 2, (qr_size[1] - logo_size[1]) // 2)
                    if hasattr(img, '_img'):
                        img._img.paste(logo_img, pos, logo_img)
                    else:
                        img.paste(logo_img, pos, logo_img)
                except Exception:
                    pass  # Logo embed failed, use QR without logo

            # Resize
            buf = io.BytesIO()
            if hasattr(img, '_img'):
                img._img.resize((width, height)).save(buf, format=fmt.upper())
            else:
                img.save(buf)
            img_data = buf.getvalue()
        except Exception:
            img_data = None

    # Method 2: QR server API fallback (no local library needed)
    if not img_data:
        try:
            from urllib.request import urlopen as _urlopen
            api_url = (
                f"https://api.qrserver.com/v1/create-qr-code/"
                f"?size={width}x{height}"
                f"&data={url}"
                f"&color={dark}"
                f"&bgcolor={light}"
                f"&format={fmt}"
            )
            resp = _urlopen(api_url, timeout=10)
            img_data = resp.read()
        except Exception:
            img_data = None

    if not img_data:
        return None, None

    part = MIMEImage(img_data, _subtype=fmt)
    part.add_header("Content-Disposition", "attachment", filename=fname)
    part.add_header("Content-ID", f"<{cid}>")
    part.add_header("X-Attachment-Id", cid)
    return part, cid


def _build_ics_attachment(ics_cfg, lead, sender, resolved_subject):
    """
    Build an iCalendar (.ics) meeting invite attachment.
    Creates a VEVENT with full RFC 5545 compliance.
    """
    name       = ics_cfg.get("name") or "invite.ics"
    subj       = ics_cfg.get("subject") or resolved_subject or "Meeting"
    start_str  = ics_cfg.get("start") or ""
    duration_h = max(1, min(int(ics_cfg.get("duration") or 1), 720))
    location   = ics_cfg.get("location") or ""
    org_name   = ics_cfg.get("orgName")  or sender.get("fromName", "")
    org_email  = ics_cfg.get("orgEmail") or sender.get("fromEmail", "")
    lead_email = lead.get("email", "")
    lead_name  = lead.get("name", "") or lead_email

    # Parse start time — support ISO8601 or free text fallback to now+1h
    try:
        if start_str:
            dt_start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        else:
            dt_start = datetime.now(timezone.utc) + timedelta(hours=1)
    except Exception:
        dt_start = datetime.now(timezone.utc) + timedelta(hours=1)

    dt_end = dt_start + timedelta(hours=duration_h)
    now    = datetime.now(timezone.utc)

    def _ical_dt(dt):
        if dt.tzinfo:
            return dt.strftime("%Y%m%dT%H%M%SZ")
        return dt.strftime("%Y%m%dT%H%M%S")

    # Spoof PRODID to a real MUA — "SynthTel" is a fingerprint
    _PRODIDS = [
        "-//Microsoft Corporation//Outlook 16.0 MIMEDIR//EN",
        "-//Microsoft Corporation//Outlook 15.0 MIMEDIR//EN",
        "-//Apple Inc.//Mac OS X 14.0//EN",
        "-//Apple Inc.//iPhone OS 17.0//EN",
        "-//Google Inc//Google Calendar 70.9054//EN",
        "-//Mozilla.org/NONSGML Mozilla Calendar V1.1//EN",
    ]
    _prodid = random.choice(_PRODIDS)

    uid  = f"{_rand_hex(16)}-{_rand_hex(8)}-{_rand_hex(4)}@{org_email.split('@')[-1] if org_email and '@' in org_email else 'mail.com'}"
    desc = f"You are invited to {subj}"
    if location:
        desc += f"\\nLocation: {location}"

    # RFC 5545 folding: lines > 75 chars get wrapped with CRLF+space
    def _fold(line):
        if len(line.encode('utf-8')) <= 75:
            return line
        out, cur = [], ""
        for char in line:
            if len((cur + char).encode('utf-8')) > 75:
                out.append(cur)
                cur = " " + char
            else:
                cur += char
        if cur:
            out.append(cur)
        return "\r\n".join(out)

    ics_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        f"PRODID:{_prodid}",
        "CALSCALE:GREGORIAN",
        "METHOD:REQUEST",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{_ical_dt(now)}",
        f"DTSTART:{_ical_dt(dt_start)}",
        f"DTEND:{_ical_dt(dt_end)}",
        f"SUMMARY:{subj}",
        _fold(f"DESCRIPTION:{desc}"),
        f"LOCATION:{location}" if location else "",
        f"ORGANIZER;CN={org_name}:mailto:{org_email}" if org_email else "",
        f"ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;"
        f"RSVP=TRUE;CN={lead_name}:mailto:{lead_email}",
        "STATUS:CONFIRMED",
        "SEQUENCE:0",
        "BEGIN:VALARM",
        "TRIGGER:-PT15M",
        "ACTION:DISPLAY",
        f"DESCRIPTION:Reminder: {subj}",
        "END:VALARM",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    ics_text = "\r\n".join(line for line in ics_lines if line) + "\r\n"

    part = MIMEBase("text", "calendar", method="REQUEST", charset="utf-8")
    part.set_payload(ics_text.encode("utf-8"))
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=name if name.endswith(".ics") else name + ".ics")
    return part


def _build_zip_attachment(zip_cfg, lead, sender, html_content):
    """
    Build a password-protected ZIP file attachment.
    Requires 'pyzipper' (auto-installs). Falls back to plain ZIP via zipfile.
    Returns (MIMEBase part, password_string) — password for #ZIP_PASSWORD substitution.
    """
    zip_name    = zip_cfg.get("name") or "document.zip"
    inner_name  = zip_cfg.get("attachName") or "document.html"
    pw_enabled  = zip_cfg.get("password", False)
    pw_type     = zip_cfg.get("pwType", "random")
    pw_len      = max(4, min(int(zip_cfg.get("pwLength") or 8), 64))
    pw_custom   = zip_cfg.get("pwCustom", "")

    # Generate password
    if pw_enabled:
        if pw_type == "custom" and pw_custom:
            password = pw_custom
        elif pw_type == "digits":
            password = _rand_digits(pw_len)
        elif pw_type == "alpha":
            password = _rand_alphanum(pw_len)
        else:  # random mixed
            password = _rand_alphanum_upper(pw_len)
    else:
        password = None

    content = html_content.encode("utf-8") if isinstance(html_content, str) else html_content

    buf = io.BytesIO()

    # Try pyzipper for AES-256 encrypted ZIP
    if password and _auto_install("pyzipper"):
        try:
            import pyzipper
            with pyzipper.AESZipFile(buf, 'w',
                                     compression=pyzipper.ZIP_DEFLATED,
                                     encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode("utf-8"))
                zf.writestr(inner_name, content)
            zip_data = buf.getvalue()
        except Exception:
            password = None
            buf = io.BytesIO()

    # Fallback: plain zipfile (no encryption or encryption failed)
    if not buf.tell():
        import zipfile
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_name, content)

    zip_data = buf.getvalue()
    if not zip_name.endswith(".zip"):
        zip_name += ".zip"

    part = MIMEBase("application", "zip")
    part.set_payload(zip_data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=zip_name)
    return part, password


def _build_eml_attachment(eml_cfg, lead, sender, resolved_html, resolved_subject):
    """
    Build an .eml file attachment — an email-within-an-email.
    Useful for forwarded message scenarios.
    """
    eml_subject   = eml_cfg.get("subject") or resolved_subject
    eml_from_name = eml_cfg.get("fromName") or sender.get("fromName", "")
    eml_from_email= eml_cfg.get("fromEmail") or sender.get("fromEmail", "")
    eml_filename  = eml_cfg.get("fileName") or "message.eml"
    eml_cc        = eml_cfg.get("cc") or ""

    inner = MIMEMultipart("alternative")
    inner["From"]    = f'"{eml_from_name}" <{eml_from_email}>' if eml_from_name else eml_from_email
    inner["To"]      = lead.get("email", "")
    inner["Subject"] = eml_subject
    inner["Date"]    = formatdate(localtime=False)
    inner["Message-ID"] = make_msgid(domain=eml_from_email.split("@")[-1] if "@" in eml_from_email else "example.com")
    if eml_cc:
        inner["Cc"] = eml_cc

    plain_text = _strip_html(resolved_html)
    inner.attach(MIMEText(plain_text, "plain", "utf-8"))
    inner.attach(MIMEText(resolved_html, "html", "utf-8"))

    eml_bytes = inner.as_bytes()

    if not eml_filename.endswith(".eml"):
        eml_filename += ".eml"

    part = MIMEBase("message", "rfc822")
    part.set_payload(eml_bytes)
    part.add_header("Content-Disposition", "attachment", filename=eml_filename)
    return part


def _build_pdf_attachment(pdf_cfg, html_content, lead, resolved_subject):
    """
    Build a PDF attachment from the HTML content.
    Tries weasyprint, then pdfkit (wkhtmltopdf), then fpdf2 minimal fallback.
    """
    pdf_name = pdf_cfg.get("name") or "document.pdf"
    if not pdf_name.endswith(".pdf"):
        pdf_name += ".pdf"

    pdf_data = None

    # Method 1: weasyprint
    if _auto_install("weasyprint"):
        try:
            from weasyprint import HTML as WP_HTML
            pdf_data = WP_HTML(string=html_content).write_pdf()
        except Exception:
            pdf_data = None

    # Method 2: pdfkit (wkhtmltopdf wrapper)
    if not pdf_data:
        try:
            import pdfkit
            buf = io.BytesIO()
            opts = {"quiet": "", "page-size": "A4", "encoding": "UTF-8"}
            pdf_data = pdfkit.from_string(html_content, False, options=opts)
        except Exception:
            pdf_data = None

    # Method 3: fpdf2 minimal text fallback
    if not pdf_data and _auto_install("fpdf2", "fpdf"):
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", size=11)
            text = _strip_html(html_content)
            for line in text.split("\n"):
                pdf.multi_cell(0, 7, line[:200])
            pdf_data = pdf.output()
            if isinstance(pdf_data, str):
                pdf_data = pdf_data.encode("latin-1")
        except Exception:
            pdf_data = None

    if not pdf_data:
        return None

    part = MIMEBase("application", "pdf")
    part.set_payload(pdf_data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=pdf_name)
    return part


def _build_svg_attachment(svg_cfg):
    """
    Build an SVG vector image attachment.
    Uses a provided raw SVG string or generates a branded placeholder.
    """
    svg_name = svg_cfg.get("name") or "graphic.svg"
    if not svg_name.endswith(".svg"):
        svg_name += ".svg"

    svg_content = svg_cfg.get("content") or (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
        '<rect width="200" height="200" fill="#667eea" rx="12"/>'
        '<text x="100" y="115" font-family="Arial" font-size="32" '
        'text-anchor="middle" fill="#ffffff">✉</text>'
        '</svg>'
    )

    part = MIMEBase("image", "svg+xml")
    part.set_payload(svg_content.encode("utf-8"))
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=svg_name)
    return part


def _build_ghost_pdf(ghost_cfg, link_url, lead_email):
    """
    Ghost PDF — a PDF with an invisible full-page clickable overlay.
    The visible content is a clean professional document; the entire
    page is an invisible link. Recipients see a legitimate PDF but
    clicking anywhere opens the URL.

    ghost_cfg keys:
        link    — URL to embed (required)
        text    — visible text content (default: professional letter body)
        title   — document title
        name    — output filename
    """
    link     = (ghost_cfg.get("link") or link_url or "").replace("#EMAIL", lead_email)
    title    = ghost_cfg.get("title") or "Document"
    pdf_name = ghost_cfg.get("name") or "document.pdf"
    if not pdf_name.endswith(".pdf"):
        pdf_name += ".pdf"
    visible_text = ghost_cfg.get("text") or (
        f"{title}\n\n"
        "Please review the attached document at your earliest convenience.\n\n"
        "This document contains important information regarding your account.\n"
        "If you have any questions, please do not hesitate to contact us."
    )

    if not link:
        return None

    pdf_data = None

    # Method 1: reportlab — best Ghost PDF support
    if _auto_install("reportlab"):
        try:
            from reportlab.pdfgen import canvas as rl_canvas
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            buf = io.BytesIO()
            c = rl_canvas.Canvas(buf, pagesize=letter)
            w, h = letter
            # Visible text
            c.setFont("Helvetica-Bold", 16)
            c.drawString(72, h - 100, title)
            c.setFont("Helvetica", 11)
            y = h - 140
            for line in visible_text.split("\n"):
                c.drawString(72, y, line[:90])
                y -= 18
                if y < 72:
                    break
            # Ghost overlay — transparent rect covering full page, linked to URL
            c.setFillColor(colors.white)
            c.setFillAlpha(0.001)          # nearly invisible
            c.setStrokeColor(colors.white)
            c.setStrokeAlpha(0.001)
            c.rect(0, 0, w, h, fill=1)    # full-page rect
            c.linkURL(link, (0, 0, w, h), relative=0)  # full-page link
            c.save()
            pdf_data = buf.getvalue()
        except Exception:
            pdf_data = None

    # Method 2: fpdf2 fallback — no clickable overlay but still a clean PDF
    if not pdf_data and _auto_install("fpdf2", "fpdf"):
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, title, ln=True)
            pdf.set_font("Helvetica", size=11)
            pdf.ln(6)
            for line in visible_text.split("\n"):
                pdf.multi_cell(0, 7, line[:200])
            pdf.ln(4)
            # Add link as text (no overlay possible in basic fpdf2)
            pdf.set_text_color(0, 0, 255)
            pdf.set_font("Helvetica", "U", 10)
            pdf.cell(0, 8, "Click here to view the document", ln=True, link=link)
            pdf_data = bytes(pdf.output())
        except Exception:
            pdf_data = None

    if not pdf_data:
        return None

    part = MIMEBase("application", "pdf")
    part.set_payload(pdf_data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=pdf_name)
    return part


def _build_html_to_image(img_cfg, html_content):
    """
    Convert HTML content to a PNG image and embed it inline.
    Makes email content appear as an image — bypasses text-based content
    filters entirely since there's no scannable text in the email body.

    img_cfg keys:
        width    — image width in px (default 650)
        height   — image height in px (default 800)
        quality  — JPEG quality 1-95 (default 85)
        format   — "png" or "jpg" (default "png")
        name     — attachment filename
    """
    width   = int(img_cfg.get("width", 650))
    height  = int(img_cfg.get("height", 800))
    fmt     = (img_cfg.get("format") or "png").lower()
    name    = img_cfg.get("name") or f"email.{fmt}"
    quality = int(img_cfg.get("quality", 85))

    img_data = None

    # Method 1: playwright (best HTML rendering)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-gpu"])
            page    = browser.new_page(viewport={"width": width, "height": height})
            page.set_content(html_content)
            page.wait_for_timeout(500)
            img_data = page.screenshot(
                type=fmt if fmt in ("png", "jpeg") else "png",
                full_page=True,
                clip={"x":0,"y":0,"width":width,"height":height} if height else None
            )
            browser.close()
    except Exception:
        img_data = None

    # Method 2: imgkit (wkhtmltoimage)
    if not img_data:
        try:
            import imgkit
            opts = {
                "width": str(width),
                "height": str(height),
                "format": fmt if fmt == "png" else "jpg",
                "quiet": "",
                "encoding": "UTF-8",
                "disable-smart-width": "",
            }
            img_data = imgkit.from_string(html_content, False, options=opts)
        except Exception:
            img_data = None

    # Method 3: html2image
    if not img_data and _auto_install("html2image"):
        try:
            from html2image import Html2Image
            import tempfile, os
            with tempfile.TemporaryDirectory() as tmpdir:
                hti = Html2Image(output_path=tmpdir, size=(width, height))
                out = hti.screenshot(html_str=html_content, save_as=f"out.{fmt}")
                if out:
                    with open(out[0], "rb") as f:
                        img_data = f.read()
        except Exception:
            img_data = None

    if not img_data:
        return None

    mime_sub = "jpeg" if fmt in ("jpg", "jpeg") else "png"
    part     = MIMEImage(img_data, _subtype=mime_sub)
    part.add_header("Content-Disposition", "inline", filename=name)
    part.add_header("Content-ID", f"<email_image_{random.randint(1000,9999)}>")
    return part


def _build_generic_attachment(file_path, filename=None):
    """
    Attach a file from disk by path.
    Used for arbitrary user-uploaded attachments.
    """
    if not os.path.isfile(file_path):
        return None
    fname = filename or os.path.basename(file_path)
    main_type, sub_type = _get_mime_type(fname)
    with open(file_path, "rb") as f:
        data = f.read()
    part = MIMEBase(main_type, sub_type)
    part.set_payload(data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename=fname)
    return part


# ═══════════════════════════════════════════════════════════
# ADVANCED INBOXING HEADERS
# ═══════════════════════════════════════════════════════════

def _apply_deliverability_headers(msg, dlv, lead_email, from_email, from_domain, ehlo_domain):
    """
    Apply all deliverability and advanced inboxing headers to msg.
    
    ── Standard Deliverability ──
    • List-Unsubscribe / List-Unsubscribe-Post (one-click RFC 8058)
    • X-Mailer (MUA spoofing for reputation)
    • Precedence (bulk / list / junk)
    • Feedback-ID (Gmail FBL loop identifier)
    • Organization (company identity)
    • X-Priority / Importance (message priority signaling)
    • X-Entity-Ref-ID (Google deduplication token)
    • Message-ID domain override
    
    ── Advanced Inboxing ──
    • List-ID (RFC 2919 mailing list identifier)
    • List-Archive, List-Help, List-Post (mailing list RFC headers)
    • X-Campaign-ID / X-Campaign-Name (campaign tracking)
    • X-Mailer-Version (version string for reputation profiling)
    • Auto-Submitted (prevents OOO auto-replies)
    • Errors-To (bounce handling address)
    • Return-Receipt-To (read receipt request)
    • X-Complaints-To (abuse report destination)
    • X-Originating-IP (claimed sending IP — trust signal)
    • X-Google-DKIM-Signature-Helper (harmless header read by Gmail filters)
    • X-Forwarded-To (forwarding hint)
    • X-Original-To (routing transparency)
    • Thread-Topic / Thread-Index (Outlook conversation threading)
    • In-Reply-To / References (fake thread membership — major inboxing boost)
    • X-MS-Exchange-Organization-* (Exchange/O365 trust headers)
    • X-MS-Has-Attach / X-MS-TNEF-Correlator (Outlook rendering hints)
    • X-Spam-Status / X-Spam-Score (SpamAssassin pass-through simulation)
    • X-Virus-Scanned (AV scan affirmation)
    • MIME-Version explicit set
    • X-Source / X-Source-Args (MTA identity)
    • Content-Language (locale hint)
    • X-Received (fake transit hop — adds legitimacy)
    • Require-Recipient-Valid-Since (RRVS RFC 7293 — prevents delivery to recycled addresses)
    """
    dlv = dlv or {}
    now = datetime.now(timezone.utc)

    # ═══════════════════════════════════════════════════════════════════════════
    # MILITARY-GRADE INBOX ENGINE — Applied unconditionally on every message
    # Based on RFC analysis + behaviour patterns of Outlook 16, Gmail, and
    # major Canadian ISP mail servers. Applied before optional dlv headers.
    # ═══════════════════════════════════════════════════════════════════════════
    import email.utils as _eu
    import base64 as _b64_inbox

    _eff_domain = from_domain or ehlo_domain or "mail.example.com"

    # X-Entity-Ref-ID removed — not used by real MUAs, fingerprints bulk senders

    # ── 2. Per-recipient uniqueness token ─────────────────────────────────────
    # Embedding recipient-keyed token prevents bulk-send fingerprinting.
    # Filters check if message content is identical across many recipients.
    _uniq_token = hashlib.sha256(
        f"{lead_email}|{from_email}|{now.isoformat()}".encode()
    ).hexdigest()[:16]
    # X-Mailer-Hash removed — non-standard header, fingerprints bulk senders

    # ── 3. MIME boundary randomisation ────────────────────────────────────────
    # Python's email library reuses predictable boundary patterns that are
    # known fingerprints for bulk mail. Patch to a MUA-style random boundary.
    try:
        if hasattr(msg, "get_boundary") and msg.get_boundary():
            _new_boundary = (
                "----=_Part_" + _rand_digits(6) + "_" +
                _rand_digits(10) + "." + _rand_digits(13)
            )
            msg.set_boundary(_new_boundary)
    except Exception:
        pass

    # X-Mailer: ISP mode should have one (real users use Outlook/Thunderbird).
    # Relay/ESP mode should NOT have one (real ESPs don't set X-Mailer).
    if not msg.get("X-Mailer") and _is_isp_mode:
        msg["X-Mailer"] = random.choice([
            "Microsoft Outlook 16.0.17928.20114",
            "Microsoft Outlook 16.0.17126.20190",
            "Mozilla Thunderbird 128.6.0",
        ])
    elif not msg.get("X-Mailer") and dlv.get("xMailer") and dlv.get("xMailer") != "none":
        _xm_default = dlv.get("xMailer", "none")
        if _xm_default == "random":
            msg["X-Mailer"] = random.choice(list(X_MAILERS.values()))
        elif _xm_default == "custom" and dlv.get("customMailer"):
            msg["X-Mailer"] = dlv["customMailer"]
        elif _xm_default not in ("none", "random", "custom"):
            msg["X-Mailer"] = X_MAILERS.get(_xm_default, "")

    # Thread-Index removed — Outlook-internal header. Real ESPs (ZeptoMail, SendGrid)
    # do NOT inject Thread-Index. Its presence without real Exchange routing is a
    # forgery signal. The inboxed reference email had no Thread-Index.

    # ── 6. MS-Exchange trust chain: always-on ─────────────────────────────────
    # SCL -1 = "trusted sender, bypass junk filter" — used by Exchange for
    # internal mail and trusted relays. Applied unless explicitly disabled via dlv.
    # (a) Exchange/Hotmail/O365 servers honour it, (b) non-Exchange ignores it.
    # MS Exchange bypass headers — ONLY useful when sending through a trusted
    # Exchange relay. In ISP mode (residential proxy), these are detected as
    # forged and INCREASE spam score. Only enable for SMTP relay mode.
    if dlv.get("msExchangeHeaders", True) and not _is_isp_mode and not msg.get("X-MS-Exchange-Organization-SCL"):
        msg["X-MS-Exchange-Organization-SCL"]             = "-1"
        msg["X-MS-Exchange-Organization-PCL"]             = "2"
        msg["X-MS-Exchange-Organization-Antispam-Report"] = "BCL:0;"
        msg["X-MS-Exchange-Organization-MessageDirectionality"] = "Originating"

    # X-Spam-Status / X-Spam-Score / X-Virus-Scanned intentionally REMOVED.
    # ────────────────────────────────────────────────────────────────────────
    # Rationale: Gmail, Outlook, and major ISPs add these headers THEMSELVES
    # after scanning inbound mail. When the *sender* includes them pre-stamped,
    # modern filters recognise this as spoofing — they check that the header
    # domain matches a known scanning MTA in their infrastructure. A forged
    # "X-Spam-Status: No" from the sending domain is a significant junk signal,
    # not a trust signal. Removing them lets the receiving server add its own
    # scan results without conflict.

    # Content-Language: only add if explicitly set — real ESPs omit it
    if dlv.get("contentLanguage") and not msg.get("Content-Language"):
        msg["Content-Language"] = dlv["contentLanguage"]

    # Errors-To removed — deprecated RFC header not present in modern ESP sends.
    # Use proper Return-Path for bounce handling instead.

    # ── 11. Auto-flag emails (🚩 red flag icon in Outlook/Hotmail inbox) ────────
    # Sets high-priority headers that trigger Outlook's red flag indicator.
    # X-Priority:1 + Importance:High + X-MSMail-Priority:High is the magic combo.
    # Applied when autoFlagEmail is enabled in dlv settings.
    if dlv.get("autoFlagEmail"):
        if not msg.get("X-Priority"):
            msg["X-Priority"]        = "1"
            msg["Importance"]        = "High"
            msg["X-MSMail-Priority"] = "High"
    elif not msg.get("X-Priority"):
        # Normal priority — no explicit header (lets ISP default apply)
        pri = dlv.get("priority", "normal")
        if pri == "high":
            msg["X-Priority"]        = "1"
            msg["Importance"]        = "High"
            msg["X-MSMail-Priority"] = "High"
        elif pri == "low":
            msg["X-Priority"] = "5"
            msg["Importance"] = "Low"

    # ── 12. Anti-detection: additional per-message entropy ────────────────────
    # When antiDetect is enabled (default), inject extra randomisation to prevent
    # bulk fingerprinting. These all have zero downside on legitimate delivery.
    # antiDetect block — intentionally minimal after removing fingerprinting headers.
    # X-Forwarded-To, X-Original-To, and X-Mailer-Version were removed because
    # they fingerprint bulk senders. The entropy is now handled by per-message
    # unique tokens (X-Entity-Ref-ID, Message-ID, Thread-Index).

    # X-Received removed — added by the RECEIVING server, not the sender.
    # The inboxed reference email had no X-Received injected by the sender.
    # Injecting it makes filters suspicious (why is the sender claiming relay activity?).

    # Authentication-Results intentionally NOT injected.
    # Gmail/Outlook/ISPs ALWAYS overwrite this header with their own scan result.
    # A pre-existing Authentication-Results from an external sender is treated as
    # potentially forged and can actually INCREASE spam score. Let the receiving
    # MTA add its own — that's the RFC-correct behavior.

    # X-Originating-IP removed — set by webmail providers for their own sends.
    # The inboxed reference email had no X-Originating-IP. External senders
    # injecting fake IPs here are detected. Omit entirely.

    # Thread-Topic removed — Outlook-internal, not used by real ESPs.

    # ── 16. Thread simulation (opt-in) ───────────────────────────────────────
    # Skip in ISP mode — fake thread headers are easily detected without DKIM
    # and increase spam score on residential IP sends.
    if dlv.get("threadSimulate") and not _is_isp_mode and not msg.get("In-Reply-To"):
        # Use RECIPIENT domain for the fake prior message-ID — looks like we're
        # replying to a message that came FROM the recipient's mail server.
        # This is the pattern that makes filters think it's a thread reply.
        _rcpt_domain = lead_email.split("@")[-1] if "@" in lead_email else _eff_domain
        _t_ts    = datetime.now().strftime("%Y%m%d%H%M%S")
        _t_local = _rand_alphanum(8) + "." + _rand_alphanum(6)
        _t_local2= _rand_alphanum(6) + "." + _rand_digits(8)
        # Root message (the one we appear to be replying to)
        fake_root = f"<{_t_ts}.{_t_local}@{_rcpt_domain}>"
        # Optional intermediate hop (makes References chain look real)
        fake_mid  = f"<{_t_local2}@mail.{_rcpt_domain}>"
        msg["In-Reply-To"] = fake_root
        msg["References"]  = f"{fake_root} {fake_mid}"

    # ── List-Unsubscribe (RFC 2369 + RFC 8058) ──
    # Skip in ISP mode — individual sends don't have unsubscribe headers
    # and they fingerprint the message as bulk mail.
    if dlv.get("listUnsub") and not _is_isp_mode:
        unsub_parts = []
        unsub_url   = (dlv.get("unsubUrl") or "").replace("#EMAIL", lead_email)
        unsub_email = dlv.get("unsubEmail") or ""
        if unsub_url:
            unsub_parts.append(f"<{unsub_url}>")
        if unsub_email:
            unsub_parts.append(f"<mailto:{unsub_email}?subject=Unsubscribe&body={lead_email}>")
        if unsub_parts:
            msg["List-Unsubscribe"] = ", ".join(unsub_parts)
        # One-click unsubscribe (RFC 8058) — REQUIRED for Gmail/Yahoo bulk sending
        if dlv.get("oneClickUnsub") and unsub_url:
            msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"

    # X-Mailer: handled above in always-on engine (step 4)

    # ── Precedence ──
    # Default OFF — "Precedence: bulk" is a direct signal to Gmail/ISPs to route
    # to promotions/junk. Only enable if explicitly set in dlv config.
    prec = dlv.get("precedence", "none")
    if prec and prec != "none":
        msg["Precedence"] = prec

    # ── Feedback-ID (Gmail FBL) ──
    # Format: campaignID:senderID:channelID:esp
    if dlv.get("feedbackId"):
        msg["Feedback-ID"] = dlv["feedbackId"]
    elif dlv.get("feedbackIdAuto"):
        cid = _rand_alphanum(8)
        sid = _rand_alphanum(6)
        msg["Feedback-ID"] = f"{cid}:{sid}:smtp:{from_domain}"

    # ── Organization ──
    if dlv.get("organization"):
        msg["Organization"] = dlv["organization"]

    # ── X-Priority / Importance ──
    pri = dlv.get("priority", "normal")
    if pri == "high":
        msg["X-Priority"] = "1"
        msg["Importance"] = "High"
    elif pri == "low":
        msg["X-Priority"] = "5"
        msg["Importance"] = "Low"
    # normal: no priority headers (default inbox treatment)

    # ── X-Entity-Ref-ID (Gmail deduplication) ──
    if dlv.get("entityRef"):
        msg["X-Entity-Ref-ID"] = str(uuid.uuid4())

    # ── List-ID (RFC 2919 — signals legitimate mailing list) ──
    if dlv.get("listId"):
        msg["List-ID"] = dlv["listId"]
    elif dlv.get("listIdAuto") and from_domain:
        # Auto-generate from sending domain
        slug = re.sub(r'[^a-z0-9]', '-', from_domain.split('.')[0].lower())
        msg["List-ID"] = f"<{slug}.{from_domain}>"

    # ── List-Archive / List-Help / List-Post (RFC 2369) ──
    if dlv.get("listArchive"):
        msg["List-Archive"] = f"<{dlv['listArchive']}>"
    if dlv.get("listHelp"):
        msg["List-Help"] = f"<{dlv['listHelp']}>"
    if dlv.get("listPost"):
        msg["List-Post"] = f"<{dlv['listPost']}>"

    # X-Campaign-ID / X-Campaign-Name intentionally omitted — pure bulk-mail signals
    # that trigger junk filters on Gmail, Outlook, and most ISPs.

    # ── Auto-Submitted (RFC 3834) — only if explicitly enabled
    # Default OFF: "auto-generated" signals bulk mail to filters
    if dlv.get("autoSubmitted"):
        msg["Auto-Submitted"] = "auto-generated"

    # ── Errors-To override (already set always-on above; user override) ──
    if dlv.get("errorsTo") and msg.get("Errors-To") != dlv["errorsTo"]:
        try: msg.replace_header("Errors-To", dlv["errorsTo"])
        except Exception: pass

    # ── Return-Receipt-To (opt-in read receipt) ──
    if dlv.get("returnReceipt") and from_email:
        if not msg.get("Return-Receipt-To"):
            msg["Return-Receipt-To"] = from_email
            msg["Disposition-Notification-To"] = from_email

    # ── X-Complaints-To ──
    if dlv.get("complaintsTo") and not msg.get("X-Complaints-To"):
        msg["X-Complaints-To"] = dlv["complaintsTo"]

    # Thread simulation handled above in always-on engine

    # ── Thread-Topic / Thread-Index (Outlook conversation view) ──
    if dlv.get("threadTopic"):
        import base64 as _b64
        msg["Thread-Topic"] = dlv["threadTopic"]
        # Thread-Index is a base64 timestamp blob that groups emails in Outlook
        ts_bytes = now.strftime("%Y%m%d%H%M%S").encode() + _rand_hex(8).encode()
        msg["Thread-Index"] = _b64.b64encode(ts_bytes).decode()

    # ── X-Originating-IP (claimed sending IP — trust signal) ──
    if dlv.get("originatingIp"):
        msg["X-Originating-IP"] = dlv["originatingIp"]
    elif dlv.get("originatingIpAuto"):
        # Generate realistic-looking internal IP
        msg["X-Originating-IP"] = f"[10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}]"

    # X-MS-Has-Attach and X-MS-TNEF-Correlator intentionally removed.
    # These are internal Exchange MTA headers, not MUA headers. Modern spam
    # filters (Gmail, Outlook EOP) verify these only appear on mail that
    # actually transited Exchange infrastructure. Spoofing them is detected
    # and penalised. The SCL/PCL/BCL headers above are sufficient for
    # Outlook junk bypass.

    # ── Content-Language override (user can set explicit locale) ──
    lang = dlv.get("contentLanguage")
    if lang:
        try: msg.replace_header("Content-Language", lang)
        except Exception:
            try: msg["Content-Language"] = lang
            except Exception: pass

    # ── X-Source / X-Source-Args (MTA identity headers) ──
    if dlv.get("sourceHeaders"):
        msg["X-Source"]       = ""
        msg["X-Source-Args"]  = ""
        msg["X-Source-Dir"]   = ""

    # ── X-Received (simulated transit hop) ──
    if dlv.get("xReceived"):
        ts_str = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
        fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        msg["X-Received"] = (
            f"by {fake_ip} with SMTP id {_rand_alphanum(6)}.{_rand_digits(12)}; {ts_str}"
        )

    # ── Require-Recipient-Valid-Since (RFC 7293) ──
    # Prevents delivery to recycled/reassigned email addresses
    if dlv.get("rrvs"):
        # Format: <address>; <date> — tells server when address was last known valid
        rrvs_date = (now - timedelta(days=random.randint(30, 365))).strftime("%a, %d %b %Y %H:%M:%S +0000")
        msg["Require-Recipient-Valid-Since"] = f"{lead_email}; {rrvs_date}"

    # ── Sensitivity header (Outlook) ──
    sensitivity = dlv.get("sensitivity")
    if sensitivity in ("Personal", "Private", "Company-Confidential"):
        msg["Sensitivity"] = sensitivity

    # ── X-PM-Message-Id (Postmark tracking) ──
    if dlv.get("pmTracking"):
        msg["X-PM-Message-Id"] = str(uuid.uuid4())

    # ── BIMI hint (Brand Indicators for Message Identification) ──
    # Not cryptographically valid but signals intent to filters
    if dlv.get("bimiSelector") and from_domain:
        msg["BIMI-Selector"] = f"v=BIMI1; s={dlv['bimiSelector']}; d={from_domain}"

    # ── ARC simulation (Authenticated Received Chain) ─────────────────────────
    # ARC is a chain of cryptographic headers that lets forwarded mail preserve
    # its authentication results. Gmail and Outlook both read ARC headers.
    # We can't sign them cryptographically without a private key, but
    # injecting plausible ARC-Authentication-Results signals the message
    # passed through a trusted intermediary.
    # Disabled by default — only useful if your SMTP provider supports ARC.
    if dlv.get("arcSimulate") and not msg.get("ARC-Authentication-Results"):
        _arc_i   = "1"
        _arc_ts  = str(int(datetime.now().timestamp()))
        _arc_dom = _eff_domain
        msg["ARC-Authentication-Results"] = (
            f"i={_arc_i}; mx.google.com;"
            f" dkim=pass header.i=@{_arc_dom} header.s=default;"
            f" spf=pass (google.com: domain of {from_email} designates"
            f" {random.randint(24,130)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            f" as permitted sender) smtp.mailfrom={from_email};"
            f" dmarc=pass (p=NONE) header.from={_arc_dom}"
        )
        msg["ARC-Message-Signature"] = (
            f"i={_arc_i}; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;"
            f" h=to:subject:message-id:date:from:mime-version:dkim-signature;"
            f" bh={_rand_alphanum(22)}==; b={_rand_alphanum(88)}=="
        )
        msg["ARC-Seal"] = (
            f"i={_arc_i}; a=rsa-sha256; t={_arc_ts}; cv=none;"
            f" d=google.com; s=arc-20160816;"
            f" b={_rand_alphanum(88)}=="
        )

    # ── Enhanced Exchange/O365 trust chain ────────────────────────────────────
    # Additional Exchange headers that appear on mail from trusted connectors
    # Exchange headers: only keep SCL:-1/PCL/BCL which Outlook/Hotmail actually honor
    # from external senders. The internal Exchange headers (Auth*, Forefront, Antispam)
    # are stripped by EOP when they arrive from outside and can increase spam score.
    if dlv.get("msExchangeHeaders", True) and not msg.get("X-MS-Exchange-Organization-SCL"):
        pass  # SCL/PCL/BCL already set in always-on engine above

    return msg


# ═══════════════════════════════════════════════════════════
# CID IMAGE EMBEDDER
# ═══════════════════════════════════════════════════════════

def _embed_images_as_datauri(html: str) -> str:
    """
    Convert external <img src="https://..."> URLs to base64 data URIs embedded
    directly in the HTML. This is proven by Email 1 (fuji-mt/kagoya) which inboxed
    with DKIM=UNKNOWN using this exact technique — 137KB HTML with all images inline.

    Eliminates ALL external URL scanning. No CID parts needed.
    Self-contained HTML — filters have nothing external to evaluate.
    """
    from urllib.request import urlopen as _uo, Request as _Req
    import base64
    import re

    seen_urls = {}  # url → data URI (reuse for duplicates)

    def _replace_src(m):
        full_tag_start = m.group(1)   # <img ... before src=
        quote_char = m.group(2)       # " or '
        url = m.group(3)              # the URL
        rest = m.group(4)             # rest of tag

        if not url.startswith(('http://', 'https://')):
            return m.group(0)

        if url in seen_urls:
            return f'{full_tag_start}src="{seen_urls[url]}"{rest}'

        try:
            req = _Req(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; Mail/1.0)',
                'Accept': 'image/*,*/*',
            })
            resp = _uo(req, timeout=8)
            img_data = resp.read()
            content_type = resp.headers.get('Content-Type', 'image/png').split(';')[0].strip()
            if not content_type.startswith('image/'):
                content_type = 'image/png'
            if len(img_data) < 100:
                return m.group(0)
            b64 = base64.b64encode(img_data).decode('ascii')
            data_uri = f'data:{content_type};base64,{b64}'
            seen_urls[url] = data_uri
            log.debug("[mime_builder] dataURI embedded: %s (%d bytes)", url[:60], len(img_data))
            return f'{full_tag_start}src="{data_uri}"{rest}'
        except Exception as e:
            log.debug("[mime_builder] dataURI embed failed %s: %s", url[:60], e)
            return m.group(0)

    modified = re.sub(
        r'(<img\b[^>]*?)\bsrc=(["\'])([^"\'>]+)\2([^>]*?>)',
        _replace_src, html, flags=re.IGNORECASE | re.DOTALL
    )
    return modified


def _embed_images_as_cid(html: str) -> tuple:
    """
    Convert external <img src="https://..."> URLs to inline CID attachments.

    This is a major inbox signal — both analyzed inboxing emails use CID
    embedding. Benefits:
    - No external URL loading (eliminates remote content scanning)
    - Self-contained email matches real MUA behavior (Outlook, Apple Mail)
    - Removes dependency on third-party CDN/tracking domains

    Returns (modified_html, list_of_(MIMEImage, cid) tuples).
    Images that fail to download are left as external URLs.
    """
    from urllib.request import urlopen as _uo, Request as _Req
    import re

    img_parts = []
    seen_urls = {}  # url → cid (reuse same CID for duplicate URLs)

    def _replace_src(m):
        before = m.group(1)  # everything before src=
        url = m.group(2)     # the URL
        after = m.group(3)   # rest of tag

        # Skip data URIs, already-CID, or non-http
        if not url.startswith(('http://', 'https://')):
            return m.group(0)

        # Reuse CID if same URL appears multiple times
        if url in seen_urls:
            return f'{before}src="cid:{seen_urls[url]}"{after}'

        try:
            req = _Req(url, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; Mail/1.0)',
                'Accept': 'image/*,*/*',
            })
            resp = _uo(req, timeout=8)
            img_data = resp.read()
            content_type = resp.headers.get('Content-Type', 'image/png').split(';')[0].strip()
            # Map content type to subtype
            subtype = content_type.split('/')[-1] if '/' in content_type else 'png'
            subtype = {'jpeg': 'jpeg', 'jpg': 'jpeg', 'png': 'png', 'gif': 'gif',
                       'webp': 'webp', 'svg+xml': 'png'}.get(subtype, 'png')
            if len(img_data) < 100:
                return m.group(0)  # skip tiny/empty responses
            cid = _rand_alphanum(8) + '@mail'
            part = MIMEImage(img_data, _subtype=subtype)
            part.add_header('Content-ID', f'<{cid}>')
            part.add_header('Content-Disposition', 'inline')
            img_parts.append((part, cid))
            seen_urls[url] = cid
            log.debug("[mime_builder] CID embedded: %s → cid:%s", url[:60], cid)
            return f'{before}src="cid:{cid}"{after}'
        except Exception as e:
            log.debug("[mime_builder] CID embed failed for %s: %s", url[:60], e)
            return m.group(0)  # keep original on failure

    # Match src="..." in img tags, handling single/double quotes
    modified = re.sub(
        r'(<img\b[^>]*?)\bsrc=(["\'])([^"\'>]+)\2([^>]*?>)',
        _replace_src, html, flags=re.IGNORECASE | re.DOTALL
    )
    return modified, img_parts


# ═══════════════════════════════════════════════════════════
# MAIN BUILDER
# ═══════════════════════════════════════════════════════════

def build_message(
    lead:           dict,
    sender:         dict,
    subject:        str,
    html:           str,
    plain:          str       = None,
    dlv:            dict      = None,
    custom_hdrs:    list      = None,
    attachments:    dict      = None,
    ehlo_domain:    str       = None,
    msg_id_domain:  str       = None,
    preheader:      str       = None,
    inject_unsub:   bool      = True,
    ensure_html:    bool      = True,
    smtp_auth_email: str      = None,
    envelope_from:   str      = None,
) -> tuple:
    """
    Build a complete MIME email message ready for sending.

    Args:
        lead:          Lead dict with 'email', 'name', 'company'
        sender:        Sender dict with 'fromEmail', 'fromName', 'replyTo'
        subject:       Resolved subject string
        html:          Resolved HTML body
        plain:         Resolved plain text (auto-generated from HTML if None)
        dlv:           Deliverability config dict
        custom_hdrs:   List of {key, value} custom header dicts
        attachments:   Attachment config dict (qr, ics, zip, eml, pdf, svg, etc.)
        ehlo_domain:   EHLO/HELO domain (used in Message-ID)
        msg_id_domain: Override domain in Message-ID
        preheader:     Invisible inbox preview text (injected into HTML)
        inject_unsub:  Whether to inject unsubscribe footer into HTML
        ensure_html:   Whether to wrap HTML in full <!DOCTYPE html> structure

    Returns:
        (message_object, metadata_dict)
        metadata_dict contains:
            'zip_password': str | None  — password for #ZIP_PASSWORD substitution
            'qr_cid':       str | None  — Content-ID for inline #QRCODE embedding
            'warnings':     list[str]   — non-fatal build warnings
    """
    dlv          = dlv or {}
    custom_hdrs  = custom_hdrs or []
    attachments  = attachments or {}

    lead_email  = (lead.get("email") or "").strip()
    lead_name   = (lead.get("name") or "").strip()
    from_email  = (sender.get("fromEmail") or "").strip()
    from_name   = (sender.get("fromName") or "").strip()
    reply_to    = (sender.get("replyTo") or "").strip()
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    ehlo        = ehlo_domain or from_domain or "mail.example.com"

    # Detect ISP mode: envelope_from on a different domain than From
    _env_domain = envelope_from.split("@")[-1] if envelope_from and "@" in envelope_from else ""
    _is_isp_mode = bool(_env_domain and _env_domain.lower() != from_domain.lower())

    warnings    = []
    zip_password = None
    qr_cid       = None

    # ── Validate minimum requirements ──
    if not lead_email:
        warnings.append("No recipient email address provided")
    if not from_email:
        warnings.append("No sender fromEmail provided")

    # ── Prepare HTML ──
    working_html = html or ""

    # ── Content encryption (encryptMessageContent) ─────────────────────────
    # Homoglyph-encode subject and fromName to break string-match spam filters.
    # Matches the behaviour of the reference inboxing sender's encryptMessageContent:true.
    # On by default — set dlv.encryptMessageContent=False to disable.
    _encrypt_content = dlv.get("encryptMessageContent", True)
    if _encrypt_content:
        subject   = _homoglyph_encode(subject)
        from_name = _homoglyph_encode(from_name)

    # ── Link encoding (resolve [LINK] / [SF_*] tags before any processing) ──
    # Must run first — before HTML structure wrapping, image embedding, etc.
    # Detects the encoding method from which [SF_*] tag is present in the template.
    _link_url    = (dlv or {}).get("linkUrl") or ""
    _link_method = 0  # default: plain
    if _HAS_LINK_ENCODER and working_html and _link_url:
        try:
            _link_method = get_method_from_tag(working_html)
            working_html = resolve_link_tags(working_html, _link_url, _link_method)
        except Exception as _le:
            log.debug("[mime_builder] link_encoder: %s", _le)

    # ── Hash-fragment link rewriting ────────────────────────────────────────
    # Move tracking query params to URL hash fragments so spam filter crawlers
    # never see the tracking payload in the GET request.
    # On by default — set dlv.hashFragmentLinks=False to disable.
    if dlv.get("hashFragmentLinks", True) and working_html:
        working_html = _hash_fragment_links(working_html)

    # Only apply HTML structure wrapping if the content actually has HTML tags.
    # Wrapping plain "Hi" in <!DOCTYPE html> then stripping it back to plain
    # injects CSS junk into the plain-text part.
    _content_has_html = bool(re.search(r'<(html|body|div|p|table|td|span|a|br|img|h[1-6])\b', working_html, re.I))
    if ensure_html and _content_has_html:
        working_html = _ensure_html_structure(working_html)
    if preheader and _content_has_html:
        working_html = _inject_preheader(working_html, preheader)

    # ── Embed external images to eliminate external URL scanning ─────────────
    # PROVEN by analysis: Email that inboxed Yahoo with DKIM=UNKNOWN used 137KB
    # HTML with ALL images as data:image/png;base64 URIs — zero external URLs.
    # External CDN links (Cloudinary, etc.) are scanned by Yahoo/Gmail filters
    # and can trigger spam scoring based on domain reputation or URL patterns.
    #
    # embedImages=True (default) → data URI mode (bake images into HTML)
    # embedImages="cid"          → CID attachment mode (multipart/related)
    # embedImages=False          → disabled (keep external URLs)
    _cid_parts = []
    _embed_mode = dlv.get("embedImages", True)
    _has_ext_imgs = bool(working_html and re.search(r'<img[^>]+src=["\']https?://', working_html, re.IGNORECASE))
    if _embed_mode and _has_ext_imgs:
        if _embed_mode == "cid":
            try:
                working_html, _cid_parts = _embed_images_as_cid(working_html)
                log.debug("[mime_builder] CID embed: %d images", len(_cid_parts))
            except Exception as _emb_err:
                log.debug("[mime_builder] CID embed failed: %s", _emb_err)
        else:
            # Default: data URI — self-contained HTML, no MIME complexity
            try:
                working_html = _embed_images_as_datauri(working_html)
            except Exception as _emb_err:
                log.debug("[mime_builder] dataURI embed failed: %s", _emb_err)

    # ── Prepare plain text ──
    working_plain = plain or _strip_html(working_html)
    if not working_plain:
        working_plain = subject or "(no content)"

    # ── Unsubscribe footer injection ──
    if inject_unsub and dlv.get("listUnsub"):
        unsub_url   = (dlv.get("unsubUrl") or "").replace("#EMAIL", lead_email)
        unsub_email = dlv.get("unsubEmail") or ""
        working_html = _inject_unsub_footer(working_html, unsub_url, unsub_email, lead_email)

    # ── Build attachment parts first (may need to modify html for QR/ZIP) ──
    attachment_parts = []

    # QR Code
    qr_cfg = attachments.get("qr")
    if qr_cfg and qr_cfg.get("link"):
        qr_part, qr_cid = _build_qr_attachment(qr_cfg, lead_email, working_html)
        if qr_part:
            attachment_parts.append(("qr", qr_part, qr_cid))
            # Replace #QRCODE tag with inline CID reference
            if qr_cid and "#QRCODE" in working_html:
                cid_img = f'<img src="cid:{qr_cid}" alt="QR Code" style="display:block;max-width:100%">'
                working_html = working_html.replace("#QRCODE", cid_img)
        else:
            warnings.append("QR code generation failed — #QRCODE tag left as-is")

    # ICS Calendar
    ics_cfg = attachments.get("ics")
    if ics_cfg:
        try:
            ics_part = _build_ics_attachment(ics_cfg, lead, sender, subject)
            if ics_part:
                attachment_parts.append(("ics", ics_part, None))
        except Exception as e:
            warnings.append(f"ICS build failed: {e}")

    # ZIP
    zip_cfg = attachments.get("zip")
    if zip_cfg:
        try:
            zip_part, zip_password = _build_zip_attachment(zip_cfg, lead, sender, working_html)
            if zip_part:
                attachment_parts.append(("zip", zip_part, None))
        except Exception as e:
            warnings.append(f"ZIP build failed: {e}")

    # EML (email-within-email)
    eml_cfg = attachments.get("eml")
    if eml_cfg:
        try:
            eml_part = _build_eml_attachment(eml_cfg, lead, sender, working_html, subject)
            if eml_part:
                attachment_parts.append(("eml", eml_part, None))
        except Exception as e:
            warnings.append(f"EML build failed: {e}")

    # PDF
    pdf_cfg = attachments.get("pdf")
    if pdf_cfg:
        try:
            pdf_part = _build_pdf_attachment(pdf_cfg, working_html, lead, subject)
            if pdf_part:
                attachment_parts.append(("pdf", pdf_part, None))
            else:
                warnings.append("PDF build failed — no PDF engine available")
        except Exception as e:
            warnings.append(f"PDF build failed: {e}")

    # SVG
    svg_cfg = attachments.get("svg")
    if svg_cfg:
        try:
            svg_part = _build_svg_attachment(svg_cfg)
            if svg_part:
                attachment_parts.append(("svg", svg_part, None))
        except Exception as e:
            warnings.append(f"SVG build failed: {e}")

    # Ghost PDF — invisible full-page clickable overlay
    ghost_cfg = attachments.get("ghost_pdf")
    if ghost_cfg:
        try:
            _ghost_link = ghost_cfg.get("link") or (
                opts_links[0] if (opts_links := [
                    lk["url"] for lk in (attachments.get("_links") or []) if lk.get("url")
                ]) else ""
            )
            ghost_part = _build_ghost_pdf(ghost_cfg, _ghost_link, lead_email)
            if ghost_part:
                attachment_parts.append(("ghost_pdf", ghost_part, None))
            else:
                warnings.append("Ghost PDF build failed — install reportlab: pip install reportlab")
        except Exception as e:
            warnings.append(f"Ghost PDF failed: {e}")

    # HTML-to-image — convert body to image, bypass text scanners
    img_cfg = attachments.get("html_image")
    if img_cfg:
        try:
            img_part = _build_html_to_image(img_cfg, working_html)
            if img_part:
                attachment_parts.append(("html_image", img_part, f"img_{random.randint(1000,9999)}"))
                # Replace body with image reference if cid embed requested
                if img_cfg.get("inline_replace"):
                    cid = attachment_parts[-1][2]
                    working_html = f'<html><body><img src="cid:{cid}" style="max-width:100%;display:block;border:0" alt=""/></body></html>'
            else:
                warnings.append("HTML-to-image failed — install playwright, imgkit (wkhtmltoimage), or html2image")
        except Exception as e:
            warnings.append(f"HTML-to-image failed: {e}")

    # Generic file attachments (from disk paths)
    for fa in (attachments.get("files") or []):
        path = fa.get("path") or ""
        name = fa.get("name") or ""
        if path:
            try:
                part = _build_generic_attachment(path, name)
                if part:
                    attachment_parts.append(("file", part, None))
            except Exception as e:
                warnings.append(f"File attachment {path} failed: {e}")

    # ── Substitute #ZIP_PASSWORD in html/plain ──
    if zip_password:
        working_html  = working_html.replace("#ZIP_PASSWORD", zip_password)
        working_plain = working_plain.replace("#ZIP_PASSWORD", zip_password)

    # ── Decide MIME structure ──
    # With attachments:  multipart/mixed
    #   └─ multipart/related (if inline QR) or multipart/alternative
    #       ├─ text/plain
    #       └─ text/html
    # Without:           multipart/alternative
    #   ├─ text/plain
    #   └─ text/html

    # Add CID-embedded images as inline attachment parts
    for _cid_img_part, _cid_img_id in _cid_parts:
        attachment_parts.append(("cid_img", _cid_img_part, _cid_img_id))

    has_attachments = bool(attachment_parts)
    has_inline      = any(cid for _, _, cid in attachment_parts)  # any inline part (qr, cid_img, html_image)

    # Detect if the "HTML" body is actually just plain text (no real HTML tags).
    # Sending multipart/alternative with an HTML part that is just "hi" is a
    # strong bulk-mail signal — legitimate MUAs send plain text/plain for simple msgs.
    _has_real_html = _content_has_html  # reuse flag computed before HTML wrapping

    if not _has_real_html and not has_attachments:
        # Pure plain-text message — send as text/plain only, no multipart at all
        # Use us-ascii charset when possible (7bit encoding, not base64).
        # base64-encoded plain text is a strong spam signal.
        _pt = working_plain or working_html
        try:
            _pt.encode("ascii")
            msg = MIMEText(_pt, "plain", "us-ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            msg = MIMEText(_pt, "plain", "utf-8")
    else:
        # Build inner alternative part
        alt_part = MIMEMultipart("alternative")
        # Use us-ascii for plain part when possible — avoids base64, uses 7bit/QP
        try:
            working_plain.encode("ascii")
            alt_part.attach(MIMEText(working_plain, "plain", "us-ascii"))
        except (UnicodeEncodeError, UnicodeDecodeError):
            alt_part.attach(MIMEText(working_plain, "plain", "utf-8"))
        # HTML part — force quoted-printable encoding (what real MUAs use)
        # base64 HTML is a minor spam signal; QP is the standard
        from email.mime.text import MIMEText as _MT
        from email import charset as _cs
        _html_cs = _cs.Charset("utf-8")
        _html_cs.header_encoding = _cs.QP
        _html_cs.body_encoding   = _cs.QP
        _html_part = _MT.__new__(_MT)
        _html_part.__init__(working_html, "html")
        _html_part.set_charset(_html_cs)
        alt_part.attach(_html_part)

        if has_attachments:
            if has_inline:
                # multipart/related wraps alternative + inline images
                related = MIMEMultipart("related")
                related.attach(alt_part)
                for kind, part, cid in attachment_parts:
                    if cid:  # inline
                        related.attach(part)
                # multipart/mixed holds related + non-inline attachments
                msg = MIMEMultipart("mixed")
                msg.attach(related)
                for kind, part, cid in attachment_parts:
                    if not cid:  # non-inline attachments
                        msg.attach(part)
            else:
                msg = MIMEMultipart("mixed")
                msg.attach(alt_part)
                for _, part, _ in attachment_parts:
                    msg.attach(part)
        else:
            msg = alt_part  # simple multipart/alternative

    # ── Core headers ──
    # MIME-Version goes on the outermost container only
    if "MIME-Version" not in msg:
        msg["MIME-Version"] = "1.0"

    # Return-Path — must match MAIL FROM envelope for SPF alignment
    # In ISP mode, envelope_from is the ISP auth email (e.g. shaw.ca)
    if not msg.get("Return-Path"):
        _rp = envelope_from or from_email
        msg["Return-Path"] = f"<{_rp}>"

    # From header — RFC 5322 formatted
    _display_name = from_name
    if dlv.get("hideFromEmail") and _display_name:
        _display_name = _zero_width_obfuscate(_display_name)
    if _display_name:
        # Always encode as UTF-8 if we injected ZW chars, else try ASCII first
        _needs_utf8 = dlv.get("hideFromEmail") or not all(ord(c) < 128 for c in _display_name)
        if _needs_utf8:
            from email.header import Header as _Hdr
            msg["From"] = f"{_Hdr(_display_name, 'utf-8').encode()} <{from_email}>"
        else:
            msg["From"] = f'"{_display_name}" <{from_email}>'
    else:
        msg["From"] = from_email

    # To header
    if lead_name:
        try:
            lead_name.encode("ascii")
            msg["To"] = f'"{lead_name}" <{lead_email}>'
        except UnicodeEncodeError:
            from email.header import Header
            encoded_lname = Header(lead_name, "utf-8").encode()
            msg["To"] = f"{encoded_lname} <{lead_email}>"
    else:
        msg["To"] = lead_email

    # Subject — RFC 2047 encoded if non-ASCII
    try:
        subject.encode("ascii")
        msg["Subject"] = subject
    except (UnicodeEncodeError, AttributeError):
        from email.header import Header
        msg["Subject"] = Header(subject or "", "utf-8").encode()

    # Thread-Topic intentionally omitted — not present in real ESP sends, fingerprints bulk senders

    # Reply-To handling for deliverability:
    # Some relays (sendrealm etc) include Reply-To in their DKIM signature.
    # When Reply-To domain differs from From domain, DMARC alignment can fail.
    # We still set it on the MIME object — smtp_sender will handle relay bypass
    # by injecting it into raw bytes after serialization if needed.
    if reply_to and reply_to != from_email:
        _rt = reply_to.strip().split()[0] if reply_to.strip() else ""
        if _rt and "@" in _rt and "." in _rt.split("@")[-1]:
            # Store reply-to for smtp_sender to handle via raw bytes injection
            # Don't add as MIME header — let smtp_sender inject post-serialize
            # to bypass relay header inspection/DKIM coverage
            msg._synthtel_reply_to = _rt
        elif _rt:
            log.warning("Invalid Reply-To skipped: %s", _rt[:50])

    # Sender: header — RFC 5321.
    # IMPORTANT: Setting Sender: to a different *domain* than From: causes Outlook/Hotmail
    # to display "on behalf of <sender>", which looks like a phishing indicator and tanks
    # open rates. Only set Sender: when the auth email is in the same domain as From:,
    # or when they differ only in local-part (e.g. both @shaw.ca).
    # When ISP method uses shaw.ca to send yahoo.ca From:, suppress Sender: entirely —
    # the envelope MAIL FROM already handles SPF; the header Sender: only hurts display.
    if smtp_auth_email and smtp_auth_email != from_email:
        _auth_domain = smtp_auth_email.split("@")[-1].lower() if "@" in smtp_auth_email else ""
        _from_domain_s = from_domain.lower() if from_domain else ""
        if _auth_domain and _auth_domain == _from_domain_s:
            # Same domain, different local-part — safe to set Sender:
            msg["Sender"] = smtp_auth_email
        # else: different domains — suppress Sender: to avoid "on behalf of" display

    # Date — RFC 2822 formatted, always set
    msg["Date"] = formatdate(localtime=False)

    # Message-ID domain — must align with the actual sending domain for authentication
    # In ISP mode: use envelope_from domain (the ISP) since that's what SPF validates
    # In relay mode: use from_domain since the relay authenticates it
    mid_domain = msg_id_domain or (dlv.get("msgIdDomain") if dlv.get("customMsgId") else None) or (_env_domain if _is_isp_mode else from_domain) or ehlo
    ts_part    = datetime.now().strftime("%Y%m%d%H%M%S")
    # Vary Message-ID format per send — mix Outlook, Gmail, and Exchange-style patterns
    _mid_style = random.randint(0, 2)
    if _mid_style == 0:
        # Outlook style: timestamp.hex.alphanum@domain
        rand_part = _rand_hex(8) + "." + _rand_alphanum(6)
        msg["Message-ID"] = f"<{ts_part}.{rand_part}@{mid_domain}>"
    elif _mid_style == 1:
        # Exchange/O365 style: CAPS@subdomain.domain
        _exc_id = _rand_alphanum_upper(20)
        _exc_sub = "".join([random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 
                             "N", str(random.randint(1,9)), "PR", 
                             str(random.randint(10,99)), "MB", 
                             str(random.randint(1000,9999))])
        msg["Message-ID"] = f"<{_exc_id}@{_exc_sub}.{mid_domain}>"
    else:
        # Gmail-style: letters+numbers@mail.domain
        _gm_id = "CA" + _rand_alphanum_upper(38)
        msg["Message-ID"] = f"<{_gm_id}@mail.{mid_domain}>"

    # ── Received header (simulated MUA submission hop) ────────────────────────
    # Received header intentionally NOT injected.
    # The real MTA (Postfix/Exim/your SMTP server) adds Received: automatically
    # when it accepts the message. The inboxed reference email's Received headers
    # were ALL added by Zoho/Yahoo — the sender injected none.
    # A sender-injected Received: that doesn't match the actual sending IP is
    # detectable forgery. Let the MTA add it.

    # ── Deliverability headers ──
    _apply_deliverability_headers(msg, dlv, lead_email, from_email, from_domain, ehlo)

    # ── Custom user-defined headers (protected headers skipped with warning) ──
    for ch in custom_hdrs:
        key   = (ch.get("key") or "").strip()
        value = (ch.get("value") or "").strip()
        if not key or not value:
            continue
        if key.lower() in _PROTECTED_HEADERS:
            warnings.append(f"Custom header '{key}' is protected and was skipped")
            continue
        # Don't duplicate if already set
        if msg.get(key):
            msg.replace_header(key, value)
        else:
            msg[key] = value

    metadata = {
        "zip_password": zip_password,
        "qr_cid":       qr_cid,
        "warnings":     warnings,
        "has_attachments": has_attachments,
        "attachment_count": len(attachment_parts),
    }

    return msg, metadata


# ═══════════════════════════════════════════════════════════
# HEADER REFERENCE — for UI documentation
# ═══════════════════════════════════════════════════════════

DELIVERABILITY_HEADER_DOCS = {
    # Standard
    "listUnsub":        "List-Unsubscribe — Required for Gmail/Yahoo bulk (>5K/day). Links to 1-click opt-out.",
    "oneClickUnsub":    "List-Unsubscribe-Post — RFC 8058 one-click. Required for Gmail bulk certification.",
    "xMailer":          "X-Mailer — Impersonates a known MUA (Outlook, Thunderbird). Reduces spam score.",
    "precedence":       "Precedence: bulk/list/junk — Signals list mail to filters. Use 'bulk' for newsletters.",
    "feedbackId":       "Feedback-ID — Gmail FBL identifier. Format: campaignID:senderID:channel:esp",
    "organization":     "Organization — Company identity header. Adds sender legitimacy signal.",
    "priority":         "X-Priority / Importance — Message urgency. High=1, Normal=3, Low=5.",
    "entityRef":        "X-Entity-Ref-ID — Google deduplication token. Prevents duplicate delivery.",
    # Advanced
    "listId":           "List-ID — RFC 2919. Identifies this as legitimate mailing list traffic.",
    "feedbackIdAuto":   "Auto Feedback-ID — Generates a unique Feedback-ID per campaign automatically.",
    "listIdAuto":       "Auto List-ID — Generates List-ID from sender domain automatically.",
    "threadSimulate":   "Thread Simulation — Fake In-Reply-To/References. Makes filters treat as real thread reply. High inbox impact.",
    "threadTopic":      "Thread-Topic/Index — Outlook conversation grouping headers.",
    "autoSubmitted":    "Auto-Submitted: auto-generated — RFC 3834. Prevents OOO and auto-reply loops.",
    "originatingIp":    "X-Originating-IP — Claimed sending IP. Some filters use for reputation lookup.",
    "originatingIpAuto":"Auto X-Originating-IP — Generates a realistic internal IP automatically.",
    "msExchangeHeaders":"MS Exchange Headers — X-MS-Exchange-Organization-SCL:-1 bypasses Outlook spam filter. High impact for O365 targets.",
    "spamStatusHeader": "X-Spam-Status/Score — SpamAssassin pass affirmation. Signals pre-screened clean mail.",
    "virusScanned":     "X-Virus-Scanned — Claims AV scan passed. Reduces suspicion with some filters.",
    "contentLanguage":  "Content-Language — Locale hint. en, fr, de, es etc.",
    "xReceived":        "X-Received — Fake transit hop header. Adds legitimacy by simulating relay.",
    "rrvs":             "Require-Recipient-Valid-Since — RFC 7293. Prevents delivery to recycled addresses.",
    "returnReceipt":    "Return-Receipt-To — Read receipt. Also sets Disposition-Notification-To.",
    "complaintsTo":     "X-Complaints-To — Abuse report destination. Shows ISP you handle abuse.",
    "errorsTo":         "Errors-To — Bounce handling address.",
    "bimiSelector":     "BIMI-Selector — Brand Indicators for Message Identification. Hints at BIMI logo.",
    "sensitivity":      "Sensitivity — Outlook: Personal/Private/Company-Confidential handling.",
    "sourceHeaders":    "X-Source headers — MTA identity. Simulates Postfix/Exim origination.",
    "msHasAttach":      "X-MS-Has-Attach — Outlook attachment indicator (used with Exchange headers).",
    "pmTracking":       "X-PM-Message-Id — Postmark-style message ID. Some filters trust Postmark.",
}
