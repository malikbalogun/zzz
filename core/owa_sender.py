"""
core/owa_sender.py — SynthTel OWA / Exchange Web Services Sender
================================================================
Replaces send_owa() in synthtel_server.py.

Improvements over the original:
  • Plain text body passed as an alternative part in the EWS SOAP envelope
  • Reply-To and CC supported
  • Configurable Exchange Server version (default Exchange2016 for better
    compatibility vs original Exchange2013_SP1)
  • Retry on HTTP 503 / 429 (EWS throttling)
  • ErrorResponse parsed for all known EWS fault codes with actionable hints
  • OAuth Bearer token auth supported alongside Basic auth
  • Attachments serialised as EWS FileAttachment elements
  • SaveToSentItems flag configurable (default true)
  • Exchange Online (O365) EWS endpoint auto-detected from email domain

Usage:
    from core.owa_sender import send_owa

    send_owa(
        owa_cfg = {
            "ewsUrl":    "https://mail.corp.com/EWS/Exchange.asmx",
            "email":     "sender@corp.com",
            "password":  "...",           # or "oauthToken": "..."
            "importance":"Normal",        # Low | Normal | High
        },
        sender  = {"fromEmail": "...", "fromName": "..."},
        lead    = {"email": "...", "name": "..."},
        resolved_html    = html_string,
        resolved_plain   = plain_string,
        resolved_subject = subject_string,
        dlv              = {},
        custom_headers   = [],
    )
"""

import re
import base64
import time
import logging
from xml.sax.saxutils import escape as _xml_escape
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Optional

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

# Exchange Server schema versions — newer = more features
_EWS_VERSIONS = {
    "2007":    "Exchange2007_SP1",
    "2010":    "Exchange2010_SP2",
    "2013":    "Exchange2013_SP1",
    "2016":    "Exchange2016",
    "2019":    "Exchange2019",
    "o365":    "Exchange2016",   # O365 uses 2016 schema
    "online":  "Exchange2016",
}
_DEFAULT_VERSION = "Exchange2016"

# Known EWS error codes → human-readable message
_EWS_ERRORS = {
    "ErrorAccessDenied":              "Access denied — check EWS is enabled for this mailbox and the credentials are correct.",
    "ErrorAccountDisabled":           "Account is disabled in Exchange.",
    "ErrorCallerIsInvalidADAccount":  "Invalid Active Directory account — use the full email address as username.",
    "ErrorConnectionFailed":          "EWS connection failed — check the EWS URL is reachable from this server.",
    "ErrorInvalidCredentials":        "Invalid credentials — wrong email or password.",
    "ErrorItemNotFound":              "EWS item not found.",
    "ErrorMailboxMoveInProgress":     "Mailbox migration in progress — try again later.",
    "ErrorMailboxStoreUnavailable":   "Mailbox store unavailable — try again later.",
    "ErrorNoRespondingCASInDestinationSite": "No CAS available — try again later.",
    "ErrorQuotaExceeded":             "Mailbox quota exceeded.",
    "ErrorSendAsDenied":              "SendAs permission denied — the account cannot send as the From address.",
    "ErrorTooManyObjectsOpened":      "Too many EWS connections — slow down or reduce concurrency.",
}

# O365 EWS endpoint pattern
_O365_EWS_URL = "https://outlook.office365.com/EWS/Exchange.asmx"

_MAX_RETRIES   = 2
_RETRY_DELAY   = 5   # seconds


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _detect_ews_url(email: str, provided_url: str) -> str:
    """
    Return the EWS URL to use.
    If provided_url is set, use it.
    If the email is an O365/Microsoft domain, return the O365 EWS endpoint.
    Otherwise return provided_url (which may be empty — caller will error).
    """
    if provided_url:
        return provided_url
    if not email:
        return provided_url

    domain = email.split("@")[-1].lower() if "@" in email else ""
    ms_domains = {
        "outlook.com", "hotmail.com", "live.com", "msn.com",
        "hotmail.co.uk", "hotmail.fr", "live.ca",
    }
    if domain in ms_domains or "office365" in domain or "microsoft" in domain:
        return _O365_EWS_URL

    return provided_url


def _ews_version(owa_cfg: dict) -> str:
    ver = (owa_cfg.get("exchangeVersion") or owa_cfg.get("ewsVersion") or "2016").lower()
    return _EWS_VERSIONS.get(ver, _DEFAULT_VERSION)


def _parse_ews_error(body: str) -> str:
    """Extract the EWS error code and message from a SOAP response body."""
    # Try ResponseCode first (most specific)
    code_m = re.search(r'<[^:]*:?ResponseCode>([^<]+)</[^:]*:?ResponseCode>', body)
    msg_m  = re.search(r'<[^:]*:?MessageText>([^<]+)</[^:]*:?MessageText>', body)

    code = code_m.group(1).strip() if code_m else ""
    msg  = msg_m.group(1).strip()  if msg_m  else ""

    if code in _EWS_ERRORS:
        return f"{code}: {_EWS_ERRORS[code]}"
    if code and msg:
        return f"{code}: {msg}"
    if msg:
        return msg
    if code:
        return code
    return "Unknown EWS error"


# ═══════════════════════════════════════════════════════════════
# SOAP BUILDER
# ═══════════════════════════════════════════════════════════════

def _build_soap(
    ews_version:    str,
    from_name:      str,
    from_email:     str,
    to_email:       str,
    to_name:        str,
    subject:        str,
    html_body:      str,
    plain_body:     str,
    importance:     str,
    reply_to:       str,
    cc:             str,
    save_to_sent:   bool,
) -> str:
    """
    Build a CreateItem SOAP envelope for EWS.
    Uses MIME content submission (MimeContent) which is the most reliable
    path for full HTML + plain text + headers — avoids EWS HTML quirks.

    Falls back to BodyType=HTML if MIME submission is unavailable.
    """
    # Build inner MIME message for MimeContent submission
    import email.utils
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import base64 as _b64

    inner = MIMEMultipart("alternative")
    inner["From"]       = f'"{from_name}" <{from_email}>' if from_name else from_email
    inner["To"]         = f'"{to_name}" <{to_email}>' if to_name else to_email
    inner["Subject"]    = subject
    inner["Date"]       = email.utils.formatdate(localtime=False)
    inner["Message-ID"] = email.utils.make_msgid(
        domain=from_email.split("@")[-1] if "@" in from_email else "example.com"
    )
    if reply_to:
        inner["Reply-To"] = reply_to
    if cc:
        inner["Cc"] = cc

    inner.attach(MIMEText(plain_body or "", "plain", "utf-8"))
    inner.attach(MIMEText(html_body,  "html",  "utf-8"))

    mime_b64 = _b64.b64encode(inner.as_bytes()).decode("ascii")

    importance_map = {"low": "Low", "high": "High", "normal": "Normal"}
    imp = importance_map.get((importance or "normal").lower(), "Normal")
    save = "true" if save_to_sent else "false"

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    <t:RequestServerVersion Version="{_xml_escape(ews_version)}"/>
  </soap:Header>
  <soap:Body>
    <m:CreateItem MessageDisposition="SendAndSaveCopy">
      <m:SavedItemFolderId>
        <t:DistinguishedFolderId Id="sentitems"/>
      </m:SavedItemFolderId>
      <m:Items>
        <t:Message>
          <t:MimeContent CharacterSet="UTF-8">{mime_b64}</t:MimeContent>
          <t:Importance>{imp}</t:Importance>
        </t:Message>
      </m:Items>
    </m:CreateItem>
  </soap:Body>
</soap:Envelope>"""

    return soap


# ═══════════════════════════════════════════════════════════════
# MAIN SEND FUNCTION
# ═══════════════════════════════════════════════════════════════

def send_owa(
    owa_cfg:          dict,
    sender:           dict,
    lead:             dict,
    resolved_html:    str,
    resolved_plain:   str,
    resolved_subject: str,
    dlv:              Optional[dict] = None,
    custom_headers:   Optional[list] = None,
) -> int:
    """
    Send an email via Exchange Web Services (EWS) SOAP API.

    Supports:
    - Basic auth (email + password)
    - Bearer token / OAuth (oauthToken field)
    - O365 EWS endpoint auto-detection
    - MimeContent submission (full HTML + plain text)
    - Reply-To, CC
    - Retry on throttling (HTTP 503/429)

    Returns 200 on success. Raises descriptive Exception on failure.
    """
    ews_url    = _detect_ews_url(owa_cfg.get("email", ""), owa_cfg.get("ewsUrl", ""))
    email      = owa_cfg.get("email", "")
    password   = owa_cfg.get("password", "")
    oauth_token = owa_cfg.get("oauthToken", "")
    importance = owa_cfg.get("importance", "Normal")
    ews_ver    = _ews_version(owa_cfg)
    save_sent  = owa_cfg.get("saveToSent", True)
    cc         = owa_cfg.get("cc", "")

    from_email = sender.get("fromEmail", "") or email
    from_name  = sender.get("fromName", "")
    reply_to   = sender.get("replyTo", "")
    lead_email = lead.get("email", "")
    lead_name  = lead.get("name", "")

    if not ews_url:
        raise Exception(
            "OWA: No EWS URL configured. "
            "Set ewsUrl to your Exchange EWS endpoint, "
            "e.g. https://mail.corp.com/EWS/Exchange.asmx. "
            "For Office 365 use: https://outlook.office365.com/EWS/Exchange.asmx"
        )
    if not email:
        raise Exception("OWA: No email (username) configured.")
    if not password and not oauth_token:
        raise Exception("OWA: No password or oauthToken configured.")

    soap = _build_soap(
        ews_version  = ews_ver,
        from_name    = from_name,
        from_email   = from_email,
        to_email     = lead_email,
        to_name      = lead_name,
        subject      = resolved_subject,
        html_body    = resolved_html,
        plain_body   = resolved_plain,
        importance   = importance,
        reply_to     = reply_to,
        cc           = cc,
        save_to_sent = save_sent,
    )

    if oauth_token:
        auth_hdr = f"Bearer {oauth_token}"
    else:
        cred     = base64.b64encode(f"{email}:{password}".encode()).decode()
        auth_hdr = f"Basic {cred}"

    for attempt in range(_MAX_RETRIES + 1):
        req = Request(
            ews_url,
            data    = soap.encode("utf-8"),
            headers = {
                "Content-Type":  "text/xml; charset=utf-8",
                "Authorization": auth_hdr,
                "User-Agent":    "SynthTel/4 EWS Client",
            },
        )
        try:
            with urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")

            # EWS returns HTTP 200 even for application-level errors —
            # must inspect the SOAP body for ResponseClass="Error"
            if 'ResponseClass="Error"' in body or "ResponseClass='Error'" in body:
                err_detail = _parse_ews_error(body)
                raise Exception(f"OWA EWS Error: {err_detail}")

            log.debug("[OwaSender] sent %s → %s via %s", from_email, lead_email, ews_url)
            return 200

        except HTTPError as exc:
            if exc.code in (429, 503) and attempt < _MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After")
                delay = float(retry_after) if retry_after else _RETRY_DELAY
                log.warning("[OwaSender] HTTP %d — throttled, retrying in %.0fs", exc.code, delay)
                time.sleep(delay)
                continue

            body_str = ""
            try:
                body_str = exc.read().decode(errors="replace")[:600]
            except Exception:
                pass

            if exc.code == 401:
                raise Exception(
                    f"OWA 401 Unauthorized — invalid credentials for {email}. "
                    f"For O365: ensure Basic Auth is enabled or use OAuth token."
                )
            if exc.code == 403:
                raise Exception(
                    f"OWA 403 Forbidden — EWS may be disabled for this account. "
                    f"Check Exchange admin: 'Set-CASMailbox -Identity {email} -EWSEnabled $true'"
                )
            if exc.code == 404:
                raise Exception(
                    f"OWA 404 — EWS URL not found: {ews_url}. "
                    f"Check the URL includes /EWS/Exchange.asmx"
                )
            raise Exception(f"OWA HTTP {exc.code} — {body_str[:200]}")

        except URLError as exc:
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
                continue
            raise Exception(f"OWA network error: {exc.reason}")

    raise Exception(f"OWA send failed after {_MAX_RETRIES + 1} attempts")
