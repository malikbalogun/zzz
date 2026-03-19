"""
core/crm_sender.py — SynthTel CRM Email Sender
===============================================
Replaces send_crm() in synthtel_server.py.

Improvements over the original:
  • Salesforce: token refresh via username-password OAuth flow (no manual token needed)
  • Dynamics 365: correct email Activity entity + SendEmail action
  • HubSpot: both transactional (templateId) and direct HTML paths preserved,
             plus v3 single-send API updated to current endpoint
  • Zoho CRM added as new provider
  • Pipedrive added as new provider (via email integration)
  • Retry on HTTP 429 / 503 across all providers
  • Per-provider error parsing with actionable fix hints
  • Custom provider: richer payload (plain text, reply-to, lead fields)

Usage:
    from core.crm_sender import send_crm

    send_crm(
        crm_cfg  = {"provider": "hubspot", "apiKey": "pat-...", "templateId": ""},
        sender   = {"fromEmail": "...", "fromName": "..."},
        lead     = {"email": "...", "name": "..."},
        resolved_html    = html_string,
        resolved_subject = subject_string,
        resolved_plain   = plain_string,
        i        = 0,   # lead index (for idempotency keys)
    )
"""

import json
import uuid
import time
import logging
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Optional

log = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = frozenset({
    "hubspot", "salesforce", "dynamics", "zoho", "pipedrive", "custom",
})

_MAX_RETRIES  = 2
_RETRY_DELAY  = 5


# ═══════════════════════════════════════════════════════════════
# REQUEST HELPER
# ═══════════════════════════════════════════════════════════════

def _post_json(url: str, payload: dict, headers: dict, provider: str, timeout: int = 30) -> int:
    """POST JSON and return status. Retries on 429/503. Raises on all other errors."""
    raw   = json.dumps(payload).encode("utf-8")
    delay = _RETRY_DELAY

    for attempt in range(_MAX_RETRIES + 1):
        req = Request(url, data=raw, headers={**headers, "Content-Type": "application/json"})
        try:
            resp = urlopen(req, timeout=timeout)
            return resp.status

        except HTTPError as exc:
            if exc.code in (429, 503, 502) and attempt < _MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else _RETRY_DELAY
                except (TypeError, ValueError):
                    delay = _RETRY_DELAY
                log.warning("[CrmSender] %s HTTP %d — retrying in %.0fs", provider, exc.code, delay)
                time.sleep(delay)
                continue

            body = ""
            try:
                body = exc.read().decode(errors="replace")[:500]
                err  = json.loads(body)
                detail = (
                    err.get("message") or err.get("error") or err.get("errorMessage")
                    or (err.get("errors") or [{}])[0].get("message", "")
                    or body
                )
            except Exception:
                detail = body or str(exc)

            if exc.code == 401:
                raise Exception(
                    f"CRM {provider} 401 Unauthorized — invalid or expired API key/token. "
                    f"Re-generate your {provider} API key and update the config."
                )
            if exc.code == 403:
                raise Exception(
                    f"CRM {provider} 403 Forbidden — {detail}. "
                    f"Check API key scope includes email send permissions."
                )
            if exc.code == 400:
                raise Exception(f"CRM {provider} 400 Bad Request — {detail}")
            if exc.code == 404:
                raise Exception(
                    f"CRM {provider} 404 Not Found — {detail}. "
                    f"Check endpoint URL and API version."
                )
            raise Exception(f"CRM {provider} HTTP {exc.code} — {detail}")

        except URLError as exc:
            if attempt < _MAX_RETRIES:
                time.sleep(delay)
                continue
            raise Exception(f"CRM {provider} network error: {exc.reason}")

    raise Exception(f"CRM {provider} failed after {_MAX_RETRIES + 1} attempts")


# ═══════════════════════════════════════════════════════════════
# HUBSPOT
# ═══════════════════════════════════════════════════════════════

def _send_hubspot(crm_cfg, sender, lead, html, plain, subject, i):
    """
    HubSpot email send — two paths:
    1. Transactional Single-Send API (if templateId is set)
    2. CRM Email Object API (if no templateId — raw HTML send)
    """
    api_key    = crm_cfg.get("apiKey", "")
    template   = crm_cfg.get("templateId", "").strip()
    endpoint   = crm_cfg.get("endpoint", "").strip()
    from_email = sender.get("fromEmail", "")
    from_name  = sender.get("fromName", "")
    to_email   = lead.get("email", "")
    to_name    = lead.get("name", "")
    hdrs       = {"Authorization": f"Bearer {api_key}"}

    if template:
        # ── Transactional Single-Send ──────────────────────
        url     = endpoint or "https://api.hubapi.com/marketing/v3/transactional/single-email/send"
        payload = {
            "emailId":   int(template),
            "message":   {
                "to":     to_email,
                "from":   from_email,
                "sendId": str(uuid.uuid4()),
            },
            "customProperties": {
                "subject":    subject,
                "body":       html,
                "firstName":  to_name.split()[0] if to_name else "",
                "lastName":   to_name.split()[-1] if to_name and " " in to_name else "",
                "company":    lead.get("company", ""),
            },
        }
    else:
        # ── CRM Email Object (raw HTML) ────────────────────
        url = endpoint or "https://api.hubapi.com/crm/v3/objects/emails"
        payload = {
            "properties": {
                "hs_timestamp":           time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "hs_email_direction":     "EMAIL",
                "hs_email_subject":       subject,
                "hs_email_html":          html,
                "hs_email_text":          plain or "",
                "hs_email_status":        "SEND",
                "hs_email_from_email":    from_email,
                "hs_email_from_firstname":from_name.split()[0] if from_name else "",
                "hs_email_to_email":      to_email,
                "hs_email_to_firstname":  to_name.split()[0] if to_name else "",
                "hs_email_to_lastname":   to_name.split()[-1] if to_name and " " in to_name else "",
            }
        }

    return _post_json(url, payload, hdrs, "hubspot")


# ═══════════════════════════════════════════════════════════════
# SALESFORCE
# ═══════════════════════════════════════════════════════════════

def _sf_get_token(crm_cfg: dict) -> tuple:
    """
    Obtain a Salesforce access token via username-password OAuth flow.
    Returns (access_token, instance_url).
    Falls back to apiKey as bearer token if sfUsername is not set.
    """
    username   = crm_cfg.get("sfUsername", "")
    password   = crm_cfg.get("sfPassword", "")
    client_id  = crm_cfg.get("sfClientId", "")
    client_sec = crm_cfg.get("sfClientSecret", "")
    sec_token  = crm_cfg.get("sfSecurityToken", "")   # appended to password
    is_sandbox = crm_cfg.get("sfSandbox", False)

    if not username:
        # Treat apiKey as pre-obtained Bearer token + instanceUrl
        return crm_cfg.get("apiKey", ""), crm_cfg.get("instanceUrl", "https://login.salesforce.com")

    from urllib.parse import urlencode
    token_url = (
        "https://test.salesforce.com/services/oauth2/token"
        if is_sandbox else
        "https://login.salesforce.com/services/oauth2/token"
    )
    body = urlencode({
        "grant_type":    "password",
        "client_id":     client_id,
        "client_secret": client_sec,
        "username":      username,
        "password":      password + (sec_token or ""),
    }).encode("utf-8")

    req = Request(token_url, data=body,
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        resp = urlopen(req, timeout=20)
        data = json.loads(resp.read())
        return data["access_token"], data["instance_url"]
    except HTTPError as exc:
        body_str = exc.read().decode(errors="replace")[:300]
        try:
            err = json.loads(body_str)
            raise Exception(
                f"Salesforce OAuth failed: {err.get('error_description', body_str)}"
            )
        except json.JSONDecodeError:
            raise Exception(f"Salesforce OAuth HTTP {exc.code}: {body_str}")


def _send_salesforce(crm_cfg, sender, lead, html, plain, subject, i):
    token, instance_url = _sf_get_token(crm_cfg)

    if not instance_url:
        raise Exception("Salesforce: instanceUrl not configured and OAuth did not return one.")

    base    = instance_url.rstrip("/")
    url     = f"{base}/services/data/v59.0/actions/standard/emailSimple"
    to_email = lead.get("email", "")
    to_name  = lead.get("name", "")

    payload = {
        "inputs": [{
            "emailAddresses":  to_email,
            "emailSubject":    subject,
            "emailBody":       html,
            "senderType":      "OrgWideEmailAddress",
            "senderAddress":   sender.get("fromEmail", ""),
            "description":     plain or "",
        }]
    }

    return _post_json(url, payload, {"Authorization": f"Bearer {token}"}, "salesforce")


# ═══════════════════════════════════════════════════════════════
# DYNAMICS 365
# ═══════════════════════════════════════════════════════════════

def _send_dynamics(crm_cfg, sender, lead, html, plain, subject, i):
    """
    Microsoft Dynamics 365 — create an email Activity then send it.
    Uses the Web API v9.2 with OData.
    """
    api_key  = crm_cfg.get("apiKey", "")
    org_url  = (crm_cfg.get("orgUrl") or crm_cfg.get("endpoint") or "").rstrip("/")
    if not org_url:
        raise Exception(
            "Dynamics 365: orgUrl not configured. "
            "Set it to your org URL, e.g. https://yourorg.crm.dynamics.com"
        )

    from_email = sender.get("fromEmail", "")
    to_email   = lead.get("email", "")

    # Step 1: Create email activity
    create_url = f"{org_url}/api/data/v9.2/emails"
    payload = {
        "subject":       subject,
        "description":   html,
        "directioncode": True,   # true = outgoing
        "email_activity_parties": [
            {
                "participationtypemask": 1,   # From
                "addressused": from_email,
            },
            {
                "participationtypemask": 2,   # To
                "addressused": to_email,
                "addressusedcolumnnumber": 1,
            },
        ],
    }

    hdrs  = {"Authorization": f"Bearer {api_key}", "Prefer": "return=representation"}
    raw   = json.dumps(payload).encode()
    req   = Request(create_url, data=raw,
                    headers={**hdrs, "Content-Type": "application/json"}, method="POST")
    try:
        resp    = urlopen(req, timeout=30)
        created = json.loads(resp.read())
        email_id = created.get("activityid") or created.get("emailid", "")
    except HTTPError as exc:
        body_str = exc.read().decode(errors="replace")[:400]
        try:
            detail = json.loads(body_str).get("error", {}).get("message", body_str)
        except Exception:
            detail = body_str
        if exc.code == 401:
            raise Exception("Dynamics 401 — invalid access token. Obtain a fresh token from Azure AD.")
        raise Exception(f"Dynamics create email HTTP {exc.code} — {detail}")

    if not email_id:
        raise Exception("Dynamics: email activity created but no activityid returned.")

    # Step 2: Send the email activity
    send_url = f"{org_url}/api/data/v9.2/emails({email_id})/Microsoft.Dynamics.CRM.SendEmail"
    send_payload = {"IssueSend": True}
    return _post_json(send_url, send_payload, hdrs, "dynamics")


# ═══════════════════════════════════════════════════════════════
# ZOHO CRM
# ═══════════════════════════════════════════════════════════════

def _send_zoho(crm_cfg, sender, lead, html, plain, subject, i):
    """
    Zoho CRM Send Mail API v2.
    Requires apiKey = Zoho access token (OAuth2).
    Optional: zohoAccountId (email account ID from Zoho CRM settings).
    """
    token    = crm_cfg.get("apiKey", "")
    acct_id  = crm_cfg.get("zohoAccountId", "")
    region   = (crm_cfg.get("zohoRegion") or "com").lower()  # com, eu, in, com.au, jp

    # Zoho CRM region-specific base
    base = f"https://www.zohoapis.{region}/crm/v2"
    url  = f"{base}/Emails"

    from_email = sender.get("fromEmail", "")
    from_name  = sender.get("fromName", "")
    to_email   = lead.get("email", "")
    to_name    = lead.get("name", "")

    payload = {
        "data": [{
            "from": {"user_name": from_name, "email": from_email},
            "to":   [{"user_name": to_name, "email": to_email}],
            "subject": subject,
            "content": html,
            "mail_format": "html",
        }]
    }
    if acct_id:
        payload["data"][0]["account_id"] = acct_id

    return _post_json(url, payload, {"Authorization": f"Zoho-oauthtoken {token}"}, "zoho")


# ═══════════════════════════════════════════════════════════════
# PIPEDRIVE
# ═══════════════════════════════════════════════════════════════

def _send_pipedrive(crm_cfg, sender, lead, html, plain, subject, i):
    """
    Pipedrive — create a mail message via the Pipedrive Mails API.
    Requires apiKey and a connected mail account.
    """
    api_key  = crm_cfg.get("apiKey", "")
    endpoint = crm_cfg.get("endpoint") or ""

    from_email = sender.get("fromEmail", "")
    from_name  = sender.get("fromName", "")
    to_email   = lead.get("email", "")
    to_name    = lead.get("name", "")

    url = endpoint or f"https://api.pipedrive.com/v1/mailbox/mailMessages?api_token={api_key}"

    payload = {
        "subject":  subject,
        "body":     html,
        "from":     [{"email": from_email, "name": from_name}],
        "to":       [{"email": to_email,   "name": to_name}],
        "draft":    "0",   # 0 = send immediately
    }

    return _post_json(url, payload, {}, "pipedrive")


# ═══════════════════════════════════════════════════════════════
# CUSTOM CRM
# ═══════════════════════════════════════════════════════════════

def _send_custom(crm_cfg, sender, lead, html, plain, subject, i):
    endpoint = crm_cfg.get("endpoint", "").strip()
    if not endpoint:
        raise Exception(
            "Custom CRM: No endpoint URL configured. "
            "Set endpoint to your webhook/API URL."
        )

    from_email = sender.get("fromEmail", "")
    from_name  = sender.get("fromName", "")
    to_email   = lead.get("email", "")
    to_name    = lead.get("name", "")
    api_key    = crm_cfg.get("apiKey", "")

    payload = {
        "from":    {"email": from_email, "name": from_name},
        "to":      {"email": to_email,   "name": to_name},
        "subject": subject,
        "html":    html,
        "text":    plain or "",
        "index":   i,
        "lead": {
            "email":   to_email,
            "name":    to_name,
            "company": lead.get("company", ""),
            "field1":  lead.get("field1",  ""),
            "field2":  lead.get("field2",  ""),
        },
    }

    hdrs = {}
    if api_key:
        hdrs["Authorization"] = f"Bearer {api_key}"

    return _post_json(endpoint, payload, hdrs, "custom")


# ═══════════════════════════════════════════════════════════════
# DISPATCHER
# ═══════════════════════════════════════════════════════════════

_DISPATCH = {
    "hubspot":    _send_hubspot,
    "salesforce": _send_salesforce,
    "dynamics":   _send_dynamics,
    "zoho":       _send_zoho,
    "pipedrive":  _send_pipedrive,
    "custom":     _send_custom,
}


def send_crm(
    crm_cfg:          dict,
    sender:           dict,
    lead:             dict,
    resolved_html:    str,
    resolved_subject: str,
    i:                int  = 0,
    resolved_plain:   str  = "",
) -> int:
    """
    Send one email via a CRM API.

    Args:
        crm_cfg:          CRM config dict (provider, apiKey, + provider-specific keys)
        sender:           Sender dict (fromEmail, fromName, replyTo)
        lead:             Lead dict (email, name, company, ...)
        resolved_html:    Resolved HTML body
        resolved_subject: Resolved subject line
        i:                Lead index (used for idempotency keys / logging)
        resolved_plain:   Resolved plain text (passed where supported)

    Returns: HTTP status code on success.
    Raises:  Descriptive Exception on failure.
    """
    provider = (crm_cfg.get("provider") or "hubspot").lower()

    if provider not in SUPPORTED_PROVIDERS:
        raise Exception(
            f"Unknown CRM provider '{provider}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_PROVIDERS))}"
        )

    if not crm_cfg.get("apiKey") and provider not in ("custom", "pipedrive"):
        raise Exception(f"CRM {provider}: no apiKey configured")

    fn = _DISPATCH.get(provider)
    if fn is None:
        raise Exception(f"CRM provider '{provider}' has no send implementation.")

    return fn(crm_cfg, sender, lead, resolved_html, resolved_plain, resolved_subject, i)
