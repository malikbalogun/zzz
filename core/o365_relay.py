"""
core/o365_relay.py
──────────────────
Microsoft 365 Anonymous (Direct Send) Relay

How it works:
  • Microsoft 365 tenants expose an SMTP endpoint at
    <tenant-domain-dashes>.mail.protection.outlook.com:25
  • An Exchange inbound connector can be configured to accept mail from
    specific IP addresses with NO authentication (Direct Send / SMTP Relay).
  • MAIL FROM can be any address in the tenant.
  • No SMTP AUTH handshake — connector validates by source IP only.

Prerequisites (admin must configure once):
  1. Exchange Admin Center → Mail flow → Connectors
  2. Create a connector: Source = Your org server, Type = Partner
  3. Restrict accepted IPs to the SynthTel server's public IP
  4. Optional: Enable "Require TLS" for STARTTLS support

Usage in campaign.py _send_one():
    elif method == "o365":
        from core.o365_relay import send_via_o365_relay
        relay = options.o365_relay  # first relay from list
        yield from send_via_o365_relay(relay, envelope)
"""

import smtplib
import socket
import ssl
import logging
import time

log = logging.getLogger("synthtel.o365_relay")


def _derive_mx(tenant_domain: str) -> str:
    """Convert 'contoso.com' → 'contoso-com.mail.protection.outlook.com'"""
    return tenant_domain.replace(".", "-") + ".mail.protection.outlook.com"


def send_via_o365_relay(
    relay:    dict,
    msg_from: str,
    msg_to:   str,
    raw_msg:  bytes,
    timeout:  int = 30,
) -> dict:
    """
    Send a single message via O365 anonymous relay.

    relay = {
        "tenantDomain": "contoso.com",
        "fromEmail":    "noreply@contoso.com",   # override MAIL FROM (optional)
        "mxHost":       "contoso-com.mail.protection.outlook.com",  # auto-derived if absent
        "port":         25,
    }
    msg_from: MAIL FROM address (usually sender's address in tenant)
    msg_to:   RCPT TO address
    raw_msg:  bytes — the full RFC 5322 message

    Returns:
        {"ok": True, "message": "..."}  or  {"ok": False, "error": "..."}
    """
    tenant   = relay.get("tenantDomain", "")
    mx_host  = relay.get("mxHost") or _derive_mx(tenant)
    port     = int(relay.get("port", 25))
    # If relay specifies a from_email, honour it for MAIL FROM
    mail_from = relay.get("fromEmail") or msg_from

    if not mx_host:
        return {"ok": False, "error": "No tenant domain or mx_host configured"}

    t0 = time.time()
    try:
        if port == 465:
            # SMTPS (rare for O365 relay but possible)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with smtplib.SMTP_SSL(mx_host, port, timeout=timeout, context=ctx) as conn:
                conn.ehlo(mail_from.split("@")[-1] if "@" in mail_from else "mail.local")
                conn.sendmail(mail_from, [msg_to], raw_msg)
        else:
            with smtplib.SMTP(mx_host, port, timeout=timeout) as conn:
                conn.ehlo(mail_from.split("@")[-1] if "@" in mail_from else "mail.local")
                # Try STARTTLS if supported — O365 may offer it on port 25
                try:
                    if conn.has_extn("STARTTLS"):
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn.starttls(context=ctx)
                        conn.ehlo()
                except Exception as tls_err:
                    log.debug("STARTTLS optional — skipping: %s", tls_err)
                # NO AUTH — anonymous relay validates by IP at the connector level
                conn.sendmail(mail_from, [msg_to], raw_msg)

        latency = round((time.time() - t0) * 1000)
        log.info("O365 relay OK  %s → %s via %s:%s (%dms)", mail_from, msg_to, mx_host, port, latency)
        return {"ok": True, "message": f"Sent via {mx_host}:{port} ({latency}ms)"}

    except smtplib.SMTPRecipientsRefused as e:
        err = str(e)
        if "550" in err and "5.7" in err:
            return {"ok": False, "error": f"IP not whitelisted in O365 connector: {err[:200]}"}
        return {"ok": False, "error": f"Recipient refused: {err[:200]}"}
    except smtplib.SMTPSenderRefused as e:
        return {"ok": False, "error": f"Sender refused (check MAIL FROM is in tenant): {str(e)[:200]}"}
    except smtplib.SMTPException as e:
        return {"ok": False, "error": f"SMTP error: {str(e)[:200]}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"ok": False, "error": f"Connection failed to {mx_host}:{port}: {str(e)[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"Unexpected error: {str(e)[:200]}"}


def test_relay_connectivity(tenant_domain: str, port: int = 25, timeout: int = 10) -> dict:
    """
    Quick TCP + SMTP banner check for a tenant relay endpoint.
    Returns {"ok": bool, "banner": str, "latency_ms": int, "mx_host": str}
    """
    mx_host = _derive_mx(tenant_domain)
    t0 = time.time()
    try:
        s = socket.create_connection((mx_host, port), timeout=timeout)
        s.settimeout(5)
        banner = b""
        try:
            banner = s.recv(512)
        except Exception:
            pass
        s.close()
        latency = round((time.time() - t0) * 1000)
        banner_str = banner.decode("utf-8", errors="replace").strip()
        return {
            "ok": banner_str.startswith("220"),
            "banner": banner_str[:120],
            "latency_ms": latency,
            "mx_host": mx_host,
            "ready": banner_str.startswith("220"),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e)[:120],
            "mx_host": mx_host,
            "ready": False,
        }
