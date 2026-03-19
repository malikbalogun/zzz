#!/usr/bin/env python3
"""
email_checker.py
================

A universal email service account checker that supports multiple providers:
- AWS SES
- SendGrid
- Mailgun
- Postmark
- Mailjet
- Brevo (Sendinblue)
- SparkPost

Auto-detects the provider from the API key format and displays:
- Send limits and quotas
- Emails sent (daily/monthly)
- Verified domains
- Verified email addresses
- Account status/health
- And more provider-specific info

Usage:
    python email_checker.py                          # Interactive mode
    python email_checker.py --key <API_KEY>          # Auto-detect provider
    python email_checker.py --key <KEY> --secret <SECRET>  # For AWS/Mailjet

Requirements:
    pip install requests boto3
"""

import argparse
import json
import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from getpass import getpass
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import base64

# ── stdlib HTTP helper — no third-party dependencies ──────────────
def _http_get(url: str, headers: dict) -> Tuple[Optional[Dict], Optional[str]]:
    """GET request using stdlib urllib. Returns (parsed_json, error_string)."""
    try:
        req  = Request(url, headers=headers, method="GET")
        resp = urlopen(req, timeout=30)
        return json.loads(resp.read().decode("utf-8", errors="replace")), None
    except HTTPError as e:
        body = ""
        try: body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception: pass
        return None, f"HTTP {e.code}: {body}"
    except URLError as e:
        return None, f"Network error: {e.reason}"
    except Exception as e:
        return None, str(e)

def _http_get_basic(url: str, username: str, password: str) -> Tuple[Optional[Dict], Optional[str]]:
    """GET with HTTP Basic Auth."""
    cred = base64.b64encode(f"{username}:{password}".encode()).decode()
    return _http_get(url, {"Authorization": f"Basic {cred}", "Accept": "application/json"})

try:
    import requests
except ImportError:
    requests = None

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    boto3 = None


@dataclass
class EmailServiceStatus:
    """Universal status container for any email service."""
    provider: str
    account_status: str = "Unknown"
    plan: str = "Unknown"
    
    # Sending limits
    daily_limit: Optional[float] = None
    monthly_limit: Optional[float] = None
    rate_limit: Optional[float] = None  # per second
    
    # Usage
    sent_today: Optional[float] = None
    sent_this_month: Optional[float] = None
    sent_last_24h: Optional[float] = None
    remaining_today: Optional[float] = None
    remaining_this_month: Optional[float] = None
    
    # Domains and emails
    domains: List[Dict[str, Any]] = field(default_factory=list)
    verified_emails: List[str] = field(default_factory=list)
    
    # Additional info
    extra_info: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class EmailProvider(ABC):
    """Abstract base class for email service providers."""
    
    @staticmethod
    @abstractmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        """Return True if the key matches this provider's format."""
        pass
    
    @abstractmethod
    def fetch_status(self) -> EmailServiceStatus:
        """Fetch and return the account status."""
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name."""
        pass


class AWSSESProvider(EmailProvider):
    """AWS Simple Email Service provider."""
    
    def __init__(self, access_key: str, secret_key: str, region: str = "us-east-1"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
    
    @property
    def name(self) -> str:
        return "AWS SES"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        # AWS access keys start with AKIA, ASIA, or AIDA and are 20 chars
        return bool(re.match(r'^A[KSI][IA][A-Z0-9]{17}$', key))
    
    def fetch_status(self) -> EmailServiceStatus:
        if boto3 is None:
            status = EmailServiceStatus(provider=self.name)
            status.errors.append("boto3 library not installed. Run: pip install boto3")
            return status
        
        status = EmailServiceStatus(provider=self.name)
        
        try:
            ses = boto3.client(
                "ses",
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
            )
            sesv2 = boto3.client(
                "sesv2",
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
            )
        except Exception as e:
            status.errors.append(f"Failed to create AWS clients: {e}")
            return status
        
        # Get account info from SESv2
        try:
            account = sesv2.get_account()
            send_quota = account.get("SendQuota", {})
            status.daily_limit = send_quota.get("Max24HourSend")
            status.sent_last_24h = send_quota.get("SentLast24Hours")
            status.rate_limit = send_quota.get("MaxSendRate")
            if status.daily_limit and status.sent_last_24h is not None:
                status.remaining_today = status.daily_limit - status.sent_last_24h
            status.account_status = account.get("EnforcementStatus", "Unknown")
            status.extra_info["production_access"] = account.get("ProductionAccessEnabled", False)
            status.extra_info["sending_enabled"] = account.get("SendingEnabled", False)
            status.extra_info["dedicated_ips"] = account.get("DedicatedIpAutoWarmupEnabled", False)
        except ClientError as e:
            # Fallback to SES v1
            try:
                quota = ses.get_send_quota()
                status.daily_limit = quota.get("Max24HourSend")
                status.sent_last_24h = quota.get("SentLast24Hours")
                status.rate_limit = quota.get("MaxSendRate")
                if status.daily_limit and status.sent_last_24h is not None:
                    status.remaining_today = status.daily_limit - status.sent_last_24h
            except Exception as e2:
                status.errors.append(f"Failed to get quota: {e2}")
        
        # Get verified domains
        try:
            domains_resp = ses.list_identities(IdentityType="Domain")
            domain_list = domains_resp.get("Identities", [])
            
            if domain_list:
                verif_resp = ses.get_identity_verification_attributes(Identities=domain_list)
                dkim_resp = ses.get_identity_dkim_attributes(Identities=domain_list)
                
                for domain in domain_list:
                    verif_attr = verif_resp.get("VerificationAttributes", {}).get(domain, {})
                    dkim_attr = dkim_resp.get("DkimAttributes", {}).get(domain, {})
                    status.domains.append({
                        "domain": domain,
                        "verified": verif_attr.get("VerificationStatus", "Unknown"),
                        "dkim_enabled": dkim_attr.get("DkimEnabled", False),
                        "dkim_status": dkim_attr.get("DkimVerificationStatus", "Unknown"),
                    })
        except Exception as e:
            status.errors.append(f"Failed to get domains: {e}")
        
        # Get verified email addresses
        try:
            emails_resp = ses.list_identities(IdentityType="EmailAddress")
            email_list = emails_resp.get("Identities", [])
            if email_list:
                verif_resp = ses.get_identity_verification_attributes(Identities=email_list)
                for email in email_list:
                    verif_attr = verif_resp.get("VerificationAttributes", {}).get(email, {})
                    if verif_attr.get("VerificationStatus") == "Success":
                        status.verified_emails.append(email)
        except Exception as e:
            status.errors.append(f"Failed to get emails: {e}")
        
        return status


class SendGridProvider(EmailProvider):
    """SendGrid email service provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.sendgrid.com/v3"
    
    @property
    def name(self) -> str:
        return "SendGrid"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        return key.startswith("SG.")
    
    def _request(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        return _http_get(
            f"{self.base_url}/{endpoint}",
            {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"},
        )
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)

        # ── Step 1: Check scopes first — tells us what this key can actually do ──
        # A restricted key may only have mail.send scope and nothing else.
        # All 401s on other endpoints are expected in that case.
        scopes = set()
        data, err = self._request("scopes")
        if data:
            scopes = set(data.get("scopes", []))
            can_send   = "mail.send" in scopes
            can_domain = "whitelabel.create" in scopes or "whitelabel.read" in scopes
            status.extra_info["can_send_mail"]   = "✅ Yes" if can_send else "🚫 No — key missing mail.send scope"
            status.extra_info["can_add_domains"] = "Yes" if can_domain else "No"
            status.extra_info["scopes_total"]    = len(scopes)
            if not can_send:
                status.errors.append(
                    "Key does NOT have 'mail.send' scope — sends will fail with 403. "
                    "Go to SendGrid → Settings → API Keys → edit this key → add Mail Send permission."
                )

        # ── Step 2: Account / plan info (requires user.account.read scope) ──
        if not scopes or "user.account.read" in scopes:
            data, err = self._request("user/account")
            if data:
                status.plan = data.get("type", "Unknown")

        # ── Step 3: Profile info (requires user.profile.read scope) ──
        if not scopes or "user.profile.read" in scopes:
            data, err = self._request("user/profile")
            if data:
                status.extra_info["company"]  = data.get("company")
                status.extra_info["username"] = data.get("username")

        # ── Step 4: Credits / monthly quota (requires billing.read or similar) ──
        data, err = self._request("user/credits")
        if data:
            status.remaining_this_month = data.get("remain")
            status.monthly_limit        = data.get("total")
            if status.monthly_limit and status.remaining_this_month is not None:
                status.sent_this_month = status.monthly_limit - status.remaining_this_month
            status.extra_info["reset_frequency"] = data.get("reset_frequency")

        # ── Step 5: Stats for today ──
        today = datetime.utcnow().strftime("%Y-%m-%d")
        data, err = self._request(f"stats?start_date={today}")
        if data and len(data) > 0:
            stats = data[0].get("stats", [{}])[0].get("metrics", {})
            status.sent_today = stats.get("requests", 0)

        # ── Step 6: Stats for this month ──
        month_start = datetime.utcnow().replace(day=1).strftime("%Y-%m-%d")
        data, err = self._request(f"stats?start_date={month_start}&aggregated_by=month")
        if data and len(data) > 0:
            stats = data[0].get("stats", [{}])[0].get("metrics", {})
            if status.sent_this_month is None:
                status.sent_this_month = stats.get("requests", 0)
            status.extra_info["delivered"]    = stats.get("delivered", 0)
            status.extra_info["bounces"]      = stats.get("bounces", 0)
            status.extra_info["spam_reports"] = stats.get("spam_reports", 0)

        # ── Step 7: Authenticated domains (requires whitelabel.read scope) ──
        if not scopes or "whitelabel.read" in scopes:
            data, err = self._request("whitelabel/domains")
            if data:
                for d in data:
                    status.domains.append({
                        "domain":    d.get("domain"),
                        "verified":  d.get("valid", False),
                        "subdomain": d.get("subdomain"),
                        "default":   d.get("default", False),
                    })

        # ── Step 8: Verified senders (requires senders.read scope) ──
        if not scopes or "senders.read" in scopes or "mail.send" in scopes:
            data, err = self._request("verified_senders")
            if data:
                for sender in data.get("results", []):
                    if sender.get("verified"):
                        status.verified_emails.append(sender.get("from_email"))

        # ── Set final account status ──
        if "🚫" in status.extra_info.get("can_send_mail", ""):
            status.account_status = "🚫 No Send Permission"
        elif status.errors:
            status.account_status = "Check Errors"
        else:
            status.account_status = "Active"

        return status


class MailgunProvider(EmailProvider):
    """Mailgun email service provider."""
    
    def __init__(self, api_key: str, domain: Optional[str] = None):
        self.api_key = api_key
        self.domain = domain
        # Detect EU vs US based on key or let user specify
        self.base_url = "https://api.mailgun.net/v3"
    
    @property
    def name(self) -> str:
        return "Mailgun"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        # Mailgun keys are typically 32+ hex chars or start with "key-"
        return key.startswith("key-") or (len(key) >= 32 and re.match(r'^[a-f0-9-]+$', key))
    
    def _request(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        return _http_get_basic(f"{self.base_url}/{endpoint}", "api", self.api_key)
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)
        
        # Get domains
        data, err = self._request("domains")
        if data:
            for d in data.get("items", []):
                domain_info = {
                    "domain": d.get("name"),
                    "verified": d.get("state") == "active",
                    "state": d.get("state"),
                    "type": d.get("type"),
                    "spam_action": d.get("spam_action"),
                }
                status.domains.append(domain_info)
                
                # Get domain stats if this is the specified domain or first one
                if self.domain is None:
                    self.domain = d.get("name")
        elif err:
            status.errors.append(f"Domains: {err}")
        
        # Get account info
        data, err = self._request("accounts")
        if err and "404" not in err:
            # Try alternative endpoint
            data, err = self._request("account")
        
        # Get sending limits from domain
        if self.domain:
            data, err = self._request(f"domains/{self.domain}/limits")
            if data:
                status.daily_limit = data.get("daily", {}).get("limit")
                status.sent_today = data.get("daily", {}).get("count")
                if status.daily_limit and status.sent_today is not None:
                    status.remaining_today = status.daily_limit - status.sent_today
                status.monthly_limit = data.get("monthly", {}).get("limit")
                status.sent_this_month = data.get("monthly", {}).get("count")
            
            # Get stats
            data, err = self._request(f"{self.domain}/stats/total")
            if data:
                stats = data.get("stats", [{}])
                if stats:
                    s = stats[0]
                    status.extra_info["delivered"] = s.get("delivered", {}).get("total", 0)
                    status.extra_info["bounced"] = s.get("failed", {}).get("permanent", {}).get("total", 0)
        
        status.account_status = "Active" if status.domains else "No domains"
        return status


class PostmarkProvider(EmailProvider):
    """Postmark email service provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.postmarkapp.com"
    
    @property
    def name(self) -> str:
        return "Postmark"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        # Postmark server tokens are UUIDs or 36-char strings
        return bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', key.lower()))
    
    def _request(self, endpoint: str, account_token: bool = False) -> Tuple[Optional[Dict], Optional[str]]:
        header_key = "X-Postmark-Account-Token" if account_token else "X-Postmark-Server-Token"
        return _http_get(
            f"{self.base_url}/{endpoint}",
            {header_key: self.api_key, "Accept": "application/json"},
        )
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)
        
        # Get server info
        data, err = self._request("server")
        if data:
            status.extra_info["server_name"] = data.get("Name")
            status.extra_info["server_id"] = data.get("ID")
            status.extra_info["smtp_api_activated"] = data.get("SmtpApiActivated")
            status.extra_info["delivery_type"] = data.get("DeliveryType")
        elif err:
            status.errors.append(f"Server: {err}")
        
        # Get sender signatures (verified emails/domains)
        data, err = self._request("senders")
        if data:
            for sender in data.get("SenderSignatures", []):
                if sender.get("Confirmed"):
                    email = sender.get("EmailAddress")
                    domain = sender.get("Domain")
                    if email:
                        status.verified_emails.append(email)
                    if domain and not any(d["domain"] == domain for d in status.domains):
                        status.domains.append({
                            "domain": domain,
                            "verified": sender.get("DKIMVerified", False),
                            "dkim_verified": sender.get("DKIMVerified", False),
                            "spf_verified": sender.get("SPFVerified", False),
                        })
        elif err:
            status.errors.append(f"Senders: {err}")
        
        # Get domains
        data, err = self._request("domains")
        if data:
            for d in data.get("Domains", []):
                if not any(dom["domain"] == d.get("Name") for dom in status.domains):
                    status.domains.append({
                        "domain": d.get("Name"),
                        "verified": d.get("DKIMVerified", False),
                        "dkim_verified": d.get("DKIMVerified", False),
                        "return_path_verified": d.get("ReturnPathDomainVerified", False),
                    })
        
        # Get outbound stats
        data, err = self._request("stats/outbound")
        if data:
            status.sent_this_month = data.get("Sent", 0)
            status.extra_info["bounced"] = data.get("Bounced", 0)
            status.extra_info["spam_complaints"] = data.get("SpamComplaints", 0)
            status.extra_info["bounce_rate"] = data.get("BounceRate", 0)
        
        status.account_status = "Active"
        return status


class MailjetProvider(EmailProvider):
    """Mailjet email service provider."""
    
    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://api.mailjet.com/v3/REST"
    
    @property
    def name(self) -> str:
        return "Mailjet"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        # Mailjet keys are 32-char alphanumeric
        return bool(re.match(r'^[a-f0-9]{32}$', key.lower())) and secret is not None
    
    def _request(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        return _http_get_basic(f"{self.base_url}/{endpoint}", self.api_key, self.api_secret)
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)
        
        # Get user info
        data, err = self._request("user")
        if data:
            user = data.get("Data", [{}])[0]
            status.extra_info["email"] = user.get("Email")
            status.extra_info["username"] = user.get("Username")
            status.extra_info["created"] = user.get("CreatedAt")
        elif err:
            status.errors.append(f"User: {err}")
        
        # Get API key info
        data, err = self._request("apikey")
        if data:
            for key in data.get("Data", []):
                if key.get("APIKey") == self.api_key:
                    status.extra_info["key_name"] = key.get("Name")
                    status.account_status = "Active" if key.get("IsActive") else "Inactive"
        
        # Get sender addresses
        data, err = self._request("sender")
        if data:
            for sender in data.get("Data", []):
                if sender.get("Status") == "Active":
                    status.verified_emails.append(sender.get("Email"))
        elif err:
            status.errors.append(f"Senders: {err}")
        
        # Get DNS records (domains)
        data, err = self._request("dns")
        if data:
            for d in data.get("Data", []):
                status.domains.append({
                    "domain": d.get("Domain"),
                    "verified": d.get("IsCheckInProgress") == False and d.get("LastCheckAt") is not None,
                    "spf_status": d.get("SPFStatus"),
                    "dkim_status": d.get("DKIMStatus"),
                })
        
        # Get statistics
        data, err = self._request("statcounters?CounterSource=APIKey&CounterTiming=Message&CounterResolution=Lifetime")
        if data:
            for stat in data.get("Data", []):
                status.extra_info["total_sent"] = stat.get("MessageSentCount", 0)
                status.extra_info["delivered"] = stat.get("MessageDeliveredCount", 0)
                status.extra_info["bounced"] = stat.get("MessageHardBouncedCount", 0) + stat.get("MessageSoftBouncedCount", 0)
        
        return status


class BrevoProvider(EmailProvider):
    """Brevo (formerly Sendinblue) email service provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.brevo.com/v3"
    
    @property
    def name(self) -> str:
        return "Brevo"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        return key.startswith("xkeysib-")
    
    def _request(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        return _http_get(
            f"{self.base_url}/{endpoint}",
            {"api-key": self.api_key, "Accept": "application/json"},
        )
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)

        # Get account info — Brevo /account returns plan details
        data, err = self._request("account")
        if data:
            status.extra_info["email"]   = data.get("email")
            status.extra_info["company"] = data.get("companyName")
            plan_info = data.get("plan", [{}])
            if plan_info:
                plan = plan_info[0] if isinstance(plan_info, list) else plan_info
                status.plan = plan.get("type", "Unknown")
                # Free accounts: credits=0, limit comes from emailsPerMonth or similar
                # Paid accounts: credits = monthly allowance
                credits = plan.get("credits") or 0
                emails_per_month = plan.get("emailsPerMonth") or plan.get("maxCredits") or 0
                limit = emails_per_month if not credits else credits
                if limit:
                    status.monthly_limit = limit
                # Also check top-level plan fields Brevo sometimes returns
                if not status.monthly_limit:
                    status.monthly_limit = (
                        data.get("plan", {}).get("emailsPerMonth") if isinstance(data.get("plan"), dict)
                        else None
                    )
        elif err:
            status.errors.append(f"Account: {err}")

        # Get remaining quota from /account directly
        data2, _ = self._request("account")
        if data2:
            remaining = data2.get("plan", [{}])
            if isinstance(remaining, list) and remaining:
                r = remaining[0]
                used   = r.get("creditsUsed") or 0
                limit2 = r.get("credits") or r.get("emailsPerMonth") or 0
                if limit2:
                    status.monthly_limit   = limit2
                    status.sent_this_month = used
                    status.remaining_this_month = max(0, limit2 - used)

        # Get senders
        data, err = self._request("senders")
        if data:
            for sender in data.get("senders", []):
                if sender.get("active"):
                    status.verified_emails.append(sender.get("email"))
        elif err:
            status.errors.append(f"Senders: {err}")

        # Get domains
        data, err = self._request("senders/domains")
        if data:
            for d in data.get("domains", []):
                status.domains.append({
                    "domain":       d.get("domain_name"),
                    "verified":     d.get("authenticated", False),
                    "dkim_verified":d.get("dkim_record", False),
                    "spf_verified": d.get("spf_record", False),
                })

        # Get today's stats
        today = datetime.utcnow().strftime("%Y-%m-%d")
        data, err = self._request(f"smtp/statistics/aggregatedReport?startDate={today}&endDate={today}")
        if data:
            status.sent_today = data.get("requests", 0)
            status.extra_info["delivered_today"] = data.get("delivered", 0)
            status.extra_info["bounces_today"]   = data.get("hardBounces", 0) + data.get("softBounces", 0)

        # Get monthly stats for sent_this_month if not already set
        if status.sent_this_month is None:
            month_start = datetime.utcnow().replace(day=1).strftime("%Y-%m-%d")
            data, err = self._request(f"smtp/statistics/aggregatedReport?startDate={month_start}&endDate={today}")
            if data:
                status.sent_this_month = data.get("requests", 0)
                if status.monthly_limit and status.sent_this_month is not None:
                    status.remaining_this_month = max(0, status.monthly_limit - status.sent_this_month)

        status.account_status = "Active"
        return status


class SparkPostProvider(EmailProvider):
    """SparkPost email service provider."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.sparkpost.com/api/v1"
    
    @property
    def name(self) -> str:
        return "SparkPost"
    
    @staticmethod
    def detect(key: str, secret: Optional[str] = None) -> bool:
        # SparkPost keys are 40-char hex strings
        return bool(re.match(r'^[a-f0-9]{40}$', key.lower()))
    
    def _request(self, endpoint: str) -> Tuple[Optional[Dict], Optional[str]]:
        return _http_get(
            f"{self.base_url}/{endpoint}",
            {"Authorization": self.api_key, "Accept": "application/json"},
        )
    
    def fetch_status(self) -> EmailServiceStatus:
        status = EmailServiceStatus(provider=self.name)
        
        # Get account info
        data, err = self._request("account")
        if data:
            results = data.get("results", {})
            status.extra_info["company"] = results.get("company_name")
            status.extra_info["country"] = results.get("country_code")
            usage = results.get("usage", {})
            status.sent_this_month = usage.get("used", 0)
            status.monthly_limit = usage.get("limit", 0)
            if status.monthly_limit:
                status.remaining_this_month = status.monthly_limit - (status.sent_this_month or 0)
        elif err:
            status.errors.append(f"Account: {err}")
        
        # Get sending domains
        data, err = self._request("sending-domains")
        if data:
            for d in data.get("results", []):
                status_info = d.get("status", {})
                status.domains.append({
                    "domain": d.get("domain"),
                    "verified": status_info.get("ownership_verified", False),
                    "dkim_status": status_info.get("dkim_status"),
                    "spf_status": status_info.get("spf_status"),
                    "compliance_status": status_info.get("compliance_status"),
                })
        elif err:
            status.errors.append(f"Domains: {err}")
        
        status.account_status = "Active" if not status.errors else "Check Errors"
        return status


# Provider registry for auto-detection
PROVIDERS = [
    AWSSESProvider,
    SendGridProvider,
    BrevoProvider,
    PostmarkProvider,
    SparkPostProvider,
    MailgunProvider,
    MailjetProvider,  # Must come after others since it requires secret
]


def detect_provider(key: str, secret: Optional[str] = None) -> Optional[type]:
    """Auto-detect the email provider from the API key format."""
    for provider_class in PROVIDERS:
        if provider_class.detect(key, secret):
            return provider_class
    return None


def create_provider(key: str, secret: Optional[str] = None, region: Optional[str] = None, domain: Optional[str] = None) -> Optional[EmailProvider]:
    """Create a provider instance based on the key."""
    provider_class = detect_provider(key, secret)
    if provider_class is None:
        return None
    
    if provider_class == AWSSESProvider:
        if not secret:
            return None
        return AWSSESProvider(key, secret, region or "us-east-1")
    elif provider_class == MailjetProvider:
        if not secret:
            return None
        return MailjetProvider(key, secret)
    elif provider_class == MailgunProvider:
        return MailgunProvider(key, domain)
    else:
        return provider_class(key)


def format_number(n: Optional[float]) -> str:
    """Format a number for display."""
    if n is None:
        return "N/A"
    if n == float("inf"):
        return "Unlimited"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return f"{int(n)}"


def format_report(status: EmailServiceStatus) -> str:
    """Format the status as a human-readable report."""
    lines = []
    lines.append("=" * 60)
    lines.append(f"  {status.provider} Account Status")
    lines.append("=" * 60)
    lines.append("")
    
    # Account status
    lines.append(f"Account Status: {status.account_status}")
    if status.plan != "Unknown":
        lines.append(f"Plan: {status.plan}")
    lines.append("")
    
    # Sending limits and usage
    lines.append("SENDING LIMITS & USAGE")
    lines.append("-" * 40)
    if status.daily_limit is not None or status.sent_today is not None or status.sent_last_24h is not None:
        if status.daily_limit:
            lines.append(f"  Daily Limit:      {format_number(status.daily_limit)}")
        if status.sent_today is not None:
            lines.append(f"  Sent Today:       {format_number(status.sent_today)}")
        if status.sent_last_24h is not None:
            lines.append(f"  Sent (24h):       {format_number(status.sent_last_24h)}")
        if status.remaining_today is not None:
            lines.append(f"  Remaining Today:  {format_number(status.remaining_today)}")
    
    if status.monthly_limit is not None or status.sent_this_month is not None:
        if status.monthly_limit:
            lines.append(f"  Monthly Limit:    {format_number(status.monthly_limit)}")
        if status.sent_this_month is not None:
            lines.append(f"  Sent This Month:  {format_number(status.sent_this_month)}")
        if status.remaining_this_month is not None:
            lines.append(f"  Remaining Month:  {format_number(status.remaining_this_month)}")
    
    if status.rate_limit:
        lines.append(f"  Rate Limit:       {format_number(status.rate_limit)}/sec")
    lines.append("")
    
    # Domains
    lines.append("VERIFIED DOMAINS")
    lines.append("-" * 40)
    if status.domains:
        for d in status.domains:
            verified = "✓" if d.get("verified") else "✗"
            dkim = ""
            if "dkim_enabled" in d:
                dkim = " | DKIM: ✓" if d.get("dkim_enabled") else " | DKIM: ✗"
            elif "dkim_status" in d:
                dkim = f" | DKIM: {d.get('dkim_status')}"
            elif "dkim_verified" in d:
                dkim = " | DKIM: ✓" if d.get("dkim_verified") else " | DKIM: ✗"
            lines.append(f"  [{verified}] {d.get('domain')}{dkim}")
    else:
        lines.append("  No domains configured")
    lines.append("")
    
    # Verified emails
    lines.append("VERIFIED EMAILS")
    lines.append("-" * 40)
    if status.verified_emails:
        for email in status.verified_emails[:10]:  # Limit display
            lines.append(f"  • {email}")
        if len(status.verified_emails) > 10:
            lines.append(f"  ... and {len(status.verified_emails) - 10} more")
    else:
        lines.append("  No verified emails")
    lines.append("")
    
    # Extra info
    if status.extra_info:
        lines.append("ADDITIONAL INFO")
        lines.append("-" * 40)
        for key, value in status.extra_info.items():
            if value is not None and value != "":
                display_key = key.replace("_", " ").title()
                lines.append(f"  {display_key}: {value}")
        lines.append("")
    
    # Errors
    if status.errors:
        lines.append("ERRORS")
        lines.append("-" * 40)
        for err in status.errors:
            lines.append(f"  ⚠ {err}")
        lines.append("")
    
    lines.append("=" * 60)
    return "\n".join(lines)


def interactive_mode():
    """Run in interactive mode, prompting for credentials."""
    print("\n" + "=" * 60)
    print("  Email Service Account Checker")
    print("=" * 60)
    print("\nSupported providers: AWS SES, SendGrid, Mailgun, Postmark,")
    print("                     Mailjet, Brevo, SparkPost\n")
    
    key = input("Enter your API key: ").strip()
    if not key:
        print("Error: API key is required")
        return
    
    # Try to detect provider
    provider_class = detect_provider(key, None)
    
    secret = None
    region = None
    domain = None
    
    # If we couldn't detect or it needs a secret, ask for it
    if provider_class is None or provider_class in (AWSSESProvider, MailjetProvider):
        secret = getpass("Enter secret key (or press Enter to skip): ").strip() or None
        
        # Try again with secret
        if secret:
            provider_class = detect_provider(key, secret)
    
    if provider_class is None:
        print("\nCould not auto-detect provider. Please choose:")
        print("  1. AWS SES")
        print("  2. SendGrid")
        print("  3. Mailgun")
        print("  4. Postmark")
        print("  5. Mailjet")
        print("  6. Brevo")
        print("  7. SparkPost")
        choice = input("\nEnter number (1-7): ").strip()
        providers_map = {
            "1": AWSSESProvider,
            "2": SendGridProvider,
            "3": MailgunProvider,
            "4": PostmarkProvider,
            "5": MailjetProvider,
            "6": BrevoProvider,
            "7": SparkPostProvider,
        }
        provider_class = providers_map.get(choice)
        if not provider_class:
            print("Invalid choice")
            return
    
    print(f"\nDetected provider: {provider_class.__name__.replace('Provider', '')}")
    
    # Get additional info if needed
    if provider_class == AWSSESProvider:
        if not secret:
            secret = getpass("AWS Secret Key: ").strip()
        region = input("AWS Region (default: us-east-1): ").strip() or "us-east-1"
    elif provider_class == MailjetProvider and not secret:
        secret = getpass("Mailjet Secret Key: ").strip()
    elif provider_class == MailgunProvider:
        domain = input("Mailgun Domain (optional): ").strip() or None
    
    # Create provider and fetch status
    provider = create_provider(key, secret, region, domain)
    if not provider:
        print("Error: Could not create provider instance")
        return
    
    print("\nFetching account status...")
    status = provider.fetch_status()
    print(format_report(status))


def main():
    parser = argparse.ArgumentParser(
        description="Check email service account status (AWS SES, SendGrid, Mailgun, etc.)"
    )
    parser.add_argument("--key", "-k", help="API key")
    parser.add_argument("--secret", "-s", help="Secret key (for AWS SES and Mailjet)")
    parser.add_argument("--region", "-r", help="AWS region (default: us-east-1)")
    parser.add_argument("--domain", "-d", help="Domain (for Mailgun)")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.key:
        interactive_mode()
        return
    
    provider = create_provider(args.key, args.secret, args.region, args.domain)
    
    if not provider:
        provider_class = detect_provider(args.key, args.secret)
        if provider_class in (AWSSESProvider, MailjetProvider):
            print(f"Error: {provider_class.__name__.replace('Provider', '')} requires --secret")
        else:
            print("Error: Could not detect provider from key format")
            print("Supported: AWS SES, SendGrid, Mailgun, Postmark, Mailjet, Brevo, SparkPost")
        sys.exit(1)
    
    status = provider.fetch_status()
    
    if args.json:
        output = {
            "provider": status.provider,
            "account_status": status.account_status,
            "plan": status.plan,
            "limits": {
                "daily": status.daily_limit,
                "monthly": status.monthly_limit,
                "rate_per_second": status.rate_limit,
            },
            "usage": {
                "sent_today": status.sent_today,
                "sent_last_24h": status.sent_last_24h,
                "sent_this_month": status.sent_this_month,
                "remaining_today": status.remaining_today,
                "remaining_this_month": status.remaining_this_month,
            },
            "domains": status.domains,
            "verified_emails": status.verified_emails,
            "extra_info": status.extra_info,
            "errors": status.errors,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        print(format_report(status))


if __name__ == "__main__":
    main()


# ═══════════════════════════════════════════════════════════════
# DOMAIN MANAGEMENT — add domain + get DNS records, verify status
# Supported: SendGrid, Mailgun, Brevo
# ═══════════════════════════════════════════════════════════════

def _http_post(url: str, headers: dict, body: dict) -> Tuple[Optional[Dict], Optional[str]]:
    """POST JSON request using stdlib urllib."""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
    raw = json.dumps(body).encode("utf-8")
    try:
        req  = Request(url, data=raw, headers={**headers, "Content-Type":"application/json"}, method="POST")
        resp = urlopen(req, timeout=30)
        txt  = resp.read().decode("utf-8", errors="replace")
        return (json.loads(txt) if txt.strip() else {}), None
    except HTTPError as e:
        body_s = ""
        try: body_s = e.read().decode("utf-8", errors="replace")[:400]
        except Exception: pass
        return None, f"HTTP {e.code}: {body_s}"
    except URLError as e:
        return None, f"Network error: {e.reason}"
    except Exception as e:
        return None, str(e)


def add_domain(key: str, domain: str, secret: str = None, region: str = "us-east-1") -> Dict:
    """
    Add a domain to an ESP account and return DNS records needed for verification.
    Returns: {provider, domain, dns_records: [{type, host, value, priority?}], error?}
    """
    key = (key or "").strip()
    domain = (domain or "").strip().lower()
    if not key or not domain:
        return {"error": "API key and domain are required"}

    # ── SendGrid ──────────────────────────────────────────────
    if key.startswith("SG."):
        data, err = _http_post(
            "https://api.sendgrid.com/v3/whitelabel/domains",
            {"Authorization": f"Bearer {key}"},
            {"domain": domain, "automatic_security": True, "custom_spf": False}
        )
        if err:
            return {"provider": "SendGrid", "domain": domain, "error": err}
        # Parse DNS records from response
        dns = data.get("dns", {})
        records = []
        for key_name, rec in dns.items():
            if isinstance(rec, dict):
                records.append({
                    "type":  rec.get("type","CNAME").upper(),
                    "host":  rec.get("host",""),
                    "value": rec.get("data",""),
                    "label": key_name,
                })
        return {
            "provider": "SendGrid",
            "domain":   domain,
            "domain_id": data.get("id"),
            "dns_records": records,
            "note": "Add these DNS records to your domain, then click Verify.",
        }

    # ── Mailgun ───────────────────────────────────────────────
    if key.startswith("key-") or (len(key) >= 32 and re.match(r'^[a-f0-9-]+$', key)):
        cred = base64.b64encode(f"api:{key}".encode()).decode()
        data, err = _http_post(
            "https://api.mailgun.net/v3/domains",
            {"Authorization": f"Basic {cred}"},
            {"name": domain, "spam_action": "disabled", "wildcard": False}
        )
        if err and "already exists" not in (err or "").lower():
            return {"provider": "Mailgun", "domain": domain, "error": err}
        # Fetch domain info for DNS records
        d2, e2 = _http_get(f"https://api.mailgun.net/v3/domains/{domain}",
                            {"Authorization": f"Basic {cred}", "Accept": "application/json"})
        if e2:
            return {"provider": "Mailgun", "domain": domain, "error": e2}
        records = []
        for rec in (d2 or {}).get("sending_dns_records", []) + (d2 or {}).get("receiving_dns_records", []):
            records.append({
                "type":  rec.get("record_type","").upper(),
                "host":  rec.get("name",""),
                "value": rec.get("value",""),
                "valid": rec.get("valid","unknown"),
            })
        return {
            "provider": "Mailgun",
            "domain":   domain,
            "dns_records": records,
            "note": "Add these DNS records, then click Verify.",
        }

    # ── Brevo ─────────────────────────────────────────────────
    if key.startswith("xkeysib-") or key.startswith("xsmtpsib-"):
        data, err = _http_post(
            "https://api.brevo.com/v3/senders/domains",
            {"api-key": key},
            {"name": domain}
        )
        if err and "already" not in (err or "").lower():
            return {"provider": "Brevo", "domain": domain, "error": err}
        # Fetch domain DNS records
        d2, e2 = _http_get(f"https://api.brevo.com/v3/senders/domains/{domain}",
                            {"api-key": key, "Accept": "application/json"})
        if e2:
            return {"provider": "Brevo", "domain": domain, "error": e2}
        records = []
        d2 = d2 or {}
        # Brevo returns dkim_record, spf_record etc.
        if d2.get("dkim_record"):
            records.append({"type":"TXT","host":d2.get("dkim_selector","brevo")+"._domainkey."+domain,
                            "value": d2["dkim_record"], "label":"DKIM"})
        if d2.get("spf_record"):
            records.append({"type":"TXT","host":domain,"value":d2["spf_record"],"label":"SPF"})
        if d2.get("dmarc_record"):
            records.append({"type":"TXT","host":"_dmarc."+domain,"value":d2["dmarc_record"],"label":"DMARC"})
        return {
            "provider": "Brevo",
            "domain":   domain,
            "dns_records": records,
            "note": "Add these DNS records, then click Verify.",
        }

    return {"error": "Domain management not supported for this provider via API key format. "
                     "Supported: SendGrid (SG.*), Mailgun (key-*), Brevo (xkeysib-*)"}


def verify_domain(key: str, domain: str, domain_id: str = None,
                  secret: str = None, region: str = "us-east-1") -> Dict:
    """
    Trigger domain verification check and return current DNS status.
    """
    key = (key or "").strip()
    domain = (domain or "").strip().lower()

    # ── SendGrid ──────────────────────────────────────────────
    if key.startswith("SG."):
        hdrs = {"Authorization": f"Bearer {key}"}
        if domain_id:
            data, err = _http_post(
                f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/validate",
                hdrs, {}
            )
        else:
            # Find domain ID first
            d2, e2 = _http_get("https://api.sendgrid.com/v3/whitelabel/domains", hdrs)
            if e2: return {"provider":"SendGrid","domain":domain,"error":e2}
            match = next((d for d in (d2 or []) if d.get("domain") == domain), None)
            if not match: return {"provider":"SendGrid","domain":domain,"error":"Domain not found in account. Add it first."}
            domain_id = match["id"]
            data, err = _http_post(
                f"https://api.sendgrid.com/v3/whitelabel/domains/{domain_id}/validate",
                hdrs, {}
            )
        if err: return {"provider":"SendGrid","domain":domain,"error":err}
        valid = (data or {}).get("valid", False)
        records = []
        for k, v in ((data or {}).get("validation_results", {}) or {}).items():
            records.append({
                "label": k,
                "valid": v.get("valid", False),
                "reason": v.get("reason",""),
            })
        return {
            "provider": "SendGrid",
            "domain":   domain,
            "verified": valid,
            "records":  records,
            "message":  "✅ Domain verified!" if valid else "❌ Not verified — check DNS records are propagated (can take up to 48h)",
        }

    # ── Mailgun ───────────────────────────────────────────────
    if key.startswith("key-") or (len(key) >= 32 and re.match(r'^[a-f0-9-]+$', key)):
        cred = base64.b64encode(f"api:{key}".encode()).decode()
        hdrs = {"Authorization": f"Basic {cred}", "Accept": "application/json"}
        data, err = _http_get(f"https://api.mailgun.net/v3/domains/{domain}", hdrs)
        if err: return {"provider":"Mailgun","domain":domain,"error":err}
        data = data or {}
        sending = data.get("sending_dns_records", [])
        all_valid = all(r.get("valid") == "valid" for r in sending) if sending else False
        return {
            "provider": "Mailgun",
            "domain":   domain,
            "verified": all_valid,
            "records":  [{"label":r.get("record_type","")+" "+r.get("name",""),
                          "valid":r.get("valid")=="valid","reason":r.get("value","")} for r in sending],
            "message":  "✅ Domain verified!" if all_valid else "❌ Some DNS records not yet valid",
        }

    # ── Brevo ─────────────────────────────────────────────────
    if key.startswith("xkeysib-") or key.startswith("xsmtpsib-"):
        data, err = _http_get(
            f"https://api.brevo.com/v3/senders/domains/{domain}",
            {"api-key": key, "Accept": "application/json"}
        )
        if err: return {"provider":"Brevo","domain":domain,"error":err}
        data = data or {}
        verified = data.get("authenticated", False)
        return {
            "provider": "Brevo",
            "domain":   domain,
            "verified": verified,
            "records":  [
                {"label":"DKIM","valid":bool(data.get("dkim_record")),"reason":""},
                {"label":"SPF","valid":bool(data.get("spf_record")),"reason":""},
            ],
            "message": "✅ Domain verified!" if verified else "❌ Not verified — check DNS records",
        }

    return {"error": "Verification not supported for this provider"}


# Billing portal URLs — we can't buy credits via API but can link to the right page
BILLING_URLS = {
    "sendgrid":  "https://app.sendgrid.com/settings/billing",
    "mailgun":   "https://app.mailgun.com/app/billing/overview",
    "brevo":     "https://app.brevo.com/account/billing",
    "postmark":  "https://account.postmarkapp.com/billing",
    "sparkpost": "https://app.sparkpost.com/account/billing",
    "ses":       "https://console.aws.amazon.com/ses/home",
    "ses-api":   "https://console.aws.amazon.com/ses/home",
    "mailjet":   "https://app.mailjet.com/account/billing-and-offers",
    "resend":    "https://resend.com/settings/billing",
}
