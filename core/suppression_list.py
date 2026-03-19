"""
core/suppression_list.py — SynthTel Global Suppression List
=============================================================
Thread-safe SQLite-backed suppression list.
Emails on this list are automatically skipped across ALL campaigns.

Routes expected in synthtel_server.py:
    GET    /api/suppression                → list all
    POST   /api/suppression               → add {emails:[], reason:""}
    DELETE /api/suppression/<email>       → remove one

Seed account routes (inbox placement testing):
    GET    /api/seed-accounts             → list all
    POST   /api/seed-accounts             → add account
    DELETE /api/seed-accounts/<email>     → remove one

S3 Redirect Generator route:
    POST   /api/tools/s3-redirects        → create S3 buckets + optional CF workers

IP Blacklist Checker route:
    POST   /api/tools/ip-blacklist        → check IPs against DNSBLs

Inbox Placement Tester routes:
    POST   /api/tools/inbox-test          → dispatch test to seed accounts
    GET    /api/tools/inbox-test/<run_id> → poll results
"""

import os
import re
import time
import uuid
import sqlite3
import threading
import logging
import socket
import hashlib
from datetime import datetime, timezone
from contextlib import contextmanager

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────

_DB_PATH = os.environ.get("ST_DB_PATH", "synthtel.db")
_db_lock = threading.Lock()


@contextmanager
def _conn():
    """Yield a thread-safe SQLite connection."""
    with _db_lock:
        con = sqlite3.connect(_DB_PATH, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def init_db():
    """Create tables if they don't exist. Call once at server startup."""
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS suppression_list (
            email       TEXT PRIMARY KEY COLLATE NOCASE,
            reason      TEXT DEFAULT 'manual',
            added_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS seed_accounts (
            email       TEXT PRIMARY KEY COLLATE NOCASE,
            password    TEXT NOT NULL,
            imap_host   TEXT DEFAULT '',
            imap_port   INTEGER DEFAULT 993,
            provider    TEXT DEFAULT 'auto',
            status      TEXT DEFAULT 'unchecked',
            added_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS inbox_test_runs (
            run_id      TEXT PRIMARY KEY,
            subject     TEXT,
            html        TEXT,
            started_at  TEXT DEFAULT (datetime('now')),
            done        INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS inbox_test_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id      TEXT NOT NULL,
            account     TEXT NOT NULL,
            provider    TEXT DEFAULT '',
            folder      TEXT DEFAULT 'pending',
            latency_ms  INTEGER DEFAULT 0,
            error       TEXT DEFAULT '',
            checked_at  TEXT DEFAULT (datetime('now'))
        );
        """)
    log.info("[suppression] DB initialised at %s", _DB_PATH)


# ─────────────────────────────────────────────────────────────
# SUPPRESSION LIST
# ─────────────────────────────────────────────────────────────

def is_suppressed(email: str) -> bool:
    """Return True if email is on the global suppression list."""
    if not email:
        return False
    with _conn() as con:
        row = con.execute(
            "SELECT 1 FROM suppression_list WHERE email=? COLLATE NOCASE",
            (email.strip().lower(),)
        ).fetchone()
    return row is not None


def add_suppressed(emails, reason: str = "manual"):
    """Add one or more emails to the suppression list."""
    if isinstance(emails, str):
        emails = [emails]
    rows = [(e.strip().lower(), reason) for e in emails if e and "@" in e]
    if not rows:
        return 0
    with _conn() as con:
        con.executemany(
            "INSERT OR IGNORE INTO suppression_list (email, reason) VALUES (?, ?)",
            rows
        )
    log.info("[suppression] added %d email(s) reason=%s", len(rows), reason)
    return len(rows)


def remove_suppressed(email: str) -> bool:
    """Remove one email from the suppression list."""
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM suppression_list WHERE email=? COLLATE NOCASE",
            (email.strip().lower(),)
        )
    return cur.rowcount > 0


def list_suppressed(search: str = "") -> list:
    """Return all suppressed emails, optionally filtered by search string."""
    with _conn() as con:
        if search:
            rows = con.execute(
                "SELECT email, reason, added_at FROM suppression_list "
                "WHERE email LIKE ? ORDER BY added_at DESC",
                (f"%{search.lower()}%",)
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT email, reason, added_at FROM suppression_list "
                "ORDER BY added_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def filter_suppressed(emails: list) -> list:
    """Return only the emails NOT on the suppression list."""
    if not emails:
        return []
    lower = {e.strip().lower() for e in emails if e}
    with _conn() as con:
        placeholders = ",".join("?" * len(lower))
        suppressed = {
            row[0] for row in con.execute(
                f"SELECT email FROM suppression_list WHERE email IN ({placeholders}) COLLATE NOCASE",
                list(lower)
            ).fetchall()
        }
    return [e for e in emails if e.strip().lower() not in suppressed]


# ─────────────────────────────────────────────────────────────
# SEED ACCOUNTS
# ─────────────────────────────────────────────────────────────

# IMAP host map for known providers — same pattern as email_sorter
_IMAP_HOSTS = {
    "gmail":   ("imap.gmail.com",   993),
    "outlook": ("imap-mail.outlook.com", 993),
    "hotmail": ("imap-mail.outlook.com", 993),
    "yahoo":   ("imap.mail.yahoo.com", 993),
    "gmx":     ("imap.gmx.net",     993),
    "aol":     ("imap.aol.com",      993),
    "icloud":  ("imap.mail.me.com", 993),
    "zoho":    ("imap.zoho.com",     993),
    "fastmail":("imap.fastmail.com", 993),
    "yandex":  ("imap.yandex.com",  993),
    "mail_ru": ("imap.mail.ru",     993),
    "protonmail": ("127.0.0.1",     1143),  # requires Proton Bridge
}


def _resolve_imap(email: str, provider: str, custom_host: str = "", custom_port: int = 993):
    """Return (host, port) for the given account."""
    if provider == "custom" and custom_host:
        return custom_host, int(custom_port or 993)
    if provider == "auto":
        domain = email.split("@")[-1].lower() if "@" in email else ""
        for key, (host, port) in _IMAP_HOSTS.items():
            if key in domain:
                return host, port
        return domain, 993  # fallback: use domain directly
    return _IMAP_HOSTS.get(provider, ("", 993))


def add_seed_account(email: str, password: str, provider: str = "auto",
                     imap_host: str = "", imap_port: int = 993) -> dict:
    """Add a seed account for inbox placement testing."""
    host, port = _resolve_imap(email, provider, imap_host, imap_port)
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO seed_accounts "
            "(email, password, imap_host, imap_port, provider, status) "
            "VALUES (?, ?, ?, ?, ?, 'unchecked')",
            (email.strip().lower(), password, host, port, provider)
        )
    return {"ok": True, "email": email, "imap_host": host, "imap_port": port}


def remove_seed_account(email: str) -> bool:
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM seed_accounts WHERE email=? COLLATE NOCASE",
            (email.strip().lower(),)
        )
    return cur.rowcount > 0


def list_seed_accounts() -> list:
    with _conn() as con:
        rows = con.execute(
            "SELECT email, imap_host, imap_port, provider, status, added_at "
            "FROM seed_accounts ORDER BY added_at DESC"
        ).fetchall()
    # Never return passwords
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────
# INBOX PLACEMENT TESTER
# ─────────────────────────────────────────────────────────────

def start_inbox_test(subject: str, html: str) -> str:
    """
    Create a run record and dispatch background IMAP polling threads.
    Returns run_id.
    """
    run_id = str(uuid.uuid4())
    with _conn() as con:
        con.execute(
            "INSERT INTO inbox_test_runs (run_id, subject, html) VALUES (?, ?, ?)",
            (run_id, subject, html)
        )
        accounts = con.execute(
            "SELECT email, password, imap_host, imap_port, provider FROM seed_accounts"
        ).fetchall()

    if not accounts:
        with _conn() as con:
            con.execute("UPDATE inbox_test_runs SET done=1 WHERE run_id=?", (run_id,))
        return run_id

    # Insert pending rows for each account
    with _conn() as con:
        con.executemany(
            "INSERT INTO inbox_test_results (run_id, account, provider, folder) VALUES (?, ?, ?, 'pending')",
            [(run_id, dict(a)["email"], dict(a)["provider"]) for a in accounts]
        )

    # Dispatch background threads
    for acc in accounts:
        t = threading.Thread(
            target=_check_inbox,
            args=(run_id, dict(acc), subject),
            daemon=True
        )
        t.start()

    # Mark done after all threads should finish (max 3 min)
    def _mark_done():
        time.sleep(180)
        with _conn() as con:
            con.execute("UPDATE inbox_test_runs SET done=1 WHERE run_id=?", (run_id,))

    threading.Thread(target=_mark_done, daemon=True).start()
    return run_id


def _check_inbox(run_id: str, account: dict, subject: str):
    """
    IMAP thread: connects to the account, waits for the test email,
    reports which folder it landed in.
    """
    import imaplib
    email_addr = account["email"]
    password   = account["password"]
    imap_host  = account["imap_host"] or _resolve_imap(email_addr, account.get("provider","auto"))[0]
    imap_port  = int(account.get("imap_port") or 993)
    t_start    = time.time()

    # Unique marker to find our email — embed in subject
    marker     = hashlib.md5(f"{run_id}:{email_addr}".encode()).hexdigest()[:12]
    search_subj = f"{subject} [{marker}]"  # the test sender should include this

    folder     = "pending"
    error_msg  = ""

    try:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        mail.login(email_addr, password)

        # Wait up to 90s for the email to arrive, checking every 8s
        for _ in range(11):
            time.sleep(8)

            # Check inbox first
            for folder_name in _discover_folders(mail):
                try:
                    mail.select(folder_name, readonly=True)
                    # Search by subject (fallback — marker may not be in subject)
                    _, data = mail.search(None, f'SUBJECT "{marker}"')
                    if not data or not data[0]:
                        _, data = mail.search(None, 'UNSEEN')
                        # Check each unseen for our subject
                        if data and data[0]:
                            for num in data[0].split()[-10:]:  # last 10 unseen
                                _, msg_data = mail.fetch(num, "(BODY[HEADER.FIELDS (SUBJECT)])")
                                if msg_data and msg_data[0]:
                                    raw = msg_data[0][1].decode(errors="replace").lower()
                                    if marker.lower() in raw or (subject or "").lower()[:20] in raw:
                                        data = ([num],)
                                        break
                            else:
                                continue

                    if data and data[0]:
                        # Classify folder
                        fn_lower = folder_name.lower()
                        if any(x in fn_lower for x in ["spam","junk","spamverdacht","courrier ind"]):
                            folder = "spam"
                        elif any(x in fn_lower for x in ["trash","deleted","gel","papier"]):
                            folder = "trash"
                        else:
                            folder = "inbox"
                        break
                except Exception:
                    continue

            if folder != "pending":
                break

        mail.logout()

    except imaplib.IMAP4.error as e:
        error_msg = f"IMAP auth error: {str(e)[:100]}"
        folder = "error"
    except Exception as e:
        error_msg = str(e)[:120]
        folder = "error"

    latency_ms = int((time.time() - t_start) * 1000)

    with _conn() as con:
        con.execute(
            "UPDATE inbox_test_results SET folder=?, error=?, latency_ms=?, "
            "checked_at=datetime('now') WHERE run_id=? AND account=?",
            (folder, error_msg, latency_ms, run_id, email_addr)
        )

        # Mark run done if all results are resolved
        pending = con.execute(
            "SELECT COUNT(*) FROM inbox_test_results WHERE run_id=? AND folder='pending'",
            (run_id,)
        ).fetchone()[0]
        if pending == 0:
            con.execute("UPDATE inbox_test_runs SET done=1 WHERE run_id=?", (run_id,))

    log.info("[inbox_test] %s → %s (%s) %dms", email_addr, folder, run_id[:8], latency_ms)


def _discover_folders(mail) -> list:
    """
    Return ordered list of folder names to search: inbox-like first, then spam/junk.
    Uses RFC 6154 LIST attributes + common name matching.
    """
    try:
        _, folder_list = mail.list()
    except Exception:
        return ["INBOX"]

    names = []
    for item in (folder_list or []):
        if not item:
            continue
        raw = item.decode(errors="replace") if isinstance(item, bytes) else str(item)
        # Parse: (\\Attribute) "delimiter" "Name" or (\\Attribute) "/" Name
        parts = raw.split('"')
        if len(parts) >= 3:
            name = parts[-2] if parts[-2] != "/" else parts[-1].strip()
        else:
            name = raw.split()[-1].strip('"')
        if name:
            names.append((raw.lower(), name))

    # Order: inbox first, then spam/junk, skip Sent/Drafts/etc
    priority = []
    spam_folders = []
    trash_folders = []
    other = []

    for raw_lower, name in names:
        nl = name.lower()
        if "inbox" in nl or "eingang" in nl:
            priority.insert(0, name)
        elif any(x in nl for x in ["spam","junk","spamverdacht","courrier ind","bulk"]):
            spam_folders.append(name)
        elif any(x in nl for x in ["trash","deleted","gel","papier","corbeille"]):
            trash_folders.append(name)
        elif any(x in nl for x in ["sent","draft","outbox","gesendet","entw"]):
            pass  # skip
        else:
            other.append(name)

    if not priority:
        priority = ["INBOX"]

    return priority + other + spam_folders + trash_folders


def get_inbox_test_results(run_id: str) -> dict:
    """Return current results for a test run."""
    with _conn() as con:
        run = con.execute(
            "SELECT done FROM inbox_test_runs WHERE run_id=?", (run_id,)
        ).fetchone()
        if not run:
            return {"error": "Run not found"}
        results = con.execute(
            "SELECT account, provider, folder, latency_ms, error FROM inbox_test_results "
            "WHERE run_id=? ORDER BY checked_at",
            (run_id,)
        ).fetchall()
    return {
        "run_id":  run_id,
        "done":    bool(dict(run)["done"]),
        "results": [dict(r) for r in results],
    }


# ─────────────────────────────────────────────────────────────
# IP BLACKLIST CHECKER
# ─────────────────────────────────────────────────────────────

# Major DNSBL zones
_DNSBL_ZONES = [
    ("Spamhaus ZEN",    "zen.spamhaus.org"),
    ("SORBS",           "dnsbl.sorbs.net"),
    ("Barracuda",       "b.barracudacentral.org"),
    ("SpamCop",         "bl.spamcop.net"),
    ("PSBL",            "psbl.surriel.com"),
    ("Mailspike",       "bl.mailspike.net"),
    ("DroneBL",         "dnsbl.dronebl.org"),
    ("UCEPROTECT L1",   "dnsbl-1.uceprotect.net"),
    ("GBUdb",           "dnsbl.justspam.org"),
    ("NiX Spam",        "ix.dnsbl.manitu.net"),
    ("Barracuda Rep",   "bb.barracudacentral.org"),
    ("SpamRats",        "spam.spamrats.com"),
]


def check_ip_blacklists(ips: list) -> dict:
    """
    Check each IP against all DNSBL zones.
    Returns {results: [{ip, listed_count, checks: [{list, listed, reason}]}]}
    """
    results = []
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
        checks = []
        listed_count = 0
        # Reverse the IP for DNSBL lookup
        reversed_ip = ".".join(reversed(ip.split(".")))
        for list_name, zone in _DNSBL_ZONES:
            lookup = f"{reversed_ip}.{zone}"
            listed = False
            reason = ""
            try:
                socket.setdefaulttimeout(3)
                answer = socket.gethostbyname(lookup)
                listed = True
                # Decode return code where known
                last_octet = answer.split(".")[-1]
                if zone == "zen.spamhaus.org":
                    codes = {
                        "2": "SBL — Spamhaus Block List",
                        "3": "SBL CSS — Snowshoe spam",
                        "4": "XBL — Exploits Block List",
                        "5": "XBL — CBL",
                        "6": "XBL — CBL",
                        "7": "XBL — NJABL",
                        "10": "PBL — ISP maintained",
                        "11": "PBL — Spamhaus maintained",
                    }
                    reason = codes.get(last_octet, f"Listed ({answer})")
                else:
                    reason = f"Listed ({answer})"
                listed_count += 1
            except socket.timeout:
                reason = "Timeout"
            except socket.gaierror:
                pass  # NXDOMAIN = not listed
            except Exception as e:
                reason = str(e)[:40]
            checks.append({"list": list_name, "listed": listed, "reason": reason})

        results.append({
            "ip": ip,
            "listed_count": listed_count,
            "clean": listed_count == 0,
            "checks": checks,
        })

    return {"results": results}


# ─────────────────────────────────────────────────────────────
# S3 REDIRECT GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_s3_redirects(
    access_key: str,
    secret_key: str,
    region: str,
    dest_url: str,
    count: int = 5,
    cloudflare: dict = None,
) -> dict:
    """
    Create N S3 buckets configured as static websites that redirect to dest_url.
    If cloudflare dict is provided (apiKey, zoneId, domain), creates CF Workers
    for HTTPS wrapping.

    Returns {redirects: [{bucket, url, https, error}]}
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return {"error": "boto3 not installed. Run: pip install boto3 --break-system-packages"}

    import json as _json

    redirects = []
    count = max(1, min(int(count), 50))

    s3 = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )

    for i in range(count):
        # Generate unique bucket name — S3 bucket names must be globally unique
        suffix = hashlib.md5(f"{uuid.uuid4()}".encode()).hexdigest()[:12]
        bucket_name = f"st-redir-{suffix}"
        redirect_url = None
        https = False
        error = None

        try:
            # Create bucket
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={"LocationConstraint": region}
                )

            # Disable block public access
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            )

            # Enable static website hosting with redirect
            s3.put_bucket_website(
                Bucket=bucket_name,
                WebsiteConfiguration={
                    "RedirectAllRequestsTo": {
                        "HostName": dest_url.replace("https://","").replace("http://","").split("/")[0],
                        "Protocol": "https" if dest_url.startswith("https") else "http",
                    }
                }
            )

            # Allow public reads
            policy = _json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*"
                }]
            })
            s3.put_bucket_policy(Bucket=bucket_name, Policy=policy)

            # S3 website endpoint (HTTP)
            if region == "us-east-1":
                s3_url = f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com"
            else:
                s3_url = f"http://{bucket_name}.s3-website.{region}.amazonaws.com"

            redirect_url = s3_url
            https = False

            # ── CloudFlare HTTPS wrapping ──
            if cloudflare and cloudflare.get("apiKey") and cloudflare.get("zoneId") and cloudflare.get("domain"):
                cf_result = _create_cf_worker(
                    cloudflare["apiKey"],
                    cloudflare["zoneId"],
                    cloudflare["domain"],
                    bucket_name,
                    s3_url,
                )
                if cf_result.get("url"):
                    redirect_url = cf_result["url"]
                    https = True
                elif cf_result.get("error"):
                    log.warning("[s3_redir] CF worker failed: %s", cf_result["error"])

            log.info("[s3_redir] created bucket %s → %s", bucket_name, redirect_url)

        except ClientError as e:
            error = e.response["Error"].get("Message", str(e))[:120]
            log.warning("[s3_redir] bucket %s failed: %s", bucket_name, error)
        except Exception as e:
            error = str(e)[:120]
            log.warning("[s3_redir] bucket %s error: %s", bucket_name, error)

        redirects.append({
            "bucket": bucket_name,
            "url":    redirect_url,
            "https":  https,
            "error":  error,
        })

    return {"redirects": redirects}


def _create_cf_worker(api_key: str, zone_id: str, domain: str, bucket_name: str, s3_url: str) -> dict:
    """
    Create a CloudFlare Worker that proxies HTTPS traffic to the S3 redirect URL.
    Returns {"url": "https://rand.domain.com"} or {"error": "..."}
    """
    try:
        import urllib.request as _ur
        import urllib.error as _ue
        import json as _json

        subdomain = bucket_name  # e.g. st-redir-abc123def456
        worker_name = f"st-{bucket_name}"

        # Worker script — simply redirects to the S3 bucket URL
        worker_script = f"""
addEventListener('fetch', event => {{
  event.respondWith(Response.redirect('{s3_url}' + new URL(event.request.url).pathname, 301));
}});
"""
        headers = {
            "X-Auth-Key": api_key,
            "Content-Type": "application/javascript",
        }
        # Try to get the account ID from the zone
        zone_req = _ur.Request(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}",
            headers={"X-Auth-Key": api_key, "Content-Type": "application/json"}
        )
        zone_resp = _json.loads(_ur.urlopen(zone_req, timeout=10).read())
        account_id = zone_resp.get("result", {}).get("account", {}).get("id")
        if not account_id:
            return {"error": "Could not determine CF account ID"}

        # Deploy worker script
        worker_req = _ur.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}",
            data=worker_script.encode(),
            headers=headers,
            method="PUT",
        )
        _ur.urlopen(worker_req, timeout=15)

        # Create DNS CNAME for subdomain → workers.dev
        dns_payload = _json.dumps({
            "type": "CNAME",
            "name": subdomain,
            "content": f"{worker_name}.{account_id}.workers.dev",
            "proxied": True,
            "ttl": 1,
        }).encode()
        dns_req = _ur.Request(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
            data=dns_payload,
            headers={"X-Auth-Key": api_key, "Content-Type": "application/json"},
            method="POST",
        )
        _ur.urlopen(dns_req, timeout=10)

        # Add Worker route
        route_payload = _json.dumps({
            "pattern": f"{subdomain}.{domain}/*",
            "script": worker_name,
        }).encode()
        route_req = _ur.Request(
            f"https://api.cloudflare.com/client/v4/zones/{zone_id}/workers/routes",
            data=route_payload,
            headers={"X-Auth-Key": api_key, "Content-Type": "application/json"},
            method="POST",
        )
        _ur.urlopen(route_req, timeout=10)

        return {"url": f"https://{subdomain}.{domain}"}

    except Exception as e:
        return {"error": str(e)[:120]}


# ─────────────────────────────────────────────────────────────
# FLASK ROUTE REGISTRATION HELPER
# ─────────────────────────────────────────────────────────────

def register_routes(app, require_auth):
    """
    Register all suppression/seed/tools routes on a Flask app.
    Call this from synthtel_server.py after creating the Flask app:

        from core.suppression_list import register_routes, init_db
        init_db()
        register_routes(app, require_auth)

    require_auth is your existing JWT decorator.
    """
    from flask import request, jsonify

    # ── Suppression list ──

    @app.route("/api/suppression", methods=["GET"])
    @require_auth
    def suppression_list_get():
        search = request.args.get("q", "")
        return jsonify({"list": list_suppressed(search)})

    @app.route("/api/suppression", methods=["POST"])
    @require_auth
    def suppression_list_add():
        data   = request.get_json() or {}
        emails = data.get("emails", [])
        reason = data.get("reason", "manual")
        n      = add_suppressed(emails, reason)
        return jsonify({"added": n})

    @app.route("/api/suppression/<path:email>", methods=["DELETE"])
    @require_auth
    def suppression_list_delete(email):
        ok = remove_suppressed(email)
        return jsonify({"ok": ok})

    # ── Seed accounts ──

    @app.route("/api/seed-accounts", methods=["GET"])
    @require_auth
    def seed_accounts_get():
        return jsonify({"accounts": list_seed_accounts()})

    @app.route("/api/seed-accounts", methods=["POST"])
    @require_auth
    def seed_accounts_add():
        data = request.get_json() or {}
        result = add_seed_account(
            email      = data.get("email",""),
            password   = data.get("password",""),
            provider   = data.get("provider","auto"),
            imap_host  = data.get("imapHost",""),
            imap_port  = int(data.get("imapPort") or 993),
        )
        return jsonify(result)

    @app.route("/api/seed-accounts/<path:email>", methods=["DELETE"])
    @require_auth
    def seed_accounts_delete(email):
        ok = remove_seed_account(email)
        return jsonify({"ok": ok})

    # ── Inbox placement tester ──

    @app.route("/api/tools/inbox-test", methods=["POST"])
    @require_auth
    def inbox_test_start():
        data    = request.get_json() or {}
        subject = data.get("subject", "Inbox test")
        html    = data.get("html", "<p>Test</p>")
        run_id  = start_inbox_test(subject, html)
        return jsonify({"run_id": run_id})

    @app.route("/api/tools/inbox-test/<run_id>", methods=["GET"])
    @require_auth
    def inbox_test_poll(run_id):
        return jsonify(get_inbox_test_results(run_id))

    # ── IP blacklist checker ──

    @app.route("/api/tools/ip-blacklist", methods=["POST"])
    @require_auth
    def ip_blacklist_check():
        data = request.get_json() or {}
        ips  = data.get("ips", [])
        return jsonify(check_ip_blacklists(ips))

    # ── S3 redirect generator ──

    @app.route("/api/tools/s3-redirects", methods=["POST"])
    @require_auth
    def s3_redirects_generate():
        data = request.get_json() or {}
        result = generate_s3_redirects(
            access_key = data.get("accessKey",""),
            secret_key = data.get("secretKey",""),
            region     = data.get("region","us-east-1"),
            dest_url   = data.get("destUrl",""),
            count      = int(data.get("count") or 5),
            cloudflare = data.get("cloudflare"),
        )
        return jsonify(result)

    log.info("[suppression] routes registered")
