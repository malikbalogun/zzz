"""
SynthTel — Telegram Bot Integration
Handles: 2FA OTPs, login notifications, admin controls, support tickets
"""
import json, os, secrets, sqlite3, threading, time, logging
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import URLError, HTTPError

log = logging.getLogger("synthtel.telegram")

DB_PATH   = os.environ.get("SYNTHTEL_DB", "/opt/synthtel/synthtel.db")
db_lock   = threading.Lock()

TG_API    = "https://api.telegram.org/bot{token}/{method}"

# ── In-memory OTP store: {user_id: {code, expires, verified}} ──────────────
_otp_store  = {}
_otp_lock   = threading.Lock()

# ── In-memory link codes: {link_code: user_id} ─────────────────────────────
_link_codes  = {}
_link_lock   = threading.Lock()

# ── Polling thread ──────────────────────────────────────────────────────────
_poll_thread  = None
_poll_running = False
_last_update  = 0


# ═══════════════════════════════════════════════════════════════════════════
# DB HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def get_conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def get_bot_token() -> str:
    """Return the configured bot token or empty string."""
    with db_lock:
        c = get_conn()
        row = c.execute("SELECT value FROM tg_config WHERE key='bot_token'").fetchone()
        c.close()
    return row["value"] if row else ""


def get_config(key: str, default="") -> str:
    with db_lock:
        c = get_conn()
        row = c.execute("SELECT value FROM tg_config WHERE key=?", (key,)).fetchone()
        c.close()
    return row["value"] if row else default


def set_config(key: str, value: str):
    with db_lock:
        c = get_conn()
        c.execute("INSERT OR REPLACE INTO tg_config (key,value) VALUES (?,?)", (key, value))
        c.commit()
        c.close()


def get_user_tg(user_id: int) -> dict | None:
    with db_lock:
        c = get_conn()
        row = c.execute(
            "SELECT tg_chat_id, tg_username, tg_2fa_enabled FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
        c.close()
    if not row or not row["tg_chat_id"]:
        return None
    return dict(row)


def get_user_by_chat(chat_id: int) -> dict | None:
    with db_lock:
        c = get_conn()
        row = c.execute(
            "SELECT id, username, role, tg_2fa_enabled FROM users WHERE tg_chat_id=?",
            (chat_id,)
        ).fetchone()
        c.close()
    return dict(row) if row else None


# ═══════════════════════════════════════════════════════════════════════════
# TELEGRAM API
# ═══════════════════════════════════════════════════════════════════════════

def tg_call(method: str, payload: dict = None) -> dict:
    token = get_bot_token()
    if not token:
        return {"ok": False, "error": "No bot token configured"}
    url = TG_API.format(token=token, method=method)
    try:
        body = json.dumps(payload or {}).encode()
        req  = Request(url, data=body, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def send_message(chat_id: int, text: str, parse_mode="HTML", reply_markup=None) -> dict:
    payload = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return tg_call("sendMessage", payload)


def edit_message_text(chat_id: int, message_id: int, text: str, parse_mode="HTML") -> dict:
    """Edit an existing message (for live-updating campaign stats)."""
    return tg_call("editMessageText", {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": parse_mode,
    })


# ═══════════════════════════════════════════════════════════════════════════
# CAMPAIGN LIVE STATS
# ═══════════════════════════════════════════════════════════════════════════

def campaign_start_msg(user_id: int, name: str, method: str, total: int) -> int | None:
    """Send initial campaign message. Returns message_id for live editing."""
    if get_config("notify_campaigns", "1") != "1":
        return None
    tg = get_user_tg(user_id)
    if not tg:
        return None
    text = (
        f"🚀 <b>Campaign Started</b>\n\n"
        f"📋 <b>{_esc(name)}</b>\n"
        f"📨 Method: <b>{_esc(method)}</b>\n"
        f"📊 Total: <b>{total:,}</b>\n\n"
        f"⏳ Sending…"
    )
    result = send_message(int(tg["tg_chat_id"]), text)
    if result.get("ok"):
        return result["result"]["message_id"]
    return None


def campaign_update_msg(user_id: int, message_id: int, name: str,
                        sent: int, failed: int, total: int,
                        method: str, speed: float = 0,
                        proxy_dead: int = 0, paused: bool = False):
    """Edit campaign message with live stats."""
    if not message_id:
        return
    tg = get_user_tg(user_id)
    if not tg:
        return
    pct  = (sent + failed) / max(total, 1) * 100
    bar  = _progress_bar(pct)
    eta  = ""
    if speed > 0 and (total - sent - failed) > 0:
        remaining = total - sent - failed
        mins = remaining / speed / 60
        if mins >= 60:
            eta = f"⏱ ETA: ~{mins/60:.1f}h"
        else:
            eta = f"⏱ ETA: ~{mins:.0f}m"

    status = "⏸ <b>PAUSED</b>" if paused else "📤 <b>Sending…</b>"
    text = (
        f"📋 <b>{_esc(name)}</b>\n"
        f"{bar} {pct:.1f}%\n\n"
        f"{status}\n"
        f"✅ Sent: <b>{sent:,}</b>  ❌ Failed: <b>{failed:,}</b>  📊 Total: <b>{total:,}</b>\n"
        f"📨 Method: {_esc(method)}"
    )
    if speed > 0:
        text += f"  ⚡ {speed:.1f}/s"
    if proxy_dead > 0:
        text += f"\n🔴 Dead proxies: {proxy_dead}"
    if eta:
        text += f"\n{eta}"

    try:
        edit_message_text(int(tg["tg_chat_id"]), message_id, text)
    except Exception:
        pass


def campaign_done_msg(user_id: int, message_id: int, name: str,
                      sent: int, failed: int, total: int,
                      stopped: bool = False, duration_s: float = 0):
    """Final edit of campaign message with completion stats."""
    tg = get_user_tg(user_id)
    if not tg:
        return
    icon = "🛑" if stopped else "✅"
    label = "Stopped" if stopped else "Completed"
    bar  = _progress_bar((sent + failed) / max(total, 1) * 100)

    dur = ""
    if duration_s > 0:
        m, s = divmod(int(duration_s), 60)
        h, m = divmod(m, 60)
        dur = f"{h}h {m}m {s}s" if h else f"{m}m {s}s"

    bounce_pct = failed / max(sent + failed, 1) * 100
    bounce_warn = ""
    if bounce_pct > 15 and (sent + failed) > 20:
        bounce_warn = f"\n⚠️ <b>High bounce rate: {bounce_pct:.1f}%</b>"

    text = (
        f"{icon} <b>Campaign {label}</b>\n\n"
        f"📋 <b>{_esc(name)}</b>\n"
        f"{bar} 100%\n\n"
        f"✅ Sent: <b>{sent:,}</b>\n"
        f"❌ Failed: <b>{failed:,}</b>\n"
        f"📊 Total: <b>{total:,}</b>\n"
    )
    if dur:
        text += f"⏱ Duration: {dur}\n"
    if sent > 0 and duration_s > 0:
        text += f"⚡ Avg speed: {sent / duration_s:.1f}/s\n"
    text += bounce_warn

    if message_id:
        try:
            edit_message_text(int(tg["tg_chat_id"]), message_id, text)
            return
        except Exception:
            pass
    # Fallback: send as new message if edit fails
    send_message(int(tg["tg_chat_id"]), text)


def _progress_bar(pct: float) -> str:
    """Unicode progress bar."""
    filled = int(pct / 5)
    return "▓" * filled + "░" * (20 - filled)


def _esc(s: str) -> str:
    """Escape HTML for Telegram."""
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def get_me() -> dict:
    return tg_call("getMe")


# ═══════════════════════════════════════════════════════════════════════════
# OTP / 2FA
# ═══════════════════════════════════════════════════════════════════════════

def generate_otp(user_id: int) -> str | None:
    """Generate a 6-digit OTP and send it via Telegram. Returns code or None."""
    tg = get_user_tg(user_id)
    if not tg:
        return None
    code = str(secrets.randbelow(900000) + 100000)
    exp  = datetime.now() + timedelta(minutes=5)
    with _otp_lock:
        _otp_store[user_id] = {"code": code, "expires": exp, "verified": False}
    text = (
        f"🔐 <b>SynthTel Login Code</b>\n\n"
        f"Your one-time code: <code>{code}</code>\n\n"
        f"⏱ Valid for 5 minutes. Do not share this code."
    )
    result = send_message(int(tg["tg_chat_id"]), text)
    if result.get("ok"):
        return code
    return None


def verify_otp(user_id: int, code: str) -> bool:
    """Verify OTP. Returns True if valid, marks as used."""
    with _otp_lock:
        entry = _otp_store.get(user_id)
        if not entry:
            return False
        if entry["verified"]:
            return False
        if datetime.now() > entry["expires"]:
            del _otp_store[user_id]
            return False
        if entry["code"] != code.strip():
            return False
        entry["verified"] = True
        del _otp_store[user_id]
    return True


def is_2fa_required(user_id: int) -> bool:
    tg = get_user_tg(user_id)
    return bool(tg and tg.get("tg_2fa_enabled"))


# ═══════════════════════════════════════════════════════════════════════════
# LINK CODES (connecting Telegram to account)
# ═══════════════════════════════════════════════════════════════════════════

def create_link_code(user_id: int) -> str:
    code = secrets.token_hex(8).upper()
    exp  = datetime.now() + timedelta(minutes=15)
    with _link_lock:
        # Clear old codes for this user
        to_del = [k for k, v in _link_codes.items() if v["user_id"] == user_id]
        for k in to_del:
            del _link_codes[k]
        _link_codes[code] = {"user_id": user_id, "expires": exp}
    return code


def consume_link_code(code: str) -> int | None:
    """Return user_id if code is valid, else None."""
    with _link_lock:
        entry = _link_codes.get(code.upper())
        if not entry:
            return None
        if datetime.now() > entry["expires"]:
            del _link_codes[code.upper()]
            return None
        uid = entry["user_id"]
        del _link_codes[code.upper()]
    return uid


# ═══════════════════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════════════

def notify_login(user_id: int, ip: str, ua: str = ""):
    tg = get_user_tg(user_id)
    if not tg:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    text = (
        f"🔔 <b>New Login — SynthTel</b>\n\n"
        f"🌐 IP: <code>{ip}</code>\n"
        f"⏰ Time: {now}\n"
        f"{'🖥 Client: ' + ua[:60] if ua else ''}\n\n"
        f"If this wasn't you, change your password immediately."
    )
    send_message(int(tg["tg_chat_id"]), text)


def notify_user(user_id: int, text: str):
    tg = get_user_tg(user_id)
    if tg:
        send_message(int(tg["tg_chat_id"]), text)


def notify_admins(text: str, tier: str = None):
    """Send message to all admins (optionally filtered by tier)."""
    with db_lock:
        c = get_conn()
        rows = c.execute(
            "SELECT id, tg_chat_id, tg_admin_tier FROM users "
            "WHERE role IN ('admin','superadmin','moderator') AND tg_chat_id IS NOT NULL AND active=1"
        ).fetchall()
        c.close()
    for row in rows:
        if tier and row["tg_admin_tier"] != tier:
            continue
        try:
            send_message(int(row["tg_chat_id"]), text)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# SUPPORT TICKETS
# ═══════════════════════════════════════════════════════════════════════════

def notify_new_ticket(ticket_id: int, username: str, subject: str, body: str):
    """Notify all admins of a new support ticket."""
    preview = body[:200] + ("…" if len(body) > 200 else "")
    text = (
        f"🎫 <b>New Support Ticket #{ticket_id}</b>\n\n"
        f"👤 User: <b>{username}</b>\n"
        f"📋 Subject: {subject}\n\n"
        f"💬 {preview}\n\n"
        f"Reply via the admin panel."
    )
    notify_admins(text)


def notify_ticket_reply(ticket_id: int, user_id: int, admin_name: str, reply: str):
    """Notify user of an admin reply to their ticket."""
    tg = get_user_tg(user_id)
    if not tg:
        return
    preview = reply[:300] + ("…" if len(reply) > 300 else "")
    text = (
        f"💬 <b>Reply to your Ticket #{ticket_id}</b>\n\n"
        f"👤 From: <b>{admin_name}</b>\n\n"
        f"{preview}\n\n"
        f"View the full conversation in the SynthTel panel."
    )
    send_message(int(tg["tg_chat_id"]), text)


def notify_ticket_closed(ticket_id: int, user_id: int, admin_name: str):
    tg = get_user_tg(user_id)
    if not tg:
        return
    text = (
        f"✅ <b>Ticket #{ticket_id} Closed</b>\n\n"
        f"Your support ticket has been closed by <b>{admin_name}</b>.\n"
        f"You can reopen it from the SynthTel panel if needed."
    )
    send_message(int(tg["tg_chat_id"]), text)


# ═══════════════════════════════════════════════════════════════════════════
# ADMIN BOT COMMANDS (incoming messages from admins)
# ═══════════════════════════════════════════════════════════════════════════

ADMIN_COMMANDS = """
<b>SynthTel Admin Bot Commands</b>

/status — System status
/users — List all users
/kick &lt;username&gt; — Deactivate a user
/unban &lt;username&gt; — Reactivate a user
/resetpw &lt;username&gt; &lt;newpw&gt; — Reset user password
/tickets — Open support tickets
/broadcast &lt;msg&gt; — Send message to all users
/help — Show this help
"""

def handle_admin_command(chat_id: int, text: str, user_row: dict):
    """Process a command from a verified admin Telegram user."""
    role = user_row.get("role", "")
    is_superadmin = role == "superadmin"
    is_admin      = role in ("admin", "superadmin")

    parts = text.strip().split(None, 2)
    cmd   = parts[0].lower() if parts else ""

    if cmd == "/start":
        send_message(chat_id,
            f"👋 Welcome back, <b>{user_row['username']}</b>!\n"
            f"Role: <b>{role.title()}</b>\n\n"
            f"Use /help to see available commands.")

    elif cmd == "/help":
        send_message(chat_id, ADMIN_COMMANDS)

    elif cmd == "/status":
        with db_lock:
            c = get_conn()
            total_users    = c.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
            total_tickets  = c.execute("SELECT COUNT(*) FROM support_tickets WHERE status='open'").fetchone()[0]
            c.close()
        send_message(chat_id,
            f"📊 <b>SynthTel Status</b>\n\n"
            f"👥 Active users: {total_users}\n"
            f"🎫 Open tickets: {total_tickets}\n"
            f"🟢 Server: Online")

    elif cmd == "/users" and is_admin:
        with db_lock:
            c = get_conn()
            rows = c.execute(
                "SELECT username, role, active, last_login FROM users ORDER BY id LIMIT 20"
            ).fetchall()
            c.close()
        lines = [f"{'✅' if r['active'] else '🚫'} <b>{r['username']}</b> [{r['role']}]" for r in rows]
        send_message(chat_id, "👥 <b>Users</b>\n\n" + "\n".join(lines))

    elif cmd == "/kick" and is_admin:
        if len(parts) < 2:
            send_message(chat_id, "Usage: /kick &lt;username&gt;")
            return
        uname = parts[1].strip().lower()
        with db_lock:
            c = get_conn()
            row = c.execute("SELECT id, username FROM users WHERE username=?", (uname,)).fetchone()
            if not row:
                c.close()
                send_message(chat_id, f"❌ User '{uname}' not found")
                return
            if row["username"] == user_row["username"]:
                c.close()
                send_message(chat_id, "❌ Cannot kick yourself")
                return
            c.execute("UPDATE users SET active=0 WHERE id=?", (row["id"],))
            c.commit()
            c.close()
        send_message(chat_id, f"✅ User <b>{uname}</b> has been deactivated")

    elif cmd == "/unban" and is_admin:
        if len(parts) < 2:
            send_message(chat_id, "Usage: /unban &lt;username&gt;")
            return
        uname = parts[1].strip().lower()
        with db_lock:
            c = get_conn()
            row = c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
            if not row:
                c.close()
                send_message(chat_id, f"❌ User '{uname}' not found")
                return
            c.execute("UPDATE users SET active=1 WHERE id=?", (row["id"],))
            c.commit()
            c.close()
        send_message(chat_id, f"✅ User <b>{uname}</b> has been reactivated")

    elif cmd == "/tickets" and is_admin:
        with db_lock:
            c = get_conn()
            rows = c.execute(
                "SELECT t.id, u.username, t.subject, t.status, t.created_at "
                "FROM support_tickets t JOIN users u ON t.user_id=u.id "
                "WHERE t.status='open' ORDER BY t.created_at DESC LIMIT 10"
            ).fetchall()
            c.close()
        if not rows:
            send_message(chat_id, "✅ No open tickets")
            return
        lines = [f"🎫 #{r['id']} <b>{r['username']}</b>: {r['subject'][:40]}" for r in rows]
        send_message(chat_id, "🎫 <b>Open Tickets</b>\n\n" + "\n".join(lines))

    elif cmd == "/broadcast" and is_superadmin:
        if len(parts) < 2:
            send_message(chat_id, "Usage: /broadcast &lt;message&gt;")
            return
        msg = " ".join(parts[1:])
        with db_lock:
            c = get_conn()
            rows = c.execute(
                "SELECT tg_chat_id FROM users WHERE tg_chat_id IS NOT NULL AND active=1"
            ).fetchall()
            c.close()
        count = 0
        for r in rows:
            try:
                send_message(int(r["tg_chat_id"]),
                    f"📢 <b>Broadcast from Admin</b>\n\n{msg}")
                count += 1
            except Exception:
                pass
        send_message(chat_id, f"✅ Broadcast sent to {count} users")

    elif cmd == "/resetpw" and is_superadmin:
        if len(parts) < 3:
            send_message(chat_id, "Usage: /resetpw &lt;username&gt; &lt;newpassword&gt;")
            return
        uname  = parts[1].strip().lower()
        new_pw = parts[2].strip()
        if len(new_pw) < 6:
            send_message(chat_id, "❌ Password must be at least 6 characters")
            return
        import secrets as sec
        try:
            import bcrypt
            pw_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
            salt    = ""
        except ImportError:
            import hashlib
            salt    = sec.token_hex(16)
            pw_hash = hashlib.sha256((new_pw + salt).encode()).hexdigest()
        with db_lock:
            c = get_conn()
            row = c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
            if not row:
                c.close()
                send_message(chat_id, f"❌ User '{uname}' not found")
                return
            c.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                      (pw_hash, salt, row["id"]))
            c.commit()
            c.close()
        send_message(chat_id, f"✅ Password reset for <b>{uname}</b>")

    else:
        if not is_admin:
            send_message(chat_id, "⛔ You don't have admin access to this bot.")
        else:
            send_message(chat_id, f"❓ Unknown command. Use /help")


def handle_user_command(chat_id: int, text: str, user_row: dict):
    """Process a command from a regular user."""
    parts = text.strip().split(None, 2)
    cmd   = parts[0].lower() if parts else ""

    if cmd == "/start":
        send_message(chat_id,
            f"👋 Hi <b>{user_row['username']}</b>! Your Telegram is connected to SynthTel.\n\n"
            f"You'll receive login alerts and support replies here.\n\n"
            f"Use /help to see what you can do.")

    elif cmd == "/help":
        send_message(chat_id,
            "📋 <b>SynthTel User Commands</b>\n\n"
            "/status — Your account status\n"
            "/ticket &lt;msg&gt; — Open a support ticket\n"
            "/help — Show this help")

    elif cmd == "/status":
        send_message(chat_id,
            f"✅ <b>Account Active</b>\n"
            f"👤 Username: <b>{user_row['username']}</b>\n"
            f"🔐 2FA: {'✅ Enabled' if user_row.get('tg_2fa_enabled') else '❌ Disabled'}")

    else:
        send_message(chat_id,
            "❓ Unknown command. Use /help\n\n"
            "To open a support ticket, visit the panel → Account → Support.")


# ═══════════════════════════════════════════════════════════════════════════
# LINK CODE HANDLER (incoming /start <code>)
# ═══════════════════════════════════════════════════════════════════════════

def handle_start_with_code(chat_id: int, tg_username: str, code: str):
    user_id = consume_link_code(code)
    if not user_id:
        send_message(chat_id,
            "❌ <b>Invalid or expired link code.</b>\n\n"
            "Go back to SynthTel → Account → Telegram and generate a new link code.")
        return
    with db_lock:
        c = get_conn()
        # Check this chat_id isn't already linked to another account
        existing = c.execute(
            "SELECT id, username FROM users WHERE tg_chat_id=? AND id!=?",
            (str(chat_id), user_id)
        ).fetchone()
        if existing:
            c.execute("UPDATE users SET tg_chat_id=NULL, tg_username=NULL WHERE id=?",
                      (existing["id"],))
        c.execute(
            "UPDATE users SET tg_chat_id=?, tg_username=? WHERE id=?",
            (str(chat_id), tg_username or "", user_id)
        )
        uname = c.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        c.commit()
        c.close()
    uname_str = uname["username"] if uname else "unknown"
    send_message(chat_id,
        f"✅ <b>Telegram Connected!</b>\n\n"
        f"Account <b>{uname_str}</b> is now linked to this chat.\n\n"
        f"You'll receive:\n"
        f"• 🔐 2FA codes (if enabled)\n"
        f"• 🔔 Login notifications\n"
        f"• 💬 Support ticket replies\n\n"
        f"Enable 2FA in the SynthTel panel under Account → Security.")


# ═══════════════════════════════════════════════════════════════════════════
# POLLING LOOP
# ═══════════════════════════════════════════════════════════════════════════

def _poll_loop():
    global _poll_running, _last_update
    log.info("Telegram polling started")
    while _poll_running:
        try:
            token = get_bot_token()
            if not token:
                time.sleep(5)
                continue
            result = tg_call("getUpdates", {
                "offset": _last_update + 1,
                "timeout": 20,
                "allowed_updates": ["message"]
            })
            if not result.get("ok"):
                time.sleep(5)
                continue
            for update in result.get("result", []):
                _last_update = update["update_id"]
                msg = update.get("message", {})
                if not msg:
                    continue
                chat_id    = msg.get("chat", {}).get("id")
                text       = msg.get("text", "")
                tg_uname   = msg.get("from", {}).get("username", "")
                if not chat_id or not text:
                    continue
                # Check if it's /start <code>
                if text.startswith("/start "):
                    code = text[7:].strip()
                    if code:
                        handle_start_with_code(chat_id, tg_uname, code)
                        continue
                # Look up user by chat_id
                user_row = get_user_by_chat(chat_id)
                if not user_row:
                    if text.startswith("/start"):
                        send_message(chat_id,
                            "👋 Welcome to SynthTel!\n\n"
                            "To link your account, go to the SynthTel panel → "
                            "Account → Telegram and follow the instructions.")
                    else:
                        send_message(chat_id,
                            "❓ Account not linked. Go to SynthTel → Account → Telegram to connect.")
                    continue
                role = user_row.get("role", "user")
                if role in ("admin", "superadmin", "moderator"):
                    handle_admin_command(chat_id, text, user_row)
                else:
                    handle_user_command(chat_id, text, user_row)
        except Exception as e:
            log.warning("Telegram poll error: %s", e)
            time.sleep(5)


def start_polling():
    global _poll_thread, _poll_running
    if _poll_thread and _poll_thread.is_alive():
        return
    _poll_running = True
    _poll_thread  = threading.Thread(target=_poll_loop, daemon=True, name="tg-poll")
    _poll_thread.start()


def stop_polling():
    global _poll_running
    _poll_running = False
