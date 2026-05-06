#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# SynthTel Sender — One-Shot Bootstrap from GitHub
# ═══════════════════════════════════════════════════════════════
# Pulls the latest SynthTel from GitHub, runs the system install
# (nginx, systemd, ufw, fail2ban, 9proxy), deploys the Python
# core + frontend, and pins the installed commit SHA so the
# in-app auto-updater can take over from there.
#
# Designed to be safe to re-run (idempotent).  After the first
# run, the in-app GitHub auto-updater handles every future
# version bump — no need to re-run this script unless you want
# to wipe and reinstall.
#
# Usage on a fresh root@VPS shell (Debian/Ubuntu):
#
#     curl -fsSL https://raw.githubusercontent.com/malikbalogun/zzz/main/bootstrap.sh | bash
#
# Or with overrides:
#
#     GH_OWNER=youruser GH_REPO=zzz GH_BRANCH=main \
#       bash <(curl -fsSL https://raw.githubusercontent.com/malikbalogun/zzz/main/bootstrap.sh)
#
# Environment overrides:
#   GH_OWNER       (default: malikbalogun)
#   GH_REPO        (default: zzz)
#   GH_BRANCH      (default: main)
#   GH_TOKEN       (optional; for private repos / higher rate limits)
#   INSTALL_DIR    (default: /opt/synthtel)
#   WEB_DIR        (default: /var/www/html)
#   SRC_DIR        (default: /opt/synthtel-src ; the git clone)
#   SKIP_INSTALL   (default: 0 ; set to 1 to skip running install.sh)
# ═══════════════════════════════════════════════════════════════

set -e

GH_OWNER="${GH_OWNER:-malikbalogun}"
GH_REPO="${GH_REPO:-zzz}"
GH_BRANCH="${GH_BRANCH:-main}"
GH_TOKEN="${GH_TOKEN:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/synthtel}"
WEB_DIR="${WEB_DIR:-/var/www/html}"
SRC_DIR="${SRC_DIR:-/opt/synthtel-src}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()    { echo -e "  ${GREEN}✓${NC} $1"; }
err()   { echo -e "  ${RED}✗${NC} $1"; }
warn()  { echo -e "  ${YELLOW}⚠${NC} $1"; }
step()  { echo -e "\n${CYAN}${BOLD}▸ $1${NC}"; }

VPS_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  SynthTel Bootstrap — pulling from GitHub        ║"
echo "  ║                                                  ║"
echo "  ║  Repo:   ${GH_OWNER}/${GH_REPO}@${GH_BRANCH}"
echo "  ║  Server: ${VPS_IP}"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Require root ─────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    err "Run as root: sudo bash bootstrap.sh"
    exit 1
fi

# ── Ensure git + curl + python3 are present ──────────────────
step "Step 1/6 — Prerequisites"
export DEBIAN_FRONTEND=noninteractive
if ! command -v git >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 \
   || ! command -v python3 >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq git curl python3 python3-pip ca-certificates >/dev/null 2>&1
fi
ok "git $(git --version | awk '{print $3}'), python3 $(python3 --version | awk '{print $2}')"

# ── Clone or update the repo ─────────────────────────────────
step "Step 2/6 — Fetch source from GitHub"
CLONE_URL="https://github.com/${GH_OWNER}/${GH_REPO}.git"
if [ -n "$GH_TOKEN" ]; then
    CLONE_URL="https://x-access-token:${GH_TOKEN}@github.com/${GH_OWNER}/${GH_REPO}.git"
fi
if [ -d "$SRC_DIR/.git" ]; then
    ok "Existing checkout at $SRC_DIR — fetching updates"
    git -C "$SRC_DIR" fetch origin "$GH_BRANCH" --quiet
    git -C "$SRC_DIR" checkout "$GH_BRANCH" --quiet
    git -C "$SRC_DIR" reset --hard "origin/$GH_BRANCH" --quiet
else
    ok "Cloning ${GH_OWNER}/${GH_REPO}@${GH_BRANCH} → $SRC_DIR"
    rm -rf "$SRC_DIR"
    git clone --branch "$GH_BRANCH" --single-branch --depth 1 \
        "$CLONE_URL" "$SRC_DIR" --quiet
fi
COMMIT_SHA=$(git -C "$SRC_DIR" rev-parse HEAD)
COMMIT_SHORT=$(git -C "$SRC_DIR" rev-parse --short HEAD)
COMMIT_MSG=$(git -C "$SRC_DIR" log -1 --pretty=%B | head -1)
ok "At commit ${COMMIT_SHORT} — ${COMMIT_MSG:0:60}"

# ── Run the system installer (idempotent) ────────────────────
if [ "$SKIP_INSTALL" = "1" ]; then
    step "Step 3/6 — Skipping install.sh (SKIP_INSTALL=1)"
elif [ -f "$SRC_DIR/install.sh" ]; then
    step "Step 3/6 — Running install.sh (system packages, nginx, systemd, ufw)"
    ( cd "$SRC_DIR" && bash install.sh )
else
    step "Step 3/6 — install.sh missing — installing core deps only"
    apt-get install -y -qq nginx python3-pip openssh-client sshpass \
        wget ufw fail2ban openssl >/dev/null 2>&1 || true
    pip3 install --break-system-packages -q \
        bcrypt msal requests dnspython pysocks paramiko \
        fpdf2 Pillow qrcode >/dev/null 2>&1 || true
fi

# ── Deploy code: copy from clone → live paths ────────────────
step "Step 4/6 — Deploy code"
mkdir -p "$INSTALL_DIR/core" "$WEB_DIR"
touch "$INSTALL_DIR/core/__init__.py"

# Python core
PY_COUNT=0
for pyfile in "$SRC_DIR"/core/*.py; do
    [ -f "$pyfile" ] || continue
    cp "$pyfile" "$INSTALL_DIR/core/$(basename "$pyfile")"
    PY_COUNT=$((PY_COUNT+1))
done
ok "Deployed ${PY_COUNT} Python module(s) → $INSTALL_DIR/core/"

# Frontend
if [ -f "$SRC_DIR/index.html" ]; then
    cp "$SRC_DIR/index.html" "$WEB_DIR/index.html"
    ok "Deployed index.html → $WEB_DIR/index.html"
fi

# JS libs (React + Babel — referenced by index.html as /libs/*.min.js).
# These MUST be served as real files; otherwise nginx's SPA-fallback
# returns index.html with text/html and the browser refuses to execute
# the scripts ("strict MIME type checking").  Auto-fetched if missing.
if [ -d "$SRC_DIR/libs" ] && ls "$SRC_DIR/libs"/*.min.js >/dev/null 2>&1; then
    mkdir -p "$WEB_DIR/libs"
    LIB_COUNT=0
    for libfile in "$SRC_DIR"/libs/*.min.js; do
        cp "$libfile" "$WEB_DIR/libs/$(basename "$libfile")"
        LIB_COUNT=$((LIB_COUNT+1))
    done
    ok "Deployed ${LIB_COUNT} JS lib(s) → $WEB_DIR/libs/"
else
    warn "$SRC_DIR/libs is missing JS files — fetching from CDN"
    mkdir -p "$WEB_DIR/libs"
    for entry in \
        "react.min.js|https://unpkg.com/react@18/umd/react.production.min.js" \
        "react-dom.min.js|https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" \
        "babel.min.js|https://unpkg.com/@babel/standalone/babel.min.js"; do
        name="${entry%%|*}"
        url="${entry##*|}"
        if curl -fsSL --max-time 60 -o "$WEB_DIR/libs/$name" "$url"; then
            ok "Fetched $name from CDN"
        else
            err "Failed to fetch $name — frontend will fall back to CDN at runtime"
        fi
    done
fi

# ── Pin the installed SHA so the auto-updater is in sync ─────
step "Step 5/6 — Pin installed commit SHA for auto-updater"
echo -n "$COMMIT_SHA" > "$INSTALL_DIR/.installed_sha"
ok "Wrote $INSTALL_DIR/.installed_sha = ${COMMIT_SHORT}"

# ── Optional: persist GH_OWNER/REPO/BRANCH/TOKEN in .env ─────
ENV_FILE="$INSTALL_DIR/.env"
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"
update_env() {
    local key="$1" value="$2"
    [ -z "$value" ] && return 0
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}
update_env SYNTHTEL_GH_OWNER  "$GH_OWNER"
update_env SYNTHTEL_GH_REPO   "$GH_REPO"
update_env SYNTHTEL_GH_BRANCH "$GH_BRANCH"
[ -n "$GH_TOKEN" ] && update_env SYNTHTEL_GH_TOKEN "$GH_TOKEN"
ok "Persisted GitHub repo settings → $ENV_FILE"

# Make sure the systemd unit reads .env so the env-vars take effect.
if [ -f /etc/systemd/system/synthtel.service ]; then
    if ! grep -q "EnvironmentFile=" /etc/systemd/system/synthtel.service 2>/dev/null; then
        sed -i "/^\[Service\]/a EnvironmentFile=-${ENV_FILE}" /etc/systemd/system/synthtel.service
        systemctl daemon-reload
        ok "Wired EnvironmentFile=${ENV_FILE} into synthtel.service"
    else
        ok "synthtel.service already sources EnvironmentFile"
    fi
fi

# ── Start / restart the service ──────────────────────────────
step "Step 6/6 — (Re)start synthtel service"
# Kill anything stuck on 5001 from a previous half-deployed run.
PID=$(lsof -ti :5001 2>/dev/null || true)
[ -n "$PID" ] && { kill -9 $PID 2>/dev/null || true; sleep 1; }

systemctl daemon-reload
systemctl enable synthtel >/dev/null 2>&1 || true
systemctl restart synthtel
sleep 3
if systemctl is-active --quiet synthtel; then
    ok "synthtel service: running"
else
    err "synthtel failed to start — last 30 lines of journal:"
    journalctl -u synthtel -n 30 --no-pager || true
    exit 1
fi

# Reload nginx (it's already up from install.sh, just re-read fresh files).
nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null && ok "nginx reloaded"

# ── Sanity verify ────────────────────────────────────────────
HTTP=$(curl -sk -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null || echo "000")
[ "$HTTP" = "200" ] && ok "Frontend HTTP 200" || warn "Frontend returned HTTP $HTTP"

API=$(curl -sk -m 5 http://127.0.0.1:5001/api/test 2>/dev/null || echo "")
echo "$API" | grep -q '"status"' && ok "Backend API responding" || warn "Backend API not yet responding"

# ── Done ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✓ SynthTel installed at commit ${COMMIT_SHORT}${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Open: ${CYAN}${BOLD}http://${VPS_IP}/${NC}"
echo -e "  Login: ${BOLD}admin / admin${NC}  ${RED}(change immediately!)${NC}"
echo ""
echo -e "  ${CYAN}Auto-updates from GitHub are now active.${NC}"
echo -e "  Check status: Account → 🔄 Updates"
echo ""
echo -e "  Commands:"
echo -e "    Logs:    ${BOLD}journalctl -u synthtel -f${NC}"
echo -e "    Restart: ${BOLD}systemctl restart synthtel${NC}"
echo -e "    Re-pull: ${BOLD}bash $0${NC}    (idempotent — safe to re-run)"
echo ""
echo -e "  ${CYAN}Next (recommended):${NC}"
echo -e "    SSL hardening:   ${BOLD}bash $SRC_DIR/harden-nginx.sh${NC}"
echo ""
