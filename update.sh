#!/bin/bash
# ═══════════════════════════════════════════════════════════
# SynthTel — Fast Update Script
# Pushes index.html + core/*.py to existing server then restarts.
# Much faster than deploy.sh (no bootstrap / no lib downloads).
#
# Usage:
#   bash update.sh              # uses default IP in script
#   bash update.sh 1.2.3.4      # override VPS IP
# ═══════════════════════════════════════════════════════════
VPS_IP="${1:-5.252.153.210}"
VPS_USER="root"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()  { echo -e "  ${GREEN}✓${NC} $1"; }
err() { echo -e "  ${RED}✗${NC} $1"; }

echo -e "${CYAN}${BOLD}  SynthTel Fast Update → ${VPS_IP}${NC}"
echo ""

# ── SSH multiplexed connection ──
SOCK="/tmp/st-update-$$"
SSH_OPTS="-o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=60 -o StrictHostKeyChecking=no -o ConnectTimeout=15"
ssh $SSH_OPTS -fN "${VPS_USER}@${VPS_IP}" 2>/dev/null
[ $? -ne 0 ] && err "SSH connection failed — check IP and key" && exit 1
cleanup() { ssh $SSH_OPTS -O exit "${VPS_USER}@${VPS_IP}" 2>/dev/null; rm -f "$SOCK"; }
trap cleanup EXIT
run_ssh() { ssh -T $SSH_OPTS "${VPS_USER}@${VPS_IP}" "$@"; }
run_scp() { scp $SSH_OPTS -q "$@"; }

# ── Upload HTML ──
if [ -f "$LOCAL_DIR/index.html" ]; then
    run_ssh "cp /var/www/html/index.html /var/www/html/index.html.bak 2>/dev/null || true"
    run_scp "$LOCAL_DIR/index.html" "${VPS_USER}@${VPS_IP}:/var/www/html/index.html"
    LOCAL_SZ=$(wc -c < "$LOCAL_DIR/index.html" | tr -d '[:space:]')
    REMOTE_SZ=$(run_ssh "wc -c < /var/www/html/index.html 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
    if [ "$REMOTE_SZ" = "$LOCAL_SZ" ]; then
        ok "index.html uploaded (${LOCAL_SZ} bytes)"
    else
        err "Size mismatch (local ${LOCAL_SZ}, remote ${REMOTE_SZ}) — retrying"
        run_scp "$LOCAL_DIR/index.html" "${VPS_USER}@${VPS_IP}:/var/www/html/index.html"
    fi
fi

# ── Upload Python core ──
if [ -d "$LOCAL_DIR/core" ]; then
    run_ssh "mkdir -p /opt/synthtel/core && touch /opt/synthtel/core/__init__.py"
    FAILED_PY=0
    for pyfile in "$LOCAL_DIR/core/"*.py; do
        fname=$(basename "$pyfile")
        run_scp "$pyfile" "${VPS_USER}@${VPS_IP}:/opt/synthtel/core/${fname}" \
            && ok "core/${fname}" \
            || { err "core/${fname} failed"; FAILED_PY=$((FAILED_PY+1)); }
    done
fi

# ── Syntax check ──
echo ""
echo -e "${CYAN}  Checking Python syntax...${NC}"
run_ssh bash << 'SYNTAXEOF'
FAIL=0
for f in /opt/synthtel/core/*.py; do
    RES=$(python3 -m py_compile "$f" 2>&1)
    if [ -n "$RES" ]; then
        echo "  ✗ SYNTAX ERROR in $(basename $f):"
        echo "    $RES"
        FAIL=1
    else
        echo "  ✓ $(basename $f)"
    fi
done
exit $FAIL
SYNTAXEOF
[ $? -ne 0 ] && err "Syntax errors — restoring backup" && run_ssh "cp /var/www/html/index.html.bak /var/www/html/index.html 2>/dev/null; true" && exit 1

# ── Force clear nginx cache + reload ──
echo ""
echo -e "${CYAN}  Restarting services...${NC}"
run_ssh bash << 'RESTARTEOF'
# Force nginx to re-read files (flushes any open file cache)
nginx -t 2>/dev/null && systemctl reload nginx && echo "  ✓ nginx reloaded"

# Kill any stuck server process
PID=$(lsof -ti :5001 2>/dev/null)
[ -n "$PID" ] && kill -9 $PID 2>/dev/null && sleep 1

# Restart synthtel
systemctl daemon-reload
systemctl restart synthtel
sleep 3
systemctl is-active --quiet synthtel \
    && echo "  ✓ synthtel: running" \
    || { echo "  ✗ synthtel FAILED — last 20 log lines:"; journalctl -u synthtel -n 20 --no-pager; exit 1; }
RESTARTEOF
[ $? -ne 0 ] && exit 1

# ── Verify new file is live ──
echo ""
echo -e "${CYAN}  Verifying new version is live...${NC}"
LIVE_VERSION=$(run_ssh "grep -o 'content=\"v4[^\"]*\"' /var/www/html/index.html 2>/dev/null | head -1" 2>/dev/null)
[ -n "$LIVE_VERSION" ] && ok "Live version: $LIVE_VERSION" || ok "File deployed (no version tag)"

HTTP=$(run_ssh "curl -sk -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null" 2>/dev/null | tr -d '[:space:]')
[ "$HTTP" = "200" ] && ok "HTTP 200 OK from nginx" || err "nginx returned $HTTP"

API=$(run_ssh "curl -sk -m 5 http://127.0.0.1:5001/api/test 2>/dev/null" 2>/dev/null)
echo "$API" | grep -q '"status"' && ok "API responding" || err "API not responding: $API"

echo ""
echo -e "${GREEN}${BOLD}  ✓ Update complete!${NC}"
echo ""
echo -e "  ⚡ IMPORTANT — To see changes in browser:"
echo -e "     ${BOLD}Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)${NC}"
echo -e "     Or open in a private/incognito window"
echo -e "     The new version tag is: $LIVE_VERSION"
echo ""
echo -e "  Logs: ssh root@${VPS_IP} 'journalctl -u synthtel -f'"
