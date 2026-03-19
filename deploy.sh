#!/bin/bash
# SynthTel — Deploy Script
# Usage: bash deploy.sh [VPS_IP]

VPS_IP="${1:-5.252.153.210}"
VPS_USER="root"
REMOTE_HTML="/var/www/html"
REMOTE_PY="/opt/synthtel"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; }
step() { echo -e "\n${CYAN}${BOLD}[$1] $2${NC}"; }

LOCAL_VERSION=$(grep -o 'content="v[^"]*"' "$LOCAL_DIR/index.html" 2>/dev/null | head -1 | grep -o 'v[^"]*')
LOCAL_SIZE=$(wc -c < "$LOCAL_DIR/index.html" 2>/dev/null | tr -d ' ')

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║       SynthTel Sender — Deploy           ║"
echo "  ╚══════════════════════════════════════════╝${NC}"
echo "  Target:  ${VPS_USER}@${VPS_IP}"
echo "  Version: ${LOCAL_VERSION:-UNKNOWN — wrong folder?}"
echo "  Size:    ${LOCAL_SIZE} bytes"
echo ""

if [ -z "$LOCAL_VERSION" ]; then
  err "Cannot read version from index.html"
  err "Make sure you extracted the zip and are running from INSIDE the extracted folder"
  err "Example: cd ~/synthtel_v4 && bash deploy.sh"
  exit 1
fi

step "0/6" "Pre-flight checks"
HAS_HTML=false; HAS_CORE=false
[ -f "$LOCAL_DIR/index.html" ] && HAS_HTML=true && ok "index.html ${LOCAL_SIZE} bytes ${LOCAL_VERSION}" || warn "index.html not found"
[ -d "$LOCAL_DIR/core" ] && ls "$LOCAL_DIR/core/"*.py &>/dev/null && HAS_CORE=true && ok "core/*.py" || warn "core/*.py not found"
! $HAS_HTML && ! $HAS_CORE && err "Nothing to deploy" && exit 1

step "1/6" "Connecting to ${VPS_IP}"
SOCK="/tmp/synthtel-deploy-$$"
SSH_OPTS="-o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=120 -o StrictHostKeyChecking=no -o ConnectTimeout=15"
ssh $SSH_OPTS -fN "${VPS_USER}@${VPS_IP}" 2>/dev/null
[ $? -ne 0 ] && err "SSH failed" && exit 1
ok "Connected"

run_ssh() { ssh -T $SSH_OPTS "${VPS_USER}@${VPS_IP}" "$@"; }
run_scp() { scp $SSH_OPTS -q "$@"; }
cleanup() { ssh $SSH_OPTS -O exit "${VPS_USER}@${VPS_IP}" 2>/dev/null; rm -f "$SOCK"; }
trap cleanup EXIT

step "2/6" "Bootstrap & Python deps"
run_ssh bash << 'BOOTEOF'
mkdir -p /opt/synthtel/core /var/www/html /var/www/html/libs
apt-get install -y -q python3-pip 2>/dev/null || true
python3 -m ensurepip --upgrade 2>/dev/null || true
echo "  Installing Python dependencies..."
for pkg in bcrypt msal requests dnspython pysocks paramiko fpdf2 Pillow qrcode; do
    python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null && echo "    ✓ $pkg" || echo "    ✗ $pkg"
done
echo "  Installing impacket (with prereqs)..."
for pkg in pyOpenSSL pycryptodome pycryptodomex ldap3 ldapdomaindump pyasn1; do
    python3 -m pip install "$pkg" --break-system-packages -q 2>/dev/null || true
done
# Try apt first (most reliable on Debian/Ubuntu)
if apt-get install -y -q python3-impacket 2>/dev/null; then
    echo "    ✓ impacket (via apt)"
else
    python3 -m pip install impacket --break-system-packages -q --no-build-isolation 2>/dev/null \
        && echo "    ✓ impacket" \
        || python3 -m pip install "impacket==0.11.0" --break-system-packages -q --no-build-isolation 2>/dev/null \
        && echo "    ✓ impacket 0.11.0" \
        || echo "    ✗ impacket (SMB auto-deploy disabled, everything else works)"
fi
python3 -c "import bcrypt, requests, paramiko, socks; print('  python deps: ok')" 2>/dev/null || echo "  python deps: partial"
cat > /etc/systemd/system/synthtel.service << 'SVCEOF'
[Unit]
Description=SynthTel Email Server
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5
[Service]
Type=simple
User=root
WorkingDirectory=/opt/synthtel
ExecStart=/usr/bin/python3 /opt/synthtel/core/server.py
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
Environment=SYNTHTEL_DB=/opt/synthtel/synthtel.db
Environment=SYNTHTEL_LOG=/opt/synthtel/synthtel.log
[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload && systemctl enable synthtel 2>/dev/null || true
echo "  systemd service: ok"
command -v nginx &>/dev/null || (apt-get update -qq && apt-get install -y -qq nginx >/dev/null 2>&1)
cat > /etc/nginx/sites-available/synthtel << 'NGXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
    client_max_body_size 25M;
    location = /index.html {
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0";
        add_header Pragma "no-cache";
        add_header Expires "0";
        etag off;
    }
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires "0";
        etag off;
    }
    location /libs/ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    location /api/ {
        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Connection '';
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        chunked_transfer_encoding on;
        gzip off;
        proxy_set_header Accept-Encoding '';
        add_header X-Accel-Buffering no;
    }
}
NGXEOF
ln -sf /etc/nginx/sites-available/synthtel /etc/nginx/sites-enabled/synthtel 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t 2>&1 | grep -q "test is successful" && echo "  nginx: ok" || echo "  nginx: config issue"
BOOTEOF
ok "Bootstrap complete"

step "3/6" "Downloading JS libraries"
run_ssh bash << 'LIBEOF'
LIBS=/var/www/html/libs; mkdir -p $LIBS; FAILED=0
dl() {
  local name=$1 dest="$LIBS/$1" min=$2; shift 2
  [ -f "$dest" ] && [ "$(wc -c < "$dest")" -gt "$min" ] && echo "  ✓ $name (cached)" && return 0
  for url in "$@"; do
    curl -sL --max-time 90 --retry 2 "$url" -o "$dest.tmp" 2>/dev/null
    SZ=$(wc -c < "$dest.tmp" 2>/dev/null || echo 0)
    [ "$SZ" -gt "$min" ] && mv "$dest.tmp" "$dest" && echo "  ✓ $name (${SZ}B)" && return 0
    rm -f "$dest.tmp"
  done
  echo "  ✗ $name FAILED"; return 1
}
dl "react.min.js" 8000 "https://unpkg.com/react@18/umd/react.production.min.js" "https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js" || FAILED=$((FAILED+1))
dl "react-dom.min.js" 100000 "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" "https://cdn.jsdelivr.net/npm/react-dom@18/umd/react-dom.production.min.js" || FAILED=$((FAILED+1))
dl "babel.min.js" 500000 "https://unpkg.com/@babel/standalone/babel.min.js" "https://cdn.jsdelivr.net/npm/@babel/standalone/babel.min.js" || FAILED=$((FAILED+1))
[ ! -f "$LIBS/fonts.css" ] && printf 'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important}\n' > "$LIBS/fonts.css" && echo "  ✓ fonts.css"
echo "FAILED=$FAILED"
LIBEOF
REACT_SIZE=$(run_ssh "wc -c < /var/www/html/libs/react.min.js 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
[ "${REACT_SIZE:-0}" -lt 8000 ] && err "react.min.js missing" && exit 1
ok "JS libraries ready"

step "4/6" "Uploading files"
if $HAS_HTML; then
  run_scp "$LOCAL_DIR/index.html" "${VPS_USER}@${VPS_IP}:${REMOTE_HTML}/index.html"
  LOCAL_SIZE=$(wc -c < "$LOCAL_DIR/index.html" | tr -d '[:space:]')
  REMOTE_SIZE=$(run_ssh "wc -c < /var/www/html/index.html 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]')
  [ "$REMOTE_SIZE" = "$LOCAL_SIZE" ] && ok "index.html ✓ ${LOCAL_SIZE} bytes" || { warn "Retrying upload..."; run_scp "$LOCAL_DIR/index.html" "${VPS_USER}@${VPS_IP}:${REMOTE_HTML}/index.html"; }
fi
if $HAS_CORE; then
  run_ssh "touch ${REMOTE_PY}/core/__init__.py" 2>/dev/null || true
  for pyfile in "$LOCAL_DIR/core/"*.py; do
    fname=$(basename "$pyfile"); run_scp "$pyfile" "${VPS_USER}@${VPS_IP}:${REMOTE_PY}/core/${fname}" && ok "core/${fname}"
  done
fi
[ -f "$LOCAL_DIR/harden-nginx.sh" ] && run_scp "$LOCAL_DIR/harden-nginx.sh" "${VPS_USER}@${VPS_IP}:/root/harden-nginx.sh" && ok "harden-nginx.sh"
[ -f "$LOCAL_DIR/install.sh" ]     && run_scp "$LOCAL_DIR/install.sh"      "${VPS_USER}@${VPS_IP}:/root/install.sh"      && ok "install.sh"

step "5/6" "Cache wipe, syntax check & restart"
DEPLOY_VER="$LOCAL_VERSION"
run_ssh bash << RESTARTEOF
FAIL=0

# ── 1. Syntax check all Python files before touching anything ──
for f in /opt/synthtel/core/*.py; do
    python3 -m py_compile "\$f" 2>&1 && echo "  OK  \$(basename \$f)" || { echo "  FAIL \$(basename \$f)"; FAIL=1; }
done
[ "\$FAIL" = "1" ] && echo "  ✗ Syntax errors — aborting restart" && exit 1

# ── 2. Wipe Python bytecode cache ─────────────────────────────
find /opt/synthtel -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find /opt/synthtel -name "*.pyc" -delete 2>/dev/null || true
echo "  ✓ Python __pycache__ cleared"

# ── 3. Force nginx to re-read index.html (no open-file cache) ──
touch /var/www/html/index.html
nginx -t 2>/dev/null && systemctl reload nginx
echo "  ✓ nginx reloaded"

# ── 4. Verify correct version landed on disk ──────────────────
LIVE_VER=\$(grep -o 'content="v[^"]*"' /var/www/html/index.html 2>/dev/null | head -1 | grep -o 'v[^"]*')
LIVE_SIZE=\$(wc -c < /var/www/html/index.html)
echo "  Disk: \${LIVE_VER:-UNKNOWN} (\${LIVE_SIZE} bytes)"
[ "\$LIVE_VER" = "$DEPLOY_VER" ] && echo "  ✓ VERSION MATCH" || echo "  ✗ MISMATCH: expected $DEPLOY_VER got \${LIVE_VER:-NONE}"

# ── 5. Kill any orphaned server process then restart cleanly ──
PID=\$(lsof -ti :5001 2>/dev/null); [ -n "\$PID" ] && kill -9 \$PID 2>/dev/null && sleep 1
systemctl daemon-reload && systemctl restart synthtel && sleep 3
systemctl is-active --quiet synthtel && echo "  ✓ synthtel: running" || { echo "  ✗ synthtel: FAILED"; journalctl -u synthtel -n 20 --no-pager; exit 1; }
RESTARTEOF
[ $? -ne 0 ] && err "Restart failed" && exit 1
ok "All services running"

step "6/6" "Health check"
run_ssh bash << 'HEALTHEOF'
echo "  ── Service status ──"
systemctl is-active --quiet synthtel && echo "  ✓ synthtel: active" || echo "  ✗ synthtel: STOPPED"
systemctl is-active --quiet nginx    && echo "  ✓ nginx:    active" || echo "  ✗ nginx:    STOPPED"
R=$(curl -sk -m 8 http://127.0.0.1:5001/api/test 2>/dev/null)
echo "$R" | grep -q '"status"' && echo "  ✓ API: OK" || echo "  ✗ API: FAIL"
echo ""
echo "  ── Version on disk ──"
grep -o 'content="v[^"]*"' /var/www/html/index.html | head -1
echo "  Size: $(wc -c < /var/www/html/index.html) bytes"
echo ""
echo "  ── Version served by nginx ──"
curl -sk http://127.0.0.1/ | grep -o 'content="v[^"]*"' | head -1
HEALTHEOF

echo ""
echo -e "${GREEN}${BOLD}  ✓ Deploy complete!${NC}"
echo -e "  Version: ${CYAN}${LOCAL_VERSION}${NC}"
echo ""
echo -e "  🌐 Open: http://${VPS_IP}"
echo -e "  🔄 Hard refresh: ${BOLD}Ctrl+Shift+R${NC} (Win/Linux)  |  ${BOLD}Cmd+Shift+R${NC} (Mac)"
echo ""
echo -e "  ── To confirm version from command line ──"
echo -e "  ${BOLD}curl -s http://${VPS_IP}/ | grep -o 'content=\"v[^\"]*\"'${NC}"
echo ""
