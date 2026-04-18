#!/bin/bash
# ═══════════════════════════════════════════════════════════
# SynthTel Sender v4 — First-Time VPS Install
# Run ONCE on a fresh VPS (Debian/Ubuntu).
# Then use deploy.sh for all subsequent updates.
#
# Usage (as root on the VPS):
#   bash install.sh
# ═══════════════════════════════════════════════════════════

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}checkmark${NC} $1"; }
step() { echo -e "\n${CYAN}[STEP $1] $2${NC}"; }
warn() { echo -e "  ${YELLOW}warn${NC}  $1"; }

VPS_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  SynthTel Sender v4 — VPS Install        ║"
echo "  ║  Server: ${VPS_IP}                   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── Require root ──
[ "$EUID" -ne 0 ] && { echo -e "${RED}Run as root!${NC}"; exit 1; }

# ══════════════════════════════════════════
# 1. System packages
# ══════════════════════════════════════════
step 1 "System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    nginx python3 python3-pip \
    openssh-client sshpass curl wget git \
    ufw fail2ban \
    openssl ca-certificates \
    >/dev/null 2>&1
ok "System packages installed"

# ══════════════════════════════════════════
# 2. Python dependencies
# ══════════════════════════════════════════
step 2 "Python packages"
# Core deps required by the server / sender modules. fpdf2 / Pillow /
# qrcode are needed by core/mime_builder.py for QR codes and PDF
# attachments. mime_builder has an auto-install fallback, but we install
# upfront so first-use isn't a surprise.
pip3 install --break-system-packages -q \
    bcrypt msal requests dnspython pysocks paramiko \
    fpdf2 Pillow qrcode
ok "Python packages: bcrypt msal requests dnspython pysocks paramiko fpdf2 Pillow qrcode"

# impacket is optional (used by the SMB / Windows auto-deploy path).
# Pip-built impacket is fragile on bare Debian, so try apt first.
if apt-get install -y -qq python3-impacket >/dev/null 2>&1; then
    ok "impacket installed via apt"
else
    if pip3 install --break-system-packages -q --no-build-isolation impacket >/dev/null 2>&1; then
        ok "impacket installed via pip"
    else
        warn "impacket install skipped — SMB auto-deploy disabled (everything else works)"
    fi
fi

# ══════════════════════════════════════════
# 3. Directory structure
# ══════════════════════════════════════════
step 3 "Directories"
mkdir -p /opt/synthtel/core
mkdir -p /var/www/html
touch /opt/synthtel/core/__init__.py
ok "/opt/synthtel/core/ created"
ok "/var/www/html/ confirmed"

# ══════════════════════════════════════════
# 4. Systemd service
# ══════════════════════════════════════════
step 4 "Systemd service"
cat > /etc/systemd/system/synthtel.service << 'SVCEOF'
[Unit]
Description=SynthTel Email Server (Modular v4)
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
systemctl daemon-reload
systemctl enable synthtel 2>/dev/null || true
ok "synthtel.service created + enabled"

# ══════════════════════════════════════════
# 5. Nginx (base config, HTTP only)
# ══════════════════════════════════════════
step 5 "Nginx configuration"
cat > /etc/nginx/sites-available/synthtel << 'NGXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;
    client_max_body_size 25M;

    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options SAMEORIGIN;
    }

    location /api/ {
        proxy_pass         http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   Connection '';
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        chunked_transfer_encoding on;
        gzip               off;
        proxy_set_header   Accept-Encoding '';
        add_header         X-Accel-Buffering no;
    }

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    gzip on;
    gzip_types text/html text/css application/javascript;
    gzip_min_length 1000;
}
NGXEOF

ln -sf /etc/nginx/sites-available/synthtel /etc/nginx/sites-enabled/synthtel
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t 2>&1
systemctl enable nginx 2>/dev/null || true
systemctl restart nginx
ok "Nginx configured and started (HTTP on port 80)"

# ══════════════════════════════════════════
# 6. Firewall (ufw)
# ══════════════════════════════════════════
step 6 "Firewall (ufw)"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow ssh    >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null 2>&1 || warn "ufw enable failed (may need reboot)"
ok "ufw: allow 22, 80, 443 | deny everything else"
# Note: 9proxy API (port 2090) only listens on localhost, no ufw rule needed

# ══════════════════════════════════════════
# 7. fail2ban (protect SSH + nginx)
# ══════════════════════════════════════════
step 7 "fail2ban"
cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 10
backend  = systemd

[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 6

[nginx-http-auth]
enabled  = true
F2BEOF
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || warn "fail2ban failed (non-critical)"
ok "fail2ban: SSH + nginx-auth protection active"

# ══════════════════════════════════════════
# 8. 9Proxy (residential proxy client)
# ══════════════════════════════════════════
step 8 "9Proxy client"
if ! command -v 9proxy &>/dev/null; then
    DEB_FILE="/tmp/9proxy-linux-debian-amd64.deb"
    wget -q -O "$DEB_FILE" "https://static.9proxy-cdn.net/download/latest/linux/9proxy-linux-debian-amd64.deb" 2>/dev/null \
        || curl -sL -o "$DEB_FILE" "https://static.9proxy-cdn.net/download/latest/linux/9proxy-linux-debian-amd64.deb" 2>/dev/null
    if [ -f "$DEB_FILE" ] && [ "$(wc -c < "$DEB_FILE")" -gt 1000 ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$DEB_FILE" >/dev/null 2>&1
        rm -f "$DEB_FILE"
        if command -v 9proxy &>/dev/null; then
            ok "9proxy installed"
        else
            warn "9proxy install failed (non-critical)"
        fi
    else
        warn "9proxy download failed (non-critical)"
    fi
else
    ok "9proxy already installed"
fi

# Start 9proxy daemon + API
if command -v 9proxy &>/dev/null; then
    systemctl start 9proxyd.service 2>/dev/null || true
    systemctl enable 9proxyd.service 2>/dev/null || true
    ok "9proxyd service enabled"

    # Create systemd service for 9proxy API on port 2090
    cat > /etc/systemd/system/9proxy-api.service << '9PEOF'
[Unit]
Description=9Proxy API Server
After=network.target 9proxyd.service
Requires=9proxyd.service

[Service]
Type=simple
ExecStart=/usr/bin/9proxy api -p 2090 -s
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
9PEOF
    systemctl daemon-reload
    systemctl enable 9proxy-api.service 2>/dev/null || true
    systemctl start 9proxy-api.service 2>/dev/null || true
    ok "9proxy API service on port 2090"
fi

# ══════════════════════════════════════════
# 9. Placeholder index.html
# ══════════════════════════════════════════
step 9 "Placeholder frontend"
if [ ! -f /var/www/html/index.html ]; then
cat > /var/www/html/index.html << 'HTMLEOF'
<!DOCTYPE html><html><head><title>SynthTel</title></head>
<body style="font-family:sans-serif;text-align:center;padding:60px">
  <h2>SynthTel Sender v4</h2>
  <p>Server is running. Run <code>bash deploy.sh</code> from your local machine to upload the frontend.</p>
</body></html>
HTMLEOF
    ok "Placeholder index.html written"
else
    ok "index.html already exists (not overwriting)"
fi

# ══════════════════════════════════════════
# 10. Verify
# ══════════════════════════════════════════
step 10 "Verification"
echo ""
systemctl is-active --quiet nginx  && ok "nginx: running"  || echo -e "  ${RED}nginx: STOPPED${NC}"
command -v 9proxy &>/dev/null && ok "9proxy: installed" || warn "9proxy: not installed"
systemctl is-active --quiet 9proxyd 2>/dev/null && ok "9proxyd: running" || warn "9proxyd: not running"
systemctl is-active --quiet 9proxy-api 2>/dev/null && ok "9proxy-api: running (port 2090)" || warn "9proxy-api: not running"
systemctl is-active --quiet synthtel 2>/dev/null \
    && ok "synthtel: running (core/server.py not deployed yet)" \
    || ok "synthtel: enabled (will start after deploy.sh uploads core/server.py)"

HTTP=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
[ "$HTTP" = "200" ] && ok "HTTP placeholder: OK (200)" || warn "HTTP returned $HTTP"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Install complete!${NC}"
echo -e "${GREEN}  http://${VPS_IP} — placeholder page serving${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "  1. From your LOCAL machine, edit deploy.sh and set VPS_IP=${VPS_IP}"
echo "  2. Run: bash deploy.sh"
echo "     This uploads index.html + all core/*.py modules"
echo "  3. (Optional) Run: bash /root/harden-nginx.sh"
echo "     Adds SSL, HSTS, security headers (A+ grade)"
echo ""
echo -e "${CYAN}Default login after deploy:${NC}"
echo "  Username: admin"
echo "  Password: admin  <-- CHANGE THIS IMMEDIATELY"
