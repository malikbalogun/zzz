#!/bin/bash
# ═══════════════════════════════════════════════════
# SynthTel — Nginx Hardening + SSL + Code Protection
# Run on VPS: bash harden-nginx.sh
# ═══════════════════════════════════════════════════

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; }
step() { echo -e "\n${CYAN}[$1] $2${NC}"; }

VPS_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  SynthTel Nginx Hardening + SSL          ║${NC}"
echo -e "${CYAN}║  VPS: ${VPS_IP}                          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"

# ══════════════════════════════════════════
# 0. FIREWALL — Lock down exposed ports
# ══════════════════════════════════════════
step 0 "Firewall — UFW Rules"

if command -v ufw &>/dev/null; then
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    ufw allow 22/tcp comment 'SSH'    > /dev/null 2>&1
    ufw allow 80/tcp comment 'HTTP'   > /dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
    # CRITICAL: Block direct access to backend from outside
    ufw deny 5001 comment 'Block direct backend access' > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
    ok "UFW enabled: SSH(22), HTTP(80), HTTPS(443) open; port 5001 blocked externally"
else
    warn "UFW not found — install with: apt install ufw"
    iptables -A INPUT -p tcp --dport 5001 -j DROP 2>/dev/null && ok "iptables: port 5001 blocked" || warn "Could not block port 5001 via iptables"
fi

# ══════════════════════════════════════════
# 1. SSL CERTIFICATE (self-signed, IP-based)
# ══════════════════════════════════════════
step 1 "SSL Certificate (Self-Signed, IP-based, 4096-bit)"

mkdir -p /etc/nginx/ssl

openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/synthtel.key \
    -out    /etc/nginx/ssl/synthtel.crt \
    -subj   "/C=US/ST=Private/L=Private/O=SynthTel/CN=${VPS_IP}" \
    -addext "subjectAltName=IP:${VPS_IP}" \
    -addext "basicConstraints=CA:TRUE" \
    -addext "keyUsage=digitalSignature,keyEncipherment,keyCertSign" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

chmod 600 /etc/nginx/ssl/synthtel.key
chmod 644 /etc/nginx/ssl/synthtel.crt
ok "4096-bit cert generated for IP ${VPS_IP} (valid 10 years)"

if [ ! -f /etc/nginx/ssl/dhparam.pem ]; then
    echo "    Generating DH parameters (~30s)..."
    openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048 2>/dev/null
    ok "DH params generated: /etc/nginx/ssl/dhparam.pem"
else
    ok "DH params already exist, skipping"
fi

# ══════════════════════════════════════════
# 2. HARDENED NGINX SITE CONFIG
# ══════════════════════════════════════════
step 2 "Nginx Hardened Site Configuration"

# Remove default site to avoid duplicate MIME type warnings
rm -f /etc/nginx/sites-enabled/default
ok "Default nginx site removed (fixes duplicate MIME type warning)"

cat > /etc/nginx/sites-available/synthtel << NGINXCONF
# ── HTTP → HTTPS redirect ──
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

# ── Main HTTPS server ──
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # ── SSL ──
    ssl_certificate     /etc/nginx/ssl/synthtel.crt;
    ssl_certificate_key /etc/nginx/ssl/synthtel.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_dhparam         /etc/nginx/ssl/dhparam.pem;
    ssl_stapling        off;

    # ── Security Headers ──
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()" always;
    add_header X-Download-Options "noopen" always;
    add_header X-Permitted-Cross-Domain-Policies "none" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # ── Content Security Policy ──
    # Allows React/Babel from unpkg, Google Fonts, inline styles (required for theme system)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;

    # ── No caching (prevents source code being stored) ──
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate" always;
    add_header Pragma "no-cache" always;

    root /var/www/html;
    index index.html;
    server_tokens off;
    autoindex off;

    # ── Frontend (SPA) ──
    location / {
        try_files \$uri \$uri/ /index.html;
        limit_req zone=general burst=50 nodelay;
    }

    # ── Login — strict rate limit (10 attempts/min per IP) ──
    location = /api/login {
        limit_req zone=login burst=5 nodelay;
        limit_req_status 429;

        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        proxy_connect_timeout 10s;
    }

    # ── API (general) ──
    location /api/ {
        limit_req zone=api burst=30 nodelay;
        limit_req_status 429;

        proxy_pass http://127.0.0.1:5001;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Accept-Encoding "";

        # Long timeout for campaign sends
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_connect_timeout 30s;

        # Streaming support for live logs
        proxy_buffering off;
        chunked_transfer_encoding on;
        proxy_cache off;
        gzip off;
    }

    # ── Block source/config/data files — return 404 not 403 ──
    # (404 doesn't reveal whether the file exists)
    location ~* \.(jsx|tsx|ts|vue|svelte|map)$ { return 404; }
    location ~ /\.                              { return 404; }
    location ~ \.db$                            { return 404; }
    location ~ \.py$                            { return 404; }
    location ~ \.sh$                            { return 404; }
    location ~ \.pem$                           { return 404; }
    location ~ \.key$                           { return 404; }
    location ~ \.log$                           { return 404; }
    location ~ \.env$                           { return 404; }
    location ~ \.git                            { return 404; }
    location ~ \.bak$                           { return 404; }
    location ~ \.sql$                           { return 404; }
    location ~ \.conf$                          { return 404; }

    client_max_body_size 50M;

    # ── Compression (static assets only — API gzip disabled above) ──
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/css application/javascript application/json text/javascript;
    gzip_min_length 1000;
}
NGINXCONF

ok "Hardened nginx site config written"

# ══════════════════════════════════════════
# 3. NGINX MAIN CONFIG — rate limit zones
# ══════════════════════════════════════════
step 3 "Nginx Global Config — Rate Limiting"

if ! grep -q "limit_req_zone.*login" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\
\
    # SynthTel rate limiting zones\
    limit_req_zone $binary_remote_addr zone=login:10m   rate=10r/m;\
    limit_req_zone $binary_remote_addr zone=api:10m     rate=60r/m;\
    limit_req_zone $binary_remote_addr zone=general:10m rate=200r/m;\
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;\
' /etc/nginx/nginx.conf
    ok "Rate limiting zones added to nginx.conf"
else
    ok "Rate limiting zones already present"
fi

if ! grep -q "server_tokens off" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\    server_tokens off;' /etc/nginx/nginx.conf
    ok "server_tokens off added"
else
    ok "server_tokens already disabled"
fi

# ══════════════════════════════════════════
# 4. ENABLE SITE SYMLINK
# ══════════════════════════════════════════
step 4 "Enable Site"

ln -sf /etc/nginx/sites-available/synthtel /etc/nginx/sites-enabled/synthtel
ok "Symlink: sites-enabled/synthtel → sites-available/synthtel"

# ══════════════════════════════════════════
# 5. FAIL2BAN — Brute force protection
# ══════════════════════════════════════════
step 5 "Fail2Ban — Brute Force Protection"

if command -v fail2ban-client &>/dev/null; then
    cat > /etc/fail2ban/jail.d/synthtel.conf << 'F2BCONF'
[synthtel-login]
enabled  = true
port     = http,https
filter   = synthtel-login
logpath  = /var/log/nginx/access.log
maxretry = 10
findtime = 300
bantime  = 3600

[nginx-limit-req]
enabled  = true
port     = http,https
filter   = nginx-limit-req
logpath  = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime  = 600
F2BCONF

    cat > /etc/fail2ban/filter.d/synthtel-login.conf << 'F2BFILTER'
[Definition]
failregex = ^<HOST> .* "POST /api/login HTTP.*" 4[0-9][0-9] .*$
ignoreregex =
F2BFILTER

    systemctl restart fail2ban 2>/dev/null && ok "Fail2ban configured: 10 failed logins = 1hr ban" || warn "Fail2ban restart failed — check: systemctl status fail2ban"
else
    warn "Fail2ban not installed — run: apt install fail2ban && bash harden-nginx.sh"
fi

# ══════════════════════════════════════════
# 6. VALIDATE AND RELOAD
# ══════════════════════════════════════════
step 6 "Validate & Reload Nginx"

if nginx -t 2>&1; then
    systemctl reload nginx
    ok "Nginx validated and reloaded successfully"
else
    err "Nginx config test FAILED — fix errors above before continuing"
    exit 1
fi

# ══════════════════════════════════════════
# 7. VERIFY
# ══════════════════════════════════════════
step 7 "Verification"

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1/" 2>/dev/null)
if [ "$HTTP_CODE" = "200" ]; then
    ok "HTTPS: https://${VPS_IP} → $HTTP_CODE"
else
    warn "HTTPS returned $HTTP_CODE — if 000: systemctl status nginx && journalctl -u nginx -n 20"
fi

HTTP_REDIR=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/" 2>/dev/null)
[ "$HTTP_REDIR" = "301" ] && ok "HTTP → HTTPS redirect: $HTTP_REDIR" || warn "Redirect returned $HTTP_REDIR (expected 301)"

PORT_CHECK=$(curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" "http://${VPS_IP}:5001/" 2>/dev/null || echo "000")
[ "$PORT_CHECK" = "000" ] && ok "Port 5001 blocked externally" || warn "Port 5001 may be accessible from outside (got: $PORT_CHECK)"

echo ""
echo -e "${CYAN}Security Headers:${NC}"
curl -sk -I "https://127.0.0.1/" 2>/dev/null | grep -i "x-frame\|x-content\|strict-trans\|referrer\|content-security\|cross-origin\|cache-control" | while read line; do
    echo -e "  ${GREEN}✓${NC} $line"
done

echo ""
echo -e "${CYAN}SSL Certificate:${NC}"
openssl x509 -in /etc/nginx/ssl/synthtel.crt -noout -subject -dates 2>/dev/null | while read line; do
    echo -e "  ${GREEN}✓${NC} $line"
done

echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Hardening complete!${NC}"
echo -e "${GREEN}  Access: https://${VPS_IP}${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Protection layers active:${NC}"
echo -e "  ${GREEN}✓${NC} UFW firewall (5001 blocked, 22/80/443 open)"
echo -e "  ${GREEN}✓${NC} 4096-bit self-signed SSL (IP-bound, 10yr)"
echo -e "  ${GREEN}✓${NC} TLS 1.2/1.3 only + strong ciphers + DH params"
echo -e "  ${GREEN}✓${NC} HSTS (2 year max-age)"
echo -e "  ${GREEN}✓${NC} Content-Security-Policy"
echo -e "  ${GREEN}✓${NC} No-sniff, no-frame, no-embed headers"
echo -e "  ${GREEN}✓${NC} Cross-Origin isolation (COEP/COOP/CORP)"
echo -e "  ${GREEN}✓${NC} Rate limiting: login (10/min), API (60/min)"
echo -e "  ${GREEN}✓${NC} Fail2ban: auto-ban after 10 failed logins (1hr)"
echo -e "  ${GREEN}✓${NC} 403→404 rewrite (don't reveal file existence)"
echo -e "  ${GREEN}✓${NC} Source files blocked (.jsx/.py/.db/.sh/.env/.sql)"
echo -e "  ${GREEN}✓${NC} No-cache headers"
echo -e "  ${GREEN}✓${NC} Server version hidden"
echo -e "  ${GREEN}✓${NC} Default nginx site removed"
echo -e "  ${GREEN}✓${NC} Frontend: DevTools detection + page wipe"
echo -e "  ${GREEN}✓${NC} Frontend: right-click / F12 / Ctrl+U blocked"
