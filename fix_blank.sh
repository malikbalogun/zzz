#!/bin/bash
# Run this DIRECTLY on your VPS:
# ssh root@5.252.153.210 'bash -s' < fix_blank.sh

set -e
LIBS=/var/www/html/libs
mkdir -p $LIBS

echo "=== Downloading React, ReactDOM, Babel to VPS ==="

dl() {
  local name=$1 dest="$LIBS/$1" min=$2; shift 2
  [ -f "$dest" ] && [ "$(wc -c < "$dest")" -gt "$min" ] && echo "  ✓ $name (already exists)" && return 0
  for url in "$@"; do
    echo -n "  $name from $(echo $url | cut -d/ -f3)... "
    curl -sL --max-time 120 --retry 2 "$url" -o "$dest.tmp" 2>/dev/null
    SZ=$(wc -c < "$dest.tmp" 2>/dev/null || echo 0)
    if [ "$SZ" -gt "$min" ]; then
      mv "$dest.tmp" "$dest"
      echo "OK (${SZ} bytes)"
      return 0
    fi
    rm -f "$dest.tmp"
    echo "failed (${SZ} bytes)"
  done
  echo "  ✗ $name FAILED ALL SOURCES"
  return 1
}

dl react.min.js 8000 \
  "https://unpkg.com/react@18/umd/react.production.min.js" \
  "https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js" \
  "https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"

dl react-dom.min.js 100000 \
  "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" \
  "https://cdn.jsdelivr.net/npm/react-dom@18/umd/react-dom.production.min.js" \
  "https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js"

dl babel.min.js 500000 \
  "https://unpkg.com/@babel/standalone/babel.min.js" \
  "https://cdn.jsdelivr.net/npm/@babel/standalone/babel.min.js" \
  "https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.23.2/babel.min.js"

# Fonts
curl -sL --max-time 10 \
  "https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" \
  -H "User-Agent: Mozilla/5.0" -o "$LIBS/fonts.css.tmp" 2>/dev/null
FSZ=$(wc -c < "$LIBS/fonts.css.tmp" 2>/dev/null || echo 0)
if [ "$FSZ" -gt 200 ]; then
  mv "$LIBS/fonts.css.tmp" "$LIBS/fonts.css"
  echo "  ✓ fonts.css OK"
else
  rm -f "$LIBS/fonts.css.tmp"
  printf 'body,button,input,select,textarea{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important}\ncode,pre{font-family:Consolas,monospace!important}\n' > "$LIBS/fonts.css"
  echo "  ✓ fonts.css (system font fallback)"
fi

# Fix nginx to serve /libs/ with caching
if ! grep -q "location /libs/" /etc/nginx/sites-available/synthtel 2>/dev/null; then
  sed -i 's|location / {|location /libs/ {\n        expires 30d;\n        add_header Cache-Control "public, immutable";\n    }\n    location / {|' /etc/nginx/sites-available/synthtel
  echo "  ✓ Added /libs/ to nginx"
fi
nginx -t 2>/dev/null && systemctl reload nginx && echo "  ✓ nginx reloaded"

echo ""
echo "=== Result ==="
ALL_OK=true
for f in react.min.js react-dom.min.js babel.min.js fonts.css; do
  if [ -f "$LIBS/$f" ] && [ "$(wc -c < "$LIBS/$f")" -gt 100 ]; then
    echo "  ✓ $f ($(wc -c < "$LIBS/$f") bytes)"
  else
    echo "  ✗ $f MISSING OR EMPTY"
    ALL_OK=false
  fi
done

echo ""
$ALL_OK && echo "SUCCESS — refresh http://5.252.153.210 now" || echo "FAILED — VPS cannot reach any CDN. Run: curl -v https://cdnjs.cloudflare.com"
