#!/bin/bash
# Run this ONCE on your Mac before deploying
# It downloads React into libs/ so deploy.sh can upload it to VPS
mkdir -p "$(dirname "$0")/libs"
echo "Downloading React 18..."
curl -L "https://unpkg.com/react@18/umd/react.production.min.js" \
     -o "$(dirname "$0")/libs/react.min.js" && \
echo "✓ Done — $(wc -c < "$(dirname "$0")/libs/react.min.js") bytes" || \
echo "✗ Failed — check internet connection"
