#!/bin/bash
# scripts/build_webui.sh — Build the WebUI SPA from the fresh Vue 3
# source and copy it to webroot/.
#
# Prereqs:
#   npm install --prefix webui/

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/webui"

if [ ! -d node_modules ]; then
    npm install
fi

npm run build

# Copy the build output into the module's webroot/ directory.
TARGET="$ROOT/webroot"
mkdir -p "$TARGET/assets"
cp dist/index.html "$TARGET/index.html"
cp dist/assets/*.js  "$TARGET/assets/index.js"
cp dist/assets/*.css "$TARGET/assets/index.css"

echo "==> WebUI built and copied to $TARGET"
