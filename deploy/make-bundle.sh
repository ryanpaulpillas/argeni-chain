#!/usr/bin/env bash
# Packs the chain and the website into cyvber-bundle.tar.gz to upload to the server.
# Run on your own computer:  bash deploy/make-bundle.sh   (from the cyvber-chain folder)
# Never includes keys or chain data: only code, the explorer and the website.
set -euo pipefail

CHAIN="$(cd "$(dirname "$0")/.." && pwd)"
SITE="${SITE:-$CHAIN/../cyvber-site}"
ASSISTANT="${ASSISTANT:-$CHAIN/../cyvber-assistant}"
OUT="${OUT:-$PWD/cyvber-bundle.tar.gz}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/cyvber-bundle/chain" "$TMP/cyvber-bundle/site"
cp -R "$CHAIN/src" "$CHAIN/scripts" "$CHAIN/public" "$CHAIN/deploy" "$CHAIN/package.json" "$CHAIN/README.md" "$TMP/cyvber-bundle/chain/"
# The AI assistant: code only (no node_modules, never its .env with the API key).
if [ -d "$ASSISTANT" ]; then
  mkdir -p "$TMP/cyvber-bundle/assistant"
  cp "$ASSISTANT/server.mjs" "$ASSISTANT/package.json" "$ASSISTANT/package-lock.json" "$TMP/cyvber-bundle/assistant/"
fi
# foundations.html is hidden from the site on purpose, so it is not published.
rsync -a --exclude foundations.html --exclude '.DS_Store' "$SITE/" "$TMP/cyvber-bundle/site/"

# Key files are JSON files holding a private key; none may be published.
if grep -rlqE --include='*.json' 'privateKey' "$TMP/cyvber-bundle" || grep -rlqE 'sk-ant-[A-Za-z0-9_-]{30,}' "$TMP/cyvber-bundle"; then
  echo "Refusing to build: a key file or API key ended up in the bundle."; exit 1
fi
tar -czf "$OUT" -C "$TMP" cyvber-bundle
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
