#!/usr/bin/env bash
# Packs the chain and the website into argeni-bundle.tar.gz to upload to the server.
# Run on your own computer:  bash deploy/make-bundle.sh   (from the argeni-chain folder)
# Never includes keys or chain data: only code, the explorer and the website.
set -euo pipefail

CHAIN="$(cd "$(dirname "$0")/.." && pwd)"
SITE="${SITE:-$CHAIN/../argeni-site}"
OUT="${OUT:-$PWD/argeni-bundle.tar.gz}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/argeni-bundle/chain" "$TMP/argeni-bundle/site"
cp -R "$CHAIN/src" "$CHAIN/scripts" "$CHAIN/public" "$CHAIN/deploy" "$CHAIN/package.json" "$CHAIN/README.md" "$TMP/argeni-bundle/chain/"
# foundations.html is hidden from the site on purpose, so it is not published.
rsync -a --exclude foundations.html --exclude '.DS_Store' "$SITE/" "$TMP/argeni-bundle/site/"

# Key files are JSON files holding a private key; none may be published.
if grep -rlqE --include='*.json' 'privateKey' "$TMP/argeni-bundle"; then
  echo "Refusing to build: a key file ended up in the bundle."; exit 1
fi
tar -czf "$OUT" -C "$TMP" argeni-bundle
echo "wrote $OUT ($(du -h "$OUT" | cut -f1))"
