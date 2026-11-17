#!/usr/bin/env bash
# Sets up a CYVBER testnet server on Ubuntu 22.04 or 24.04. Run as root from the unpacked bundle:
#
#   TREASURY=cy...your-treasury-address ANTHROPIC_API_KEY=sk-ant-... bash cyvber-bundle/chain/deploy/setup-server.sh
#
# ANTHROPIC_API_KEY is optional: with it, the website's AI assistant is installed too. It is stored
# only in /etc/cyvber/assistant.env (readable by root and the service).
#
# Safe to run again to update the code: the testnet (genesis, keys, chain data) is created only once.
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")/../.." && pwd)"
VALIDATORS="${VALIDATORS:-4}"

[ "$(id -u)" = 0 ] || { echo "Please run as root (or with sudo)."; exit 1; }
[ -d "$BUNDLE/chain/src" ] && [ -d "$BUNDLE/site" ] || { echo "Run this script from inside the unpacked cyvber-bundle."; exit 1; }

echo "== 1/6 System packages"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg ufw debian-keyring debian-archive-keyring apt-transport-https

echo "== 2/6 Node.js 24"
if ! node -v 2>/dev/null | grep -q '^v24'; then
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
fi
node -e "require('crypto').generateKeyPairSync('ml-dsa-65'); require('crypto').generateKeyPairSync('slh-dsa-sha2-128s')" \
  || { echo "This Node.js can't make post-quantum (ML-DSA / SLH-DSA) keys; it needs OpenSSL 3.5 or newer."; exit 1; }

echo "== 3/6 Caddy (web server with automatic HTTPS)"
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y caddy
fi

echo "== 4/6 CYV code and website"
id cyvber >/dev/null 2>&1 || useradd --system --home-dir /opt/cyvber --shell /usr/sbin/nologin cyvber
mkdir -p /opt/cyvber
rm -rf /opt/cyvber/chain.new /opt/cyvber/site.new
cp -R "$BUNDLE/chain" /opt/cyvber/chain.new
cp -R "$BUNDLE/site" /opt/cyvber/site.new
rm -rf /opt/cyvber/chain /opt/cyvber/site
mv /opt/cyvber/chain.new /opt/cyvber/chain
mv /opt/cyvber/site.new /opt/cyvber/site
chown -R root:root /opt/cyvber/chain /opt/cyvber/site
chmod -R a+rX /opt/cyvber/chain /opt/cyvber/site

if [ -d "$BUNDLE/assistant" ]; then
  rm -rf /opt/cyvber/assistant.new && cp -R "$BUNDLE/assistant" /opt/cyvber/assistant.new
  (cd /opt/cyvber/assistant.new && npm ci --omit=dev --no-audit --no-fund)
  rm -rf /opt/cyvber/assistant && mv /opt/cyvber/assistant.new /opt/cyvber/assistant
  chown -R root:root /opt/cyvber/assistant && chmod -R a+rX /opt/cyvber/assistant
fi

echo "== 5/6 Testnet (created only once)"
if [ ! -f /opt/cyvber/testnet/genesis.json ]; then
  [ -n "${TREASURY:-}" ] || { echo "Set TREASURY=<your treasury address>. Create it on your own computer, never on the server."; exit 1; }
  node /opt/cyvber/chain/scripts/init-testnet.js --treasury "$TREASURY" --validators "$VALIDATORS" --out /opt/cyvber/testnet
else
  echo "testnet already exists, keeping it"
fi
mkdir -p /opt/cyvber/testnet/data
chown -R cyvber:cyvber /opt/cyvber/testnet
chmod 700 /opt/cyvber/testnet/keys
chmod 600 /opt/cyvber/testnet/keys/*.json

echo "== 6/6 Services and firewall"
cp /opt/cyvber/chain/deploy/cyvber-node@.service /etc/systemd/system/cyvber-node@.service
cp /opt/cyvber/chain/deploy/Caddyfile /etc/caddy/Caddyfile
systemctl daemon-reload
COUNT=$(ls /opt/cyvber/testnet/node-*.json | wc -l)
for i in $(seq 1 "$COUNT"); do
  systemctl enable "cyvber-node@$i" >/dev/null
  systemctl restart "cyvber-node@$i"
done
if [ -d /opt/cyvber/assistant ]; then
  mkdir -p /etc/cyvber && chmod 750 /etc/cyvber && chgrp cyvber /etc/cyvber
  if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    umask 077; printf 'ANTHROPIC_API_KEY=%s\n' "$ANTHROPIC_API_KEY" > /etc/cyvber/assistant.env
    chgrp cyvber /etc/cyvber/assistant.env; chmod 640 /etc/cyvber/assistant.env
  fi
  if [ -f /etc/cyvber/assistant.env ]; then
    cp /opt/cyvber/chain/deploy/cyvber-assistant.service /etc/systemd/system/cyvber-assistant.service
    systemctl daemon-reload
    systemctl enable cyvber-assistant >/dev/null
    systemctl restart cyvber-assistant
  else
    echo "AI assistant not started: run again with ANTHROPIC_API_KEY=... to enable it."
  fi
fi
systemctl enable caddy >/dev/null
systemctl restart caddy
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

sleep 5
echo
echo "Node 1 status:"
curl -s http://127.0.0.1:26601/status | head -c 400 || echo "(node not answering yet; check: journalctl -u cyvber-node@1 -n 50)"
echo
echo
echo "Done. Open https://cyvber.com and https://explorer.cyvber.com"
echo "(HTTPS certificates can take a minute; they need the GoDaddy DNS records to point here.)"
echo "IMPORTANT: back up /opt/cyvber/testnet/keys somewhere private."
