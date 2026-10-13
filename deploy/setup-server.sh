#!/usr/bin/env bash
# Sets up an Argeni testnet server on Ubuntu 22.04 or 24.04. Run as root from the unpacked bundle:
#
#   TREASURY=ag...your-treasury-address bash argeni-bundle/chain/deploy/setup-server.sh
#
# Safe to run again to update the code: the testnet (genesis, keys, chain data) is created only once.
set -euo pipefail

BUNDLE="$(cd "$(dirname "$0")/../.." && pwd)"
VALIDATORS="${VALIDATORS:-4}"

[ "$(id -u)" = 0 ] || { echo "Please run as root (or with sudo)."; exit 1; }
[ -d "$BUNDLE/chain/src" ] && [ -d "$BUNDLE/site" ] || { echo "Run this script from inside the unpacked argeni-bundle."; exit 1; }

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

echo "== 4/6 Argeni code and website"
id argeni >/dev/null 2>&1 || useradd --system --home-dir /opt/argeni --shell /usr/sbin/nologin argeni
mkdir -p /opt/argeni
rm -rf /opt/argeni/chain.new /opt/argeni/site.new
cp -R "$BUNDLE/chain" /opt/argeni/chain.new
cp -R "$BUNDLE/site" /opt/argeni/site.new
rm -rf /opt/argeni/chain /opt/argeni/site
mv /opt/argeni/chain.new /opt/argeni/chain
mv /opt/argeni/site.new /opt/argeni/site
chown -R root:root /opt/argeni/chain /opt/argeni/site
chmod -R a+rX /opt/argeni/chain /opt/argeni/site

echo "== 5/6 Testnet (created only once)"
if [ ! -f /opt/argeni/testnet/genesis.json ]; then
  [ -n "${TREASURY:-}" ] || { echo "Set TREASURY=<your treasury address>. Create it on your own computer, never on the server."; exit 1; }
  node /opt/argeni/chain/scripts/init-testnet.js --treasury "$TREASURY" --validators "$VALIDATORS" --out /opt/argeni/testnet
else
  echo "testnet already exists, keeping it"
fi
mkdir -p /opt/argeni/testnet/data
chown -R argeni:argeni /opt/argeni/testnet
chmod 700 /opt/argeni/testnet/keys
chmod 600 /opt/argeni/testnet/keys/*.json

echo "== 6/6 Services and firewall"
cp /opt/argeni/chain/deploy/argeni-node@.service /etc/systemd/system/argeni-node@.service
cp /opt/argeni/chain/deploy/Caddyfile /etc/caddy/Caddyfile
systemctl daemon-reload
COUNT=$(ls /opt/argeni/testnet/node-*.json | wc -l)
for i in $(seq 1 "$COUNT"); do
  systemctl enable "argeni-node@$i" >/dev/null
  systemctl restart "argeni-node@$i"
done
systemctl enable caddy >/dev/null
systemctl restart caddy
ufw allow OpenSSH >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

sleep 5
echo
echo "Node 1 status:"
curl -s http://127.0.0.1:26601/status | head -c 400 || echo "(node not answering yet; check: journalctl -u argeni-node@1 -n 50)"
echo
echo
echo "Done. Open https://argeni.io and https://explorer.argeni.io"
echo "(HTTPS certificates can take a minute; they need the GoDaddy DNS records to point here.)"
echo "IMPORTANT: back up /opt/argeni/testnet/keys somewhere private."
