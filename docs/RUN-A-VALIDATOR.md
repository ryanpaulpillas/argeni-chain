# Run a CYVBER testnet validator

A new node needs **one seed address**. It finds the rest of the network by itself:
every minute it asks its seeds and peers which nodes they know (`GET /peers`), shakes hands with
new ones over the post-quantum channel (ML-KEM-768 + X25519, ML-DSA identities), and joins those
that run the same chain. Addresses on loopback or private networks are never shared or dialled.

Seed: `https://rpc.cyvber.com` (chain `cyvber-testnet-1`)

## 1. Server

Ubuntu 22.04/24.04, 2 vCPU, 4 GB RAM, a domain name pointing at it (e.g. `node.example.com`),
Node.js 24 (needs OpenSSL 3.5+ for post-quantum keys) and Caddy for HTTPS.

```bash
git clone https://github.com/ryanpaulpillas/cyvber-chain.git && cd cyvber-chain
curl -s https://rpc.cyvber.com/genesis > genesis.json
node src/cli.js keygen --out validator.json            # ML-DSA-87 validator key; keep it private
```

## 2. Node config (`node.json`)

```json
{
  "genesis": "genesis.json",
  "dataDir": "data",
  "host": "127.0.0.1",
  "port": 26601,
  "publicUrl": "https://node.example.com",
  "seeds": ["https://rpc.cyvber.com"],
  "trustProxy": true,
  "validatorKey": "validator.json"
}
```

Caddy (`/etc/caddy/Caddyfile`):

```
node.example.com {
	reverse_proxy 127.0.0.1:26601
}
```

Start it with `node src/cli.js node --config node.json` (or a systemd unit like
`deploy/cyvber-node@.service`). Within a minute `https://node.example.com/peers` lists the network,
and `https://rpc.cyvber.com/peers` lists your node.

## 3. Become a validator

The minimum stake is 100,000 test CYV (the faucet gives 100 a day), so on the testnet the CYVBER
team delegates the stake. Make a stake request; it holds no private key:

```bash
node src/cli.js keygen --out owner.json                 # your account; earns the validator's fees and rewards
node src/cli.js stake request --validator-key validator.json --operator <owner address> \
  --amount 100000 --out request.json --rpc https://rpc.cyvber.com
```

Send `request.json` to the CYVBER team. If you already hold enough test CYV, bond it yourself:
`stake join --key owner.json --validator-key validator.json --amount 100000 --rpc https://rpc.cyvber.com`.

Your validator signs blocks from the next height on. Check it at https://explorer.cyvber.com.

Downtime is jailed for a day and double-signing is slashed. Run one copy of a validator key, never two.
