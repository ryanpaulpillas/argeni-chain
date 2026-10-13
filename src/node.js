// Network node: HTTP API, consensus participation, gossip to peers and catch-up sync.
import fs from 'node:fs';
import http from 'node:http';
import { Chain } from './chain.js';
import { Consensus } from './consensus.js';
import { addressFromPublicKey, isAddress, keyTypeOf, publicKeyFromPrivate } from './crypto.js';
import { createTransfer, txHash } from './tx.js';
import { formatAmount, parseAmount } from './coin.js';

// Post-quantum (ML-DSA-65) signatures are ~3.3 KB each, so blocks and proposals can be a few MB.
const MAX_BODY_BYTES = 16_000_000;
const EXPLORER_HTML = new URL('../public/explorer.html', import.meta.url);
const SYNC_INTERVAL_MS = 3_000;
const PRUNE_INTERVAL_MS = 60_000;

export class Node {
  // Public-network options (all off by default, so a local devnet behaves as before):
  //   trustProxy: take the client IP from X-Forwarded-For when the request comes from a local reverse proxy
  //   faucetAddressCooldownMs / faucetIpCooldownMs: how often one address / one IP may use the faucet
  //   txsPerMinutePerIp: cap on POST /txs per client IP (0 = unlimited)
  constructor({ genesis, dataDir = null, port = 0, host = '127.0.0.1', peers = [], validatorKey = null, faucetKey = null, faucetAmount = '100',
    trustProxy = false, faucetAddressCooldownMs = 60_000, faucetIpCooldownMs = 0, txsPerMinutePerIp = 0, log = console.log }) {
    this.chain = new Chain(genesis, { dataDir });
    this.port = port;
    this.host = host;
    this.peers = peers.map((p) => p.replace(/\/$/, ''));
    this.validatorKey = validatorKey;
    this.faucetKey = faucetKey;
    this.faucetUnits = parseAmount(faucetAmount, genesis.coin.decimals);
    this.trustProxy = trustProxy;
    this.faucetAddressLimit = new RateLimiter(1, faucetAddressCooldownMs);
    this.faucetIpLimit = new RateLimiter(1, faucetIpCooldownMs);
    this.txLimit = new RateLimiter(txsPerMinutePerIp, 60_000);
    this.log = log;
    this.timers = [];
    this.syncing = false;
  }

  async start() {
    this.server = http.createServer((req, res) => this.#handle(req, res));
    await new Promise((resolve, reject) => {
      this.server.once('error', (err) => reject(err.code === 'EADDRINUSE' ? new Error(`port ${this.port} is already in use (is another node running?)`) : err));
      this.server.listen(this.port, this.host, resolve);
    });
    this.port = this.server.address().port;
    this.url = `http://${this.host}:${this.port}`;
    await this.sync();
    this.timers.push(setInterval(() => this.sync(), SYNC_INTERVAL_MS));
    this.timers.push(setInterval(() => [this.faucetAddressLimit, this.faucetIpLimit, this.txLimit].forEach((l) => l.prune()), PRUNE_INTERVAL_MS));
    if (this.validatorKey) {
      this.consensus = new Consensus({
        chain: this.chain,
        privateKey: this.validatorKey,
        broadcast: (msg) => this.#broadcast('/consensus', msg),
        onDecide: (block) => this.#broadcast('/blocks', block),
        log: this.log,
      });
      this.consensus.start();
    }
    const role = this.validatorKey ? `validator ${addressFromPublicKey(publicKeyFromPrivate(this.validatorKey))}` : 'full node';
    this.log(`argeni node listening on ${this.url} (${role}), chain ${this.chain.genesis.chainId}, height ${this.chain.height}`);
    return this;
  }

  async stop() {
    this.consensus?.stop();
    this.timers.forEach(clearInterval);
    this.timers = [];
    await new Promise((resolve) => this.server.close(resolve));
    this.server.closeAllConnections?.();
  }

  // Pulls missing blocks from any peer that is ahead of us.
  async sync() {
    if (this.syncing || !this.peers.length) return;
    this.syncing = true;
    try {
      for (const peer of this.peers) {
        const status = await fetchJson(`${peer}/status`).catch(() => null);
        if (!status || status.chainId !== this.chain.genesis.chainId || status.genesisHash !== this.chain.genesisHash) continue;
        while (status.height > this.chain.height) {
          const block = await fetchJson(`${peer}/blocks/${this.chain.height + 1}`).catch(() => null);
          if (!block) break;
          const result = this.chain.addBlock(block);
          if (!result.ok) {
            this.log(`sync from ${peer} stopped at height ${this.chain.height + 1}: ${result.error}`);
            break;
          }
        }
      }
    } finally {
      this.syncing = false;
    }
  }

  #broadcast(route, body) {
    for (const peer of this.peers) {
      fetch(`${peer}${route}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5_000),
      }).catch(() => {});
    }
  }

  async #handle(req, res) {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', 'content-type');
    if (req.method === 'OPTIONS') return send(res, 204, null);
    const url = new URL(req.url, 'http://local');
    const parts = url.pathname.split('/').filter(Boolean);
    try {
      if (req.method === 'GET' && parts.length === 1 && parts[0] === 'network') return send(res, 200, await this.#network());
      if (req.method === 'GET') return this.#get(parts, res, url.searchParams);
      if (req.method === 'POST') return this.#post(parts, await readJson(req), res, this.#clientIp(req));
      return send(res, 405, { error: 'method not allowed' });
    } catch (err) {
      return send(res, err.status ?? 500, { error: err.status ? err.message : 'internal error' });
    }
  }

  #latest(query, summarize) {
    const limit = clampLimit(query.get('limit'), 10);
    const out = [];
    for (let h = this.chain.height; h >= 1 && out.length < limit; h--) out.push(summarize(h));
    return out;
  }

  #blockSummary(block) {
    return {
      height: block.header.height,
      hash: block.hash,
      timestamp: block.header.timestamp,
      proposer: addressFromPublicKey(block.header.proposer),
      txCount: block.txs.length,
      fees: block.txs.reduce((sum, tx) => sum + BigInt(tx.fee), 0n).toString(),
      signatures: block.commit.precommits.map((p) => addressFromPublicKey(p.validator)),
      round: block.commit.round,
    };
  }

  #txSummary(hash) {
    const found = this.chain.getTx(hash);
    if (!found) return null;
    const { tx, block } = found;
    return { status: 'confirmed', hash, height: block.header.height, timestamp: block.header.timestamp, ...txFields(tx) };
  }

  #get(parts, res, query) {
    const { chain } = this;
    const { decimals } = chain.genesis.coin;
    if (parts.length === 0) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(EXPLORER_HTML));
    }
    if (parts[0] === 'status' && parts.length === 1) {
      return send(res, 200, {
        chainId: chain.genesis.chainId,
        genesisHash: chain.genesisHash,
        coin: chain.genesis.coin,
        height: chain.height,
        tipHash: chain.tipHash,
        validators: chain.genesis.validators.map(addressFromPublicKey),
        self: this.validatorKey ? addressFromPublicKey(publicKeyFromPrivate(this.validatorKey)) : null,
        quorum: chain.quorum,
        supply: `${formatAmount(chain.state.supply, decimals)} ${chain.genesis.coin.symbol}`,
        maxSupply: `${formatAmount(chain.genesis.maxSupply, decimals)} ${chain.genesis.coin.symbol}`,
        mempool: chain.mempool.size,
        txCount: chain.txIndex.size,
        consensus: this.consensus?.status() ?? null,
        peers: this.peers,
        faucet: Boolean(this.faucetKey),
      });
    }
    if (parts[0] === 'genesis' && parts.length === 1) return send(res, 200, chain.genesis);
    if (parts[0] === 'blocks' && parts.length === 1) {
      return send(res, 200, this.#latest(query, (h) => this.#blockSummary(chain.getBlock(h))));
    }
    if (parts[0] === 'blocks' && parts.length === 2) {
      const height = parts[1] === 'latest' ? chain.height : Number(parts[1]);
      const block = chain.getBlock(height);
      if (!block) return send(res, 404, { error: 'block not found' });
      return send(res, 200, { ...block, txHashes: block.txs.map(txHash), proposerAddress: addressFromPublicKey(block.header.proposer) });
    }
    if (parts[0] === 'accounts' && (parts.length === 2 || (parts.length === 3 && parts[2] === 'txs'))) {
      if (!isAddress(parts[1])) return send(res, 400, { error: 'invalid address' });
      if (parts.length === 3) {
        const hashes = chain.addressIndex.get(parts[1]) ?? [];
        const limit = clampLimit(query.get('limit'), 25);
        return send(res, 200, { total: hashes.length, txs: hashes.slice(-limit).reverse().map((h) => this.#txSummary(h)) });
      }
      const account = chain.state.get(parts[1]);
      return send(res, 200, {
        address: parts[1],
        balance: account.balance.toString(),
        balanceFormatted: `${formatAmount(account.balance, decimals)} ${chain.genesis.coin.symbol}`,
        nonce: account.nonce,
        pendingNonce: chain.pendingNonce(parts[1]),
        migratedTo: account.migratedTo ?? null,
        pqCommit: account.pqCommit ?? null,
        txCount: chain.addressIndex.get(parts[1])?.length ?? 0,
        validator: chain.genesis.validators.some((v) => addressFromPublicKey(v) === parts[1]),
      });
    }
    if (parts[0] === 'txs' && parts.length === 1) {
      const limit = clampLimit(query.get('limit'), 10);
      const out = [];
      for (let h = chain.height; h >= 1 && out.length < limit; h--) {
        for (const tx of [...chain.getBlock(h).txs].reverse()) {
          if (out.length < limit) out.push(this.#txSummary(txHash(tx)));
        }
      }
      return send(res, 200, out);
    }
    if (parts[0] === 'txs' && parts.length === 2) {
      if (chain.mempool.has(parts[1])) {
        const tx = chain.mempool.get(parts[1]);
        return send(res, 200, { status: 'pending', hash: parts[1], ...txFields(tx) });
      }
      const summary = this.#txSummary(parts[1]);
      return summary ? send(res, 200, summary) : send(res, 404, { error: 'transaction not found' });
    }
    return send(res, 404, { error: 'not found' });
  }

  // Every validator's view of the chain, gathered by this node from its peers, so a browser that can
  // only reach this node (e.g. through rpc.argeni.io) can still see which validators are online.
  async #network() {
    if (this.networkCache && Date.now() - this.networkCache.at < 2000) return this.networkCache.value;
    const summarize = (s) => s && { validator: s.self, height: s.height, consensus: s.consensus };
    const own = { validator: this.validatorKey ? addressFromPublicKey(publicKeyFromPrivate(this.validatorKey)) : null, height: this.chain.height, consensus: this.consensus?.status() ?? null };
    const peers = await Promise.all(this.peers.map((p) => fetchJson(`${p}/status`).then(summarize).catch(() => null)));
    const value = { validators: this.chain.genesis.validators.map(addressFromPublicKey), nodes: [own, ...peers.filter(Boolean)] };
    this.networkCache = { at: Date.now(), value };
    return value;
  }

  // The caller's IP. Behind a reverse proxy on this machine, the real client is in X-Forwarded-For.
  #clientIp(req) {
    const remote = req.socket.remoteAddress ?? '';
    const local = remote === '127.0.0.1' || remote === '::1' || remote === '::ffff:127.0.0.1';
    if (this.trustProxy && local) {
      const forwarded = String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim();
      if (forwarded) return forwarded;
    }
    return remote;
  }

  #post(parts, body, res, ip) {
    const { chain } = this;
    if (parts[0] === 'txs' && parts.length === 1) {
      const wait = this.txLimit.check(ip);
      if (wait) return send(res, 429, { error: `too many transactions from your address, try again in ${formatWait(wait)}` });
      const result = chain.addTx(body);
      if (!result.ok) return send(res, 400, { error: result.error });
      if (!result.known) this.#broadcast('/txs', body);
      return send(res, 202, { hash: result.hash });
    }
    if (parts[0] === 'blocks' && parts.length === 1) {
      const height = body?.header?.height;
      if (Number.isSafeInteger(height) && height <= chain.height) return send(res, 200, { ok: true, known: true });
      if (Number.isSafeInteger(height) && height > chain.height + 1) {
        this.sync();
        return send(res, 202, { ok: true, syncing: true });
      }
      const result = chain.addBlock(body);
      if (!result.ok) return send(res, 400, { error: result.error });
      this.log(`accepted finalized block ${height} (${body.txs.length} txs) from peer`);
      this.#broadcast('/blocks', body);
      return send(res, 200, { ok: true });
    }
    if (parts[0] === 'consensus' && parts.length === 1) {
      if (!this.consensus) return send(res, 200, { ok: true, ignored: 'not a validator' });
      const result = this.consensus.handle(body);
      if (result.ahead) this.sync();
      return result.ok ? send(res, 200, { ok: true }) : send(res, 400, { error: result.error });
    }
    if (parts[0] === 'faucet' && parts.length === 1) return this.#faucet(body, res, ip);
    return send(res, 404, { error: 'not found' });
  }

  #faucet(body, res, ip) {
    if (!this.faucetKey) return send(res, 404, { error: 'this node has no faucet' });
    const address = body?.address;
    if (!isAddress(address)) return send(res, 400, { error: 'invalid address' });
    const addressWait = this.faucetAddressLimit.peek(address);
    if (addressWait) return send(res, 429, { error: `this address already received test ARGENI, try again in ${formatWait(addressWait)}` });
    const ipWait = this.faucetIpLimit.peek(ip);
    if (ipWait) return send(res, 429, { error: `the faucet was already used from your network, try again in ${formatWait(ipWait)}` });
    const { chain } = this;
    const faucetAddress = addressFromPublicKey(publicKeyFromPrivate(this.faucetKey));
    const tx = createTransfer({
      chainId: chain.genesis.chainId,
      privateKey: this.faucetKey,
      to: address,
      amount: this.faucetUnits,
      fee: BigInt(chain.genesis.minFee),
      nonce: chain.pendingNonce(faucetAddress),
      memo: 'testnet faucet',
    });
    const result = chain.addTx(tx);
    if (!result.ok) return send(res, 503, { error: `faucet unavailable: ${result.error}` });
    this.faucetAddressLimit.check(address);
    this.faucetIpLimit.check(ip);
    this.#broadcast('/txs', tx);
    return send(res, 202, { hash: result.hash, amount: formatAmount(this.faucetUnits, chain.genesis.coin.decimals) });
  }
}

// Fixed-window limiter: at most `max` events per key per `windowMs`. max 0 or windowMs 0 = unlimited.
export class RateLimiter {
  constructor(max, windowMs, now = () => Date.now()) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
    this.windows = new Map(); // key -> { count, resetAt }
  }

  // Milliseconds until `key` may act again, or 0 if it may act now. Does not record anything.
  peek(key) {
    if (!this.max || !this.windowMs) return 0;
    const w = this.windows.get(key);
    if (!w || w.resetAt <= this.now()) return 0;
    return w.count >= this.max ? w.resetAt - this.now() : 0;
  }

  // Records one event for `key`. Returns 0 if allowed, else milliseconds to wait (and records nothing).
  check(key) {
    const wait = this.peek(key);
    if (wait || !this.max || !this.windowMs) return wait;
    const now = this.now();
    const w = this.windows.get(key);
    if (!w || w.resetAt <= now) this.windows.set(key, { count: 1, resetAt: now + this.windowMs });
    else w.count++;
    return 0;
  }

  prune() {
    const now = this.now();
    for (const [key, w] of this.windows) if (w.resetAt <= now) this.windows.delete(key);
  }
}

function formatWait(ms) {
  const s = Math.ceil(ms / 1000);
  if (s < 60) return `${s} second${s === 1 ? '' : 's'}`;
  const m = Math.ceil(s / 60);
  if (m < 60) return `${m} minute${m === 1 ? '' : 's'}`;
  const h = Math.ceil(m / 60);
  return `${h} hour${h === 1 ? '' : 's'}`;
}

function txFields(tx) {
  const keyType = keyTypeOf(tx.from);
  if (tx.type === 'migrate') {
    return { type: 'migrate', keyType, toKeyType: keyTypeOf(tx.to), from: addressFromPublicKey(tx.from), to: addressFromPublicKey(tx.to), amount: '0', fee: tx.fee, nonce: tx.nonce, memo: `Migration to a post-quantum (${keyTypeOf(tx.to) === 'slh-dsa-128s' ? 'SLH-DSA-128s' : 'ML-DSA-65'}) key` };
  }
  if (tx.type === 'pq-commit') {
    return { type: 'pq-commit', keyType, from: addressFromPublicKey(tx.from), to: null, amount: '0', fee: tx.fee, nonce: tx.nonce, memo: 'Migration commitment to a post-quantum key', commitment: tx.commitment };
  }
  return { type: 'transfer', keyType, from: addressFromPublicKey(tx.from), to: tx.to, amount: tx.amount, fee: tx.fee, nonce: tx.nonce, memo: tx.memo ?? '' };
}

function clampLimit(value, fallback) {
  const n = Number(value ?? fallback);
  return Number.isSafeInteger(n) ? Math.min(Math.max(n, 1), 100) : fallback;
}

function send(res, status, body) {
  res.writeHead(status, body === null ? {} : { 'content-type': 'application/json' });
  res.end(body === null ? undefined : JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('request body too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'));
      } catch {
        reject(Object.assign(new Error('body must be JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

export async function fetchJson(url, options = {}) {
  const res = await fetch(url, { ...options, signal: AbortSignal.timeout(5_000) });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}
