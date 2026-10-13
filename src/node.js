// Network node: HTTP API, consensus participation, gossip to peers and catch-up sync.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { Chain } from './chain.js';
import { Consensus } from './consensus.js';
import { addressFromPublicKey, isAddress, keyTypeOf, parseMultisig, publicKeyFromPrivate } from './crypto.js';
import { createTransfer, createTx, txHash } from './tx.js';
import { formatAmount, parseAmount } from './coin.js';
import { totalLocked, vestingEnd } from './state.js';

// Post-quantum (ML-DSA-65) signatures are ~3.3 KB each, so blocks and proposals can be a few MB.
const MAX_BODY_BYTES = 16_000_000;
const EXPLORER_HTML = new URL('../public/explorer.html', import.meta.url);
const SYNC_INTERVAL_MS = 3_000;
const PRUNE_INTERVAL_MS = 60_000;
const SNAPSHOTS_KEPT = 2;
const MAX_PEERS = 64;

export class Node {
  // Public-network options (all off by default, so a local devnet behaves as before):
  //   trustProxy: take the client IP from X-Forwarded-For when the request comes from a local reverse proxy
  //   faucetAddressCooldownMs / faucetIpCooldownMs: how often one address / one IP may use the faucet
  //   txsPerMinutePerIp: cap on POST /txs per client IP (0 = unlimited)
  // Fast sync: snapshotEvery = keep a snapshot of the state every N blocks for new nodes to start
  // from; trustedBlock = { height, hash } makes an empty node start from that snapshot (taken from
  // a peer, checked against the hash) instead of replaying every block since genesis.
  constructor({ genesis, dataDir = null, port = 0, host = '127.0.0.1', peers = [], validatorKey = null, faucetKey = null, faucetAmount = '100',
    trustProxy = false, faucetAddressCooldownMs = 60_000, faucetIpCooldownMs = 0, txsPerMinutePerIp = 0, snapshotEvery = 1000, trustedBlock = null,
    publicUrl = null, log = console.log }) {
    this.genesis = genesis;
    this.dataDir = dataDir;
    this.chain = new Chain(genesis, { dataDir });
    this.snapshotEvery = snapshotEvery;
    this.trustedBlock = trustedBlock;
    this.snapshots = new Map(); // height -> snapshot (in memory; also written to dataDir/snapshots)
    // Peer discovery: a node with a publicUrl announces it to its peers on start, so a new validator
    // joins the gossip without anyone editing other nodes' configs.
    this.relayed = new Set(); // consensus messages already passed on
    this.publicUrl = publicUrl ? publicUrl.replace(/\/$/, '') : null;
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
    if (this.trustedBlock && this.chain.height < this.trustedBlock.height) await this.#fastSync();
    this.#loadSnapshots();
    this.chain.onCommit((block) => this.#maybeSnapshot(block.header.height));
    await this.sync();
    await this.#announce();
    this.timers.push(setInterval(() => this.sync(), SYNC_INTERVAL_MS));
    this.timers.push(setInterval(() => this.#announce(), 60_000));
    this.timers.push(setInterval(() => [this.faucetAddressLimit, this.faucetIpLimit, this.txLimit].forEach((l) => l.prune()), PRUNE_INTERVAL_MS));
    if (this.validatorKey) {
      this.consensus = new Consensus({
        chain: this.chain,
        privateKey: this.validatorKey,
        broadcast: (msg) => this.#broadcast('/consensus', msg),
        onDecide: (block) => this.#broadcast('/blocks', block),
        onEquivocation: (a, b) => this.#reportDoubleSign(a, b),
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
    // Close open keep-alive connections right away: peers keep sending messages, so waiting for
    // them to go idle could take a long time.
    const closed = new Promise((resolve) => this.server.close(resolve));
    this.server.closeAllConnections?.();
    await closed;
  }

  // Starts an empty node from a peer's snapshot of the trusted block.
  async #fastSync() {
    const { height, hash } = this.trustedBlock;
    for (const peer of this.peers) {
      const snap = await fetchJson(`${peer}/snapshot?height=${height}`, { timeoutMs: 120_000 }).catch(() => null);
      if (!snap) continue;
      try {
        Chain.verifySnapshot(this.genesis, snap, { height, hash });
        this.chain = new Chain(this.genesis, { dataDir: this.dataDir, snapshot: snap });
        this.log(`started from snapshot at block ${height} (${hash.slice(0, 12)}) from ${peer}`);
        return;
      } catch (err) {
        this.log(`snapshot from ${peer} rejected: ${err.message}`);
      }
    }
    throw new Error(`no peer served a valid snapshot of block ${height}; ask a peer which snapshot heights it has (GET /snapshot)`);
  }

  #snapshotDir() {
    return this.dataDir ? path.join(this.dataDir, 'snapshots') : null;
  }

  #loadSnapshots() {
    const dir = this.#snapshotDir();
    if (!dir || !fs.existsSync(dir)) return;
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort().slice(-SNAPSHOTS_KEPT)) {
      try {
        const snap = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
        this.snapshots.set(snap.height, snap);
      } catch {
        // ignore a damaged snapshot; a new one is made later
      }
    }
  }

  #maybeSnapshot(height) {
    if (!this.snapshotEvery || height % this.snapshotEvery !== 0) return;
    const snap = this.chain.snapshot();
    this.snapshots.set(height, snap);
    const dir = this.#snapshotDir();
    if (dir) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `${String(height).padStart(10, '0')}.json`), JSON.stringify(snap));
    }
    for (const h of [...this.snapshots.keys()].sort((a, b) => a - b).slice(0, -SNAPSHOTS_KEPT)) {
      this.snapshots.delete(h);
      if (dir) fs.rmSync(path.join(dir, `${String(h).padStart(10, '0')}.json`), { force: true });
    }
  }

  // Submits proof that a validator signed two different blocks; it is slashed and removed.
  #reportDoubleSign(a, b) {
    const strip = ({ type, height, round, blockHash, validRound, validator, signature }) => ({ type, height, round, blockHash, ...(type === 'proposal' ? { validRound } : {}), validator, signature });
    const reporter = publicKeyFromPrivate(this.validatorKey);
    try {
      const tx = createTx({ type: 'evidence', chainId: this.genesis.chainId, voteA: strip(a), voteB: strip(b), fee: BigInt(this.genesis.minFee), nonce: this.chain.pendingNonce(addressFromPublicKey(reporter)) }, { privateKey: this.validatorKey });
      const result = this.chain.addTx(tx);
      this.log(`validator ${addressFromPublicKey(a.validator)} signed two different blocks at height ${a.height}: ${result.ok ? 'evidence submitted' : `evidence not submitted (${result.error})`}`);
      if (result.ok && !result.known) this.#broadcast('/txs', tx);
    } catch (err) {
      this.log(`could not submit double-sign evidence: ${err.message}`);
    }
  }

  #acceptCommit(msg) {
    const height = msg.block?.header?.height;
    if (!Number.isSafeInteger(height) || height <= this.chain.height) return { ok: true };
    if (height > this.chain.height + 1) return { ok: true, ahead: true };
    const result = this.chain.addBlock(msg.block);
    return result.ok ? { ok: true } : { ok: false, error: result.error };
  }

  // Tells peers how to reach this node; they add it to their gossip list.
  async #announce() {
    if (!this.publicUrl) return;
    await Promise.all(this.peers.map((peer) => fetchJson(`${peer}/peers`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: this.publicUrl, genesisHash: this.chain.genesisHash }),
    }).catch(() => null)));
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
    for (let h = this.chain.height; h > this.chain.base && out.length < limit; h--) out.push(summarize(h));
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
        validators: chain.validatorList.map(addressFromPublicKey),
        historyFrom: chain.base + 1,
        snapshots: [...this.snapshots.values()].map((sn) => ({ height: sn.height, hash: sn.block.hash })),
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
    if (parts[0] === 'snapshot' && parts.length === 1) {
      if (!query.has('height')) return send(res, 200, { heights: [...this.snapshots.keys()], every: this.snapshotEvery });
      const snap = this.snapshots.get(Number(query.get('height')));
      return snap ? send(res, 200, snap) : send(res, 404, { error: `no snapshot at that height; available: ${[...this.snapshots.keys()].join(', ') || 'none yet'}` });
    }
    if (parts[0] === 'validators' && parts.length === 1) {
      const symbol = chain.genesis.coin.symbol;
      return send(res, 200, {
        active: chain.validatorList.length,
        quorum: chain.quorum,
        minStake: `${formatAmount(chain.params.minStake, decimals)} ${symbol}`,
        validators: chain.state.validators.map((v) => ({
          address: addressFromPublicKey(v.key),
          publicKey: v.key,
          keyType: keyTypeOf(v.key),
          owner: v.owner,
          stake: v.stake.toString(),
          stakeFormatted: `${formatAmount(v.stake, decimals)} ${symbol}`,
          status: v.status,
          genesis: Boolean(v.genesis),
          missedInARow: v.missed,
          jailedUntil: v.jailedUntil ?? null,
          unbondAt: v.unbondAt ?? null,
        })),
        banned: [...chain.state.banned].map(addressFromPublicKey),
      });
    }
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
        validator: chain.validatorList.some((v) => addressFromPublicKey(v) === parts[1]),
        locked: totalLocked(account, Date.now()).toString(),
        lockedFormatted: `${formatAmount(totalLocked(account, Date.now()), decimals)} ${chain.genesis.coin.symbol}`,
        vesting: (account.vesting ?? []).map((g) => ({ ...g, fullyUnlockedAt: vestingEnd(g) })),
        ownsValidators: chain.state.validators.filter((v) => v.owner === parts[1]).map((v) => addressFromPublicKey(v.key)),
      });
    }
    if (parts[0] === 'txs' && parts.length === 1) {
      const limit = clampLimit(query.get('limit'), 10);
      const out = [];
      for (let h = chain.height; h > chain.base && out.length < limit; h--) {
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
    const value = { validators: this.chain.validatorList.map(addressFromPublicKey), nodes: [own, ...peers.filter(Boolean)] };
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
      // Valid messages seen for the first time are passed on to our peers, so validators that are
      // not directly connected (e.g. an outside validator that only knows rpc.argeni.io) still hear
      // each other.
      const id = typeof body?.signature === 'string' ? `${body.type}:${body.signature.slice(0, 128)}` : body?.type === 'commit' ? `commit:${body.block?.hash}` : null;
      if (id && this.relayed.has(id)) return send(res, 200, { ok: true, known: true });
      const result = this.consensus ? this.consensus.handle(body) : (body?.type === 'commit' ? this.#acceptCommit(body) : { ok: true });
      if (result.ahead) this.sync();
      if (!result.ok) return send(res, 400, { error: result.error });
      if (id) {
        this.relayed.add(id);
        if (this.relayed.size > 20_000) this.relayed.delete(this.relayed.values().next().value);
        this.#broadcast('/consensus', body);
      }
      return send(res, 200, { ok: true });
    }
    if (parts[0] === 'faucet' && parts.length === 1) return this.#faucet(body, res, ip);
    if (parts[0] === 'peers' && parts.length === 1) {
      let url;
      try {
        url = new URL(body?.url);
      } catch {
        return send(res, 400, { error: 'url must be an http(s) URL' });
      }
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) return send(res, 400, { error: 'url must be a plain http(s) URL' });
      if (body.genesisHash !== chain.genesisHash) return send(res, 400, { error: 'different chain' });
      const peer = url.origin + url.pathname.replace(/\/$/, '');
      if (peer === this.publicUrl || peer === this.url || this.peers.includes(peer)) return send(res, 200, { ok: true, known: true });
      if (this.peers.length >= MAX_PEERS) return send(res, 503, { error: 'peer list full' });
      this.peers.push(peer);
      this.log(`new peer ${peer}`);
      return send(res, 200, { ok: true });
    }
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

const KEY_NAMES = { 'ml-dsa-87': 'ML-DSA-87', 'ml-dsa-65': 'ML-DSA-65', 'slh-dsa-256s': 'SLH-DSA-256s', 'slh-dsa-128s': 'SLH-DSA-128s', ed25519: 'Ed25519', multisig: 'multisig' };

function txFields(tx) {
  const keyType = keyTypeOf(tx.from);
  const base = { type: tx.type, keyType, from: addressFromPublicKey(tx.from), to: null, amount: '0', fee: tx.fee, nonce: tx.nonce, memo: '' };
  const ms = parseMultisig(tx.from);
  if (ms) base.multisig = `${ms.threshold} of ${ms.keys.length}`;
  switch (tx.type) {
    case 'migrate':
      return { ...base, toKeyType: keyTypeOf(tx.to), to: addressFromPublicKey(tx.to), memo: `Migration to a post-quantum (${KEY_NAMES[keyTypeOf(tx.to)]}) key` };
    case 'pq-commit':
      return { ...base, memo: 'Migration commitment to a post-quantum key', commitment: tx.commitment };
    case 'vest':
      return { ...base, to: tx.to, amount: tx.amount, memo: tx.memo || `Vesting grant: ${tx.lockMonths}-month lock, then ${tx.vestMonths} monthly unlocks`, lockMonths: tx.lockMonths, vestMonths: tx.vestMonths };
    case 'validator-join':
      return { ...base, to: addressFromPublicKey(tx.validator), amount: tx.amount, memo: 'Validator joins with stake' };
    case 'validator-bond':
      return { ...base, to: addressFromPublicKey(tx.validator), amount: tx.amount, memo: 'Adds stake to a validator' };
    case 'validator-leave':
      return { ...base, to: addressFromPublicKey(tx.validator), memo: 'Validator leaves; stake returns after unbonding' };
    case 'validator-unjail':
      return { ...base, to: addressFromPublicKey(tx.validator), memo: 'Validator returns from jail' };
    case 'evidence':
      return { ...base, to: addressFromPublicKey(tx.voteA.validator), memo: `Double-signing evidence at block ${tx.voteA.height}: validator slashed` };
    default:
      return { ...base, to: tx.to, amount: tx.amount, memo: tx.memo ?? '' };
  }
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

export async function fetchJson(url, { timeoutMs = 5_000, ...options } = {}) {
  const res = await fetch(url, { ...options, signal: AbortSignal.timeout(timeoutMs) });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}
