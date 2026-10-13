// Chain state machine: genesis, block building and validation, commit certificates,
// mempool and persistence. Agreement on which block comes next is in consensus.js; a block
// joins the chain only with a commit certificate signed by a quorum of validators.
import fs from 'node:fs';
import path from 'node:path';
import { addressFromPublicKey, canonical, hashObject, isAddress, isPublicKey, keyTypeOf, merkleRoot, verify, KEY_TYPES } from './crypto.js';
import { checkTx, txHash } from './tx.js';
import { State, migrationError } from './state.js';
import { isUnits } from './coin.js';

const MAX_MEMPOOL = 10_000;
export const MAX_CLOCK_DRIFT_MS = 10_000;

// Byzantine fault tolerance: with n validators, up to f = floor((n - 1) / 3) may be faulty or
// offline. Decisions need more than two thirds of the validators.
export function faultTolerance(n) {
  return Math.floor((n - 1) / 3);
}

export function quorum(n) {
  return Math.floor((2 * n) / 3) + 1;
}

// The exact bytes a validator signs for a vote or proposal.
export function voteSignBytes(chainId, { type, height, round, blockHash, validRound }) {
  return canonical({ chainId, type, height, round, blockHash, ...(type === 'proposal' ? { validRound } : {}) });
}

export function validateGenesis(genesis) {
  const errors = [];
  if (typeof genesis.chainId !== 'string' || !genesis.chainId) errors.push('chainId');
  if (!Number.isSafeInteger(genesis.timestamp)) errors.push('timestamp');
  if (!Number.isSafeInteger(genesis.blockTimeMs) || genesis.blockTimeMs < 20) errors.push('blockTimeMs');
  if (!Number.isSafeInteger(genesis.maxTxsPerBlock) || genesis.maxTxsPerBlock < 1) errors.push('maxTxsPerBlock');
  if (!isUnits(genesis.minFee)) errors.push('minFee');
  if (!isUnits(genesis.blockReward)) errors.push('blockReward');
  if (!isUnits(genesis.maxSupply)) errors.push('maxSupply');
  if (genesis.emptyBlockIntervalMs !== undefined && (!Number.isSafeInteger(genesis.emptyBlockIntervalMs) || genesis.emptyBlockIntervalMs < 0)) errors.push('emptyBlockIntervalMs');
  if (!genesis.coin || typeof genesis.coin.symbol !== 'string' || !Number.isSafeInteger(genesis.coin.decimals)) errors.push('coin');
  const v = genesis.validators;
  if (!Array.isArray(v) || !v.length || !v.every(isPublicKey) || new Set(v).size !== v.length) errors.push('validators');
  if (genesis.ed25519SunsetHeight !== undefined && (!Number.isSafeInteger(genesis.ed25519SunsetHeight) || genesis.ed25519SunsetHeight < 1)) errors.push('ed25519SunsetHeight');
  if (genesis.retiredKeyTypes !== undefined && (typeof genesis.retiredKeyTypes !== 'object' || Array.isArray(genesis.retiredKeyTypes)
    || !Object.entries(genesis.retiredKeyTypes).every(([type, h]) => KEY_TYPES.includes(type) && Number.isSafeInteger(h) && h >= 1))) errors.push('retiredKeyTypes');
  if (genesis.maxBlockBytes !== undefined && (!Number.isSafeInteger(genesis.maxBlockBytes) || genesis.maxBlockBytes < 100_000)) errors.push('maxBlockBytes');
  if (!genesis.alloc || !Object.entries(genesis.alloc).every(([a, amt]) => isAddress(a) && isUnits(amt))) {
    errors.push('alloc');
  } else if (isUnits(genesis.maxSupply)) {
    const total = Object.values(genesis.alloc).reduce((sum, amt) => sum + BigInt(amt), 0n);
    if (total > BigInt(genesis.maxSupply)) errors.push('alloc exceeds maxSupply');
  }
  if (errors.length) throw new Error(`invalid genesis: ${errors.join(', ')}`);
}

// Algorithm retirement: genesis.retiredKeyTypes maps a key type to the block height from which it is
// retired (genesis.ed25519SunsetHeight is the older spelling for Ed25519). A retired key may only be
// used to migrate its account to a key type that is still active.
export function retiredAt(genesis, type) {
  return genesis.retiredKeyTypes?.[type] ?? (type === 'ed25519' ? genesis.ed25519SunsetHeight : undefined);
}

// Returns an error string or null.
export function sunsetError(genesis, tx, height) {
  const sunset = retiredAt(genesis, keyTypeOf(tx.from));
  if (!sunset || height < sunset || tx.type === 'migrate') return null;
  return `${keyTypeOf(tx.from)} keys were retired at block ${sunset}; migrate this account to an active post-quantum key`;
}

// Byte size of a transaction as it travels and is stored (bounds block size, since hash-based
// signatures are tens of kilobytes).
const DEFAULT_MAX_BLOCK_BYTES = 8_000_000;
const txBytes = (tx) => Buffer.byteLength(JSON.stringify(tx));

export class Chain {
  constructor(genesis, { dataDir = null, now = () => Date.now() } = {}) {
    validateGenesis(genesis);
    this.genesis = genesis;
    this.genesisHash = hashObject(genesis);
    this.validators = new Set(genesis.validators);
    this.quorum = quorum(genesis.validators.length);
    this.dataDir = dataDir;
    this.now = now;
    this.blocks = [];
    this.state = State.fromAlloc(genesis.alloc);
    this.txIndex = new Map(); // tx hash -> block height
    this.addressIndex = new Map(); // address -> tx hashes sent or received, oldest first
    this.mempool = new Map(); // tx hash -> tx
    this.listeners = new Set();
    if (dataDir) this.#load();
  }

  get height() {
    return this.blocks.length;
  }

  get tip() {
    return this.blocks.at(-1) ?? null;
  }

  get tipHash() {
    return this.tip ? this.tip.hash : this.genesisHash;
  }

  get tipTimestamp() {
    return this.tip ? this.tip.header.timestamp : this.genesis.timestamp;
  }

  // Validator that proposes in a given height and round; rotates so a silent proposer is skipped next round.
  proposerFor(height, round) {
    return this.genesis.validators[(height + round) % this.genesis.validators.length];
  }

  getBlock(height) {
    return height >= 1 && height <= this.height ? this.blocks[height - 1] : null;
  }

  // Confirmed transaction by hash, with the block it is in.
  getTx(hash) {
    const height = this.txIndex.get(hash);
    if (height === undefined) return null;
    const block = this.getBlock(height);
    return { tx: block.txs.find((t) => txHash(t) === hash), block };
  }

  onCommit(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // Pending nonce for an address: confirmed nonce plus its transactions waiting in the mempool.
  pendingNonce(address) {
    let nonce = this.state.get(address).nonce;
    const pending = new Set();
    for (const tx of this.mempool.values()) {
      if (addressFromPublicKey(tx.from) === address) pending.add(tx.nonce);
    }
    while (pending.has(nonce)) nonce++;
    return nonce;
  }

  addTx(tx) {
    const error = checkTx(tx, this.genesis) ?? sunsetError(this.genesis, tx, this.height + 1);
    if (error) return { ok: false, error };
    const hash = txHash(tx);
    if (this.mempool.has(hash) || this.txIndex.has(hash)) return { ok: true, hash, known: true };
    const from = addressFromPublicKey(tx.from);
    const sender = this.state.get(from);
    if (sender.migratedTo) return { ok: false, error: `this account was migrated to ${sender.migratedTo}; use the new post-quantum key` };
    if (tx.type === 'migrate') {
      const policyError = migrationError(sender, tx, this.migrationPolicy(this.height + 1));
      if (policyError) return { ok: false, error: policyError };
    }
    if (tx.type === 'transfer' && this.state.get(tx.to).migratedTo) {
      return { ok: false, error: `the recipient migrated to ${this.state.get(tx.to).migratedTo}; send there instead` };
    }
    if (tx.nonce < sender.nonce) return { ok: false, error: 'nonce already used' };
    for (const pending of this.mempool.values()) {
      if (pending.from === tx.from && pending.nonce === tx.nonce) return { ok: false, error: 'a transaction with this nonce is already pending' };
    }
    if (this.mempool.size >= MAX_MEMPOOL) return { ok: false, error: 'mempool full' };
    this.mempool.set(hash, tx);
    return { ok: true, hash, known: false };
  }

  // Inputs to the migration security rules (state.js migrationError) for a block at `height`.
  migrationPolicy(height) {
    return { height, retiredAt: (type) => retiredAt(this.genesis, type) };
  }

  // True if at least one pending transaction could go into the next block right now.
  hasPendingWork() {
    if (!this.mempool.size) return false;
    for (const tx of this.mempool.values()) {
      try {
        this.state.clone().applyTx(tx, addressFromPublicKey(tx.from), this.migrationPolicy(this.height + 1));
        return true;
      } catch {
        // not applicable yet (e.g. waiting for an earlier nonce)
      }
    }
    return false;
  }

  // Builds (but does not commit) the next block from the mempool, proposed by `proposer`.
  buildBlock(proposer) {
    const proposerAddress = addressFromPublicKey(proposer);
    const state = this.state.clone();
    const included = [];
    let bytes = 0;
    const candidates = [...this.mempool.values()].sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.nonce - b.nonce));
    for (const tx of candidates) {
      if (included.length >= this.genesis.maxTxsPerBlock) break;
      if (bytes + txBytes(tx) > (this.genesis.maxBlockBytes ?? DEFAULT_MAX_BLOCK_BYTES)) continue;
      if (sunsetError(this.genesis, tx, this.height + 1)) continue;
      const attempt = state.clone();
      try {
        attempt.applyTx(tx, proposerAddress, this.migrationPolicy(this.height + 1));
      } catch {
        continue;
      }
      state.accounts = attempt.accounts;
      included.push(tx);
      bytes += txBytes(tx);
    }
    state.mint(proposerAddress, BigInt(this.genesis.blockReward), BigInt(this.genesis.maxSupply));
    const header = {
      chainId: this.genesis.chainId,
      height: this.height + 1,
      timestamp: Math.max(this.now(), this.tipTimestamp + 1),
      prevHash: this.tipHash,
      txRoot: merkleRoot(included.map(txHash)),
      stateRoot: state.root(),
      proposer,
    };
    return { header, txs: included, hash: hashObject(header) };
  }

  // Checks a proposed block against the current tip. Returns { state } or { error }.
  validateBlock(block, { checkTime = true } = {}) {
    if (!block || typeof block !== 'object' || !block.header || !Array.isArray(block.txs)) return { error: 'malformed block' };
    const { header } = block;
    if (header.chainId !== this.genesis.chainId) return { error: 'wrong chainId' };
    if (header.height !== this.height + 1) return { error: `wrong height: expected ${this.height + 1}, got ${header.height}` };
    if (header.prevHash !== this.tipHash) return { error: 'prevHash does not match tip' };
    if (!Number.isSafeInteger(header.timestamp) || header.timestamp <= this.tipTimestamp) return { error: 'timestamp not after parent' };
    if (checkTime && header.timestamp > this.now() + MAX_CLOCK_DRIFT_MS) return { error: 'block is from the future' };
    if (!this.validators.has(header.proposer)) return { error: 'proposer is not a validator' };
    if (block.hash !== hashObject(header)) return { error: 'hash does not match header' };
    if (block.txs.length > this.genesis.maxTxsPerBlock) return { error: 'too many transactions' };
    if (block.txs.reduce((sum, tx) => sum + txBytes(tx), 0) > (this.genesis.maxBlockBytes ?? DEFAULT_MAX_BLOCK_BYTES)) return { error: 'block too large' };
    if (header.txRoot !== merkleRoot(block.txs.map(txHash))) return { error: 'txRoot mismatch' };

    const proposerAddress = addressFromPublicKey(header.proposer);
    const state = this.state.clone();
    for (const tx of block.txs) {
      const error = checkTx(tx, this.genesis) ?? sunsetError(this.genesis, tx, header.height);
      if (error) return { error: `invalid transaction: ${error}` };
      try {
        state.applyTx(tx, proposerAddress, this.migrationPolicy(header.height));
      } catch (err) {
        return { error: `invalid transaction: ${err.message}` };
      }
    }
    state.mint(proposerAddress, BigInt(this.genesis.blockReward), BigInt(this.genesis.maxSupply));
    if (header.stateRoot !== state.root()) return { error: 'stateRoot mismatch' };
    return { state };
  }

  // A commit certificate is a set of precommit votes for this block from a quorum of validators.
  verifyCommit(block) {
    const commit = block.commit;
    if (!commit || !Number.isSafeInteger(commit.round) || commit.round < 0 || !Array.isArray(commit.precommits)) return 'missing commit certificate';
    const signers = new Set();
    for (const vote of commit.precommits) {
      if (!vote || !this.validators.has(vote.validator) || signers.has(vote.validator)) continue;
      if (vote.type !== 'precommit' || vote.height !== block.header?.height || vote.round !== commit.round || vote.blockHash !== block.hash) continue;
      if (!verify(voteSignBytes(this.genesis.chainId, vote), vote.signature, vote.validator)) continue;
      signers.add(vote.validator);
    }
    return signers.size >= this.quorum ? null : `commit has ${signers.size} valid signatures, needs ${this.quorum}`;
  }

  // Adds a finalized block (with commit certificate), e.g. one received while syncing.
  addBlock(block) {
    const certError = this.verifyCommit(block);
    if (certError) return { ok: false, error: certError };
    const result = this.validateBlock(block, { checkTime: false });
    if (result.error) return { ok: false, error: result.error };
    this.commitBlock(block, result.state);
    return { ok: true };
  }

  // Appends a block whose certificate and state were already checked by the caller.
  commitBlock(block, state, { persist = true } = {}) {
    this.blocks.push(block);
    this.state = state;
    for (const tx of block.txs) {
      const hash = txHash(tx);
      this.txIndex.set(hash, block.header.height);
      const to = tx.type === 'migrate' ? addressFromPublicKey(tx.to) : tx.to;
      for (const address of new Set([addressFromPublicKey(tx.from), to].filter(Boolean))) {
        if (!this.addressIndex.has(address)) this.addressIndex.set(address, []);
        this.addressIndex.get(address).push(hash);
      }
      this.mempool.delete(hash);
    }
    for (const [hash, tx] of this.mempool) {
      if (tx.nonce < this.state.get(addressFromPublicKey(tx.from)).nonce) this.mempool.delete(hash);
    }
    if (persist && this.dataDir) {
      const file = path.join(this.dataDir, 'blocks', `${String(block.header.height).padStart(10, '0')}.json`);
      fs.writeFileSync(file, JSON.stringify(block));
    }
    for (const listener of this.listeners) listener(block);
  }

  // Replays stored blocks through full validation, so a tampered data dir is rejected.
  #load() {
    const dir = path.join(this.dataDir, 'blocks');
    fs.mkdirSync(dir, { recursive: true });
    const markerFile = path.join(this.dataDir, 'genesis-hash');
    if (fs.existsSync(markerFile)) {
      const stored = fs.readFileSync(markerFile, 'utf8').trim();
      if (stored !== this.genesisHash) throw new Error(`data dir ${this.dataDir} belongs to a different genesis`);
    } else {
      fs.writeFileSync(markerFile, this.genesisHash);
    }
    for (const file of fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort()) {
      const block = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
      const certError = this.verifyCommit(block);
      const result = certError ? { error: certError } : this.validateBlock(block, { checkTime: false });
      if (result.error) throw new Error(`stored block ${file} is invalid: ${result.error}`);
      this.commitBlock(block, result.state, { persist: false });
    }
  }
}
