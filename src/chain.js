// Chain state machine: genesis, block building and validation, commit certificates,
// mempool and persistence. Agreement on which block comes next is in consensus.js; a block
// joins the chain only with a commit certificate signed by a quorum of validators.
import fs from 'node:fs';
import path from 'node:path';
import { addressFromPublicKey, canonical, hashObject, isAddress, isPublicKey, keyTypeOf, memberKeyTypes, merkleRoot, verify, KEY_TYPES, PQ_KEY_TYPES } from './crypto.js';
import { checkTx, txHash } from './tx.js';
import { State, migrationError, stakingParams, MAX_GRANTS } from './state.js';
export { State };
import { isUnits } from './coin.js';

const MAX_MEMPOOL = 10_000;
const MAX_PENDING_PER_ACCOUNT = 32;
// What a pending transaction can take from its sender's spendable balance.
const pendingCost = (t) => BigInt(t.fee) + (['transfer', 'vest', 'validator-join', 'validator-bond'].includes(t.type) ? BigInt(t.amount) : 0n);
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
  if (genesis.staking !== undefined) {
    const st = genesis.staking;
    if (st && st.minVestAmount !== undefined && !isUnits(st.minVestAmount)) errors.push('staking.minVestAmount');
    const ints = ['maxValidators', 'minValidators', 'unbondingMs', 'jailMs', 'downtimeBlocks', 'downtimeSlashBps', 'doubleSignSlashBps', 'evidenceMaxAgeBlocks'];
    if (typeof st !== 'object' || Array.isArray(st) || Object.keys(st).some((k) => k !== 'minStake' && k !== 'minVestAmount' && !ints.includes(k))
      || (st.minStake !== undefined && !isUnits(st.minStake)) || ints.some((k) => st[k] !== undefined && (!Number.isSafeInteger(st[k]) || st[k] < 0))
      || (st.downtimeSlashBps ?? 0) > 10_000 || (st.doubleSignSlashBps ?? 0) > 10_000 || st.maxValidators === 0 || st.downtimeBlocks === 0) errors.push('staking');
  }
  if (genesis.rewards !== undefined) {
    const r = genesis.rewards;
    if (!r || typeof r !== 'object' || !Array.isArray(r.years) || !r.years.length || r.years.length > 20 || !r.years.every(isUnits)
      || (r.start !== undefined && !Number.isSafeInteger(r.start)) || Object.keys(r).some((k) => k !== 'years' && k !== 'start')) errors.push('rewards (years: amounts per year, optional start)');
  }
  if (Array.isArray(v) && v.some((k) => keyTypeOf(k) === 'multisig')) errors.push('validators (a validator needs a single key)');
  if (genesis.vesting !== undefined) {
    const ok = typeof genesis.vesting === 'object' && !Array.isArray(genesis.vesting) && Object.entries(genesis.vesting).every(([a, grants]) => {
      if (!Array.isArray(grants) || !grants.length || grants.length > MAX_GRANTS) return false;
      const fine = grants.every((g) => g && isUnits(g.amount) && (g.atStart === undefined || (isUnits(g.atStart) && BigInt(g.atStart) <= BigInt(g.amount)))
        && Number.isSafeInteger(g.lockMonths ?? 0) && (g.lockMonths ?? 0) >= 0 && Number.isSafeInteger(g.vestMonths ?? 0) && (g.vestMonths ?? 0) >= 0
        && (g.start === undefined || Number.isSafeInteger(g.start)));
      const total = fine ? grants.reduce((sum, g) => sum + BigInt(g.amount), 0n) : 0n;
      return fine && isUnits(genesis.alloc?.[a] ?? '') && total <= BigInt(genesis.alloc[a]);
    });
    if (!ok) errors.push('vesting (each grant needs amount, lockMonths, vestMonths, and grants may not exceed the address\'s alloc)');
  }
  if (!genesis.alloc || !Object.entries(genesis.alloc).every(([a, amt]) => isAddress(a) && isUnits(amt))) {
    errors.push('alloc');
  } else if (isUnits(genesis.maxSupply)) {
    const pool = Array.isArray(genesis.rewards?.years) && genesis.rewards.years.every(isUnits) ? genesis.rewards.years.reduce((sum, amt) => sum + BigInt(amt), 0n) : 0n;
    const total = Object.values(genesis.alloc).reduce((sum, amt) => sum + BigInt(amt), 0n) + pool;
    if (total > BigInt(genesis.maxSupply)) errors.push('alloc exceeds maxSupply (counting the validator reward pool)');
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
  if (tx.type === 'migrate') return null;
  for (const type of memberKeyTypes(tx.from)) {
    const sunset = retiredAt(genesis, type);
    if (sunset && height >= sunset) return `${type} keys were retired at block ${sunset}; migrate this account to an active post-quantum key`;
  }
  if (tx.type === 'validator-join') {
    const sunset = retiredAt(genesis, keyTypeOf(tx.validator));
    if (sunset && height >= sunset) return `${keyTypeOf(tx.validator)} keys were retired at block ${sunset}; use another validator key type`;
  }
  return null;
}

// Validator signatures in a commit that are valid for `block` under `validatorSet`: one per
// validator, in a fixed order. Returns [] for a missing or malformed commit.
export function validPrecommits(genesis, block, validatorSet, commit = block.commit) {
  if (!commit || !Number.isSafeInteger(commit.round) || commit.round < 0 || !Array.isArray(commit.precommits)) return [];
  const members = new Set(validatorSet);
  const seen = new Map();
  for (const vote of commit.precommits) {
    if (!vote || !members.has(vote.validator) || seen.has(vote.validator)) continue;
    if (vote.type !== 'precommit' || vote.height !== block.header?.height || vote.round !== commit.round || vote.blockHash !== block.hash) continue;
    if (!verify(voteSignBytes(genesis.chainId, vote), vote.signature, vote.validator)) continue;
    seen.set(vote.validator, vote);
  }
  return validatorSet.filter((k) => seen.has(k)).map((k) => seen.get(k));
}

// Byte size of a transaction as it travels and is stored (bounds block size, since hash-based
// signatures are tens of kilobytes).
const DEFAULT_MAX_BLOCK_BYTES = 8_000_000;
const txBytes = (tx) => Buffer.byteLength(JSON.stringify(tx));

export class Chain {
  constructor(genesis, { dataDir = null, now = () => Date.now(), snapshot = null } = {}) {
    validateGenesis(genesis);
    this.genesis = genesis;
    this.genesisHash = hashObject(genesis);
    this.params = stakingParams(genesis);
    this.dataDir = dataDir;
    this.now = now;
    this.base = 0; // height of the snapshot this node started from (0 = from genesis)
    this.baseBlock = null;
    this.blocks = [];
    this.state = State.fromGenesis(genesis);
    this.tipSigners = null; // the validator set that signed the tip block
    this.txIndex = new Map(); // tx hash -> block height
    this.addressIndex = new Map(); // address -> tx hashes sent or received, oldest first
    this.mempool = new Map(); // tx hash -> tx
    this.listeners = new Set();
    if (dataDir) {
      fs.mkdirSync(dataDir, { recursive: true });
      const file = path.join(dataDir, 'snapshot.json');
      if (!snapshot && fs.existsSync(file)) snapshot = JSON.parse(fs.readFileSync(file, 'utf8'));
      else if (snapshot) fs.writeFileSync(file, JSON.stringify(snapshot));
    }
    if (snapshot) this.#restore(snapshot);
    if (dataDir) this.#load();
  }

  get height() {
    return this.base + this.blocks.length;
  }

  get tip() {
    return this.blocks.at(-1) ?? this.baseBlock;
  }

  get tipHash() {
    return this.tip ? this.tip.hash : this.genesisHash;
  }

  get tipTimestamp() {
    return this.tip ? this.tip.header.timestamp : this.genesis.timestamp;
  }

  // The validators that sign the next block, in a fixed order (genesis validators first, then by
  // join time). Changes when validators join, leave, are jailed or slashed.
  get validatorList() {
    return this.state.activeValidators();
  }

  get validators() {
    return new Set(this.validatorList);
  }

  get quorum() {
    return quorum(this.validatorList.length);
  }

  // Validator that proposes in a given height and round; rotates so a silent proposer is skipped next round.
  proposerFor(height, round) {
    const list = this.validatorList;
    return list[(height + round) % list.length];
  }

  getBlock(height) {
    if (height === this.base && this.baseBlock) return this.baseBlock;
    return height > this.base && height <= this.height ? this.blocks[height - this.base - 1] : null;
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

  // Rules context for the block at `height` with `timestamp`.
  ctx(height, timestamp, proposer, state = this.state) {
    return {
      height, timestamp, params: this.params, retiredAt: (type) => retiredAt(this.genesis, type), rewardAddress: state.rewardAddress(proposer),
      rewards: this.genesis.rewards ?? null, genesisTimestamp: this.genesis.timestamp,
    };
  }

  // Inputs to the migration security rules (state.js migrationError) for a block at `height`.
  migrationPolicy(height) {
    return { height, retiredAt: (type) => retiredAt(this.genesis, type) };
  }

  #checkTx(tx, height) {
    return checkTx(tx, this.genesis, { voteBytes: (vote) => voteSignBytes(this.genesis.chainId, vote) }) ?? sunsetError(this.genesis, tx, height);
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
    const error = this.#checkTx(tx, this.height + 1);
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
    if ((tx.type === 'transfer' || tx.type === 'vest') && this.state.get(tx.to).migratedTo) {
      return { ok: false, error: `the recipient migrated to ${this.state.get(tx.to).migratedTo}; send there instead` };
    }
    if (tx.nonce < sender.nonce) return { ok: false, error: 'nonce already used' };
    // Rules that depend only on the current state (vesting locks, staking) are reported right away.
    if (tx.nonce === sender.nonce) {
      try {
        this.state.clone().applyTx(tx, this.ctx(this.height + 1, Math.max(this.now(), this.tipTimestamp + 1), this.validatorList[0]));
      } catch (err) {
        return { ok: false, error: err.message };
      }
    }
    for (const pending of this.mempool.values()) {
      if (pending.from === tx.from && pending.nonce === tx.nonce) return { ok: false, error: 'a transaction with this nonce is already pending' };
    }
    // An account can only queue what it can pay for, so an empty account cannot fill the mempool.
    const mine = [...this.mempool.values()].filter((p) => p.from === tx.from);
    if (mine.length >= MAX_PENDING_PER_ACCOUNT) return { ok: false, error: `this account already has ${MAX_PENDING_PER_ACCOUNT} pending transactions; wait for some to be included` };
    const queued = mine.reduce((sum, p) => sum + pendingCost(p), 0n) + pendingCost(tx);
    if (this.state.spendable(from, Math.max(this.now(), this.tipTimestamp + 1)) < queued) return { ok: false, error: 'insufficient balance for this and the account\'s pending transactions' };
    if (this.mempool.size >= MAX_MEMPOOL) return { ok: false, error: 'mempool full' };
    this.mempool.set(hash, tx);
    return { ok: true, hash, known: false };
  }

  // True if at least one pending transaction could go into the next block right now.
  hasPendingWork() {
    if (!this.mempool.size) return false;
    const ctx = this.ctx(this.height + 1, Math.max(this.now(), this.tipTimestamp + 1), this.validatorList[0]);
    for (const tx of this.mempool.values()) {
      try {
        this.state.clone().applyTx(tx, ctx);
        return true;
      } catch {
        // not applicable yet (e.g. waiting for an earlier nonce)
      }
    }
    return false;
  }

  // The signatures for the tip block that the next block carries (they record who was online).
  #lastCommit() {
    if (!this.tip) return null;
    const precommits = validPrecommits(this.genesis, this.tip, this.tipSigners);
    return { round: this.tip.commit.round, precommits };
  }

  // State after a block's transactions: liveness from lastCommit, unbonding, block reward.
  #finishBlock(state, header, lastCommit) {
    const ctx = this.ctx(header.height, header.timestamp, header.proposer, state);
    const signers = lastCommit ? new Set(lastCommit.precommits.map((p) => p.validator)) : null;
    state.endBlock(ctx, { prevSet: this.tipSigners, signers });
    state.mint(ctx.rewardAddress, BigInt(this.genesis.blockReward), BigInt(this.genesis.maxSupply));
  }

  // Builds (but does not commit) the next block from the mempool, proposed by `proposer`.
  buildBlock(proposer) {
    const height = this.height + 1;
    const timestamp = Math.max(this.now(), this.tipTimestamp + 1);
    let state = this.state.clone();
    const ctx = this.ctx(height, timestamp, proposer, state);
    const included = [];
    const lastCommit = this.#lastCommit();
    let bytes = lastCommit ? txBytes(lastCommit) : 0;
    const candidates = [...this.mempool.values()].sort((a, b) => (a.from < b.from ? -1 : a.from > b.from ? 1 : a.nonce - b.nonce));
    for (const tx of candidates) {
      if (included.length >= this.genesis.maxTxsPerBlock) break;
      if (bytes + txBytes(tx) > (this.genesis.maxBlockBytes ?? DEFAULT_MAX_BLOCK_BYTES)) continue;
      if (this.#checkTx(tx, height)) continue;
      const attempt = state.clone();
      try {
        attempt.applyTx(tx, ctx);
      } catch {
        continue;
      }
      state = attempt;
      included.push(tx);
      bytes += txBytes(tx);
    }
    const header = {
      chainId: this.genesis.chainId,
      height,
      timestamp,
      prevHash: this.tipHash,
      txRoot: merkleRoot(included.map(txHash)),
      validatorsHash: hashObject(this.validatorList),
      lastCommitHash: lastCommit ? hashObject(lastCommit) : null,
      proposer,
    };
    this.#finishBlock(state, header, lastCommit);
    header.stateRoot = state.root();
    return { header, txs: included, lastCommit, hash: hashObject(header) };
  }

  // Checks a proposed block against the current tip. Returns { state } or { error }.
  validateBlock(block, { checkTime = true } = {}) {
    if (!block || typeof block !== 'object' || !block.header || !Array.isArray(block.txs)) return { error: 'malformed block' };
    const { header } = block;
    const lastCommit = block.lastCommit ?? null;
    if (header.chainId !== this.genesis.chainId) return { error: 'wrong chainId' };
    if (header.height !== this.height + 1) return { error: `wrong height: expected ${this.height + 1}, got ${header.height}` };
    if (header.prevHash !== this.tipHash) return { error: 'prevHash does not match tip' };
    if (!Number.isSafeInteger(header.timestamp) || header.timestamp <= this.tipTimestamp) return { error: 'timestamp not after parent' };
    if (checkTime && header.timestamp > this.now() + MAX_CLOCK_DRIFT_MS) return { error: 'block is from the future' };
    if (!this.validators.has(header.proposer)) return { error: 'proposer is not a validator' };
    if (block.hash !== hashObject(header)) return { error: 'hash does not match header' };
    if (header.validatorsHash !== hashObject(this.validatorList)) return { error: 'validatorsHash does not match the validator set' };
    if (block.txs.length > this.genesis.maxTxsPerBlock) return { error: 'too many transactions' };
    if (block.txs.reduce((sum, tx) => sum + txBytes(tx), 0) + (lastCommit ? txBytes(lastCommit) : 0) > (this.genesis.maxBlockBytes ?? DEFAULT_MAX_BLOCK_BYTES)) return { error: 'block too large' };
    if (header.txRoot !== merkleRoot(block.txs.map(txHash))) return { error: 'txRoot mismatch' };

    // The previous block's signatures: all valid, one per validator, at least a quorum.
    if (!this.tip) {
      if (lastCommit !== null || header.lastCommitHash !== null) return { error: 'the first block has no lastCommit' };
    } else {
      if (!lastCommit || header.lastCommitHash !== hashObject(lastCommit)) return { error: 'lastCommit missing or does not match lastCommitHash' };
      const valid = validPrecommits(this.genesis, this.tip, this.tipSigners, lastCommit);
      if (valid.length !== lastCommit.precommits.length || canonical(valid) !== canonical(lastCommit.precommits)) return { error: 'lastCommit has invalid, duplicate or unordered signatures' };
      if (valid.length < quorum(this.tipSigners.length)) return { error: 'lastCommit lacks a quorum' };
    }

    let state = this.state.clone();
    const ctx = this.ctx(header.height, header.timestamp, header.proposer, state);
    for (const tx of block.txs) {
      const error = this.#checkTx(tx, header.height);
      if (error) return { error: `invalid transaction: ${error}` };
      try {
        state.applyTx(tx, ctx);
      } catch (err) {
        return { error: `invalid transaction: ${err.message}` };
      }
    }
    this.#finishBlock(state, header, lastCommit);
    if (header.stateRoot !== state.root()) return { error: 'stateRoot mismatch' };
    if (!state.activeValidators().length) return { error: 'block would leave no validators' };
    return { state };
  }

  // A commit certificate is a set of precommit votes for this block from a quorum of validators.
  verifyCommit(block) {
    const n = validPrecommits(this.genesis, block, this.validatorList).length;
    if (!block.commit) return 'missing commit certificate';
    return n >= this.quorum ? null : `commit has ${n} valid signatures, needs ${this.quorum}`;
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
    this.tipSigners = this.validatorList;
    this.blocks.push(block);
    this.state = state;
    for (const tx of block.txs) {
      const hash = txHash(tx);
      this.txIndex.set(hash, block.header.height);
      const to = tx.type === 'migrate' ? addressFromPublicKey(tx.to) : tx.validator ? addressFromPublicKey(tx.validator) : tx.type === 'evidence' ? addressFromPublicKey(tx.voteA.validator) : tx.to;
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

  // ---- snapshots (fast sync) ----
  // A snapshot is the full state after a block, plus that block and the validator set that signed it.
  // It is checked against the block: hash, stateRoot, validatorsHash and a quorum of signatures. A new
  // node trusts one block hash (from a source it trusts, e.g. the explorer) instead of replaying
  // every block since genesis.

  snapshot() {
    if (!this.tip) throw new Error('no blocks yet');
    return { chainId: this.genesis.chainId, genesisHash: this.genesisHash, height: this.height, block: this.tip, signers: this.tipSigners, state: this.state.toJSON() };
  }

  static verifySnapshot(genesis, snap, trusted = null) {
    const error = (m) => { throw new Error(`invalid snapshot: ${m}`); };
    if (!snap || snap.genesisHash !== hashObject(genesis) || snap.chainId !== genesis.chainId) error('different chain');
    const { block, signers } = snap;
    if (!block?.header || block.header.height !== snap.height || block.hash !== hashObject(block.header)) error('block does not match');
    if (trusted && (trusted.height !== snap.height || trusted.hash !== block.hash)) error(`block ${snap.height} is not the trusted block`);
    if (!Array.isArray(signers) || !signers.length || hashObject(signers) !== block.header.validatorsHash) error('validator set does not match the block');
    if (validPrecommits(genesis, block, signers).length < quorum(signers.length)) error('block lacks a quorum of signatures');
    const state = State.fromJSON(snap.state);
    if (state.root() !== block.header.stateRoot) error('state does not match the block\'s stateRoot');
    return state;
  }

  #restore(snap) {
    this.state = Chain.verifySnapshot(this.genesis, snap);
    this.base = snap.height;
    this.baseBlock = snap.block;
    this.tipSigners = snap.signers;
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
      if (block.header?.height <= this.base) continue;
      const certError = this.verifyCommit(block);
      const result = certError ? { error: certError } : this.validateBlock(block, { checkTime: false });
      if (result.error) throw new Error(`stored block ${file} is invalid: ${result.error}`);
      this.commitBlock(block, result.state, { persist: false });
    }
  }
}
