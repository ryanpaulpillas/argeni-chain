// Byzantine fault tolerant consensus, following the Tendermint algorithm
// (Buchman, Kwon, Milosevic 2018, "The latest gossip on BFT consensus", Algorithm 1).
//
// Each height runs in rounds. In round r the proposer for (height, r) proposes a block;
// validators PREVOTE for it (or nil), then PRECOMMIT once more than two thirds prevoted the
// same block. A block is final when more than two thirds PRECOMMIT it; those signatures are
// the commit certificate stored with the block. Locking on a prevoted block keeps two
// different blocks from ever being finalized at one height while at most f of the
// n >= 3f + 1 validators misbehave. If a round stalls, timeouts move everyone to the next
// round and the next proposer. Each finalized block is also gossiped with its certificate
// (a 'commit' message), so a validator that missed the votes can verify it and catch up.
import { sign, verify, publicKeyFromPrivate, isHex } from './crypto.js';
import { faultTolerance, voteSignBytes } from './chain.js';

const MAX_FUTURE_MESSAGES = 2_000;
const VOTE_TYPES = new Set(['prevote', 'precommit']);

export class Consensus {
  constructor({ chain, privateKey, broadcast, onDecide = () => {}, onEquivocation = () => {}, log = () => {} }) {
    this.chain = chain;
    this.privateKey = privateKey;
    this.me = publicKeyFromPrivate(privateKey);
    this.broadcast = broadcast;
    this.onDecide = onDecide;
    this.onEquivocation = onEquivocation; // (voteA, voteB): a validator signed two different blocks
    this.log = log;
    this.blockTimeMs = chain.genesis.blockTimeMs;
    this.running = false;
    this.timers = new Set();
    this.future = [];
    this.lastCommit = null;
  }

  start() {
    this.running = true;
    this.unsubscribe = this.chain.onCommit((block) => {
      if (block.header.height >= this.height) this.#enterHeight();
    });
    this.rebroadcastTimer = setInterval(() => this.#rebroadcast(), this.blockTimeMs * 2);
    this.#enterHeight();
  }

  stop() {
    this.running = false;
    this.unsubscribe?.();
    clearInterval(this.rebroadcastTimer);
    this.#clearTimers();
  }

  status() {
    return { height: this.height, round: this.round, step: this.step, lockedRound: this.lockedRound, validator: this.member };
  }

  // Entry point for messages from peers. Returns { ok, ahead } or { ok: false, error }.
  handle(msg) {
    if (!this.running) return { ok: false, error: 'consensus not running' };
    if (msg?.type === 'commit') return this.#handleCommit(msg);
    const tip = this.chain.tip;
    if (msg?.type === 'precommit' && tip && msg.height === tip.header.height && msg.blockHash === tip.hash) return this.#lateSignature(msg);
    const error = this.#check(msg);
    if (error) return { ok: false, error };
    if (msg.height < this.height) return { ok: true };
    if (msg.height > this.height) {
      if (msg.height === this.height + 1 && this.future.length < MAX_FUTURE_MESSAGES) this.future.push(msg);
      return { ok: true, ahead: true };
    }
    this.#store(msg);
    this.#evaluate();
    return { ok: true };
  }

  // A valid signature for the latest block that arrived after it was finalized (e.g. from a validator
  // reached through a relay) is still added to its certificate, so the next block's lastCommit records
  // the validator as online and it shares in that block's rewards.
  #lateSignature(msg) {
    const { tip, tipSigners } = this.chain;
    const precommits = tip.commit?.precommits;
    if (!precommits || msg.round !== tip.commit.round || !tipSigners?.includes(msg.validator)) return { ok: true };
    if (precommits.some((p) => p.validator === msg.validator)) return { ok: true, known: true };
    if (!verify(voteSignBytes(this.chain.genesis.chainId, msg), msg.signature, msg.validator)) return { ok: false, error: 'invalid signature' };
    precommits.push({ type: 'precommit', height: msg.height, round: msg.round, blockHash: msg.blockHash, validator: msg.validator, signature: msg.signature });
    return { ok: true };
  }

  // A finalized block from a peer; its quorum certificate is the authority, checked by addBlock.
  #handleCommit(msg) {
    const height = msg.block?.header?.height;
    if (!Number.isSafeInteger(height)) return { ok: false, error: 'malformed commit' };
    if (height <= this.chain.height) return { ok: true };
    if (height > this.chain.height + 1) return { ok: true, ahead: true };
    const result = this.chain.addBlock(msg.block);
    return result.ok ? { ok: true } : { ok: false, error: result.error };
  }

  // ---- height and round lifecycle ----

  #enterHeight() {
    this.#clearTimers();
    this.height = this.chain.height + 1;
    this.round = 0;
    this.step = 'wait'; // short pause between blocks, so empty blocks come at most every blockTimeMs
    this.lockedBlock = null;
    this.lockedRound = -1;
    this.validBlock = null;
    this.validRound = -1;
    this.proposals = new Map(); // round -> proposal
    this.blocks = new Map(); // block hash -> block (from proposals)
    this.votes = { prevote: new Map(), precommit: new Map() }; // round -> Map(validator -> vote)
    this.validity = new Map(); // block hash -> validateBlock result
    this.fired = new Set();
    this.own = [];
    // The validator set can change from one height to the next (staking, jailing, slashing).
    this.members = this.chain.validators;
    this.f = faultTolerance(this.members.size);
    this.q = this.chain.quorum;
    this.member = this.members.has(this.me); // a key that isn't (yet) a validator follows along without voting
    const pending = this.future.filter((m) => m.height === this.height);
    this.future = this.future.filter((m) => m.height > this.height);
    pending.filter((m) => !this.#check(m)).forEach((m) => this.#store(m)); // re-checked against this height's set
    const delay = Math.max(0, this.chain.tipTimestamp + this.blockTimeMs - this.chain.now());
    this.#schedule(delay, () => this.#waitForWork());
  }

  // With genesis.emptyBlockIntervalMs set, an idle chain doesn't make a block every blockTimeMs:
  // a height starts when there are transactions to include, another validator has started it,
  // or the interval has passed (a heartbeat block). Without it, every height starts right away.
  #waitForWork() {
    const idle = this.chain.genesis.emptyBlockIntervalMs ?? 0;
    const othersStarted = this.proposals.size > 0 || this.votes.prevote.size > 0 || this.votes.precommit.size > 0;
    if (!idle || othersStarted || this.chain.now() - this.chain.tipTimestamp >= idle || this.chain.hasPendingWork()) {
      this.#startRound(0);
      return;
    }
    this.#schedule(Math.min(250, this.blockTimeMs), () => this.#waitForWork());
  }

  #startRound(round) {
    this.round = round;
    this.step = 'propose';
    if (this.chain.proposerFor(this.height, round) === this.me) {
      const block = this.validBlock ?? this.chain.buildBlock(this.me);
      this.#send({ type: 'proposal', height: this.height, round, validRound: this.validRound, blockHash: block.hash, block });
    } else {
      const { height } = this;
      this.#schedule(this.#timeout(3, round), () => {
        if (this.height === height && this.round === round && this.step === 'propose') {
          this.#vote('prevote', null);
          this.#evaluate();
        }
      });
    }
    this.#evaluate();
  }

  // ---- the decision rules; re-run after every message and timeout ----

  #evaluate() {
    if (!this.running || this.step === 'wait') return;
    while (this.#applyOneRule()) {
      if (this.step === 'wait') return;
    }
  }

  #applyOneRule() {
    const r = this.round;

    // Decide: a quorum of precommits for a block we have, in any round.
    for (const [round, votes] of this.votes.precommit) {
      for (const hash of this.#hashesWithQuorum(votes)) {
        const block = this.blocks.get(hash);
        if (block && this.#valid(block)) {
          this.#decide(block, round, hash);
          return false;
        }
      }
    }

    // Catch up: f + 1 validators are already in a later round.
    for (const round of this.#laterRounds()) {
      this.#startRound(round);
      return true;
    }

    const proposal = this.proposals.get(r);
    const block = proposal?.block;

    if (proposal && this.step === 'propose') {
      if (proposal.validRound === -1) {
        const ok = this.#valid(block) && (this.lockedRound === -1 || this.lockedBlock.hash === block.hash);
        this.#vote('prevote', ok ? block.hash : null);
        return true;
      }
      if (proposal.validRound < r && this.#count('prevote', proposal.validRound, block.hash) >= this.q) {
        const ok = this.#valid(block) && (this.lockedRound <= proposal.validRound || this.lockedBlock?.hash === block.hash);
        this.#vote('prevote', ok ? block.hash : null);
        return true;
      }
    }

    if (this.step === 'prevote' && this.#total('prevote', r) >= this.q && this.#once(`prevote-timeout:${r}`)) {
      const { height } = this;
      this.#schedule(this.#timeout(1, r), () => {
        if (this.height === height && this.round === r && this.step === 'prevote') {
          this.#vote('precommit', null);
          this.#evaluate();
        }
      });
    }

    if (proposal && this.step !== 'propose' && !this.fired.has(`lock:${r}`)
      && this.#count('prevote', r, block.hash) >= this.q && this.#valid(block)) {
      this.fired.add(`lock:${r}`);
      if (this.step === 'prevote') {
        this.lockedBlock = block;
        this.lockedRound = r;
        this.#vote('precommit', block.hash);
      }
      this.validBlock = block;
      this.validRound = r;
      return true;
    }

    if (this.step === 'prevote' && this.#count('prevote', r, null) >= this.q) {
      this.#vote('precommit', null);
      return true;
    }

    if (this.#total('precommit', r) >= this.q && this.#once(`precommit-timeout:${r}`)) {
      const { height } = this;
      this.#schedule(this.#timeout(1, r), () => {
        if (this.height === height && this.round === r) this.#startRound(r + 1);
      });
    }
    return false;
  }

  #decide(block, round, hash) {
    const precommits = [...this.votes.precommit.get(round).values()].filter((v) => v.blockHash === hash);
    const committed = { header: block.header, txs: block.txs, lastCommit: block.lastCommit ?? null, hash: block.hash, commit: { round, precommits } };
    const { state } = this.validity.get(hash);
    if (this.chain.height + 1 !== this.height) return this.#enterHeight();
    this.log(`committed block ${this.height} (${block.txs.length} txs, round ${round}, ${precommits.length}/${this.members.size} signatures) ${hash.slice(0, 12)}`);
    this.chain.commitBlock(committed, state); // triggers #enterHeight through the commit listener
    this.lastCommit = { type: 'commit', block: committed };
    this.broadcast(this.lastCommit);
    this.onDecide(committed);
  }

  // ---- messages ----

  #vote(type, blockHash) {
    this.step = type;
    if (!this.member) return;
    this.#send({ type, height: this.height, round: this.round, blockHash });
  }

  #send(fields) {
    const msg = { ...fields, validator: this.me };
    msg.signature = sign(voteSignBytes(this.chain.genesis.chainId, msg), this.privateKey);
    this.own.push(msg);
    this.#store(msg);
    this.broadcast(msg);
  }

  #rebroadcast() {
    if (!this.running) return;
    for (const msg of this.own) this.broadcast(msg);
    if (this.lastCommit) this.broadcast(this.lastCommit);
  }

  // Stateless checks: shape, membership, proposer for the round, signature.
  #check(msg) {
    if (!msg || typeof msg !== 'object') return 'message must be an object';
    if (msg.type !== 'proposal' && !VOTE_TYPES.has(msg.type)) return 'unknown message type';
    if (!Number.isSafeInteger(msg.height) || msg.height < 1 || !Number.isSafeInteger(msg.round) || msg.round < 0) return 'bad height or round';
    if (msg.height === this.height ? !this.members.has(msg.validator) : !this.chain.validators.has(msg.validator)) return 'sender is not a validator';
    if (msg.type === 'proposal') {
      if (msg.validator !== this.chain.proposerFor(msg.height, msg.round)) return 'sender is not the proposer for this round';
      if (!Number.isSafeInteger(msg.validRound) || msg.validRound < -1 || msg.validRound >= msg.round) return 'bad validRound';
      if (!msg.block || msg.block.hash !== msg.blockHash) return 'proposal block does not match blockHash';
    }
    if (msg.blockHash !== null && !isHex(msg.blockHash, 32)) return 'bad blockHash';
    if (msg.type === 'proposal' && msg.blockHash === null) return 'proposal needs a block';
    if (!verify(voteSignBytes(this.chain.genesis.chainId, msg), msg.signature, msg.validator)) return 'invalid signature';
    return null;
  }

  // Keeps the first message per (type, round, validator); later conflicting ones are ignored.
  #store(msg) {
    if (msg.type === 'proposal') {
      const first = this.proposals.get(msg.round);
      if (first && first.blockHash !== msg.blockHash) this.onEquivocation(first, msg);
      if (first) return;
      const block = { header: msg.block.header, txs: msg.block.txs, lastCommit: msg.block.lastCommit ?? null, hash: msg.block.hash };
      this.proposals.set(msg.round, { ...msg, block });
      this.blocks.set(block.hash, block);
      return;
    }
    const byRound = this.votes[msg.type];
    if (!byRound.has(msg.round)) byRound.set(msg.round, new Map());
    const votes = byRound.get(msg.round);
    const first = votes.get(msg.validator);
    if (!first) votes.set(msg.validator, msg);
    else if (first.blockHash !== msg.blockHash && first.blockHash !== null && msg.blockHash !== null) this.onEquivocation(first, msg);
  }

  // ---- helpers ----

  #valid(block) {
    if (!this.validity.has(block.hash)) this.validity.set(block.hash, this.chain.validateBlock(block));
    return Boolean(this.validity.get(block.hash).state);
  }

  #count(type, round, blockHash) {
    let n = 0;
    for (const vote of this.votes[type].get(round)?.values() ?? []) if (vote.blockHash === blockHash) n++;
    return n;
  }

  #total(type, round) {
    return this.votes[type].get(round)?.size ?? 0;
  }

  #hashesWithQuorum(votes) {
    const counts = new Map();
    for (const vote of votes.values()) {
      if (vote.blockHash !== null) counts.set(vote.blockHash, (counts.get(vote.blockHash) ?? 0) + 1);
    }
    return [...counts].filter(([, n]) => n >= this.q).map(([hash]) => hash);
  }

  #laterRounds() {
    const senders = new Map();
    const note = (round, validator) => {
      if (round <= this.round) return;
      if (!senders.has(round)) senders.set(round, new Set());
      senders.get(round).add(validator);
    };
    for (const p of this.proposals.values()) note(p.round, p.validator);
    for (const type of VOTE_TYPES) for (const [round, votes] of this.votes[type]) for (const v of votes.keys()) note(round, v);
    return [...senders].filter(([, s]) => s.size >= this.f + 1).map(([round]) => round).sort((a, b) => a - b);
  }

  #once(key) {
    if (this.fired.has(key)) return false;
    this.fired.add(key);
    return true;
  }

  // Timeouts grow with the round so a slow network eventually gets enough time.
  #timeout(multiple, round) {
    return this.blockTimeMs * multiple + Math.floor((this.blockTimeMs * round) / 2);
  }

  #schedule(ms, fn) {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      if (this.running) fn();
    }, ms);
    this.timers.add(timer);
  }

  #clearTimers() {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }
}
