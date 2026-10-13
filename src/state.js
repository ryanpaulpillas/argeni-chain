// Chain state: accounts, total supply and the validator registry.
//
// Account: balance (BigInt base units), nonce, an optional pqCommit (hash of the post-quantum address
// the account has committed to migrate to), after a migration migratedTo, and optional vesting grants
// (part of the balance that unlocks month by month and can't be spent before).
//
// Validator registry, in join order: { key, owner, stake, status, missed, jailedUntil?, unbondAt?,
// genesis? }. status is 'active' (in the set that signs blocks), 'jailed' (removed for missing too
// many blocks; can return with validator-unjail) or 'unbonding' (left or slashed; the stake returns to
// the owner when the unbonding period ends). Keys caught double-signing are banned for good.
// Every active validator has one vote; joining needs at least minStake bonded.
import { addressFromPublicKey, hashObject, keyTypeOf, sha256 } from './crypto.js';
import { migrationCommitment } from './tx.js';

// Average Gregorian month, so "12 months" means one year of block time.
export const MONTH_MS = 2_629_746_000;
const DAY_MS = 86_400_000;
export const MAX_GRANTS = 16;

// Staking and penalty settings: genesis.staking overrides any of these.
export function stakingParams(genesis) {
  const one = 10n ** BigInt(genesis.coin.decimals);
  const p = genesis.staking ?? {};
  return {
    minStake: BigInt(p.minStake ?? (100_000n * one).toString()),
    maxValidators: p.maxValidators ?? 100,
    minValidators: p.minValidators ?? Math.min(4, genesis.validators.length),
    unbondingMs: p.unbondingMs ?? 14 * DAY_MS,
    jailMs: p.jailMs ?? DAY_MS,
    downtimeBlocks: p.downtimeBlocks ?? 500, // missed in a row before jailing
    downtimeSlashBps: p.downtimeSlashBps ?? 10, // 0.1% of stake
    doubleSignSlashBps: p.doubleSignSlashBps ?? 500, // 5% of stake, and banned for good
    evidenceMaxAgeBlocks: p.evidenceMaxAgeBlocks ?? 100_000,
  };
}

// Amount of a grant still locked at time t (ms).
export function lockedAmount(grant, t) {
  const amount = BigInt(grant.amount);
  const atStart = BigInt(grant.atStart ?? '0');
  const months = Math.max(0, Math.floor((t - grant.start) / MONTH_MS));
  if (grant.vestMonths === 0) return months >= grant.lockMonths ? 0n : amount - atStart;
  const steps = Math.min(Math.max(months - grant.lockMonths, 0), grant.vestMonths);
  return amount - atStart - ((amount - atStart) * BigInt(steps)) / BigInt(grant.vestMonths);
}

export function totalLocked(account, t) {
  return (account.vesting ?? []).reduce((sum, g) => sum + lockedAmount(g, t), 0n);
}

// When the last grant of an account is fully unlocked (ms), or null.
export function vestingEnd(grant) {
  return grant.start + (grant.lockMonths + grant.vestMonths) * MONTH_MS;
}

// Migration security rules. `policy` = { height, retiredAt }: the block the tx goes into and a
// function giving the block height at which a key type is retired (or undefined). Returns an error
// string or null.
//  - If the account committed to a post-quantum key (pq-commit), it can only migrate to that key.
//    So even an attacker who later recovers the Ed25519 key with a quantum computer can't redirect
//    the funds: new commitments are refused after the sunset, and the old one can't be changed.
//  - After its key type is retired, an account without a commitment can migrate only if its public
//    key was never published (it never signed a transaction), so a quantum attacker had nothing to work on.
//  - A migration can't move funds onto a key type that is itself retired.
export function migrationError(account, tx, { height, retiredAt = () => undefined } = {}) {
  const from = addressFromPublicKey(tx.from);
  const target = addressFromPublicKey(tx.to);
  const targetRetired = retiredAt(keyTypeOf(tx.to));
  if (targetRetired && height >= targetRetired) return `${keyTypeOf(tx.to)} keys were retired at block ${targetRetired}; choose another post-quantum key type`;
  if (account.pqCommit) {
    return account.pqCommit === migrationCommitment(tx.chainId, from, target) ? null : 'this account committed to a different post-quantum key; it can only migrate to that key';
  }
  const sunset = retiredAt(keyTypeOf(tx.from));
  if (sunset && height >= sunset && account.nonce > 0) {
    return `this account's ${keyTypeOf(tx.from)} key was exposed and it made no migration commitment before block ${sunset}; it can't migrate safely`;
  }
  return null;
}

export class State {
  constructor(accounts = new Map(), supply = 0n, validators = [], banned = new Set()) {
    this.accounts = accounts;
    this.supply = supply;
    this.validators = validators;
    this.banned = banned;
  }

  static fromGenesis(genesis) {
    const state = new State();
    for (const [address, amount] of Object.entries(genesis.alloc)) {
      state.credit(address, BigInt(amount));
      state.supply += BigInt(amount);
    }
    for (const [address, grants] of Object.entries(genesis.vesting ?? {})) {
      const account = state.get(address);
      state.accounts.set(address, { ...account, vesting: grants.map((g) => normalizeGrant(g, genesis.timestamp)) });
    }
    state.validators = genesis.validators.map((key) => ({ key, owner: addressFromPublicKey(key), stake: 0n, status: 'active', missed: 0, genesis: true }));
    return state;
  }

  clone() {
    const copy = new Map();
    for (const [address, account] of this.accounts) copy.set(address, { ...account });
    return new State(copy, this.supply, this.validators.map((v) => ({ ...v })), new Set(this.banned));
  }

  get(address) {
    return this.accounts.get(address) ?? { balance: 0n, nonce: 0 };
  }

  // Balance that can be spent at time t (not locked by vesting).
  spendable(address, t) {
    const account = this.get(address);
    const free = account.balance - totalLocked(account, t);
    return free > 0n ? free : 0n;
  }

  credit(address, amount) {
    if (amount === 0n) return;
    const account = this.get(address);
    this.accounts.set(address, { ...account, balance: account.balance + amount });
  }

  // Creates new coins, never beyond maxSupply. Returns the amount actually minted.
  mint(address, amount, maxSupply) {
    const minted = amount < maxSupply - this.supply ? amount : maxSupply - this.supply;
    if (minted <= 0n) return 0n;
    this.credit(address, minted);
    this.supply += minted;
    return minted;
  }

  // ---- validators ----

  activeValidators() {
    return this.validators.filter((v) => v.status === 'active').map((v) => v.key);
  }

  validator(key) {
    return this.validators.find((v) => v.key === key) ?? null;
  }

  // Where a block proposer's fees and rewards go: its owner account.
  rewardAddress(proposerKey) {
    return this.validator(proposerKey)?.owner ?? addressFromPublicKey(proposerKey);
  }

  #slash(v, bps) {
    const cut = (v.stake * BigInt(bps)) / 10_000n;
    v.stake -= cut;
    this.supply -= cut; // slashed ARGENI is burned
    return cut;
  }

  // Liveness and unbonding, after a block's transactions. `prevSet` = the validators that had to sign
  // the previous block; `signers` = those whose signatures this block carries for it.
  endBlock(ctx, { prevSet = null, signers = null } = {}) {
    const p = ctx.params;
    if (prevSet && signers) {
      for (const key of prevSet) {
        const v = this.validator(key);
        if (!v || v.status !== 'active') continue;
        v.missed = signers.has(key) ? 0 : v.missed + 1;
        if (v.missed >= p.downtimeBlocks && this.activeValidators().length > p.minValidators) {
          this.#slash(v, p.downtimeSlashBps);
          v.status = 'jailed';
          v.jailedUntil = ctx.timestamp + p.jailMs;
          v.missed = 0;
        }
      }
    }
    for (const v of this.validators.filter((x) => x.status === 'unbonding' && ctx.timestamp >= x.unbondAt)) {
      this.credit(v.owner, v.stake);
      this.validators.splice(this.validators.indexOf(v), 1);
    }
  }

  // ---- transactions ----

  // Applies a transaction that already passed checkTx. Throws if the state rejects it.
  // ctx = { height, timestamp, retiredAt, params, rewardAddress }.
  applyTx(tx, ctx) {
    const from = addressFromPublicKey(tx.from);
    const sender = this.get(from);
    const fee = BigInt(tx.fee);
    const t = ctx.timestamp;
    if (sender.migratedTo) throw new Error(`account was migrated to ${sender.migratedTo}; use the new key`);
    if (tx.nonce !== sender.nonce) throw new Error(`bad nonce: expected ${sender.nonce}, got ${tx.nonce}`);
    const spend = (amount, what = 'insufficient balance') => {
      if (this.spendable(from, t) < amount + fee) {
        throw new Error(totalLocked(sender, t) > 0n && sender.balance >= amount + fee ? `${what}: part of this balance is still locked by vesting` : what);
      }
      const now = this.get(from);
      this.accounts.set(from, { ...now, balance: now.balance - amount - fee, nonce: now.nonce + 1 });
      this.credit(ctx.rewardAddress, fee);
    };
    const owned = () => {
      const v = this.validator(tx.validator);
      if (!v) throw new Error('unknown validator');
      if (v.owner !== from) throw new Error('only the validator\'s owner account can do this');
      return v;
    };
    const p = ctx.params;

    switch (tx.type) {
      case 'pq-commit':
        spend(0n, 'insufficient balance for the fee');
        this.accounts.set(from, { ...this.get(from), pqCommit: tx.commitment });
        return;

      case 'migrate': {
        const policyError = migrationError(sender, tx, ctx);
        if (policyError) throw new Error(policyError);
        const target = addressFromPublicKey(tx.to);
        const dest = this.get(target);
        if (dest.migratedTo) throw new Error('migration target is itself a migrated account');
        if (this.spendable(from, t) < fee) throw new Error('insufficient balance for the fee');
        const grants = [...(dest.vesting ?? []), ...(sender.vesting ?? [])];
        if (grants.length > MAX_GRANTS) throw new Error('the target account has too many vesting grants');
        this.accounts.set(from, { balance: 0n, nonce: sender.nonce + 1, migratedTo: target });
        this.accounts.set(target, { ...dest, balance: dest.balance + sender.balance - fee, ...(grants.length ? { vesting: grants } : {}) });
        this.credit(ctx.rewardAddress, fee);
        for (const v of this.validators) if (v.owner === from) v.owner = target; // validator ownership moves too
        return;
      }

      case 'transfer':
      case 'vest': {
        const recipient = this.get(tx.to);
        if (recipient.migratedTo) throw new Error(`recipient migrated to ${recipient.migratedTo}; send there instead`);
        const amount = BigInt(tx.amount);
        if (tx.type === 'vest' && (recipient.vesting?.length ?? 0) >= MAX_GRANTS) throw new Error('the recipient has too many vesting grants');
        spend(amount);
        this.credit(tx.to, amount);
        if (tx.type === 'vest') {
          const now = this.get(tx.to);
          const grant = normalizeGrant({ amount: tx.amount, atStart: tx.atStart, lockMonths: tx.lockMonths, vestMonths: tx.vestMonths }, t);
          this.accounts.set(tx.to, { ...now, vesting: [...(now.vesting ?? []), grant] });
        }
        return;
      }

      case 'validator-join': {
        const amount = BigInt(tx.amount);
        if (this.banned.has(tx.validator)) throw new Error('this validator key was banned for double-signing');
        if (this.validator(tx.validator)) throw new Error('this validator key is already registered');
        if (amount < p.minStake) throw new Error(`stake must be at least ${p.minStake} base units`);
        if (this.activeValidators().length >= p.maxValidators) throw new Error('the validator set is full');
        spend(amount);
        this.validators.push({ key: tx.validator, owner: from, stake: amount, status: 'active', missed: 0 });
        return;
      }

      case 'validator-bond': {
        const v = owned();
        if (v.status === 'unbonding') throw new Error('this validator is leaving; it cannot take more stake');
        spend(BigInt(tx.amount));
        v.stake += BigInt(tx.amount);
        return;
      }

      case 'validator-leave': {
        const v = owned();
        if (v.status === 'unbonding') throw new Error('this validator is already leaving');
        if (v.status === 'active' && this.activeValidators().length <= p.minValidators) throw new Error(`the network needs at least ${p.minValidators} validators`);
        spend(0n);
        v.status = 'unbonding';
        v.unbondAt = t + p.unbondingMs;
        return;
      }

      case 'validator-unjail': {
        const v = owned();
        if (v.status !== 'jailed') throw new Error('this validator is not jailed');
        if (t < v.jailedUntil) throw new Error(`jailed until ${new Date(v.jailedUntil).toISOString()}`);
        if (!v.genesis && v.stake < p.minStake) throw new Error('stake is below the minimum; add stake with validator-bond first');
        if (this.activeValidators().length >= p.maxValidators) throw new Error('the validator set is full');
        spend(0n);
        v.status = 'active';
        v.missed = 0;
        delete v.jailedUntil;
        return;
      }

      case 'evidence': {
        const key = tx.voteA.validator;
        const v = this.validator(key);
        if (!v || this.banned.has(key)) throw new Error('no slashable validator for this evidence (unknown, already punished, or fully unbonded)');
        if (tx.voteA.height > ctx.height || tx.voteA.height < ctx.height - p.evidenceMaxAgeBlocks) throw new Error('evidence is too old or from the future');
        spend(0n);
        this.#slash(v, p.doubleSignSlashBps);
        this.banned.add(key);
        if (v.status !== 'unbonding') {
          v.status = 'unbonding';
          v.unbondAt = t + p.unbondingMs;
        }
        return;
      }

      default:
        throw new Error('unsupported transaction type');
    }
  }

  root() {
    const entries = [...this.accounts.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([address, { balance, nonce, migratedTo, pqCommit, vesting }]) => {
        const entry = [address, balance.toString(), nonce];
        if (migratedTo) entry.push(migratedTo);
        else if (pqCommit) entry.push({ pqCommit });
        if (vesting?.length) entry.push({ vesting });
        return entry;
      });
    const validators = this.validators.map((v) => [sha256(v.key), v.owner, v.stake.toString(), v.status, v.missed, v.jailedUntil ?? null, v.unbondAt ?? null, Boolean(v.genesis)]);
    return hashObject({ supply: this.supply.toString(), accounts: entries, validators, banned: [...this.banned].map((k) => sha256(k)).sort() });
  }

  // Plain-JSON copy (for snapshots) and back.
  toJSON() {
    return {
      supply: this.supply.toString(),
      accounts: [...this.accounts].map(([a, acc]) => [a, { ...acc, balance: acc.balance.toString() }]),
      validators: this.validators.map((v) => ({ ...v, stake: v.stake.toString() })),
      banned: [...this.banned],
    };
  }

  static fromJSON(json) {
    return new State(
      new Map(json.accounts.map(([a, acc]) => [a, { ...acc, balance: BigInt(acc.balance) }])),
      BigInt(json.supply),
      json.validators.map((v) => ({ ...v, stake: BigInt(v.stake) })),
      new Set(json.banned),
    );
  }
}

function normalizeGrant(g, defaultStart) {
  return {
    amount: String(g.amount),
    ...(g.atStart && g.atStart !== '0' ? { atStart: String(g.atStart) } : {}),
    lockMonths: g.lockMonths ?? 0,
    vestMonths: g.vestMonths ?? 0,
    start: g.start ?? defaultStart,
  };
}
