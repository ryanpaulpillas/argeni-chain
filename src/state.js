// Account state: balance (BigInt base units), nonce, an optional pqCommit (hash of the post-quantum
// address the account has committed to migrate to) and, after a migration, migratedTo per address,
// plus total supply.
import { addressFromPublicKey, hashObject, keyTypeOf } from './crypto.js';
import { migrationCommitment } from './tx.js';

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
  constructor(accounts = new Map(), supply = 0n) {
    this.accounts = accounts;
    this.supply = supply;
  }

  static fromAlloc(alloc) {
    const state = new State();
    for (const [address, amount] of Object.entries(alloc)) {
      state.credit(address, BigInt(amount));
      state.supply += BigInt(amount);
    }
    return state;
  }

  clone() {
    const copy = new Map();
    for (const [address, account] of this.accounts) copy.set(address, { ...account });
    return new State(copy, this.supply);
  }

  get(address) {
    return this.accounts.get(address) ?? { balance: 0n, nonce: 0 };
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

  // Applies a transaction that already passed checkTx. Throws if the state rejects it.
  applyTx(tx, proposerAddress, policy = {}) {
    const from = addressFromPublicKey(tx.from);
    const sender = this.get(from);
    const fee = BigInt(tx.fee);
    if (sender.migratedTo) throw new Error(`account was migrated to ${sender.migratedTo}; use the new key`);
    if (tx.nonce !== sender.nonce) throw new Error(`bad nonce: expected ${sender.nonce}, got ${tx.nonce}`);

    if (tx.type === 'pq-commit') {
      if (sender.balance < fee) throw new Error('insufficient balance for the fee');
      this.accounts.set(from, { ...sender, balance: sender.balance - fee, nonce: sender.nonce + 1, pqCommit: tx.commitment });
      this.credit(proposerAddress, fee);
      return;
    }

    if (tx.type === 'migrate') {
      const policyError = migrationError(sender, tx, policy);
      if (policyError) throw new Error(policyError);
      const target = addressFromPublicKey(tx.to);
      if (this.get(target).migratedTo) throw new Error('migration target is itself a migrated account');
      if (sender.balance < fee) throw new Error('insufficient balance for the fee');
      const moved = sender.balance - fee;
      this.accounts.set(from, { balance: 0n, nonce: sender.nonce + 1, migratedTo: target });
      this.credit(target, moved);
      this.credit(proposerAddress, fee);
      return;
    }

    const amount = BigInt(tx.amount);
    const recipient = this.get(tx.to);
    if (recipient.migratedTo) throw new Error(`recipient migrated to ${recipient.migratedTo}; send there instead`);
    if (sender.balance < amount + fee) throw new Error('insufficient balance');
    this.accounts.set(from, { ...sender, balance: sender.balance - amount - fee, nonce: sender.nonce + 1 });
    this.credit(tx.to, amount);
    this.credit(proposerAddress, fee);
  }

  root() {
    const entries = [...this.accounts.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([address, { balance, nonce, migratedTo, pqCommit }]) => {
        const entry = [address, balance.toString(), nonce];
        if (migratedTo) entry.push(migratedTo);
        else if (pqCommit) entry.push({ pqCommit });
        return entry;
      });
    return hashObject({ supply: this.supply.toString(), accounts: entries });
  }
}
