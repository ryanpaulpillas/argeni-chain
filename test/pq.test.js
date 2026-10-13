// Post-quantum keys (ML-DSA-65, SLH-DSA-128s), migration from Ed25519, migration commitments, the
// Ed25519 sunset, and PQ validators.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Chain, quorum, voteSignBytes } from '../src/chain.js';
import { Consensus } from '../src/consensus.js';
import { addressFromPublicKey, generateKeyPair, keyTypeOf, sign, verify } from '../src/crypto.js';
import { createMigration, createMigrationCommit, createTransfer, checkTx } from '../src/tx.js';

const ONE = 10n ** 18n;
const BILLION = 1_000_000_000n * ONE;
const FEE = 1000n;

function setup({ validatorType = 'ml-dsa-65', sunset } = {}) {
  const keys = Array.from({ length: 4 }, () => generateKeyPair(validatorType));
  const legacy = generateKeyPair('ed25519');
  const pq = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'argeni-pq-test', timestamp: 1_000_000, coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: BILLION.toString(),
    validators: keys.map((k) => k.publicKey),
    alloc: { [addressFromPublicKey(legacy.publicKey)]: (100n * ONE).toString(), [addressFromPublicKey(pq.publicKey)]: (50n * ONE).toString() },
    ...(sunset ? { ed25519SunsetHeight: sunset } : {}),
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  return { genesis, chain, clock, keys, legacy, pq, legacyAddr: addressFromPublicKey(legacy.publicKey), pqAddr: addressFromPublicKey(pq.publicKey) };
}

function finalize(ctx) {
  ctx.clock.t += ctx.genesis.blockTimeMs;
  const block = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  const precommits = ctx.keys.slice(0, quorum(4)).map((k) => {
    const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: k.publicKey };
    return { ...vote, signature: sign(voteSignBytes(ctx.genesis.chainId, vote), k.privateKey) };
  });
  const result = ctx.chain.addBlock({ ...block, commit: { round: 0, precommits } });
  assert.deepEqual(result, { ok: true });
  return block;
}

const transfer = (ctx, from, to, amount, nonce) => createTransfer({ chainId: ctx.genesis.chainId, privateKey: from.privateKey, to, amount, fee: FEE, nonce });

test('ML-DSA-65 keys sign and verify; signatures do not cross key types', () => {
  const pq = generateKeyPair('ml-dsa-65');
  const ed = generateKeyPair('ed25519');
  assert.equal(keyTypeOf(pq.publicKey), 'ml-dsa-65');
  const sig = sign('hello', pq.privateKey);
  assert.equal(sig.length, 3309 * 2);
  assert.equal(verify('hello', sig, pq.publicKey), true);
  assert.equal(verify('hellO', sig, pq.publicKey), false);
  assert.equal(verify('hello', sig.slice(0, -2) + '00', pq.publicKey), false);
  assert.equal(verify('hello', sign('hello', ed.privateKey), pq.publicKey), false);
  assert.equal(verify('hello', sig, ed.publicKey), false);
  assert.notEqual(addressFromPublicKey(pq.publicKey), addressFromPublicKey(ed.publicKey));
  assert.match(addressFromPublicKey(pq.publicKey), /^ag[0-9a-f]{40}$/);
});

test('a post-quantum account sends ARGENI, finalized by post-quantum validators', () => {
  const ctx = setup();
  const bob = addressFromPublicKey(generateKeyPair('ml-dsa-65').publicKey);
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.pq, bob, 5n * ONE, 0)).ok, true);
  const block = finalize(ctx);
  assert.equal(block.txs.length, 1);
  assert.equal(ctx.chain.state.get(bob).balance, 5n * ONE);
  assert.equal(ctx.chain.state.get(ctx.pqAddr).balance, 45n * ONE - FEE);
});

test('migration moves an Ed25519 account to a post-quantum key and locks the old key', () => {
  const ctx = setup();
  const newKey = generateKeyPair('ml-dsa-65');
  const newAddr = addressFromPublicKey(newKey.publicKey);
  const tx = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, pqPrivateKey: newKey.privateKey, fee: FEE, nonce: 0 });
  assert.equal(ctx.chain.addTx(tx).ok, true);
  finalize(ctx);

  const old = ctx.chain.state.get(ctx.legacyAddr);
  assert.equal(old.balance, 0n);
  assert.equal(old.migratedTo, newAddr);
  assert.equal(ctx.chain.state.get(newAddr).balance, 100n * ONE - FEE);

  // The old key can't move anything any more, even if a quantum computer recovers it later.
  const fromOld = transfer(ctx, ctx.legacy, ctx.pqAddr, 1n, 1);
  assert.match(ctx.chain.addTx(fromOld).error, /was migrated to ag/, 'refused on arrival');
  ctx.chain.mempool.set('forced', fromOld); // even if it reached a block builder some other way
  assert.equal(finalize(ctx).txs.length, 0, 'transfer from a migrated account is never included');
  ctx.chain.mempool.delete('forced');
  assert.match(ctx.chain.addTx(transfer(ctx, ctx.pq, ctx.legacyAddr, ONE, 0)).error, /recipient migrated to ag/);
  // Payments to the old address are refused, pointing to the new one.
  assert.throws(() => ctx.chain.state.clone().applyTx(transfer(ctx, ctx.pq, ctx.legacyAddr, ONE, 0), newAddr), /recipient migrated to ag/);
  // The new post-quantum key spends normally.
  assert.equal(ctx.chain.addTx(transfer(ctx, newKey, ctx.pqAddr, ONE, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.pqAddr).balance, 51n * ONE);
});

test('a migration needs valid signatures from both the old and the new key', () => {
  const ctx = setup();
  const newKey = generateKeyPair('ml-dsa-65');
  const good = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, pqPrivateKey: newKey.privateKey, fee: FEE, nonce: 0 });
  const otherPq = generateKeyPair('ml-dsa-65');
  assert.match(checkTx({ ...good, to: otherPq.publicKey }, ctx.genesis), /invalid signature/);
  assert.match(checkTx({ ...good, pqSignature: sign('x', newKey.privateKey) }, ctx.genesis), /invalid post-quantum signature/);
  const fromPq = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.pq.privateKey, pqPrivateKey: newKey.privateKey, fee: FEE, nonce: 0 });
  assert.match(checkTx(fromPq, ctx.genesis), /only Ed25519 accounts can migrate/);
  assert.equal(checkTx(good, ctx.genesis), null);
});

const commit = (ctx, oldKey, newKey, nonce) => createMigrationCommit({ chainId: ctx.genesis.chainId, privateKey: oldKey.privateKey, pqPublicKey: newKey.publicKey, fee: FEE, nonce });
const migration = (ctx, oldKey, newKey, nonce) => createMigration({ chainId: ctx.genesis.chainId, privateKey: oldKey.privateKey, pqPrivateKey: newKey.privateKey, fee: FEE, nonce });

test('after the sunset height Ed25519 keys can only migrate, to the committed key', () => {
  const ctx = setup({ sunset: 3 });
  const bob = addressFromPublicKey(generateKeyPair('ml-dsa-65').publicKey);
  const newKey = generateKeyPair('ml-dsa-65');
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.legacy, bob, ONE, 0)).ok, true, 'allowed before the sunset');
  finalize(ctx); // height 1
  assert.equal(ctx.chain.addTx(commit(ctx, ctx.legacy, newKey, 1)).ok, true, 'commitment allowed before the sunset');
  finalize(ctx); // height 2
  assert.equal(ctx.chain.state.get(ctx.legacyAddr).pqCommit.length, 64);
  const late = ctx.chain.addTx(transfer(ctx, ctx.legacy, bob, ONE, 2));
  assert.match(late.error, /retired at block 3/);
  assert.match(ctx.chain.addTx(commit(ctx, ctx.legacy, generateKeyPair('ml-dsa-65'), 2)).error, /retired at block 3/, 'no new commitments after the sunset');
  assert.equal(ctx.chain.addTx(migration(ctx, ctx.legacy, newKey, 2)).ok, true, 'migration to the committed key is allowed');
  finalize(ctx);
  assert.equal(ctx.chain.state.get(addressFromPublicKey(newKey.publicKey)).balance, 99n * ONE - 3n * FEE);
});

test('a quantum attacker holding the old key cannot redirect a committed migration', () => {
  const ctx = setup({ sunset: 2 });
  const owner = generateKeyPair('slh-dsa-128s');
  assert.equal(ctx.chain.addTx(commit(ctx, ctx.legacy, owner, 0)).ok, true);
  finalize(ctx); // height 1; the sunset is next
  // The attacker has recovered the Ed25519 private key and tries to move the funds to their own key.
  const attacker = generateKeyPair('ml-dsa-65');
  const theft = migration(ctx, ctx.legacy, attacker, 1);
  assert.equal(checkTx(theft, ctx.genesis), null, 'the signatures themselves are valid');
  assert.match(ctx.chain.addTx(theft).error, /committed to a different post-quantum key/);
  ctx.chain.mempool.set('forced', theft); // even if a proposer tried to include it
  assert.equal(finalize(ctx).txs.length, 0);
  ctx.chain.mempool.delete('forced');
  assert.equal(ctx.chain.state.get(addressFromPublicKey(attacker.publicKey)).balance, 0n);
  // The owner's migration to the committed hash-based key still goes through.
  assert.equal(ctx.chain.addTx(migration(ctx, ctx.legacy, owner, 1)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(addressFromPublicKey(owner.publicKey)).balance, 100n * ONE - 2n * FEE);
});

test('after the sunset an exposed key without a commitment cannot migrate; a never-used key can', () => {
  const ctx = setup({ sunset: 2 });
  const unused = generateKeyPair('ed25519');
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.pq, addressFromPublicKey(unused.publicKey), 5n * ONE, 0)).ok, true);
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.legacy, ctx.pqAddr, ONE, 0)).ok, true, 'this publishes the legacy key');
  finalize(ctx); // height 1
  assert.match(ctx.chain.addTx(migration(ctx, ctx.legacy, generateKeyPair('ml-dsa-65'), 1)).error, /was exposed and it made no migration commitment before block 2/);
  const fresh = generateKeyPair('ml-dsa-65');
  assert.equal(ctx.chain.addTx(migration(ctx, unused, fresh, 0)).ok, true, 'its public key was never published');
  finalize(ctx);
  assert.equal(ctx.chain.state.get(addressFromPublicKey(fresh.publicKey)).balance, 5n * ONE - FEE);
});

test('SLH-DSA-128s (hash-based, FIPS 205) keys sign, verify and send ARGENI', () => {
  const slh = generateKeyPair('slh-dsa-128s');
  assert.equal(keyTypeOf(slh.publicKey), 'slh-dsa-128s');
  const sig = sign('hello', slh.privateKey);
  assert.equal(sig.length, 7856 * 2);
  assert.equal(verify('hello', sig, slh.publicKey), true);
  assert.equal(verify('hellO', sig, slh.publicKey), false);
  assert.equal(verify('hello', sign('hello', generateKeyPair('ml-dsa-65').privateKey), slh.publicKey), false);
  assert.match(addressFromPublicKey(slh.publicKey), /^ag[0-9a-f]{40}$/);

  const ctx = setup();
  const slhAddr = addressFromPublicKey(slh.publicKey);
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.pq, slhAddr, 5n * ONE, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.addTx(transfer(ctx, slh, ctx.pqAddr, ONE, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(slhAddr).balance, 4n * ONE - FEE);
});

test('a commitment is bound to its chain and account and can only come from an Ed25519 key', () => {
  const ctx = setup();
  const newKey = generateKeyPair('ml-dsa-65');
  const good = commit(ctx, ctx.legacy, newKey, 0);
  assert.equal(checkTx(good, ctx.genesis), null);
  assert.match(checkTx({ ...good, commitment: 'ab'.repeat(32) }, ctx.genesis), /invalid signature/);
  assert.match(checkTx({ ...good, commitment: 'zz' }, ctx.genesis), /32-byte hex/);
  assert.match(checkTx(commit(ctx, ctx.pq, newKey, 0), ctx.genesis), /only Ed25519/);
  // A transfer after committing keeps the commitment (and the commitment changes the state root).
  ctx.chain.addTx(good);
  finalize(ctx);
  ctx.chain.addTx(transfer(ctx, ctx.legacy, ctx.pqAddr, ONE, 1));
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.legacyAddr).pqCommit, good.commitment);
});

test('four post-quantum validators reach consensus', async () => {
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const genesis = {
    chainId: 'argeni-pq-consensus', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 50, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: BILLION.toString(),
    validators: keys.map((k) => k.publicKey), alloc: {},
  };
  const members = new Map();
  const nodes = keys.map((key) => {
    const chain = new Chain(genesis);
    const consensus = new Consensus({ chain, privateKey: key.privateKey, broadcast: (msg) => {
      for (const [pk, c] of members) if (pk !== key.publicKey) setTimeout(() => c.handle(structuredClone(msg)), Math.random() * 5);
    } });
    members.set(key.publicKey, consensus);
    return { chain, consensus };
  });
  nodes.forEach((n) => n.consensus.start());
  try {
    const end = Date.now() + 10_000;
    while (!nodes.every((n) => n.chain.height >= 3) && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
    assert.ok(nodes.every((n) => n.chain.height >= 3), 'chain advanced');
    for (let h = 1; h <= 3; h++) assert.equal(new Set(nodes.map((n) => n.chain.getBlock(h).hash)).size, 1);
    const block = nodes[0].chain.getBlock(1);
    assert.ok(block.commit.precommits.every((p) => keyTypeOf(p.validator) === 'ml-dsa-65'));
    assert.equal(nodes[1].chain.verifyCommit(block), null);
  } finally {
    nodes.forEach((n) => n.consensus.stop());
  }
});
