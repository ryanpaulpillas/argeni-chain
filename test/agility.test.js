// The strongest NIST post-quantum key types, rotation between them, algorithm retirement and the
// block size limit that keeps large hash-based signatures in check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Chain, quorum, voteSignBytes } from '../src/chain.js';
import { addressFromPublicKey, generateKeyPair, keyTypeOf, sign, verify, KEY_INFO, DEFAULT_KEY_TYPE } from '../src/crypto.js';
import { createMigration, createTransfer } from '../src/tx.js';

const ONE = 10n ** 18n;
const FEE = 1000n;

function setup(extra = {}) {
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-87'));
  const lattice = generateKeyPair('ml-dsa-65');
  const strong = generateKeyPair('ml-dsa-87');
  const genesis = {
    chainId: 'argeni-agility-test', timestamp: 1_000_000, coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: keys.map((k) => k.publicKey),
    alloc: { [addressFromPublicKey(lattice.publicKey)]: (100n * ONE).toString(), [addressFromPublicKey(strong.publicKey)]: (100n * ONE).toString() },
    ...extra,
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  return { genesis, chain, clock, keys, lattice, strong, latticeAddr: addressFromPublicKey(lattice.publicKey), strongAddr: addressFromPublicKey(strong.publicKey) };
}

function finalize(ctx) {
  ctx.clock.t += ctx.genesis.blockTimeMs;
  const block = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  const precommits = ctx.keys.slice(0, quorum(4)).map((k) => {
    const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: k.publicKey };
    return { ...vote, signature: sign(voteSignBytes(ctx.genesis.chainId, vote), k.privateKey) };
  });
  assert.deepEqual(ctx.chain.addBlock({ ...block, commit: { round: 0, precommits } }), { ok: true });
  return block;
}

const transfer = (ctx, from, to, amount, nonce) => createTransfer({ chainId: ctx.genesis.chainId, privateKey: from.privateKey, to, amount, fee: FEE, nonce });
const migrate = (ctx, from, to, nonce) => createMigration({ chainId: ctx.genesis.chainId, privateKey: from.privateKey, pqPrivateKey: to.privateKey, fee: FEE, nonce });

test('ML-DSA-87 and SLH-DSA-256s (NIST category 5) sign and verify; ML-DSA-87 is the default', () => {
  assert.equal(DEFAULT_KEY_TYPE, 'ml-dsa-87');
  for (const [type, bytes] of [['ml-dsa-87', 4627], ['slh-dsa-256s', 29792]]) {
    const k = generateKeyPair(type);
    assert.equal(keyTypeOf(k.publicKey), type);
    assert.equal(KEY_INFO[type].category, 5);
    const sig = sign('argeni', k.privateKey);
    assert.equal(sig.length, bytes * 2);
    assert.equal(verify('argeni', sig, k.publicKey), true);
    assert.equal(verify('argenI', sig, k.publicKey), false);
    assert.match(addressFromPublicKey(k.publicKey), /^ag[0-9a-f]{64}$/, '256-bit address');
  }
  // A signature from one category-5 scheme never verifies under the other.
  const a = generateKeyPair('ml-dsa-87');
  const b = generateKeyPair('slh-dsa-256s');
  assert.equal(verify('x', sign('x', a.privateKey), b.publicKey), false);
  assert.equal(verify('x', sign('x', b.privateKey), a.publicKey), false);
});

test('a lattice-based account rotates to hash-based SLH-DSA-256s and the old key is locked', () => {
  const ctx = setup();
  const vault = generateKeyPair('slh-dsa-256s');
  const vaultAddr = addressFromPublicKey(vault.publicKey);
  assert.equal(ctx.chain.addTx(migrate(ctx, ctx.lattice, vault, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.latticeAddr).migratedTo, vaultAddr);
  assert.equal(ctx.chain.state.get(vaultAddr).balance, 100n * ONE - FEE);
  assert.match(ctx.chain.addTx(transfer(ctx, ctx.lattice, ctx.strongAddr, ONE, 1)).error, /was migrated/);
  // The hash-based vault spends normally.
  assert.equal(ctx.chain.addTx(transfer(ctx, vault, ctx.strongAddr, ONE, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.strongAddr).balance, 101n * ONE);
});

test('a retired key type can only migrate, and only to a key type that is still active', () => {
  const ctx = setup({ retiredKeyTypes: { 'ml-dsa-65': 2 } });
  const bob = addressFromPublicKey(generateKeyPair().publicKey);
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.lattice, bob, ONE, 0)).ok, true, 'allowed before retirement');
  finalize(ctx); // block 1
  assert.match(ctx.chain.addTx(transfer(ctx, ctx.lattice, bob, ONE, 1)).error, /ml-dsa-65 keys were retired at block 2/);
  assert.match(ctx.chain.addTx(migrate(ctx, ctx.strong, generateKeyPair('ml-dsa-65'), 0)).error, /ml-dsa-65 keys were retired/, 'no moving funds onto a retired type');
  const fresh = generateKeyPair('ml-dsa-87');
  // This account already signed (its key is public) and made no commitment, so like Ed25519 after
  // the sunset it can't migrate safely: a quantum attacker could race it.
  assert.match(ctx.chain.addTx(migrate(ctx, ctx.lattice, fresh, 1)).error, /exposed/);
  // The strong ML-DSA-87 account is unaffected.
  assert.equal(ctx.chain.addTx(transfer(ctx, ctx.strong, bob, ONE, 0)).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(bob).balance, 2n * ONE);
});

test('genesis rejects unknown key types in the retirement schedule', () => {
  const ctx = setup();
  assert.throws(() => new Chain({ ...ctx.genesis, retiredKeyTypes: { 'rsa-2048': 5 } }), /retiredKeyTypes/);
  assert.throws(() => new Chain({ ...ctx.genesis, retiredKeyTypes: { ed25519: 0 } }), /retiredKeyTypes/);
});

test('blocks respect a byte limit, so large hash-based transactions spread across blocks', () => {
  const ctx = setup({ maxBlockBytes: 150_000 });
  const vaults = Array.from({ length: 3 }, () => generateKeyPair('slh-dsa-256s'));
  for (const v of vaults) ctx.chain.addTx(transfer(ctx, ctx.strong, addressFromPublicKey(v.publicKey), 5n * ONE, vaults.indexOf(v)));
  finalize(ctx);
  for (const v of vaults) ctx.chain.addTx(transfer(ctx, v, ctx.strongAddr, ONE, 0)); // ~60 KB each
  const first = finalize(ctx);
  assert.equal(first.txs.length, 2, 'only two ~60 KB transactions fit in 150 KB');
  assert.equal(finalize(ctx).txs.length, 1, 'the third goes in the next block');

  // A proposer that ignores the limit gets its block rejected by everyone else.
  const vault = generateKeyPair('slh-dsa-256s');
  ctx.chain.addTx(transfer(ctx, ctx.strong, addressFromPublicKey(vault.publicKey), ONE, 3));
  finalize(ctx);
  for (let i = 0; i < 3; i++) ctx.chain.addTx(transfer(ctx, vault, ctx.strongAddr, 1n, i));
  ctx.clock.t += ctx.genesis.blockTimeMs;
  ctx.chain.genesis.maxBlockBytes = 10_000_000; // a cheating proposer's view
  const oversized = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  ctx.chain.genesis.maxBlockBytes = 150_000;
  assert.equal(oversized.txs.length, 3);
  assert.match(ctx.chain.validateBlock(oversized).error, /block too large/);
});
