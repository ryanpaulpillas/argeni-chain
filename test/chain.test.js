import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Chain, quorum, faultTolerance, voteSignBytes } from '../src/chain.js';
import { addressFromPublicKey, generateKeyPair, hashObject, sign } from '../src/crypto.js';
import { createTransfer, checkTx } from '../src/tx.js';
import { formatAmount, parseAmount } from '../src/coin.js';

const DECIMALS = 18;
const ONE = 10n ** 18n;
const BILLION = 1_000_000_000n * ONE;

function setup({ validators = 4, blockReward = '0', maxSupply = BILLION, aliceFunds = 100n * ONE } = {}) {
  const keys = Array.from({ length: validators }, generateKeyPair);
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const genesis = {
    chainId: 'argeni-test',
    timestamp: 1_000_000,
    coin: { name: 'Argeni', symbol: 'ARGENI', decimals: DECIMALS },
    blockTimeMs: 1000,
    maxTxsPerBlock: 100,
    minFee: '1000',
    blockReward,
    maxSupply: maxSupply.toString(),
    validators: keys.map((k) => k.publicKey),
    alloc: { [addressFromPublicKey(alice.publicKey)]: aliceFunds.toString() },
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  return { genesis, chain, clock, keys, alice, bob, aliceAddr: addressFromPublicKey(alice.publicKey), bobAddr: addressFromPublicKey(bob.publicKey) };
}

function transfer(ctx, { amount = ONE, fee = 1000n, nonce = 0, from = ctx.alice } = {}) {
  return createTransfer({ chainId: ctx.genesis.chainId, privateKey: from.privateKey, to: ctx.bobAddr, amount, fee, nonce });
}

function precommit(ctx, key, block, round = 0) {
  const vote = { type: 'precommit', height: block.header.height, round, blockHash: block.hash, validator: key.publicKey };
  return { ...vote, signature: sign(voteSignBytes(ctx.genesis.chainId, vote), key.privateKey) };
}

// Builds the next block and signs it with `signers` validators (a quorum by default).
function finalize(ctx, { signers = quorum(ctx.keys.length), proposer = 0 } = {}) {
  ctx.clock.t += ctx.genesis.blockTimeMs;
  const block = ctx.chain.buildBlock(ctx.keys[proposer].publicKey);
  return { ...block, commit: { round: 0, precommits: ctx.keys.slice(0, signers).map((k) => precommit(ctx, k, block)) } };
}

test('quorum needs more than two thirds of validators', () => {
  assert.deepEqual([1, 3, 4, 7, 10].map(quorum), [1, 3, 3, 5, 7]);
  assert.deepEqual([1, 3, 4, 7, 10].map(faultTolerance), [0, 0, 1, 2, 3]);
});

test('amounts convert between ARGENI and base units', () => {
  assert.equal(parseAmount('1.5', DECIMALS), 1_500_000_000_000_000_000n);
  assert.equal(formatAmount(1_500_000_000_000_000_000n, DECIMALS), '1.5');
  assert.equal(formatAmount(BILLION, DECIMALS), '1000000000');
  assert.throws(() => parseAmount('1.' + '1'.repeat(19), DECIMALS));
  assert.throws(() => parseAmount('-1', DECIMALS));
});

test('supply can never exceed maxSupply', () => {
  assert.throws(() => setup({ aliceFunds: BILLION + 1n }), /alloc exceeds maxSupply/);
  // Genesis holds all but 1.5 ARGENI; a 1 ARGENI block reward mints 1, then 0.5, then nothing.
  const ctx = setup({ aliceFunds: BILLION - (3n * ONE) / 2n, blockReward: ONE.toString() });
  for (let i = 0; i < 3; i++) assert.deepEqual(ctx.chain.addBlock(finalize(ctx)), { ok: true });
  assert.equal(ctx.chain.state.supply, BILLION);
  assert.equal(ctx.chain.state.get(addressFromPublicKey(ctx.keys[0].publicKey)).balance, (3n * ONE) / 2n);
});

test('a finalized transfer moves funds and pays the fee to the proposer', () => {
  const ctx = setup();
  assert.equal(ctx.chain.addTx(transfer(ctx, { amount: 5n * ONE })).ok, true);
  const block = finalize(ctx);
  assert.equal(block.txs.length, 1);
  assert.deepEqual(ctx.chain.addBlock(block), { ok: true });
  assert.equal(ctx.chain.state.get(ctx.bobAddr).balance, 5n * ONE);
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, 95n * ONE - 1000n);
  assert.equal(ctx.chain.state.get(addressFromPublicKey(ctx.keys[0].publicKey)).balance, 1000n);
  assert.equal(ctx.chain.state.supply, 100n * ONE);
  assert.equal(ctx.chain.mempool.size, 0);
});

test('tampered, wrong-chain and underpriced transactions are rejected', () => {
  const ctx = setup();
  const tx = transfer(ctx);
  assert.match(checkTx({ ...tx, amount: (2n * ONE).toString() }, ctx.genesis), /invalid signature/);
  assert.match(checkTx({ ...tx, chainId: 'other' }, ctx.genesis), /wrong chainId/);
  assert.match(checkTx(transfer(ctx, { fee: 1n }), ctx.genesis), /fee below minimum/);
  assert.match(checkTx({ ...tx, extra: 1 }, ctx.genesis), /unknown fields/);
});

test('a transaction cannot be replayed and overspending is never included', () => {
  const ctx = setup();
  const tx = transfer(ctx, { amount: 60n * ONE });
  ctx.chain.addTx(tx);
  ctx.chain.addTx(transfer(ctx, { amount: 60n * ONE, nonce: 1 }));
  const block = finalize(ctx);
  assert.equal(block.txs.length, 1);
  ctx.chain.addBlock(block);
  assert.equal(ctx.chain.addTx(tx).known, true);
  assert.equal(ctx.chain.addTx(transfer(ctx, { amount: 2n * ONE, nonce: 0 })).error, 'nonce already used');
  assert.equal(ctx.chain.state.get(ctx.bobAddr).balance, 60n * ONE);
});

test('blocks without a valid quorum certificate are rejected', () => {
  const ctx = setup();
  const block = finalize(ctx, { signers: 2 }); // 2 of 4 is not more than two thirds
  assert.match(ctx.chain.addBlock(block).error, /2 valid signatures, needs 3/);

  const dup = { ...block, commit: { round: 0, precommits: [block.commit.precommits[0], block.commit.precommits[0], block.commit.precommits[1]] } };
  assert.match(ctx.chain.addBlock(dup).error, /needs 3/);

  const outsider = generateKeyPair();
  const forged = { ...block, commit: { round: 0, precommits: [...block.commit.precommits, precommit(ctx, outsider, block)] } };
  assert.match(ctx.chain.addBlock(forged).error, /needs 3/);

  const wrongRound = finalize(ctx);
  wrongRound.commit.round = 1;
  assert.match(ctx.chain.addBlock(wrongRound).error, /needs 3/);
});

test('a quorum cannot certify an invalid block', () => {
  const ctx = setup();
  ctx.chain.addTx(transfer(ctx, { amount: 3n * ONE }));
  const block = finalize(ctx);
  const resign = (header, txs = block.txs) => {
    const b = { header, txs, hash: hashObject(header) };
    return { ...b, commit: { round: 0, precommits: ctx.keys.map((k) => precommit(ctx, k, b)) } };
  };
  const inflated = structuredClone(block);
  inflated.txs[0].amount = (50n * ONE).toString();
  assert.match(ctx.chain.addBlock(inflated).error, /needs 3|txRoot/);
  assert.match(ctx.chain.addBlock(resign(block.header, inflated.txs)).error, /invalid signature|txRoot/);
  assert.match(ctx.chain.addBlock(resign({ ...block.header, stateRoot: 'f'.repeat(64) })).error, /stateRoot mismatch/);
  assert.match(ctx.chain.addBlock(resign({ ...block.header, proposer: generateKeyPair().publicKey })).error, /not a validator/);
  assert.match(ctx.chain.addBlock(resign({ ...block.header, timestamp: ctx.genesis.timestamp })).error, /timestamp not after parent/);
});

test('a node restarts from its data dir and refuses a different genesis', () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argeni-'));
  try {
    const ctx = setup();
    ctx.chain = new Chain(ctx.genesis, { dataDir, now: () => ctx.clock.t });
    ctx.chain.addTx(transfer(ctx, { amount: 7n * ONE }));
    ctx.chain.addBlock(finalize(ctx));
    ctx.chain.addBlock(finalize(ctx));
    const restarted = new Chain(ctx.genesis, { dataDir, now: () => ctx.clock.t });
    assert.equal(restarted.height, 2);
    assert.equal(restarted.state.get(ctx.bobAddr).balance, 7n * ONE);
    assert.throws(() => new Chain({ ...ctx.genesis, chainId: 'other' }, { dataDir }), /different genesis/);

    // Removing a signature from a stored block makes the node refuse to start.
    const file = path.join(dataDir, 'blocks', '0000000001.json');
    const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
    stored.commit.precommits = stored.commit.precommits.slice(0, 2);
    fs.writeFileSync(file, JSON.stringify(stored));
    assert.throws(() => new Chain(ctx.genesis, { dataDir }), /stored block .* is invalid/);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
