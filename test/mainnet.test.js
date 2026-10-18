// Mainnet features: vesting locks, multisig accounts, staking (validators joining and leaving),
// slashing for double-signing and downtime, and fast sync from a snapshot.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Chain, quorum, voteSignBytes } from '../src/chain.js';
import { Consensus } from '../src/consensus.js';
import { addressFromPublicKey, generateKeyPair, multisigKey, signMultisigPart, combineMultisig, sign } from '../src/crypto.js';
import { createTransfer, createTx, signingBytes, validatorConsentBytes } from '../src/tx.js';
import { MONTH_MS } from '../src/state.js';

const ONE = 10n ** 18n;
const FEE = 1000n;
const DAY = 86_400_000;

function setup({ validators = 4, vesting, staking, alloc = {} } = {}) {
  const keys = Array.from({ length: validators }, () => generateKeyPair('ml-dsa-65'));
  const alice = generateKeyPair('ml-dsa-65');
  const aliceAddr = addressFromPublicKey(alice.publicKey);
  const genesis = {
    chainId: 'argeni-mainnet-test', timestamp: 1_000_000, coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: keys.map((k) => k.publicKey),
    alloc: { [aliceAddr]: (1_000_000n * ONE).toString(), ...alloc },
    ...(vesting ? { vesting } : {}),
    staking: { minStake: (1000n * ONE).toString(), ...staking },
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  const byKey = new Map(keys.map((k) => [k.publicKey, k]));
  return { genesis, chain, clock, keys, byKey, alice, aliceAddr };
}

const precommit = (ctx, key, block) => {
  const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: key.publicKey };
  return { ...vote, signature: sign(voteSignBytes(ctx.genesis.chainId, vote), key.privateKey) };
};

// Builds, signs (by everyone in the current set, minus `skip`) and adds the next block.
function finalize(ctx, { advance = ctx.genesis.blockTimeMs, skip = [] } = {}) {
  ctx.clock.t += advance;
  const set = ctx.chain.validatorList;
  const proposer = set.find((k) => !skip.includes(k));
  const block = ctx.chain.buildBlock(proposer);
  const signers = set.filter((k) => !skip.includes(k)).map((k) => ctx.byKey.get(k));
  const result = ctx.chain.addBlock({ ...block, commit: { round: 0, precommits: signers.map((k) => precommit(ctx, k, block)) } });
  assert.deepEqual(result, { ok: true });
  return block;
}

function submit(ctx, tx) {
  const r = ctx.chain.addTx(tx);
  assert.equal(r.error, undefined);
  return r;
}

const nonceOf = (ctx, key) => ctx.chain.pendingNonce(addressFromPublicKey(key.publicKey));
const send = (ctx, from, to, amount) => createTransfer({ chainId: ctx.genesis.chainId, privateKey: from.privateKey, to, amount, fee: FEE, nonce: nonceOf(ctx, from) });

test('a vested allocation stays locked, then unlocks month by month', () => {
  const founder = generateKeyPair('ml-dsa-65');
  const founderAddr = addressFromPublicKey(founder.publicKey);
  const ctx = setup({
    alloc: { [founderAddr]: (2400n * ONE).toString() },
    vesting: { [founderAddr]: [{ amount: (2400n * ONE).toString(), lockMonths: 12, vestMonths: 24 }] },
  });
  submit(ctx, send(ctx, ctx.alice, founderAddr, 10n * ONE)); // free money on top of the grant
  finalize(ctx);

  // Before the lock ends, only the 10 free ARGENI can move.
  const tooMuch = send(ctx, founder, ctx.aliceAddr, 11n * ONE);
  assert.match(ctx.chain.addTx(tooMuch).error, /locked by vesting/);
  submit(ctx, send(ctx, founder, ctx.aliceAddr, 9n * ONE));
  finalize(ctx);

  // 13 months in: one 24th (100 ARGENI) has unlocked.
  ctx.clock.t = ctx.genesis.timestamp + 13 * MONTH_MS;
  finalize(ctx, { advance: 0 });
  assert.match(ctx.chain.addTx(send(ctx, founder, ctx.aliceAddr, 101n * ONE)).error, /locked by vesting/);
  submit(ctx, send(ctx, founder, ctx.aliceAddr, 100n * ONE));
  finalize(ctx);

  // 36 months in: everything is free.
  ctx.clock.t = ctx.genesis.timestamp + 36 * MONTH_MS;
  finalize(ctx, { advance: 0 });
  assert.equal(ctx.chain.state.spendable(founderAddr, ctx.clock.t), ctx.chain.state.get(founderAddr).balance);
});

test('vesting grants can be sent later, and stay locked through a key migration', () => {
  const ctx = setup();
  const hire = generateKeyPair('ml-dsa-65');
  const hireAddr = addressFromPublicKey(hire.publicKey);
  submit(ctx, createTx({ type: 'vest', chainId: ctx.genesis.chainId, to: hireAddr, amount: 1200n * ONE, atStart: 0n, lockMonths: 6, vestMonths: 12, fee: FEE, nonce: nonceOf(ctx, ctx.alice) }, { privateKey: ctx.alice.privateKey }));
  submit(ctx, send(ctx, ctx.alice, hireAddr, ONE)); // to pay fees
  finalize(ctx);
  assert.match(ctx.chain.addTx(send(ctx, hire, ctx.aliceAddr, 2n * ONE)).error, /locked by vesting/);

  // Rotating to a new key carries the lock along: the grant can't be escaped by migrating.
  const newKey = generateKeyPair('ml-dsa-87');
  const newAddr = addressFromPublicKey(newKey.publicKey);
  submit(ctx, createTx({ type: 'migrate', chainId: ctx.genesis.chainId, to: newKey.publicKey, fee: FEE, nonce: 0 }, { privateKey: hire.privateKey, extraSigners: { pqSignature: newKey.privateKey } }));
  finalize(ctx);
  assert.equal(ctx.chain.state.get(newAddr).vesting.length, 1);
  assert.match(ctx.chain.addTx(send(ctx, newKey, ctx.aliceAddr, 2n * ONE)).error, /locked by vesting/);

  ctx.clock.t = ctx.genesis.timestamp + 19 * MONTH_MS; // the grant started a block after genesis
  finalize(ctx, { advance: 0 });
  submit(ctx, send(ctx, newKey, ctx.aliceAddr, 1200n * ONE));
  finalize(ctx);
  assert.equal(ctx.chain.state.get(newAddr).balance, ONE - 2n * FEE);
});

test('a 2-of-3 multisig vault needs two of its keys to move funds', () => {
  const ctx = setup();
  const members = Array.from({ length: 3 }, () => generateKeyPair('ml-dsa-87'));
  const vault = multisigKey(2, members.map((m) => m.publicKey));
  const vaultAddr = addressFromPublicKey(vault);
  submit(ctx, send(ctx, ctx.alice, vaultAddr, 500n * ONE));
  finalize(ctx);

  // Each member signs the same bytes on their own machine; the parts are then combined.
  const body = { type: 'transfer', chainId: ctx.genesis.chainId, from: vault, to: ctx.aliceAddr, amount: (100n * ONE).toString(), fee: FEE.toString(), nonce: 0 };
  const bytes = signingBytes(body);
  const parts = members.map((m) => signMultisigPart(bytes, vault, m.privateKey));
  const outsider = generateKeyPair('ml-dsa-87');

  assert.match(ctx.chain.addTx({ ...body, signature: parts[0] }).error, /invalid signature/, 'one key is not enough');
  assert.match(ctx.chain.addTx({ ...body, signature: combineMultisig([parts[0], parts[0]]) }).error, /invalid signature/, 'the same key twice is not two keys');
  assert.match(ctx.chain.addTx({ ...body, signature: `${parts[0]},1:${sign(bytes, outsider.privateKey)}` }).error, /invalid signature/, 'an outsider cannot stand in');
  submit(ctx, { ...body, signature: combineMultisig([parts[2], parts[0]]) });
  finalize(ctx);
  assert.equal(ctx.chain.state.get(vaultAddr).balance, 400n * ONE - FEE);
});

test('a staked validator joins the set, must then sign blocks, and gets its stake back after leaving', () => {
  const ctx = setup({ staking: { unbondingMs: 7 * DAY } });
  const operator = generateKeyPair('ml-dsa-87');
  ctx.byKey.set(operator.publicKey, operator);
  const join = (amount, extra = {}) => createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: operator.publicKey, amount, fee: FEE, nonce: nonceOf(ctx, ctx.alice), ...extra },
    { privateKey: ctx.alice.privateKey, extraSigners: { validatorSignature: operator.privateKey } });

  assert.match(ctx.chain.addTx(join(999n * ONE)).error, /at least/);
  const unsigned = createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: operator.publicKey, amount: 1000n * ONE, fee: FEE, nonce: 0, validatorSignature: '00' }, { privateKey: ctx.alice.privateKey });
  assert.match(ctx.chain.addTx(unsigned).error, /validator key must sign/);
  submit(ctx, join(1000n * ONE));
  finalize(ctx);
  assert.equal(ctx.chain.validatorList.length, 5);
  assert.equal(ctx.chain.quorum, 4);
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, 999_000n * ONE - FEE);

  // With 5 validators, 3 signatures no longer finalize a block.
  ctx.clock.t += 1000;
  const block = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  const three = ctx.keys.slice(0, 3).map((k) => precommit(ctx, k, block));
  assert.match(ctx.chain.addBlock({ ...block, commit: { round: 0, precommits: three } }).error, /needs 4/);
  assert.deepEqual(ctx.chain.addBlock({ ...block, commit: { round: 0, precommits: [...three, precommit(ctx, operator, block)] } }), { ok: true });

  // Leaving: out of the set at once, stake returned after the unbonding period.
  submit(ctx, createTx({ type: 'validator-leave', chainId: ctx.genesis.chainId, validator: operator.publicKey, fee: FEE, nonce: nonceOf(ctx, ctx.alice) }, { privateKey: ctx.alice.privateKey }));
  finalize(ctx);
  assert.equal(ctx.chain.validatorList.length, 4);
  finalize(ctx, { advance: 6 * DAY });
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, 999_000n * ONE - 2n * FEE, 'still unbonding');
  finalize(ctx, { advance: DAY });
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, 1_000_000n * ONE - 2n * FEE, 'stake returned');
  assert.equal(ctx.chain.state.validator(operator.publicKey), null);
});

test('the set cannot shrink below the minimum', () => {
  const ctx = setup();
  const v = ctx.keys[0];
  // A genesis validator's owner is its own key's address.
  submit(ctx, send(ctx, ctx.alice, addressFromPublicKey(v.publicKey), ONE));
  finalize(ctx);
  const leave = createTx({ type: 'validator-leave', chainId: ctx.genesis.chainId, validator: v.publicKey, fee: FEE, nonce: nonceOf(ctx, v) }, { privateKey: v.privateKey });
  assert.match(ctx.chain.addTx(leave).error, /at least 4 validators/);
});

test('double-signing is proven by evidence: stake slashed and burned, key banned for good', () => {
  const ctx = setup({ staking: { unbondingMs: DAY } });
  const cheat = generateKeyPair('ml-dsa-87');
  ctx.byKey.set(cheat.publicKey, cheat);
  submit(ctx, createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: cheat.publicKey, amount: 2000n * ONE, fee: FEE, nonce: 0 }, { privateKey: ctx.alice.privateKey, extraSigners: { validatorSignature: cheat.privateKey } }));
  finalize(ctx);
  const supplyBefore = ctx.chain.state.supply;

  // The cheat signs two different blocks at the same height and round.
  const vote = (blockHash) => {
    const v = { type: 'prevote', height: ctx.chain.height, round: 0, blockHash, validator: cheat.publicKey };
    return { ...v, signature: sign(voteSignBytes(ctx.genesis.chainId, v), cheat.privateKey) };
  };
  const reporter = generateKeyPair('ml-dsa-65');
  submit(ctx, send(ctx, ctx.alice, addressFromPublicKey(reporter.publicKey), ONE));
  finalize(ctx);
  const evidence = (a, b) => createTx({ type: 'evidence', chainId: ctx.genesis.chainId, voteA: a, voteB: b, fee: FEE, nonce: nonceOf(ctx, reporter) }, { privateKey: reporter.privateKey });
  assert.match(ctx.chain.addTx(evidence(vote('a'.repeat(64)), vote('a'.repeat(64)))).error, /different blocks/);
  assert.match(ctx.chain.addTx(evidence(vote('a'.repeat(64)), { ...vote('b'.repeat(64)), signature: vote('c'.repeat(64)).signature })).error, /invalid vote signature/);
  submit(ctx, evidence(vote('a'.repeat(64)), vote('b'.repeat(64))));
  finalize(ctx);

  assert.equal(ctx.chain.validatorList.length, 4, 'removed from the set at once');
  assert.equal(ctx.chain.state.validator(cheat.publicKey).stake, 1900n * ONE, '5% slashed');
  assert.equal(ctx.chain.state.supply, supplyBefore - 100n * ONE, 'slashed ARGENI is burned');
  finalize(ctx, { advance: DAY });
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, 1_000_000n * ONE - 100n * ONE - 2n * FEE - ONE, 'the rest returned after unbonding');
  const rejoin = createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: cheat.publicKey, amount: 2000n * ONE, fee: FEE, nonce: nonceOf(ctx, ctx.alice) }, { privateKey: ctx.alice.privateKey, extraSigners: { validatorSignature: cheat.privateKey } });
  assert.match(ctx.chain.addTx(rejoin).error, /banned/);
});

test('a validator that stops signing is jailed and lightly slashed, and can come back later', () => {
  const ctx = setup({ validators: 4, staking: { downtimeBlocks: 3, jailMs: DAY, minValidators: 3 } });
  const sleepy = generateKeyPair('ml-dsa-87');
  ctx.byKey.set(sleepy.publicKey, sleepy);
  submit(ctx, createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: sleepy.publicKey, amount: 10_000n * ONE, fee: FEE, nonce: 0 }, { privateKey: ctx.alice.privateKey, extraSigners: { validatorSignature: sleepy.privateKey } }));
  finalize(ctx);
  // Its missed signatures are recorded from each next block's lastCommit; 3 misses in a row = jail.
  for (let i = 0; i < 4; i++) finalize(ctx, { skip: [sleepy.publicKey] });
  const v = ctx.chain.state.validator(sleepy.publicKey);
  assert.equal(v.status, 'jailed');
  assert.equal(v.stake, 9990n * ONE, '0.1% slashed');
  assert.equal(ctx.chain.validatorList.length, 4);

  const unjail = () => createTx({ type: 'validator-unjail', chainId: ctx.genesis.chainId, validator: sleepy.publicKey, fee: FEE, nonce: nonceOf(ctx, ctx.alice) }, { privateKey: ctx.alice.privateKey });
  assert.match(ctx.chain.addTx(unjail()).error, /jailed until/);
  ctx.clock.t += DAY;
  submit(ctx, unjail());
  finalize(ctx, { advance: 0 });
  assert.equal(ctx.chain.validatorList.length, 5);
});

test('a block must carry a quorum of valid signatures for the block before it', () => {
  const ctx = setup();
  finalize(ctx);
  ctx.clock.t += 1000;
  const block = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  assert.equal(block.lastCommit.precommits.length, 4);
  const tamper = (lastCommit) => ctx.chain.validateBlock({ ...block, lastCommit });
  assert.match(tamper(null).error, /lastCommit missing/);
  assert.match(tamper({ ...block.lastCommit, precommits: block.lastCommit.precommits.slice(0, 2) }).error, /lastCommit missing or does not match/);
});

test('a new node starts from a verified snapshot instead of replaying every block', () => {
  const ctx = setup();
  const user = addressFromPublicKey(generateKeyPair('ml-dsa-65').publicKey);
  for (let i = 0; i < 3; i++) {
    submit(ctx, send(ctx, ctx.alice, user, ONE));
    finalize(ctx);
  }
  const snap = JSON.parse(JSON.stringify(ctx.chain.snapshot()));
  const trusted = { height: 3, hash: ctx.chain.tipHash };
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'argeni-snap-'));
  try {
    Chain.verifySnapshot(ctx.genesis, snap, trusted);
    const fresh = new Chain(ctx.genesis, { snapshot: snap, dataDir, now: () => ctx.clock.t });
    assert.equal(fresh.height, 3);
    assert.equal(fresh.state.get(user).balance, 3n * ONE);
    assert.equal(fresh.getBlock(1), null, 'history before the snapshot is not stored');

    // It follows the chain from there, block by block, with full checks.
    submit(ctx, send(ctx, ctx.alice, user, ONE));
    const next = finalize(ctx);
    assert.deepEqual(fresh.addBlock({ ...next, commit: ctx.chain.getBlock(4).commit }), { ok: true });
    assert.equal(fresh.state.root(), ctx.chain.state.root());

    // ...and restarts from its data dir.
    const restarted = new Chain(ctx.genesis, { dataDir, now: () => ctx.clock.t });
    assert.equal(restarted.height, 4);

    // A snapshot with an edited balance, or not matching the trusted block, is refused.
    const forged = structuredClone(snap);
    forged.state.accounts.find(([a]) => a === user)[1].balance = (1000n * ONE).toString();
    assert.throws(() => Chain.verifySnapshot(ctx.genesis, forged), /stateRoot/);
    assert.throws(() => Chain.verifySnapshot(ctx.genesis, snap, { height: 3, hash: 'f'.repeat(64) }), /not the trusted block/);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a validator that stakes in joins a running network and starts voting', async () => {
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const operator = generateKeyPair('ml-dsa-65');
  const owner = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'argeni-join-test', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 40, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: keys.map((k) => k.publicKey), alloc: { [addressFromPublicKey(owner.publicKey)]: (5000n * ONE).toString() },
    staking: { minStake: (1000n * ONE).toString() },
  };
  const members = new Map();
  const broadcast = (from) => (msg) => {
    for (const [key, c] of members) if (key !== from) setTimeout(() => c.handle(structuredClone(msg)), Math.random() * 5);
  };
  const nodes = [...keys, operator].map((key) => {
    const chain = new Chain(genesis);
    const consensus = new Consensus({ chain, privateKey: key.privateKey, broadcast: broadcast(key.publicKey) });
    members.set(key.publicKey, consensus);
    return { key, chain, consensus };
  });
  nodes.forEach((n) => n.consensus.start());
  const waitFor = async (check) => {
    const end = Date.now() + 15_000;
    while (!check()) {
      if (Date.now() > end) throw new Error('timed out');
      await new Promise((r) => setTimeout(r, 10));
    }
  };
  try {
    await waitFor(() => nodes.every((n) => n.chain.height >= 2));
    assert.equal(nodes[4].consensus.status().validator, false, 'follows along before staking');
    const tx = createTx({ type: 'validator-join', chainId: genesis.chainId, validator: operator.publicKey, amount: 1000n * ONE, fee: 1000n, nonce: 0 }, { privateKey: owner.privateKey, extraSigners: { validatorSignature: operator.privateKey } });
    nodes.forEach((n) => n.chain.addTx(tx));
    await waitFor(() => nodes.every((n) => n.chain.validatorList.length === 5));
    const joinedAt = nodes[0].chain.height;
    await waitFor(() => nodes.every((n) => n.chain.height >= joinedAt + 6));
    // The new validator's signatures now appear in finalized blocks, and its turns to propose come up.
    const later = nodes[0].chain.blocks.filter((b) => b.header.height > joinedAt + 1);
    assert.ok(later.some((b) => b.commit.precommits.some((p) => p.validator === operator.publicKey) || b.lastCommit.precommits.some((p) => p.validator === operator.publicKey)));
    assert.ok(later.some((b) => b.header.proposer === operator.publicKey), 'it proposes blocks too');
    for (let h = 1; h <= joinedAt + 6; h++) assert.equal(new Set(nodes.map((n) => n.chain.getBlock(h)?.hash)).size, 1, `agreement at ${h}`);
  } finally {
    nodes.forEach((n) => n.consensus.stop());
  }
});

test('genesis rejects malformed vesting and staking settings', () => {
  const ctx = setup();
  assert.throws(() => new Chain({ ...ctx.genesis, vesting: { [ctx.aliceAddr]: [{ amount: (2_000_000n * ONE).toString(), lockMonths: 12, vestMonths: 24 }] } }), /vesting/);
  assert.throws(() => new Chain({ ...ctx.genesis, staking: { doubleSignSlashBps: 20_000 } }), /staking/);
  assert.throws(() => new Chain({ ...ctx.genesis, validators: [multisigKey(2, [generateKeyPair('ml-dsa-65').publicKey, generateKeyPair('ml-dsa-65').publicKey]), ...ctx.genesis.validators] }), /single key/);
  assert.equal(quorum(5), 4);
});

test('the validator reward pool pays the validators that signed, front-loaded by year, within the fixed supply', () => {
  const ctx = setup({});
  ctx.chain = new Chain({ ...ctx.genesis, rewards: { years: [(1200n * ONE).toString(), (600n * ONE).toString()] } }, { now: () => ctx.clock.t });
  const supply = ctx.chain.state.supply;
  assert.equal(ctx.chain.state.rewardPool, 1800n * ONE, 'the pool is part of the supply from genesis');
  const owner = (k) => addressFromPublicKey(k.publicKey);
  finalize(ctx, { skip: [ctx.keys[3].publicKey] });
  // One month later: year 1 releases 1200 / 12 = 100 ARGENI a month. Validator 4 stays silent.
  ctx.clock.t = ctx.genesis.timestamp + MONTH_MS;
  finalize(ctx, { advance: 0, skip: [ctx.keys[3].publicKey] });
  finalize(ctx, { skip: [ctx.keys[3].publicKey] }); // carries the signatures (3 of 4) for the block above
  const paid = ctx.chain.state.rewardsPaid;
  assert.ok(paid > 99n * ONE && paid < 100n * ONE + ONE / 1000n, `about a month of year-1 rewards paid (${paid})`); // + a few seconds
  const shares = ctx.keys.map((k) => ctx.chain.state.get(owner(k)).balance);
  assert.equal(shares[3], 0n, 'a validator that did not sign earns nothing for that block');
  assert.ok(shares[0] > 0n && shares[0] === shares[1] && shares[1] === shares[2], 'signers share equally');
  assert.equal(ctx.chain.state.supply, supply, 'paying rewards never creates coins');
  // Year 2 is smaller: after 18 months, 1200 + 300 have been released.
  ctx.clock.t = ctx.genesis.timestamp + 18 * MONTH_MS;
  finalize(ctx, { advance: 0 });
  finalize(ctx);
  assert.ok(ctx.chain.state.rewardsPaid > 1499n * ONE && ctx.chain.state.rewardsPaid < 1500n * ONE + ONE / 1000n);
  assert.equal(ctx.chain.state.rewardPool + ctx.chain.state.rewardsPaid, 1800n * ONE);
});

test('delegated stake: the operator runs the validator and earns; the stake returns to the provider', () => {
  const ctx = setup({ staking: { unbondingMs: DAY } });
  ctx.chain = new Chain({ ...ctx.genesis, rewards: { years: [(1200n * ONE).toString()] } }, { now: () => ctx.clock.t });
  const operatorAccount = generateKeyPair('ml-dsa-65');
  const operatorAddr = addressFromPublicKey(operatorAccount.publicKey);
  const vkey = generateKeyPair('ml-dsa-87');
  ctx.byKey.set(vkey.publicKey, vkey);
  // The operator's validator key consents (no nonce involved); the provider (e.g. the ecosystem fund) submits.
  const offer = createTx({ type: 'validator-join', chainId: ctx.genesis.chainId, validator: vkey.publicKey, operator: operatorAddr, amount: 1000n * ONE, fee: FEE, nonce: 0 }, { privateKey: ctx.alice.privateKey });
  submit(ctx, { ...offer, validatorSignature: sign(validatorConsentBytes(offer), vkey.privateKey) });
  finalize(ctx);
  assert.equal(ctx.chain.state.validator(vkey.publicKey).operator, operatorAddr);
  ctx.clock.t = ctx.genesis.timestamp + MONTH_MS;
  for (let i = 0; i < 6; i++) finalize(ctx, { advance: i ? 1000 : 0 });
  assert.ok(ctx.chain.state.get(operatorAddr).balance > 0n, 'rewards and fees go to the operator');
  const aliceBefore = ctx.chain.state.get(ctx.aliceAddr).balance;

  // The operator can take the validator out (it needs a little ARGENI for the fee, which it has earned).
  submit(ctx, createTx({ type: 'validator-leave', chainId: ctx.genesis.chainId, validator: vkey.publicKey, fee: FEE, nonce: 0 }, { privateKey: operatorAccount.privateKey }));
  finalize(ctx);
  // Only the provider can add stake.
  assert.match(ctx.chain.addTx(createTx({ type: 'validator-bond', chainId: ctx.genesis.chainId, validator: vkey.publicKey, amount: ONE, fee: FEE, nonce: 1 }, { privateKey: operatorAccount.privateKey })).error, /owner account/);
  finalize(ctx, { advance: DAY });
  assert.equal(ctx.chain.state.get(ctx.aliceAddr).balance, aliceBefore + 1000n * ONE, 'the stake went back to the provider, not the operator');
});

test('the mainnet genesis builder writes the planned allocation into the chain', async () => {
  const { buildGenesis, PLAN } = await import('../scripts/mainnet-genesis.js');
  const addr = () => addressFromPublicKey(generateKeyPair('ml-dsa-65').publicKey);
  const [f1, f2] = [addr(), addr()];
  const config = {
    chainId: 'argeni-1', launch: 1_800_000_000_000, validators: Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65').publicKey),
    addresses: { ecosystem: addr(), treasury: addr(), publicDistribution: addr(), partners: addr(), teamPool: addr(), liquidity: addr(), founders: { [f1]: '30000000', [f2]: '10000000' } },
  };
  const genesis = buildGenesis(config);
  const chain = new Chain(genesis, { now: () => genesis.timestamp });
  assert.equal(chain.state.supply, 500_000_000n * ONE, 'exactly 500,000,000 ARGENI');
  assert.equal(chain.state.rewardPool, 60_000_000n * ONE);
  const t0 = genesis.timestamp;
  const free = (a, t) => chain.state.spendable(a, t);
  assert.equal(free(config.addresses.ecosystem, t0), 15_000_000n * ONE, 'ecosystem: 10% free at launch');
  assert.equal(free(config.addresses.treasury, t0 + 5 * MONTH_MS), 0n, 'treasury locked for 6 months');
  assert.equal(free(f1, t0 + 12 * MONTH_MS), 0n, 'founders locked for 12 months');
  assert.equal(free(f1, t0 + 13 * MONTH_MS), 1_250_000n * ONE, 'then 1/24 a month');
  assert.equal(free(f1, t0 + 36 * MONTH_MS), 30_000_000n * ONE, 'fully free after 3 years');
  assert.equal(free(config.addresses.liquidity, t0), 25_000_000n * ONE);
  assert.equal(PLAN.validatorRewards.reduce((s, x) => s + x, 0n), 60_000_000n);
  assert.equal(chain.state.get(config.addresses.teamPool).balance, 35_000_000n * ONE, 'team pool = 75M team allocation minus founder vaults');
  assert.throws(() => buildGenesis({ ...config, addresses: { ...config.addresses, founders: { [f1]: '75000000' } } }), /team pool/);
});
