// Q-Day Tripwire: ownerless bait keys, commit-reveal bounty claims and the automatic defense levels.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Chain, State, quorum, voteSignBytes } from '../src/chain.js';
import { addressFromPublicKey, generateKeyPair, sign } from '../src/crypto.js';
import { createMigration, createMigrationCommit, createTransfer, createTx, checkTx } from '../src/tx.js';
import { CURVES, RSA_2048, RUNG_IDS, alertLevel, canaryCommitment, checkSolution, multiply, onCurve, rungInfo, rungPoint, testing } from '../src/tripwire.js';

const ONE = 10n ** 18n;
const BILLION = 1_000_000_000n * ONE;
const FEE = 1000n;
const BOUNTY = 1_000_000n * ONE;
const NODE_CURVES = { 'ecc-160': 'secp160r1', 'ecc-192': 'prime192v1', 'ecc-224': 'secp224r1', 'ecc-256': 'prime256v1', secp256k1: 'secp256k1' };

afterEach(() => testing.clear());

function setup({ tripwire = { bounties: Object.fromEntries(RUNG_IDS.map((id) => [id, BOUNTY.toString()])), revealDelayBlocks: 3, graceBlocks: 20 }, tripwireExtra = {}, sunset } = {}) {
  if (tripwire) tripwire = { ...tripwire, ...tripwireExtra };
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const legacy = generateKeyPair('ed25519');
  const committed = generateKeyPair('ed25519');
  const hunter = generateKeyPair('ml-dsa-65');
  const thief = generateKeyPair('ml-dsa-65');
  const alloc = Object.fromEntries([legacy, committed, hunter, thief].map((k) => [addressFromPublicKey(k.publicKey), (100n * ONE).toString()]));
  const genesis = {
    chainId: 'argeni-tripwire-test', timestamp: 1_000_000, coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: BILLION.toString(),
    validators: keys.map((k) => k.publicKey), alloc,
    ...(tripwire ? { tripwire } : {}),
    ...(sunset ? { ed25519SunsetHeight: sunset } : {}),
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  return { genesis, chain, clock, keys, legacy, committed, hunter, thief, addr: (k) => addressFromPublicKey(k.publicKey) };
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

const nonceOf = (ctx, k) => ctx.chain.pendingNonce(ctx.addr(k));
const commitTx = (ctx, k, rung, solution) => createTx({ type: 'canary-commit', chainId: ctx.genesis.chainId, fee: FEE, nonce: nonceOf(ctx, k), commitment: canaryCommitment(ctx.genesis.chainId, rung, ctx.addr(k), solution) }, { privateKey: k.privateKey });
const revealTx = (ctx, k, rung, solution) => createTx({ type: 'canary-reveal', chainId: ctx.genesis.chainId, fee: FEE, nonce: nonceOf(ctx, k), rung, solution }, { privateKey: k.privateKey });

// A solvable stand-in for a curve rung: a random private key d and its point d·G.
function weakTarget(rung) {
  const c = CURVES[rung];
  const d = BigInt('0x' + crypto.randomBytes(40).toString('hex')) % (c.n - 1n) + 1n;
  const [x, y] = multiply(c, d);
  testing.setTarget(rung, { x, y });
  return d.toString(16);
}

// Commits, waits out the reveal delay and reveals. Returns the reveal block.
function claim(ctx, k, rung, solution) {
  assert.equal(ctx.chain.addTx(commitTx(ctx, k, rung, solution)).ok, true);
  finalize(ctx);
  for (let i = 0; i < ctx.genesis.tripwire.revealDelayBlocks; i++) finalize(ctx);
  const r = ctx.chain.addTx(revealTx(ctx, k, rung, solution));
  assert.equal(r.ok, true, r.error);
  return finalize(ctx);
}

test('bait points are on their curves, the same everywhere, and match the published rung info', () => {
  for (const id of Object.keys(CURVES)) {
    const pt = rungPoint(id);
    assert.equal(onCurve(CURVES[id], [pt.x, pt.y]), true, id);
    assert.equal(pt.y % 2n, 0n);
    const info = rungInfo(id);
    assert.equal(BigInt('0x' + info.target.x), pt.x);
    assert.equal(BigInt('0x' + info.target.y), pt.y);
  }
  assert.equal(RSA_2048.toString(10).length, 617);
  assert.equal(RSA_2048.toString(2).length, 2048);
});

test('curve arithmetic matches node:crypto on every rung curve', () => {
  for (const [id, name] of Object.entries(NODE_CURVES)) {
    const c = CURVES[id];
    const d = BigInt('0x' + crypto.randomBytes(40).toString('hex')) % (c.n - 1n) + 1n;
    const ecdh = crypto.createECDH(name);
    ecdh.setPrivateKey(Buffer.from(d.toString(16).padStart(Math.ceil(c.n.toString(16).length / 2) * 2, '0'), 'hex'));
    const pub = ecdh.getPublicKey('hex');
    const half = (pub.length - 2) / 2;
    assert.deepEqual(multiply(c, d), [BigInt('0x' + pub.slice(2, 2 + half)), BigInt('0x' + pub.slice(2 + half))], id);
    assert.equal(multiply(c, c.n), null, `${id}: n·G is the point at infinity`);
  }
});

test('solutions: only the real private key or the real factors break a rung', () => {
  const d = weakTarget('ecc-160');
  assert.equal(checkSolution('ecc-160', d), true);
  assert.equal(checkSolution('ecc-160', d.toUpperCase()), true);
  assert.equal(checkSolution('ecc-160', (BigInt('0x' + d) + 1n).toString(16)), false);
  assert.equal(checkSolution('ecc-160', '0'), false);
  assert.equal(checkSolution('ecc-160', 'xyz'), false);
  assert.equal(checkSolution('ecc-256', d), false, 'a key for another rung does not work');
  assert.equal(checkSolution('rsa-2048', '3.5'), false);
  testing.setTarget('rsa-2048', { n: 1009n * 2003n });
  assert.equal(checkSolution('rsa-2048', `${(1009).toString(16)}.${(2003).toString(16)}`), true);
  assert.equal(checkSolution('rsa-2048', `${(2003).toString(16)}.${(1009).toString(16)}`), false, 'factors must be in order p < q');
  assert.equal(checkSolution('rsa-2048', `1.${(1009n * 2003n).toString(16)}`), false, 'trivial factors do not count');
});

test('genesis: bounties are part of the fixed supply and must be well formed', () => {
  const ctx = setup();
  assert.equal(ctx.chain.state.canary.pool, BOUNTY * BigInt(RUNG_IDS.length));
  assert.equal(ctx.chain.state.supply, 400n * ONE + BOUNTY * BigInt(RUNG_IDS.length));
  assert.throws(() => setup({ tripwire: { bounties: { 'ecc-999': '1' } } }), /tripwire/);
  assert.throws(() => setup({ tripwire: { bounties: { 'ecc-160': BILLION.toString() } } }), /maxSupply/);
  assert.throws(() => setup({ tripwire: { bounties: {} } }), /tripwire/);
});

test('a valid claim pays the bounty and records the break; the rung cannot be claimed twice', () => {
  const ctx = setup();
  const d = weakTarget('ecc-160');
  const before = ctx.chain.state.get(ctx.addr(ctx.hunter)).balance;
  const block = claim(ctx, ctx.hunter, 'ecc-160', d);
  assert.equal(ctx.chain.state.get(ctx.addr(ctx.hunter)).balance, before + BOUNTY - 2n * FEE);  // the commitment deposit was locked at commit and returned with the bounty
  assert.deepEqual(ctx.chain.state.canary.broken['ecc-160'], { height: block.header.height, by: ctx.addr(ctx.hunter) });
  assert.equal(alertLevel(ctx.chain.state.canary.broken), 1);
  assert.equal(ctx.chain.retiredAt('ed25519'), undefined, 'level 1 changes no rules');
  assert.equal(ctx.chain.addTx(commitTx(ctx, ctx.thief, 'ecc-160', d)).ok, true);
  finalize(ctx);
  for (let i = 0; i < 3; i++) finalize(ctx);
  assert.match(ctx.chain.addTx(revealTx(ctx, ctx.thief, 'ecc-160', d)).error, /already broken/);
});

test('reveals need an earlier commit from the same account, and must wait out the delay', () => {
  const ctx = setup();
  const d = weakTarget('ecc-192');
  assert.match(ctx.chain.addTx(revealTx(ctx, ctx.hunter, 'ecc-192', d)).error, /commit first/);
  assert.equal(ctx.chain.addTx(commitTx(ctx, ctx.hunter, 'ecc-192', d)).ok, true);
  finalize(ctx);
  assert.match(ctx.chain.addTx(revealTx(ctx, ctx.hunter, 'ecc-192', d)).error, /too early/);
  // Someone who copies the solution from the mempool has no commitment of their own in time.
  assert.match(ctx.chain.addTx(revealTx(ctx, ctx.thief, 'ecc-192', d)).error, /commit first/);
  assert.match(ctx.chain.addTx(commitTx(ctx, ctx.hunter, 'ecc-192', d)).error, /already made/);
});

test('a wrong solution is rejected even with a matching commitment', () => {
  const ctx = setup();
  weakTarget('ecc-160');
  assert.match(checkTx(revealTx(ctx, ctx.hunter, 'ecc-160', 'zz'), ctx.genesis), /hex private key/);
  assert.equal(ctx.chain.addTx(commitTx(ctx, ctx.hunter, 'ecc-160', 'abc123')).ok, true);
  for (let i = 0; i < 4; i++) finalize(ctx);
  assert.match(ctx.chain.addTx(revealTx(ctx, ctx.hunter, 'ecc-160', 'abc123')).error, /does not break/);
});

test('level 2 (ECC-224 broken) brings the Ed25519 sunset forward by graceBlocks', () => {
  const ctx = setup({ sunset: 10_000 });
  const block = claim(ctx, ctx.hunter, 'ecc-224', weakTarget('ecc-224'));
  assert.equal(alertLevel(ctx.chain.state.canary.broken), 2);
  assert.equal(ctx.chain.retiredAt('ed25519'), block.header.height + 20);
  // Ed25519 accounts still work during the grace period.
  assert.equal(ctx.chain.addTx(createTransfer({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, to: ctx.addr(ctx.hunter), amount: ONE, fee: FEE, nonce: 0 })).ok, true);
});

test('level 3 (a 256-bit curve broken) retires Ed25519 from the next block; committed accounts can still escape', () => {
  const ctx = setup();
  // Before the break: one Ed25519 account commits to its future post-quantum key.
  const escape = generateKeyPair('ml-dsa-65');
  assert.equal(ctx.chain.addTx(createMigrationCommit({ chainId: ctx.genesis.chainId, privateKey: ctx.committed.privateKey, pqPublicKey: escape.publicKey, fee: FEE, nonce: 0 })).ok, true);
  assert.equal(ctx.chain.addTx(createTransfer({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, to: ctx.addr(ctx.hunter), amount: ONE, fee: FEE, nonce: 0 })).ok, true);
  finalize(ctx);

  const block = claim(ctx, ctx.hunter, 'secp256k1', weakTarget('secp256k1'));
  assert.equal(alertLevel(ctx.chain.state.canary.broken), 3);
  assert.equal(ctx.chain.retiredAt('ed25519'), block.header.height + 1);

  // Classical keys can no longer send...
  assert.match(ctx.chain.addTx(createTransfer({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, to: ctx.addr(ctx.hunter), amount: ONE, fee: FEE, nonce: 1 })).error, /retired/);
  // ...an exposed key without a commitment cannot migrate (a quantum attacker could be holding it)...
  const grab = generateKeyPair('ml-dsa-65');
  assert.match(ctx.chain.addTx(createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.legacy.privateKey, pqPrivateKey: grab.privateKey, fee: FEE, nonce: 1 })).error, /no migration commitment/);
  // ...but the committed account moves to its committed key.
  assert.equal(ctx.chain.addTx(createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.committed.privateKey, pqPrivateKey: escape.privateKey, fee: FEE, nonce: 1 })).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.addr(ctx.committed)).migratedTo, addressFromPublicKey(escape.publicKey));
});

test('factoring RSA-2048 triggers level 2 (prepare): a factoring break alone does not prove Ed25519 is broken', () => {
  const ctx = setup();
  testing.setTarget('rsa-2048', { n: 1009n * 2003n });
  const block = claim(ctx, ctx.hunter, 'rsa-2048', `${(1009).toString(16)}.${(2003).toString(16)}`);
  assert.equal(ctx.chain.retiredAt('ed25519'), block.header.height + ctx.chain.tripwire.graceBlocks);
});

test('the tripwire never pushes a planned sunset later', () => {
  const ctx = setup({ sunset: 8 });
  claim(ctx, ctx.hunter, 'ecc-224', weakTarget('ecc-224'));
  assert.equal(ctx.chain.retiredAt('ed25519'), 8);
});

test('tripwire state is part of the state root and survives a snapshot', () => {
  const ctx = setup();
  claim(ctx, ctx.hunter, 'ecc-160', weakTarget('ecc-160'));
  const copy = State.fromJSON(JSON.parse(JSON.stringify(ctx.chain.state.toJSON())));
  assert.equal(copy.root(), ctx.chain.state.root());
  assert.deepEqual(copy.canary.broken, ctx.chain.state.canary.broken);
  const changed = ctx.chain.state.clone();
  changed.canary.pool -= 1n;
  assert.notEqual(changed.root(), ctx.chain.state.root());
});

test('a chain without a tripwire refuses canary transactions', () => {
  const ctx = setup({ tripwire: null });
  assert.equal(ctx.chain.state.canary, null);
  assert.match(ctx.chain.addTx(commitTx(ctx, ctx.hunter, 'ecc-160', 'abc')).error, /no Q-Day Tripwire/);
});

test('end to end: a node publishes the ladder and accepts a claim over HTTP', async () => {
  const net = await import('node:net');
  const { Node, fetchJson } = await import('../src/node.js');
  const port = await new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  const validator = generateKeyPair('ml-dsa-65');
  const hunter = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'argeni-tripwire-e2e', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 100, emptyBlockIntervalMs: 100, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: BILLION.toString(),
    validators: [validator.publicKey], alloc: { [addressFromPublicKey(hunter.publicKey)]: (100n * ONE).toString() },
    tripwire: { bounties: { 'ecc-160': BOUNTY.toString(), 'ecc-256': (5n * BOUNTY).toString() }, revealDelayBlocks: 2 },
  };
  const node = new Node({ genesis, port, peers: [], validatorKey: validator.privateKey, log: () => {} });
  await node.start();
  const url = `http://127.0.0.1:${port}`;
  const post = (tx) => fetchJson(`${url}/txs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) });
  const waitFor = async (check) => { for (let i = 0; i < 150; i++) { if (await check()) return; await new Promise((r) => setTimeout(r, 100)); } throw new Error('timed out'); };
  const hunterAddr = addressFromPublicKey(hunter.publicKey);
  try {
    const ladder = await fetchJson(`${url}/tripwire`);
    assert.equal(ladder.level, 0);
    assert.deepEqual(ladder.rungs.map((r) => r.id), ['ecc-160', 'ecc-256']);
    assert.equal(ladder.rungs[1].bounty, '5000000 ARGENI');
    assert.equal(BigInt('0x' + ladder.rungs[1].target.x), rungPoint('ecc-256').x);

    const d = weakTarget('ecc-160');
    const nonce = async () => (await fetchJson(`${url}/accounts/${hunterAddr}`)).pendingNonce;
    await post(createTx({ type: 'canary-commit', chainId: genesis.chainId, fee: FEE, nonce: await nonce(), commitment: canaryCommitment(genesis.chainId, 'ecc-160', hunterAddr, d) }, { privateKey: hunter.privateKey }));
    const committedAt = (await fetchJson(`${url}/status`)).height;
    await waitFor(async () => (await fetchJson(`${url}/status`)).height >= committedAt + 4);
    await post(createTx({ type: 'canary-reveal', chainId: genesis.chainId, fee: FEE, nonce: await nonce(), rung: 'ecc-160', solution: d }, { privateKey: hunter.privateKey }));
    await waitFor(async () => (await fetchJson(`${url}/tripwire`)).level === 1);
    const after = await fetchJson(`${url}/tripwire`);
    assert.equal(after.rungs[0].broken.by, hunterAddr);
    assert.equal(after.bountyPoolLeft, '5000000 ARGENI');
    assert.equal((await fetchJson(`${url}/accounts/${hunterAddr}`)).balance, (100n * ONE + BOUNTY - 2n * FEE).toString()); // deposit refunded with the bounty
  } finally {
    await node.stop();
  }
});

test('a commitment locks a deposit: refunded with the bounty, forfeited to the pool if it lapses', () => {
  const ctx = setup({ tripwireExtra: { commitTtlBlocks: 3 } });
  const deposit = ctx.chain.tripwire.commitDeposit;
  const poolBefore = ctx.chain.state.canary.pool;
  const before = ctx.chain.state.get(ctx.addr(ctx.thief)).balance;
  // A junk commitment that is never revealed.
  assert.equal(ctx.chain.addTx(commitTx(ctx, ctx.thief, 'ecc-256', 'abc')).ok, true);
  finalize(ctx);
  assert.equal(ctx.chain.state.get(ctx.addr(ctx.thief)).balance, before - deposit - FEE, 'the deposit is locked');
  for (let i = 0; i < 3; i++) finalize(ctx);
  assert.equal(Object.keys(ctx.chain.state.canary.commits).length, 0, 'the lapsed commitment is gone from the state');
  assert.equal(ctx.chain.state.canary.pool, poolBefore + deposit, 'its deposit went to the bounty pool');
});
