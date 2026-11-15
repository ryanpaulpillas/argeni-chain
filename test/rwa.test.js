// ARS-1 real-world assets: compliance enforced by consensus, and post-quantum-only administration.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Chain, State, quorum, voteSignBytes } from '../src/chain.js';
import { addressFromPublicKey, generateKeyPair, sha256, sign } from '../src/crypto.js';
import { createMigration, createTx, checkTx } from '../src/tx.js';
import { assetIdFor } from '../src/rwa.js';

const ONE = 10n ** 18n;
const FEE = 1000n;
const DOC = sha256('offering documents');
const H = (s) => sha256(s);

function setup() {
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const k = {
    issuer: generateKeyPair('ml-dsa-87'),
    compliance: generateKeyPair('ml-dsa-65'),
    recovery: generateKeyPair('ml-dsa-65'),
    attestor: generateKeyPair('ml-dsa-65'),
    alice: generateKeyPair('ml-dsa-65'), // Filipino, qualified
    bob: generateKeyPair('ml-dsa-65'), // Filipino, qualified
    yuki: generateKeyPair('ml-dsa-65'), // foreign, qualified
    rita: generateKeyPair('ml-dsa-65'), // Filipino, retail
    legacy: generateKeyPair('ed25519'),
    vault: generateKeyPair('slh-dsa-128s'),
  };
  const alloc = Object.fromEntries(Object.values(k).map((key) => [addressFromPublicKey(key.publicKey), (100n * ONE).toString()]));
  const genesis = {
    chainId: 'cyvber-rwa-test', timestamp: 1_000_000, coin: { name: 'CYVBER', symbol: 'CYVBER', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: keys.map((v) => v.publicKey), alloc,
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  const addr = (key) => addressFromPublicKey(key.publicKey);
  return { genesis, chain, clock, keys, k, addr };
}

function finalize(ctx) {
  ctx.clock.t += ctx.genesis.blockTimeMs;
  const block = ctx.chain.buildBlock(ctx.keys[0].publicKey);
  const precommits = ctx.keys.slice(0, quorum(4)).map((v) => {
    const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: v.publicKey };
    return { ...vote, signature: sign(voteSignBytes(ctx.genesis.chainId, vote), v.privateKey) };
  });
  assert.deepEqual(ctx.chain.addBlock({ ...block, commit: { round: 0, precommits } }), { ok: true });
  return block;
}

const build = (ctx, key, fields) => createTx({ chainId: ctx.genesis.chainId, fee: FEE, nonce: ctx.chain.pendingNonce(ctx.addr(key)), ...fields }, { privateKey: key.privateKey });

// Submits and finalizes; fails the test if the chain refuses.
function ok(ctx, key, fields) {
  const r = ctx.chain.addTx(build(ctx, key, fields));
  assert.equal(r.ok, true, `${fields.type}: ${r.error}`);
  finalize(ctx);
}

// Asserts the chain refuses the transaction with a matching error.
function refused(ctx, key, fields, pattern) {
  const r = ctx.chain.addTx(build(ctx, key, fields));
  assert.equal(r.ok, false, `${fields.type} should have been refused`);
  assert.match(r.error, pattern);
}

const RULES = { kycRequired: true, investorClasses: ['qualified'], allowedCountries: ['*'], foreignCapBps: 4000, maxHolders: 200, lockupUntilHeight: 0, minHoldingUnits: '1', redeemable: false };
const LEGAL = { entity: 'Pilot Property Holdings Inc.', secRegNo: 'TEST-0001', offering: 'pilot', jurisdiction: 'PH', docsHash: DOC, docsUri: 'https://cyvber.com/assets/PHRE1' };

function createAsset(ctx, { issuer = ctx.k.issuer, symbol = 'PHRE1', rules = {}, maxSupply = '1000' } = {}) {
  const roles = { compliance: ctx.addr(ctx.k.compliance), recovery: ctx.addr(ctx.k.recovery), attestor: ctx.addr(ctx.k.attestor) };
  ok(ctx, issuer, { type: 'asset-create', symbol, name: 'Pilot Property Holdings Inc. - Class A', class: 'real-estate', decimals: 0, maxSupply, roles, legal: LEGAL, rules: { ...RULES, ...rules } });
  return assetIdFor(ctx.genesis.chainId, ctx.addr(issuer), symbol);
}

function kyc(ctx, who, { country = 'PH', foreign = false, investorClass = 'qualified', expiresHeight = 1_000_000 } = {}) {
  ok(ctx, ctx.k.compliance, { type: 'kyc-attest', address: ctx.addr(who), level: 2, country, foreign, investorClass, expiresHeight, recordHash: H(`kyc file ${ctx.addr(who)}`) });
}

const bal = (ctx, assetId, who) => ctx.chain.state.rwa.balances[assetId]?.[ctx.addr(who)]?.balance ?? '0';
const asset = (ctx, assetId) => ctx.chain.state.rwa.assets[assetId];

test('an asset is created, investors are verified, units are issued and traded, and fees are paid in CYVBER', () => {
  const ctx = setup();
  const before = ctx.chain.state.root();
  const id = createAsset(ctx);
  assert.notEqual(ctx.chain.state.root(), before, 'asset state is part of the state root');
  kyc(ctx, ctx.k.alice);
  kyc(ctx, ctx.k.bob);
  const cyvberBefore = ctx.chain.state.get(ctx.addr(ctx.k.alice)).balance;
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 100n, docRef: H('subscription agreement') });
  ok(ctx, ctx.k.alice, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.bob), amount: 30n });
  assert.equal(bal(ctx, id, ctx.k.alice), '70');
  assert.equal(bal(ctx, id, ctx.k.bob), '30');
  assert.equal(asset(ctx, id).supply, '100');
  assert.equal(asset(ctx, id).holders, 2);
  assert.equal(ctx.chain.state.get(ctx.addr(ctx.k.alice)).balance, cyvberBefore - FEE, 'the transfer fee is paid in CYVBER');
  ok(ctx, ctx.k.attestor, { type: 'asset-attest', assetId: id, kind: 'appraisal', valueHash: H('appraisal report'), uri: 'https://cyvber.com/assets/PHRE1/appraisal' });
  assert.equal(asset(ctx, id).lastAttestation.kind, 'appraisal');
  refused(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 901n, docRef: H('x') }, /maximum supply/);
});

test('a classical key can never administer an asset; only post-quantum keys can', () => {
  const ctx = setup();
  const roles = { compliance: ctx.addr(ctx.k.compliance), recovery: ctx.addr(ctx.k.recovery), attestor: null };
  const create = build(ctx, ctx.k.legacy, { type: 'asset-create', symbol: 'OLD1', name: 'Classical issuer', class: 'equity', decimals: 0, maxSupply: '10', roles, legal: LEGAL, rules: RULES });
  assert.match(checkTx(create, ctx.genesis), /post-quantum key/);
  refused(ctx, ctx.k.legacy, { type: 'kyc-attest', address: ctx.addr(ctx.k.alice), level: 1, country: 'PH', foreign: false, investorClass: 'retail', expiresHeight: 100, recordHash: H('k') }, /classical key can never administer/);
  // An Ed25519 holder can still hold and trade units; only administration is post-quantum only.
  const id = createAsset(ctx, { rules: { kycRequired: false, investorClasses: ['retail'] } });
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.legacy), amount: 5n, docRef: H('s') });
  ok(ctx, ctx.k.legacy, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.alice), amount: 2n });
  assert.equal(bal(ctx, id, ctx.k.alice), '2');
});

test('an asset can require hash-based SLH-DSA admin keys, and that can never be relaxed', () => {
  const ctx = setup();
  refused(ctx, ctx.k.issuer, { type: 'asset-create', symbol: 'VAULT1', name: 'Hash-based', class: 'debt', decimals: 0, maxSupply: '10', roles: { compliance: ctx.addr(ctx.k.compliance), recovery: ctx.addr(ctx.k.recovery), attestor: null }, legal: LEGAL, rules: { ...RULES, adminKeys: 'hash-based' } }, /hash-based SLH-DSA/);
  const id = createAsset(ctx, { issuer: ctx.k.vault, symbol: 'VAULT1', rules: { adminKeys: 'hash-based' } });
  assert.equal(asset(ctx, id).rules.adminKeys, 'hash-based');
  kyc(ctx, ctx.k.alice);
  // The ML-DSA compliance key may no longer freeze units of this asset.
  refused(ctx, ctx.k.compliance, { type: 'asset-freeze', assetId: id, address: ctx.addr(ctx.k.alice), reasonHash: H('r') }, /hash-based SLH-DSA/);
  refused(ctx, ctx.k.vault, { type: 'asset-update', assetId: id, rules: { ...RULES, adminKeys: 'pq' } }, /cannot be relaxed/);
  ok(ctx, ctx.k.vault, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 3n, docRef: H('s') });
});

test('every transfer rule is enforced by the chain', () => {
  const ctx = setup();
  const id = createAsset(ctx, { rules: { maxHolders: 2, minHoldingUnits: '10', allowedCountries: ['PH', 'JP'] } });
  kyc(ctx, ctx.k.alice);
  kyc(ctx, ctx.k.bob);
  kyc(ctx, ctx.k.rita, { investorClass: 'retail' });
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 100n, docRef: H('s') });
  const transfer = (to, amount) => ({ type: 'asset-transfer', assetId: id, to: ctx.addr(to), amount });

  refused(ctx, ctx.k.alice, transfer(ctx.k.yuki, 20n), /no valid KYC/);
  refused(ctx, ctx.k.alice, transfer(ctx.k.rita, 20n), /investor class \(retail\)/);
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 5n), /minimum of 10/);
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 95n), /left below the minimum/);
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 101n), /insufficient PHRE1 balance/);
  ok(ctx, ctx.k.alice, transfer(ctx.k.bob, 50n));
  kyc(ctx, ctx.k.yuki, { country: 'JP', foreign: true });
  refused(ctx, ctx.k.alice, transfer(ctx.k.yuki, 20n), /at most 2 holders/);

  // Country list, pause, freeze and lock-up.
  kyc(ctx, ctx.k.yuki, { country: 'US', foreign: true });
  ok(ctx, ctx.k.issuer, { type: 'asset-update', assetId: id, rules: { ...RULES, maxHolders: 5, minHoldingUnits: '10', allowedCountries: ['PH', 'JP'] } });
  refused(ctx, ctx.k.alice, transfer(ctx.k.yuki, 20n), /holders from US/);
  ok(ctx, ctx.k.compliance, { type: 'asset-pause', assetId: id, reasonHash: H('maintenance') });
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 10n), /paused/);
  ok(ctx, ctx.k.compliance, { type: 'asset-unpause', assetId: id, reasonHash: H('done') });
  ok(ctx, ctx.k.compliance, { type: 'asset-freeze', assetId: id, address: ctx.addr(ctx.k.bob), reasonHash: H('AMLC freeze order') });
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 10n), /receiver's PHRE1 units are frozen/);
  refused(ctx, ctx.k.bob, transfer(ctx.k.alice, 10n), /your PHRE1 units are frozen/);
  ok(ctx, ctx.k.compliance, { type: 'asset-unfreeze', assetId: id, address: ctx.addr(ctx.k.bob), reasonHash: H('lifted') });
  ok(ctx, ctx.k.issuer, { type: 'asset-update', assetId: id, rules: { ...RULES, maxHolders: 5, minHoldingUnits: '10', lockupUntilHeight: 1000 } });
  refused(ctx, ctx.k.alice, transfer(ctx.k.bob, 10n), /locked up until block 1000/);

  // Only the right role can act.
  refused(ctx, ctx.k.alice, { type: 'asset-freeze', assetId: id, address: ctx.addr(ctx.k.bob), reasonHash: H('r') }, /only the asset's compliance/);
  refused(ctx, ctx.k.compliance, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.bob), amount: 10n, docRef: H('s') }, /only the asset's issuer/);
});

test('the 40% foreign-ownership cap holds exactly, and neither issuance nor recovery can bypass KYC or the cap', () => {
  const ctx = setup();
  const id = createAsset(ctx, { rules: { minHoldingUnits: '0' } });
  kyc(ctx, ctx.k.alice);
  kyc(ctx, ctx.k.yuki, { country: 'JP', foreign: true });
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 60n, docRef: H('s') });
  refused(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.yuki), amount: 41n, docRef: H('s') }, /more than 40%/);
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.yuki), amount: 40n, docRef: H('s') }); // exactly 40 of 100
  assert.equal(asset(ctx, id).foreignUnits, '40');
  refused(ctx, ctx.k.alice, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.yuki), amount: 1n }, /more than 40%/);
  refused(ctx, ctx.k.recovery, { type: 'asset-force-transfer', assetId: id, holder: ctx.addr(ctx.k.alice), to: ctx.addr(ctx.k.yuki), amount: 1n, orderHash: H('court order') }, /more than 40%/);
  refused(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.bob), amount: 1n, docRef: H('s') }, /no valid KYC/);
  refused(ctx, ctx.k.recovery, { type: 'asset-force-transfer', assetId: id, holder: ctx.addr(ctx.k.alice), to: ctx.addr(ctx.k.bob), amount: 1n, orderHash: H('order') }, /no valid KYC/);
  // Re-flagging a domestic holder as foreign is refused when it would break the cap.
  refused(ctx, ctx.k.compliance, { type: 'kyc-attest', address: ctx.addr(ctx.k.alice), level: 2, country: 'JP', foreign: true, investorClass: 'qualified', expiresHeight: 1_000_000, recordHash: H('k') }, /foreign-ownership cap/);
  // Expired KYC no longer qualifies.
  kyc(ctx, ctx.k.bob, { expiresHeight: ctx.chain.height + 2 });
  finalize(ctx);
  finalize(ctx);
  refused(ctx, ctx.k.alice, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.bob), amount: 1n }, /no valid KYC/);
});

test('revoking KYC freezes the investor; recovery moves units under a court order; redemption follows the rules', () => {
  const ctx = setup();
  const id = createAsset(ctx);
  kyc(ctx, ctx.k.alice);
  kyc(ctx, ctx.k.bob);
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 50n, docRef: H('s') });
  ok(ctx, ctx.k.compliance, { type: 'kyc-revoke', address: ctx.addr(ctx.k.alice), reasonHash: H('sanctions hit') });
  refused(ctx, ctx.k.alice, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.bob), amount: 10n }, /frozen/);
  refused(ctx, ctx.k.issuer, { type: 'asset-force-transfer', assetId: id, holder: ctx.addr(ctx.k.alice), to: ctx.addr(ctx.k.bob), amount: 50n, orderHash: H('o') }, /only the asset's recovery/);
  ok(ctx, ctx.k.recovery, { type: 'asset-force-transfer', assetId: id, holder: ctx.addr(ctx.k.alice), to: ctx.addr(ctx.k.bob), amount: 50n, orderHash: H('court order') });
  assert.equal(bal(ctx, id, ctx.k.bob), '50');
  assert.equal(asset(ctx, id).holders, 1);

  refused(ctx, ctx.k.bob, { type: 'asset-redeem', assetId: id, holder: ctx.addr(ctx.k.bob), amount: 10n, docRef: H('r') }, /not redeemable/);
  ok(ctx, ctx.k.issuer, { type: 'asset-redeem', assetId: id, holder: ctx.addr(ctx.k.bob), amount: 10n, docRef: H('buyback') });
  ok(ctx, ctx.k.issuer, { type: 'asset-update', assetId: id, rules: { ...RULES, redeemable: true } });
  ok(ctx, ctx.k.bob, { type: 'asset-redeem', assetId: id, holder: ctx.addr(ctx.k.bob), amount: 40n, docRef: H('redemption') });
  assert.equal(asset(ctx, id).supply, '0');
  assert.equal(asset(ctx, id).holders, 0);
});

test('key rotation carries units, KYC and admin roles to the new post-quantum key', () => {
  const ctx = setup();
  const id = createAsset(ctx);
  kyc(ctx, ctx.k.alice);
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 20n, docRef: H('s') });

  // The investor rotates to a hash-based key and keeps both units and KYC.
  const aliceNew = generateKeyPair('slh-dsa-128s');
  const m1 = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.k.alice.privateKey, pqPrivateKey: aliceNew.privateKey, fee: FEE, nonce: ctx.chain.pendingNonce(ctx.addr(ctx.k.alice)) });
  assert.equal(ctx.chain.addTx(m1).ok, true);
  finalize(ctx);
  assert.equal(bal(ctx, id, aliceNew), '20');
  assert.equal(bal(ctx, id, ctx.k.alice), '0');
  kyc(ctx, ctx.k.bob);
  ok(ctx, aliceNew, { type: 'asset-transfer', assetId: id, to: ctx.addr(ctx.k.bob), amount: 5n });

  // The issuer rotates its key after 20 years; the asset follows without re-registration.
  const issuerNew = generateKeyPair('ml-dsa-87');
  const m2 = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.k.issuer.privateKey, pqPrivateKey: issuerNew.privateKey, fee: FEE, nonce: ctx.chain.pendingNonce(ctx.addr(ctx.k.issuer)) });
  assert.equal(ctx.chain.addTx(m2).ok, true);
  finalize(ctx);
  assert.equal(asset(ctx, id).roles.issuer, ctx.addr(issuerNew));
  ok(ctx, issuerNew, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.bob), amount: 5n, docRef: H('s') });

  // The compliance agent rotates; its whole KYC registry moves with it.
  const complianceNew = generateKeyPair('ml-dsa-65');
  const m3 = createMigration({ chainId: ctx.genesis.chainId, privateKey: ctx.k.compliance.privateKey, pqPrivateKey: complianceNew.privateKey, fee: FEE, nonce: ctx.chain.pendingNonce(ctx.addr(ctx.k.compliance)) });
  assert.equal(ctx.chain.addTx(m3).ok, true);
  finalize(ctx);
  assert.equal(asset(ctx, id).roles.compliance, ctx.addr(complianceNew));
  ok(ctx, ctx.k.bob, { type: 'asset-transfer', assetId: id, to: ctx.addr(aliceNew), amount: 5n });
  ok(ctx, complianceNew, { type: 'asset-freeze', assetId: id, address: ctx.addr(ctx.k.bob), reasonHash: H('r') });
});

test('asset state survives a snapshot round trip and rebuilds identically from the blocks', () => {
  const ctx = setup();
  const id = createAsset(ctx);
  kyc(ctx, ctx.k.alice);
  kyc(ctx, ctx.k.yuki, { country: 'JP', foreign: true });
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.alice), amount: 70n, docRef: H('s') });
  ok(ctx, ctx.k.issuer, { type: 'asset-issue', assetId: id, to: ctx.addr(ctx.k.yuki), amount: 30n, docRef: H('s') });
  const root = ctx.chain.state.root();
  assert.equal(State.fromJSON(JSON.parse(JSON.stringify(ctx.chain.state.toJSON()))).root(), root);
  const replay = new Chain(ctx.genesis, { now: () => ctx.clock.t });
  for (const block of ctx.chain.blocks) assert.deepEqual(replay.addBlock(block), { ok: true });
  assert.equal(replay.state.root(), root);
  assert.equal(replay.state.rwa.assets[id].foreignUnits, '30');
});

test('end to end: a node publishes assets, holders and KYC over HTTP', async () => {
  const net = await import('node:net');
  const { Node, fetchJson } = await import('../src/node.js');
  const port = await new Promise((resolve) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  const validator = generateKeyPair('ml-dsa-65');
  const [issuer, compliance, recovery, alice] = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const a = (key) => addressFromPublicKey(key.publicKey);
  const genesis = {
    chainId: 'cyvber-rwa-e2e', timestamp: Date.now(), coin: { name: 'CYVBER', symbol: 'CYVBER', decimals: 18 },
    blockTimeMs: 100, emptyBlockIntervalMs: 100, maxTxsPerBlock: 100, minFee: FEE.toString(), blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: [validator.publicKey], alloc: Object.fromEntries([issuer, compliance, alice].map((key) => [a(key), (100n * ONE).toString()])),
  };
  const node = new Node({ genesis, port, peers: [], validatorKey: validator.privateKey, log: () => {} });
  await node.start();
  const url = `http://127.0.0.1:${port}`;
  const waitFor = async (check) => { for (let i = 0; i < 150; i++) { if (await check()) return; await new Promise((r) => setTimeout(r, 100)); } throw new Error('timed out'); };
  const send = async (key, fields) => {
    const nonce = (await fetchJson(`${url}/accounts/${a(key)}`)).pendingNonce;
    await fetchJson(`${url}/txs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(createTx({ chainId: genesis.chainId, fee: FEE, nonce, ...fields }, { privateKey: key.privateKey })) });
    await waitFor(async () => (await fetchJson(`${url}/accounts/${a(key)}`)).nonce === nonce + 1);
  };
  try {
    assert.deepEqual(await fetchJson(`${url}/assets`), { count: 0, assets: [] });
    await send(issuer, { type: 'asset-create', symbol: 'PHRE1', name: 'Pilot Property', class: 'real-estate', decimals: 0, maxSupply: '1000', roles: { compliance: a(compliance), recovery: a(recovery), attestor: null }, legal: LEGAL, rules: RULES });
    const id = assetIdFor(genesis.chainId, a(issuer), 'PHRE1');
    await send(compliance, { type: 'kyc-attest', address: a(alice), level: 2, country: 'PH', foreign: false, investorClass: 'qualified', expiresHeight: 1_000_000, recordHash: H('kyc') });
    await send(issuer, { type: 'asset-issue', assetId: id, to: a(alice), amount: 25n, docRef: H('subscription') });
    const list = await fetchJson(`${url}/assets`);
    assert.equal(list.count, 1);
    assert.equal(list.assets[0].adminKeys, 'pq');
    const view = await fetchJson(`${url}/assets/${id}`);
    assert.equal(view.supply, '25');
    assert.deepEqual(view.balances, [{ address: a(alice), balance: '25', frozen: false }]);
    const holdings = await fetchJson(`${url}/accounts/${a(alice)}/assets`);
    assert.equal(holdings.holdings[0].symbol, 'PHRE1');
    assert.equal(holdings.kyc[0].compliance, a(compliance));
    assert.equal(holdings.kyc[0].recordHash, H('kyc'), 'only a hash of the KYC file is public');
  } finally {
    await node.stop();
  }
});
