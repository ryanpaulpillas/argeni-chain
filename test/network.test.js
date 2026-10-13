// Runs three real nodes over HTTP and checks they agree on the chain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Node, RateLimiter, fetchJson } from '../src/node.js';
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';
import { createTransfer } from '../src/tx.js';

const ONE = 10n ** 18n;

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(check, timeoutMs = 15_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('timed out waiting for condition');
}

test('four validators over HTTP finalize one shared chain, gossip transactions and run a faucet', async () => {
  const validators = Array.from({ length: 4 }, generateKeyPair);
  const faucet = generateKeyPair();
  const user = generateKeyPair();
  const userAddr = addressFromPublicKey(user.publicKey);
  const genesis = {
    chainId: 'argeni-nettest',
    timestamp: Date.now(),
    coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 150,
    maxTxsPerBlock: 100,
    minFee: '1000',
    blockReward: '0',
    maxSupply: (1_000_000_000n * ONE).toString(),
    validators: validators.map((v) => v.publicKey),
    alloc: { [addressFromPublicKey(faucet.publicKey)]: (1000n * ONE).toString() },
  };
  const ports = [];
  for (let i = 0; i < 4; i++) ports.push(await freePort());
  const urls = ports.map((p) => `http://127.0.0.1:${p}`);
  const nodes = validators.map((v, i) => new Node({
    genesis,
    port: ports[i],
    peers: urls.filter((_, j) => j !== i),
    validatorKey: v.privateKey,
    faucetKey: i === 0 ? faucet.privateKey : null,
    faucetAmount: '100',
    log: () => {},
  }));
  await Promise.all(nodes.map((n) => n.start()));
  try {
    const faucetRes = await fetchJson(`${urls[0]}/faucet`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: userAddr }),
    });
    assert.equal(faucetRes.amount, '100');

    // The faucet tx is accepted on node 0; it must reach node 2's state through gossip and blocks.
    await waitFor(async () => (await fetchJson(`${urls[2]}/accounts/${userAddr}`)).balance === (100n * ONE).toString());

    // Send from the user through node 1.
    const tx = createTransfer({ chainId: genesis.chainId, privateKey: user.privateKey, to: addressFromPublicKey(faucet.publicKey), amount: 40n * ONE, fee: 1000n, nonce: 0 });
    await fetchJson(`${urls[1]}/txs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) });
    await waitFor(async () => {
      const balances = await Promise.all(urls.map((u) => fetchJson(`${u}/accounts/${userAddr}`)));
      return balances.every((b) => b.balance === (60n * ONE - 1000n).toString());
    });

    // All three nodes agree on every block up to the lowest common height.
    const statuses = await Promise.all(urls.map((u) => fetchJson(`${u}/status`)));
    const height = Math.min(...statuses.map((s) => s.height));
    assert.ok(height >= 2);
    const hashes = await Promise.all(urls.map((u) => fetchJson(`${u}/blocks/${height}`)));
    assert.equal(new Set(hashes.map((b) => b.hash)).size, 1);
    const proposers = new Set();
    for (let h = 1; h <= height; h++) {
      const block = await fetchJson(`${urls[0]}/blocks/${h}`);
      proposers.add(block.header.proposer);
      assert.ok(block.commit.precommits.length >= 3, 'every block carries a quorum certificate');
    }
    assert.ok(proposers.size >= 2, 'blocks should come from more than one validator');
    const status = await fetchJson(`${urls[0]}/status`);
    assert.equal(status.supply, '1000 ARGENI');
    assert.equal(status.maxSupply, '1000000000 ARGENI');

    const bad = await fetch(`${urls[0]}/txs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...tx, nonce: 1 }) });
    assert.equal(bad.status, 400);
  } finally {
    await Promise.all(nodes.map((n) => n.stop()));
  }
});

test('rate limiter allows max events per window per key', () => {
  let now = 0;
  const limit = new RateLimiter(2, 1000, () => now);
  assert.equal(limit.check('a'), 0);
  assert.equal(limit.check('a'), 0);
  assert.equal(limit.check('a'), 1000);
  assert.equal(limit.check('b'), 0);
  now = 1000;
  assert.equal(limit.check('a'), 0);
  assert.equal(new RateLimiter(0, 1000).check('x'), 0, '0 means unlimited');
});

test('faucet limits apply per address and per client IP behind a proxy', async () => {
  const validator = generateKeyPair();
  const faucet = generateKeyPair();
  const genesis = {
    chainId: 'argeni-faucet-test', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 200, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: [validator.publicKey], alloc: { [addressFromPublicKey(faucet.publicKey)]: (1000n * ONE).toString() },
  };
  const node = new Node({ genesis, port: await freePort(), validatorKey: validator.privateKey, faucetKey: faucet.privateKey,
    trustProxy: true, faucetAddressCooldownMs: 60_000, faucetIpCooldownMs: 60_000, txsPerMinutePerIp: 2, log: () => {} });
  await node.start();
  const ask = (address, ip) => fetch(`${node.url}/faucet`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify({ address }) });
  try {
    const a = addressFromPublicKey(generateKeyPair().publicKey);
    const b = addressFromPublicKey(generateKeyPair().publicKey);
    assert.equal((await ask(a, '203.0.113.1')).status, 202);
    assert.equal((await ask(a, '203.0.113.2')).status, 429, 'same address again');
    assert.equal((await ask(b, '203.0.113.1')).status, 429, 'same IP again');
    assert.equal((await ask(b, '203.0.113.3')).status, 202, 'new address from a new IP');

    const bad = { type: 'transfer' };
    const post = () => fetch(`${node.url}/txs`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.7' }, body: JSON.stringify(bad) });
    assert.equal((await post()).status, 400);
    assert.equal((await post()).status, 400);
    assert.equal((await post()).status, 429, 'third tx from the same IP within a minute is limited');
  } finally {
    await node.stop();
  }
});
