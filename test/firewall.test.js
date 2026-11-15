// The node firewall: connection caps, rate limits, body limits, misbehaviour bans that escalate,
// peer-identity bans, and exemptions that keep a node's own operator and validators connected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Firewall, addressKey } from '../src/firewall.js';
import { Node, fetchJson } from '../src/node.js';
import { createHello } from '../src/p2p.js';
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';

const ONE = 10n ** 18n;

function clock() {
  const c = { t: 1_000_000 };
  c.now = () => c.t;
  return c;
}

test('IPv6 clients are grouped by /64 so rotating addresses inside one subscriber block does not help', () => {
  assert.equal(addressKey('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(addressKey('2001:db8:1:2:bbbb:cccc:dddd:eeee'), '2001:db8:1:2::/64');
  assert.equal(addressKey('::ffff:203.0.113.9'), '203.0.113.9');
});

test('rate limits per kind of request refill over time; the post-quantum handshake has its own budget', () => {
  const c = clock();
  const fw = new Firewall({ rates: { read: 5, handshake: 2 } }, { now: c.now });
  for (let i = 0; i < 5; i++) assert.equal(fw.checkRequest('203.0.113.1', 'read'), null);
  const refused = fw.checkRequest('203.0.113.1', 'read');
  assert.equal(refused.status, 429);
  assert.ok(refused.retryAfterMs > 0);
  assert.equal(fw.checkRequest('203.0.113.1', 'handshake'), null, 'a separate bucket');
  assert.equal(fw.checkRequest('203.0.113.2', 'read'), null, 'another address is unaffected');
  c.t += 12_000; // 5 per minute = one token every 12 s
  assert.equal(fw.checkRequest('203.0.113.1', 'read'), null);
});

test('misbehaviour bans an address, each repeat ban lasts twice as long, and points decay for honest mistakes', () => {
  const c = clock();
  const fw = new Firewall({ banThreshold: 100, banBaseMs: 60_000 }, { now: c.now });
  const ip = '198.51.100.7';
  for (let i = 0; i < 9; i++) assert.equal(fw.penalize(ip, 'bad-json'), 0);
  assert.equal(fw.penalize(ip, 'bad-json'), 60_000, '10 malformed bodies = 100 points = first ban');
  assert.equal(fw.checkRequest(ip, 'read').status, 403);
  assert.equal(fw.connectionOpened(ip), false, 'banned addresses are dropped at the connection');
  c.t += 61_000;
  assert.equal(fw.checkRequest(ip, 'read'), null, 'ban expired');
  assert.equal(fw.penalize(ip, 'tampered') + fw.penalize(ip, 'tampered'), 120_000, 'second ban doubles');
  // An honest wallet with a stale nonce now and then is never banned: points decay 20 per minute.
  const wallet = '198.51.100.8';
  for (let i = 0; i < 200; i++) {
    c.t += 10_000;
    assert.equal(fw.penalize(wallet, 'invalid-tx'), 0);
  }
  assert.equal(fw.status().stats.bans, 2);
});

test('connections per address are capped and released when they close', () => {
  const fw = new Firewall({ maxConnectionsPerIp: 2 });
  assert.equal(fw.connectionOpened('203.0.113.5'), true);
  assert.equal(fw.connectionOpened('203.0.113.5'), true);
  assert.equal(fw.connectionOpened('203.0.113.5'), false);
  fw.connectionClosed('203.0.113.5');
  assert.equal(fw.connectionOpened('203.0.113.5'), true);
});

test('loopback, allow-listed addresses and trusted peer identities are never banned', () => {
  const trusted = new Set(['validator-key']);
  const fw = new Firewall({ allow: ['192.0.2.10'], banThreshold: 10 }, { trustedPeer: (k) => trusted.has(k) });
  for (const ip of ['127.0.0.1', '::1', '192.0.2.10']) {
    for (let i = 0; i < 50; i++) fw.penalize(ip, 'tampered');
    assert.equal(fw.bannedFor(ip), 0, ip);
  }
  for (let i = 0; i < 50; i++) fw.penalizePeer('validator-key', 'invalid-block');
  assert.equal(fw.peerBannedFor('validator-key'), 0, 'a validator is reported, not cut off');
  assert.ok(fw.penalizePeer('stranger-key', 'invalid-block') > 0, 'an unknown identity is banned');
  assert.ok(fw.peerBannedFor('stranger-key') > 0);
});

test('the tracking table cannot be grown without limit by spraying addresses', () => {
  const fw = new Firewall({ maxTracked: 1000 });
  for (let i = 0; i < 5000; i++) fw.penalize(`10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`, 'not-found');
  assert.ok(fw.hosts.size <= 1000);
});

async function freePort() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

test('end to end: a live node refuses floods, oversized bodies and garbage, and bans the sender', async () => {
  const validator = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'cyvber-firewall-test', timestamp: Date.now(), coin: { name: 'CYVBER', symbol: 'CYVBER', decimals: 18 },
    blockTimeMs: 500, maxTxsPerBlock: 10, minFee: '1000', blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: [validator.publicKey], alloc: { [addressFromPublicKey(generateKeyPair().publicKey)]: (10n * ONE).toString() },
  };
  // exemptLocal off, so this test's own requests (from 127.0.0.1) are subject to the firewall.
  const firewall = { exemptLocal: false, rates: { read: 20, handshake: 3 }, bodyLimits: { tx: 2_000 }, banThreshold: 50 };
  const port = await freePort();
  const node = new Node({ genesis, port, validatorKey: validator.privateKey, firewall, log: () => {} });
  await node.start();
  const url = `http://127.0.0.1:${port}`;
  const raw = (path, init) => fetch(`${url}${path}`, init);
  try {
    // Rate limit, with Retry-After.
    const statuses = [];
    for (let i = 0; i < 25; i++) statuses.push((await raw('/status')).status);
    assert.ok(statuses.includes(429));
    const limited = await raw('/status');
    assert.ok(Number(limited.headers.get('retry-after')) >= 1);

    // Oversized transaction body, refused from the Content-Length header alone.
    node.firewall.hosts.clear();
    const big = await raw('/txs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pad: 'x'.repeat(5_000) }) });
    assert.equal(big.status, 413);

    // The post-quantum handshake has a tight budget of its own.
    node.firewall.hosts.clear();
    const me = generateKeyPair('ml-dsa-65');
    const hello = () => createHello({ chainId: genesis.chainId, genesisHash: node.chain.genesisHash, identityKey: me.privateKey, identityPublicKey: me.publicKey }).hello;
    const shakes = [];
    for (let i = 0; i < 5; i++) shakes.push((await raw('/p2p/handshake', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hello: hello() }) })).status);
    assert.deepEqual(shakes.slice(0, 3), [200, 200, 200]);
    assert.equal(shakes[4], 429);

    // Garbage gets the sender banned, and the ban drops even well-formed requests.
    node.firewall.hosts.clear();
    for (let i = 0; i < 6; i++) await raw('/txs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{not json' });
    const after = await raw('/genesis');
    assert.equal(after.status, 403);
    const status = node.firewall.status({ detail: true });
    assert.equal(status.blocked.addresses, 1);
    assert.ok(status.blockedAddresses[0].reasons['bad-json'] >= 5);

    // The operator can see the firewall (detail only on a direct local connection).
    node.firewall.hosts.clear();
    const view = await fetchJson(`${url}/firewall`);
    assert.deepEqual(view.layers, ['connection', 'rate', 'size', 'behaviour', 'peer-identity']);
    assert.ok(Array.isArray(view.blockedAddresses));
  } finally {
    await node.stop();
  }
});

test('behind a local proxy, a forged X-Forwarded-For cannot pass as local to slip past the firewall', async () => {
  const validator = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'cyvber-firewall-proxy', timestamp: Date.now(), coin: { name: 'CYVBER', symbol: 'CYVBER', decimals: 18 },
    blockTimeMs: 500, maxTxsPerBlock: 10, minFee: '1000', blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: [validator.publicKey], alloc: {},
  };
  const port = await freePort();
  const node = new Node({ genesis, port, validatorKey: validator.privateKey, trustProxy: true, firewall: { rates: { read: 3 } }, log: () => {} });
  await node.start();
  try {
    // What Caddy sends for a client at 203.0.113.50 that forged its own header: the real address is appended last.
    const headers = { 'x-forwarded-for': '127.0.0.1, 203.0.113.50' };
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await fetch(`http://127.0.0.1:${port}/status`, { headers })).status);
    assert.equal(codes.at(-1), 429, 'treated as 203.0.113.50, not as local');
    assert.ok(node.firewall.hosts.has('203.0.113.50'));
    assert.equal((await fetch(`http://127.0.0.1:${port}/status`)).status, 200, 'the proxy itself and local tools stay exempt');
  } finally {
    await node.stop();
  }
});
