// Autonomous peer discovery: a new node given one seed address finds the rest of the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { Node, fetchJson, isPrivateHost } from '../src/node.js';
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';

const ONE = 10n ** 18n;

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(check, timeoutMs = 20_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('timed out waiting for condition');
}

function genesisFor(validators) {
  return {
    chainId: 'cyvber-discovery-test',
    timestamp: Date.now(),
    coin: { name: 'CYVBER', symbol: 'CYV', decimals: 18 },
    blockTimeMs: 150,
    maxTxsPerBlock: 100,
    minFee: '1000',
    blockReward: '0',
    maxSupply: (1_000_000_000n * ONE).toString(),
    validators: validators.map((v) => v.publicKey),
    alloc: { [addressFromPublicKey(generateKeyPair().publicKey)]: (1000n * ONE).toString() },
  };
}

test('private and loopback hosts are never shared or dialled', () => {
  for (const h of ['localhost', '127.0.0.1', '10.0.0.5', '172.20.1.1', '192.168.1.9', '169.254.1.1', '100.64.0.1', '0.0.0.0', '[::1]', 'fd00::1', 'fe80::1', 'node.local'])
    assert.equal(isPrivateHost(h), true, h);
  for (const h of ['rpc.cyvber.com', '188.166.223.3', '8.8.8.8', '172.32.0.1', '[2a03:b0c0::1]'])
    assert.equal(isPrivateHost(h), false, h);
});

test('a new node with only a seed address discovers the other nodes and syncs', async () => {
  const validator = generateKeyPair('ml-dsa-65');
  const genesis = genesisFor([validator]);
  const ports = [await freePort(), await freePort(), await freePort()];
  const urls = ports.map((p) => `http://127.0.0.1:${p}`);
  const opts = { genesis, discoverPrivate: true, log: () => {} };
  const seed = new Node({ ...opts, port: ports[0], publicUrl: urls[0], validatorKey: validator.privateKey });
  const b = new Node({ ...opts, port: ports[1], publicUrl: urls[1], seeds: [urls[0]] });
  const c = new Node({ ...opts, port: ports[2], publicUrl: urls[2], seeds: [urls[0]] });
  await seed.start();
  try {
    await b.start();
    await waitFor(() => seed.peers.includes(urls[1])); // b announced itself to the seed
    await c.start(); // c learns b from the seed's peer list
    await waitFor(() => c.peers.includes(urls[1]) && c.peers.includes(urls[0]));
    await waitFor(() => b.peers.includes(urls[2])); // c announced itself to b
    const list = await fetchJson(`${urls[0]}/peers`);
    assert.ok(list.peers.includes(urls[0]) && list.peers.includes(urls[1]) && list.peers.includes(urls[2]));
    await waitFor(() => seed.chain.height >= 2 && c.chain.height >= 2);
    assert.equal(c.chain.genesisHash, seed.chain.genesisHash);
  } finally {
    await Promise.all([c, b, seed].map((n) => n.stop().catch(() => {})));
  }
});

test('discovery ignores nodes of another chain and keeps loopback out of public peer lists', async () => {
  const v1 = generateKeyPair('ml-dsa-65');
  const v2 = generateKeyPair('ml-dsa-65');
  const ports = [await freePort(), await freePort(), await freePort()];
  const urls = ports.map((p) => `http://127.0.0.1:${p}`);
  const other = new Node({ genesis: { ...genesisFor([v2]), chainId: 'some-other-chain' }, port: ports[0], publicUrl: urls[0], validatorKey: v2.privateKey, discoverPrivate: true, log: () => {} });
  const main = new Node({ genesis: genesisFor([v1]), port: ports[1], publicUrl: urls[1], validatorKey: v1.privateKey, seeds: [urls[0]], discoverPrivate: true, log: () => {} });
  const strict = new Node({ genesis: genesisFor([generateKeyPair('ml-dsa-65')]), port: ports[2], peers: ['http://127.0.0.1:9'], publicUrl: urls[2], log: () => {} });
  await other.start();
  try {
    await main.start();
    assert.equal(main.peers.includes(urls[0]), false);
    assert.equal(main.lastDiscovery.added, 0);
    await strict.start();
    const list = await fetchJson(`${urls[2]}/peers`);
    assert.deepEqual(list.peers, []); // its own loopback publicUrl and loopback peer are not shared
  } finally {
    await Promise.all([strict, main, other].map((n) => n.stop().catch(() => {})));
  }
});
