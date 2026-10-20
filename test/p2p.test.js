// Encrypted node-to-node links: ML-KEM-768 key exchange (FIPS 203), ML-DSA identities (FIPS 204),
// AES-256-GCM messages; tampering, replays and impostors are refused; nothing readable crosses the wire.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { createHello, acceptHello, completeHello } from '../src/p2p.js';
import { Node, fetchJson } from '../src/node.js';
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';

const ONE = 10n ** 18n;
const CHAIN = { chainId: 'argeni-p2p-test', genesisHash: 'ab'.repeat(32) };

function pair() {
  const a = generateKeyPair('ml-dsa-65');
  const b = generateKeyPair('ml-dsa-65');
  const { hello, kemPrivateKey } = createHello({ ...CHAIN, identityKey: a.privateKey, identityPublicKey: a.publicKey });
  const seenNonces = new Set();
  const { reply, session: responder } = acceptHello(hello, { ...CHAIN, identityKey: b.privateKey, identityPublicKey: b.publicKey, seenNonces });
  const initiator = completeHello(hello, kemPrivateKey, reply);
  return { a, b, hello, kemPrivateKey, reply, initiator, responder, seenNonces };
}

test('ML-KEM-768 handshake gives both nodes the same keys; messages and replies round-trip', () => {
  const { a, b, hello, initiator, responder } = pair();
  assert.equal(Buffer.from(hello.kem, 'base64').length, 1206, 'ML-KEM-768 public key (SPKI)');
  assert.equal(initiator.peerKey, b.publicKey);
  assert.equal(responder.peerKey, a.publicKey);
  const req = initiator.encryptRequest({ method: 'POST', path: '/consensus', body: { type: 'prevote', height: 7 } });
  assert.ok(!Buffer.from(req.ct, 'base64').toString('latin1').includes('prevote'), 'ciphertext hides the message');
  assert.deepEqual(responder.decryptRequest(req), { method: 'POST', path: '/consensus', body: { type: 'prevote', height: 7 } });
  const rep = responder.encryptReply(req.seq, { status: 200, body: { ok: true } });
  assert.deepEqual(initiator.decryptReply(req.seq, rep.ct), { status: 200, body: { ok: true } });
});

test('tampered and replayed messages are refused', () => {
  const { initiator, responder } = pair();
  const req = initiator.encryptRequest({ path: '/blocks' });
  const bytes = Buffer.from(req.ct, 'base64');
  bytes[3] ^= 1;
  assert.throws(() => responder.decryptRequest({ ...req, ct: bytes.toString('base64') }), /failed authentication/);
  assert.throws(() => responder.decryptRequest({ ...req, seq: req.seq + 1 }), /failed authentication/, 'moving a message to another slot');
  responder.decryptRequest(req);
  assert.throws(() => responder.decryptRequest(req), /replayed/);
  // Out-of-order delivery is fine, as long as nothing repeats.
  const r1 = initiator.encryptRequest({ n: 1 });
  const r2 = initiator.encryptRequest({ n: 2 });
  assert.deepEqual(responder.decryptRequest(r2), { n: 2 });
  assert.deepEqual(responder.decryptRequest(r1), { n: 1 });
});

test('a session key from one pair of nodes opens nothing in another', () => {
  const one = pair();
  const two = pair();
  const req = one.initiator.encryptRequest({ secret: 1 });
  assert.throws(() => two.responder.decryptRequest({ ...req, sid: two.responder.sid }), /failed authentication/);
});

test('impostors, swapped keys and replayed handshakes are refused', () => {
  const { a, b, hello, kemPrivateKey, reply, seenNonces } = pair();
  const ctxB = { ...CHAIN, identityKey: b.privateKey, identityPublicKey: b.publicKey, seenNonces };

  // Replaying a recorded hello.
  assert.throws(() => acceptHello(hello, ctxB), /replayed handshake/);

  // Someone in the middle swaps in their own ML-KEM key: the identity signature no longer matches.
  const mitmKem = crypto.generateKeyPairSync('ml-kem-768').publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const fresh = createHello({ ...CHAIN, identityKey: a.privateKey, identityPublicKey: a.publicKey }).hello;
  assert.throws(() => acceptHello({ ...fresh, kem: mitmKem }, ctxB), /signature invalid/);

  // A reply signed by a different key than the one this peer showed before (identity pinning).
  const impostor = generateKeyPair('ml-dsa-65');
  assert.throws(() => completeHello(hello, kemPrivateKey, reply, { expectedPeerKey: impostor.publicKey }), /identity changed/);
  // A reply whose fields were altered in transit.
  assert.throws(() => completeHello(hello, kemPrivateKey, { ...reply, sid: 'f'.repeat(32) }), /signature invalid/);

  // Old handshakes, other chains, classical identities and non-ML-KEM keys.
  const stale = createHello({ ...CHAIN, identityKey: a.privateKey, identityPublicKey: a.publicKey }).hello;
  assert.throws(() => acceptHello({ ...stale, ts: Date.now() - 5 * 60_000 }, ctxB), /too old/);
  assert.throws(() => acceptHello(createHello({ ...CHAIN, chainId: 'other', identityKey: a.privateKey, identityPublicKey: a.publicKey }).hello, ctxB), /different chain/);
  const ed = generateKeyPair('ed25519');
  assert.throws(() => acceptHello(createHello({ ...CHAIN, identityKey: ed.privateKey, identityPublicKey: ed.publicKey }).hello, ctxB), /post-quantum/);
});

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
  throw new Error('timed out');
}

test('live nodes talk only through the encrypted channel: a wiretap sees no votes, blocks or transactions', async () => {
  const validators = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const faucet = generateKeyPair('ml-dsa-65');
  const genesis = {
    chainId: 'argeni-wiretap', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 150, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: (500_000_000n * ONE).toString(),
    validators: validators.map((v) => v.publicKey), alloc: { [addressFromPublicKey(faucet.publicKey)]: (1000n * ONE).toString() },
  };
  const ports = [];
  for (let i = 0; i < 5; i++) ports.push(await freePort());
  const urls = ports.slice(0, 4).map((p) => `http://127.0.0.1:${p}`);

  // A wiretap in front of node 4: everything other nodes send to it passes through here.
  const captured = [];
  const tap = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const body = Buffer.concat(chunks);
      captured.push(`${req.method} ${req.url} ${body.toString('utf8')}`);
      try {
        const upstream = await fetch(`${urls[3]}${req.url}`, { method: req.method, headers: { 'content-type': 'application/json' }, body: req.method === 'GET' ? undefined : body });
        res.writeHead(upstream.status, { 'content-type': 'application/json' });
        res.end(Buffer.from(await upstream.arrayBuffer()));
      } catch {
        res.writeHead(502);
        res.end();
      }
    });
  });
  await new Promise((resolve) => tap.listen(ports[4], '127.0.0.1', resolve));
  const tapUrl = `http://127.0.0.1:${ports[4]}`;

  const nodes = validators.map((v, i) => new Node({
    genesis, port: ports[i], validatorKey: v.privateKey, faucetKey: i === 0 ? faucet.privateKey : null, log: () => {},
    peers: urls.map((u, j) => (j === 3 ? tapUrl : u)).filter((_, j) => j !== i),
  }));
  await Promise.all(nodes.map((n) => n.start()));
  try {
    const user = addressFromPublicKey(generateKeyPair().publicKey);
    await fetchJson(`${urls[0]}/faucet`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ address: user }) });
    await waitFor(async () => nodes.every((n) => n.chain.state.get(user).balance === 100n * ONE) && nodes.every((n) => n.chain.height >= 5));

    const status = await fetchJson(`${urls[3]}/status`);
    assert.equal(status.p2p.encrypted, true);
    assert.equal(status.p2p.keyExchange, 'ML-KEM-768 (FIPS 203)');
    assert.ok(status.p2p.inboundSessions >= 1);

    const wire = captured.join('\n');
    assert.ok(captured.length > 20, 'traffic flowed through the tap');
    assert.ok(captured.every((c) => c.startsWith('POST /p2p')), 'every peer message used the encrypted channel');
    for (const secret of ['prevote', 'precommit', 'blockHash', 'stateRoot', user, 'testnet faucet']) {
      assert.ok(!wire.includes(secret), `"${secret}" is not readable on the wire`);
    }

    // Plain (unencrypted) gossip is refused.
    const plain = await fetch(`${urls[3]}/consensus`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'prevote' }) });
    assert.equal(plain.status, 403);
  } finally {
    await Promise.all(nodes.map((n) => n.stop()));
    tap.closeAllConnections?.();
    await new Promise((resolve) => tap.close(resolve));
  }
});

test('an outsider cannot fill the peer list with addresses it does not own', async () => {
  const p2p = await import('../src/p2p.js');
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const genesis = { chainId: 'argeni-peers', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 }, blockTimeMs: 300, maxTxsPerBlock: 10, minFee: '1000', blockReward: '0', maxSupply: (500_000_000n * ONE).toString(), validators: keys.map((k) => k.publicKey), alloc: {} };
  const [port, honestPort] = [await freePort(), await freePort()];
  const node = new Node({ genesis, port, validatorKey: keys[0].privateKey, log: () => {} });
  await node.start();
  const url = `http://127.0.0.1:${port}`;
  try {
    const { genesisHash } = await fetchJson(`${url}/status`);
    const me = generateKeyPair('ml-dsa-65');
    const { hello, kemPrivateKey } = p2p.createHello({ chainId: genesis.chainId, genesisHash, identityKey: me.privateKey, identityPublicKey: me.publicKey });
    const session = p2p.completeHello(hello, kemPrivateKey, await fetchJson(`${url}/p2p/handshake`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hello }) }));
    const announce = async (target) => {
      const req = session.encryptRequest({ method: 'POST', path: '/peers', body: { url: target, genesisHash } });
      const res = await fetchJson(`${url}/p2p`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req) });
      return session.decryptReply(req.seq, res.ct);
    };
    for (let i = 0; i < 5; i++) assert.equal((await announce(`http://127.0.0.1:${honestPort}`)).status, 400, 'nobody answers there');
    // A real node at an address that is not the announcer's own: refused, because the identities differ.
    const other = new Node({ genesis, port: honestPort, log: () => {} });
    await other.start();
    try {
      assert.match((await announce(`http://127.0.0.1:${honestPort}`)).body.error, /different node/);
    } finally {
      await other.stop();
    }
    assert.equal(node.peers.length, 0);
  } finally {
    await node.stop();
  }
});
