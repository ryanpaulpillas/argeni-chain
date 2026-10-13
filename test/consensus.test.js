// Runs several validators over a simulated network with offline nodes, lost and delayed
// messages, and a proposer that sends different blocks to different validators.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Chain, voteSignBytes } from '../src/chain.js';
import { Consensus } from '../src/consensus.js';
import { addressFromPublicKey, generateKeyPair, hashObject, sign } from '../src/crypto.js';
import { createTransfer } from '../src/tx.js';

const ONE = 10n ** 18n;

class Network {
  constructor({ dropRate = 0, maxDelayMs = 5 } = {}) {
    this.members = new Map(); // public key -> consensus
    this.down = new Set();
    this.dropRate = dropRate;
    this.maxDelayMs = maxDelayMs;
    this.tamper = null; // (msg, toKey) -> msg to deliver instead
  }

  send(from, msg) {
    if (this.down.has(from)) return;
    for (const [key, node] of this.members) {
      if (key === from || this.down.has(key) || Math.random() < this.dropRate) continue;
      const delivered = this.tamper ? this.tamper(msg, key) : msg;
      setTimeout(() => {
        if (!this.down.has(key)) node.handle(structuredClone(delivered));
      }, Math.random() * this.maxDelayMs);
    }
  }
}

function makeNet(n, networkOptions, genesisExtra = {}) {
  const keys = Array.from({ length: n }, generateKeyPair);
  const faucet = generateKeyPair();
  const genesis = {
    chainId: 'argeni-consensus-test',
    timestamp: Date.now(),
    coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 40,
    maxTxsPerBlock: 100,
    minFee: '1000',
    blockReward: '0',
    maxSupply: (1_000_000_000n * ONE).toString(),
    validators: keys.map((k) => k.publicKey),
    alloc: { [addressFromPublicKey(faucet.publicKey)]: (1000n * ONE).toString() },
    ...genesisExtra,
  };
  const net = new Network(networkOptions);
  const nodes = keys.map((key) => {
    const chain = new Chain(genesis);
    const consensus = new Consensus({ chain, privateKey: key.privateKey, broadcast: (msg) => net.send(key.publicKey, msg) });
    net.members.set(key.publicKey, consensus);
    return { key, chain, consensus };
  });
  return { genesis, keys, faucet, net, nodes, start: () => nodes.forEach((n) => n.consensus.start()), stop: () => nodes.forEach((n) => n.consensus.stop()) };
}

async function waitFor(check, timeoutMs = 10_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error('timed out');
}

// Safety: no two honest nodes ever finalized different blocks at the same height.
function assertAgreement(nodes) {
  const maxHeight = Math.max(...nodes.map((n) => n.chain.height));
  for (let h = 1; h <= maxHeight; h++) {
    const hashes = new Set(nodes.map((n) => n.chain.getBlock(h)?.hash).filter(Boolean));
    assert.equal(hashes.size, 1, `nodes disagree at height ${h}`);
  }
}

test('four validators finalize the same blocks and include transactions', async () => {
  const t = makeNet(4);
  t.start();
  try {
    const user = addressFromPublicKey(generateKeyPair().publicKey);
    const tx = createTransfer({ chainId: t.genesis.chainId, privateKey: t.faucet.privateKey, to: user, amount: 5n * ONE, fee: 1000n, nonce: 0 });
    t.nodes.forEach((n) => n.chain.addTx(tx));
    await waitFor(() => t.nodes.every((n) => n.chain.height >= 5));
    assertAgreement(t.nodes);
    for (const n of t.nodes) assert.equal(n.chain.state.get(user).balance, 5n * ONE);
    for (let h = 1; h <= 5; h++) assert.ok(t.nodes[0].chain.verifyCommit(t.nodes[0].chain.getBlock(h)) === null);
  } finally {
    t.stop();
  }
});

test('the chain keeps finalizing with one of four validators offline, including its proposer turns', async () => {
  const t = makeNet(4);
  t.net.down.add(t.keys[2].publicKey);
  t.start();
  try {
    const live = t.nodes.filter((_, i) => i !== 2);
    await waitFor(() => live.every((n) => n.chain.height >= 8));
    assertAgreement(live);
    const roundsUsed = new Set(live[0].chain.blocks.map((b) => b.commit.round));
    assert.ok(roundsUsed.has(1) || [...roundsUsed].some((r) => r > 0), 'a round change should skip the offline proposer');
    assert.equal(t.nodes[2].chain.height, 0);
  } finally {
    t.stop();
  }
});

test('with two of four offline nothing is finalized; when one returns the chain resumes', async () => {
  const t = makeNet(4);
  t.net.down.add(t.keys[0].publicKey);
  t.net.down.add(t.keys[1].publicKey);
  t.start();
  try {
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(t.nodes.every((n) => n.chain.height === 0), 'no quorum means no blocks');
    t.net.down.delete(t.keys[1].publicKey);
    const live = t.nodes.slice(1);
    await waitFor(() => live.every((n) => n.chain.height >= 3));
    assertAgreement(live);
  } finally {
    t.stop();
  }
});

test('lost and delayed messages do not break agreement', async () => {
  const t = makeNet(4, { dropRate: 0.2, maxDelayMs: 30 });
  t.start();
  try {
    await waitFor(() => t.nodes.filter((n) => n.chain.height >= 5).length >= 3, 20_000);
    assertAgreement(t.nodes);
  } finally {
    t.stop();
  }
});

test('a proposer sending different blocks to different validators cannot split the chain', async () => {
  const t = makeNet(4);
  const byzantine = t.keys[1]; // proposer of height 1, round 0
  const half = new Set([t.keys[2].publicKey]);
  t.net.tamper = (msg, to) => {
    if (msg.type !== 'proposal' || msg.validator !== byzantine.publicKey || !half.has(to)) return msg;
    const header = { ...msg.block.header, timestamp: msg.block.header.timestamp + 1 };
    const block = { header, txs: msg.block.txs, hash: hashObject(header) };
    const forged = { ...msg, blockHash: block.hash, block };
    return { ...forged, signature: sign(voteSignBytes(t.genesis.chainId, forged), byzantine.privateKey) };
  };
  t.start();
  try {
    await waitFor(() => t.nodes.every((n) => n.chain.height >= 6));
    assertAgreement(t.nodes);
  } finally {
    t.stop();
  }
});

test('an idle chain waits for transactions instead of making empty blocks', async () => {
  const t = makeNet(4, {}, { emptyBlockIntervalMs: 1500 });
  t.start();
  try {
    await waitFor(() => t.nodes.every((n) => n.chain.height >= 1)); // first heartbeat
    const idleHeight = t.nodes[0].chain.height;
    await new Promise((r) => setTimeout(r, 600)); // 15 block times with no transactions
    assert.equal(t.nodes[0].chain.height, idleHeight, 'no empty blocks while idle');

    const user = addressFromPublicKey(generateKeyPair().publicKey);
    const tx = createTransfer({ chainId: t.genesis.chainId, privateKey: t.faucet.privateKey, to: user, amount: ONE, fee: 1000n, nonce: 0 });
    for (const n of t.nodes) n.chain.addTx(tx); // in a real node, gossip delivers the tx to every validator
    await waitFor(() => t.nodes.every((n) => n.chain.state.get(user).balance === ONE), 3000);
    assertAgreement(t.nodes);
  } finally {
    t.stop();
  }
});
