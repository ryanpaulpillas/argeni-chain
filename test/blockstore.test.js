import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Chain, quorum, voteSignBytes, RECENT_BLOCKS } from '../src/chain.js';
import { BlockStore } from '../src/blockstore.js';
import { addressFromPublicKey, canonical, generateKeyPair, sign } from '../src/crypto.js';
import { createTransfer } from '../src/tx.js';

function setup(dataDir) {
  const keys = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-87'));
  const alice = generateKeyPair();
  const genesis = {
    chainId: 'cyvber-store', timestamp: 1_000_000, coin: { name: 'CYVBER', symbol: 'CYV', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: (10n ** 30n).toString(),
    validators: keys.map((k) => k.publicKey), alloc: { [addressFromPublicKey(alice.publicKey)]: (10n ** 24n).toString() },
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { dataDir, now: () => clock.t });
  const next = () => {
    clock.t += 1000;
    const block = chain.buildBlock(keys[chain.height % 4].publicKey);
    const precommits = keys.slice(0, quorum(4)).map((k) => {
      const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: k.publicKey };
      return { ...vote, signature: sign(voteSignBytes(genesis.chainId, vote), k.privateKey) };
    });
    const full = { ...block, commit: { round: 0, precommits } };
    assert.deepEqual(chain.addBlock(full), { ok: true });
    return full;
  };
  return { genesis, chain, clock, next, alice, keys };
}

test('compact block files decode to the identical block and are much smaller', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cyvber-bs-'));
  try {
    const ctx = setup(null);
    ctx.chain.addTx(createTransfer({ chainId: ctx.genesis.chainId, privateKey: ctx.alice.privateKey, to: 'cy' + 'ab'.repeat(32), amount: 5n, fee: 1000n, nonce: 0, memo: 'hi' }));
    ctx.next();
    const block = ctx.next(); // has a lastCommit and a commit, ML-DSA-87 signatures
    const store = new BlockStore(path.join(dir, 'blocks'));
    store.write(block);
    assert.equal(canonical(store.read(2)), canonical(block));
    const plain = Buffer.byteLength(JSON.stringify(block));
    const compact = fs.statSync(path.join(dir, 'blocks', '0000000002.cb')).size;
    assert.ok(compact * 2.5 < plain, `compact ${compact} B vs plain ${plain} B`);
    // A second store over the same folder reads it (keys.json is shared).
    assert.equal(canonical(new BlockStore(path.join(dir, 'blocks')).read(2)), canonical(block));
    // Converting older plain files.
    fs.unlinkSync(path.join(dir, 'blocks', '0000000002.cb'));
    fs.writeFileSync(path.join(dir, 'blocks', '0000000002.json'), JSON.stringify(block));
    assert.equal(canonical(store.read(2)), canonical(block)); // older plain files are read
    const res = store.compact();
    assert.equal(res.done, 1);
    assert.ok(!fs.existsSync(path.join(dir, 'blocks', '0000000002.json')));
    assert.equal(canonical(store.read(2)), canonical(block));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a node keeps only recent blocks in memory, reads older ones from disk, and restarts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cyvber-mem-'));
  try {
    const ctx = setup(dir);
    const first = ctx.next();
    for (let i = 0; i < RECENT_BLOCKS + 20; i++) ctx.next();
    assert.equal(ctx.chain.recent.length, RECENT_BLOCKS);
    assert.equal(ctx.chain.height, RECENT_BLOCKS + 21);
    assert.equal(canonical(ctx.chain.getBlock(1)), canonical(first));
    assert.equal(ctx.chain.getBlock(ctx.chain.height).hash, ctx.chain.tip.hash);
    const restarted = new Chain(ctx.genesis, { dataDir: dir, now: () => ctx.clock.t });
    assert.equal(restarted.height, ctx.chain.height);
    assert.equal(restarted.tipHash, ctx.chain.tipHash);
    assert.equal(restarted.state.root(), ctx.chain.state.root());
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
