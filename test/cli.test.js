// End to end through the command-line wallet and real HTTP nodes: a multisig vault spends with two
// of three signatures, a vesting grant is sent, and a new validator stakes in, fast-syncs from a
// snapshot and starts signing blocks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { Node, fetchJson } from '../src/node.js';
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';
import { writeKeyFile } from '../src/keyfile.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const ONE = 10n ** 18n;
const run = promisify(execFile);

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(check, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('timed out waiting for condition');
}

test('multisig, vesting and staking work from the command line; a new validator fast-syncs and signs', { timeout: 120_000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argeni-cli-'));
  const file = (name) => path.join(dir, name);
  const keyFile = (name, type = 'ml-dsa-65') => writeKeyFile(file(name), generateKeyPair(type));
  const validators = Array.from({ length: 4 }, (_, i) => keyFile(`v${i}.json`));
  const owner = keyFile('owner.json');
  const members = ['a', 'b', 'c'].map((m) => keyFile(`member-${m}.json`, 'ml-dsa-87'));
  const operator = keyFile('operator.json');
  const genesis = {
    chainId: 'argeni-cli-test', timestamp: Date.now(), coin: { name: 'Argeni', symbol: 'ARGENI', decimals: 18 },
    blockTimeMs: 150, maxTxsPerBlock: 100, minFee: '1000', blockReward: '0', maxSupply: (1_000_000_000n * ONE).toString(),
    validators: validators.map((v) => v.publicKey), alloc: { [owner.address]: (100_000n * ONE).toString() },
    staking: { minStake: (1000n * ONE).toString() },
  };
  const ports = [];
  for (let i = 0; i < 5; i++) ports.push(await freePort());
  const urls = ports.map((p) => `http://127.0.0.1:${p}`);
  const nodes = validators.map((v, i) => new Node({ genesis, port: ports[i], peers: urls.filter((_, j) => j !== i), validatorKey: v.privateKey, snapshotEvery: 3, log: () => {} }));
  await Promise.all(nodes.map((n) => n.start()));
  const cli = async (...args) => (await run(process.execPath, [CLI, ...args, '--rpc', urls[0]])).stdout;
  const account = (a) => fetchJson(`${urls[0]}/accounts/${a}`);
  let joiner = null;
  try {
    // A 2-of-3 vault: funded, then spent with two members' signatures.
    const created = await cli('multisig', 'create', '--threshold', '2', '--keys', ['a', 'b', 'c'].map((m) => file(`member-${m}.json`)).join(','), '--out', file('vault.json'));
    const vaultAddr = /address (ag[0-9a-f]{64})/.exec(created)[1];
    await cli('send', '--key', file('owner.json'), '--to', vaultAddr, '--amount', '500');
    await waitFor(async () => (await account(vaultAddr)).balance === (500n * ONE).toString());
    const recipient = addressFromPublicKey(generateKeyPair().publicKey);
    await cli('multisig', 'propose', '--vault', file('vault.json'), '--to', recipient, '--amount', '120', '--out', file('spend.json'));
    assert.match(await cli('multisig', 'sign', '--tx', file('spend.json'), '--key', file('member-a.json')), /1 of 2 signatures/);
    await assert.rejects(cli('multisig', 'submit', '--tx', file('spend.json')), /invalid signature/, 'one signature is refused');
    assert.match(await cli('multisig', 'sign', '--tx', file('spend.json'), '--key', file('member-c.json')), /2 of 2 signatures — ready/);
    await cli('multisig', 'submit', '--tx', file('spend.json'));
    await waitFor(async () => (await account(recipient)).balance === (120n * ONE).toString());

    // A vesting grant shows up as locked.
    const hire = addressFromPublicKey(generateKeyPair().publicKey);
    await cli('vest', '--key', file('owner.json'), '--to', hire, '--amount', '2400', '--lock', '12', '--vest', '24');
    await waitFor(async () => (await account(hire)).locked === (2400n * ONE).toString());

    // A new validator stakes in from the command line.
    assert.match(await cli('stake', 'join', '--key', file('owner.json'), '--validator-key', file('operator.json'), '--amount', '1000'), /joins with 1000 ARGENI staked/);
    await waitFor(async () => (await fetchJson(`${urls[0]}/validators`)).active === 5);
    assert.match(await cli('validators'), /5 active validators, quorum 4/);

    // Its node starts from a snapshot instead of replaying the chain, then signs blocks.
    let snap;
    await waitFor(async () => {
      const { snapshots } = await fetchJson(`${urls[0]}/status`);
      snap = snapshots.at(-1);
      return snap && snap.height >= 3;
    });
    joiner = new Node({ genesis, port: ports[4], peers: urls.slice(0, 4), validatorKey: operator.privateKey, trustedBlock: snap, log: () => {} });
    for (const n of nodes) n.peers.push(urls[4]);
    await joiner.start();
    assert.equal(joiner.chain.base, snap.height, 'started from the snapshot');
    const target = (await fetchJson(`${urls[0]}/status`)).height + 4;
    await waitFor(async () => (await fetchJson(`${urls[4]}/status`)).height >= target);
    const latest = await fetchJson(`${urls[0]}/blocks/latest`);
    assert.ok(latest.commit.precommits.some((p) => p.validator === operator.publicKey) || latest.lastCommit.precommits.some((p) => p.validator === operator.publicKey), 'the new validator signs');
    assert.equal((await fetchJson(`${urls[4]}/blocks/${target}`)).hash, (await fetchJson(`${urls[0]}/blocks/${target}`)).hash);

    // Leaving: out of the set, stake on its way back.
    await cli('stake', 'leave', '--key', file('owner.json'), '--validator', operator.address);
    await waitFor(async () => (await fetchJson(`${urls[0]}/validators`)).active === 4);
  } finally {
    await joiner?.stop();
    await Promise.all(nodes.map((n) => n.stop()));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
