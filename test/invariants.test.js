// Randomised check of the money rules: after every block, the CYV that exists (balances + stake +
// unpaid pools) must equal the recorded supply, no balance may go negative, and nonces only rise.
// Random transfers, self-transfers, vesting grants, validator joins/leaves and doomed transactions
// (overspends, replays, wrong nonces) are thrown at the chain for many blocks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Chain, quorum, voteSignBytes } from '../src/chain.js';
import { addressFromPublicKey, generateKeyPair, sign } from '../src/crypto.js';
import { createTransfer, createTx } from '../src/tx.js';

const ONE = 10n ** 18n;
let seed = 20261121;
const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed % n; };

function accounted(state) {
  let total = state.rewardPool + (state.canary?.pool ?? 0n);
  for (const a of state.accounts.values()) {
    assert.ok(a.balance >= 0n, 'negative balance');
    total += a.balance;
  }
  for (const v of state.validators) total += v.stake;
  for (const c of Object.values(state.canary?.commits ?? {})) total += BigInt(c.deposit);
  return total;
}

test('money is never created or lost under random traffic', () => {
  const vals = Array.from({ length: 4 }, () => generateKeyPair('ml-dsa-65'));
  const users = Array.from({ length: 6 }, () => generateKeyPair('ed25519'));
  const addr = (k) => addressFromPublicKey(k.publicKey);
  const genesis = {
    chainId: 'cyvber-fuzz', timestamp: 1_000_000, coin: { name: 'CYVBER', symbol: 'CYV', decimals: 18 },
    blockTimeMs: 1000, maxTxsPerBlock: 50, minFee: '1000', blockReward: '0', maxSupply: (500_000_000n * ONE).toString(),
    validators: vals.map((k) => k.publicKey),
    alloc: Object.fromEntries(users.map((u, i) => [addr(u), (BigInt(i + 1) * 300_000n * ONE).toString()])),
    staking: { minStake: (100_000n * ONE).toString(), unbondingMs: 5_000 },
  };
  const clock = { t: genesis.timestamp };
  const chain = new Chain(genesis, { now: () => clock.t });
  const supply0 = chain.state.supply;
  const extraVals = [];
  const lastNonce = new Map();
  let accepted = 0, rejected = 0;

  for (let height = 1; height <= 150; height++) {
    for (let i = 0; i < 1 + rand(6); i++) {
      const u = users[rand(users.length)];
      const nonce = chain.pendingNonce(addr(u));
      const kind = rand(10);
      let tx;
      if (kind < 4) tx = createTransfer({ chainId: genesis.chainId, privateKey: u.privateKey, to: addr(users[rand(users.length)]), amount: BigInt(1 + rand(5000)) * ONE, fee: 1000n, nonce });
      else if (kind === 4) tx = createTransfer({ chainId: genesis.chainId, privateKey: u.privateKey, to: addr(u), amount: 1n, fee: 1000n, nonce }); // self-transfer (anchoring)
      else if (kind === 5) tx = createTransfer({ chainId: genesis.chainId, privateKey: u.privateKey, to: addr(users[0]), amount: 10n ** 30n, fee: 1000n, nonce }); // overspend
      else if (kind === 6) tx = createTransfer({ chainId: genesis.chainId, privateKey: u.privateKey, to: addr(users[1]), amount: ONE, fee: 1000n, nonce: Math.max(0, nonce - 1) }); // replayed nonce
      else if (kind === 7) tx = createTx({ type: 'vest', chainId: genesis.chainId, to: addr(users[rand(users.length)]), amount: BigInt(100 + rand(900)) * ONE, atStart: 0n, lockMonths: rand(3), vestMonths: 1 + rand(6), fee: 1000n, nonce }, { privateKey: u.privateKey });
      else if (kind === 8 && extraVals.length < 3) {
        const vk = generateKeyPair('ml-dsa-65');
        tx = createTx({ type: 'validator-join', chainId: genesis.chainId, validator: vk.publicKey, amount: 100_000n * ONE, fee: 1000n, nonce }, { privateKey: u.privateKey, extraSigners: { validatorSignature: vk.privateKey } });
        extraVals.push({ vk, owner: u });
      } else if (kind === 9 && extraVals.length) {
        const { vk, owner } = extraVals[rand(extraVals.length)];
        tx = createTx({ type: 'validator-leave', chainId: genesis.chainId, validator: vk.publicKey, fee: 1000n, nonce: chain.pendingNonce(addr(owner)) }, { privateKey: owner.privateKey });
      } else continue;
      if (chain.addTx(tx).ok) accepted++; else rejected++;
    }
    // Finalize the block with the current validator set (joined validators' keys are known here).
    clock.t += 1000;
    const set = chain.validatorList;
    const keyOf = (pk) => [...vals, ...extraVals.map((e) => e.vk)].find((k) => k.publicKey === pk);
    const proposer = set[height % set.length];
    const block = chain.buildBlock(proposer);
    const precommits = set.slice(0, quorum(set.length)).map((pk) => {
      const vote = { type: 'precommit', height: block.header.height, round: 0, blockHash: block.hash, validator: pk };
      return { ...vote, signature: sign(voteSignBytes(genesis.chainId, vote), keyOf(pk).privateKey) };
    });
    const result = chain.addBlock({ ...block, commit: { round: 0, precommits } });
    assert.equal(result.ok, true, result.error);

    assert.equal(accounted(chain.state), chain.state.supply, `money out of balance at block ${height}`);
    assert.equal(chain.state.supply, supply0, 'supply changed with no rewards or slashing');
    for (const u of users) {
      const n = chain.state.get(addr(u)).nonce;
      assert.ok(n >= (lastNonce.get(addr(u)) ?? 0), 'nonce went down');
      lastNonce.set(addr(u), n);
    }
  }
  assert.ok(accepted > 100 && rejected > 20, `exercised: ${accepted} accepted, ${rejected} rejected`);
});
