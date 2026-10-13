// Demo activity: funds four wallets from the faucet, then sends random transfers between
// them through random nodes so the explorer has something to show. Ctrl+C to stop.
import { addressFromPublicKey, generateKeyPair } from '../src/crypto.js';
import { createTransfer } from '../src/tx.js';
import { formatAmount } from '../src/coin.js';
import { fetchJson } from '../src/node.js';

const NODES = ['http://127.0.0.1:26601', 'http://127.0.0.1:26602', 'http://127.0.0.1:26603', 'http://127.0.0.1:26604'];
const INTERVAL_MS = 1500;
const MEMOS = ['coffee', 'rent share', 'invoice #1042', 'thanks!', 'lunch', 'refund', 'test payment', ''];

const wallets = ['Alice', 'Bob', 'Carol', 'Dave'].map((name) => {
  const keys = generateKeyPair('ml-dsa-87');
  return { name, ...keys, address: addressFromPublicKey(keys.publicKey) };
});
const pick = (list) => list[Math.floor(Math.random() * list.length)];
const post = (url, body) => fetchJson(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

const status = await fetchJson(`${NODES[0]}/status`);
const genesis = await fetchJson(`${NODES[0]}/genesis`);
const { decimals, symbol } = status.coin;

for (const w of wallets) {
  await post(`${NODES[0]}/faucet`, { address: w.address });
  console.log(`faucet  -> ${w.name.padEnd(5)} ${w.address}  +100 ${symbol}`);
}
console.log('waiting for the faucet transfers to be finalized…');
for (;;) {
  const balances = await Promise.all(wallets.map((w) => fetchJson(`${NODES[0]}/accounts/${w.address}`)));
  if (balances.every((b) => BigInt(b.balance) > 0n)) break;
  await new Promise((r) => setTimeout(r, 500));
}

setInterval(async () => {
  const from = pick(wallets);
  const to = pick(wallets.filter((w) => w !== from));
  const node = pick(NODES);
  try {
    const account = await fetchJson(`${node}/accounts/${from.address}`);
    const amount = BigInt(Math.floor(Math.random() * 500 + 1)) * 10n ** BigInt(decimals - 2); // 0.01 – 5.00
    const fee = BigInt(genesis.minFee);
    if (BigInt(account.balance) < amount + fee) return;
    const memo = pick(MEMOS);
    const tx = createTransfer({ chainId: genesis.chainId, privateKey: from.privateKey, to: to.address, amount, fee, nonce: account.pendingNonce, ...(memo ? { memo } : {}) });
    await post(`${node}/txs`, tx);
    console.log(`${from.name.padEnd(5)} -> ${to.name.padEnd(5)} ${formatAmount(amount, decimals).padStart(5)} ${symbol}  via ${node.slice(-5)}${memo ? `  "${memo}"` : ''}`);
  } catch (err) {
    console.log(`skipped: ${err.message}`);
  }
}, INTERVAL_MS);
