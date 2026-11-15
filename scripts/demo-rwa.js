// Demo real-world asset (ARS-1) on a running devnet: a sample tokenized property whose
// administrators all use hash-based SLH-DSA keys. Creates the asset, verifies two investors (one
// Filipino, one foreign), issues units up to the 40% foreign cap and publishes an appraisal.
// Demonstration only: no real asset, company or offering stands behind it.
import { addressFromPublicKey, generateKeyPair, sha256 } from '../src/crypto.js';
import { createTx } from '../src/tx.js';
import { assetIdFor } from '../src/rwa.js';
import { fetchJson } from '../src/node.js';

const RPC = process.argv[2] ?? 'http://127.0.0.1:26601';
const post = (path, body) => fetchJson(`${RPC}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const make = (name, type) => {
  const keys = generateKeyPair(type);
  return { name, ...keys, address: addressFromPublicKey(keys.publicKey) };
};
const issuer = make('issuer', 'slh-dsa-128s');
const compliance = make('compliance', 'slh-dsa-128s');
const recovery = make('recovery', 'slh-dsa-128s');
const attestor = make('attestor', 'slh-dsa-128s');
const maria = make('Maria (PH)', 'ml-dsa-87');
const kenji = make('Kenji (JP)', 'ml-dsa-87');

const genesis = await fetchJson(`${RPC}/genesis`);
const fee = BigInt(genesis.minFee);

for (const w of [issuer, compliance, attestor, maria, kenji]) await post('/faucet', { address: w.address });
console.log('funding the demo accounts from the faucet…');
for (;;) {
  const accounts = await Promise.all([issuer, compliance, attestor, maria, kenji].map((w) => fetchJson(`${RPC}/accounts/${w.address}`)));
  if (accounts.every((a) => BigInt(a.balance) > 0n)) break;
  await sleep(500);
}

async function send(w, fields) {
  const { nonce } = await fetchJson(`${RPC}/accounts/${w.address}`);
  await post('/txs', createTx({ chainId: genesis.chainId, fee, nonce, ...fields }, { privateKey: w.privateKey }));
  for (let i = 0; i < 120; i++) {
    if ((await fetchJson(`${RPC}/accounts/${w.address}`)).nonce > nonce) return console.log(`  ${fields.type.padEnd(14)} by ${w.name}`);
    await sleep(500);
  }
  throw new Error(`${fields.type} was not included`);
}

const symbol = 'PHRE1';
await send(issuer, {
  type: 'asset-create', symbol, name: 'Demo Makati Office Tower, Class A', class: 'real-estate', decimals: 0, maxSupply: '1000',
  roles: { compliance: compliance.address, recovery: recovery.address, attestor: attestor.address },
  legal: { entity: 'Demo Property Holdings (example only)', secRegNo: 'DEMO-ONLY', offering: 'pilot', jurisdiction: 'PH', docsHash: sha256('demo offering documents'), docsUri: 'https://cyvber.io/demo/PHRE1' },
  rules: { kycRequired: true, investorClasses: ['qualified', 'institutional'], allowedCountries: ['*'], foreignCapBps: 4000, maxHolders: 200, lockupUntilHeight: 0, minHoldingUnits: '1', redeemable: false, adminKeys: 'hash-based' },
});
const assetId = assetIdFor(genesis.chainId, issuer.address, symbol);
const kyc = (w, country, foreign) => send(compliance, { type: 'kyc-attest', address: w.address, level: 2, country, foreign, investorClass: 'qualified', expiresHeight: 100_000_000, recordHash: sha256(`demo kyc ${w.address}`) });
await kyc(maria, 'PH', false);
await kyc(kenji, 'JP', true);
await send(issuer, { type: 'asset-issue', assetId, to: maria.address, amount: 600n, docRef: sha256('demo subscription Maria') });
await send(issuer, { type: 'asset-issue', assetId, to: kenji.address, amount: 400n, docRef: sha256('demo subscription Kenji') });
await send(attestor, { type: 'asset-attest', assetId, kind: 'appraisal', valueHash: sha256('demo appraisal report'), uri: 'https://cyvber.io/demo/PHRE1/appraisal' });

const asset = await fetchJson(`${RPC}/assets/${assetId}`);
console.log(`\n${asset.symbol}: ${asset.supply}/${asset.maxSupply} units, ${asset.holders} holders, foreign share ${asset.foreignShareBps / 100}% (cap 40%), admin keys: ${asset.rules.adminKeys}`);
console.log(`assetId ${assetId}`);
