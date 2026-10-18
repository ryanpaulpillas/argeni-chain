// Creates a local 4-validator devnet in ./devnet: keys, genesis and node configs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPair } from '../src/crypto.js';
import { parseAmount } from '../src/coin.js';
import { writeKeyFile } from '../src/cli.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'devnet');
// 4 is the smallest set that keeps finalizing blocks with one validator offline (n >= 3f + 1).
const VALIDATORS = 4;
const BASE_PORT = 26601;
const DECIMALS = 18;
const MAX_SUPPLY = '500000000'; // 500 million ARGENI, all created at genesis
const FAUCET_SHARE = '1000000';
const REWARD_POOL = '60000000'; // validator incentives, paid out by the chain

if (fs.existsSync(root)) {
  console.error(`${root} already exists. Delete it first to start a fresh devnet.`);
  process.exit(1);
}

// All keys are post-quantum: ML-DSA-87 (FIPS 204, NIST category 5).
const validators = Array.from({ length: VALIDATORS }, (_, i) => writeKeyFile(path.join(root, 'keys', `validator-${i + 1}.json`), generateKeyPair('ml-dsa-87')));
const faucet = writeKeyFile(path.join(root, 'keys', 'faucet.json'), generateKeyPair('ml-dsa-87'));
const treasury = writeKeyFile(path.join(root, 'keys', 'treasury.json'), generateKeyPair('ml-dsa-87'));

// Fixed supply: all 500 million ARGENI exist from genesis and blockReward is 0, so no coin is
// ever minted; validators earn transaction fees. How the supply is split (team, ecosystem,
// sale, reserve) is still to be decided; on devnet it sits in one treasury key plus the faucet.
const genesis = {
  chainId: 'argeni-devnet-1',
  timestamp: Date.now(),
  coin: { name: 'Argeni', symbol: 'ARGENI', decimals: DECIMALS },
  blockTimeMs: 2000,
  maxTxsPerBlock: 500,
  minFee: parseAmount('0.0001', DECIMALS).toString(),
  blockReward: '0',
  maxSupply: parseAmount(MAX_SUPPLY, DECIMALS).toString(),
  validators: validators.map((v) => v.publicKey),
  // Validator incentives (12%): paid by the chain to the validators that sign, front-loaded over 4 years.
  rewards: { years: ['24000000', '18000000', '12000000', '6000000'].map((n) => parseAmount(n, DECIMALS).toString()) },
  alloc: {
    [treasury.address]: (parseAmount(MAX_SUPPLY, DECIMALS) - parseAmount(FAUCET_SHARE, DECIMALS) - parseAmount(REWARD_POOL, DECIMALS)).toString(),
    [faucet.address]: parseAmount(FAUCET_SHARE, DECIMALS).toString(),
  },
};
fs.writeFileSync(path.join(root, 'genesis.json'), `${JSON.stringify(genesis, null, 2)}\n`);

for (let i = 1; i <= VALIDATORS; i++) {
  const config = {
    genesis: 'genesis.json',
    dataDir: `data/node-${i}`,
    host: '127.0.0.1',
    port: BASE_PORT + i - 1,
    peers: Array.from({ length: VALIDATORS }, (_, j) => j + 1).filter((j) => j !== i).map((j) => `http://127.0.0.1:${BASE_PORT + j - 1}`),
    validatorKey: `keys/validator-${i}.json`,
    ...(i === 1 ? { faucetKey: 'keys/faucet.json', faucetAmount: '100' } : {}),
  };
  fs.writeFileSync(path.join(root, `node-${i}.json`), `${JSON.stringify(config, null, 2)}\n`);
}

console.log(`devnet created in ${root}
chain id   ${genesis.chainId}
coin       ${genesis.coin.symbol} (${DECIMALS} decimals)
validators ${validators.map((v) => v.address).join('\n           ')}
supply     500,000,000 ARGENI, fixed (no minting)
treasury   ${treasury.address} (439,000,000)
rewards    60,000,000 validator pool (24M, 18M, 12M, 6M a year)
faucet     ${faucet.address} (1,000,000, served by node 1)

Start it with: npm run devnet`);
