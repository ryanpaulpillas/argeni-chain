// Creates the public testnet on a server: genesis, validator and faucet keys, node configs.
//
//   node scripts/init-testnet.js --treasury <ag… address> [--validators 4] [--out testnet]
//
// The treasury (499,000,000 test ARGENI) is only an ADDRESS here: its key is created on the
// operator's own computer and never touches the server. Validator and faucet keys are created
// here, post-quantum (ML-DSA-87), readable only by the user running this script.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { generateKeyPair, isAddress } from '../src/crypto.js';
import { parseAmount } from '../src/coin.js';
import { writeKeyFile } from '../src/cli.js';

const { values } = parseArgs({
  options: {
    treasury: { type: 'string' },
    validators: { type: 'string', default: '4' },
    out: { type: 'string', default: 'testnet' },
    'chain-id': { type: 'string', default: 'argeni-testnet-1' },
  },
});

const count = Number(values.validators);
if (!isAddress(values.treasury ?? '')) {
  console.error('--treasury <address> is required: create it on your own computer with\n  node src/cli.js keygen --out argeni-treasury.json\nand pass only the address it prints.');
  process.exit(1);
}
if (!Number.isInteger(count) || count < 1 || count > 20) {
  console.error('--validators must be a number from 1 to 20 (4 or more to tolerate a failure)');
  process.exit(1);
}
const root = path.resolve(values.out);
if (fs.existsSync(root)) {
  console.error(`${root} already exists. A testnet is created once; delete it only if you mean to start a new chain.`);
  process.exit(1);
}

const DECIMALS = 18;
const BASE_PORT = 26601;
const validators = Array.from({ length: count }, (_, i) => writeKeyFile(path.join(root, 'keys', `validator-${i + 1}.json`), generateKeyPair('ml-dsa-87')));
const faucet = writeKeyFile(path.join(root, 'keys', 'faucet.json'), generateKeyPair('ml-dsa-87'));

const genesis = {
  chainId: values['chain-id'],
  timestamp: Date.now(),
  coin: { name: 'Argeni', symbol: 'ARGENI', decimals: DECIMALS },
  blockTimeMs: 2000,
  emptyBlockIntervalMs: 60_000, // idle chain: one heartbeat block a minute instead of one every 2 s
  maxTxsPerBlock: 200, // post-quantum transactions are ~10 KB each
  minFee: parseAmount('0.0001', DECIMALS).toString(),
  blockReward: '0',
  maxSupply: parseAmount('500000000', DECIMALS).toString(),
  validators: validators.map((v) => v.publicKey),
  // Staking: new validators join by bonding at least minStake; penalties for double-signing and downtime.
  staking: {
    minStake: parseAmount('100000', DECIMALS).toString(),
    maxValidators: 100,
    minValidators: count,
    unbondingMs: 14 * 24 * 60 * 60 * 1000,
    jailMs: 24 * 60 * 60 * 1000,
    downtimeBlocks: 500,
    downtimeSlashBps: 10, // 0.1%
    doubleSignSlashBps: 500, // 5%
  },
  alloc: {
    [values.treasury]: parseAmount('499000000', DECIMALS).toString(),
    [faucet.address]: parseAmount('1000000', DECIMALS).toString(),
  },
};
fs.writeFileSync(path.join(root, 'genesis.json'), `${JSON.stringify(genesis, null, 2)}\n`);

const publicLimits = {
  trustProxy: true, // nodes sit behind Caddy on the same machine
  txsPerMinutePerIp: 30,
};
for (let i = 1; i <= count; i++) {
  const config = {
    genesis: 'genesis.json',
    dataDir: `data/node-${i}`,
    host: '127.0.0.1',
    port: BASE_PORT + i - 1,
    peers: Array.from({ length: count }, (_, j) => j + 1).filter((j) => j !== i).map((j) => `http://127.0.0.1:${BASE_PORT + j - 1}`),
    validatorKey: `keys/validator-${i}.json`,
    ...publicLimits,
    ...(i === 1 ? {
      faucetKey: 'keys/faucet.json',
      faucetAmount: '100',
      faucetAddressCooldownMs: 24 * 60 * 60 * 1000, // each address once a day
      faucetIpCooldownMs: 60 * 60 * 1000, // each network once an hour
    } : {}),
  };
  fs.writeFileSync(path.join(root, `node-${i}.json`), `${JSON.stringify(config, null, 2)}\n`);
}

console.log(`testnet created in ${root}
chain id    ${genesis.chainId}
validators  ${count} (ML-DSA-87, post-quantum, NIST category 5)
treasury    ${values.treasury}  499,000,000 test ARGENI (key stays off this server)
faucet      ${faucet.address}  1,000,000 test ARGENI, served by node 1
Back up ${path.join(root, 'keys')} somewhere safe and private.`);
