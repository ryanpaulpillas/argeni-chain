#!/usr/bin/env node
// argeni command-line tool: keys, running a node, balances, transfers, faucet.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, addressFromPublicKey, keyTypeOf, KEY_TYPES, PQ_KEY_TYPES } from './crypto.js';
import { createTransfer, createMigration, createMigrationCommit } from './tx.js';
import { formatAmount, parseAmount } from './coin.js';
import { Node, fetchJson } from './node.js';

const DEFAULT_RPC = 'http://127.0.0.1:26601';

const USAGE = `argeni <command> [options]

  keygen --out <file> [--type ml-dsa-65|slh-dsa-128s|ed25519]
                                              create a new key file (default: post-quantum ML-DSA-65;
                                              slh-dsa-128s is hash-based, for savings/cold storage)
  address --key <file>                        print the address of a key file
  node --config <file>                        run a node
  status [--rpc <url>]                        show chain status
  balance <address> [--rpc <url>]             show an account balance
  send --key <file> --to <address> --amount <ARGENI> [--fee <ARGENI>] [--memo <text>] [--rpc <url>]
  faucet <address> [--rpc <url>]              request testnet ARGENI
  pq-commit --key <old ed25519 file> --new-key <post-quantum file> [--rpc <url>]
                                              lock in the post-quantum key an Ed25519 account will
                                              migrate to (do this before the sunset height)
  migrate --key <old ed25519 file> --new-key <post-quantum file> [--rpc <url>]
                                              move a whole Ed25519 account to a post-quantum key

Default --rpc is ${DEFAULT_RPC}.`;

export function writeKeyFile(file, keys) {
  if (fs.existsSync(file)) throw new Error(`${file} already exists; refusing to overwrite a key`);
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const content = { address: addressFromPublicKey(keys.publicKey), ...keys };
  if (!content.type) content.type = 'ed25519';
  fs.writeFileSync(file, `${JSON.stringify(content, null, 2)}\n`, { mode: 0o600 });
  return content;
}

export function readKeyFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function main(argv) {
  const [command, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      out: { type: 'string' },
      type: { type: 'string', default: 'ml-dsa-65' },
      'new-key': { type: 'string' },
      key: { type: 'string' },
      config: { type: 'string' },
      rpc: { type: 'string', default: DEFAULT_RPC },
      to: { type: 'string' },
      amount: { type: 'string' },
      fee: { type: 'string' },
      memo: { type: 'string' },
    },
  });
  const rpc = values.rpc.replace(/\/$/, '');

  switch (command) {
    case 'keygen': {
      if (!values.out) throw new Error('--out is required');
      if (!KEY_TYPES.includes(values.type)) throw new Error(`--type must be one of: ${KEY_TYPES.join(', ')}`);
      const { address } = writeKeyFile(values.out, generateKeyPair(values.type));
      console.log(`wrote ${values.out} (${values.type}${PQ_KEY_TYPES.includes(values.type) ? ', post-quantum' : ''})\naddress ${address}\nKeep this file private: anyone with it controls the funds.`);
      return;
    }
    case 'address': {
      if (!values.key) throw new Error('--key is required');
      console.log(addressFromPublicKey(readKeyFile(values.key).publicKey));
      return;
    }
    case 'node': {
      if (!values.config) throw new Error('--config is required');
      const configPath = path.resolve(values.config);
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      const resolve = (p) => (p ? path.resolve(path.dirname(configPath), p) : null);
      const node = new Node({
        genesis: JSON.parse(fs.readFileSync(resolve(config.genesis), 'utf8')),
        dataDir: resolve(config.dataDir),
        port: config.port,
        host: config.host,
        peers: config.peers ?? [],
        validatorKey: config.validatorKey ? readKeyFile(resolve(config.validatorKey)).privateKey : null,
        faucetKey: config.faucetKey ? readKeyFile(resolve(config.faucetKey)).privateKey : null,
        faucetAmount: config.faucetAmount,
        trustProxy: config.trustProxy,
        faucetAddressCooldownMs: config.faucetAddressCooldownMs,
        faucetIpCooldownMs: config.faucetIpCooldownMs,
        txsPerMinutePerIp: config.txsPerMinutePerIp,
      });
      await node.start();
      const shutdown = () => node.stop().then(() => process.exit(0));
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      return;
    }
    case 'status': {
      console.log(JSON.stringify(await fetchJson(`${rpc}/status`), null, 2));
      return;
    }
    case 'balance': {
      if (!positionals[0]) throw new Error('address is required');
      const account = await fetchJson(`${rpc}/accounts/${positionals[0]}`);
      console.log(`${account.balanceFormatted} (nonce ${account.nonce})`);
      return;
    }
    case 'send': {
      if (!values.key || !values.to || !values.amount) throw new Error('--key, --to and --amount are required');
      const status = await fetchJson(`${rpc}/status`);
      const { decimals, symbol } = status.coin;
      const genesis = await fetchJson(`${rpc}/genesis`);
      const key = readKeyFile(values.key);
      const from = addressFromPublicKey(key.publicKey);
      const account = await fetchJson(`${rpc}/accounts/${from}`);
      const tx = createTransfer({
        chainId: status.chainId,
        privateKey: key.privateKey,
        to: values.to,
        amount: parseAmount(values.amount, decimals),
        fee: values.fee ? parseAmount(values.fee, decimals) : BigInt(genesis.minFee),
        nonce: account.pendingNonce,
        memo: values.memo,
      });
      const { hash } = await fetchJson(`${rpc}/txs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(tx),
      });
      console.log(`sent ${values.amount} ${symbol} to ${values.to} (fee ${formatAmount(tx.fee, decimals)})\ntx ${hash}`);
      return;
    }
    case 'pq-commit': {
      if (!values.key || !values['new-key']) throw new Error('--key and --new-key are required');
      const genesis = await fetchJson(`${rpc}/genesis`);
      const oldKey = readKeyFile(values.key);
      const newKey = readKeyFile(values['new-key']);
      if (!PQ_KEY_TYPES.includes(keyTypeOf(newKey.publicKey))) throw new Error('--new-key must be a post-quantum key file');
      const from = addressFromPublicKey(oldKey.publicKey);
      const account = await fetchJson(`${rpc}/accounts/${from}`);
      const tx = createMigrationCommit({
        chainId: genesis.chainId,
        privateKey: oldKey.privateKey,
        pqPublicKey: newKey.publicKey,
        fee: BigInt(genesis.minFee),
        nonce: account.pendingNonce,
      });
      const { hash } = await fetchJson(`${rpc}/txs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(tx),
      });
      console.log(`committed ${from}
       -> ${addressFromPublicKey(newKey.publicKey)} (${keyTypeOf(newKey.publicKey)})
only a hash is published; this account can now migrate only to that key
tx ${hash}`);
      return;
    }
    case 'migrate': {
      if (!values.key || !values['new-key']) throw new Error('--key and --new-key are required');
      const genesis = await fetchJson(`${rpc}/genesis`);
      const oldKey = readKeyFile(values.key);
      const newKey = readKeyFile(values['new-key']);
      const from = addressFromPublicKey(oldKey.publicKey);
      const account = await fetchJson(`${rpc}/accounts/${from}`);
      const tx = createMigration({
        chainId: genesis.chainId,
        privateKey: oldKey.privateKey,
        pqPrivateKey: newKey.privateKey,
        fee: BigInt(genesis.minFee),
        nonce: account.pendingNonce,
      });
      const { hash } = await fetchJson(`${rpc}/txs`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(tx),
      });
      console.log(`migrating ${from}\n       -> ${addressFromPublicKey(newKey.publicKey)} (${keyTypeOf(newKey.publicKey)})\nthe whole balance moves; the old key is locked afterwards\ntx ${hash}`);
      return;
    }
    case 'faucet': {
      if (!positionals[0]) throw new Error('address is required');
      const result = await fetchJson(`${rpc}/faucet`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ address: positionals[0] }),
      });
      console.log(`faucet sent ${result.amount} to ${positionals[0]}\ntx ${result.hash}`);
      return;
    }
    default:
      console.log(USAGE);
      if (command && command !== 'help') process.exitCode = 1;
  }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}
