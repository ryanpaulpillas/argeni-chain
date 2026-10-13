#!/usr/bin/env node
// argeni command-line tool: keys, running a node, balances, transfers, faucet.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, addressFromPublicKey, publicKeyFromPrivate, keyTypeOf, KEY_TYPES, PQ_KEY_TYPES, DEFAULT_KEY_TYPE } from './crypto.js';
import { createTransfer, createMigration, createMigrationCommit } from './tx.js';
import { formatAmount, parseAmount } from './coin.js';
import { writeKeyFile, readKeyFile, loadSigningKey, choosePassphrase, encryptKeyFile, decryptKeyFile, isEncrypted, askPassphrase } from './keyfile.js';
import { Node, fetchJson } from './node.js';

const DEFAULT_RPC = 'http://127.0.0.1:26601';

const USAGE = `argeni <command> [options]

  keygen --out <file> [--type ml-dsa-87|ml-dsa-65|slh-dsa-256s|slh-dsa-128s|ed25519] [--encrypt]
                                              create a new key file (default: post-quantum ML-DSA-87,
                                              NIST category 5; slh-dsa-256s is hash-based, category 5,
                                              for savings, cold storage and treasuries). --encrypt
                                              protects it with a passphrase (use it for vaults)
  encrypt --key <file> --out <file>           write a passphrase-protected copy of a key file
  check-key --key <file>                      confirm a (backup) key file opens and matches its address
  address --key <file>                        print the address of a key file
  node --config <file>                        run a node
  status [--rpc <url>]                        show chain status
  balance <address> [--rpc <url>]             show an account balance
  send --key <file> --to <address> --amount <ARGENI> [--fee <ARGENI>] [--memo <text>] [--rpc <url>]
  faucet <address> [--rpc <url>]              request testnet ARGENI
  pq-commit --key <current key file> --new-key <post-quantum file> [--rpc <url>]
                                              lock in the key this account will migrate to
                                              (do this before its key type is retired)
  migrate --key <current key file> --new-key <post-quantum file> [--rpc <url>]
                                              move a whole account to a different post-quantum key
                                              (Ed25519 -> post-quantum, or rotate e.g. ML-DSA -> SLH-DSA)

Default --rpc is ${DEFAULT_RPC}.`;

// Key-file helpers live in keyfile.js; re-exported for scripts that import them from here.
export { writeKeyFile, readKeyFile };

// Node keys are read unattended, so they must be plain files (protected by file permissions).
function plainKey(file) {
  const keys = readKeyFile(file);
  if (isEncrypted(keys)) throw new Error(`${file} is encrypted; a running node needs an unencrypted key file`);
  return keys.privateKey;
}

async function main(argv) {
  const [command, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      out: { type: 'string' },
      type: { type: 'string', default: DEFAULT_KEY_TYPE },
      'new-key': { type: 'string' },
      key: { type: 'string' },
      config: { type: 'string' },
      rpc: { type: 'string', default: DEFAULT_RPC },
      to: { type: 'string' },
      amount: { type: 'string' },
      fee: { type: 'string' },
      memo: { type: 'string' },
      encrypt: { type: 'boolean', default: false },
    },
  });
  const rpc = values.rpc.replace(/\/$/, '');

  switch (command) {
    case 'keygen': {
      if (!values.out) throw new Error('--out is required');
      if (!KEY_TYPES.includes(values.type)) throw new Error(`--type must be one of: ${KEY_TYPES.join(', ')}`);
      if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists; refusing to overwrite a key`);
      const passphrase = values.encrypt ? await choosePassphrase() : null;
      const keys = generateKeyPair(values.type);
      const plain = { address: addressFromPublicKey(keys.publicKey), ...keys };
      writeKeyFile(values.out, passphrase ? encryptKeyFile(plain, passphrase) : plain);
      console.log(`wrote ${values.out} (${values.type}${PQ_KEY_TYPES.includes(values.type) ? ', post-quantum' : ''}${passphrase ? ', encrypted' : ''})\naddress ${plain.address}`);
      console.log(passphrase
        ? 'Without the passphrase this file cannot be opened, and nobody can recover it. Store backups and the passphrase separately.'
        : 'Keep this file private: anyone with it controls the funds.');
      return;
    }
    case 'encrypt': {
      if (!values.key || !values.out) throw new Error('--key and --out are required');
      const file = readKeyFile(values.key);
      if (isEncrypted(file)) throw new Error(`${values.key} is already encrypted`);
      if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists; refusing to overwrite a key`);
      writeKeyFile(values.out, encryptKeyFile(file, await choosePassphrase()));
      console.log(`wrote encrypted ${values.out} for ${file.address}\nCheck it with: argeni check-key --key ${values.out}\nThen delete the unencrypted ${values.key} securely.`);
      return;
    }
    case 'check-key': {
      if (!values.key) throw new Error('--key is required');
      const file = readKeyFile(values.key);
      const keys = isEncrypted(file) ? decryptKeyFile(file, await askPassphrase(`Passphrase for ${path.basename(values.key)}: `)) : file;
      if (publicKeyFromPrivate(keys.privateKey) !== keys.publicKey || addressFromPublicKey(keys.publicKey) !== keys.address) throw new Error('key file does not match its address');
      console.log(`OK: ${values.key} opens and controls ${keys.address} (${keys.type}${isEncrypted(file) ? ', encrypted' : ', NOT encrypted'})`);
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
        validatorKey: config.validatorKey ? plainKey(resolve(config.validatorKey)) : null,
        faucetKey: config.faucetKey ? plainKey(resolve(config.faucetKey)) : null,
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
      const key = await loadSigningKey(values.key);
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
      const oldKey = await loadSigningKey(values.key);
      const newKey = await loadSigningKey(values['new-key']);
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
      const oldKey = await loadSigningKey(values.key);
      const newKey = await loadSigningKey(values['new-key']);
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
