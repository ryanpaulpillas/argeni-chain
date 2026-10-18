#!/usr/bin/env node
// argeni command-line tool: keys, running a node, balances, transfers, faucet.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, addressFromPublicKey, publicKeyFromPrivate, keyTypeOf, sign, multisigKey, parseMultisig, signMultisigPart, combineMultisig, KEY_TYPES, PQ_KEY_TYPES, DEFAULT_KEY_TYPE } from './crypto.js';
import { createTransfer, createMigration, createMigrationCommit, createTx, signingBytes } from './tx.js';
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

Vesting (locked allocations, e.g. team grants)
  vest --key <file> --to <address> --amount <ARGENI> --lock <months> --vest <months> [--at-start <ARGENI>]
                                              send ARGENI that unlocks over time: nothing for --lock
                                              months, then equal monthly parts over --vest months

Multi-signature vaults (e.g. 2 of 3 founders must sign)
  multisig create --threshold <m> --keys <a.json,b.json,c.json> --out <vault.json>
                                              make a vault from members' key files (only their public
                                              keys are read); prints the vault's address
  multisig propose --vault <vault.json> --to <address> --amount <ARGENI> --out <tx.json>
                   [--lock <months> --vest <months>]   prepare an unsigned transfer (or vesting grant)
  multisig sign --tx <tx.json> --key <member key file>  add one member's signature (offline is fine)
  multisig submit --tx <tx.json>              send it once enough members have signed

Staking (validators)
  validators [--rpc <url>]                    list validators, stake and status
  stake join --key <owner key> --validator-key <file> --amount <ARGENI>
                                              bond ARGENI and add a validator (its key signs too)
  stake add --key <owner key> --validator <address> --amount <ARGENI>
  stake delegate --key <stake provider key> --validator-pubkey <file> --operator <address> --amount <ARGENI> --out <offer.json>
                                              lend stake to an operator: they run the validator and earn
                                              its rewards; the stake comes back to you when it leaves
  stake accept --offer <offer.json> --validator-key <file>
                                              (operator) countersign a stake offer and submit it
  export-pubkey --key <file> --out <file>     write only the public part of a key file (safe to share)
  stake leave --key <owner key> --validator <address>
                                              leave the set; the stake returns after unbonding
  stake unjail --key <owner key> --validator <address>
                                              return after a downtime jail has ended

Default --rpc is ${DEFAULT_RPC}.`;

// Key-file helpers live in keyfile.js; re-exported for scripts that import them from here.
export { writeKeyFile, readKeyFile };

// Node keys are read unattended, so they must be plain files (protected by file permissions).
function plainKey(file) {
  const keys = readKeyFile(file);
  if (isEncrypted(keys)) throw new Error(`${file} is encrypted; a running node needs an unencrypted key file`);
  return keys.privateKey;
}

const postTx = (rpc, tx) => fetchJson(`${rpc}/txs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(tx) });
const months = (v, name) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`--${name} must be a whole number of months`);
  return n;
};

// Signs and sends a transaction of any type from a (possibly passphrase-protected) key file.
async function signAndSend(rpc, keyFile, { extraSigners, ...fields }) {
  const genesis = await fetchJson(`${rpc}/genesis`);
  const key = await loadSigningKey(keyFile);
  if (!key.privateKey) throw new Error(`${keyFile} is a multisig vault; use "argeni multisig propose"`);
  const account = await fetchJson(`${rpc}/accounts/${addressFromPublicKey(key.publicKey)}`);
  const tx = createTx({ chainId: genesis.chainId, fee: BigInt(genesis.minFee), nonce: account.pendingNonce, ...fields }, { privateKey: key.privateKey, extraSigners });
  const { hash } = await postTx(rpc, tx);
  return { tx, hash, genesis };
}

async function validatorKeyByAddress(rpc, address) {
  const { validators } = await fetchJson(`${rpc}/validators`);
  const v = validators.find((x) => x.address === address);
  if (!v) throw new Error(`${address} is not a registered validator`);
  return v.publicKey;
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
      lock: { type: 'string' },
      vest: { type: 'string' },
      'at-start': { type: 'string' },
      threshold: { type: 'string' },
      keys: { type: 'string' },
      vault: { type: 'string' },
      tx: { type: 'string' },
      validator: { type: 'string' },
      'validator-key': { type: 'string' },
      'validator-pubkey': { type: 'string' },
      operator: { type: 'string' },
      offer: { type: 'string' },
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
        snapshotEvery: config.snapshotEvery,
        trustedBlock: config.trustedBlock ?? null,
        publicUrl: config.publicUrl ?? null,
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
      if (!key.privateKey) throw new Error(`${values.key} is a multisig vault; use "argeni multisig propose"`);
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
    case 'vest': {
      if (!values.key || !values.to || !values.amount || values.lock === undefined || values.vest === undefined) throw new Error('--key, --to, --amount, --lock and --vest are required');
      const { coin } = await fetchJson(`${rpc}/status`);
      const fields = {
        type: 'vest', to: values.to, amount: parseAmount(values.amount, coin.decimals),
        lockMonths: months(values.lock, 'lock'), vestMonths: months(values.vest, 'vest'),
        ...(values['at-start'] ? { atStart: parseAmount(values['at-start'], coin.decimals) } : {}),
        ...(values.memo ? { memo: values.memo } : {}),
      };
      const { hash } = await signAndSend(rpc, values.key, fields);
      console.log(`granted ${values.amount} ${coin.symbol} to ${values.to}: locked ${values.lock} months, then unlocks monthly over ${values.vest} months\ntx ${hash}`);
      return;
    }
    case 'multisig': {
      const sub = positionals[0];
      if (sub === 'create') {
        if (!values.threshold || !values.keys || !values.out) throw new Error('--threshold, --keys and --out are required');
        const members = values.keys.split(',').map((f) => readKeyFile(f.trim()).publicKey);
        const publicKey = multisigKey(Number(values.threshold), members);
        const address = addressFromPublicKey(publicKey);
        writeKeyFile(values.out, { address, type: 'multisig', threshold: Number(values.threshold), members: members.map(addressFromPublicKey), publicKey });
        console.log(`wrote ${values.out}: ${values.threshold} of ${members.length} multisig\naddress ${address}\nThis file holds no private key; each member keeps their own key file.`);
        return;
      }
      if (sub === 'propose') {
        if (!values.vault || !values.to || !values.amount || !values.out) throw new Error('--vault, --to, --amount and --out are required');
        const vault = readKeyFile(values.vault);
        if (!parseMultisig(vault.publicKey)) throw new Error(`${values.vault} is not a multisig vault file`);
        const genesis = await fetchJson(`${rpc}/genesis`);
        const account = await fetchJson(`${rpc}/accounts/${vault.address}`);
        const vesting = values.lock !== undefined || values.vest !== undefined;
        const tx = createTx({
          type: vesting ? 'vest' : 'transfer', chainId: genesis.chainId, from: vault.publicKey, to: values.to,
          amount: parseAmount(values.amount, genesis.coin.decimals), fee: BigInt(genesis.minFee), nonce: account.pendingNonce,
          ...(vesting ? { lockMonths: months(values.lock ?? '0', 'lock'), vestMonths: months(values.vest ?? '0', 'vest') } : {}),
          ...(values.memo ? { memo: values.memo } : {}),
        });
        if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists`);
        fs.writeFileSync(values.out, `${JSON.stringify({ tx, signatures: [] }, null, 2)}\n`);
        console.log(`wrote ${values.out}: ${values.amount} ${genesis.coin.symbol} from ${vault.address} to ${values.to}\nNow ${parseMultisig(vault.publicKey).threshold} members run: argeni multisig sign --tx ${values.out} --key <their key file>`);
        return;
      }
      if (sub === 'sign') {
        if (!values.tx || !values.key) throw new Error('--tx and --key are required');
        const file = JSON.parse(fs.readFileSync(values.tx, 'utf8'));
        const ms = parseMultisig(file.tx.from);
        const key = await loadSigningKey(values.key);
        console.log(`signing: ${file.tx.type} of ${file.tx.amount} base units to ${file.tx.to} (nonce ${file.tx.nonce}, chain ${file.tx.chainId})`);
        file.signatures = [combineMultisig([...file.signatures, signMultisigPart(signingBytes(file.tx), file.tx.from, key.privateKey)])];
        fs.writeFileSync(values.tx, `${JSON.stringify(file, null, 2)}\n`);
        const have = file.signatures[0].split(',').length;
        console.log(`${have} of ${ms.threshold} signatures${have >= ms.threshold ? ` — ready: argeni multisig submit --tx ${values.tx}` : ''}`);
        return;
      }
      if (sub === 'submit') {
        if (!values.tx) throw new Error('--tx is required');
        const file = JSON.parse(fs.readFileSync(values.tx, 'utf8'));
        const { hash } = await postTx(rpc, { ...file.tx, signature: combineMultisig(file.signatures) });
        console.log(`submitted\ntx ${hash}`);
        return;
      }
      throw new Error('use: multisig create | propose | sign | submit');
    }
    case 'export-pubkey': {
      if (!values.key || !values.out) throw new Error('--key and --out are required');
      const { address, type, publicKey } = readKeyFile(values.key);
      if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists`);
      fs.writeFileSync(values.out, `${JSON.stringify({ address, type, publicKey }, null, 2)}\n`);
      console.log(`wrote ${values.out}: the public key of ${address} (no private key; safe to share)`);
      return;
    }
    case 'validators': {
      const v = await fetchJson(`${rpc}/validators`);
      console.log(`${v.active} active validators, quorum ${v.quorum}, minimum stake ${v.minStake}`);
      for (const x of v.validators) console.log(`${x.address}  ${x.status.padEnd(9)} ${x.genesis ? 'genesis' : x.stakeFormatted}${x.missedInARow ? `  missed ${x.missedInARow} in a row` : ''}`);
      if (v.banned.length) console.log(`banned for double-signing: ${v.banned.join(', ')}`);
      return;
    }
    case 'stake': {
      const sub = positionals[0];
      if (sub === 'accept') {
        if (!values.offer || !values['validator-key']) throw new Error('--offer and --validator-key are required');
        const offer = JSON.parse(fs.readFileSync(values.offer, 'utf8'));
        const vkey = await loadSigningKey(values['validator-key']);
        if (offer.type !== 'validator-join' || offer.validator !== vkey.publicKey) throw new Error('this offer is not for your validator key');
        const { coin } = await fetchJson(`${rpc}/status`);
        console.log(`accepting ${formatAmount(offer.amount, coin.decimals)} ${coin.symbol} of stake from ${addressFromPublicKey(offer.from)}; rewards go to ${offer.operator}`);
        const { hash } = await postTx(rpc, { ...offer, validatorSignature: sign(signingBytes(offer), vkey.privateKey) });
        console.log(`validator ${addressFromPublicKey(vkey.publicKey)} joins\nRun its node now: from the next block on it must sign.\ntx ${hash}`);
        return;
      }
      if (!values.key) throw new Error('--key (the owner account) is required');
      const { coin } = await fetchJson(`${rpc}/status`);
      if (sub === 'join') {
        if (!values['validator-key'] || !values.amount) throw new Error('--validator-key and --amount are required');
        const vkey = await loadSigningKey(values['validator-key']);
        const { hash } = await signAndSend(rpc, values.key, { type: 'validator-join', validator: vkey.publicKey, amount: parseAmount(values.amount, coin.decimals), extraSigners: { validatorSignature: vkey.privateKey } });
        console.log(`validator ${addressFromPublicKey(vkey.publicKey)} joins with ${values.amount} ${coin.symbol} staked\nRun its node with this validator key now: once the block is final it must sign blocks, or it gets jailed.\ntx ${hash}`);
        return;
      }
      if (sub === 'delegate') {
        if (!values['validator-pubkey'] || !values.operator || !values.amount || !values.out) throw new Error('--validator-pubkey, --operator, --amount and --out are required');
        const { publicKey: validator } = readKeyFile(values['validator-pubkey']);
        const genesis = await fetchJson(`${rpc}/genesis`);
        const key = await loadSigningKey(values.key);
        const account = await fetchJson(`${rpc}/accounts/${addressFromPublicKey(key.publicKey)}`);
        const tx = createTx({ type: 'validator-join', chainId: genesis.chainId, validator, operator: values.operator, amount: parseAmount(values.amount, coin.decimals), fee: BigInt(genesis.minFee), nonce: account.pendingNonce }, { privateKey: key.privateKey });
        if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists`);
        fs.writeFileSync(values.out, `${JSON.stringify(tx, null, 2)}\n`);
        console.log(`wrote ${values.out}: ${values.amount} ${coin.symbol} of stake for validator ${addressFromPublicKey(validator)}, run and earned by ${values.operator}\nSend it to the operator; they finish with: argeni stake accept --offer ${values.out} --validator-key <their validator key>`);
        return;
      }
      if (!['add', 'leave', 'unjail'].includes(sub)) throw new Error('use: stake join | delegate | accept | add | leave | unjail');
      if (!values.validator) throw new Error('--validator <address> is required');
      const validator = await validatorKeyByAddress(rpc, values.validator);
      const type = { add: 'validator-bond', leave: 'validator-leave', unjail: 'validator-unjail' }[sub];
      const { hash } = await signAndSend(rpc, values.key, { type, validator, ...(sub === 'add' ? { amount: parseAmount(values.amount ?? '', coin.decimals) } : {}) });
      console.log(`${type} sent for ${values.validator}\ntx ${hash}`);
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
