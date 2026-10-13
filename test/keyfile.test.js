// Passphrase-encrypted key files (vaults): round trip, wrong passphrase, tampering, and the CLI.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { addressFromPublicKey, generateKeyPair, sign, verify } from '../src/crypto.js';
import { encryptKeyFile, decryptKeyFile, isEncrypted } from '../src/keyfile.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.js');
const PASS = 'correct horse battery staple';
const plainFile = (type) => { const k = generateKeyPair(type); return { address: addressFromPublicKey(k.publicKey), ...k }; };

test('an encrypted vault key opens only with its passphrase and signs normally', () => {
  const plain = plainFile('slh-dsa-256s');
  const enc = encryptKeyFile(plain, PASS);
  assert.equal(isEncrypted(enc), true);
  assert.equal(enc.privateKey, undefined, 'no private key in the clear');
  assert.equal(JSON.stringify(enc).includes(plain.privateKey.slice(20, 80)), false);
  const back = decryptKeyFile(enc, PASS);
  assert.equal(back.privateKey, plain.privateKey);
  assert.equal(verify('vault', sign('vault', back.privateKey), plain.publicKey), true);
  assert.throws(() => decryptKeyFile(enc, 'correct horse battery stapler'), /wrong passphrase/);
});

test('editing an encrypted key file (address or ciphertext) makes it fail', () => {
  const enc = encryptKeyFile(plainFile('ml-dsa-87'), PASS);
  const other = plainFile('ml-dsa-87');
  assert.throws(() => decryptKeyFile({ ...enc, address: other.address }, PASS), /wrong passphrase|changed/);
  const flipped = structuredClone(enc);
  flipped.encrypted.ciphertext = (flipped.encrypted.ciphertext[0] === 'a' ? 'b' : 'a') + flipped.encrypted.ciphertext.slice(1);
  assert.throws(() => decryptKeyFile(flipped, PASS), /wrong passphrase|changed/);
  assert.throws(() => encryptKeyFile(plainFile('ml-dsa-87'), 'short'), /at least 12/);
});

test('CLI: keygen --encrypt, check-key, encrypt an existing key, and refuse a bad passphrase', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argeni-vault-'));
  try {
    const run = (args, input) => spawnSync(process.execPath, [CLI, ...args], { input, encoding: 'utf8' });
    const vault = path.join(dir, 'vault.json');
    let r = run(['keygen', '--out', vault, '--type', 'slh-dsa-256s', '--encrypt'], `${PASS}\n${PASS}\n`);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /slh-dsa-256s, post-quantum, encrypted/);
    assert.equal(isEncrypted(JSON.parse(fs.readFileSync(vault, 'utf8'))), true);
    assert.equal((fs.statSync(vault).mode & 0o777).toString(8), '600');

    r = run(['check-key', '--key', vault], `${PASS}\n`);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /OK: .* opens and controls ag[0-9a-f]{64} \(slh-dsa-256s, encrypted\)/);
    r = run(['check-key', '--key', vault], 'not the passphrase!\n');
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /wrong passphrase/);

    r = run(['keygen', '--out', path.join(dir, 'x.json'), '--encrypt'], `${PASS}\nsomething different\n`);
    assert.match(r.stderr, /different/);
    assert.equal(fs.existsSync(path.join(dir, 'x.json')), false, 'nothing written on a mismatch');

    const plain = path.join(dir, 'plain.json');
    run(['keygen', '--out', plain], '');
    r = run(['encrypt', '--key', plain, '--out', path.join(dir, 'plain.enc.json')], `${PASS}\n${PASS}\n`);
    assert.equal(r.status, 0, r.stderr);
    r = run(['check-key', '--key', path.join(dir, 'plain.enc.json')], `${PASS}\n`);
    assert.match(r.stdout, /ml-dsa-87, encrypted/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
