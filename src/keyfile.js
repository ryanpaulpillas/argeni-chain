// Key files on disk, optionally encrypted with a passphrase (for vaults, treasuries and founder keys).
//
// Plain:     { address, type, publicKey, privateKey }
// Encrypted: { address, type, publicKey, encrypted: { version, kdf: "scrypt", N, r, p, salt,
//              cipher: "aes-256-gcm", iv, tag, ciphertext } }
//
// The private key is encrypted with AES-256-GCM under a key derived from the passphrase with scrypt
// (memory-hard, so guessing passphrases is slow and expensive). The address, type and public key are
// authenticated as associated data, so editing them makes decryption fail. AES-256 keeps a 128-bit
// margin even against Grover's quantum search.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { addressFromPublicKey, publicKeyFromPrivate } from './crypto.js';

const SCRYPT = { N: 2 ** 17, r: 8, p: 1 };
const MIN_PASSPHRASE = 12;

const aad = (file) => Buffer.from(JSON.stringify([file.address, file.type, file.publicKey]));
const kdf = (passphrase, salt, { N, r, p }) => crypto.scryptSync(passphrase.normalize('NFKC'), salt, 32, { N, r, p, maxmem: 256 * 1024 * 1024 });

export function encryptKeyFile(file, passphrase) {
  if (!file.privateKey) throw new Error('key file is already encrypted');
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const { privateKey, ...pub } = file;
  const cipher = crypto.createCipheriv('aes-256-gcm', kdf(passphrase, salt, SCRYPT), iv);
  cipher.setAAD(aad(pub));
  const ciphertext = Buffer.concat([cipher.update(privateKey, 'utf8'), cipher.final()]);
  return {
    ...pub,
    encrypted: {
      version: 1, kdf: 'scrypt', ...SCRYPT, salt: salt.toString('hex'),
      cipher: 'aes-256-gcm', iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: ciphertext.toString('hex'),
    },
  };
}

// Returns the plain key file. Throws on a wrong passphrase or any tampering.
export function decryptKeyFile(file, passphrase) {
  if (file.privateKey) return file;
  const e = file.encrypted;
  if (!e || e.version !== 1 || e.kdf !== 'scrypt' || e.cipher !== 'aes-256-gcm') throw new Error('unsupported key file format');
  let privateKey;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', kdf(passphrase, Buffer.from(e.salt, 'hex'), e), Buffer.from(e.iv, 'hex'));
    decipher.setAAD(aad(file));
    decipher.setAuthTag(Buffer.from(e.tag, 'hex'));
    privateKey = Buffer.concat([decipher.update(Buffer.from(e.ciphertext, 'hex')), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('wrong passphrase (or the key file was changed)');
  }
  if (publicKeyFromPrivate(privateKey) !== file.publicKey || addressFromPublicKey(file.publicKey) !== file.address) {
    throw new Error('key file is inconsistent: the decrypted key does not match its address');
  }
  const { encrypted, ...pub } = file;
  return { ...pub, privateKey };
}

export const isEncrypted = (file) => !file.privateKey && !!file.encrypted;

export function writeKeyFile(file, keys) {
  if (fs.existsSync(file)) throw new Error(`${file} already exists; refusing to overwrite a key`);
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const content = keys.address ? keys : { address: addressFromPublicKey(keys.publicKey), ...keys };
  if (!content.type) content.type = 'ed25519';
  fs.writeFileSync(file, `${JSON.stringify(content, null, 2)}\n`, { mode: 0o600 });
  return content;
}

export function readKeyFile(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// Reads a passphrase: hidden typing on a terminal, or one line from standard input when piped.
let pipedLines = null;
export async function askPassphrase(question) {
  if (!process.stdin.isTTY) {
    if (!pipedLines) {
      const chunks = [];
      for await (const chunk of process.stdin) chunks.push(chunk);
      pipedLines = Buffer.concat(chunks).toString('utf8').split(/\r?\n/);
    }
    if (!pipedLines.length) throw new Error('no passphrase on standard input');
    return pipedLines.shift();
  }
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const write = rl._writeToOutput.bind(rl);
  rl._writeToOutput = (s) => write(s.includes(question) ? s : s.replace(/[^\r\n]/g, '*'));
  return new Promise((resolve) => rl.question(question, (answer) => { rl.close(); process.stdout.write('\n'); resolve(answer); }));
}

// A key file ready to sign with: plain files as they are, encrypted ones after asking for the passphrase.
export async function loadSigningKey(file) {
  const keys = readKeyFile(file);
  if (!isEncrypted(keys)) return keys;
  return decryptKeyFile(keys, await askPassphrase(`Passphrase for ${path.basename(file)}: `));
}

export async function choosePassphrase() {
  const first = await askPassphrase(`New passphrase (at least ${MIN_PASSPHRASE} characters): `);
  if (first.length < MIN_PASSPHRASE) throw new Error(`passphrase must be at least ${MIN_PASSPHRASE} characters`);
  const second = await askPassphrase('Repeat the passphrase: ');
  if (first !== second) throw new Error('the two passphrases are different');
  return first;
}
