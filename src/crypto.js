// Hashing, signature keys (Ed25519 and the NIST post-quantum ML-DSA and SLH-DSA families) and
// addresses. Uses only node:crypto.
import crypto from 'node:crypto';

// DER prefixes that wrap a raw 32-byte Ed25519 key so node:crypto accepts it.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export const ADDRESS_PREFIX = 'ag';

// Deterministic JSON: object keys sorted, so the same data always hashes the same.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function hashObject(obj) {
  return sha256(canonical(obj));
}

// Key types. Keys are passed around as strings: Ed25519 public keys as 64 hex characters (raw 32
// bytes, private: the raw 32-byte seed); post-quantum keys as "<label>:" + hex of the SPKI / PKCS#8 DER.
//
//   ml-dsa-87     FIPS 204, lattice-based, NIST category 5 (highest). The default for new keys.
//   ml-dsa-65     FIPS 204, lattice-based, category 3. Smaller and still strong.
//   slh-dsa-256s  FIPS 205, hash-based, category 5. Security rests only on SHA-256, a different
//                 family of mathematics from the lattices, so it is the fallback if lattice schemes
//                 are ever weakened. Large signatures (29,792 bytes, ~0.4 s to sign): savings and
//                 cold-storage accounts, treasuries.
//   slh-dsa-128s  FIPS 205, hash-based, category 1. Smaller hash-based option (7,856-byte signatures).
//   ed25519       RFC 8032, classical. Kept so older accounts work; can be retired and migrated away.
export const KEY_TYPES = ['ml-dsa-87', 'ml-dsa-65', 'slh-dsa-256s', 'slh-dsa-128s', 'ed25519'];
export const PQ_KEY_TYPES = ['ml-dsa-87', 'ml-dsa-65', 'slh-dsa-256s', 'slh-dsa-128s'];
export const DEFAULT_KEY_TYPE = 'ml-dsa-87';
const PQ = {
  'ml-dsa-87': { prefix: 'mldsa87:', node: 'ml-dsa-87', sigBytes: 4627 },
  'ml-dsa-65': { prefix: 'mldsa65:', node: 'ml-dsa-65', sigBytes: 3309 },
  'slh-dsa-256s': { prefix: 'slhdsa256s:', node: 'slh-dsa-sha2-256s', sigBytes: 29792 },
  'slh-dsa-128s': { prefix: 'slhdsa128s:', node: 'slh-dsa-sha2-128s', sigBytes: 7856 },
};
// What each key type is, for explorers, wallets and documentation.
export const KEY_INFO = {
  'ml-dsa-87': { standard: 'FIPS 204', family: 'lattice', category: 5, postQuantum: true },
  'ml-dsa-65': { standard: 'FIPS 204', family: 'lattice', category: 3, postQuantum: true },
  'slh-dsa-256s': { standard: 'FIPS 205', family: 'hash', category: 5, postQuantum: true },
  'slh-dsa-128s': { standard: 'FIPS 205', family: 'hash', category: 1, postQuantum: true },
  ed25519: { standard: 'RFC 8032', family: 'elliptic curve', category: 0, postQuantum: false },
};

function pqSpec(key) {
  return Object.entries(PQ).find(([, spec]) => key.startsWith(spec.prefix));
}

export function keyTypeOf(key) {
  if (typeof key !== 'string') return null;
  if (key.startsWith(MULTISIG_PREFIX)) return 'multisig';
  const pq = pqSpec(key);
  if (pq) return pq[0];
  return isHex(key, 32) ? 'ed25519' : null;
}

export function isPublicKey(value) {
  const type = keyTypeOf(value);
  if (type === 'ed25519') return true;
  if (type === 'multisig') return parseMultisig(value) !== null;
  if (!PQ[type]) return false;
  const hex = value.slice(PQ[type].prefix.length);
  return hex.length > 0 && hex.length <= 6000 && /^[0-9a-f]+$/.test(hex) && hex.length % 2 === 0;
}

export function generateKeyPair(type = 'ed25519') {
  if (PQ[type]) {
    const { prefix, node } = PQ[type];
    const { publicKey, privateKey } = crypto.generateKeyPairSync(node);
    return {
      type,
      publicKey: prefix + publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
      privateKey: prefix + privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
    };
  }
  if (type !== 'ed25519') throw new Error(`unknown key type "${type}" (use ${KEY_TYPES.join(', ')})`);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    type,
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length).toString('hex'),
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(PKCS8_PREFIX.length).toString('hex'),
  };
}

function privateKeyObject(privateKey) {
  const pq = pqSpec(privateKey);
  if (pq) {
    return crypto.createPrivateKey({ key: Buffer.from(privateKey.slice(pq[1].prefix.length), 'hex'), format: 'der', type: 'pkcs8' });
  }
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(privateKey, 'hex')]), format: 'der', type: 'pkcs8' });
}

export function publicKeyFromPrivate(privateKey) {
  const spki = crypto.createPublicKey(privateKeyObject(privateKey)).export({ format: 'der', type: 'spki' });
  const pq = pqSpec(privateKey);
  return pq ? pq[1].prefix + spki.toString('hex') : spki.subarray(SPKI_PREFIX.length).toString('hex');
}

export function sign(message, privateKey) {
  return crypto.sign(null, Buffer.from(message), privateKeyObject(privateKey)).toString('hex');
}

export function verify(message, signatureHex, publicKey) {
  const type = keyTypeOf(publicKey);
  if (type === 'multisig') return verifyMultisig(message, signatureHex, publicKey);
  try {
    if (type === 'ed25519') {
      if (!isHex(signatureHex, 64)) return false;
      const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey, 'hex')]), format: 'der', type: 'spki' });
      return crypto.verify(null, Buffer.from(message), key, Buffer.from(signatureHex, 'hex'));
    }
    if (PQ[type] && isPublicKey(publicKey)) {
      const { prefix, node, sigBytes } = PQ[type];
      if (!isHex(signatureHex, sigBytes)) return false;
      const key = crypto.createPublicKey({ key: Buffer.from(publicKey.slice(prefix.length), 'hex'), format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== node) return false;
      return crypto.verify(null, Buffer.from(message), key, Buffer.from(signatureHex, 'hex'));
    }
  } catch {
    // malformed key or signature
  }
  return false;
}

// Address = "ag" + all 32 bytes of sha256 of the public key (64 hex characters). A full 256-bit hash
// keeps 128-bit security even against Grover's quantum search for a key matching an address.
// Ed25519: sha256(raw 32-byte key). Post-quantum: sha256(type label || SPKI DER), e.g. "mldsa87:",
// so addresses of different key types never collide.
export const ADDRESS_HEX_LENGTH = 64;
export function addressFromPublicKey(publicKey) {
  if (keyTypeOf(publicKey) === 'multisig') return ADDRESS_PREFIX + sha256(Buffer.from(publicKey, 'utf8'));
  const pq = pqSpec(publicKey);
  const bytes = pq
    ? Buffer.concat([Buffer.from(pq[1].prefix), Buffer.from(publicKey.slice(pq[1].prefix.length), 'hex')])
    : Buffer.from(publicKey, 'hex');
  return ADDRESS_PREFIX + sha256(bytes);
}

export function isAddress(value) {
  return typeof value === 'string' && value.startsWith(ADDRESS_PREFIX) && isHex(value.slice(ADDRESS_PREFIX.length), 32);
}

export function isHex(value, bytes) {
  return typeof value === 'string' && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
}

// Binary Merkle root over hex leaf hashes; odd leaf is carried up by hashing it with itself.
export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256('');
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(sha256(level[i] + (level[i + 1] ?? level[i])));
    }
    level = next;
  }
  return level[0];
}

// ---- Multi-signature accounts ----
// A multisig "public key" is "msig:<m>:<key1>,<key2>,…": any m of the listed post-quantum keys must
// sign. Its address is "ag" + sha256 of that whole string, so it never collides with a single key's
// address. A multisig signature is "<i>:<hex>,<j>:<hex>,…", where i is the signer's position in the
// list. Used for treasuries and founder vaults ("2 of 3 must sign"), so one lost or stolen key is
// not enough to move funds.
export const MULTISIG_PREFIX = 'msig:';
export const MAX_MULTISIG_KEYS = 10;

// Returns { threshold, keys } or null if the string is not a well-formed multisig key.
export function parseMultisig(value) {
  if (typeof value !== 'string' || !value.startsWith(MULTISIG_PREFIX) || value.length > 80_000) return null;
  const match = /^msig:([1-9]\d?):(.+)$/.exec(value);
  if (!match) return null;
  const threshold = Number(match[1]);
  const keys = match[2].split(',');
  if (keys.length < 2 || keys.length > MAX_MULTISIG_KEYS || threshold > keys.length) return null;
  if (!keys.every((k) => PQ_KEY_TYPES.includes(keyTypeOf(k)) && isPublicKey(k))) return null;
  for (let i = 1; i < keys.length; i++) if (!(keys[i - 1] < keys[i])) return null; // sorted, no duplicates
  return { threshold, keys };
}

// Builds the canonical multisig key: keys sorted and de-duplicated.
export function multisigKey(threshold, publicKeys) {
  const keys = [...new Set(publicKeys)].sort();
  const key = `${MULTISIG_PREFIX}${threshold}:${keys.join(',')}`;
  if (!parseMultisig(key)) throw new Error(`a multisig needs 2-${MAX_MULTISIG_KEYS} different post-quantum keys and a threshold from 1 to their number`);
  return key;
}

// The key types inside a key: one for a single key, the member types for a multisig.
export function memberKeyTypes(publicKey) {
  const ms = parseMultisig(publicKey);
  return ms ? [...new Set(ms.keys.map(keyTypeOf))] : [keyTypeOf(publicKey)];
}

// One member's signature part, "<index>:<hex>". Members sign the same bytes independently, offline.
export function signMultisigPart(message, msig, privateKey) {
  const ms = parseMultisig(msig);
  if (!ms) throw new Error('not a multisig key');
  const index = ms.keys.indexOf(publicKeyFromPrivate(privateKey));
  if (index < 0) throw new Error('this key is not a member of the multisig');
  return `${index}:${sign(message, privateKey)}`;
}

// Joins signature parts into one multisig signature (sorted by index, duplicates dropped).
export function combineMultisig(parts) {
  const byIndex = new Map();
  for (const part of parts.flatMap((p) => p.split(',')).filter(Boolean)) byIndex.set(Number(part.split(':')[0]), part);
  return [...byIndex.keys()].sort((a, b) => a - b).map((i) => byIndex.get(i)).join(',');
}

function verifyMultisig(message, signature, publicKey) {
  const ms = parseMultisig(publicKey);
  if (!ms || typeof signature !== 'string' || signature.length > 400_000) return false;
  const parts = signature.split(',');
  if (parts.length < ms.threshold || parts.length > ms.keys.length) return false;
  const seen = new Set();
  for (const part of parts) {
    const match = /^(\d{1,2}):([0-9a-f]+)$/.exec(part);
    if (!match) return false;
    const index = Number(match[1]);
    if (index >= ms.keys.length || seen.has(index)) return false;
    if (!verify(message, match[2], ms.keys[index])) return false;
    seen.add(index);
  }
  return seen.size >= ms.threshold;
}
