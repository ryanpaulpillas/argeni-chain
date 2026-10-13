// Transactions: build, sign, hash and stateless validation.
//   transfer  move ARGENI from one account to an address (any key type)
//   pq-commit lock in, ahead of time, the post-quantum key an account will migrate to. It records only
//             a hash of the future address, so the new key stays private until the migration.
//   migrate   move a whole account to a different post-quantum key: Ed25519 -> post-quantum, or one
//             post-quantum key to another (e.g. ML-DSA -> SLH-DSA if lattice schemes are ever weakened,
//             or simply to rotate a key). Signed by BOTH keys, so it proves control of the old account
//             and possession of the new key; the old account is then locked for good. If the account
//             made a pq-commit, the new key must match it (see state.js migrationError).
import { canonical, hashObject, sha256, sign, verify, isAddress, isHex, isPublicKey, keyTypeOf, publicKeyFromPrivate, addressFromPublicKey, PQ_KEY_TYPES } from './crypto.js';
import { isUnits } from './coin.js';

export const MAX_MEMO_LENGTH = 256;
const TRANSFER_FIELDS = ['type', 'chainId', 'from', 'to', 'amount', 'fee', 'nonce', 'memo', 'signature'];
const MIGRATE_FIELDS = ['type', 'chainId', 'from', 'to', 'fee', 'nonce', 'signature', 'pqSignature'];
const COMMIT_FIELDS = ['type', 'chainId', 'from', 'commitment', 'fee', 'nonce', 'signature'];
const FIELDS = { transfer: TRANSFER_FIELDS, migrate: MIGRATE_FIELDS, 'pq-commit': COMMIT_FIELDS };

// The hash an account commits to: binds the chain, the old address and the new post-quantum address.
export function migrationCommitment(chainId, fromAddress, toAddress) {
  return sha256(`argeni-pq-commit:v1|${chainId}|${fromAddress}|${toAddress}`);
}

export function txBody(tx) {
  const { signature, pqSignature, ...body } = tx;
  return body;
}

export function txHash(tx) {
  return hashObject(tx);
}

export function createTransfer({ chainId, privateKey, to, amount, fee, nonce, memo }) {
  const body = {
    type: 'transfer',
    chainId,
    from: publicKeyFromPrivate(privateKey),
    to,
    amount: amount.toString(),
    fee: fee.toString(),
    nonce,
    ...(memo ? { memo } : {}),
  };
  return { ...body, signature: sign(canonical(body), privateKey) };
}

export function createMigration({ chainId, privateKey, pqPrivateKey, fee, nonce }) {
  const body = {
    type: 'migrate',
    chainId,
    from: publicKeyFromPrivate(privateKey),
    to: publicKeyFromPrivate(pqPrivateKey),
    fee: fee.toString(),
    nonce,
  };
  const bytes = canonical(body);
  return { ...body, signature: sign(bytes, privateKey), pqSignature: sign(bytes, pqPrivateKey) };
}

export function createMigrationCommit({ chainId, privateKey, pqPublicKey, fee, nonce }) {
  const from = publicKeyFromPrivate(privateKey);
  const body = {
    type: 'pq-commit',
    chainId,
    from,
    commitment: migrationCommitment(chainId, addressFromPublicKey(from), addressFromPublicKey(pqPublicKey)),
    fee: fee.toString(),
    nonce,
  };
  return { ...body, signature: sign(canonical(body), privateKey) };
}

// Checks everything that does not depend on account state. Returns an error string or null.
export function checkTx(tx, { chainId, minFee }) {
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return 'transaction must be an object';
  const fields = Object.hasOwn(FIELDS, tx.type) ? FIELDS[tx.type] : null;
  if (!fields) return 'unsupported transaction type';
  const extra = Object.keys(tx).filter((k) => !fields.includes(k));
  if (extra.length) return `unknown fields: ${extra.join(', ')}`;
  if (tx.chainId !== chainId) return `wrong chainId (expected ${chainId})`;
  if (!isPublicKey(tx.from)) return 'from must be a public key';
  if (tx.type === 'pq-commit') {
    if (!isHex(tx.commitment, 32)) return 'commitment must be a 32-byte hex hash';
    if (!isUnits(tx.fee) || BigInt(tx.fee) < BigInt(minFee)) return `fee must be at least the minimum (${minFee})`;
    if (!Number.isSafeInteger(tx.nonce) || tx.nonce < 0) return 'nonce must be a non-negative integer';
    if (!verify(canonical(txBody(tx)), tx.signature, tx.from)) return 'invalid signature';
    return null;
  }
  if (tx.type === 'migrate') {
    if (!PQ_KEY_TYPES.includes(keyTypeOf(tx.to)) || !isPublicKey(tx.to)) return `migration target must be a post-quantum public key (${PQ_KEY_TYPES.join(', ')})`;
    if (tx.to === tx.from) return 'migration target must be a different key';
    if (!isUnits(tx.fee) || BigInt(tx.fee) < BigInt(minFee)) return `fee must be at least the minimum (${minFee})`;
    if (!Number.isSafeInteger(tx.nonce) || tx.nonce < 0) return 'nonce must be a non-negative integer';
    const bytes = canonical(txBody(tx));
    if (!verify(bytes, tx.signature, tx.from)) return 'invalid signature';
    if (!verify(bytes, tx.pqSignature, tx.to)) return 'invalid post-quantum signature';
    return null;
  }
  if (!isAddress(tx.to)) return 'to must be an Argeni address';
  if (!isUnits(tx.amount) || BigInt(tx.amount) <= 0n) return 'amount must be a positive base-unit integer string';
  if (!isUnits(tx.fee)) return 'fee must be a base-unit integer string';
  if (BigInt(tx.fee) < BigInt(minFee)) return `fee below minimum (${minFee})`;
  if (!Number.isSafeInteger(tx.nonce) || tx.nonce < 0) return 'nonce must be a non-negative integer';
  if (tx.memo !== undefined && (typeof tx.memo !== 'string' || tx.memo.length > MAX_MEMO_LENGTH)) {
    return `memo must be a string of at most ${MAX_MEMO_LENGTH} characters`;
  }
  if (!verify(canonical(txBody(tx)), tx.signature, tx.from)) return 'invalid signature';
  return null;
}
