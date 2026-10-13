// Transactions: build, sign, hash and stateless validation.
//   transfer  move ARGENI from one account to an address (any key type)
//   pq-commit lock in, ahead of time, the post-quantum key an account will migrate to. It records only
//             a hash of the future address, so the new key stays private until the migration.
//   migrate   move a whole account to a different post-quantum key: Ed25519 -> post-quantum, or one
//             post-quantum key to another (e.g. ML-DSA -> SLH-DSA if lattice schemes are ever weakened,
//             or simply to rotate a key). Signed by BOTH keys, so it proves control of the old account
//             and possession of the new key; the old account is then locked for good. If the account
//             made a pq-commit, the new key must match it (see state.js migrationError).
//   vest      send ARGENI that unlocks month by month (team grants and other locked allocations)
//   validator-join / -bond / -leave / -unjail   staking: join the validator set, add stake, leave
//             (stake returns after unbonding), return after a downtime jail
//   evidence  two conflicting signed votes from one validator; it is slashed and banned
// Any of them can come from a multisig account ("msig:m:key,…", m of the keys sign).
import { canonical, hashObject, sha256, sign, verify, isAddress, isHex, isPublicKey, keyTypeOf, publicKeyFromPrivate, addressFromPublicKey, PQ_KEY_TYPES } from './crypto.js';
import { isUnits } from './coin.js';

export const MAX_MEMO_LENGTH = 256;
export const MAX_VESTING_MONTHS = 120;
const ENVELOPE = ['type', 'chainId', 'from', 'fee', 'nonce', 'signature'];
const FIELDS = {
  transfer: [...ENVELOPE, 'to', 'amount', 'memo'],
  migrate: [...ENVELOPE, 'to', 'pqSignature'],
  'pq-commit': [...ENVELOPE, 'commitment'],
  // Sends `amount` that unlocks over time: nothing for lockMonths, then in equal monthly steps over
  // vestMonths (atStart is free right away). Used for team grants and other locked allocations.
  vest: [...ENVELOPE, 'to', 'amount', 'atStart', 'lockMonths', 'vestMonths', 'memo'],
  // Staking: an owner account bonds ARGENI to a consensus key, which then joins the validator set.
  // Signed by the owner AND the validator key (proves the operator holds it).
  'validator-join': [...ENVELOPE, 'validator', 'amount', 'validatorSignature'],
  'validator-bond': [...ENVELOPE, 'validator', 'amount'],
  'validator-leave': [...ENVELOPE, 'validator'],
  'validator-unjail': [...ENVELOPE, 'validator'],
  // Proof that a validator signed two different blocks for the same height and round.
  evidence: [...ENVELOPE, 'voteA', 'voteB'],
};
export const TX_TYPES = Object.keys(FIELDS);
const VOTE_FIELDS = ['type', 'height', 'round', 'blockHash', 'validRound', 'validator', 'signature'];

// The hash an account commits to: binds the chain, the old address and the new post-quantum address.
export function migrationCommitment(chainId, fromAddress, toAddress) {
  return sha256(`argeni-pq-commit:v1|${chainId}|${fromAddress}|${toAddress}`);
}

export function txBody(tx) {
  const { signature, pqSignature, validatorSignature, ...body } = tx;
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

// Builds and signs any transaction type. `privateKey` signs as `from`; for a multisig `from`, pass
// `from` and `signature` (collected with signMultisigPart / combineMultisig) instead.
export function createTx(fields, { privateKey, extraSigners = {} } = {}) {
  const body = { ...fields };
  if (!body.from) body.from = publicKeyFromPrivate(privateKey);
  for (const k of ['fee', 'amount', 'atStart']) if (body[k] !== undefined) body[k] = body[k].toString();
  const bytes = canonical(body);
  const tx = { ...body, ...(privateKey ? { signature: sign(bytes, privateKey) } : {}) };
  for (const [field, key] of Object.entries(extraSigners)) tx[field] = sign(bytes, key);
  return tx;
}

// The bytes every signer of a transaction signs (also each member of a multisig).
export function signingBytes(tx) {
  return canonical(txBody(tx));
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

const isNonce = (n) => Number.isSafeInteger(n) && n >= 0;
const positive = (v) => isUnits(v) && BigInt(v) > 0n;
const isSingleKey = (k) => isPublicKey(k) && keyTypeOf(k) !== 'multisig';

// A signed consensus message as carried in evidence.
function voteError(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return 'vote must be an object';
  if (Object.keys(v).some((k) => !VOTE_FIELDS.includes(k))) return 'vote has unknown fields';
  if (!['proposal', 'prevote', 'precommit'].includes(v.type)) return 'bad vote type';
  if (!Number.isSafeInteger(v.height) || v.height < 1 || !Number.isSafeInteger(v.round) || v.round < 0) return 'bad vote height or round';
  if (!isHex(v.blockHash, 32)) return 'vote must be for a block';
  if (!isSingleKey(v.validator)) return 'bad vote validator';
  return null;
}

// Checks everything that does not depend on account state. Returns an error string or null.
// `voteBytes(vote)` gives the bytes a validator signs for a vote (from chain.js), for evidence.
export function checkTx(tx, { chainId, minFee }, { voteBytes } = {}) {
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return 'transaction must be an object';
  const fields = Object.hasOwn(FIELDS, tx.type) ? FIELDS[tx.type] : null;
  if (!fields) return 'unsupported transaction type';
  const extra = Object.keys(tx).filter((k) => !fields.includes(k));
  if (extra.length) return `unknown fields: ${extra.join(', ')}`;
  if (tx.chainId !== chainId) return `wrong chainId (expected ${chainId})`;
  if (!isPublicKey(tx.from)) return 'from must be a public key';
  if (!isUnits(tx.fee)) return 'fee must be a base-unit integer string';
  if (BigInt(tx.fee) < BigInt(minFee)) return `fee below minimum (${minFee})`;
  if (!isNonce(tx.nonce)) return 'nonce must be a non-negative integer';
  if (tx.memo !== undefined && (typeof tx.memo !== 'string' || tx.memo.length > MAX_MEMO_LENGTH)) {
    return `memo must be a string of at most ${MAX_MEMO_LENGTH} characters`;
  }
  const bytes = canonical(txBody(tx));
  switch (tx.type) {
    case 'transfer':
      if (!isAddress(tx.to)) return 'to must be an Argeni address';
      if (!positive(tx.amount)) return 'amount must be a positive base-unit integer string';
      break;
    case 'pq-commit':
      if (!isHex(tx.commitment, 32)) return 'commitment must be a 32-byte hex hash';
      break;
    case 'migrate':
      if (!PQ_KEY_TYPES.includes(keyTypeOf(tx.to)) || !isPublicKey(tx.to)) return `migration target must be a post-quantum public key (${PQ_KEY_TYPES.join(', ')})`;
      if (tx.to === tx.from) return 'migration target must be a different key';
      if (!verify(bytes, tx.signature, tx.from)) return 'invalid signature';
      if (!verify(bytes, tx.pqSignature, tx.to)) return 'invalid post-quantum signature';
      break;
    case 'vest':
      if (!isAddress(tx.to)) return 'to must be an Argeni address';
      if (!positive(tx.amount)) return 'amount must be a positive base-unit integer string';
      if (tx.atStart !== undefined && (!isUnits(tx.atStart) || BigInt(tx.atStart) > BigInt(tx.amount))) return 'atStart must be at most amount';
      if (!Number.isSafeInteger(tx.lockMonths) || tx.lockMonths < 0 || tx.lockMonths > MAX_VESTING_MONTHS) return `lockMonths must be 0-${MAX_VESTING_MONTHS}`;
      if (!Number.isSafeInteger(tx.vestMonths) || tx.vestMonths < 0 || tx.vestMonths > MAX_VESTING_MONTHS) return `vestMonths must be 0-${MAX_VESTING_MONTHS}`;
      if (tx.lockMonths + tx.vestMonths === 0) return 'a vesting grant must lock for at least one month';
      break;
    case 'validator-join':
      if (!PQ_KEY_TYPES.includes(keyTypeOf(tx.validator)) || !isPublicKey(tx.validator)) return 'validator must be a post-quantum public key';
      if (!positive(tx.amount)) return 'amount must be a positive base-unit integer string';
      if (!verify(bytes, tx.validatorSignature, tx.validator)) return 'invalid validator signature (the validator key must sign too)';
      break;
    case 'validator-bond':
      if (!positive(tx.amount)) return 'amount must be a positive base-unit integer string';
    // falls through
    case 'validator-leave':
    case 'validator-unjail':
      if (!isSingleKey(tx.validator)) return 'validator must be a public key';
      break;
    case 'evidence': {
      const error = voteError(tx.voteA) ?? voteError(tx.voteB);
      if (error) return `evidence: ${error}`;
      const a = tx.voteA;
      const b = tx.voteB;
      if (a.validator !== b.validator || a.type !== b.type || a.height !== b.height || a.round !== b.round) return 'evidence votes must be from one validator for the same step';
      if (a.blockHash === b.blockHash) return 'evidence votes must be for different blocks';
      if (!voteBytes) return 'evidence cannot be checked here';
      if (!verify(voteBytes(a), a.signature, a.validator) || !verify(voteBytes(b), b.signature, b.validator)) return 'evidence has an invalid vote signature';
      break;
    }
    default:
      return 'unsupported transaction type';
  }
  if (!verify(bytes, tx.signature, tx.from)) return 'invalid signature';
  return null;
}
