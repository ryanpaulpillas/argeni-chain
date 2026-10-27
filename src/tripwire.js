// Q-Day Tripwire: the chain watches for proof that classical public-key cryptography has been broken
// and defends itself when it happens.
//
// The ladder is a set of bait keys ("rungs") of rising strength. Nobody holds their private keys:
//   - each elliptic-curve rung is a point found by hashing a public seed onto the curve (try-and-
//     increment). Finding its private key means solving a discrete logarithm nobody was ever given;
//   - the RSA rung is the RSA-2048 Challenge number, published by RSA Laboratories in 1991, whose
//     factors were never known to anyone.
// So a claim cannot come from a leaked or stolen key: only from breaking the mathematics.
//
// Every rung carries a bounty from genesis. A claim is two transactions: canary-commit (a hash of the
// solution bound to the claimer's address) and, at least revealDelayBlocks later, canary-reveal with
// the solution. The chain checks it (d·G = P, or p·q = N), pays the bounty and raises its alert level.
// The commit stops anyone copying a solution they see in the mempool.
//
// Alert levels, set by the strongest rung broken:
//   1 watch    ECC-160 or ECC-192 broken: recorded on chain for wallets and explorers; no rule change.
//   2 prepare  ECC-224 broken: the Ed25519 sunset is brought forward to graceBlocks from now.
//   3 sunset   a 256-bit curve or RSA-2048 broken (Ed25519's strength): Ed25519 is retired from the
//              next block. Classical accounts can then only migrate, under the usual post-sunset rules
//              (to the key they committed to with pq-commit, or if their key was never exposed).
// Retirements take effect from the block after the reveal, so a block's rules never change halfway.
import crypto from 'node:crypto';
import { sha256 } from './crypto.js';

export const TRIPWIRE_SEED = 'ARGENI Q-Day Tripwire v1';
const ED25519_LEVEL3 = 3;

// SEC 2 / FIPS 186 curve parameters (all have cofactor 1, so every curve point is in the prime-order group).
export const CURVES = {
  'ecc-160': {
    name: 'secp160r1', bits: 160, level: 1,
    p: 0xffffffffffffffffffffffffffffffff7fffffffn,
    a: 0xffffffffffffffffffffffffffffffff7ffffffcn,
    b: 0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45n,
    gx: 0x4a96b5688ef573284664698968c38bb913cbfc82n,
    gy: 0x23a628553168947d59dcc912042351377ac5fb32n,
    n: 0x0100000000000000000001f4c8f927aed3ca752257n,
  },
  'ecc-192': {
    name: 'P-192 (secp192r1)', bits: 192, level: 1,
    p: 0xfffffffffffffffffffffffffffffffeffffffffffffffffn,
    a: 0xfffffffffffffffffffffffffffffffefffffffffffffffcn,
    b: 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1n,
    gx: 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012n,
    gy: 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811n,
    n: 0xffffffffffffffffffffffff99def836146bc9b1b4d22831n,
  },
  'ecc-224': {
    name: 'P-224 (secp224r1)', bits: 224, level: 2,
    p: 0xffffffffffffffffffffffffffffffff000000000000000000000001n,
    a: 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffen,
    b: 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4n,
    gx: 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21n,
    gy: 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34n,
    n: 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dn,
  },
  'ecc-256': {
    name: 'P-256 (secp256r1)', bits: 256, level: 3,
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
    n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  },
  secp256k1: {
    name: 'secp256k1 (Bitcoin, Ethereum)', bits: 256, level: 3,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    a: 0n,
    b: 7n,
    gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  },
};

// The RSA-2048 Challenge number (RSA Laboratories, 1991; 617 digits, factors never published).
export const RSA_2048 = BigInt(
  '25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784'
  + '40691829064124951508218929855914917618450280848912007284499268739280728777673597141834727026189637'
  + '50149718246911650776133798590957000973304597488084284017974291006424586918171951187461215151726546'
  + '32282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163'
  + '81501067481045166037730605620161967625613384414360383390441495263443219011465754445417842402092461'
  + '65157233507787077498171257724679629263863563732899121548314381678998850404453640235273819513786365'
  + '64391212010397122822120720357',
);

export const RUNGS = { ...Object.fromEntries(Object.entries(CURVES).map(([id, c]) => [id, { kind: 'ecc', name: c.name, bits: c.bits, level: c.level }])),
  'rsa-2048': { kind: 'rsa', name: 'RSA-2048 Challenge', bits: 2048, level: 3 } };
export const RUNG_IDS = Object.keys(RUNGS);
export const LEVEL_NAMES = ['none', 'watch', 'prepare', 'sunset'];

// ---- modular arithmetic and curve points (affine; null is the point at infinity) ----

const mod = (x, m) => { const r = x % m; return r < 0n ? r + m : r; };
export function powMod(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
  }
  return r;
}
const inv = (x, m) => powMod(x, m - 2n, m); // m is prime

// Square root mod an odd prime (Tonelli-Shanks), or null if x is not a square.
export function sqrtMod(x, p) {
  x = mod(x, p);
  if (x === 0n) return 0n;
  if (powMod(x, (p - 1n) / 2n, p) !== 1n) return null;
  if (p % 4n === 3n) return powMod(x, (p + 1n) / 4n, p);
  let q = p - 1n, s = 0n;
  while (q % 2n === 0n) { q /= 2n; s++; }
  let z = 2n;
  while (powMod(z, (p - 1n) / 2n, p) !== p - 1n) z++;
  let m = s, c = powMod(z, q, p), t = powMod(x, q, p), r = powMod(x, (q + 1n) / 2n, p);
  while (t !== 1n) {
    let i = 0n, t2 = t;
    while (t2 !== 1n) { t2 = (t2 * t2) % p; i++; }
    const b = powMod(c, 1n << (m - i - 1n), p);
    m = i; c = (b * b) % p; t = (t * c) % p; r = (r * b) % p;
  }
  return r;
}

function add(c, P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  const { p } = c;
  if (P[0] === Q[0]) {
    if (mod(P[1] + Q[1], p) === 0n) return null;
    const l = mod((3n * P[0] * P[0] + c.a) * inv(2n * P[1], p), p);
    const x = mod(l * l - 2n * P[0], p);
    return [x, mod(l * (P[0] - x) - P[1], p)];
  }
  const l = mod((Q[1] - P[1]) * inv(Q[0] - P[0], p), p);
  const x = mod(l * l - P[0] - Q[0], p);
  return [x, mod(l * (P[0] - x) - P[1], p)];
}

export function multiply(c, k, P = [c.gx, c.gy]) {
  let R = null;
  for (let bit = BigInt(k.toString(2).length) - 1n; bit >= 0n; bit--) {
    R = add(c, R, R);
    if ((k >> bit) & 1n) R = add(c, R, P);
  }
  return R;
}

export const onCurve = (c, [x, y]) => mod(y * y - (x * x * x + c.a * x + c.b), c.p) === 0n;

// The ownerless bait point of a curve rung: the first x = SHA-512(seed | rung | counter) mod p that
// lies on the curve, with the even y. Same on every machine, and nobody knows its discrete log.
const pointCache = new Map();
export function rungPoint(id) {
  if (pointCache.has(id)) return pointCache.get(id);
  const c = CURVES[id];
  for (let ctr = 0; ; ctr++) {
    const h = BigInt('0x' + sha512Hex(`${TRIPWIRE_SEED}|${id}|${ctr}`));
    const x = h % c.p;
    let y = sqrtMod(x * x * x + c.a * x + c.b, c.p);
    if (y === null) continue;
    if (y & 1n) y = c.p - y;
    const point = { x, y, counter: ctr };
    pointCache.set(id, point);
    return point;
  }
}

function sha512Hex(text) {
  return crypto.createHash('sha512').update(text).digest('hex');
}

// Tests replace a target with one whose solution they know. Only code running inside this process can
// do this; nothing that arrives over the network or in a genesis file reaches it.
const testTargets = new Map();
export const testing = {
  setTarget(id, target) { testTargets.set(id, target); },
  clear() { testTargets.clear(); },
};
const eccTarget = (id) => testTargets.get(id) ?? rungPoint(id);
const rsaTarget = () => testTargets.get('rsa-2048')?.n ?? RSA_2048;

// Public description of a rung (what a claimant must break).
export function rungInfo(id) {
  const r = RUNGS[id];
  if (r.kind === 'rsa') return { id, ...r, target: { n: rsaTarget().toString(16) }, solution: 'the two prime factors p < q of n, as "<p hex>.<q hex>"' };
  const pt = eccTarget(id);
  return { id, ...r, target: { x: pt.x.toString(16), y: pt.y.toString(16), counter: pt.counter }, solution: 'the private key d (1 ≤ d < n) with d·G = target, in hex' };
}

// ---- solutions ----

const HEX = /^[0-9a-f]+$/;
export const MAX_SOLUTION_LENGTH = 1100;

// Canonical form: lowercase hex without leading zeros (RSA: "p.q" with p < q). Returns null if malformed.
export function normalizeSolution(rung, solution) {
  if (typeof solution !== 'string' || solution.length > MAX_SOLUTION_LENGTH || !RUNGS[rung]) return null;
  const parts = solution.toLowerCase().split('.');
  if (parts.length !== (RUNGS[rung].kind === 'rsa' ? 2 : 1) || !parts.every((s) => HEX.test(s))) return null;
  return parts.map((s) => BigInt('0x' + s).toString(16)).join('.');
}

// True if `solution` breaks the rung: one scalar multiplication (25-50 ms) or one multiplication.
// Results are cached, because a node re-applies pending transactions (mempool checks, block
// building, validation) and a junk claim must not cost that work every time.
const solutionCache = new Map();
const SOLUTION_CACHE_SIZE = 512;
export function checkSolution(rung, solution) {
  const norm = normalizeSolution(rung, solution);
  if (!norm) return false;
  const key = `${rung}|${norm}|${testTargets.size ? JSON.stringify(testTargets.get(rung) ?? null, (k, v) => (typeof v === 'bigint' ? v.toString(16) : v)) : ''}`;
  if (solutionCache.has(key)) return solutionCache.get(key);
  const ok = verifySolution(rung, norm);
  if (solutionCache.size >= SOLUTION_CACHE_SIZE) solutionCache.delete(solutionCache.keys().next().value);
  solutionCache.set(key, ok);
  return ok;
}

function verifySolution(rung, norm) {
  if (RUNGS[rung].kind === 'rsa') {
    const [p, q] = norm.split('.').map((s) => BigInt('0x' + s));
    return p > 1n && p < q && p * q === rsaTarget();
  }
  const c = CURVES[rung];
  const d = BigInt('0x' + norm);
  if (d < 1n || d >= c.n) return false;
  const P = multiply(c, d);
  const target = eccTarget(rung);
  return P !== null && P[0] === target.x && P[1] === target.y;
}

// What a claimant commits to first: binds the chain, the rung, the claimer and the solution.
export function canaryCommitment(chainId, rung, fromAddress, solution) {
  return sha256(`argeni-canary:v1|${chainId}|${rung}|${fromAddress}|${normalizeSolution(rung, solution) ?? ''}`);
}

// ---- genesis settings ----

// genesis.tripwire = { bounties: { <rung id>: units, ... }, revealDelayBlocks?, graceBlocks? }
export function tripwireParams(genesis) {
  const t = genesis.tripwire;
  if (!t) return null;
  return {
    bounties: t.bounties,
    revealDelayBlocks: t.revealDelayBlocks ?? 10,
    // Level 2 brings the Ed25519 sunset this many blocks forward (default: about 30 days).
    graceBlocks: t.graceBlocks ?? Math.max(1, Math.round((30 * 86_400_000) / genesis.blockTimeMs)),
  };
}

export function tripwireGenesisErrors(t) {
  if (t === undefined) return [];
  const ok = t && typeof t === 'object' && !Array.isArray(t)
    && Object.keys(t).every((k) => ['bounties', 'revealDelayBlocks', 'graceBlocks'].includes(k))
    && t.bounties && typeof t.bounties === 'object' && Object.keys(t.bounties).length > 0
    && Object.entries(t.bounties).every(([id, v]) => RUNGS[id] && typeof v === 'string' && /^(0|[1-9]\d*)$/.test(v))
    && ['revealDelayBlocks', 'graceBlocks'].every((k) => t[k] === undefined || (Number.isSafeInteger(t[k]) && t[k] >= 1));
  return ok ? [] : ['tripwire (bounties: { rung: units }, optional revealDelayBlocks and graceBlocks ≥ 1)'];
}

export const bountyPool = (t) => (t ? Object.values(t.bounties).reduce((s, v) => s + BigInt(v), 0n) : 0n);

// Alert level from the set of broken rungs.
export function alertLevel(broken) {
  return Object.keys(broken).reduce((lvl, id) => Math.max(lvl, RUNGS[id].level), 0);
}

// The Ed25519 retirement height a newly broken rung imposes, given the reveal height.
export function retirementFor(rung, height, params) {
  const lvl = RUNGS[rung].level;
  if (lvl >= ED25519_LEVEL3) return height + 1;
  if (lvl === 2) return height + params.graceBlocks;
  return undefined;
}
