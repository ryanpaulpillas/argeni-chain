// ARS-1 real-world asset tokens (docs/ARS-1-RWA.md): native transaction types, checked by every
// validator, for securities such as shares in a property SPV, a loan, a fund unit or a receipt.
//
// Legal title stays off chain; a unit records a claim on the issuer and points to its documents by
// hash. Compliance is enforced by consensus, not by wallets: a transfer that breaks KYC, investor
// class, country, holder-count, foreign-ownership, lock-up or minimum-holding rules is refused.
// No personal data is stored, only codes and hashes (Data Privacy Act, RA 10173).
//
// Post-quantum administration: every admin action (issuing, freezing, force-transfers, KYC, rule
// changes, attestations) must be signed by a post-quantum key or a multisig of them. A classical key
// can never administer an asset, so a future quantum computer can't forge an issuer's or transfer
// agent's signature over an asset meant to last decades. An asset can go further and require
// hash-based SLH-DSA keys, whose security rests only on hash functions.
//
// State (plain JSON, amounts as decimal strings), kept in State.rwa:
//   assets[assetId]          the asset record (see assetCreate)
//   balances[assetId][addr]  { balance, frozen?, foreign? }
//   kyc[compliance][addr]    { level, country, foreign, investorClass, expiresHeight, recordHash }
import { isAddress, isHex, memberKeyTypes, PQ_KEY_TYPES, sha256 } from './crypto.js';
import { isUnits } from './coin.js';

const ENVELOPE = ['type', 'chainId', 'from', 'fee', 'nonce', 'signature'];
export const RWA_FIELDS = {
  'asset-create': [...ENVELOPE, 'symbol', 'name', 'class', 'decimals', 'maxSupply', 'roles', 'legal', 'rules'],
  'asset-issue': [...ENVELOPE, 'assetId', 'to', 'amount', 'docRef'],
  'asset-transfer': [...ENVELOPE, 'assetId', 'to', 'amount', 'memo'],
  'asset-redeem': [...ENVELOPE, 'assetId', 'holder', 'amount', 'docRef'],
  'asset-freeze': [...ENVELOPE, 'assetId', 'address', 'reasonHash'],
  'asset-unfreeze': [...ENVELOPE, 'assetId', 'address', 'reasonHash'],
  'asset-pause': [...ENVELOPE, 'assetId', 'reasonHash'],
  'asset-unpause': [...ENVELOPE, 'assetId', 'reasonHash'],
  'asset-force-transfer': [...ENVELOPE, 'assetId', 'holder', 'to', 'amount', 'orderHash'],
  'asset-update': [...ENVELOPE, 'assetId', 'roles', 'legal', 'rules'],
  'asset-attest': [...ENVELOPE, 'assetId', 'kind', 'valueHash', 'uri'],
  'kyc-attest': [...ENVELOPE, 'address', 'level', 'country', 'foreign', 'investorClass', 'expiresHeight', 'recordHash'],
  'kyc-revoke': [...ENVELOPE, 'address', 'reasonHash'],
};
export const RWA_TYPES = Object.keys(RWA_FIELDS);
// Signed by an administrator, never by an ordinary holder (asset-redeem may be either; see below).
const ADMIN_TYPES = new Set(RWA_TYPES.filter((t) => t !== 'asset-transfer' && t !== 'asset-redeem'));

export const ASSET_CLASSES = ['equity', 'debt', 'fund', 'real-estate', 'commodity', 'receivable'];
export const INVESTOR_CLASSES = ['retail', 'qualified', 'institutional'];
export const OFFERINGS = ['stratbox', 'registered', 'exempt', 'pilot'];
export const ATTEST_KINDS = ['reserve', 'nav', 'appraisal', 'audit', 'distribution'];
export const ADMIN_KEY_POLICIES = ['pq', 'hash-based']; // any post-quantum key, or SLH-DSA only
const HASH_BASED_TYPES = ['slh-dsa-256s', 'slh-dsa-128s'];
const MAX_URI = 256;

export function assetIdFor(chainId, issuerAddress, symbol) {
  return sha256(`cyvber-asset:v1|${chainId}|${issuerAddress}|${symbol}`);
}

// Null if `publicKey` may administer an asset under `policy`, else the reason it may not.
export function adminKeyError(publicKey, policy = 'pq') {
  const types = memberKeyTypes(publicKey);
  if (!types.every((t) => PQ_KEY_TYPES.includes(t))) {
    return 'asset administration needs a post-quantum key (ML-DSA or SLH-DSA, or a multisig of them); a classical key can never administer an asset';
  }
  if (policy === 'hash-based' && !types.every((t) => HASH_BASED_TYPES.includes(t))) {
    return 'this asset requires hash-based SLH-DSA keys for its administrators';
  }
  return null;
}

// ---- stateless checks ----

const isHash = (v) => isHex(v, 32);
const positive = (v) => isUnits(v) && BigInt(v) > 0n;
const text = (v, max, min = 1) => typeof v === 'string' && v.length >= min && v.length <= max;
const plainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const onlyKeys = (o, allowed) => Object.keys(o).every((k) => allowed.includes(k));
const isCountry = (c) => typeof c === 'string' && /^[A-Z]{2}$/.test(c);

function rolesError(roles, { partial = false } = {}) {
  const allowed = ['compliance', 'recovery', 'attestor'];
  if (!plainObject(roles) || !onlyKeys(roles, allowed)) return `roles must be an object with ${allowed.join(', ')}`;
  if (!partial && (!roles.compliance || !roles.recovery)) return 'roles.compliance and roles.recovery are required';
  for (const [role, address] of Object.entries(roles)) {
    if (!(role === 'attestor' && address === null) && !isAddress(address)) return `roles.${role} must be an CYVBER address`;
  }
  return null;
}

function legalError(legal) {
  const allowed = ['entity', 'secRegNo', 'offering', 'jurisdiction', 'docsHash', 'docsUri'];
  if (!plainObject(legal) || !onlyKeys(legal, allowed) || allowed.some((k) => legal[k] === undefined)) return `legal must have ${allowed.join(', ')}`;
  if (!text(legal.entity, 128)) return 'legal.entity must be 1-128 characters';
  if (!text(legal.secRegNo, 64)) return 'legal.secRegNo must be 1-64 characters';
  if (!OFFERINGS.includes(legal.offering)) return `legal.offering must be one of ${OFFERINGS.join(', ')}`;
  if (!isCountry(legal.jurisdiction)) return 'legal.jurisdiction must be a 2-letter country code';
  if (!isHash(legal.docsHash)) return 'legal.docsHash must be a 32-byte hex hash of the offering documents';
  if (!text(legal.docsUri, MAX_URI)) return `legal.docsUri must be 1-${MAX_URI} characters`;
  return null;
}

const RULE_KEYS = ['kycRequired', 'investorClasses', 'allowedCountries', 'foreignCapBps', 'maxHolders', 'lockupUntilHeight', 'minHoldingUnits', 'redeemable', 'adminKeys'];
function rulesError(rules) {
  if (!plainObject(rules) || !onlyKeys(rules, RULE_KEYS) || RULE_KEYS.some((k) => k !== 'adminKeys' && rules[k] === undefined)) {
    return `rules must have ${RULE_KEYS.filter((k) => k !== 'adminKeys').join(', ')} (and optionally adminKeys)`;
  }
  if (typeof rules.kycRequired !== 'boolean') return 'rules.kycRequired must be true or false';
  if (!Array.isArray(rules.investorClasses) || !rules.investorClasses.length || !rules.investorClasses.every((c) => INVESTOR_CLASSES.includes(c))) {
    return `rules.investorClasses must list some of ${INVESTOR_CLASSES.join(', ')}`;
  }
  const countries = rules.allowedCountries;
  if (!Array.isArray(countries) || !countries.length || countries.length > 250 || !(countries.join() === '*' || countries.every(isCountry))) {
    return 'rules.allowedCountries must be ["*"] or a list of 2-letter country codes';
  }
  if (rules.foreignCapBps !== null && !(Number.isSafeInteger(rules.foreignCapBps) && rules.foreignCapBps >= 0 && rules.foreignCapBps <= 10_000)) return 'rules.foreignCapBps must be 0-10000 or null';
  if (rules.maxHolders !== null && !(Number.isSafeInteger(rules.maxHolders) && rules.maxHolders >= 1)) return 'rules.maxHolders must be a positive integer or null';
  if (!Number.isSafeInteger(rules.lockupUntilHeight) || rules.lockupUntilHeight < 0) return 'rules.lockupUntilHeight must be a block height (0 = none)';
  if (!isUnits(rules.minHoldingUnits)) return 'rules.minHoldingUnits must be a base-unit integer string';
  if (typeof rules.redeemable !== 'boolean') return 'rules.redeemable must be true or false';
  if (rules.adminKeys !== undefined && !ADMIN_KEY_POLICIES.includes(rules.adminKeys)) return `rules.adminKeys must be one of ${ADMIN_KEY_POLICIES.join(', ')}`;
  return null;
}

// Checks an ARS-1 transaction's own fields (the envelope and signature are checked by tx.js).
export function checkRwaTx(tx) {
  if (ADMIN_TYPES.has(tx.type)) {
    const error = adminKeyError(tx.from);
    if (error) return error;
  }
  if (tx.type !== 'asset-create' && tx.type !== 'kyc-attest' && tx.type !== 'kyc-revoke' && !isHash(tx.assetId)) return 'assetId must be a 32-byte hex id';
  for (const field of ['docRef', 'reasonHash', 'orderHash', 'valueHash', 'recordHash']) {
    if (RWA_FIELDS[tx.type].includes(field) && !isHash(tx[field])) return `${field} must be a 32-byte hex hash of the supporting document`;
  }
  for (const field of ['to', 'holder', 'address']) {
    if (RWA_FIELDS[tx.type].includes(field) && !isAddress(tx[field])) return `${field} must be an CYVBER address`;
  }
  if (RWA_FIELDS[tx.type].includes('amount') && !positive(tx.amount)) return 'amount must be a positive base-unit integer string';
  switch (tx.type) {
    case 'asset-create':
      if (typeof tx.symbol !== 'string' || !/^[A-Z0-9]{2,12}$/.test(tx.symbol)) return 'symbol must be 2-12 characters, A-Z and 0-9';
      if (!text(tx.name, 64)) return 'name must be 1-64 characters';
      if (!ASSET_CLASSES.includes(tx.class)) return `class must be one of ${ASSET_CLASSES.join(', ')}`;
      if (!Number.isSafeInteger(tx.decimals) || tx.decimals < 0 || tx.decimals > 18) return 'decimals must be 0-18';
      if (!positive(tx.maxSupply)) return 'maxSupply must be a positive base-unit integer string';
      return rolesError(tx.roles) ?? legalError(tx.legal) ?? rulesError(tx.rules);
    case 'asset-update':
      if (tx.roles === undefined && tx.legal === undefined && tx.rules === undefined) return 'asset-update needs roles, legal or rules';
      return (tx.roles !== undefined ? rolesError(tx.roles, { partial: true }) : null)
        ?? (tx.legal !== undefined ? legalError(tx.legal) : null)
        ?? (tx.rules !== undefined ? rulesError(tx.rules) : null);
    case 'asset-attest':
      if (!ATTEST_KINDS.includes(tx.kind)) return `kind must be one of ${ATTEST_KINDS.join(', ')}`;
      if (!text(tx.uri, MAX_URI)) return `uri must be 1-${MAX_URI} characters`;
      return null;
    case 'kyc-attest':
      if (![1, 2, 3].includes(tx.level)) return 'level must be 1 (basic), 2 (full CDD) or 3 (enhanced)';
      if (!isCountry(tx.country)) return 'country must be a 2-letter country code';
      if (typeof tx.foreign !== 'boolean') return 'foreign must be true or false';
      if (!INVESTOR_CLASSES.includes(tx.investorClass)) return `investorClass must be one of ${INVESTOR_CLASSES.join(', ')}`;
      if (!Number.isSafeInteger(tx.expiresHeight) || tx.expiresHeight < 1) return 'expiresHeight must be a block height';
      return null;
    default:
      return null;
  }
}

// ---- state ----

export function emptyRwa() {
  return { assets: {}, balances: {}, kyc: {} };
}

export function isEmptyRwa(rwa) {
  return !rwa || (!Object.keys(rwa.assets).length && !Object.keys(rwa.kyc).length);
}

// A valid (present, unexpired) KYC entry for `address` with the asset's compliance agent, or null.
export function kycFor(rwa, asset, address, height) {
  const entry = rwa.kyc[asset.roles.compliance]?.[address];
  return entry && entry.expiresHeight > height ? entry : null;
}

// Moves `amount` units of an asset: src -> dst, or issuance (src null) or redemption (dst null).
// Runs the receiver checks (KYC, investor class, country, holder count, foreign cap) and the minimum
// holding check, then writes the result. Throws on the first broken rule, before writing anything.
function move(rwa, asset, src, dst, amount, { height, minHolding = true }) {
  const rules = asset.rules;
  const bals = rwa.balances[asset.assetId] ?? {};
  const s = src ? bals[src] ?? { balance: '0' } : null;
  const d = dst ? bals[dst] ?? { balance: '0' } : null;
  const sBal = s ? BigInt(s.balance) : 0n;
  const dBal = d ? BigInt(d.balance) : 0n;
  if (src && sBal < amount) throw new Error(`insufficient ${asset.symbol} balance`);
  let supply = BigInt(asset.supply);
  let foreignUnits = BigInt(asset.foreignUnits);
  let holders = asset.holders;
  const foreignBefore = foreignUnits;
  let dstForeign = d && dBal > 0n ? Boolean(d.foreign) : false;

  if (!src) {
    supply += amount;
    if (supply > BigInt(asset.maxSupply)) throw new Error(`issuing this would exceed the maximum supply of ${asset.maxSupply}`);
  } else {
    if (sBal - amount === 0n) holders--;
    if (s.foreign) foreignUnits -= amount;
  }
  if (!dst) {
    supply -= amount;
  } else {
    const entry = kycFor(rwa, asset, dst, height);
    if (rules.kycRequired && !entry) throw new Error('the receiver has no valid KYC with this asset\'s compliance agent');
    if (entry) {
      if (!rules.investorClasses.includes(entry.investorClass)) throw new Error(`the receiver's investor class (${entry.investorClass}) may not hold this asset`);
      if (rules.allowedCountries.join() !== '*' && !rules.allowedCountries.includes(entry.country)) throw new Error(`holders from ${entry.country} may not hold this asset`);
    }
    if (dBal === 0n) {
      holders++;
      dstForeign = Boolean(entry?.foreign);
    }
    if (dstForeign) foreignUnits += amount;
    if (rules.maxHolders !== null && holders > rules.maxHolders) throw new Error(`this asset may have at most ${rules.maxHolders} holders`);
  }
  // Foreign-ownership cap (40% for land-owning companies: Constitution Art. XII, RA 4726). A move that
  // reduces foreign holdings is always allowed, so the cap can be restored, never worsened.
  if (rules.foreignCapBps !== null && foreignUnits >= foreignBefore && foreignUnits > 0n && foreignUnits * 10_000n > supply * BigInt(rules.foreignCapBps)) {
    throw new Error(`foreign holders would own more than ${rules.foreignCapBps / 100}% of this asset`);
  }
  if (minHolding) {
    const min = BigInt(rules.minHoldingUnits);
    if (src && sBal - amount > 0n && sBal - amount < min) throw new Error(`the sender would be left below the minimum holding of ${min} units`);
    if (dst && dBal + amount < min) throw new Error(`the receiver would hold less than the minimum of ${min} units`);
  }

  rwa.balances[asset.assetId] = bals;
  if (src) bals[src] = { ...s, balance: (sBal - amount).toString(), ...(sBal - amount === 0n ? { foreign: false } : {}) };
  if (dst) bals[dst] = { ...d, balance: (dBal + amount).toString(), foreign: dstForeign };
  for (const a of [src, dst]) if (a && bals[a].balance === '0' && !bals[a].frozen) delete bals[a];
  asset.supply = supply.toString();
  asset.foreignUnits = foreignUnits.toString();
  asset.holders = holders;
}

const frozen = (rwa, asset, address) => Boolean(rwa.balances[asset.assetId]?.[address]?.frozen);

// Applies an ARS-1 transaction that passed checkRwaTx. `from` is the signer's address;
// ctx = { height, chainId, isMigrated(address) }. Throws before writing anything if a rule is broken.
export function applyRwaTx(rwa, tx, from, ctx) {
  const { height } = ctx;
  if (tx.type === 'kyc-attest' || tx.type === 'kyc-revoke') return applyKyc(rwa, tx, from, height);

  if (tx.type === 'asset-create') {
    const assetId = assetIdFor(ctx.chainId, from, tx.symbol);
    if (rwa.assets[assetId]) throw new Error(`this issuer already created ${tx.symbol}`);
    if (tx.roles.recovery === from) throw new Error('the recovery agent must be a different key from the issuer');
    const adminKeys = tx.rules.adminKeys ?? 'pq';
    const keyError = adminKeyError(tx.from, adminKeys);
    if (keyError) throw new Error(keyError);
    rwa.assets[assetId] = {
      assetId, symbol: tx.symbol, name: tx.name, class: tx.class, decimals: tx.decimals, maxSupply: tx.maxSupply,
      supply: '0', holders: 0, foreignUnits: '0', paused: false,
      roles: { issuer: from, compliance: tx.roles.compliance, recovery: tx.roles.recovery, attestor: tx.roles.attestor ?? null },
      legal: { ...tx.legal }, rules: { ...tx.rules, adminKeys }, createdHeight: height, lastAttestation: null,
    };
    return;
  }

  const asset = rwa.assets[tx.assetId];
  if (!asset) throw new Error('unknown asset');
  const role = (name) => {
    if (asset.roles[name] !== from) throw new Error(`only the asset's ${name} can do this`);
    const keyError = adminKeyError(tx.from, asset.rules.adminKeys);
    if (keyError) throw new Error(keyError);
  };
  const notMigrated = (address, who) => {
    if (ctx.isMigrated(address)) throw new Error(`the ${who} account was migrated; use its new address`);
  };

  switch (tx.type) {
    case 'asset-issue':
      role('issuer');
      notMigrated(tx.to, 'receiving');
      return move(rwa, asset, null, tx.to, BigInt(tx.amount), { height });

    case 'asset-transfer': {
      if (asset.paused) throw new Error(`${asset.symbol} is paused`);
      if (tx.to === from) throw new Error('cannot transfer to yourself');
      if (frozen(rwa, asset, from)) throw new Error(`your ${asset.symbol} units are frozen`);
      if (frozen(rwa, asset, tx.to)) throw new Error(`the receiver's ${asset.symbol} units are frozen`);
      notMigrated(tx.to, 'receiving');
      if (height < asset.rules.lockupUntilHeight) throw new Error(`${asset.symbol} is locked up until block ${asset.rules.lockupUntilHeight}`);
      return move(rwa, asset, from, tx.to, BigInt(tx.amount), { height });
    }

    case 'asset-redeem': {
      // A holder may redeem their own units if the asset is redeemable; the issuer may redeem anyone's
      // (maturity, buyback), always with a post-quantum key.
      if (tx.holder === from && asset.roles.issuer !== from) {
        if (!asset.rules.redeemable) throw new Error(`${asset.symbol} is not redeemable by holders`);
        if (asset.paused) throw new Error(`${asset.symbol} is paused`);
        if (frozen(rwa, asset, from)) throw new Error(`your ${asset.symbol} units are frozen`);
      } else {
        role('issuer');
      }
      return move(rwa, asset, tx.holder, null, BigInt(tx.amount), { height, minHolding: false });
    }

    case 'asset-force-transfer':
      role('recovery');
      if (tx.holder === tx.to) throw new Error('holder and receiver must differ');
      notMigrated(tx.to, 'receiving');
      return move(rwa, asset, tx.holder, tx.to, BigInt(tx.amount), { height, minHolding: false });

    case 'asset-freeze':
    case 'asset-unfreeze': {
      role('compliance');
      const bals = (rwa.balances[asset.assetId] ??= {});
      const entry = bals[tx.address] ?? { balance: '0' };
      if (tx.type === 'asset-freeze') bals[tx.address] = { ...entry, frozen: true };
      else if (entry.balance === '0') delete bals[tx.address];
      else bals[tx.address] = { ...entry, frozen: false };
      return;
    }

    case 'asset-pause':
    case 'asset-unpause':
      if (asset.roles.compliance !== from && asset.roles.issuer !== from) throw new Error('only the asset\'s compliance agent or issuer can do this');
      {
        const keyError = adminKeyError(tx.from, asset.rules.adminKeys);
        if (keyError) throw new Error(keyError);
      }
      asset.paused = tx.type === 'asset-pause';
      return;

    case 'asset-update': {
      role('issuer');
      if (tx.roles?.recovery === from) throw new Error('the recovery agent must be a different key from the issuer');
      // The admin-key policy can only get stricter: an asset never goes back to weaker keys.
      if (tx.rules && asset.rules.adminKeys === 'hash-based' && (tx.rules.adminKeys ?? 'pq') !== 'hash-based') {
        throw new Error('this asset requires hash-based admin keys; that cannot be relaxed');
      }
      if (tx.roles) asset.roles = { ...asset.roles, ...tx.roles };
      if (tx.legal) asset.legal = { ...tx.legal };
      if (tx.rules) asset.rules = { ...tx.rules, adminKeys: tx.rules.adminKeys ?? 'pq' };
      return;
    }

    case 'asset-attest':
      role('attestor');
      asset.lastAttestation = { kind: tx.kind, valueHash: tx.valueHash, uri: tx.uri, height };
      return;

    default:
      throw new Error('unsupported transaction type');
  }
}

// kyc-attest / kyc-revoke: the signer is the compliance agent whose registry is written. Revoking an
// investor freezes their units in every asset that agent supervises (recovery can then move them).
function applyKyc(rwa, tx, from, height) {
  const registry = rwa.kyc[from] ?? {};
  const supervised = Object.values(rwa.assets).filter((a) => a.roles.compliance === from);
  if (tx.type === 'kyc-revoke') {
    if (!registry[tx.address]) throw new Error('this address has no KYC entry with you');
    delete registry[tx.address];
    for (const asset of supervised) {
      const entry = rwa.balances[asset.assetId]?.[tx.address];
      if (entry) entry.frozen = true;
    }
  } else {
    if (tx.expiresHeight <= height) throw new Error('expiresHeight must be in the future');
    // A holder newly flagged foreign counts against the foreign caps of the assets they hold.
    for (const asset of supervised) {
      const entry = rwa.balances[asset.assetId]?.[tx.address];
      if (!entry || entry.balance === '0' || Boolean(entry.foreign) === tx.foreign) continue;
      const units = BigInt(entry.balance);
      const foreignUnits = BigInt(asset.foreignUnits) + (tx.foreign ? units : -units);
      if (tx.foreign && asset.rules.foreignCapBps !== null && foreignUnits * 10_000n > BigInt(asset.supply) * BigInt(asset.rules.foreignCapBps)) {
        throw new Error(`marking this holder foreign would put ${asset.symbol} over its foreign-ownership cap`);
      }
      asset.foreignUnits = foreignUnits.toString();
      entry.foreign = tx.foreign;
    }
    registry[tx.address] = { level: tx.level, country: tx.country, foreign: tx.foreign, investorClass: tx.investorClass, expiresHeight: tx.expiresHeight, recordHash: tx.recordHash };
  }
  if (Object.keys(registry).length) rwa.kyc[from] = registry;
  else delete rwa.kyc[from];
}

// Key rotation (migrate): the old address's asset units, its KYC entries, its asset roles and, for a
// compliance agent, its whole KYC registry move to the new post-quantum address. Investors keep their
// securities, and issuers and transfer agents rotate keys without re-registering any asset.
export function migrateRwa(rwa, from, to) {
  for (const [assetId, bals] of Object.entries(rwa.balances)) {
    const old = bals[from];
    if (!old) continue;
    const cur = bals[to];
    const asset = rwa.assets[assetId];
    if (cur) {
      if (BigInt(cur.balance) > 0n && BigInt(old.balance) > 0n) asset.holders--;
      // When both addresses held units, the merged holding takes the new address's foreign flag, and
      // the foreign total is corrected for the units that changed flag.
      const foreign = BigInt(cur.balance) > 0n ? Boolean(cur.foreign) : Boolean(old.foreign);
      if (BigInt(cur.balance) > 0n && Boolean(old.foreign) !== foreign) {
        asset.foreignUnits = (BigInt(asset.foreignUnits) + (foreign ? 1n : -1n) * BigInt(old.balance)).toString();
      }
      bals[to] = { balance: (BigInt(cur.balance) + BigInt(old.balance)).toString(), frozen: Boolean(cur.frozen || old.frozen), foreign };
    } else {
      bals[to] = { ...old };
    }
    delete bals[from];
  }
  for (const registry of Object.values(rwa.kyc)) {
    if (registry[from]) {
      registry[to] ??= registry[from];
      delete registry[from];
    }
  }
  if (rwa.kyc[from]) {
    rwa.kyc[to] = { ...rwa.kyc[from], ...(rwa.kyc[to] ?? {}) };
    delete rwa.kyc[from];
  }
  for (const asset of Object.values(rwa.assets)) {
    for (const r of Object.keys(asset.roles)) if (asset.roles[r] === from) asset.roles[r] = to;
  }
}

// Public view of an asset for the API: the record plus its holder balances (addresses only).
export function assetView(rwa, assetId) {
  const asset = rwa?.assets[assetId];
  if (!asset) return null;
  const supply = BigInt(asset.supply);
  return {
    ...asset,
    foreignShareBps: supply > 0n ? Number((BigInt(asset.foreignUnits) * 10_000n) / supply) : 0,
    balances: Object.entries(rwa.balances[assetId] ?? {}).map(([address, b]) => ({ address, balance: b.balance, frozen: Boolean(b.frozen) })),
  };
}
