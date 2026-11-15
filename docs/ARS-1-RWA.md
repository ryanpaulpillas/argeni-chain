# ARS-1: Real-World Asset Tokens on CYVBER

**Status:** v0.1, implemented on the devnet and testnet (src/rwa.js, test/rwa.test.js; 2026-11-01).
Not legal advice: every rule below must be checked by Philippine securities counsel before any real
asset is offered. Demo assets only until a licensed issuer and CASP take part.

**Post-quantum administration (CYVBER's advantage).** Every admin action (create, issue, freeze,
pause, force-transfer, rule changes, attestations, KYC) must be signed by a post-quantum key
(ML-DSA or SLH-DSA, or a multisig of them). The chain refuses classical keys for these actions
outright, so a future quantum computer can never forge an issuer's or transfer agent's signature on
an asset meant to last 20-30 years, such as real estate. An asset can also set
`rules.adminKeys: "hash-based"` to require SLH-DSA keys, whose security rests only on hash
functions; this can be tightened but never relaxed. Admin keys rotate with `migrate`, and the
asset's roles and the compliance agent's KYC registry follow the new key.

ARS-1 defines how a real-world asset (shares in an SPV, a loan, a fund unit, a warehouse receipt)
is represented on the CYVBER chain. The chain has no smart contracts, so ARS-1 adds **native
transaction types**, checked by every validator like `transfer` and `migrate`.

## 1. Principles

1. **Legal title stays off-chain.** A token is a record of a claim on an issuer (normally an
   SEC-registered SPV). It does not transfer land titles, which only the Registry of Deeds can.
   The token always points to the legal documents by hash.
2. **Compliance is enforced by the chain, not by the wallet.** Transfers that break KYC, lock-up,
   holder-count or foreign-ownership rules are refused by consensus.
3. **No personal data on chain.** The chain stores only codes and hashes (Data Privacy Act,
   RA 10173). KYC files stay with the licensed CASP or transfer agent.
4. **Fees are paid in CYVBER.** Asset tokens are never used for fees, and CYVBER is never an asset
   token.
5. **Post-quantum administration, enforced.** Admin transactions signed by a classical key are
   refused by consensus. Vault-grade assets can require SLH-DSA (`rules.adminKeys: "hash-based"`;
   see `deploy/FOUNDER-VAULT.md`).

## 2. Roles

| Role | Who in practice | Can do |
|---|---|---|
| `issuer` | The SPV that owns the asset | Create the asset, issue and redeem units, update rules, appoint the other roles |
| `compliance` | Licensed CASP / transfer agent | Attest and revoke investor KYC, freeze and unfreeze accounts, pause the asset |
| `recovery` | Transfer agent acting on a court order or a lost-key procedure | Force-transfer units, citing a document hash |
| `attestor` | Custodian, auditor or appraiser | Publish reserve, NAV or appraisal attestations |
| holder | Investor | Transfer and redeem (if allowed) |

One address may hold several roles in a pilot. At mainnet, `issuer` and `recovery` must be
different keys.

## 3. State

### 3.1 Asset record

```js
assets[assetId] = {
  assetId,              // sha256("cyvber-asset:v1|" + chainId + "|" + issuerAddress + "|" + symbol)
  symbol,               // 2–12 chars, A–Z 0–9, unique per issuer
  name,                 // up to 64 chars
  class,                // 'equity' | 'debt' | 'fund' | 'real-estate' | 'commodity' | 'receivable'
  decimals,             // 0–18
  maxSupply,            // base units, decimal string
  supply,               // base units currently issued
  roles: { issuer, compliance, recovery, attestor },   // addresses
  legal: {
    entity,             // e.g. "Example Property Holdings Inc."
    secRegNo,           // SEC company registration no.
    offering,           // 'stratbox' | 'registered' | 'exempt' (+ reference no.)
    jurisdiction,       // 'PH'
    docsHash,           // sha256 of the offering document bundle
    docsUri,            // where holders can read it
  },
  rules: {
    kycRequired,        // true for every security
    investorClasses,    // e.g. ['qualified'] or ['retail', 'qualified']
    allowedCountries,   // ISO 3166 alpha-2 list, or ['*']
    foreignCapBps,      // max share held by foreign holders, basis points (4000 = 40%); null = no cap
    maxHolders,         // null = no cap
    lockupUntilHeight,  // holder-to-holder transfers refused before this block; 0 = none
    minHoldingUnits,    // a holder may not be left with a balance between 0 and this
    redeemable,         // holders may send units back for redemption
  },
  paused,               // all transfers refused (issuance and recovery still allowed)
  holders,              // count of addresses with balance > 0
  foreignUnits,         // total units held by foreign-flagged addresses
  lastAttestation,      // { kind, valueHash, uri, height } or null
}
```

### 3.2 Balances and flags

```js
assetBalances[assetId][address] = { balance, frozen }
```

### 3.3 Investor registry (shared by all assets of one compliance agent)

```js
kyc[complianceAddress][address] = {
  level,          // 1 = basic, 2 = full CDD, 3 = enhanced (AMLA terms)
  country,        // ISO alpha-2 of nationality / incorporation
  foreign,        // true if counted against the foreign-ownership cap
  investorClass,  // 'retail' | 'qualified' | 'institutional'
  expiresHeight,  // re-KYC deadline
  recordHash,     // sha256 of the off-chain KYC file (never the file itself)
}
```

All new state is folded into `State.root()` so validators agree on it.

## 4. Transactions

All carry the usual `type, chainId, from, fee, nonce, signature`. `from` is the signer's public
key, and the role check uses `addressFromPublicKey(from)`.

| Type | Signer | Extra fields | Effect |
|---|---|---|---|
| `asset-create` | issuer | `symbol, name, class, decimals, maxSupply, roles, legal, rules` | Registers the asset with supply 0 |
| `asset-issue` | issuer | `assetId, to, amount, docRef` | Mints units to a KYC'd investor (subscription) |
| `asset-transfer` | holder | `assetId, to, amount, memo?` | Moves units if every rule in §5 passes |
| `asset-redeem` | holder or issuer | `assetId, holder, amount, docRef?` | Burns units (redemption, maturity, buyback) |
| `asset-freeze` / `asset-unfreeze` | compliance | `assetId, address, reasonHash` | Freezes one holder (AMLC freeze order, sanctions) |
| `asset-pause` / `asset-unpause` | compliance or issuer | `assetId, reasonHash` | Stops all holder transfers |
| `asset-force-transfer` | recovery | `assetId, from, to, amount, orderHash` | Moves units without the holder's signature; `orderHash` = hash of the court order or lost-key affidavit |
| `asset-update` | issuer | `assetId, rules?, legal?, roles?` | Changes rules or documents. Can't raise `maxSupply` past existing filings or lower it below `supply` |
| `asset-attest` | attestor | `assetId, kind, valueHash, uri` | Records proof of reserve, NAV or appraisal (`kind`: 'reserve', 'nav', 'appraisal', 'audit') |
| `kyc-attest` | compliance | `address, level, country, foreign, investorClass, expiresHeight, recordHash` | Adds or renews an investor |
| `kyc-revoke` | compliance | `address, reasonHash` | Removes an investor; their units become frozen until moved by recovery |

`docRef`, `reasonHash` and `orderHash` are 32-byte hex hashes of off-chain documents, so every
admin action leaves an audit trail without publishing the document.

## 5. Transfer checks

`asset-transfer` is refused, with the first matching error, if:

1. the asset does not exist or is `paused`;
2. the sender or receiver is `frozen`, or either account has `migratedTo` set;
3. `height < rules.lockupUntilHeight`;
4. the receiver has no valid KYC with the asset's compliance agent (missing, expired, or
   revoked), when `kycRequired`;
5. the receiver's `investorClass` is not in `rules.investorClasses`, or `country` is not in
   `rules.allowedCountries`;
6. the transfer would push `holders` above `rules.maxHolders`;
7. the transfer would push `foreignUnits` above `supply × foreignCapBps / 10000`
   (40% for land-owning and condominium corporations under the Constitution and RA 4726);
8. the sender would be left with `0 < balance < minHoldingUnits`, or the receiver would end up
   below it;
9. the sender lacks the units, or lacks CYVBER for the fee.

`asset-issue` and `asset-force-transfer` apply checks 4–7 to the receiver, so neither the issuer
nor the recovery role can bypass KYC or the foreign cap. They ignore pause, freeze and lock-up.

## 6. Key migration

When an account runs `migrate`, its asset balances and its KYC entries move to the new address
in the same transaction, and the old address keeps nothing. Without this, investors who rotate to
a new post-quantum key would lose their securities or need a force-transfer.

## 7. Distributions (v0.2)

Dividends and coupons are paid off-chain or in CYVBER. v0.1 only records them:
`asset-attest` with `kind: 'distribution'` and a `valueHash` of the payout list at a snapshot
height. On-chain pro-rata payouts are left for later because they would mean writing to every
holder in one block.

## 8. How the rules map to Philippine law

| Requirement | Law / regulator | ARS-1 mechanism |
|---|---|---|
| Register the offering or use an exemption / sandbox | RA 8799 (SRC), SEC MC 5 s.2025, StratBox | `legal.offering` + `docsHash`; issuance only by the SPV's `issuer` key |
| Trade only through a registered CASP | SEC CASP rules | CASP holds the `compliance` role; non-KYC'd addresses can't receive units |
| KYC / CDD, freezes, record keeping | AMLA (RA 9160 as amended), AMLC | `kyc-attest` levels, `asset-freeze`, hashed reasons |
| Travel Rule | AMLC / FATF | Off-chain between CASPs; the chain keeps `recordHash` only |
| No personal data published | Data Privacy Act (RA 10173) | Codes and hashes only |
| 40% foreign ownership limit | 1987 Constitution Art. XII; RA 4726 | `foreignCapBps` + `foreignUnits` |
| Court orders, estate settlement, lost keys | Rules of Court | `asset-force-transfer` with `orderHash` |
| Qualified-buyer-only offerings | SRC exemptions | `investorClasses: ['qualified']` |
| Taxes (DST, CGT, withholding) | NIRC, BIR | Off-chain; the transfer agent reports from chain history |

## 9. Example: pilot real-estate SPV

```json
{
  "type": "asset-create",
  "symbol": "PHRE1",
  "name": "Pilot Property Holdings Inc. – Class A",
  "class": "real-estate",
  "decimals": 0,
  "maxSupply": "100000",
  "roles": { "issuer": "cy…spv", "compliance": "cy…casp", "recovery": "cy…agent", "attestor": "cy…appraiser" },
  "legal": { "entity": "Pilot Property Holdings Inc.", "secRegNo": "TO CONFIRM", "offering": "stratbox", "jurisdiction": "PH", "docsHash": "…", "docsUri": "https://cyvber.io/assets/PHRE1" },
  "rules": { "kycRequired": true, "investorClasses": ["qualified"], "allowedCountries": ["*"], "foreignCapBps": 4000, "maxHolders": 200, "lockupUntilHeight": 0, "minHoldingUnits": "1", "redeemable": false }
}
```

## 10. Implementation notes (v0.1 as built)

Differences from the draft above: `asset-create` takes `roles: { compliance, recovery, attestor }`
(the signer is the issuer); `asset-force-transfer` names the holder in `holder`; `legal.offering`
also accepts `pilot`; `rules.adminKeys` ('pq' default, or 'hash-based') was added; `asset-pause` may
be signed by the compliance agent or the issuer. A move that reduces foreign holdings is always
allowed, so an asset above its foreign cap can be brought back under it. HTTP: `GET /assets`,
`GET /assets/:id`, `GET /accounts/:address/assets`. CLI: `cyvber asset list|show|holdings|send`.

## 11. Original implementation plan

1. `src/tx.js`: field lists and stateless checks for each new type, plus `create…` helpers.
2. `src/state.js`: `assets`, `assetBalances`, `kyc` maps; `applyTx` branches; §5 checks as a
   pure function `assetTransferError()` like `migrationError()`; include in `root()` and `clone()`.
3. `migrate`: carry asset balances and KYC entries over (§6).
4. HTTP: `GET /assets`, `GET /assets/:id`, `GET /assets/:id/holders`, `GET /accounts/:address/assets`.
5. CLI: `asset create | issue | transfer | redeem | freeze | attest`, `kyc attest | revoke`.
6. Explorer: asset pages showing supply, holders, the foreign-ownership share, attestations and
   links to the documents.
7. Tests: each rejection in §5; issue/force-transfer can't bypass KYC or the foreign cap; the
   foreign cap holds at exactly 40%; frozen and paused behavior; migration carries assets;
   state root changes with every asset write; restart from disk rebuilds asset state.

## 12. Open questions

- Should `compliance` and `recovery` be multi-signature (e.g. 2 of 3) from day one? Recommended
  for anything beyond the pilot; multisig accounts of post-quantum keys work for every role.
- Does the SEC want a read-only regulator node or API key for StratBox supervision?
- Who acts as transfer agent for the pilot, and is a separate custodian needed?
- Should holders be able to see the holder count and foreign share publicly, or only regulators?
