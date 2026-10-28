# Argeni chain

The Argeni blockchain, built from scratch in Node.js with no dependencies.
Native coin: **ARGENI** (18 decimals), fixed supply of **500,000,000**.
Status: **devnet / testnet only**, not for real value.

## Quick start

```bash
npm test               # run the test suite
npm run devnet:init    # create a 4-validator devnet in ./devnet (keys, genesis, configs)
npm run devnet         # start all four nodes (ports 26601-26604)
```

In another terminal:

```bash
node src/cli.js keygen --out my-wallet.json
node src/cli.js faucet <your address>            # 100 test ARGENI from node 1
node src/cli.js balance <your address>
node src/cli.js send --key my-wallet.json --to <address> --amount 10
node src/cli.js status

# post-quantum safety for an older Ed25519 wallet
node src/cli.js keygen --out vault.json --type slh-dsa-128s   # or ml-dsa-65 (default)
node src/cli.js pq-commit --key old.json --new-key vault.json # lock in the future key (before the sunset)
node src/cli.js migrate --key old.json --new-key vault.json   # move everything; old key locked
```

Live demo: with the devnet running, open **http://127.0.0.1:26601/** for the block explorer
(any node serves it) and run `npm run demo` in another terminal to generate transfers.

`devnet/` holds private keys and is git-ignored. Delete it to start a fresh chain.

Public testnet: see [deploy/DEPLOY.md](deploy/DEPLOY.md) (DigitalOcean + GoDaddy DNS, automatic HTTPS).

## How it works

| Part | Design |
|---|---|
| Accounts | Post-quantum **ML-DSA-65** keys (NIST FIPS 204, lattice-based) by default, or **SLH-DSA-SHA2-128s** (FIPS 205, hash-based: secure as long as SHA-256 is, even if lattice schemes fall; 7,856-byte signatures, ~0.2 s to sign, so best for savings/cold storage). Ed25519 keys still accepted. Address = `ag` + first 20 bytes of sha256 of the key (post-quantum keys hashed with a type label, `mldsa65:` or `slhdsa128s:`). Balance and nonce per address. |
| Migration | A `migrate` transaction moves a whole Ed25519 account to a new post-quantum key. It is signed by both keys; the old account is locked afterwards (it can't send, and payments to it are refused). Optional `ed25519SunsetHeight` in genesis: from that block on, Ed25519 keys may only migrate. |
| Migration security | A `pq-commit` transaction (Ed25519-signed, before the sunset) records sha256(`argeni-pq-commit:v1` \| chainId \| old address \| new address). Only the hash is public. From then on the account can only migrate to that key, and no new commitment is accepted after the sunset, so an attacker who later recovers the Ed25519 key with a quantum computer can't redirect the funds. After the sunset, an account without a commitment can migrate only if it never signed a transaction (its public key was never revealed). |
| Transactions | Signed transfers with amount, fee, nonce and optional memo, plus `pq-commit` and `migrate`. Nonce prevents replay; chainId prevents cross-chain replay. |
| Blocks | Header with height, timestamp, previous hash, Merkle root of transactions, state root and proposer, plus a commit certificate: precommit signatures from more than two thirds of validators. |
| Consensus | BFT, following the Tendermint algorithm (`src/consensus.js`): propose, prevote, precommit, with locking and round changes. Blocks are final once committed; no reorgs. With n validators it tolerates f = floor((n-1)/3) faulty or offline ones (4 validators tolerate 1). Below quorum the chain pauses rather than forks. |
| Supply | `maxSupply` is enforced: genesis allocations cannot exceed it and minting stops at it. Devnet: all 500,000,000 ARGENI exist at genesis (499M treasury, 1M faucet), `blockReward` 0. |
| Q-Day Tripwire | Optional `genesis.tripwire` (`src/tripwire.js`). A ladder of bait keys nobody owns: points hashed onto secp160r1, P-192, P-224, P-256 and secp256k1 from the public seed `ARGENI Q-Day Tripwire v1`, plus the RSA-2048 Challenge number. Each carries a bounty from the fixed supply. A claim is `canary-commit` (hash of chain, rung, claimer and solution), then `canary-reveal` at least `revealDelayBlocks` later (a commitment locks a refundable deposit, default 10 ARGENI, and lapses after `commitTtlBlocks`, its deposit going to the bounty pool); the chain checks d·G = P (or p·q = N), pays the bounty and raises its alert level. Level 1 (ECC-160/192): recorded only. Level 2 (ECC-224 or RSA-2048): the Ed25519 sunset moves to `graceBlocks` from now (default about 30 days). Level 3 (a 256-bit curve): Ed25519 is retired from the next block, and classical accounts can only migrate under the post-sunset rules. A tripwire can only bring a planned sunset earlier. `GET /tripwire` and `argeni canary ladder` show the ladder. |
| Fees | Fees go to the block proposer. |
| Idle chain | With `emptyBlockIntervalMs` in genesis, validators wait for transactions instead of making an empty block every `blockTimeMs`, with a heartbeat block at that interval. |
| Public-node limits | Node config `trustProxy`, `faucetAddressCooldownMs`, `faucetIpCooldownMs`, `txsPerMinutePerIp`. |
| Network | HTTP: transactions, consensus votes and finalized blocks are gossiped to peers; nodes catch up from peers every 3 s and verify each block's certificate. |
| Storage | One JSON file per block in the data dir; on restart every block and certificate is re-validated, and a tampered file stops the node. |

### HTTP API

`GET /status`, `GET /genesis`, `GET /blocks?limit=`, `GET /blocks/:height|latest`, `GET /accounts/:address`,
`GET /accounts/:address/txs?limit=`, `GET /txs?limit=`, `GET /txs/:hash`, `GET /tripwire`, `POST /txs`, `POST /blocks` and `POST /consensus` (peers), `POST /faucet` (testnet node only).

## Tested

`npm test` covers transfers, replay and overspend protection, the supply cap, forged and
under-signed certificates, restart from disk, and consensus under: one validator offline, two
offline (halts, then resumes), a quantum attacker holding an old key trying to redirect a committed migration, 20% message loss with delays, and a proposer sending different
blocks to different validators. The suite passed 16 runs in a row.

## Not done yet (needed before a public mainnet)

- **Validator set changes / staking.** Validators are fixed in genesis, with equal voting power.
- **Slashing.** Double-signing is ignored (first vote kept) but not punished.
- **Peer-to-peer layer.** Node links are encrypted and authenticated (ML-KEM-768 key exchange, ML-DSA identities, AES-256-GCM; see `src/p2p.js`). Discovery is by announcement to known peers only.
- **Smart contracts.** Only ARGENI transfers exist.
- **Peer authentication, rate limiting and DoS protection** on the HTTP API.
- **Efficient storage.** State is in memory and rebuilt on start; the state root is recomputed in full each block.
- **Tokenomics.** Supply is fixed at 500 million; how it is split (team, ecosystem, sale, reserve, vesting) and the mainnet fee level are not decided.
- **Independent security audit.**

Do not sell ARGENI, give it out for value, or launch a public mainnet until the legal checklist
(SEC, BSP, AMLC) is cleared. See `argeni-backend/docs/ARGENI-LEGAL-TODO.pdf`.
