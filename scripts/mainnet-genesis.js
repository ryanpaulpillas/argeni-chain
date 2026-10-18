// Builds a mainnet genesis from the planned allocation of 500,000,000 ARGENI: every allocation's
// lock-up is written in as an on-chain vesting grant, and the validator incentives become the
// front-loaded reward pool the chain pays out every block.
//
//   node scripts/mainnet-genesis.js --config allocation.json --out genesis.json
//
// allocation.json (see scripts/mainnet-allocation.example.json): chainId, launch time, validator
// public keys, and one ADDRESS per allocation (vaults created offline; no private key is ever read).
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { isAddress, isPublicKey } from '../src/crypto.js';
import { parseAmount } from '../src/coin.js';
import { Chain } from '../src/chain.js';

const DECIMALS = 18;
const SUPPLY = 500_000_000n;
const u = (n) => parseAmount(String(n), DECIMALS);

// The plan published on argeni.io (token page). Months count from launch.
export const PLAN = {
  ecosystem: { amount: 150_000_000n, atStart: 15_000_000n, lockMonths: 0, vestMonths: 36 }, // 30%
  treasury: { amount: 100_000_000n, lockMonths: 6, vestMonths: 48 }, // 20%: at most 5% of supply a year
  validatorRewards: [24_000_000n, 18_000_000n, 12_000_000n, 6_000_000n], // 12%, front-loaded over 4 years
  publicDistribution: { amount: 50_000_000n }, // 10%, only after legal review (held, not offered)
  // Team (15%, shown publicly as one allocation): founder vaults get their amounts as grants locked
  // 12 months then vesting over 24; the rest is the team pool, from which each person's grant is sent
  // with `vest` on the same schedule.
  team: { amount: 75_000_000n, lockMonths: 12, vestMonths: 24 },
  partners: { amount: 40_000_000n, lockMonths: 6, vestMonths: 18 }, // 8%
  liquidity: { amount: 25_000_000n }, // 5%
};

export function buildGenesis(config) {
  const errors = [];
  const a = config.addresses ?? {};
  for (const name of ['ecosystem', 'treasury', 'publicDistribution', 'partners', 'teamPool', 'liquidity']) {
    if (!isAddress(a[name] ?? '')) errors.push(`addresses.${name} must be an Argeni address`);
  }
  const founders = Object.entries(a.founders ?? {});
  if (!founders.every(([addr, amt]) => isAddress(addr) && /^[1-9]\d*$/.test(String(amt)))) errors.push('addresses.founders must map founder addresses to whole ARGENI amounts');
  const foundersTotal = founders.reduce((sum, [, amt]) => sum + BigInt(amt), 0n);
  if (foundersTotal >= PLAN.team.amount) errors.push(`founder amounts must leave part of the ${PLAN.team.amount} ARGENI team allocation for the team pool (they add up to ${foundersTotal})`);
  if (!Array.isArray(config.validators) || config.validators.length < 4 || !config.validators.every(isPublicKey)) errors.push('validators must be at least 4 validator public keys');
  if (!Number.isSafeInteger(config.launch)) errors.push('launch must be a timestamp in milliseconds');
  const addrs = [a.ecosystem, a.treasury, a.publicDistribution, a.partners, a.teamPool, a.liquidity, ...founders.map(([x]) => x)];
  if (new Set(addrs).size !== addrs.length) errors.push('every allocation needs its own address');
  if (errors.length) throw new Error(`invalid allocation config:\n  ${errors.join('\n  ')}`);

  const alloc = {};
  const vesting = {};
  const grant = (address, { amount, atStart = 0n, lockMonths, vestMonths }) => {
    alloc[address] = u(amount).toString();
    vesting[address] = [{ amount: u(amount).toString(), ...(atStart ? { atStart: u(atStart).toString() } : {}), lockMonths, vestMonths }];
  };
  grant(a.ecosystem, PLAN.ecosystem);
  grant(a.treasury, PLAN.treasury);
  grant(a.partners, PLAN.partners);
  for (const [address, amount] of founders) grant(address, { ...PLAN.team, amount: BigInt(amount) });
  alloc[a.publicDistribution] = u(PLAN.publicDistribution.amount).toString();
  alloc[a.teamPool] = u(PLAN.team.amount - foundersTotal).toString();
  alloc[a.liquidity] = u(PLAN.liquidity.amount).toString();

  const genesis = {
    chainId: config.chainId ?? 'argeni-1',
    timestamp: config.launch,
    coin: { name: 'Argeni', symbol: 'ARGENI', decimals: DECIMALS },
    blockTimeMs: 2000,
    emptyBlockIntervalMs: 60_000,
    maxTxsPerBlock: 200,
    minFee: u('0.0001').toString(),
    blockReward: '0',
    maxSupply: u(SUPPLY).toString(),
    validators: config.validators,
    staking: {
      minStake: u(100_000).toString(), maxValidators: 100, minValidators: 4, unbondingMs: 14 * 86_400_000, jailMs: 86_400_000,
      downtimeBlocks: 500, downtimeSlashBps: 10, doubleSignSlashBps: 500,
    },
    rewards: { years: PLAN.validatorRewards.map((y) => u(y).toString()) },
    alloc,
    vesting,
  };
  const total = Object.values(alloc).reduce((s, x) => s + BigInt(x), 0n) + genesis.rewards.years.reduce((s, x) => s + BigInt(x), 0n);
  if (total !== u(SUPPLY)) throw new Error(`allocation adds up to ${total}, not the full supply`);
  new Chain(genesis); // full genesis validation
  return genesis;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { values } = parseArgs({ options: { config: { type: 'string' }, out: { type: 'string' } } });
  if (!values.config || !values.out) {
    console.error('usage: node scripts/mainnet-genesis.js --config allocation.json --out genesis.json');
    process.exit(1);
  }
  try {
    if (fs.existsSync(values.out)) throw new Error(`${values.out} already exists`);
    const genesis = buildGenesis(JSON.parse(fs.readFileSync(values.config, 'utf8')));
    fs.writeFileSync(values.out, `${JSON.stringify(genesis, null, 2)}\n`);
    console.log(`wrote ${values.out}: ${genesis.chainId}, 500,000,000 ARGENI
  ecosystem 150M (15M free, rest over 36 months) · treasury 100M (6-month lock, 48 months)
  validator rewards 60M paid by the chain: 24M, 18M, 12M, 6M per year
  public distribution 50M (held until legal review) · team 75M (founder vaults + team pool; 12-month lock, 24 months)
  partners 40M (6-month lock, 18 months) · liquidity 25M`);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}
