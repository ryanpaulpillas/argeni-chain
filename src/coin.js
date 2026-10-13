// Conversion between ARGENI amounts ("1.5") and base units (BigInt).
// All amounts on chain are base-unit integers stored as decimal strings.

export function parseAmount(text, decimals) {
  if (typeof text !== 'string' || !/^\d+(\.\d+)?$/.test(text)) {
    throw new Error(`invalid amount "${text}"`);
  }
  const [whole, frac = ''] = text.split('.');
  if (frac.length > decimals) throw new Error(`amount "${text}" has more than ${decimals} decimal places`);
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

export function formatAmount(units, decimals) {
  const value = BigInt(units);
  const base = 10n ** BigInt(decimals);
  const frac = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return frac ? `${value / base}.${frac}` : `${value / base}`;
}

// Canonical base-unit string: digits only, no leading zeros.
export function isUnits(value) {
  return typeof value === 'string' && /^(0|[1-9]\d*)$/.test(value) && value.length <= 78;
}
