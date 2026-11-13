import type { Act, Quantity, Value } from './ir';

/** Currency exponents for rendering. An unknown currency is shown in raw minor units, never guessed. */
export const CCY_EXPONENT: Record<string, number> = { USD: 2, EUR: 2, GBP: 2, CAD: 2, AUD: 2, CHF: 2, JPY: 0, KRW: 0 };

export function fmtMoney(ccy: string, minor: number): string {
  const e = CCY_EXPONENT[ccy];
  if (e === undefined) return `${ccy} ${minor} (minor units)`; // never guess an exponent
  if (e === 0) return `${ccy} ${minor}`;
  const s = String(minor).padStart(e + 1, '0');
  return `${ccy} ${s.slice(0, -e)}.${s.slice(-e)}`;
}
export function fmtQuantity(q: Quantity): string {
  switch (q.u.k) {
    case 'money': return fmtMoney(q.u.ccy, q.n);
    case 'count': return `${q.n}`;
    case 'duration': return `${q.n}ms`;
    case 'instant': return `@${q.n}`;
    case 'bytes': return `${q.n}B`;
    case 'ratio': return `${q.n}ppm`;
  }
}
export const fmtValue = (v: Value): string => (v.k === 'q' ? fmtQuantity(v.q) : v.k === 's' ? JSON.stringify(v.s) : `{${v.items.map(fmtValue).join(', ')}}`);
export function fmtAct(a: Act): string {
  const ps = Object.keys(a.params).sort().map((k) => `${k}=${fmtValue(a.params[k]!)}`).join(', ');
  return `${a.verb} on ${a.res}${ps ? ` (${ps})` : ''}`;
}
