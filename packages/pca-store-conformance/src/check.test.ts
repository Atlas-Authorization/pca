import { describe, expect, it } from 'vitest';
import { checkHistory, checkKey, decideKey, deletion, formatOps, minimize } from './check';
import type { Op } from './model';

const mk = (res: Op['res'], lo: number, call: number, ret: number, extra: Partial<Op> = {}): Op => ({
  client: 'c',
  kind: 'advance',
  key: 'k',
  lo,
  w: lo,
  call,
  ret: res === 'unknown' ? Infinity : ret,
  res,
  ...extra,
});

describe('decideKey', () => {
  it('overlap first, then exact, then search', () => {
    expect(decideKey([mk('true', 1, 0, 1), mk('true', 1, 2, 3)])).toMatchObject({ verdict: 'violation', method: 'overlap' });
    expect(decideKey([mk('true', 1, 0, 1), mk('false', 1, 2, 3)])).toMatchObject({ verdict: 'ok', method: 'exact' });
    expect(decideKey([mk('false', 1, 0, 1)])).toMatchObject({ verdict: 'violation', method: 'exact' });
    expect(decideKey([mk('unknown', 1, 0, 0), mk('false', 1, 2, 3)])).toMatchObject({ verdict: 'ok', method: 'search' });
    expect(decideKey([mk('unknown', 1, 5, 0), mk('false', 1, 2, 3)])).toMatchObject({ verdict: 'violation', method: 'search' });
  });
  it('searches the PRUNED history and passes the budget through', () => {
    const r = decideKey([mk('true', 5, 0, 1), mk('false', 5, 2, 3), mk('unknown', 7, 0, 0)]);
    expect(r.kept).toHaveLength(2);
    expect(decideKey([mk('unknown', 1, 0, 0), mk('false', 1, 2, 3)], 0).verdict).toBe('unresolved');
  });
});

describe('deletion / minimize', () => {
  it('deleting a FALSE removes only it; deleting a writer also removes the FALSEs it may explain (lo <= w)', () => {
    const t = mk('true', 5, 0, 1);
    const f4 = mk('false', 4, 2, 3);
    const f5 = mk('false', 5, 2, 3);
    const f6 = mk('false', 6, 2, 3);
    const u = mk('unknown', 5, 0, 0);
    expect(deletion([t, f4, f5, f6, u], f5)).toEqual([t, f4, f6, u]);
    expect(deletion([t, f4, f5, f6, u], t)).toEqual([f6, u]);
    expect(deletion([t, f4, f5, f6, u], u)).toEqual([t, f6]);
  });
  it('shrinks to a 1-minimal violating history', () => {
    const noise = [mk('true', 1, 0, 1), mk('false', 1, 2, 3), mk('true', 2, 4, 5)];
    const bad = [mk('true', 9, 10, 11), mk('true', 8, 12, 13)];
    const m = minimize([...noise, ...bad]);
    expect(m).toEqual(bad);
    expect(minimize(bad)).toEqual(bad);
  });
  it('keeps going after the first successful deletion (scans to a fixpoint)', () => {
    const bad = [mk('false', 3, 0, 1), mk('true', 1, 2, 3), mk('true', 2, 4, 5), mk('false', 7, 6, 7)];
    const m = minimize(bad);
    expect(m).toHaveLength(1);
    expect(decideKey(m).verdict).toBe('violation');
  });
});

describe('checkKey', () => {
  it('reports key, kind, sizes, verdict and method; no counterexample when legal', () => {
    const r = checkKey([mk('true', 1, 0, 1, { key: 'kk', kind: 'consume' }), mk('false', 1, 2, 3, { key: 'kk', kind: 'consume' })]);
    expect(r).toEqual({ key: 'kk', kind: 'consume', ops: 2, searched: 1, verdict: 'ok', method: 'exact' });
  });
  it('an overlapping pair is the counterexample, sorted by invocation', () => {
    const a = mk('true', 1, 5, 6);
    const b = mk('true', 1, 0, 1);
    const r = checkKey([a, mk('false', 0, 7, 8), b]);
    expect(r.counterexample).toEqual([b, a]);
    expect(r.minimized).toBe(true);
  });
  it('otherwise shrinks, unless disabled or over the limit', () => {
    const h = [mk('true', 1, 0, 1), mk('true', 3, 2, 3), mk('false', 9, 4, 5)];
    expect(checkKey(h)).toMatchObject({ verdict: 'violation', minimized: true, counterexample: [h[2]] });
    expect(checkKey(h, { minimize: false })).toMatchObject({ minimized: false, counterexample: h });
    expect(checkKey(h, { minimizeLimit: 2 })).toMatchObject({ minimized: false, counterexample: h });
    expect(checkKey(h, { minimizeLimit: 3 })).toMatchObject({ minimized: true });
  });
  it('unresolved keys carry no counterexample', () => {
    const r = checkKey([mk('unknown', 1, 0, 0), mk('false', 1, 2, 3)], { budget: 0 });
    expect(r.verdict).toBe('unresolved');
    expect(r.counterexample).toBeUndefined();
  });
});

describe('checkHistory', () => {
  it('partitions by (kind, key) and counts outcomes', () => {
    const h = [
      mk('true', 1, 0, 1, { key: 'a' }),
      mk('true', 1, 0, 1, { key: 'a', kind: 'consume', w: 9 }), // same key, other kind: an independent register
      mk('false', 1, 2, 3, { key: 'b' }),
      mk('unknown', 1, 2, 3, { key: 'c' }),
    ];
    const r = checkHistory(h);
    expect(r.ops).toBe(4);
    expect(r.keys).toBe(4);
    expect(r.outcomes).toEqual({ true: 2, false: 1, unknown: 1 });
    expect(r.violations.map((v) => v.key)).toEqual(['b']);
    expect(r.unresolved).toEqual([]);
    expect(r.ok).toBe(false);
  });
  it('ok only with neither violations nor unresolved keys', () => {
    expect(checkHistory([]).ok).toBe(true);
    expect(checkHistory([mk('true', 1, 0, 1)]).ok).toBe(true);
    const u = checkHistory([mk('unknown', 1, 0, 0), mk('false', 1, 2, 3)], { budget: 0 });
    expect(u.ok).toBe(false);
    expect(u.unresolved).toHaveLength(1);
    expect(u.violations).toHaveLength(0);
  });
  it('groups many operations of one key together', () => {
    const r = checkHistory([mk('true', 1, 0, 1), mk('true', 2, 2, 3), mk('true', 3, 4, 5)]);
    expect(r.keys).toBe(1);
    expect(r.ok).toBe(true);
  });
});

describe('formatOps', () => {
  it('one line per operation, sorted, times relative to the first invocation', () => {
    const lines = formatOps([
      { client: 'p1c2', kind: 'consume', key: 'k', lo: 100, w: 700, call: 12.5, ret: Infinity, res: 'unknown' },
      { client: 'p0c1', kind: 'advance', key: 'k', lo: 4, w: 4, call: 10, ret: 11.25, res: 'true' },
      { client: 'p0c0', kind: 'advance', key: 'k', lo: 3, w: 3, call: 11, ret: 13, res: 'false' },
    ]);
    expect(lines).toEqual([
      'p0c1: advance(4) [+0.000ms .. +1.250ms] -> TRUE',
      'p0c0: advance(3) [+1.000ms .. +3.000ms] -> false',
      'p1c2: consumeOnce(now=100, retainUntil=700) [+2.500ms .. open] -> unknown',
    ]);
  });
});
