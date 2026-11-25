import { describe, expect, it } from 'vitest';
import { checkKey, decideKey } from './check';
import type { Op } from './model';

const mk = (res: Op['res'], lo: number, call: number, ret: number): Op => ({
  client: 'c',
  kind: 'advance',
  key: 'k',
  lo,
  w: lo,
  call,
  ret: res === 'unknown' ? Infinity : ret,
  res,
});

describe('decideKey / checkKey details', () => {
  it('an overlap violation keeps every operation it was given', () => {
    const ops = [mk('true', 1, 0, 5), mk('true', 1, 2, 7), mk('false', 0, 10, 11)];
    const r = decideKey(ops);
    expect(r.method).toBe('overlap');
    expect(r.kept).toEqual(ops);
    expect(r.kept).not.toBe(ops);
  });
  it('checkKey applies a positive budget (a one-state budget cannot decide a key that needs two)', () => {
    const ops = [mk('unknown', 1, 0, 0), mk('false', 1, 2, 3)];
    expect(checkKey(ops, { budget: 1 }).verdict).toBe('unresolved');
    expect(checkKey(ops).verdict).toBe('ok');
  });
});
