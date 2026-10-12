import { describe, expect, it } from 'vitest';
import { PRIME } from '../field';
import { type AW, type PA, type PaEnv, awFlat, awParse, awWidth, paAdd, paAddPublic0, paFlat, paNeg, paParse, paScale, paSub, paVerify, paWidth, wAdd, wAddPublic, wNeg, wScale, wSub } from './pa';

const P = PRIME;
const pa = (x: bigint, tag: bigint[], key: bigint[]): PA => ({ x, tag, key });
const A = pa(10n, [1n, 2n, 3n], [4n, 5n, 6n]);
const B = pa(P - 1n, [P - 1n, 20n, 30n], [40n, P - 2n, 60n]);

describe('PA arithmetic is elementwise and reduced mod p', () => {
  it('paAdd', () => {
    expect(paAdd(A, B)).toEqual(pa(9n, [0n, 22n, 33n], [44n, 3n, 66n]));
  });
  it('paSub', () => {
    expect(paSub(A, B)).toEqual(pa(11n, [2n, P - 18n, P - 27n], [P - 36n, 7n, P - 54n]));
    expect(paSub(A, A)).toEqual(pa(0n, [0n, 0n, 0n], [0n, 0n, 0n]));
  });
  it('paNeg', () => {
    expect(paNeg(A)).toEqual(pa(P - 10n, [P - 1n, P - 2n, P - 3n], [P - 4n, P - 5n, P - 6n]));
    expect(paNeg(pa(0n, [0n], [0n]))).toEqual(pa(0n, [0n], [0n]));
  });
  it('paScale', () => {
    expect(paScale(A, 3n)).toEqual(pa(30n, [3n, 6n, 9n], [12n, 15n, 18n]));
    expect(paScale(B, 2n)).toEqual(pa(P - 2n, [P - 2n, 40n, 60n], [80n, P - 4n, 120n]));
    expect(paScale(A, 0n)).toEqual(pa(0n, [0n, 0n, 0n], [0n, 0n, 0n]));
  });
  it('does not mutate its inputs', () => {
    const a = pa(1n, [2n], [3n]);
    const b = pa(4n, [5n], [6n]);
    paAdd(a, b);
    paSub(a, b);
    paNeg(a);
    paScale(a, 9n);
    expect(a).toEqual(pa(1n, [2n], [3n]));
    expect(b).toEqual(pa(4n, [5n], [6n]));
  });
});

describe('paAddPublic0', () => {
  const env = (id: number, tagged: boolean): PaEnv => ({ id, n: 3, delta: 7n, tagged });
  it('party 0 moves only x (tags and keys untouched)', () => {
    const r = paAddPublic0(env(0, true), A, 5n);
    expect(r).toEqual(pa(15n, [1n, 2n, 3n], [4n, 5n, 6n]));
    expect(paAddPublic0(env(0, false), A, 5n)).toEqual(pa(15n, [1n, 2n, 3n], [4n, 5n, 6n]));
    expect(paAddPublic0(env(0, true), pa(P - 1n, [], []), 3n).x).toBe(2n);
  });
  it('other tagged parties re-key K_0j <- K_0j - delta*c and leave x and tags alone', () => {
    const r = paAddPublic0(env(2, true), A, 5n);
    expect(r).toEqual(pa(10n, [1n, 2n, 3n], [4n - 35n + P, 5n, 6n]));
    expect(A.key).toEqual([4n, 5n, 6n]); // input not mutated
    expect(paAddPublic0(env(1, true), pa(0n, [0n], [3n]), 1n).key[0]).toBe(P - 4n);
  });
  it('untagged other parties return the share unchanged (same object)', () => {
    expect(paAddPublic0(env(1, false), A, 5n)).toBe(A);
  });
});

describe('AW arithmetic', () => {
  const w = (v: PA, ...m: PA[]): AW => ({ v, m });
  const X = w(A, pa(1n, [1n, 1n, 1n], [1n, 1n, 1n]), pa(2n, [2n, 2n, 2n], [2n, 2n, 2n]));
  const Y = w(pa(5n, [5n, 5n, 5n], [5n, 5n, 5n]), pa(7n, [0n, 0n, 0n], [0n, 0n, 0n]), pa(P - 1n, [P - 1n, P - 1n, P - 1n], [P - 1n, P - 1n, P - 1n]));
  it('wAdd / wSub apply to the value and every MAC component, in order', () => {
    const s = wAdd(X, Y);
    expect(s.v).toEqual(paAdd(X.v, Y.v));
    expect(s.m).toEqual([paAdd(X.m[0]!, Y.m[0]!), paAdd(X.m[1]!, Y.m[1]!)]);
    expect(s.m[1]!.x).toBe(1n);
    const d = wSub(X, Y);
    expect(d.v).toEqual(paSub(X.v, Y.v));
    expect(d.m).toEqual([paSub(X.m[0]!, Y.m[0]!), paSub(X.m[1]!, Y.m[1]!)]);
    expect(d.m[0]!.x).toBe(P - 6n);
  });
  it('wNeg / wScale', () => {
    expect(wNeg(X)).toEqual({ v: paNeg(X.v), m: X.m.map(paNeg) });
    expect(wNeg(X).m[1]!.x).toBe(P - 2n);
    expect(wScale(X, 3n)).toEqual({ v: paScale(X.v, 3n), m: X.m.map((p) => paScale(p, 3n)) });
    expect(wScale(X, 3n).m[1]!.x).toBe(6n);
  });
  it('wAddPublic moves party 0\'s value by c and each MAC share l by alpha_l * c', () => {
    const alpha = [pa(3n, [1n, 1n, 1n], [2n, 2n, 2n]), pa(4n, [5n, 5n, 5n], [6n, 6n, 6n])];
    const e0: PaEnv = { id: 0, n: 3, delta: 7n, tagged: true };
    const r0 = wAddPublic(e0, X, 10n, alpha);
    expect(r0.v).toEqual(paAddPublic0(e0, X.v, 10n));
    expect(r0.m[0]).toEqual(paAdd(X.m[0]!, paScale(alpha[0]!, 10n)));
    expect(r0.m[1]).toEqual(paAdd(X.m[1]!, paScale(alpha[1]!, 10n)));
    expect(r0.m[1]!.x).toBe(2n + 40n);
    expect(r0.v.x).toBe(20n);
    const e1: PaEnv = { id: 1, n: 3, delta: 7n, tagged: true };
    const r1 = wAddPublic(e1, X, 10n, alpha);
    expect(r1.v.x).toBe(10n);
    expect(r1.v.key[0]).toBe(P + 4n - 70n);
  });
});

describe('paVerify', () => {
  const env: PaEnv = { id: 0, n: 3, delta: 7n, tagged: true };
  it('accepts exactly tag = key[from] + delta * x', () => {
    const a = pa(0n, [0n, 0n, 0n], [0n, 100n, 200n]);
    expect(paVerify(env, a, 1, 3n, 121n)).toBe(true);
    expect(paVerify(env, a, 2, 3n, 221n)).toBe(true);
    expect(paVerify(env, a, 1, 3n, 122n)).toBe(false);
    expect(paVerify(env, a, 1, 4n, 121n)).toBe(false);
    expect(paVerify(env, a, 2, 3n, 121n)).toBe(false);
    expect(paVerify(env, pa(0n, [], [P - 1n, 0n]), 0, 1n, 6n)).toBe(true); // wraps mod p
  });
});

describe('wire codec', () => {
  it('widths', () => {
    expect(paWidth(4, true)).toBe(7);
    expect(paWidth(2, true)).toBe(3);
    expect(paWidth(4, false)).toBe(1);
    expect(awWidth(3, 2, true)).toBe(15);
    expect(awWidth(3, 2, false)).toBe(3);
    expect(awWidth(4, 0, true)).toBe(7);
  });
  const full = pa(1n, [10n, 11n, 12n, 13n], [20n, 21n, 22n, 23n]);
  it('paFlat: x, then tags of the others ascending, then keys of the others ascending', () => {
    expect(paFlat(full, 2, 4, true)).toEqual([1n, 10n, 11n, 13n, 20n, 21n, 23n]);
    expect(paFlat(full, 0, 4, true)).toEqual([1n, 11n, 12n, 13n, 21n, 22n, 23n]);
    expect(paFlat(full, 3, 4, true)).toEqual([1n, 10n, 11n, 12n, 20n, 21n, 22n]);
    expect(paFlat(full, 2, 4, false)).toEqual([1n]);
  });
  it('paParse inverts paFlat at any offset (own slot zero) and honours untagged', () => {
    const flat = paFlat(full, 2, 4, true);
    const padded = [99n, 98n, ...flat, 97n];
    expect(paParse(padded, 2, 2, 4, true)).toEqual(pa(1n, [10n, 11n, 0n, 13n], [20n, 21n, 0n, 23n]));
    expect(paParse(flat, 0, 0, 4, true)).toEqual(pa(1n, [0n, 10n, 11n, 13n], [0n, 20n, 21n, 23n]));
    expect(paParse([5n, 6n], 1, 1, 4, false)).toEqual(pa(6n, [], []));
    expect(paParse([5n], 0, 0, 2, false)).toEqual(pa(5n, [], []));
  });
  it('awFlat / awParse roundtrip value then each MAC share in order', () => {
    const m1 = pa(2n, [30n, 31n, 32n, 33n], [40n, 41n, 42n, 43n]);
    const m2 = pa(3n, [50n, 51n, 52n, 53n], [60n, 61n, 62n, 63n]);
    const aw: AW = { v: full, m: [m1, m2] };
    const flat = awFlat(aw, 1, 4, true);
    expect(flat.length).toBe(awWidth(4, 2, true));
    expect(flat).toEqual([...paFlat(full, 1, 4, true), ...paFlat(m1, 1, 4, true), ...paFlat(m2, 1, 4, true)]);
    const back = awParse([7n, ...flat], 1, 1, 4, 2, true);
    expect(back.v).toEqual(paParse(flat, 0, 1, 4, true));
    expect(back.m[0]).toEqual(paParse(flat, 7, 1, 4, true));
    expect(back.m[1]).toEqual(paParse(flat, 14, 1, 4, true));
    expect(back.m.length).toBe(2);
    expect(back.m[1]!.x).toBe(3n);
    const u: AW = { v: pa(1n, [], []), m: [pa(2n, [], []), pa(3n, [], [])] };
    expect(awFlat(u, 0, 3, false)).toEqual([1n, 2n, 3n]);
    expect(awParse([1n, 2n, 3n], 0, 0, 3, 2, false)).toEqual({ v: pa(1n, [], []), m: [pa(2n, [], []), pa(3n, [], [])] });
    expect(awParse([1n], 0, 0, 3, 0, false).m).toEqual([]);
  });
});
