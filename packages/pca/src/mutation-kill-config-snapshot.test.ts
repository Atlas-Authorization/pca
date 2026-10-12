/** Mutation-kill tests for snapshotConfig: identity of shared values, ArrayBuffer copies, null-prototype objects, enumerability, nullish `keep` inputs. */
import { describe, expect, it } from 'vitest';
import { snapshotConfig } from './config-snapshot';

describe('snapshotConfig', () => {
  it('a value referenced twice snapshots to ONE copy (typed array, ArrayBuffer, Date, Map, Set)', () => {
    const u = new Uint8Array([1, 2]);
    const ab = new ArrayBuffer(2);
    const d = new Date(5);
    const m = new Map([[1, 2]]);
    const st = new Set([1]);
    const s = snapshotConfig({ u1: u, u2: u, a1: ab, a2: ab, d1: d, d2: d, m1: m, m2: m, s1: st, s2: st });
    expect(s.u1).toBe(s.u2);
    expect(s.a1).toBe(s.a2);
    expect(s.d1).toBe(s.d2);
    expect(s.m1).toBe(s.m2);
    expect(s.s1).toBe(s.s2);
    expect(s.u1).not.toBe(u);
    expect(s.d1).not.toBe(d);
    expect(s.m1).not.toBe(m);
    expect(s.s1).not.toBe(st);
  });
  it('an ArrayBuffer is copied (unshared), with its bytes', () => {
    const ab = new Uint8Array([7, 8, 9]).buffer;
    const s = snapshotConfig({ b: ab });
    expect(s.b).toBeInstanceOf(ArrayBuffer);
    expect(s.b).not.toBe(ab);
    expect([...new Uint8Array(s.b)]).toEqual([7, 8, 9]);
    new Uint8Array(ab)[0] = 0;
    expect(new Uint8Array(s.b)[0]).toBe(7);
  });
  it('a null-prototype object is plain data: copied, frozen, null prototype kept', () => {
    const o = Object.create(null) as Record<string, unknown>;
    o.list = [1];
    const s = snapshotConfig({ o });
    expect(s.o).not.toBe(o);
    expect(Object.isFrozen(s.o)).toBe(true);
    expect(Object.getPrototypeOf(s.o)).toBeNull();
    expect(Object.isFrozen(s.o.list)).toBe(true);
  });
  it('an ordinary object copy keeps Object.prototype', () => {
    const s = snapshotConfig({ a: { x: 1 } });
    expect(Object.getPrototypeOf(s)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(s.a)).toBe(Object.prototype);
  });
  it('non-enumerable own properties are not copied', () => {
    const o: Record<string, unknown> = { v: 1 };
    Object.defineProperty(o, 'hidden', { value: 2, enumerable: false });
    const s = snapshotConfig({ o }) as { o: Record<string, unknown> };
    expect(Object.keys(s.o)).toEqual(['v']);
    expect('hidden' in s.o).toBe(false);
  });
  it('a data property is snapshotted from its descriptor value, not through a get trap', () => {
    const p = new Proxy({ a: 1 } as Record<string, unknown>, { get: () => 2 });
    expect({ ...(snapshotConfig({ p }).p as object) }).toEqual({ a: 1 });
  });
  it('null / undefined with a keep list are returned as-is (never throw)', () => {
    expect(snapshotConfig(null, { keep: ['a'] })).toBeNull();
    expect(snapshotConfig(undefined, { keep: ['a'] })).toBeUndefined();
  });
});
