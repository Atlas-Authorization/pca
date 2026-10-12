/** Round 2: the hybrid threshold verifier freezes its configuration (PQ pool, authorities, descriptor) at construction. */
import { describe, expect, it } from 'vitest';
import { createHybridThresholdVerifier } from './index';

/** Deep recording proxy over arrays and plain objects (functions and class instances are left alone). */
function recorder<T>(value: T): { value: T; arm: () => void; reads: string[] } {
  const reads: string[] = [];
  let armed = false;
  const cache = new WeakMap<object, unknown>();
  const wrap = (v: unknown, path: string): unknown => {
    if (v === null || typeof v !== 'object') return v;
    const proto = Object.getPrototypeOf(v);
    if (!Array.isArray(v) && proto !== Object.prototype && proto !== null) return v;
    if (cache.has(v)) return cache.get(v);
    const p = new Proxy(v as object, {
      get(t, k, r) {
        if (armed) reads.push(`${path}.${String(k)}`);
        return wrap(Reflect.get(t, k, r), `${path}.${String(k)}`);
      },
    });
    cache.set(v, p);
    return p;
  };
  return { value: wrap(value, 'opts') as T, arm: () => { armed = true; }, reads };
}

describe('createHybridThresholdVerifier configuration snapshot', () => {
  it('never reads the caller configuration after construction', () => {
    const rec = recorder({ groupKey: 'g', pqPublicKeys: ['p'], t: 1, pqT: 1, pqBlock: { alg: 'x', signers: [] }, groupDescriptor: { body: { t: 1 }, sig: 's' }, trustedAuthorities: ['a'] });
    const v = createHybridThresholdVerifier(rec.value as never);
    rec.arm();
    try { v({ pcactn: { action: {} } } as never); } catch { /* only the reads matter */ }
    expect(rec.reads).toEqual([]);
  });
});
