/** createMultiRootVerifierVerified freezes its policy: using it never reads the caller's configuration after construction. */
import { describe, expect, it } from 'vitest';
import { createMultiRootVerifierVerified } from '../src/ext-attest';

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
  return { value: wrap(value, 'policy') as T, arm: () => { armed = true; }, reads };
}
class FixedVerifier {
  async verify() { return { ok: false, reason: 'fixed' }; }
}

describe('createMultiRootVerifierVerified configuration snapshot', () => {
  it('never reads the caller policy after construction (emptying roots later changes nothing)', async () => {
    const rec = recorder({ roots: [{ id: 'a', verifier: new FixedVerifier(), required: true }, { id: 'b', verifier: new FixedVerifier() }], threshold: 1 });
    const v = createMultiRootVerifierVerified(rec.value as never);
    rec.arm();
    try { await v.verify({ document: {}, ctx: {}, nowMs: 1, expected: { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' } } as never); } catch { /* only the reads matter */ }
    expect(rec.reads).toEqual([]);
  });
});
