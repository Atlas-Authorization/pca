/** Round 2: the gateway freezes its configuration at construction (routes, audience, ...). */
import { describe, expect, it } from 'vitest';
import { createGateway } from './index';

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

describe('createGateway configuration snapshot', () => {
  it('never reads the caller configuration after construction (emptying routes later changes nothing)', async () => {
    const rec = recorder({ audience: 'aud', routes: [{ method: 'GET', path: '/x', verb: 'read', resource: 'r' }], resolveGrant: async () => null, unmatchedRoute: 'deny', insecureSkipPlanRootCheck: true, policy: { mode: 'signature-only' }, replayGuard: { claim: async () => true }, requireChecks: [] });
    const gw = createGateway(rec.value as never);
    rec.arm();
    try { await gw({ method: 'GET', path: '/x', headers: {} } as never); } catch { /* only the reads matter */ }
    expect(rec.reads).toEqual([]);
  });
});
