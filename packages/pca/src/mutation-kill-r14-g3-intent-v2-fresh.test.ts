/**
 * r14 (g3) static-mutant kills for intent-v2.ts: the module-level helpers optObj, optArr, isObj, isNonNeg, own and bad are
 * built once at import. Each test re-evaluates the module (vi.resetModules + dynamic import) and replays the pinned
 * killV2 decide / active tables through it (every check, exact reason, the strict canonical env), plus the context
 * shape checks those helpers decide.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { assert, describe, expect, it, vi } from 'vitest';

// Speed only, semantics unchanged: these tables re-verify the same few Ed25519 signatures tens of thousands of times
// (pure-JS bigint arithmetic, ~35 ms a case). The verdicts of the PURE functions ed25519.verify and point decoding /
// small-order / torsion checks are memoized by their exact input bytes, so a mutant that changes a signed message, key
// or signature still reaches the real arithmetic.
vi.mock('@noble/curves/ed25519', async (importOriginal) => {
  const m: any = await importOriginal();
  const ed = m.ed25519;
  const hex = (x: unknown) => (typeof x === 'string' ? 's' + x : x instanceof Uint8Array ? Buffer.from(x).toString('hex') : 'o' + String(x));
  const vc = new Map<string, { v?: boolean; e?: unknown }>();
  const verify = (sig: any, msg: any, pk: any, opts?: any) => {
    const k = `${hex(sig)}|${hex(msg)}|${hex(pk)}|${JSON.stringify(opts ?? null)}`;
    let r = vc.get(k);
    if (r === undefined) {
      try { r = { v: ed.verify(sig, msg, pk, opts) }; } catch (e) { r = { e }; }
      vc.set(k, r);
    }
    if ('e' in r) throw r.e;
    return r.v;
  };
  const EP = ed.ExtendedPoint;
  const pc = new Map<string, { p?: any; e?: unknown }>();
  const fromHex = (h: any, ...rest: any[]) => {
    const k = hex(h) + '|' + JSON.stringify(rest);
    let r = pc.get(k);
    if (r === undefined) {
      try {
        const p = EP.fromHex(h, ...rest);
        const memo = new Map<PropertyKey, boolean>();
        // the points are frozen: memoize the two predicates through a proxy (they live on the prototype)
        r = { p: new Proxy(p, { get: (t, f) => (f === 'isSmallOrder' || f === 'isTorsionFree' ? () => { if (!memo.has(f)) memo.set(f, t[f]()); return memo.get(f); } : Reflect.get(t, f)) }) };
      } catch (e) { r = { e }; }
      pc.set(k, r);
    }
    if ('e' in r) throw r.e;
    return r.p;
  };
  const EPx = new Proxy(EP, { get: (t, k) => (k === 'fromHex' ? fromHex : Reflect.get(t, k)) });
  return { ...m, ed25519: new Proxy(ed, { get: (t, k) => (k === 'verify' ? verify : k === 'ExtendedPoint' ? EPx : Reflect.get(t, k)) }) };
});

const V = JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', 'killV2.json.gz'))).toString('utf8'));
const toTs = (x: any): any => {
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o: any = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};
const noThrow = <A extends unknown[], R>(name: string, f: (...a: A) => R) => (...a: A): R => {
  try { return f(...a); } catch (e) { return assert.fail(`${name} threw: ${(e as Error)?.message ?? String(e)}`); }
};
async function fresh() {
  vi.resetModules();
  const m = await import('./intent-v2');
  const h = await import('./hash');
  return { m, h, decide: noThrow('decideIntentV2', m.decideIntentV2), active: noThrow('intentV2Active', m.intentV2Active), ctxErr: noThrow('intentV2ContextError', m.intentV2ContextError) };
}

describe('intent-v2.ts (fresh module)', () => {
  it('context shape: absent members are defaults, present ones are typed', async () => {
    const f = await fresh();
    expect(f.ctxErr({})).toBeNull();
    expect(f.ctxErr({ policy: {}, params: {}, schema: { docs: [], keys: [] }, session: {}, acc: {}, map: {} })).toBeNull();
    expect(f.ctxErr({ wb: { artifacts: { facts: [], labels: [], verdicts: [], offer_set: {} }, policy: { classifiers: [] } } })).toBeNull();
    expect(f.ctxErr({ wb: { artifacts: { facts: {} } } })).toBe('wb.artifacts.facts must be an array');
    expect(f.ctxErr({ policy: null })).toBe('policy must be an object');
  });
  it('killV2 decide: every check [name, ok, reason] and the strict canonical env', async () => {
    const f = await fresh();
    for (const c of V.decide) {
      if (c.name === 'corpus/acc-state-own-proto-key') continue; // the golden file lost this input (see mutation-kill-r13-g3-v2-replay.test.ts)
      const d = f.decide(toTs(c.p), toTs(c.grant), c.ctx === undefined ? undefined : toTs(c.ctx), c.now);
      expect({ checks: d.checks.map((k: any) => [k.name, k.ok, k.reason ?? null]), env: f.h.canonicalizeStrict((d.env ?? {}) as any) }, c.name).toEqual({ checks: c.checks, env: c.env });
    }
  });
  it('killV2 active: intentV2Active', async () => {
    const f = await fresh();
    for (const c of V.active) expect(f.active(toTs(c.p), c.ctx === undefined ? undefined : toTs(c.ctx)), c.name).toBe(c.want);
  });
});
