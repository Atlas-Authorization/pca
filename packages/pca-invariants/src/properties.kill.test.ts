/**
 * Branch-level checks of the invariant properties. Each property is executed directly on a hand-built input (`property.run`)
 * against the real core or against a core with one function replaced, so every guard of a property is shown to bite: a guard
 * that stops rejecting (or starts rejecting a legal input) changes the verdict asserted here. The generated-input domains of
 * the properties are checked with `fc.sample` on the property itself, and the runner/registry glue by counting core calls.
 */
import fc from 'fast-check';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type Capability, type Caveat, delegate, encodeKey, hashCanonical, sign } from '@atlasauth/pca';
import { type CaveatSpec, type GeneratedChain, buildChain, keyPairFromSeed } from './arbitraries';

type Props = typeof import('./properties');
type Real = Record<string, unknown>;
type Fn = (...a: unknown[]) => unknown;
type Verdict = 'ok' | 'false' | 'threw';

afterEach(() => {
  vi.resetModules();
  vi.doUnmock('@atlasauth/pca');
});

/** Load `./properties` against the real core with `patch(real)` laid over its exports. */
async function load(patch: (real: Real) => Real = () => ({})): Promise<Props> {
  vi.resetModules();
  vi.doMock('@atlasauth/pca', async (orig) => {
    const real = (await orig()) as Real;
    return { ...real, ...patch(real) };
  });
  return (await import('./properties')) as Props;
}

const call = (f: unknown, ...a: unknown[]): unknown => (f as Fn)(...a);

interface Runnable {
  run(v: unknown, dontRunHook: boolean): unknown;
}

/** Run a property on exactly one input: 'ok' = passed, 'false' = returned false, 'threw' = raised an error. */
function verdict(prop: Runnable, input: unknown[]): Verdict {
  const r = prop.run(input, true) as null | { error?: unknown; errorMessage?: unknown };
  if (r === null) return 'ok';
  return /returning false/.test(String(r.errorMessage ?? r.error)) ? 'false' : 'threw';
}

const inv = (m: Props, name: string) => m.INVARIANTS.find((i) => i.name === name)!;
const uniq = <T>(xs: T[]): T[] => [...new Set(xs)];
const flip = (): (() => boolean) => {
  let n = 0;
  return () => n++ % 2 === 0;
};

const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const mk = (rootSpecs: CaveatSpec[], hops: CaveatSpec[][] = []): GeneratedChain =>
  buildChain({
    principalSeed: seed(1),
    holder0Seed: seed(2),
    rootSpecs,
    hops: hops.map((addedSpecs, i) => ({ holderSeed: seed(3 + i), addedSpecs })),
    predicates: [{ verb: '*' }],
  });
const G1 = (): GeneratedChain => mk([{ k: 'expires', at: 500 }, { k: 'not_before', at: 1 }]);
const G2 = (): GeneratedChain => mk([{ k: 'expires', at: 500 }, { k: 'not_before', at: 1 }], [[{ k: 'delegation_depth', max: 2 }]]);
const G3 = (): GeneratedChain =>
  mk([{ k: 'expires', at: 500 }, { k: 'rate', max: 3, per_secs: 60 }], [[{ k: 'delegation_depth', max: 2 }], [{ k: 'not_before', at: 1 }]]);
const withCaps = (g: GeneratedChain, caps: unknown[]): GeneratedChain => ({ ...g, caps: caps as Capability[] });
const hole = undefined as never;

const PT = { action: { verb: 'read', resource: '/x' }, cavCtx: { now: 5 } };
const POL = { weights: { alpha: 1, beta: 1, gamma: 1, delta: 1, epsilon: 1, zeta: 1 }, theta1: 0.3, theta2: 0.6, kappa: 1, lambda: 0, rho: 0, bMax: 5 };
const IN = { semanticDistance: 0.5, reversibility: 0.5, blastRadius: 0.5, taint: 0.5, confidence: 0.5, age: 0.5 };
const DL = { dSem: 0.1, dBlast: 0.1, dTaint: 0.1, dAge: 0.1, dRev: 0.1, dConf: 0.1 };
const NOT_ADMIT = { admit: false, needStepUp: true, t: 3, metered: false };
const AUTO = { admit: true, needStepUp: false, t: 1, metered: true };

// ================================== 1. attenuation ==================================

describe('attenuation-monotonicity: branch behaviour', () => {
  const okVerify = () => ({ verifyChain: () => ({ ok: true }) });
  const run = async (patch: (r: Real) => Real, g: GeneratedChain, points: unknown[] = [PT]): Promise<Verdict> =>
    verdict((await load(patch)).attenuationMonotonicityProperty(), [g, points]);

  it('accepts a legal chain on the real core', async () => {
    expect(await run(() => ({}), G3())).toBe('ok');
    expect(await run(() => ({}), G1())).toBe('ok');
  });

  it('rejects a chain the verifier refuses', async () => {
    expect(await run(() => ({ verifyChain: () => ({ ok: false }) }), G2())).toBe('false');
  });

  it('rejects a child whose caveats are not an append-only extension of its parent', async () => {
    const g = G2();
    const [c0, c1] = g.caps as [Capability, Capability];
    expect(await run(okVerify, g)).toBe('ok');
    // shorter than the parent
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [] }]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: c1.caveats.slice(0, 1) }]))).toBe('false');
    // same length, first caveat different
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [{ type: 'expires', at: 1 }, ...c1.caveats.slice(1)] }]))).toBe('false');
    // same length, last parent caveat different
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [c1.caveats[0]!, { type: 'not_before', at: 2 }, c1.caveats[2]!] }]))).toBe('false');
    // longer than the parent but still the same prefix is fine
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [...c1.caveats, { type: 'not_before', at: 3 }] }]))).toBe('ok');
  });

  it('rejects a hole in the child or the parent caveat list as a plain false verdict', async () => {
    const g = G2();
    const [c0, c1] = g.caps as [Capability, Capability];
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [hole, ...c1.caveats.slice(1)] }]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [c0, { ...c1, caveats: [c1.caveats[0]!, hole, c1.caveats[2]!] }]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [{ ...c0, caveats: [hole, c0.caveats[1]!] }, c1]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [{ ...c0, caveats: [c0.caveats[0]!, hole] }, c1]))).toBe('false');
  });

  it('rejects a missing hop (an empty slot in the chain) as a plain false verdict', async () => {
    const g = G2();
    const [c0, c1] = g.caps as [Capability, Capability];
    expect(await run(okVerify, withCaps(g, [c0, hole]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [hole, c1]))).toBe('false');
    expect(await run(okVerify, withCaps(g, [c0, c1, hole]))).toBe('false');
  });

  it('rejects an empty chain (no leaf) as a plain false verdict', async () => {
    expect(await run(okVerify, withCaps(G1(), []))).toBe('false');
  });

  it('rejects a leaf whose carried budget allocation is not monotone', async () => {
    const g = G1();
    const one = (cv: unknown[]): GeneratedChain => withCaps(g, [{ ...g.caps[0]!, caveats: cv }]);
    // negative limit: the core refuses it; the numeric check alone would not
    expect(await run(okVerify, one([{ type: 'budget_alloc', limit: -1 }]))).toBe('false');
    expect(await run(okVerify, one([{ type: 'budget_alloc', limit: 20 }, { type: 'budget_alloc', limit: 10 }]))).toBe('ok');
  });

  it('checks the numeric allocation order itself, reading only numeric limits of budget_alloc caveats', async () => {
    const g = G1();
    const one = (cv: unknown[]): GeneratedChain => withCaps(g, [{ ...g.caps[0]!, caveats: cv }]);
    const patch = (): Real => ({ ...okVerify(), allocationsMonotone: () => ({ ok: true }) });
    const a = (limit: unknown): unknown => ({ type: 'budget_alloc', limit });
    expect(await run(patch, one([a(10), a(20)]))).toBe('false');
    expect(await run(patch, one([a(20), a(10)]))).toBe('ok');
    expect(await run(patch, one([a(10), a(10)]))).toBe('ok');
    expect(await run(patch, one([a(10), { type: 'rate', limit: 20 }]))).toBe('ok');
    expect(await run(patch, one([a(10), a('20')]))).toBe('ok');
    expect(await run(patch, one([a(10), { limit: 20 }]))).toBe('ok');
    expect(await run(patch, one([null, a(10)]))).toBe('ok');
    expect(await run(patch, one([5, a(10)]))).toBe('ok');
    expect(await run(patch, one([a(10), Object.assign(() => 0, { type: 'budget_alloc', limit: 99 })]))).toBe('ok');
    expect(await run(patch, one([a(5), a(10), a(1)]))).toBe('false');
    expect(await run(patch, one([a(30), a(20), a(25)]))).toBe('false');
  });

  const widening = (): Real => ({
    verifyChain: () => ({ ok: true }),
    evaluatePredicates: () => ({ allowed: true }),
    evaluateCaveats: (cavs: unknown) => ({ ok: (cavs as unknown[]).length >= 3, failed: [] }),
  });
  const gw = (): GeneratedChain => mk([{ k: 'expires', at: 500 }], [[{ k: 'not_before', at: 1 }, { k: 'delegation_depth', max: 2 }]]);

  it('rejects a core under which a descendant is allowed where its ancestor was not', async () => {
    expect(await run(widening, gw())).toBe('false');
    // the same core on a chain that never gains authority is fine
    expect(await run(widening, mk([{ k: 'expires', at: 500 }, { k: 'not_before', at: 1 }, { k: 'delegation_depth', max: 2 }], [[]]))).toBe('ok');
  });

  it('reads a predicate denial as "not allowed" for every hop, so caveat widening behind a denial is not a violation', async () => {
    const deny = (): Real => ({ ...widening(), evaluatePredicates: () => ({ allowed: false }) });
    expect(await run(deny, gw())).toBe('ok');
  });

  it('treats a predicate verdict that flips from denied to allowed down the chain as widening', async () => {
    const alt = (): Real => {
      let n = 0;
      return { verifyChain: () => ({ ok: true }), evaluatePredicates: () => ({ allowed: n++ % 2 === 1 }), evaluateCaveats: () => ({ ok: true, failed: [] }) };
    };
    expect(await run(alt, G2())).toBe('false');
  });

  it('probes every point against every hop', async () => {
    const seen: string[] = [];
    const rec = (r: Real): Real => ({
      evaluatePredicates: (...a: unknown[]) => {
        seen.push(JSON.stringify(a[1]));
        return call(r.evaluatePredicates, ...a);
      },
    });
    const p2 = { action: { verb: 'write', resource: '/y' }, cavCtx: { now: 6 } };
    expect(await run(rec, G2(), [PT, p2])).toBe('ok');
    expect(seen).toEqual([PT, PT, p2, p2].map((p) => JSON.stringify(p.action)));
  });

  it('draws one to five probe points per chain', () => {
    return load().then((m) => {
      const lens = fc.sample(m.attenuationMonotonicityProperty(), { numRuns: 200, seed: 11 }).map((t) => t[1].length);
      expect(Math.min(...lens)).toBe(1);
      expect(Math.max(...lens)).toBe(5);
    });
  });
});

// ================================= 2. budget soundness ================================

describe('risk-wellformed-and-monotone: branch behaviour', () => {
  async function risk(rs: number[]) {
    const q = [...rs];
    let calls = 0;
    const m = await load(() => ({
      riskScore: () => {
        calls++;
        if (q.length === 0) throw new Error('unexpected extra riskScore call');
        return q.shift();
      },
    }));
    return { v: verdict(m.riskMonotoneProperty(), [POL, IN, DL]), get calls() { return calls; } };
  }

  it('accepts a clamped, monotone pair (including the boundary values)', async () => {
    expect((await risk([0.5, 0.6])).v).toBe('ok');
    expect((await risk([0, 0])).v).toBe('ok');
    expect((await risk([1, 1])).v).toBe('ok');
    expect((await risk([0.5, 0.5])).v).toBe('ok');
    expect((await risk([1e-9, 0])).v).toBe('ok');
  });

  it('rejects an out-of-range base score without scoring the worsened input', async () => {
    for (const r of [-0.1, 1.5, Number.NaN, 2]) {
      const c = await risk([r]);
      expect(c.v).toBe('false');
      expect(c.calls).toBe(1);
    }
  });

  it('rejects an out-of-range worsened score', async () => {
    expect((await risk([0.5, 1.5])).v).toBe('false');
    expect((await risk([0.5, -0.1])).v).toBe('false');
    expect((await risk([0, -5e-10])).v).toBe('false');
    expect((await risk([0.2, Number.NaN])).v).toBe('false');
  });

  it('rejects a worsened input that scores lower', async () => {
    expect((await risk([0.5, 0.4])).v).toBe('false');
    expect((await risk([0.5, 0.5 - 1e-6])).v).toBe('false');
  });

  it('scores the base and the worsened inputs, in that order', async () => {
    const seen: unknown[] = [];
    const m = await load((r) => ({
      riskScore: (i: unknown, w: unknown) => {
        seen.push([i, w]);
        return call(r.riskScore, i, w);
      },
    }));
    expect(verdict(m.riskMonotoneProperty(), [POL, IN, DL])).toBe('ok');
    expect(seen).toHaveLength(2);
    expect(seen[0]).toEqual([IN, POL.weights]);
    expect(seen[1]).toEqual([
      { semanticDistance: 0.6, reversibility: 0.4, blastRadius: 0.6, taint: 0.6, confidence: 0.4, age: 0.6 },
      POL.weights,
    ]);
  });
});

describe('admission-soundness: branch behaviour', () => {
  interface O { valid?: string | null; c?: number; a?: unknown; sb?: number }
  async function adm(o: O, policy: unknown = POL, budget: unknown = { B: 10, tau: 0 }): Promise<Verdict> {
    const m = await load(() => ({
      ...(o.valid !== undefined ? { validateRiskPolicy: () => o.valid } : {}),
      riskScore: () => 0.5,
      cost: () => o.c ?? 0.1,
      admit: () => o.a ?? NOT_ADMIT,
      ...(o.sb !== undefined ? { safetyBound: () => o.sb } : {}),
    }));
    return verdict(m.admissionSoundnessProperty(), [policy, IN, budget]);
  }

  it('accepts an escalation and the real safety bound', async () => {
    expect(await adm({})).toBe('ok');
  });

  it('refuses a generated policy the validator rejects', async () => {
    expect(await adm({ valid: 'kappa must be > 0' })).toBe('false');
  });

  it('a metered action must be machine-only (t < 3)', async () => {
    expect(await adm({ a: { admit: false, needStepUp: true, t: 3, metered: true } })).toBe('false');
    expect(await adm({ a: { admit: false, needStepUp: true, t: 4, metered: true } })).toBe('false');
    expect(await adm({ a: { admit: false, needStepUp: true, t: 2, metered: true } })).toBe('ok');
  });

  it('a metered action must be covered by the budget (boundary: B + 1e-9 == c is covered)', async () => {
    const t2 = { admit: false, needStepUp: true, t: 2, metered: true };
    expect(await adm({ a: t2, c: 0.5 }, POL, { B: 0.4, tau: 0 })).toBe('false');
    expect(await adm({ a: t2, c: 1e-9 }, POL, { B: 0, tau: 0 })).toBe('ok');
    expect(await adm({ a: t2, c: 0.5 }, POL, { B: 0.5, tau: 0 })).toBe('ok');
  });

  it('an auto-admit must be t = 1, metered, and covered', async () => {
    expect(await adm({ a: AUTO })).toBe('ok');
    expect(await adm({ a: AUTO, c: 1e-9 }, POL, { B: 0, tau: 0 })).toBe('ok');
    expect(await adm({ a: AUTO, c: 0.5 }, POL, { B: 0.4, tau: 0 })).toBe('false');
    expect(await adm({ a: { ...AUTO, t: 2 } })).toBe('false');
    expect(await adm({ a: { ...AUTO, metered: false } })).toBe('false');
    expect(await adm({ a: { ...AUTO, t: 2, metered: false } })).toBe('false');
  });

  it('the safety bound must equal bMax / kappa (0 when kappa is not positive)', async () => {
    expect(await adm({ sb: 5 })).toBe('ok');
    expect(await adm({ sb: 99 })).toBe('false');
    expect(await adm({ sb: 4.999 })).toBe('false');
    expect(await adm({ valid: null, sb: 0 }, { ...POL, kappa: 0 })).toBe('ok');
    expect(await adm({ valid: null, sb: 5 }, { ...POL, kappa: 0 })).toBe('false');
    expect(await adm({ sb: 1e-9 }, { ...POL, bMax: 0 })).toBe('ok');
    expect(await adm({ sb: 2e-9 }, { ...POL, bMax: 0 })).toBe('false');
  });
});

describe('cumulative-budget-bound: branch behaviour', () => {
  interface O { policy?: unknown; n?: number; r?: number; c?: number; a?: unknown; sb?: number }
  async function cum(o: O) {
    const seen: { B: number; tau: number; asOf: number }[] = [];
    const m = await load(() => ({
      riskScore: () => o.r ?? 0.5,
      cost: () => o.c ?? 0,
      admit: (_r: unknown, b: unknown) => {
        seen.push({ ...(b as { B: number; tau: number; asOf: number }) });
        return o.a ?? AUTO;
      },
      safetyBound: () => o.sb ?? 100,
    }));
    const v = verdict(m.cumulativeBudgetBoundProperty(), [o.policy ?? POL, Array.from({ length: o.n ?? 1 }, () => IN)]);
    return { v, seen };
  }

  it('starts from a full budget, passes the exact budget shape, and debits the cost after each action', async () => {
    const { v, seen } = await cum({ n: 3, r: 0.5, c: 1, sb: 5 });
    expect(v).toBe('ok');
    expect(seen).toStrictEqual([
      { B: 5, tau: 0, asOf: 0 },
      { B: 4, tau: 0, asOf: 0 },
      { B: 3, tau: 0, asOf: 0 },
    ]);
  });

  it('a negative bMax starts from an empty budget', async () => {
    const { seen } = await cum({ policy: { ...POL, bMax: -3 }, r: 0 });
    expect(seen[0]).toStrictEqual({ B: 0, tau: 0, asOf: 0 });
  });

  it('rejects an admission the budget cannot cover (boundary: B + 1e-9 == c is covered)', async () => {
    expect((await cum({ r: 0.1, c: 6, sb: 100 })).v).toBe('false');
    expect((await cum({ policy: { ...POL, bMax: 0 }, r: 0, c: 1e-9 })).v).toBe('ok');
    expect((await cum({ policy: { ...POL, bMax: 0 }, r: 0, c: 2e-9 })).v).toBe('false');
  });

  it('only debits metered actions below the human step-up band', async () => {
    expect((await cum({ a: { admit: false, needStepUp: true, t: 1, metered: false }, c: 100 })).v).toBe('ok');
    expect((await cum({ a: { admit: false, needStepUp: true, t: 3, metered: true }, c: 100 })).v).toBe('ok');
    expect((await cum({ a: { admit: false, needStepUp: true, t: 2, metered: true }, c: 100 })).v).toBe('false');
  });

  it('rejects a cumulative risk above the budget or above the stated bound', async () => {
    expect((await cum({ policy: { ...POL, kappa: 1, bMax: 1 }, r: 2, c: 0, sb: 100 })).v).toBe('false');
    expect((await cum({ policy: { ...POL, kappa: 0, bMax: 1 }, r: 2, c: 0, sb: 0.5 })).v).toBe('false');
    expect((await cum({ policy: { ...POL, kappa: 1, bMax: 1 }, n: 2, r: 0.5, c: 0, sb: 100 })).v).toBe('ok');
  });

  it('accepts a cumulative risk exactly at the 1e-6 tolerance of each bound', async () => {
    expect((await cum({ policy: { ...POL, kappa: 1, bMax: 0 }, r: 1e-6, c: 0, sb: 100 })).v).toBe('ok');
    expect((await cum({ policy: { ...POL, kappa: 0, bMax: 0 }, r: 1e-6, c: 0, sb: 0 })).v).toBe('ok');
    expect((await cum({ policy: { ...POL, kappa: 0, bMax: 0 }, r: 2e-6, c: 0, sb: 0 })).v).toBe('false');
  });

  it('draws one to forty actions per sequence', async () => {
    const m = await load();
    const lens = fc.sample(m.cumulativeBudgetBoundProperty(), { numRuns: 200, seed: 5 }).map((t) => t[1].length);
    expect(Math.min(...lens)).toBeGreaterThanOrEqual(1);
    expect(Math.max(...lens)).toBeLessThanOrEqual(40);
    expect(Math.max(...lens)).toBeGreaterThan(10);
  });
});

// =================================== 3. fail-closed ===================================

describe('fail-closed:undecidable-leaf: branch behaviour', () => {
  const CTX = { action: { verb: 'read', resource: '/x' }, subject: { role: 'admin' } };
  const LEAVES = [
    { field: 'subject.role.definitely_absent', op: 'eq', value: 'x' },
    { field: 'subject.role', op: 'lt', value: 5 },
    { field: 'subject.role', op: 'in', value: 'not-an-array' },
    { field: 'subject.role', op: 'eq' },
    { field: 'subject.role', op: 'member_of', value: 'g', collection: 'env.no_such_collection' },
  ];
  interface O { tri?: unknown; cond?: unknown; preds?: unknown }
  async function leaf(pick: number, o: O = {}) {
    const tris: unknown[][] = [];
    const preds: unknown[][] = [];
    const m = await load((r) => ({
      evaluateConditionTri: (...a: unknown[]) => {
        tris.push(a);
        return o.tri ?? call(r.evaluateConditionTri, ...a);
      },
      evaluateCondition: (...a: unknown[]) => o.cond ?? call(r.evaluateCondition, ...a),
      evaluatePredicates: (...a: unknown[]) => {
        preds.push(a);
        return o.preds ?? call(r.evaluatePredicates, ...a);
      },
    }));
    return { v: verdict(m.undecidableLeafFailsClosedProperty(), [pick, 'read', '/x']), tris, preds, m };
  }

  it.each([0, 1, 2, 3, 4])('builds the expected undecidable leaf and probes it in the expected context (pick %i)', async (pick) => {
    const { v, tris, preds } = await leaf(pick);
    expect(v).toBe('ok');
    expect(tris).toHaveLength(1);
    expect(tris[0]).toStrictEqual([LEAVES[pick], CTX]);
    expect(preds).toStrictEqual([[[{ verb: 'read', resource: '/x', where: [LEAVES[pick]] }], CTX]]);
  });

  it('rejects an unknown builder index, a leaf that decides true, a leaf that evaluates truthy, and a predicate that allows', async () => {
    expect((await leaf(99)).v).toBe('false');
    expect((await leaf(5)).v).toBe('false');
    expect((await leaf(0, { tri: 'true' })).v).toBe('false');
    expect((await leaf(0, { cond: true })).v).toBe('false');
    expect((await leaf(0, { preds: { allowed: true } })).v).toBe('false');
    expect((await leaf(0, { preds: { allowed: false } })).v).toBe('ok');
  });

  it('draws the five leaf builders, three verbs and the one resource', async () => {
    const m = await load();
    const s = fc.sample(m.undecidableLeafFailsClosedProperty(), { numRuns: 300, seed: 3 });
    expect(uniq(s.map((t) => t[0])).sort()).toEqual([0, 1, 2, 3, 4]);
    expect(uniq(s.map((t) => t[1])).sort()).toEqual(['delete', 'read', 'write']);
    expect(uniq(s.map((t) => t[2]))).toEqual(['/x']);
  });
});

describe('fail-closed:undecidable-groups: branch behaviour', () => {
  const CTX = { action: { verb: 'read', resource: '/x' }, subject: { role: 'admin' } };
  const CHILD = { field: 'subject.role', op: 'lt', value: 5 };
  async function groups(answers: string[]) {
    const calls: unknown[][] = [];
    const m = await load(() => ({
      evaluateConditionTri: (...a: unknown[]) => {
        calls.push(a);
        return answers[calls.length - 1] ?? 'unknown';
      },
    }));
    return { v: verdict(m.undecidableGroupsFailClosedProperty(), [0]), calls };
  }

  it('probes not / empty all_of / empty any_of / all_of / any_of over the undecidable child, in that order', async () => {
    const { v, calls } = await groups([]);
    expect(v).toBe('ok');
    expect(calls).toStrictEqual([
      [{ not: CHILD }, CTX],
      [{ all_of: [] }, CTX],
      [{ any_of: [] }, CTX],
      [{ all_of: [CHILD] }, CTX],
      [{ any_of: [CHILD] }, CTX],
    ]);
  });

  it.each([0, 1, 2, 3, 4])('rejects a core that decides true for group number %i', async (k) => {
    const answers = ['unknown', 'unknown', 'unknown', 'unknown', 'unknown'];
    answers[k] = 'true';
    expect((await groups(answers)).v).toBe('false');
    answers[k] = 'false';
    expect((await groups(answers)).v).toBe('ok');
  });

  it('is green on the real core', async () => {
    expect(verdict((await load()).undecidableGroupsFailClosedProperty(), [0])).toBe('ok');
  });
});

describe('fail-closed:member-of-cycle-safe: branch behaviour', () => {
  it('decides reachable targets true and the absent one false on the real core', async () => {
    const p = (await load()).memberOfCycleSafeProperty();
    for (const t of ['a', 'b', 'c', 'z']) expect(verdict(p, [t])).toBe('ok');
  });

  it('probes the cyclic adjacency in the expected context with the target as the operand', async () => {
    const calls: unknown[][] = [];
    const m = await load((r) => ({
      evaluateConditionTri: (...a: unknown[]) => {
        calls.push(a);
        return call(r.evaluateConditionTri, ...a);
      },
    }));
    expect(verdict(m.memberOfCycleSafeProperty(), ['c'])).toBe('ok');
    expect(calls).toStrictEqual([
      [
        { field: 'subject.g', op: 'member_of', value: 'c', collection: 'env.rel' },
        { action: { verb: 'read', resource: '/x' }, subject: { g: 'a' }, env: { rel: { a: ['b'], b: ['a', 'c'] } } },
      ],
    ]);
  });

  it('rejects a core with the wrong verdict for a reachable or an unreachable target', async () => {
    const never = await load(() => ({ evaluateConditionTri: () => 'false' }));
    expect(verdict(never.memberOfCycleSafeProperty(), ['a'])).toBe('false');
    expect(verdict(never.memberOfCycleSafeProperty(), ['z'])).toBe('ok');
    const always = await load(() => ({ evaluateConditionTri: () => 'true' }));
    expect(verdict(always.memberOfCycleSafeProperty(), ['z'])).toBe('false');
    expect(verdict(always.memberOfCycleSafeProperty(), ['b'])).toBe('ok');
  });

  it('draws exactly the four targets', async () => {
    const m = await load();
    const s = fc.sample(m.memberOfCycleSafeProperty(), { numRuns: 200, seed: 2 });
    expect(uniq(s.map((t) => t[0])).sort()).toEqual(['a', 'b', 'c', 'z']);
  });
});

describe('fail-closed:unknown-caveat-type: branch behaviour', () => {
  it('evaluates the bare unknown caveat in a bare time context', async () => {
    const calls: unknown[][] = [];
    const m = await load((r) => ({
      envelopeCaveatEvaluator: (...a: unknown[]) => {
        calls.push(a);
        return call(r.envelopeCaveatEvaluator, ...a);
      },
    }));
    expect(verdict(m.unknownCaveatTypeDeniesProperty(), ['zzz', 5])).toBe('ok');
    expect(calls).toStrictEqual([[{ type: 'zzz' }, { now: 5 }]]);
  });

  it('rejects an evaluator that satisfies an unknown caveat, and an evaluateCaveats that accepts it', async () => {
    const m = await load(() => ({ envelopeCaveatEvaluator: () => true }));
    expect(verdict(m.unknownCaveatTypeDeniesProperty(), ['zzz', 5])).toBe('false');
    const m2 = await load(() => ({ evaluateCaveats: () => ({ ok: true, failed: [] }) }));
    expect(verdict(m2.unknownCaveatTypeDeniesProperty(), ['zzz', 5])).toBe('false');
  });

  it('every known type name, bare, is also denied (so the exclusion list cannot change a verdict)', async () => {
    const p = (await load()).unknownCaveatTypeDeniesProperty();
    for (const t of ['expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc']) {
      expect(verdict(p, [t, 5])).toBe('ok');
    }
  });

  it('draws non-empty types of at most 12 characters and times in [0, 10_000_000]', async () => {
    const m = await load();
    const s = fc.sample(m.unknownCaveatTypeDeniesProperty(), { numRuns: 800, seed: 8 });
    for (const [type, now] of s) {
      expect(type.length).toBeGreaterThanOrEqual(1);
      expect(type.length).toBeLessThanOrEqual(12);
      expect(Number.isInteger(now)).toBe(true);
      expect(now).toBeGreaterThanOrEqual(0);
      expect(now).toBeLessThanOrEqual(10_000_000);
    }
    expect(s.some(([t]) => t.length === 12)).toBe(true);
  });
});

describe('fail-closed:forged-chain-rejected: branch behaviour', () => {
  const AUX = seed(9);
  const AUXPUB = keyPairFromSeed(AUX).pub;
  async function forged(mutation: string, pick: number, g: GeneratedChain, verify: () => { ok: boolean } = () => ({ ok: true }), aux: Uint8Array = AUX) {
    const calls: unknown[][] = [];
    const m = await load(() => ({
      verifyChain: (...a: unknown[]) => {
        calls.push(a);
        return verify();
      },
    }));
    return { v: verdict(m.forgedChainRejectedProperty(), [g, mutation, pick, aux]), calls };
  }
  const setup = () => {
    const g = G3();
    return { g, snap: structuredClone(g.caps) as Capability[] };
  };

  it('accepts every attack on a real chain (the real verifier rejects each one)', async () => {
    const m = await load();
    const p = m.forgedChainRejectedProperty();
    const g = G3();
    for (const mutation of ['tamper-caveat', 'drop-leaf-caveat', 'swap-holder', 'break-parent', 'bad-sig', 'wrong-root-issuer', 'suite-mismatch', 'break-id', 'append-forged-hop']) {
      for (const pick of [0, 1, 2, 3, 4, 5]) expect(verdict(p, [g, mutation, pick, AUX]), `${mutation}/${pick}`).toBe('ok');
    }
  });

  it('refuses a pristine chain that does not verify', async () => {
    for (const mutation of ['tamper-caveat', 'wrong-root-issuer', 'append-forged-hop']) {
      const { v, calls } = await forged(mutation, 1, G3(), () => ({ ok: false }));
      expect(v).toBe('false');
      expect(calls).toHaveLength(1);
    }
  });

  it('tamper-caveat appends an expiry of 999 to the chosen hop (pick modulo the chain length)', async () => {
    for (const [pick, idx] of [[4, 1], [1, 1], [0, 0], [2, 2], [5, 2]] as const) {
      const { g, snap } = setup();
      const { v, calls } = await forged('tamper-caveat', pick, g);
      expect(v).toBe('false');
      expect(calls).toHaveLength(2);
      expect(calls[0]).toEqual([snap, g.rootIssuer]);
      const exp = structuredClone(snap);
      exp[idx]!.caveats = [...exp[idx]!.caveats, { type: 'expires', at: 999 }];
      expect(calls[1]).toEqual([exp, g.rootIssuer]);
    }
  });

  it('drop-leaf-caveat removes the last caveat of the leaf; a leaf without caveats is inapplicable', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('drop-leaf-caveat', 0, g);
    expect(v).toBe('false');
    const exp = structuredClone(snap);
    exp[2]!.caveats = exp[2]!.caveats.slice(0, -1);
    expect(calls[1]).toEqual([exp, g.rootIssuer]);
    const empty = withCaps(g, [snap[0], snap[1], { ...snap[2]!, caveats: [] }]);
    const r = await forged('drop-leaf-caveat', 0, empty);
    expect(r.v).toBe('ok');
    expect(r.calls).toHaveLength(1);
  });

  it('swap-holder rebinds the chosen hop to the auxiliary key', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('swap-holder', 2, g);
    expect(v).toBe('false');
    const exp = structuredClone(snap);
    exp[2]!.holder = AUXPUB;
    expect(calls[1]).toEqual([exp, g.rootIssuer]);
  });

  it('break-parent detaches the chosen non-root hop (the root is never chosen) with a fixed bogus parent', async () => {
    const bogus = hashCanonical({ bogus: 32, tag: 'not-a-real-parent' });
    for (const [pick, idx] of [[0, 1], [1, 1], [2, 2], [3, 1], [5, 2]] as const) {
      const { g, snap } = setup();
      const { v, calls } = await forged('break-parent', pick, g);
      expect(v).toBe('false');
      const exp = structuredClone(snap);
      exp[idx]!.parent = bogus;
      expect(calls[1]).toEqual([exp, g.rootIssuer]);
    }
    // a two-hop chain still has a non-root hop to detach; a one-hop chain does not
    const g2 = G2();
    const r2 = await forged('break-parent', 0, g2);
    expect(r2.v).toBe('false');
    expect(r2.calls).toHaveLength(2);
    const r1 = await forged('break-parent', 0, G1());
    expect(r1.v).toBe('ok');
    expect(r1.calls).toHaveLength(1);
  });

  it('bad-sig replaces the signature with a well-formed signature over other bytes by another key', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('bad-sig', 1, g);
    expect(v).toBe('false');
    const exp = structuredClone(snap);
    exp[1]!.sig = encodeKey(sign(AUX, Uint8Array.of(1, 2, 3, 4)));
    expect(calls[1]).toEqual([exp, g.rootIssuer]);
  });

  it('wrong-root-issuer verifies the pristine chain against the auxiliary key; a colliding key is inapplicable', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('wrong-root-issuer', 0, g);
    expect(v).toBe('false');
    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual([snap, AUXPUB]);
    const same = await forged('wrong-root-issuer', 0, { ...g, rootIssuer: AUXPUB });
    expect(same.v).toBe('ok');
    expect(same.calls).toHaveLength(1);
  });

  it('suite-mismatch claims the post-quantum suite on the chosen hop', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('suite-mismatch', 1, g);
    expect(v).toBe('false');
    const exp = structuredClone(snap);
    exp[1]!.alg = 'ml-dsa-65';
    expect(calls[1]).toEqual([exp, g.rootIssuer]);
  });

  it('break-id replaces the id of the chosen hop with an unrelated digest bound to its index', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('break-id', 5, g);
    expect(v).toBe('false');
    const exp = structuredClone(snap);
    exp[2]!.id = hashCanonical({ not: 'the-body-digest', n: 2 });
    expect(calls[1]).toEqual([exp, g.rootIssuer]);
  });

  it('append-forged-hop appends one attribute-free hop issued from the leaf but signed by the auxiliary key', async () => {
    const { g, snap } = setup();
    const { v, calls } = await forged('append-forged-hop', 0, g);
    expect(v).toBe('false');
    expect(calls).toHaveLength(2);
    const sent = (calls[1]![0] as Capability[]);
    expect(sent).toHaveLength(4);
    expect(sent.slice(0, 3)).toEqual(snap);
    expect(sent[3]).toEqual(delegate(snap[2]!, AUXPUB, [], AUX));
    expect(sent[3]!.caveats).toEqual(snap[2]!.caveats);
    expect(calls[1]![1]).toBe(g.rootIssuer);
  });

  it('an empty slot where the mutation applies makes the case inapplicable (no second verification)', async () => {
    const g = G2();
    const holed = withCaps(g, [g.caps[0], hole]);
    for (const mutation of ['tamper-caveat', 'drop-leaf-caveat', 'swap-holder', 'break-parent', 'bad-sig', 'suite-mismatch', 'break-id', 'append-forged-hop']) {
      const r = await forged(mutation, 1, holed);
      expect(r.v, mutation).toBe('ok');
      expect(r.calls, mutation).toHaveLength(1);
    }
    const empty = withCaps(g, []);
    for (const mutation of ['tamper-caveat', 'drop-leaf-caveat', 'swap-holder', 'break-parent', 'bad-sig', 'suite-mismatch', 'break-id', 'append-forged-hop']) {
      const r = await forged(mutation, 7, empty);
      expect(r.v, mutation).toBe('ok');
    }
  });

  it('an unrecognised mutation name performs no attack', async () => {
    const r = await forged('', 1, G3());
    expect(r.v).toBe('ok');
    expect(r.calls).toHaveLength(1);
  });

  it('draws all nine attack names and a pick of at most 1_000_000', async () => {
    const m = await load();
    const s = fc.sample(m.forgedChainRejectedProperty(), { numRuns: 300, seed: 4 });
    expect(uniq(s.map((t) => t[1])).sort()).toEqual(
      ['append-forged-hop', 'bad-sig', 'break-id', 'break-parent', 'drop-leaf-caveat', 'suite-mismatch', 'swap-holder', 'tamper-caveat', 'wrong-root-issuer'],
    );
    for (const t of s) {
      expect(t[2]).toBeGreaterThanOrEqual(0);
      expect(t[2]).toBeLessThanOrEqual(1_000_000);
      expect(t[3]).toHaveLength(32);
    }
  });
});

describe('fail-closed:garbage-chain-rejected: branch behaviour', () => {
  it('rejects the empty chain and unsigned chains on the real core, and a verifier that accepts them', async () => {
    const m = await load();
    expect(verdict(m.garbageChainRejectedProperty(), [[]])).toBe('ok');
    const cap = { id: 'a', issuer: 'b', holder: 'c', caveats: [{ type: 'zz' }], body_digest: 'd', sig: 'e' };
    expect(verdict(m.garbageChainRejectedProperty(), [[cap, cap]])).toBe('ok');
    const bad = await load(() => ({ verifyChain: () => ({ ok: true }) }));
    expect(verdict(bad.garbageChainRejectedProperty(), [[]])).toBe('false');
  });

  it('draws well-typed unsigned capabilities with only the six fields, caveats that carry only a string type, and at most four hops', async () => {
    const m = await load();
    const s = fc.sample(m.garbageChainRejectedProperty(), { numRuns: 600, seed: 6 });
    const lens = s.map((t) => t[0].length);
    expect(Math.min(...lens)).toBe(0);
    expect(Math.max(...lens)).toBe(4);
    const caps = s.flatMap((t) => t[0]);
    expect(caps.length).toBeGreaterThan(100);
    let maxCaveats = 0;
    for (const c of caps) {
      expect(Object.keys(c).sort()).toEqual(['body_digest', 'caveats', 'holder', 'id', 'issuer', 'sig']);
      for (const k of ['id', 'issuer', 'holder', 'body_digest', 'sig'] as const) expect(typeof c[k]).toBe('string');
      expect(c.caveats.length).toBeLessThanOrEqual(3);
      maxCaveats = Math.max(maxCaveats, c.caveats.length);
      for (const cv of c.caveats as Caveat[]) {
        expect(Object.keys(cv)).toEqual(['type']);
        expect(typeof cv.type).toBe('string');
      }
    }
    expect(maxCaveats).toBe(3);
  });
});

// ================================== 4. determinism =====================================

describe('determinism: branch behaviour', () => {
  async function det(patch: (r: Real) => Real, g: GeneratedChain = G1()): Promise<Verdict> {
    const m = await load(patch);
    return verdict(m.determinismProperty(), [g, PT, [{ verb: '*' }], POL, IN, { B: 1, tau: 0 }]);
  }

  it('accepts the real (deterministic) core, with and without a leaf', async () => {
    expect(await det(() => ({}))).toBe('ok');
    expect(await det(() => ({}), withCaps(G1(), []))).toBe('ok');
  });

  it('rejects a verifier whose ok or whose reason changes between calls', async () => {
    expect(await det(() => { const f = flip(); return { verifyChain: () => ({ ok: f(), reason: 'r' }) }; })).toBe('false');
    expect(await det(() => { const f = flip(); return { verifyChain: () => ({ ok: true, reason: f() ? 'a' : 'b' }) }; })).toBe('false');
    expect(await det(() => ({ verifyChain: () => ({ ok: true, reason: 'r' }) }))).toBe('ok');
  });

  it('rejects predicate evaluation whose allowed or whose reason changes', async () => {
    expect(await det(() => { const f = flip(); return { evaluatePredicates: () => ({ allowed: f(), reason: 'r' }) }; })).toBe('false');
    expect(await det(() => { const f = flip(); return { evaluatePredicates: () => ({ allowed: true, reason: f() ? 'a' : 'b' }) }; })).toBe('false');
  });

  it('rejects caveat evaluation whose ok or whose failed list changes, only when there is a leaf', async () => {
    const okDiff = () => { const f = flip(); return { evaluateCaveats: () => ({ ok: f(), failed: ['a'] }) }; };
    const failedDiff = () => { const f = flip(); return { evaluateCaveats: () => ({ ok: true, failed: f() ? ['a'] : ['b'] }) }; };
    expect(await det(okDiff)).toBe('false');
    expect(await det(failedDiff)).toBe('false');
    expect(await det(okDiff, withCaps(G1(), []))).toBe('ok');
    expect(await det(failedDiff, withCaps(G1(), []))).toBe('ok');
  });

  it('evaluates the caveats of the last hop of the chain', async () => {
    const seen: unknown[] = [];
    const g = G2();
    expect(
      await det((r) => ({
        evaluateCaveats: (...a: unknown[]) => {
          seen.push(a[0]);
          return call(r.evaluateCaveats, ...a);
        },
      }), g),
    ).toBe('ok');
    expect(seen).toHaveLength(2);
    expect(seen[0]).toEqual(g.caps[1]!.caveats);
  });

  it('rejects a threshold whose t, proof or optimisticAllowed changes', async () => {
    const mk3 = (field: 't' | 'proof' | 'optimisticAllowed') => () => {
      const f = flip();
      return {
        requiredThreshold: () => ({
          t: field === 't' && f() ? 1 : 2,
          proof: field === 'proof' && f() ? 'claim' : 'standard',
          optimisticAllowed: field === 'optimisticAllowed' && f(),
        }),
      };
    };
    expect(await det(mk3('t'))).toBe('false');
    expect(await det(mk3('proof'))).toBe('false');
    expect(await det(mk3('optimisticAllowed'))).toBe('false');
  });

  it('rejects an admission whose admit, needStepUp, t or metered changes', async () => {
    const mkA = (field: 'admit' | 'needStepUp' | 't' | 'metered') => () => {
      const f = flip();
      return {
        admit: () => ({
          admit: field === 'admit' ? f() : false,
          needStepUp: field === 'needStepUp' ? f() : false,
          t: field === 't' ? (f() ? 1 : 2) : 2,
          metered: field === 'metered' ? f() : false,
        }),
      };
    };
    for (const field of ['admit', 'needStepUp', 't', 'metered'] as const) expect(await det(mkA(field)), field).toBe('false');
  });
});

describe('forbid-monotone: branch behaviour', () => {
  const READ = { verb: 'read' };
  const DEL = { verb: 'delete' };
  const WRITE = { verb: 'write' };
  // an eval point: `action` is an ActionContext (it wraps the verb/resource), as arbEvalPoint generates
  const ACT = { action: { action: { verb: 'read', resource: '/x' } }, cavCtx: { now: 1 } };
  async function forbid(input: { permits: unknown[]; forbids: unknown[]; extra: unknown[]; rot?: number }, decisions?: string[]) {
    const calls: unknown[][] = [];
    const m = await load((r) => ({
      decideClauses: (...a: unknown[]) => {
        calls.push(a);
        return decisions ? { decision: decisions[calls.length - 1] } : call(r.decideClauses, ...a);
      },
    }));
    return { v: verdict(m.forbidMonotoneProperty(), [input.permits, input.forbids, input.extra, ACT, input.rot ?? 0]), calls };
  }

  it('holds on the real decision procedure whether or not a forbid matches', async () => {
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [WRITE] })).v).toBe('ok');
    expect((await forbid({ permits: [READ], forbids: [READ], extra: [WRITE], rot: 2 })).v).toBe('ok');
    expect((await forbid({ permits: [READ, WRITE], forbids: [DEL, READ], extra: [DEL], rot: 5 })).v).toBe('ok');
  });

  it('builds permit / escalate / forbid clauses with indexed ids, base first, and rotates the full list for the third decision', async () => {
    const { v, calls } = await forbid({ permits: [READ, WRITE], forbids: [DEL], extra: [WRITE], rot: 2 });
    expect(v).toBe('ok');
    const base = [
      { id: 'p0', kind: 'permit', when: READ },
      { id: 'p1', kind: 'permit', when: WRITE },
      { id: 'e0', kind: 'escalate', when: WRITE },
    ];
    const withForbid = [...base, { id: 'f0', kind: 'forbid', when: DEL }];
    expect(calls).toHaveLength(3);
    expect(calls[0]![0]).toStrictEqual(base);
    expect(calls[1]![0]).toStrictEqual(withForbid);
    expect(calls[2]![0]).toStrictEqual([...withForbid.slice(2), ...withForbid.slice(0, 2)]);
    expect(calls[0]![1]).toStrictEqual(ACT.action);
    // a rotation of 4 over four clauses wraps to no rotation
    const w = await forbid({ permits: [READ, WRITE], forbids: [DEL], extra: [WRITE], rot: 4 });
    expect(w.calls[2]![0]).toStrictEqual(withForbid);
  });

  it('rejects a decision procedure where adding a forbid raises the decision', async () => {
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['deny', 'allow', 'allow'])).v).toBe('false');
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['deny', 'escalate', 'escalate'])).v).toBe('false');
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['escalate', 'allow', 'allow'])).v).toBe('false');
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['allow', 'allow', 'allow'])).v).toBe('ok');
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['allow', 'escalate', 'escalate'])).v).toBe('ok');
  });

  it('rejects an outcome other than deny when ANY forbid matches', async () => {
    const r = await forbid({ permits: [READ], forbids: [READ, DEL], extra: [] }, ['allow', 'allow', 'allow']);
    expect(r.v).toBe('false');
    const r2 = await forbid({ permits: [READ], forbids: [DEL, READ], extra: [] }, ['allow', 'allow', 'allow']);
    expect(r2.v).toBe('false');
    expect((await forbid({ permits: [READ], forbids: [READ], extra: [] }, ['allow', 'deny', 'deny'])).v).toBe('ok');
    expect((await forbid({ permits: [READ], forbids: [DEL, WRITE], extra: [] }, ['allow', 'allow', 'allow'])).v).toBe('ok');
  });

  it('rejects a decision that depends on the order of the clauses', async () => {
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['allow', 'allow', 'deny'])).v).toBe('false');
    expect((await forbid({ permits: [READ], forbids: [DEL], extra: [] }, ['allow', 'escalate', 'allow'])).v).toBe('false');
  });

  it('draws three predicate lists, an eval point and a rotation of at most 5', async () => {
    const m = await load();
    const s = fc.sample(m.forbidMonotoneProperty(), { numRuns: 300, seed: 9 });
    for (const t of s) {
      expect(t[0].length).toBeGreaterThanOrEqual(1);
      expect(t[2].length).toBeLessThanOrEqual(4);
      expect(t[4]).toBeGreaterThanOrEqual(0);
      expect(t[4]).toBeLessThanOrEqual(5);
    }
    expect(uniq(s.map((t) => t[4])).sort()).toEqual([0, 1, 2, 3, 4, 5]);
  });
});

// ================================= runner / registry ==================================

describe('INVARIANTS registry passes the requested runs and seed to every property', () => {
  const CASES: [string, string, number, number][] = [
    ['attenuation-monotonicity', 'verifyChain', 1, 1],
    ['risk-wellformed-and-monotone', 'riskScore', 2, 2],
    ['admission-soundness', 'admit', 1, 1],
    ['cumulative-budget-bound', 'safetyBound', 1, 1],
    ['fail-closed:undecidable-leaf', 'evaluateConditionTri', 1, 1],
    ['fail-closed:undecidable-groups', 'evaluateConditionTri', 5, 5],
    ['fail-closed:member-of-cycle-safe', 'evaluateConditionTri', 1, 1],
    ['fail-closed:unknown-caveat-type', 'envelopeCaveatEvaluator', 1, 1],
    ['fail-closed:forged-chain-rejected', 'verifyChain', 1, 2],
    ['fail-closed:garbage-chain-rejected', 'verifyChain', 1, 1],
    ['forbid-monotone', 'decideClauses', 3, 3],
    ['determinism', 'verifyChain', 2, 2],
  ];

  async function trace(name: string, fn: string, runs: number, s: number): Promise<string[]> {
    const calls: string[] = [];
    const m = await load((r) => ({
      [fn]: (...a: unknown[]) => {
        calls.push(JSON.stringify(a));
        return call(r[fn], ...a);
      },
    }));
    inv(m, name).run(runs, s);
    return calls;
  }

  it.each(CASES)('%s runs exactly the requested number of cases, reproducibly from the seed', async (name, fn, lo, hi) => {
    const a = await trace(name, fn, 4, 7);
    expect(a.length).toBeGreaterThanOrEqual(4 * lo);
    expect(a.length).toBeLessThanOrEqual(4 * hi);
    const b = await trace(name, fn, 4, 7);
    expect(b).toEqual(a);
  });

  it('lists the twelve invariants once each, in a stable order', async () => {
    const m = await load();
    expect(m.INVARIANTS.map((i) => i.name)).toEqual(CASES.map((c) => c[0]));
  });

  it('different seeds draw different cases', async () => {
    const a = await trace('determinism', 'verifyChain', 4, 7);
    const b = await trace('determinism', 'verifyChain', 4, 8);
    expect(b).not.toEqual(a);
  });
});

describe('checkInvariants', () => {
  it('refuses a zero, negative, fractional or NaN run count and a fractional seed, and accepts one run', async () => {
    const m = await load();
    for (const numRuns of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => m.checkInvariants({ numRuns })).toThrow(new RangeError('checkInvariants: numRuns must be a positive integer'));
    }
    for (const s of [1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => m.checkInvariants({ seed: s, numRuns: 1 })).toThrow(new RangeError('checkInvariants: seed must be an integer'));
    }
    const one = m.checkInvariants({ numRuns: 1, seed: 3 });
    expect(one).toHaveLength(12);
    expect(one.every((r) => r.ok && r.numRuns === 1 && r.seed === 3 && r.error === undefined)).toBe(true);
  });

  it('exposes the documented defaults', async () => {
    const m = await load();
    expect(m.DEFAULT_SEED).toBe(20260108);
    expect(m.DEFAULT_NUM_RUNS).toBe(1000);
  });

  it('is green on the real core', async () => {
    const m = await load();
    const res = m.checkInvariants({ numRuns: 40, seed: 11 });
    expect(res.map((r) => [r.name, r.ok])).toEqual(m.INVARIANTS.map((i) => [i.name, true]));
  });

  it('runs every invariant and reports a failure with its message; bail stops at the first failure', async () => {
    const m = await load(() => ({ verifyChain: () => ({ ok: true }) }));
    const res = m.checkInvariants({ numRuns: 20, seed: 3 });
    expect(res).toHaveLength(12);
    expect(res.filter((r) => !r.ok).map((r) => r.name)).toEqual(['fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected']);
    for (const r of res.filter((x) => !x.ok)) {
      expect(r).toEqual({ name: r.name, ok: false, numRuns: 20, seed: 3, error: expect.stringContaining('Property failed') });
    }
    for (const r of res.filter((x) => x.ok)) expect(Object.keys(r).sort()).toEqual(['name', 'numRuns', 'ok', 'seed']);
    const bailed = m.checkInvariants({ numRuns: 20, seed: 3, bail: true });
    expect(bailed).toHaveLength(9);
    expect(bailed[8]!.name).toBe('fail-closed:forged-chain-rejected');
    expect(bailed[8]!.ok).toBe(false);
    expect(bailed.slice(0, 8).every((r) => r.ok)).toBe(true);
  });

  it('records a thrown non-Error value as its string form', async () => {
    const m = await load();
    const orig = m.INVARIANTS[0]!;
    const backup = orig.run;
    (orig as { run: unknown }).run = () => {
      throw 'plain string failure';
    };
    try {
      const res = m.checkInvariants({ numRuns: 1, seed: 1, bail: true });
      expect(res).toEqual([{ name: orig.name, ok: false, numRuns: 1, seed: 1, error: 'plain string failure' }]);
    } finally {
      (orig as { run: unknown }).run = backup;
    }
  });
});
