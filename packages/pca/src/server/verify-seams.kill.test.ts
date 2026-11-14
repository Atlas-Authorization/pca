/**
 * server/verify.ts against collaborators that answer what the real ones never do: a core refusal without a reason, a core
 * check other than `bond` reported unsupported, a K1 bound entry without a caveat, a revocation refusal without a reason.
 * Each stub wraps the real function and only rewrites its result when a test asks for it.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

type CoreResult = { allow: boolean; checks: Record<string, string>; reason?: string };
type K1Result = { bound: unknown[] };
const h = vi.hoisted(() => ({
  core: null as null | ((r: CoreResult) => CoreResult),
  k1: null as null | ((r: K1Result) => K1Result),
  revFail: false,
}));

vi.mock('../pcactn-full', async (importOriginal) => {
  const m = await importOriginal<typeof import('../pcactn-full')>();
  return {
    ...m,
    verifyPCActnCore: async (...a: Parameters<typeof m.verifyPCActnCore>) => {
      const r = await m.verifyPCActnCore(...a);
      return h.core ? (h.core(r as CoreResult) as typeof r) : r;
    },
  };
});
vi.mock('../caveat-lang', async (importOriginal) => {
  const m = await importOriginal<typeof import('../caveat-lang')>();
  return {
    ...m,
    evaluateK1: (...a: Parameters<typeof m.evaluateK1>) => {
      const r = m.evaluateK1(...a);
      return h.k1 ? (h.k1(r as K1Result) as unknown as typeof r) : r;
    },
  };
});
vi.mock('../revocation', async (importOriginal) => {
  const m = await importOriginal<typeof import('../revocation')>();
  return { ...m, checkRevocationEpoch: (...a: Parameters<typeof m.checkRevocationEpoch>) => (h.revFail ? { ok: false } : m.checkRevocationEpoch(...a)) };
});

import { AUD, NOW, setup } from './fixture.test-util';
import { verifyPCActn } from './verify';

const MARKER = ['Stry', 'ker was here'].join('');
const opts = (s: ReturnType<typeof setup>) => ({
  grant: s.grant,
  now: NOW,
  audience: AUD,
  require: [] as string[],
  insecureSkipPlanRootCheck: true,
  context: { plan: s.plan, risk: s.lowRisk, params: {}, budget: { B: 1, tau: NOW, asOf: NOW } },
});
const unsupportedWhy = (n: string) => `${n}: unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)`;

beforeEach(() => {
  h.core = null;
  h.k1 = null;
  h.revFail = false;
});

describe('verifyPCActn with a reasonless core refusal', () => {
  it('lists no undefined reason', async () => {
    const s = setup();
    h.core = (r) => {
      const { reason: _r, ...rest } = r;
      return rest;
    };
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...opts(s), audience: 'another-rs' });
    expect(v.checks.audience).toBe('fail');
    expect(v.reasons.filter((x) => typeof x !== 'string')).toEqual([]);
  });
});

describe('verifyPCActn with core checks reported unsupported', () => {
  it('only a not-enforced status becomes unsupported; a check the server decided keeps its status', async () => {
    const s = setup();
    h.core = (r) => ({ ...r, checks: { ...r.checks, policy: 'unsupported' } });
    const v = await verifyPCActn(s.mk(s.plan[0]!), opts(s));
    expect(v.allow).toBe(false);
    expect(v.checks.policy).toBe('pass');
    expect(v.reasons).toContain(unsupportedWhy('policy'));
  });
  it('a check is refused unless allowUnsupported names it', async () => {
    const s = setup();
    h.core = (r) => ({ ...r, checks: { ...r.checks, [MARKER]: 'unsupported' } });
    const v = await verifyPCActn(s.mk(s.plan[0]!), opts(s));
    expect(v.allow).toBe(false);
    expect(v.checks[MARKER]).toBe('unsupported');
    expect(v.reasons).toContain(unsupportedWhy(MARKER));
  });
});

describe('verifyPCActn with a K1 bound entry without a caveat', () => {
  it('is skipped when looking for max_uses', async () => {
    const s = setup({ taskCaveats: [{ type: 'sealed' }] });
    h.k1 = (r) => ({ ...r, bound: [{ caveat: undefined, hop: 0, cap_hash: '' }, ...r.bound] });
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...opts(s), k1: {} });
    expect(v.checks.malformed).toBeUndefined();
    expect(v.checks.delegated_caveats).toBe('pass');
    expect(v.k1Bound).toBeUndefined();
  });
});

describe('verifyPCActn with a reasonless revocation refusal', () => {
  it('fails freshness with the fallback reason', async () => {
    const s = setup();
    h.revFail = true;
    const v = await verifyPCActn(s.mk(s.plan[0]!), { ...opts(s), context: { ...opts(s).context, revocationEpoch: { epoch: {} as never, guardianPublic: 'g' } } });
    expect(v.checks.freshness).toBe('fail');
    expect(v.reasons).toContain('freshness: revocation epoch rejected');
  });
});
