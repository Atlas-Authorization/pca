// Exact-outcome tests for the action catalog (definition guards, exact-verb resolution, the digest comparator, the
// no-downgrade rule at equality) and for the catalog risk inputs (amount and kappa boundaries, taint guards).
import { describe, expect, it } from 'vitest';
import { DEFAULT_CATALOG, buildCatalog, catalogDigest, defineAction, extendCatalog, type ActionSpec } from './catalog';
import { catalogRisk } from './catalog-risk';
import type { Capability } from './capability';

type Cmp = (a: unknown, b: unknown) => number;
const captureFirstSort = (run: () => void): Cmp => {
  const orig = Array.prototype.sort;
  let got: Cmp | undefined;
  Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
    if (fn && !got) got = fn;
    return orig.call(this, fn);
  } as typeof orig;
  try {
    run();
  } finally {
    Array.prototype.sort = orig;
  }
  if (!got) throw new Error('no comparator captured');
  return got;
};

const base = { connector: 'acme', action: 'x', reversibility: 'reversible' as const, blastRadius: 0.1, description: 'd' };

describe('defineAction / buildCatalog / extendCatalog', () => {
  it('a non-string action or amountField is refused with its own message', () => {
    expect(() => defineAction({ ...base, action: 5 as never })).toThrow(new Error('defineAction: connector and action are required'));
    expect(() => defineAction({ ...base, amountField: 5 as never })).toThrow(new Error('defineAction: amountField must be a non-empty string'));
    expect(defineAction({ ...base, amountField: 'amount' })).toEqual({ ...base, amountField: 'amount', verb: 'acme.x' });
  });
  it('resolve finds the exact verb of an action that has no aliases', () => {
    const spec = defineAction(base);
    const c = buildCatalog([spec]);
    expect(c.resolve!('acme', 'x')).toBe(spec);
    expect(c.resolve!('acme', 'y')).toBeUndefined();
  });
  it('the digest sorts by verb with a total three-way comparator', () => {
    const cmp = captureFirstSort(() => catalogDigest(DEFAULT_CATALOG));
    const a = { verb: 'a.x' };
    const b = { verb: 'b.x' };
    expect([cmp(a, b), cmp(b, a), cmp(a, { verb: 'a.x' })]).toEqual([-1, 1, 0]);
  });
  it('an extra entry exactly as cautious as the existing one is allowed', () => {
    const spec = defineAction(base);
    const c = extendCatalog(buildCatalog([spec]), [{ ...spec, description: 'again' }]);
    expect(c.get('acme.x')!.description).toBe('again');
  });
});

describe('catalogRisk: amounts, kappa and taint', () => {
  const pay: ActionSpec = { connector: 'acme', action: 'pay', verb: 'acme.pay', reversibility: 'irreversible', blastRadius: 0.9, description: 'd', amountField: 'amount' };
  const catalogOf = () => buildCatalog([pay]);
  /** A grant whose envelope's kappa reads as 100 during validation (two reads), then as `later`. */
  const grant = (later: unknown): Capability => {
    let reads = 0;
    const risk_policy = {
      weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 },
      theta1: 0,
      theta2: 1,
      get kappa(): unknown {
        return reads++ < 2 ? 100 : later;
      },
      lambda: 0,
      rho: 0,
      bMax: 0,
    };
    return { caveats: [{ type: 'envelope', goal_commit: 'g', predicates: [], caveats: [], agent_binding: {}, risk_policy }] } as unknown as Capability;
  };
  const risk = (amount: unknown, later: unknown, taint?: unknown) => catalogRisk('acme.pay', { amount }, grant(later), { catalog: catalogOf(), ...(taint === undefined ? {} : { taint: taint as number }) });
  it('amount / kappa, with an amount of exactly 0 priced at 0', () => {
    expect(risk(50, 100)).toEqual({ reversibility: 0, blastRadius: 0.5, confidence: 1 });
    expect(risk(0, 100)).toEqual({ reversibility: 0, blastRadius: 0, confidence: 1 });
  });
  it('a kappa that is not a positive number gives blast radius 1', () => {
    expect(risk(10, '100').blastRadius).toBe(1);
    expect(risk(10, -5).blastRadius).toBe(1);
    expect(risk(0, 0).blastRadius).toBe(1);
  });
  it('a non-finite amount gives blast radius 1 whatever kappa is', () => {
    expect(risk(Number.POSITIVE_INFINITY, Number.POSITIVE_INFINITY).blastRadius).toBe(1);
  });
  it('taint is supplied only when it is a finite number, judged on the value read', () => {
    expect(risk(50, 100, 0.25)).toEqual({ reversibility: 0, blastRadius: 0.5, confidence: 1, taint: 0.25 });
    expect(risk(50, 100, Number.NaN)).toEqual({ reversibility: 0, blastRadius: 0.5, confidence: 1 });
    expect('taint' in risk(50, 100, Number.POSITIVE_INFINITY)).toBe(false);
    let reads = 0;
    const opts = { catalog: catalogOf(), get taint(): number { return (reads++ === 0 ? 'x' : 0.5) as number; } };
    expect('taint' in catalogRisk('acme.pay', { amount: 50 }, grant(100), opts)).toBe(false);
  });
});
