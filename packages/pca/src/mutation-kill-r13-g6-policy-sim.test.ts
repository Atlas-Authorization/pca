/**
 * r13 mutation kills for policy-sim.ts: exact simulate() outcomes (risk value per budget model, the start clock, ordering,
 * the uncatalogued fallbacks reaching predicates and caveats, deny / step-up reasons, the rate window threading, peak and
 * autonomous risk) and the exact lintPolicy findings (codes, levels, messages and the boundaries of each rule).
 */
import { describe, expect, it } from 'vitest';
import { compilePolicy, type CompiledPolicy } from './facade';
import { lintPolicy, simulate } from './policy-sim';
import type { Catalog, ActionSpec } from './catalog';

/** Capture an outcome so a thrown error is compared (name + message) instead of failing the test as an error. */
type Settled<T> = { ok: true; value: T } | { ok: false; error: { name: string; message: string } };
function settle<T>(f: () => T): Settled<T> {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    const x = e as Error;
    return { ok: false, error: { name: x?.name, message: x?.message } };
  }
}
const ok = <T>(value: T) => ({ ok: true as const, value });

const HOUR = 3_600_000;
const DAY = 86_400_000;
const catOf = (...specs: ActionSpec[]): Catalog => ({
  get: (v) => specs.find((s) => s.verb === v),
  forConnector: (c) => specs.filter((s) => s.connector === c),
  all: () => specs,
});

describe('simulate: risk value', () => {
  it('risk model: blast radius even for a money action with an amount', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' }, budgetModel: 'risk' });
    expect(simulate(p, [{ verb: 'stripe.refund', resource: 'ch', params: { amount: 42 } }]).results[0]!.r).toBe(0.9);
  });
  it('dollars model: amount / kappa; a non-positive kappa falls back to the blast radius', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' } });
    expect(simulate(p, [{ verb: 'stripe.refund', resource: 'ch', params: { amount: 42 } }]).results[0]!.r).toBe(0.42);
    const z: CompiledPolicy = { ...p, predicates: [], riskPolicy: { ...p.riskPolicy, kappa: 0 } };
    expect(simulate(z, [{ verb: 'stripe.refund', resource: 'ch', params: { amount: 42 } }]).results[0]!.r).toBe(0.9);
  });
  it('the blast radius is clamped into [0,1]', () => {
    const p = compilePolicy({ permissions: { github: ['read'] } });
    const mk = (blastRadius: number): ActionSpec => ({ connector: 'c', action: 'a', verb: 'c.a', reversibility: 'reversible', blastRadius, description: 'd' });
    expect(simulate(p, [{ verb: 'c.a', resource: 'x' }], { catalog: catOf(mk(5)) }).results[0]!.r).toBe(1);
    expect(simulate(p, [{ verb: 'c.a', resource: 'x' }], { catalog: catOf(mk(-3)) }).results[0]!.r).toBe(0);
  });
});

describe('simulate: uncatalogued verbs', () => {
  it('a granted uncatalogued verb under the dollars model is treated as irreversible, blast 0.8 (no throw)', () => {
    const c = compilePolicy({ permissions: { stripe: ['refund'], acme: ['x'] }, limits: { refund: '$100' } });
    // W7b keeps the human co-sign tiers when anything granted is irreversible; pin the dollars-model tiers so the pricing is what is tested
    const p = { ...c, riskPolicy: { ...c.riskPolicy, theta1: 1, theta2: 1 } };
    expect(settle(() => simulate(p, [{ verb: 'acme.x', resource: 'r' }]).results[0])).toEqual(
      ok({ action: { verb: 'acme.x', resource: 'r' }, outcome: 'auto', t: 1, r: 0.8, budgetAfter: 20 }),
    );
  });
  it("the action context's reversibility_class is 'irreversible' for an uncatalogued verb and the spec class otherwise", () => {
    const p = compilePolicy({ permissions: { github: ['read'], acme: ['x'] } });
    const q: CompiledPolicy = {
      ...p,
      predicates: [
        { verb: 'github.read', resource: '*', where: [{ field: 'action.reversibility_class', op: 'eq', value: 'reversible' }] },
        { verb: 'acme.x', resource: '*', where: [{ field: 'action.reversibility_class', op: 'eq', value: 'irreversible' }] },
      ],
    };
    const rep = simulate(q, [{ verb: 'github.read', resource: 'r', at: 1 }, { verb: 'acme.x', resource: 'r', at: 2 }]);
    expect(rep.results.map((x) => x.outcome)).toStrictEqual(['auto', 'step_up']);
  });
  it('the caveat context uses the spec blast radius', () => {
    const p = compilePolicy({ permissions: { github: ['read'] } });
    const q: CompiledPolicy = { ...p, caveats: [...p.caveats, { type: 'max_blast_radius', max: 0.5 }] };
    expect(simulate(q, [{ verb: 'github.read', resource: 'r' }]).results[0]!.outcome).toBe('auto');
  });
});

describe('simulate: clock and ordering', () => {
  it('opts.start sets the clock of actions without an explicit time', () => {
    const p = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$5/day' }, now: 0 });
    const r = simulate(p, [{ verb: 'stripe.refund', resource: 'ch', params: { amount: 1 } }], { start: 2 * DAY }).results[0]!;
    expect(r.outcome).toBe('deny');
    expect(r.reason).toBe('caveat(s) failed: expires');
  });
  it('actions without a time keep their input order (start + i)', () => {
    const p = compilePolicy({ permissions: { github: ['read'] } });
    const rep = simulate(p, [{ verb: 'github.read', resource: 'first' }, { verb: 'github.read', resource: 'second' }], { start: 10 });
    expect(rep.results.map((x) => x.action.resource)).toStrictEqual(['first', 'second']);
  });
});

describe('simulate: outcomes, reasons and aggregates', () => {
  it('an ungranted verb is denied with the predicate reason', () => {
    const p = compilePolicy({ permissions: { gmail: ['send'] } });
    const r = simulate(p, [{ verb: 'gmail.delete', resource: 'm' }]).results[0]!;
    expect(r).toStrictEqual({ action: { verb: 'gmail.delete', resource: 'm' }, outcome: 'deny', r: 0.8, reason: 'no predicate permits gmail.delete on m', budgetAfter: 1 });
  });
  it('failed caveats are listed by type, comma separated', () => {
    const p = compilePolicy({ permissions: { github: ['read'] }, limits: { read: '0/hour' }, now: 0 });
    const r = simulate(p, [{ verb: 'github.read', resource: 'r', at: 2 * HOUR }]).results[0]!;
    expect(r.outcome).toBe('deny');
    expect(r.reason).toBe('caveat(s) failed: expires, rate');
  });
  it('the rate window counts earlier auto-admitted actions', () => {
    const p = compilePolicy({ permissions: { github: ['read'] }, limits: { read: '1/hour' }, now: 0 });
    const rep = simulate(p, [{ verb: 'github.read', resource: 'r', at: 1000 }, { verb: 'github.read', resource: 'r', at: 2000 }]);
    expect(rep.results.map((x) => [x.outcome, x.reason])).toStrictEqual([['auto', undefined], ['deny', 'caveat(s) failed: rate']]);
  });
  it('step-up names the tier; peak and autonomous risk aggregate', () => {
    const p = compilePolicy({ permissions: { github: ['read'], slack: ['post_message'] } });
    const rep = simulate(p, [
      { verb: 'github.read', resource: 'r', at: 0 },
      { verb: 'slack.post_message', resource: 'c', at: 0 },
      { verb: 'github.read', resource: 'r', at: 0 },
    ]);
    const { budgetAfter, ...step } = rep.results[1]!;
    expect(step).toStrictEqual({ action: { verb: 'slack.post_message', resource: 'c', at: 0 }, outcome: 'step_up', t: 2, r: 0.5, reason: 'requires tier 2' });
    expect(budgetAfter).toBeCloseTo(0.95, 12);
    expect(rep.auto).toBe(2);
    expect(rep.stepUp).toBe(1);
    expect(rep.deny).toBe(0);
    expect(rep.peakRisk).toBe(0.5);
    expect(rep.autonomousRisk).toBe(0.1);
    expect(rep.endBudget).toBeCloseTo(0.9, 12);
  });
});

describe('lintPolicy: exact findings', () => {
  const base = () => compilePolicy({ permissions: { github: ['read'] } });
  it('a clean, reversible, catalogued policy has no findings', () => {
    expect(lintPolicy(base())).toStrictEqual([]);
  });
  it('a limit that matches nothing is an error naming the key', () => {
    const p = compilePolicy({ permissions: { github: ['read'] }, limits: { raed: '5' } });
    expect(lintPolicy(p)).toStrictEqual([{ level: 'error', code: 'limit-unmatched', message: "limit for 'raed' matches no granted action" }]);
  });
  it('broad-resource reads the predicate of THAT verb', () => {
    const p = compilePolicy({ permissions: { github: ['read', 'delete_repo'] } });
    const q: CompiledPolicy = { ...p, predicates: [{ verb: 'github.read', resource: '*' }, { verb: 'github.delete_repo', resource: 'repo:acme/*' }] };
    expect(lintPolicy(q)).toStrictEqual([]);
  });
  it('a granted verb with no predicate at all counts as broad', () => {
    const p = compilePolicy({ permissions: { github: ['delete_repo'] } });
    expect(settle(() => lintPolicy({ ...p, predicates: [] }).map((l) => l.code))).toEqual(ok(['broad-resource']));
  });
  it('broad-resource fires from rate_limited up, with the exact message', () => {
    const p = compilePolicy({ permissions: { github: ['merge_pr'] } });
    expect(lintPolicy(p)).toStrictEqual([
      { level: 'warn', code: 'broad-resource', message: "'github.merge_pr' (rate_limited) matches ANY resource — consider a resource prefix" },
    ]);
  });
  it('an unlimited money action is flagged', () => {
    const p = compilePolicy({ permissions: { stripe: ['charge'] } });
    expect(lintPolicy(p)).toStrictEqual([
      { level: 'warn', code: 'money-unbounded', message: "money action 'stripe.charge' has no per-call limit — spend is bounded only by the trust budget" },
    ]);
  });
  it('an uncatalogued verb is reported as info', () => {
    const p = compilePolicy({ permissions: { acme: ['x'] } });
    expect(lintPolicy(p)).toStrictEqual([
      { level: 'warn', code: 'broad-resource', message: "'acme.x' (irreversible) matches ANY resource — consider a resource prefix" },
      { level: 'info', code: 'uncatalogued', message: "'acme.x' is not in the catalog — treated conservatively (irreversible, high blast radius)" },
    ]);
  });
  it('theta2 >= 1: info without irreversible actions, warn (with the suffix) when any is irreversible', () => {
    const r = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$100' } });
    expect(lintPolicy(r).filter((l) => l.code === 'no-step-up-band')).toStrictEqual([
      { level: 'info', code: 'no-step-up-band', message: 'theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted' },
    ]);
    const c = compilePolicy({ permissions: { stripe: ['refund', 'payout'] }, limits: { refund: '$100', payout: '$100' } });
    const m = { ...c, riskPolicy: { ...c.riskPolicy, theta1: 1, theta2: 1 } }; // W7b: compilePolicy itself keeps the tiers when anything is irreversible
    expect(lintPolicy(m).filter((l) => l.code === 'no-step-up-band')).toStrictEqual([
      { level: 'warn', code: 'no-step-up-band', message: 'theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted — including irreversible actions' },
    ]);
  });
  it('large-autonomy: bMax/kappa strictly above 100, positive kappa only', () => {
    const with_ = (kappa: number, bMax: number) => lintPolicy({ ...base(), riskPolicy: { ...base().riskPolicy, kappa, bMax } });
    expect(with_(2, 300)).toStrictEqual([{ level: 'warn', code: 'large-autonomy', message: 'autonomous bound is 150× a max-risk action between human co-signs' }]);
    expect(with_(1, 100)).toStrictEqual([]);
    expect(with_(10, 500)).toStrictEqual([]);
    expect(with_(0, 1)).toStrictEqual([]);
    expect(with_(1, 1)).toStrictEqual([]);
  });
});
