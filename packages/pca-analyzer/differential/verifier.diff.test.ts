/**
 * Differential: the analyzer's static answers against the real verifier primitives (`evaluatePredicates`,
 * `evaluateCaveats`) on generated policies and actions. The analyzer may say "I cannot tell" (approximate), but it must
 * never claim an unreachable / always-deny / subsumed / disjoint answer that a concrete action refutes, and every witness
 * or counterexample it returns must be real. Lives outside `src/` because it reuses the generators of
 * `@atlasauth/pca-invariants` by relative path.
 */
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { type ActionContext, type Caveat, type CaveatContext, type Predicate, evaluateCaveats, evaluatePredicates } from '@atlasauth/pca';
import { arbActionContext, arbCaveatContext, arbPredicateList } from '../../pca-invariants/src/arbitraries';
import { type AnalyzerAction, type PolicyInput, alwaysDenies, disjoint, reachable, subsumes } from '../src';

const SEED = Number(process.env.PCA_DIFF_SEED ?? 20261026);
const RUNS = Number(process.env.PCA_DIFF_RUNS ?? 1500);

const arbCaveats: fc.Arbitrary<Caveat[]> = fc.array(
  fc.oneof(
    fc.record({ type: fc.constant('max_blast_radius'), max: fc.double({ min: 0, max: 1, noNaN: true }) }),
    fc.record({ type: fc.constant('reversibility_max'), class: fc.constantFrom('reversible', 'rate_limited', 'irreversible') }),
    fc.record({ type: fc.constant('expires'), at: fc.integer({ min: 0, max: 10_000_000 }) }),
    fc.record({ type: fc.constant('not_before'), at: fc.integer({ min: 0, max: 10_000_000 }) }),
    fc.record({ type: fc.constant('delegation_depth'), max: fc.integer({ min: 0, max: 4 }) }),
  ) as fc.Arbitrary<Caveat>,
  { maxLength: 3 },
);

const toAction = (ctx: ActionContext, cav: CaveatContext): AnalyzerAction => {
  const a: AnalyzerAction = { verb: ctx.action.verb, resource: ctx.action.resource, params: { ...(ctx.action.params ?? {}) } };
  if (typeof cav.reversibilityClass === 'string') a.reversibilityClass = cav.reversibilityClass;
  if (ctx.subject) a.subject = { ...ctx.subject };
  if (ctx.env) a.env = { ...ctx.env };
  return a;
};
const ctxOf = (a: AnalyzerAction): ActionContext => ({
  action: { verb: a.verb, resource: a.resource, params: a.params ?? {}, ...(a.reversibilityClass ? { reversibility_class: a.reversibilityClass } : {}) },
  subject: a.subject ?? {},
  env: a.env ?? {},
});
const predAdmits = (preds: Predicate[], a: AnalyzerAction) => evaluatePredicates(preds, ctxOf(a)).allowed;

describe('analyzer vs the verifier primitives', () => {
  it('never calls unreachable what the verifier admits', () => {
    fc.assert(
      fc.property(arbPredicateList, arbCaveats, arbActionContext, arbCaveatContext, (preds, caveats, ctx, cav) => {
        const verifierAdmits = evaluatePredicates(preds, ctx).allowed && evaluateCaveats(caveats, cav).ok;
        if (!verifierAdmits) return true;
        const r = reachable({ predicates: preds, caveats }, toAction(ctx, cav));
        return r.reachable === true;
      }),
      { numRuns: RUNS, seed: SEED },
    );
  });
  it('never calls a policy always-deny when the verifier admits something', () => {
    fc.assert(
      fc.property(arbPredicateList, arbCaveats, arbActionContext, arbCaveatContext, (preds, caveats, ctx, cav) => {
        const verifierAdmits = evaluatePredicates(preds, ctx).allowed && evaluateCaveats(caveats, cav).ok;
        if (!verifierAdmits) return true;
        return alwaysDenies({ predicates: preds, caveats }).alwaysDenies === false;
      }),
      { numRuns: RUNS, seed: SEED + 1 },
    );
  });
  it('every witness the analyzer returns is admitted by the real evaluator', () => {
    fc.assert(
      fc.property(arbPredicateList, arbActionContext, (preds, ctx) => {
        const r = reachable({ predicates: preds }, { verb: ctx.action.verb, resource: ctx.action.resource });
        if (r.reachable && r.witness && !r.approximate) return predAdmits(preds, r.witness);
        const d = alwaysDenies({ predicates: preds });
        if (!d.alwaysDenies && d.witness) return predAdmits(preds, d.witness);
        return true;
      }),
      { numRuns: RUNS, seed: SEED + 2 },
    );
  });
  it('subsumes: a "yes" is never refuted by a concrete action, and a counterexample is real', () => {
    fc.assert(
      fc.property(arbPredicateList, arbPredicateList, arbActionContext, (a, b, ctx) => {
        const act = toAction(ctx, {} as CaveatContext);
        const s = subsumes({ predicates: a }, { predicates: b });
        if (s.subsumes && predAdmits(b, act) && !predAdmits(a, act)) return false;
        if (!s.subsumes && s.counterexample && !s.approximate) return predAdmits(b, s.counterexample) && !predAdmits(a, s.counterexample);
        return true;
      }),
      { numRuns: RUNS, seed: SEED + 3 },
    );
  });
  it('disjoint: a "yes" is never refuted by a concrete action, and a witness is admitted by both', () => {
    fc.assert(
      fc.property(arbPredicateList, arbPredicateList, arbActionContext, (a, b, ctx) => {
        const act = toAction(ctx, {} as CaveatContext);
        const d = disjoint({ predicates: a }, { predicates: b });
        if (d.disjoint && predAdmits(a, act) && predAdmits(b, act)) return false;
        if (!d.disjoint && d.witness && !d.approximate) return predAdmits(a, d.witness) && predAdmits(b, d.witness);
        return true;
      }),
      { numRuns: RUNS, seed: SEED + 4 },
    );
  });
  it('the corpus exercises the interesting answers, not only the vacuous ones', () => {
    let reachableYes = 0, subsumesYes = 0, disjointYes = 0, denyYes = 0, n = 0;
    fc.assert(
      fc.property(arbPredicateList, arbPredicateList, (a, b) => {
        n++;
        if (reachable({ predicates: a }, { verb: 'read', resource: '/acct/1' }).reachable) reachableYes++;
        if (subsumes({ predicates: a }, { predicates: b }).subsumes) subsumesYes++;
        if (disjoint({ predicates: a }, { predicates: b }).disjoint) disjointYes++;
        if (alwaysDenies({ predicates: a } as PolicyInput).alwaysDenies) denyYes++;
        return true;
      }),
      { numRuns: 400, seed: SEED },
    );
    expect(n).toBe(400);
    for (const c of [reachableYes, subsumesYes, disjointYes, denyYes]) expect(c).toBeGreaterThan(0);
  });
});
