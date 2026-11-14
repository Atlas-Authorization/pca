import { describe, expect, it } from 'vitest';
import { evaluateConditionTri, type ActionContext, type Condition } from '@atlasauth/pca';
import {
  evaluateResidual,
  policyDigestOf,
  residual,
  residualPolicy,
  toModel,
  whatMayIDo,
  type KnownContext,
  type PolicyInput,
  type Residual,
  type ResidualOptions,
  type Veto,
  type VerbShape,
  type WhatMayIDoOptions,
} from './index';

// ---- partial evaluation of conditions ---------------------------------------------------------------

const T: Condition = { field: 'subject.a', op: 'eq', value: 1 }; // folds to true
const F: Condition = { field: 'subject.a', op: 'eq', value: 2 }; // folds to false
const U: Condition = { field: 'subject.nope', op: 'eq', value: 1 }; // missing field: unknown
const S1: Condition = { field: 'action.params.x', op: 'eq', value: 1 }; // symbolic
const S2: Condition = { field: 'action.params.y', op: 'gt', value: 2 }; // symbolic
const KNOWN: KnownContext = { verb: 'v', subject: { a: 1 } };

const permit = (where: Condition[], k: KnownContext = KNOWN, o?: ResidualOptions): Residual => residual({ predicates: [{ verb: 'v', where }] }, k, o);

/** What one condition partially evaluates to: a constant, or the remaining symbolic condition. */
function tri(x: Condition, k: KnownContext = KNOWN, o?: ResidualOptions): 'true' | 'false' | 'unknown' | Condition {
  const [a] = permit([x], k, o).policy.predicates;
  if (a !== undefined) {
    if (a.where === undefined) return 'true';
    expect(a.where).toHaveLength(1);
    return a.where[0]!;
  }
  const [b] = permit([{ not: x }], k, o).policy.predicates;
  return b !== undefined && b.where === undefined ? 'false' : 'unknown';
}

const bad = (c: unknown): Condition => c as Condition;

describe('partial evaluation of condition groups', () => {
  it('all_of', () => {
    expect(tri({ all_of: [T] })).toBe('true');
    expect(tri({ all_of: [T, T] })).toBe('true');
    expect(tri({ all_of: [F] })).toBe('false');
    expect(tri({ all_of: [T, F] })).toBe('false');
    expect(tri({ all_of: [F, T] })).toBe('false');
    expect(tri({ all_of: [F, U] })).toBe('false');
    expect(tri({ all_of: [U, F] })).toBe('false');
    expect(tri({ all_of: [F, S1] })).toBe('false');
    expect(tri({ all_of: [S1, F] })).toBe('false');
    expect(tri({ all_of: [U] })).toBe('unknown');
    expect(tri({ all_of: [T, U] })).toBe('unknown');
    expect(tri({ all_of: [U, U] })).toBe('unknown');
    expect(tri({ all_of: [T, S1] })).toEqual(S1);
    expect(tri({ all_of: [S1, T] })).toEqual(S1);
    expect(tri({ all_of: [S1, S2] })).toEqual({ all_of: [S1, S2] });
    expect(tri({ all_of: [T, S1, U] })).toEqual({ all_of: [S1, U] });
    expect(tri({ all_of: [U, S1, T] })).toEqual({ all_of: [U, S1] });
    expect(tri({ all_of: [S1, U, S2] })).toEqual({ all_of: [S1, U, S2] });
  });

  it('any_of', () => {
    expect(tri({ any_of: [F] })).toBe('false');
    expect(tri({ any_of: [F, F] })).toBe('false');
    expect(tri({ any_of: [T] })).toBe('true');
    expect(tri({ any_of: [F, T] })).toBe('true');
    expect(tri({ any_of: [T, F] })).toBe('true');
    expect(tri({ any_of: [T, U] })).toBe('true');
    expect(tri({ any_of: [U, T] })).toBe('true');
    expect(tri({ any_of: [T, S1] })).toBe('true');
    expect(tri({ any_of: [S1, T] })).toBe('true');
    expect(tri({ any_of: [U] })).toBe('unknown');
    expect(tri({ any_of: [F, U] })).toBe('unknown');
    expect(tri({ any_of: [U, U] })).toBe('unknown');
    expect(tri({ any_of: [F, S1] })).toEqual(S1);
    expect(tri({ any_of: [S1, F] })).toEqual(S1);
    expect(tri({ any_of: [S1, S2] })).toEqual({ any_of: [S1, S2] });
    expect(tri({ any_of: [F, S1, U] })).toEqual({ any_of: [S1, U] });
    expect(tri({ any_of: [U, S1, F] })).toEqual({ any_of: [U, S1] });
  });

  it('not', () => {
    expect(tri({ not: T })).toBe('false');
    expect(tri({ not: F })).toBe('true');
    expect(tri({ not: U })).toBe('unknown');
    expect(tri({ not: S1 })).toEqual({ not: S1 });
    expect(tri({ not: { not: S1 } })).toEqual({ not: { not: S1 } });
    expect(tri({ not: { all_of: [T, S1] } })).toEqual({ not: S1 });
    expect(tri({ not: { not: T } })).toBe('true');
  });

  it('an empty or malformed group is unknown and never falls through to a sibling key (the evaluator order is all_of, any_of, not)', () => {
    expect(tri({ all_of: [] })).toBe('unknown');
    expect(tri({ any_of: [] })).toBe('unknown');
    expect(tri(bad({ all_of: [], any_of: [T] }))).toBe('unknown');
    expect(tri(bad({ all_of: [], not: F }))).toBe('unknown');
    expect(tri(bad({ any_of: [], not: F }))).toBe('unknown');
    expect(tri(bad({ all_of: 'x', any_of: [T] }))).toBe('unknown');
    expect(tri(bad({ any_of: 'x', not: F }))).toBe('unknown');
    expect(tri(bad({ all_of: [T], any_of: [F] }))).toBe('true');
    expect(tri(bad({ any_of: [F], not: F }))).toBe('false');
  });

  it('agrees with the evaluator on every constant combination', () => {
    const ctx: ActionContext = { action: { verb: 'v', resource: 'r', params: {} }, subject: { a: 1 }, env: {} };
    const leaves = [T, F, U];
    const conds: Condition[] = [];
    for (const x of leaves) {
      conds.push(x, { not: x }, { all_of: [x] }, { any_of: [x] });
      for (const y of leaves) conds.push({ all_of: [x, y] }, { any_of: [x, y] }, { all_of: [x, { not: y }] }, { any_of: [{ not: x }, y] });
    }
    for (const c of conds) expect(tri(c)).toBe(evaluateConditionTri(c, ctx));
  });

  it('a condition that is not an object is unknown', () => {
    expect(tri(bad(null))).toBe('unknown');
    expect(tri(bad(5))).toBe('unknown');
    expect(tri(bad('x'))).toBe('unknown');
    expect(permit([bad(null)]).decision).toBe('never');
    expect(permit([bad('x')]).decision).toBe('never');
    expect(permit([bad(false)]).decision).toBe('never');
  });
});

describe('which leaves stay symbolic', () => {
  it('a field that is not under a known root folds to unknown when the verb and resource are known', () => {
    const odd = ['Stry', 'ker was here'].join('');
    const c: Condition = { field: odd, op: 'eq', value: 1 };
    expect(permit([c], { verb: 'v', resource: '/r' }).decision).toBe('never');
    expect(permit([c], { verb: 'v' }).decision).toBe('never');
    expect(permit([c], { resource: '/r' }).decision).toBe('never');
    expect(residual({ predicates: [{ verb: '*', where: [c] }] }, { verb: 'v', resource: '/r' }, { unknown: [] }).decision).toBe('never');
  });

  it('a leaf that reads an unknown field, ref or collection stays as written', () => {
    expect(tri(S1)).toEqual(S1);
    const viaRef: Condition = { field: 'subject.a', op: 'eq', ref: 'action.params.y' };
    expect(tri(viaRef)).toEqual(viaRef);
    const viaCollection: Condition = { field: 'subject.a', op: 'member_of', collection: 'action.params.groups', value: 'g' };
    expect(tri(viaCollection)).toEqual(viaCollection);
    expect(tri({ field: 'subject.a', op: 'eq', ref: 'subject.a' })).toBe('true');
  });

  it('a path is symbolic when it is an unknown path, below one, or an ancestor of one; a sibling with the same prefix text is folded', () => {
    const k: KnownContext = { verb: 'v', subject: { tier: 'g', tierx: 1, other: 2 }, env: { q: 1 } };
    const o: ResidualOptions = { unknown: ['subject.tier'] };
    const same: Condition = { field: 'subject.tier', op: 'eq', value: 'g' };
    const below: Condition = { field: 'subject.tier.level', op: 'eq', value: 1 };
    const ancestor: Condition = { field: 'subject', op: 'exists' };
    expect(tri(same, k, o)).toEqual(same);
    expect(tri(below, k, o)).toEqual(below);
    expect(tri(ancestor, k, o)).toEqual(ancestor);
    expect(tri({ field: 'subject.tierx', op: 'eq', value: 1 }, k, o)).toBe('true');
    expect(tri({ field: 'subject.other', op: 'eq', value: 2 }, k, o)).toBe('true');
    expect(tri({ field: 'env.q', op: 'eq', value: 1 }, k, o)).toBe('true');
    // reading the whole action reads the unknown parameters
    const wholeAction: Condition = { field: 'action', op: 'exists' };
    expect(tri(wholeAction)).toEqual(wholeAction);
    expect(tri({ field: 'action.paramsx', op: 'exists' })).toBe('false');
  });

  it('with no known verb or resource, conditions on them stay symbolic; with them known they fold', () => {
    const pol = (c: Condition): PolicyInput => ({ predicates: [{ verb: '*', where: [c] }] });
    const verbIs: Condition = { field: 'action.verb', op: 'eq', value: 'a' };
    expect(residual(pol(verbIs), {}).policy.predicates).toEqual([{ verb: '*', where: [verbIs] }]);
    expect(residual(pol(verbIs), { verb: 'a' }).decision).toBe('always');
    expect(residual(pol(verbIs), { verb: 'b' }).decision).toBe('never');
    const resIs: Condition = { field: 'action.resource', op: 'prefix', value: '/acct/' };
    expect(residual(pol(resIs), { verb: 'v' }).policy.predicates).toEqual([{ verb: '*', where: [resIs] }]);
    expect(residual(pol(resIs), { verb: 'v', resource: '/acct/1' }).decision).toBe('always');
    expect(residual(pol(resIs), { verb: 'v', resource: '/other' }).decision).toBe('never');
    // resourceUnknown keeps it symbolic even when a resource is supplied
    expect(residual(pol(resIs), { verb: 'v', resource: '/acct/1' }, { resourceUnknown: true }).policy.predicates).toEqual([{ verb: '*', where: [resIs] }]);
    expect(residual(pol(resIs), { verb: 'v', resource: '/acct/1' }, { resourceUnknown: false }).decision).toBe('always');
  });
});

describe('the known context', () => {
  it('folds known subject, env, parameters and reversibility class', () => {
    const whereSubject: Condition = { field: 'subject.tier', op: 'eq', value: 'gold' };
    const whereEnv: Condition = { field: 'env.mode', op: 'eq', value: 'live' };
    const whereRev: Condition = { field: 'action.reversibility_class', op: 'eq', value: 'irreversible' };
    expect(permit([whereSubject], { verb: 'v', subject: { tier: 'gold' } }).decision).toBe('always');
    expect(permit([whereSubject], { verb: 'v', subject: { tier: 'tin' } }).decision).toBe('never');
    expect(permit([whereSubject], { verb: 'v' }).decision).toBe('never');
    expect(permit([whereEnv], { verb: 'v', env: { mode: 'live' } }).decision).toBe('always');
    expect(permit([whereEnv], { verb: 'v', env: { mode: 'x' } }).decision).toBe('never');
    expect(permit([whereEnv], { verb: 'v' }).decision).toBe('never');
    expect(permit([whereRev], { verb: 'v', reversibilityClass: 'irreversible' }).decision).toBe('always');
    expect(permit([whereRev], { verb: 'v', reversibilityClass: 'reversible' }).decision).toBe('never');
    expect(permit([whereRev], { verb: 'v' }).decision).toBe('never');
    const amount: Condition = { field: 'action.params.amount', op: 'lte', value: 500 };
    expect(permit([amount], { verb: 'v', params: { amount: 400 } }, { unknown: [] }).decision).toBe('always');
    expect(permit([amount], { verb: 'v', params: { amount: 501 } }, { unknown: [] }).decision).toBe('never');
  });

  it('a known verb that is an array entry or a wildcard in the policy matches; resource matchers are dropped once the resource is known', () => {
    const p: PolicyInput = { predicates: [{ verb: ['a', 'b'], resource: '/acct/*', where: [S1] }] };
    expect(residual(p, { verb: 'b' }).policy.predicates).toStrictEqual([{ verb: '*', resource: '/acct/*', where: [S1] }]);
    expect(residual(p, { verb: 'b', resource: '/acct/1' }).policy.predicates).toStrictEqual([{ verb: '*', where: [S1] }]);
    expect(residual(p, { verb: 'c' }).decision).toBe('never');
    expect(residual(p, { verb: 'b', resource: '/zzz' }).decision).toBe('never');
    // nothing known: the predicate is kept as written
    expect(residual(p, {}).policy.predicates).toStrictEqual([{ verb: ['a', 'b'], resource: '/acct/*', where: [S1] }]);
    // a predicate with no resource matcher carries no resource key, known resource or not
    const noRes: PolicyInput = { predicates: [{ verb: 'v', where: [S1] }] };
    expect(residual(noRes, { verb: 'v' }).policy.predicates).toStrictEqual([{ verb: '*', where: [S1] }]);
    expect(residual(noRes, { verb: 'v', resource: '/r' }).policy.predicates).toStrictEqual([{ verb: '*', where: [S1] }]);
    expect(residual(noRes, {}).policy.predicates).toStrictEqual([{ verb: 'v', where: [S1] }]);
  });
});

describe('permit clauses', () => {
  it('a clause with no where is unconditional; an empty where is too; a non-array where never permits', () => {
    expect(residual({ predicates: [{ verb: 'v' }] }, { verb: 'v' })).toMatchObject({ decision: 'always', policy: { predicates: [{ verb: '*' }] } });
    expect(permit([]).decision).toBe('always');
    expect(permit(bad('x') as unknown as Condition[]).decision).toBe('never');
  });

  it('folds constants out of the where list and keeps the symbolic rest, in order', () => {
    expect(permit([T]).decision).toBe('always');
    expect(permit([F]).decision).toBe('never');
    expect(permit([U]).decision).toBe('never');
    expect(permit([T, U]).decision).toBe('never');
    expect(permit([F, S1]).decision).toBe('never');
    expect(permit([S1, F]).decision).toBe('never');
    expect(permit([T, S1]).policy.predicates).toStrictEqual([{ verb: '*', where: [S1] }]);
    expect(permit([S1, S2]).policy.predicates).toStrictEqual([{ verb: '*', where: [S1, S2] }]);
    expect(permit([T, S1, U]).policy.predicates).toStrictEqual([{ verb: '*', where: [S1, U] }]);
    expect(permit([U, S1, T]).policy.predicates).toStrictEqual([{ verb: '*', where: [U, S1] }]);
  });

  it('a non-object clause is skipped', () => {
    const p = { predicates: [null, 5, 'x', { verb: 'v', where: [S1] }] } as unknown as PolicyInput;
    expect(residual(p, {}).policy.predicates).toStrictEqual([{ verb: 'v', where: [S1] }]);
    expect(residual({ predicates: [null, 7] } as unknown as PolicyInput, {}).decision).toBe('never');
    expect(residual({ predicates: [null, 7] } as unknown as PolicyInput, { verb: 'v' }).decision).toBe('never');
  });

  it('a delegation chain flattens depth first and keeps every ancestor', () => {
    const ancestors: PolicyInput[] = [
      { predicates: [{ verb: 'v', where: [S2] }], meet: [{ predicates: [{ verb: 'v', where: [S1, S2] }] }] },
      { predicates: [{ verb: 'v' }], caveats: [{ type: 'delegation_depth', max: 3 }] },
    ];
    const chain: PolicyInput = { predicates: [{ verb: 'v', where: [S1] }], caveats: [{ type: 'max_blast_radius', max: 5 }], meet: ancestors };
    const r = residual(chain, { verb: 'v' });
    expect(r.decision).toBe('conditional');
    expect(r.policy.predicates).toStrictEqual([{ verb: '*', where: [S1] }]);
    expect(r.policy.caveats).toEqual([{ type: 'max_blast_radius', max: 5 }]);
    expect(r.policy.meet).toStrictEqual([
      { predicates: [{ verb: '*', where: [S2] }], caveats: [], vetoes: [], tighten: [] },
      { predicates: [{ verb: '*', where: [S1, S2] }], caveats: [], vetoes: [], tighten: [] },
      { predicates: [{ verb: '*' }], caveats: [{ type: 'delegation_depth', max: 3 }], vetoes: [], tighten: [] },
    ]);
    // the digest covers the chain
    expect(r.policyDigest).toBe(policyDigestOf(toModel(chain)));
    expect(r.policyDigest).not.toBe(policyDigestOf(toModel({ predicates: [{ verb: 'v', where: [S1] }], caveats: [{ type: 'max_blast_radius', max: 5 }], meet: ancestors.slice(0, 1) })));
  });

  it('is never when any ancestor has no surviving permit', () => {
    const chain: PolicyInput = { predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'other' }] }] };
    expect(residual(chain, { verb: 'v' })).toMatchObject({ decision: 'never', reason: 'no permit survives the known facts' });
    const chain2: PolicyInput = { predicates: [{ verb: 'other' }], meet: [{ predicates: [{ verb: 'v' }] }] };
    expect(residual(chain2, { verb: 'v' }).decision).toBe('never');
  });

  it('a result without ancestors has no meet key', () => {
    const r = residual({ predicates: [{ verb: 'v', where: [S1] }] }, { verb: 'v' });
    expect('meet' in r.policy).toBe(false);
    expect(r.policy).toStrictEqual({ predicates: [{ verb: '*', where: [S1] }], caveats: [], vetoes: [], tighten: [] });
  });
});

describe('never results', () => {
  const base: PolicyInput = { predicates: [{ verb: 'v' }] };
  const empty = { predicates: [], caveats: [], vetoes: [], tighten: [] };

  it('carries the exact shape', () => {
    const p: PolicyInput = { predicates: [{ verb: 'v' }], caveats: [{ type: 'expires', at: 5 }, { type: 'not_before', at: 10 }] };
    expect(residual(p, { verb: 'v' })).toStrictEqual({
      decision: 'never',
      reason: 'caveats unsatisfiable: not_before (10) >= expires (5): the validity window is empty',
      policy: empty,
      policyDigest: policyDigestOf(toModel(p)),
    });
    expect(residual(base, { verb: 'x' })).toStrictEqual({ decision: 'never', reason: 'no permit survives the known facts', policy: empty, policyDigest: policyDigestOf(toModel(base)) });
    const chainBad: PolicyInput = { predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'v' }], caveats: [{ type: 'rate', max: 0, per_secs: 1 }] }] };
    expect(residual(chainBad, { verb: 'v' }).reason).toBe('caveats unsatisfiable: rate.max 0 < 1 forbids every action');
  });

  it('the reversibility cap is checked against the known class', () => {
    const classes = ['reversible', 'rate_limited', 'irreversible'];
    classes.forEach((cap, capIdx) => {
      const p: PolicyInput = { predicates: [{ verb: 'v' }], caveats: [{ type: 'reversibility_max', class: cap }] };
      classes.forEach((cls, i) => {
        const r = residual(p, { verb: 'v', reversibilityClass: cls });
        if (i <= capIdx) expect(r.decision, `${cls} under ${cap}`).not.toBe('never');
        else expect(r, `${cls} under ${cap}`).toMatchObject({ decision: 'never', reason: 'reversibility class exceeds the caveat cap' });
      });
      expect(residual(p, { verb: 'v', reversibilityClass: 'bogus' })).toMatchObject({ decision: 'never', reason: 'reversibility class exceeds the caveat cap' });
      // no class known: nothing to rule out
      expect(residual(p, { verb: 'v' }).decision).not.toBe('never');
    });
    // no cap: any class, even an unrecognised one, is left alone
    expect(residual(base, { verb: 'v', reversibilityClass: 'irreversible' }).decision).toBe('always');
    expect(residual(base, { verb: 'v', reversibilityClass: 'bogus' }).decision).toBe('always');
  });

  it('a deny veto is certain only when nothing about it depends on the unknowns', () => {
    const p = (veto: Veto): PolicyInput => ({ predicates: [{ verb: 'v' }], vetoes: [veto] });
    const certain = (veto: Veto, k: KnownContext = { verb: 'v' }): boolean => {
      const r = residual(p(veto), k);
      if (r.decision === 'never') {
        expect(r.reason).toBe(`veto ${veto.id} applies to every completion`);
        return true;
      }
      return false;
    };
    expect(certain({ id: 'a', kind: 'deny', when: { verb: 'v' } })).toBe(true);
    expect(certain({ id: 'b', kind: 'deny', when: { verb: 'v', resource: '*' } })).toBe(true);
    expect(certain({ id: 'c', kind: 'deny', when: { verb: 'v', resource: '/a/*' } })).toBe(false);
    expect(certain({ id: 'c', kind: 'deny', when: { verb: 'v', resource: '/a/*' } }, { verb: 'v', resource: '/a/1' })).toBe(true);
    expect(certain({ id: 'd', kind: 'deny', when: { verb: 'v', where: [S1] } })).toBe(false);
    expect(certain({ id: 'e', kind: 'approval', when: { verb: 'v' } })).toBe(false);
    expect(certain({ id: 'f', kind: 'deny', when: { verb: 'v' }, unless: [S1] })).toBe(false);
    expect(certain({ id: 'g', kind: 'deny', when: { verb: 'v' }, unless: [F] }, KNOWN)).toBe(true);
    expect(certain({ id: 'h', kind: 'deny', when: { verb: 'v' }, unless: [U] }, KNOWN)).toBe(true);
    expect(certain({ id: 'i', kind: 'deny', when: { verb: 'v' }, over: { path: 'action.params.amount', threshold: 5 } })).toBe(false);
    expect(certain({ id: 'j', kind: 'deny', when: { verb: 'v', where: [T] } }, KNOWN)).toBe(true);
    // a veto on an ancestor counts too
    const chain: PolicyInput = { predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'v' }], vetoes: [{ id: 'anc', kind: 'deny', when: { verb: 'v' } }] }] };
    expect(residual(chain, { verb: 'v' }).reason).toBe('veto anc applies to every completion');
  });
});

describe('always results', () => {
  it('needs every part to have an unconditional permit and no veto or tighten rule', () => {
    expect(residual({ predicates: [{ verb: 'v' }] }, { verb: 'v' }).decision).toBe('always');
    expect(residual({ predicates: [{ verb: 'v', where: [S1] }] }, { verb: 'v' }).decision).toBe('conditional');
    // one unconditional clause among conditional ones is enough
    expect(residual({ predicates: [{ verb: 'v', where: [S1] }, { verb: 'v' }] }, { verb: 'v' }).decision).toBe('always');
    expect(residual({ predicates: [{ verb: 'v' }], vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }] }, { verb: 'v' }).decision).toBe('conditional');
    expect(residual({ predicates: [{ verb: 'v' }], tighten: [{ id: 't', when: S1, signal: 'escalate' }] }, { verb: 'v' }).decision).toBe('conditional');
    // every ancestor must qualify
    expect(residual({ predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'v', where: [S1] }] }] }, { verb: 'v' }).decision).toBe('conditional');
    expect(residual({ predicates: [{ verb: 'v', where: [S1] }], meet: [{ predicates: [{ verb: 'v' }] }] }, { verb: 'v' }).decision).toBe('conditional');
    expect(residual({ predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'v' }] }] }, { verb: 'v' }).decision).toBe('always');
    expect(residual({ predicates: [{ verb: 'v' }], meet: [{ predicates: [{ verb: 'v' }], vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }] }] }, { verb: 'v' }).decision).toBe('conditional');
  });
});

describe('tighten rules', () => {
  const withTighten = (when: Condition) => residual({ predicates: [{ verb: 'v' }], tighten: [{ id: 't', when, signal: 'escalate' }] }, KNOWN).policy.tighten;
  it('drops a rule that cleanly cannot hold and keeps the rest', () => {
    expect(withTighten(F)).toEqual([]);
    expect(withTighten(T)).toEqual([{ id: 't', when: T, signal: 'escalate' }]);
    expect(withTighten(U)).toEqual([{ id: 't', when: U, signal: 'escalate' }]);
    expect(withTighten(S1)).toEqual([{ id: 't', when: S1, signal: 'escalate' }]);
    // a partly folded trigger is replaced by its residue
    expect(withTighten({ all_of: [T, S1] })).toEqual([{ id: 't', when: S1, signal: 'escalate' }]);
    expect(withTighten({ not: { all_of: [T, S1] } })).toEqual([{ id: 't', when: { not: S1 }, signal: 'escalate' }]);
  });
  it('keeps every field of the rule and the order of several rules', () => {
    const r = residual(
      { predicates: [{ verb: 'v' }], tighten: [{ id: 'a', when: F, signal: 'deny' }, { id: 'b', when: S1, signal: 'deny' }, { id: 'c', when: T, signal: 'escalate' }] },
      KNOWN,
    );
    expect(r.policy.tighten).toStrictEqual([
      { id: 'b', when: S1, signal: 'deny' },
      { id: 'c', when: T, signal: 'escalate' },
    ]);
  });
});

describe('vetoes', () => {
  const run = (veto: Veto, k: KnownContext = KNOWN, o?: ResidualOptions): Residual => residual({ predicates: [{ verb: 'v' }], vetoes: [veto] }, k, o);
  const approval = (extra: Partial<Veto> = {}): Veto => ({ id: 'ap', kind: 'approval', when: { verb: 'v' }, ...extra });

  it('is dropped when its verb or resource cannot match the known facts, and keeps its matchers when they are unknown', () => {
    expect(run(approval({ when: { verb: 'other' } })).policy.vetoes).toEqual([]);
    expect(run(approval({ when: { verb: ['x', 'v'] } })).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    expect(run(approval({ when: { verb: '*' } })).policy.vetoes).toHaveLength(1);
    // verb unknown: the matcher is kept as written
    expect(run(approval({ when: { verb: 'other' } }), {}).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: 'other' } }]);
    // resource known and not matching: dropped; matching: the matcher is no longer needed
    expect(run(approval({ when: { verb: 'v', resource: '/a/*' } }), { verb: 'v', resource: '/b/1' }).policy.vetoes).toEqual([]);
    expect(run(approval({ when: { verb: 'v', resource: '/a/*' } }), { verb: 'v', resource: '/a/1' }).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    // resource unknown: kept; none: no resource key at all
    expect(run(approval({ when: { verb: 'v', resource: '/a/*' } }), { verb: 'v' }).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*', resource: '/a/*' } }]);
    expect(run(approval(), { verb: 'v' }).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    expect(run(approval({ when: { verb: 'v', resource: '/a/*' } }), { verb: 'v', resource: '/a/1' }, { resourceUnknown: true }).policy.vetoes).toStrictEqual([
      { id: 'ap', kind: 'approval', when: { verb: '*', resource: '/a/*' } },
    ]);
  });

  it('its where list follows veto polarity: a clean false removes it, true and unknown leave it unconditional', () => {
    const w = (where: Condition[]) => run(approval({ when: { verb: 'v', where } })).policy.vetoes;
    expect(w([F])).toEqual([]);
    expect(w([T, F])).toEqual([]);
    expect(w([T])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    expect(w([U])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    expect(w([T, U])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
    expect(w([S1])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*', where: [S1] } }]);
    expect(w([T, S1, U])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*', where: [S1, U] } }]);
    expect(w([])).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
  });

  it('an amount threshold on a known value removes the veto unless the amount is over, missing, not a finite number, or negative', () => {
    const over: Veto = { id: 'o', kind: 'deny', when: { verb: 'v' }, over: { path: 'subject.amt', threshold: 100 } };
    const dec = (subject: Record<string, unknown>) => run(over, { verb: 'v', subject }).decision;
    expect(dec({ amt: 100 })).toBe('always');
    expect(dec({ amt: 99.9 })).toBe('always');
    expect(dec({ amt: 0 })).toBe('always');
    expect(dec({ amt: 101 })).toBe('never');
    expect(dec({ amt: 100.5 })).toBe('never');
    expect(dec({ amt: -1 })).toBe('never');
    expect(dec({ amt: Number.NaN })).toBe('never');
    expect(dec({ amt: 'abc' })).toBe('never');
    expect(dec({ amt: null })).toBe('never');
    expect(dec({})).toBe('never');
    expect(run(over, { verb: 'v' }).decision).toBe('never');
  });

  it('an amount threshold on an unknown value is carried', () => {
    const over: Veto = { id: 'o', kind: 'deny', when: { verb: 'v' }, over: { path: 'action.params.amount', threshold: 100 } };
    const r = run(over);
    expect(r.decision).toBe('conditional');
    expect(r.policy.vetoes).toStrictEqual([{ id: 'o', kind: 'deny', when: { verb: '*' }, over: { path: 'action.params.amount', threshold: 100 } }]);
    // known amount: folded away, not carried
    expect(run(over, { verb: 'v', params: { amount: 5 } }, { unknown: [] }).policy.vetoes).toEqual([]);
    expect(run(over, { verb: 'v', params: { amount: 500 } }, { unknown: [] }).decision).toBe('never');
  });

  it('a deny veto with an exception: a certain exception removes it, an uncertain one stays', () => {
    const deny = (unless?: Condition[]): Veto => ({ id: 'd', kind: 'deny', when: { verb: 'v', where: [S1] }, ...(unless ? { unless } : {}) });
    expect(run(deny([T])).policy.vetoes).toEqual([]);
    expect(run(deny([])).policy.vetoes).toEqual([]);
    expect(run(deny([F])).policy.vetoes).toStrictEqual([{ id: 'd', kind: 'deny', when: { verb: '*', where: [S1] } }]);
    expect(run(deny([U])).policy.vetoes).toStrictEqual([{ id: 'd', kind: 'deny', when: { verb: '*', where: [S1] } }]);
    expect(run(deny([S2])).policy.vetoes).toStrictEqual([{ id: 'd', kind: 'deny', when: { verb: '*', where: [S1] }, unless: [S2] }]);
    expect(run(deny([T, S2, U])).policy.vetoes).toStrictEqual([{ id: 'd', kind: 'deny', when: { verb: '*', where: [S1] }, unless: [S2, U] }]);
    expect(run(deny()).policy.vetoes).toStrictEqual([{ id: 'd', kind: 'deny', when: { verb: '*', where: [S1] } }]);
  });

  it('an approval veto carries its evidence of approval as written and never uses it to drop the veto', () => {
    expect(run(approval({ unless: [T] })).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' }, unless: [T] }]);
    expect(run(approval({ unless: [F, S1, U] })).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' }, unless: [F, S1, U] }]);
    expect(run(approval({ unless: [] })).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' }, unless: [] }]);
    expect(run(approval()).policy.vetoes).toStrictEqual([{ id: 'ap', kind: 'approval', when: { verb: '*' } }]);
  });

  it('several vetoes keep their order and each is judged alone', () => {
    const r = residual(
      {
        predicates: [{ verb: 'v' }],
        vetoes: [
          { id: 'one', kind: 'approval', when: { verb: 'v', where: [S1] } },
          { id: 'gone', kind: 'approval', when: { verb: 'other' } },
          { id: 'two', kind: 'approval', when: { verb: 'v', where: [S2] } },
        ],
      },
      KNOWN,
    );
    expect(r.policy.vetoes.map((v) => v.id)).toEqual(['one', 'two']);
  });
});

describe('residualPolicy and evaluateResidual', () => {
  const P: PolicyInput = {
    predicates: [{ verb: 'v', where: [{ field: 'subject.tier', op: 'eq', value: 'gold' }, { field: 'env.mode', op: 'eq', value: 'live' }] }],
    caveats: [{ type: 'reversibility_max', class: 'rate_limited' }],
  };
  const r = residual(P, { verb: 'v' }, { unknown: ['action.params', 'subject.tier', 'env.mode'] });
  const ctx = (over: Partial<ActionContext> = {}, cls: string | null = 'reversible'): ActionContext => ({
    action: { verb: 'v', resource: '/r', params: {}, ...(cls !== null ? { reversibility_class: cls } : {}) },
    subject: { tier: 'gold' },
    env: { mode: 'live' },
    ...over,
  });

  it('the context reaches the residual policy: subject, env and reversibility class', () => {
    expect(evaluateResidual(r, ctx())).toBe('allow');
    expect(evaluateResidual(r, ctx({ subject: { tier: 'tin' } }))).toBe('deny');
    expect(evaluateResidual(r, ctx({ env: { mode: 'test' } }))).toBe('deny');
    expect(evaluateResidual(r, ctx({}, 'rate_limited'))).toBe('allow');
    expect(evaluateResidual(r, ctx({}, 'irreversible'))).toBe('deny');
    expect(evaluateResidual(r, ctx({}, null))).toBe('deny');
  });

  it('a never residual denies whatever its policy says', () => {
    const forged: Residual = { decision: 'never', reason: 'x', policy: { predicates: [{ verb: '*' }], caveats: [], vetoes: [], tighten: [] }, policyDigest: 'd' };
    expect(evaluateResidual(forged, ctx())).toBe('deny');
    expect(evaluateResidual({ ...forged, decision: 'always' }, ctx())).toBe('allow');
    expect(evaluateResidual({ ...forged, decision: 'conditional' }, ctx())).toBe('allow');
  });

  it('residualPolicy carries the ancestors as copies and omits meet when there are none', () => {
    const chain = residual({ predicates: [{ verb: 'v', where: [S1] }], meet: [{ predicates: [{ verb: 'v', where: [S2] }] }] }, { verb: 'v' });
    const rp = residualPolicy(chain);
    expect(rp).toStrictEqual({
      predicates: [{ verb: '*', where: [S1] }],
      caveats: [],
      vetoes: [],
      tighten: [],
      meet: [{ predicates: [{ verb: '*', where: [S2] }], caveats: [], vetoes: [], tighten: [] }],
    });
    expect((rp as unknown as { meet: unknown[] }).meet[0]).not.toBe(chain.policy.meet![0]);
    const plain = residualPolicy(residual({ predicates: [{ verb: 'v', where: [S1] }] }, { verb: 'v' }));
    expect('meet' in plain).toBe(false);
  });
});

// ---- "what may I do?" -------------------------------------------------------------------------------

const pt = (x: number) => ({ lo: x, hi: x, loInclusive: true, hiInclusive: true });
const digestOf = (p: PolicyInput): string => policyDigestOf(toModel(p));
const P = 'action.params.n';
const shapeOf = (params: VerbShape['params']): VerbShape => ({ verb: 'v', params });
const one = (policy: PolicyInput, params: VerbShape['params'], known: KnownContext = {}, opts: WhatMayIDoOptions = {}) => whatMayIDo(policy, [shapeOf(params)], known, opts)[0]!;
const permitWhere = (where: Condition[]): PolicyInput => ({ predicates: [{ verb: 'v', where }] });
const FRESH_OTHER = { autonomous: [], withApproval: [], other: true };

describe('whatMayIDo: numeric ranges', () => {
  it('lists points in order even when the policy names them out of order', () => {
    const policy = permitWhere([{ field: P, op: 'in', value: [300, 100, 200] }]);
    expect(one(policy, { n: { type: 'integer' } })).toEqual({
      verb: 'v',
      status: 'autonomous',
      params: { n: { kind: 'numeric', autonomous: [pt(100), pt(200), pt(300)], withApproval: [] } },
      resources: FRESH_OTHER,
      policyDigest: digestOf(policy),
      advisory: true,
    });
  });

  it('keeps two open ranges apart when the point between them is excluded', () => {
    const e = one(permitWhere([{ field: P, op: 'ne', value: 10 }]), { n: { type: 'integer' } });
    expect(e.status).toBe('autonomous');
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 10 }, { lo: 10 }], withApproval: [] });
  });

  it('joins a point to the open ranges around it, and drops the closing bound when the range runs on', () => {
    const e = one(permitWhere([{ any_of: [{ field: P, op: 'lt', value: 5 }, { field: P, op: 'gte', value: 10 }] }]), { n: { type: 'integer' } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 5 }, { lo: 10, loInclusive: true }], withApproval: [] });
    const lte = one(permitWhere([{ field: P, op: 'lte', value: 10 }]), { n: { type: 'integer' } });
    expect(lte.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 10, hiInclusive: true }], withApproval: [] });
  });

  it('finds thresholds inside nested groups and value lists', () => {
    const e = one(
      permitWhere([
        {
          any_of: [
            { all_of: [{ field: P, op: 'gte', value: 10 }, { not: { field: P, op: 'gte', value: 20 } }] },
            { field: P, op: 'in', value: [30, 40] },
          ],
        },
      ]),
      { n: { type: 'integer' } },
    );
    expect(e.params.n).toStrictEqual({
      kind: 'numeric',
      autonomous: [{ lo: 10, hi: 20, loInclusive: true }, pt(30), pt(40)],
      withApproval: [],
    });
  });

  it('only numeric entries of a value list are thresholds', () => {
    const e = one(permitWhere([{ any_of: [{ field: P, op: 'gte', value: 10 }, { field: P, op: 'in', value: [10, '40'] }] }]), { n: { type: 'integer' } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 10, loInclusive: true }], withApproval: [] });
  });

  it('a malformed group inside a symbolic condition is skipped when collecting thresholds', () => {
    const malformed = { any_of: [{ field: P, op: 'gte', value: 10 }, { all_of: 'x' }, { any_of: 'y' }] } as unknown as Condition;
    const e = one(permitWhere([malformed]), { n: { type: 'integer' } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 10, loInclusive: true }], withApproval: [] });
  });

  it('many shuffled thresholds still give ordered neighbouring ranges', () => {
    const N = 61;
    const pts = Array.from({ length: N }, (_, i) => ((i * 37) % N) * 7 + 3); // a shuffled permutation
    const sorted = [...pts].sort((x, y) => x - y);
    const e = one(permitWhere([{ field: P, op: 'nin', value: pts }]), { n: { type: 'integer' } });
    const expected: Record<string, number>[] = [{ hi: sorted[0]! }];
    for (let i = 0; i + 1 < N; i++) expected.push({ lo: sorted[i]!, hi: sorted[i + 1]! });
    expected.push({ lo: sorted[N - 1]! });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: expected, withApproval: [] });
  });

  it('clips ranges to the declared minimum and maximum', () => {
    // both bounds are policy thresholds: the closed range [5, 9]
    const closed = one(permitWhere([{ field: P, op: 'gte', value: 5 }, { field: P, op: 'lte', value: 9 }]), { n: { type: 'integer', min: 5, max: 9 } });
    expect(closed.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 5, hi: 9, loInclusive: true, hiInclusive: true }], withApproval: [] });
    // a lower bound that is open stays open at the minimum
    const openLo = one(permitWhere([{ field: P, op: 'gt', value: 5 }, { field: P, op: 'lte', value: 9 }]), { n: { type: 'integer', min: 5, max: 9 } });
    expect(openLo.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 5, hi: 9, hiInclusive: true }], withApproval: [] });
    // an upper bound that is open stays open at the maximum
    const openHi = one(permitWhere([{ field: P, op: 'gt', value: 5 }, { field: P, op: 'lt', value: 9 }]), { n: { type: 'integer', max: 9 } });
    expect(openHi.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 5, hi: 9 }], withApproval: [] });
    // a range that starts below the minimum is cut to it
    const cut = one(permitWhere([{ field: P, op: 'gt', value: -10 }, { field: P, op: 'lte', value: 500 }]), { n: { type: 'integer', min: 0 } });
    expect(cut.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 0, loInclusive: true, hi: 500, hiInclusive: true }], withApproval: [] });
    // a range that runs on is cut to the maximum
    const runsOn = one(permitWhere([{ field: P, op: 'gte', value: 5 }]), { n: { type: 'integer', min: 0, max: 20 } });
    expect(runsOn.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 5, hi: 20, loInclusive: true, hiInclusive: true }], withApproval: [] });
    // only a maximum: the range below the threshold is cut at it, closed
    const onlyMax = one(permitWhere([{ field: P, op: 'lte', value: 500 }]), { n: { type: 'integer', max: 100 } });
    expect(onlyMax.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 100, hiInclusive: true }], withApproval: [] });
  });

  it('values the schema forbids are not part of the domain', () => {
    const e = one(permitWhere([{ field: P, op: 'in', value: [-3, 5, 30] }]), { n: { type: 'integer', min: 0, max: 20 } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [pt(5)], withApproval: [] });
  });

  it('a bounded parameter the policy never mentions spans its whole declared range', () => {
    const e = one({ predicates: [{ verb: 'v' }] }, { n: { type: 'integer', min: 0, max: 100 } });
    expect(e.status).toBe('autonomous');
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 0, loInclusive: true, hi: 100, hiInclusive: true }], withApproval: [] });
  });

  it('a parameter that is numeric by its values is numeric even without a declared type', () => {
    const e = one(permitWhere([{ field: P, op: 'lte', value: 5 }]), { n: {} });
    expect(e.params.n).toMatchObject({ kind: 'numeric' });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 5, hiInclusive: true }], withApproval: [] });
  });

  it('puts the approval threshold between the autonomous and the approval range, per parameter', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'v', where: [{ field: 'action.params.amount', op: 'lte', value: 500 }, { field: 'action.params.qty', op: 'lte', value: 500 }] }],
      vetoes: [{ id: 'big', kind: 'approval', when: { verb: 'v' }, over: { path: 'action.params.amount', threshold: 200 }, unless: [{ field: 'env.approved', op: 'eq', value: true }] }],
    };
    const e = one(policy, { amount: { type: 'integer', min: 0, max: 100000 }, qty: { type: 'integer', min: 0, max: 1000 } });
    expect(e.status).toBe('autonomous');
    expect(e.params.amount).toStrictEqual({
      kind: 'numeric',
      autonomous: [{ lo: 0, loInclusive: true, hi: 200, hiInclusive: true }],
      withApproval: [{ lo: 200, hi: 500, hiInclusive: true }],
    });
    // the threshold belongs to the amount only
    expect(e.params.qty).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 0, loInclusive: true, hi: 500, hiInclusive: true }], withApproval: [] });
  });
});

describe('whatMayIDo: enumerated and free parameters', () => {
  it('a closed value set the policy never mentions is listed in order', () => {
    const e = one({ predicates: [{ verb: 'v' }] }, { tag: { type: 'string', values: ['z', 'a'] } });
    expect(e.params.tag).toStrictEqual({ kind: 'enum', autonomous: ['a', 'z'], withApproval: [], otherAutonomous: false, otherWithApproval: false });
  });

  it('an open string parameter reports whether values outside the policy are admitted', () => {
    const open = one(permitWhere([{ field: 'action.params.note', op: 'ne', value: 'x' }]), { note: { type: 'string' } });
    expect(open.params.note).toStrictEqual({ kind: 'enum', autonomous: [], withApproval: [], otherAutonomous: true, otherWithApproval: false });
    const closed = one(permitWhere([{ field: 'action.params.note', op: 'in', value: ['b', 'a'] }]), { note: { type: 'string' } });
    expect(closed.params.note).toStrictEqual({ kind: 'enum', autonomous: ['a', 'b'], withApproval: [], otherAutonomous: false, otherWithApproval: false });
  });

  it('a value that starts with the internal marker is treated as the marker, not listed', () => {
    const e = one(permitWhere([{ field: 'action.params.note', op: 'in', value: ['\u0000lit', 'b'] }]), { note: { type: 'string' } });
    expect(e.params.note).toStrictEqual({ kind: 'enum', autonomous: ['b'], withApproval: [], otherAutonomous: true, otherWithApproval: false });
  });

  it('when everything needs approval, the other values need approval too', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'v', where: [{ field: 'action.params.note', op: 'ne', value: 'x' }] }],
      vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v' } }],
    };
    const e = one(policy, { note: { type: 'string' } });
    expect(e.status).toBe('needs-approval');
    expect(e.params.note).toStrictEqual({ kind: 'enum', autonomous: [], withApproval: [], otherAutonomous: false, otherWithApproval: true });
    expect(e.resources).toEqual({ autonomous: [], withApproval: [], other: true });
  });

  it('a parameter nothing constrains is unconstrained and does not hide the verb', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'v' }] };
    const e = one(policy, { note: { type: 'string' } });
    expect(e).toEqual({ verb: 'v', status: 'autonomous', params: { note: { kind: 'unconstrained' } }, resources: FRESH_OTHER, policyDigest: digestOf(policy), advisory: true });
    expect(e.params.note).toStrictEqual({ kind: 'unconstrained' });
  });

  it('separates autonomous values from values that need approval, and a value seen both ways is autonomous', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'v', resource: '/r/*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }],
      vetoes: [{ id: 'ap', kind: 'approval', when: { verb: 'v', where: [{ field: 'action.params.kind', op: 'eq', value: 'big' }] } }],
    };
    const e = one(policy, { amount: { type: 'integer' }, kind: { type: 'string', values: ['big', 'small'] } });
    expect(e).toEqual({
      verb: 'v',
      status: 'autonomous',
      params: {
        amount: { kind: 'numeric', autonomous: [{ hi: 100, hiInclusive: true }], withApproval: [] },
        kind: { kind: 'enum', autonomous: ['small'], withApproval: ['big'], otherAutonomous: false, otherWithApproval: false },
      },
      resources: { autonomous: ['/r/', '/r/x'], withApproval: [], other: false },
      policyDigest: digestOf(policy),
      advisory: true,
    });
  });

  it('a verb with nothing admitted has empty domains', () => {
    const policy = permitWhere([{ field: P, op: 'eq', value: 1 }, { field: P, op: 'eq', value: 2 }]);
    const e = one(policy, { n: { type: 'integer' }, tag: { type: 'string', values: ['a'] } });
    expect(e).toEqual({
      verb: 'v',
      status: 'denied',
      params: {
        n: { kind: 'numeric', autonomous: [], withApproval: [] },
        tag: { kind: 'enum', autonomous: [], withApproval: [], otherAutonomous: false, otherWithApproval: false },
      },
      resources: { autonomous: [], withApproval: [], other: false },
      policyDigest: digestOf(policy),
      advisory: true,
    });
  });
});

describe('whatMayIDo: resources', () => {
  it('lists resources by how they are admitted, sorted', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'v', resource: '/zz' }, { verb: 'v', resource: '/aa' }, { verb: 'v', resource: '/yy' }, { verb: 'v', resource: '/cc' }],
      vetoes: [
        { id: 'one', kind: 'approval', when: { verb: 'v', resource: '/yy' } },
        { id: 'two', kind: 'approval', when: { verb: 'v', resource: '/cc' } },
      ],
    };
    const e = one(policy, {});
    expect(e.status).toBe('autonomous');
    expect(e.resources).toEqual({ autonomous: ['/aa', '/zz'], withApproval: ['/cc', '/yy'], other: false });
  });

  it('a resource that starts with the internal marker is treated as the marker', () => {
    const e = one({ predicates: [{ verb: 'v', resource: '\u0000r' }, { verb: 'v', resource: '/z' }] }, {});
    expect(e.resources).toEqual({ autonomous: ['/z'], withApproval: [], other: true });
  });

  it('a known resource narrows the answer to it', () => {
    const e = one({ predicates: [{ verb: 'v', resource: '/acct/*' }] }, {}, { resource: '/acct/1' });
    expect(e.status).toBe('autonomous');
    expect(e.resources).toEqual({ autonomous: ['/acct/1'], withApproval: [], other: false });
    const none = one({ predicates: [{ verb: 'v', resource: '/acct/*' }] }, {}, { resource: '/other/1' });
    expect(none.status).toBe('denied');
    expect(none.reason).toBe('no permit survives the known facts');
  });
});

describe('whatMayIDo: statuses, bounds and pass-through', () => {
  it('a denied verb has the exact empty shape, and processing continues with the next verb', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'v' }] };
    const out = whatMayIDo(policy, [{ verb: 'nope', params: {} }, { verb: 'v', params: {} }], {});
    expect(out).toHaveLength(2);
    expect(out[0]).toStrictEqual({
      verb: 'nope',
      status: 'denied',
      params: {},
      resources: { autonomous: [], withApproval: [], other: false },
      policyDigest: digestOf(policy),
      advisory: true,
      reason: 'no permit survives the known facts',
    });
    expect(out[1]!.status).toBe('autonomous');
  });

  it('passes the remaining budget and missing discharges through as copies, and omits them otherwise', () => {
    const remaining = { usd: 40 };
    const missing = ['compliance'];
    const e = one({ predicates: [{ verb: 'v' }] }, {}, {}, { remaining, missingDischarges: missing });
    expect(e.remaining).toEqual({ usd: 40 });
    expect(e.remaining).not.toBe(remaining);
    expect(e.missingDischarges).toEqual(['compliance']);
    expect(e.missingDischarges).not.toBe(missing);
    const plain = one({ predicates: [{ verb: 'v' }] }, {});
    expect('remaining' in plain).toBe(false);
    expect('missingDischarges' in plain).toBe(false);
  });

  it('refuses to claim a domain when the grid is larger than the bound, and honours a bound that is exactly met', () => {
    const policy = permitWhere([{ field: P, op: 'in', value: [300, 100, 200] }]);
    // the grid has 9 representatives
    const exact = one(policy, { n: { type: 'integer' } }, {}, { maxCombinations: 9 });
    expect(exact.status).toBe('autonomous');
    expect('approximate' in exact).toBe(false);
    const over = whatMayIDo(policy, [shapeOf({ n: { type: 'integer' } })], {}, { maxCombinations: 8 });
    expect(over).toStrictEqual([
      {
        verb: 'v',
        status: 'needs-approval',
        params: {},
        resources: { autonomous: [], withApproval: [], other: false },
        policyDigest: digestOf(policy),
        advisory: true,
        approximate: true,
        reason: 'representative grid exceeded the bound; no domain is claimed',
      },
    ]);
    // a bound that is not a number is ignored
    const ignored = one(policy, { n: { type: 'integer' } }, {}, { maxCombinations: '8' as unknown as number });
    expect(ignored.status).toBe('autonomous');
    // the bound ends the verb: the next verb is still answered
    const two = whatMayIDo(policy, [shapeOf({ n: { type: 'integer' } }), { verb: 'other', params: {} }], {}, { maxCombinations: 8 });
    expect(two.map((x) => x.status)).toEqual(['needs-approval', 'denied']);
  });

  it('varies the reversibility class only when a caveat caps it', () => {
    const capped: PolicyInput = { predicates: [{ verb: 'v' }], caveats: [{ type: 'reversibility_max', class: 'rate_limited' }] };
    const e = one(capped, {});
    expect(e).toEqual({ verb: 'v', status: 'autonomous', params: {}, resources: FRESH_OTHER, policyDigest: digestOf(capped), advisory: true });
  });

  it('flags an over-approximation and says why', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'v', resource: 're:/a/.*', where: [{ field: 'action.params.q', op: 'like', value: 'a*' }] }] };
    const e = one(policy, { q: { type: 'string' } });
    expect(e.approximate).toBe(true);
    expect(e.reason).toMatch(/^over-approximated \(re: regex resource matcher .+ enumerated; `like` condition .+ exactly\)$/);
  });
});

describe('partial evaluation: paths, negated groups and the known action', () => {
  it('a path is an ancestor of an unknown only when the unknown continues it at a dot', () => {
    // 'subject.ab' is not below 'subject.a': the condition on subject.a folds
    expect(tri(T, KNOWN, { unknown: ['subject.ab'] })).toBe('true');
    expect(tri(T, KNOWN, { unknown: ['subject.a.b'] })).toEqual(T);
  });

  it('a negated symbolic any_of stays symbolic', () => {
    expect(tri({ not: { any_of: [S1, S2] } })).toEqual({ not: { any_of: [S1, S2] } });
    expect(tri({ not: { any_of: [F, S1, S2] } })).toEqual({ not: { any_of: [S1, S2] } });
  });

  it('the known action has no reversibility class member unless one is known', () => {
    const whole = (value: Record<string, unknown>): PolicyInput => ({ predicates: [{ verb: 'v', where: [{ field: 'action', op: 'eq', value }] }] });
    const bare = { verb: 'v', resource: '/r', params: {} };
    expect(residual(whole(bare), { verb: 'v', resource: '/r' }, { unknown: [] }).decision).toBe('always');
    expect(residual(whole({ ...bare, reversibility_class: 'reversible' }), { verb: 'v', resource: '/r', reversibilityClass: 'reversible' }, { unknown: [] }).decision).toBe('always');
    expect(residual(whole(bare), { verb: 'v', resource: '/r', reversibilityClass: 'reversible' }, { unknown: [] }).decision).toBe('never');
  });
});

describe('whatMayIDo: range order and merging', () => {
  it('a range open below sorts first even when its value was seen after a higher point', () => {
    // the eq literal is probed before the cell values, so 20 is seen before 9
    const later = one(permitWhere([{ any_of: [{ field: P, op: 'eq', value: 20 }, { field: P, op: 'lt', value: 10 }] }]), { n: { type: 'integer' } });
    expect(later.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 10 }, pt(20)], withApproval: [] });
    const earlier = one(permitWhere([{ any_of: [{ field: P, op: 'lt', value: 10 }, { all_of: [{ field: P, op: 'gte', value: 20 }, { field: P, op: 'lte', value: 20 }] }] }]), { n: { type: 'integer' } });
    expect(earlier.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ hi: 10 }, pt(20)], withApproval: [] });
  });

  it('a point sorts before the open range that starts at it, whichever was seen first', () => {
    // m is enumerated outside n: with m = 'a' the value 15 is admitted, with m = 'b' only 10, so 15 is seen first
    const mFirst = one(
      permitWhere([
        {
          any_of: [
            { all_of: [{ field: 'action.params.m', op: 'eq', value: 'a' }, { field: P, op: 'gt', value: 10 }, { field: P, op: 'lt', value: 20 }] },
            { all_of: [{ field: 'action.params.m', op: 'eq', value: 'b' }, { field: P, op: 'eq', value: 10 }] },
          ],
        },
      ]),
      { n: { type: 'integer' } },
    );
    expect(mFirst.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 10, hi: 20, loInclusive: true }], withApproval: [] });
    const pointFirst = one(permitWhere([{ field: P, op: 'gte', value: 10 }, { field: P, op: 'lt', value: 20 }]), { n: { type: 'integer' } });
    expect(pointFirst.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 10, hi: 20, loInclusive: true }], withApproval: [] });
  });

  it('several values in one unbounded cell merge into one range', () => {
    // the declared value list adds probes the policy does not threshold on: every one of them lies in the single cell
    const e = one({ predicates: [{ verb: 'v' }] }, { n: { type: 'integer', values: [1, 2] as unknown as string[] } });
    expect(e.status).toBe('autonomous');
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{}], withApproval: [] });
  });

  it('only a declared minimum still bounds a parameter the policy never mentions', () => {
    const e = one({ predicates: [{ verb: 'v' }] }, { n: { type: 'integer', min: 5 } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 5, loInclusive: true }], withApproval: [] });
  });

  it('a presence condition on the parameter contributes no threshold', () => {
    const e = one(permitWhere([{ field: P, op: 'exists' }, { field: P, op: 'gte', value: 10 }]), { n: { type: 'integer' } });
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 10, loInclusive: true }], withApproval: [] });
  });

  it('an amount threshold is a cell boundary as written', () => {
    // a threshold that is not a number is not a grid probe, but it still splits the approval range where it compares
    const policy: PolicyInput = {
      predicates: [{ verb: 'v', where: [{ field: P, op: 'gte', value: 0 }, { field: P, op: 'lte', value: 500 }, { field: P, op: 'ne', value: 50 }] }],
      vetoes: [{ id: 'big', kind: 'approval', when: { verb: 'v' }, over: { path: P, threshold: '100' as unknown as number } }],
    };
    const e = one(policy, { n: { type: 'integer' } });
    expect(e.status).toBe('autonomous');
    expect(e.params.n).toStrictEqual({ kind: 'numeric', autonomous: [{ lo: 0, hi: 50, loInclusive: true }], withApproval: [{ lo: '100', hi: 500, hiInclusive: true }] });
  });

  it('a closed value set never reports other values, even when they would need approval', () => {
    const policy: PolicyInput = {
      predicates: [{ verb: 'v' }],
      vetoes: [{ id: 'a', kind: 'approval', when: { verb: 'v', where: [{ field: 'action.params.tag', op: 'ne', value: 'a' }] } }],
    };
    const e = one(policy, { tag: { type: 'string', values: ['a', 'b'] } });
    expect(e.status).toBe('autonomous');
    expect(e.params.tag).toStrictEqual({ kind: 'enum', autonomous: ['a'], withApproval: ['b'], otherAutonomous: false, otherWithApproval: false });
  });
});
