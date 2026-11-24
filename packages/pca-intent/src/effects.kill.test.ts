import { describe, expect, it } from 'vitest';
import { checkPostconditions, effectContext, verifyOutcome, type EffectPostcondition, type IntentLearner, type Outcome, type VerbSpace } from './index';

const vs: VerbSpace = { verb: 'v', reversibility: 'reversible', weight: 1, dims: [] };
const o = (values: Record<string, number | string> = {}): Outcome => ({ verb: 'v', values });
const pc = (id: string, where: EffectPostcondition['where'], verb = 'v'): EffectPostcondition => ({ id, verb, description: id, where });
const eq1 = (field: string) => ({ field, op: 'eq' as const, value: 1 });

describe('postcondition leaves are collected through every group form', () => {
  it('all_of, any_of and not each contribute their leaves (pending names them all)', () => {
    const rep = checkPostconditions(
      vs,
      o(),
      {},
      [pc('g', [{ all_of: [eq1('env.effect.a'), eq1('env.effect.a2')] }, { any_of: [eq1('env.effect.b'), eq1('env.effect.b2')] }, { not: eq1('env.effect.c') }])],
    );
    expect(rep).toEqual({ status: 'pending', violated: [], missing: ['env.effect.a', 'env.effect.a2', 'env.effect.b', 'env.effect.b2', 'env.effect.c'], checked: [], notApplicable: [] });
  });
  it('a group key holding a non-array falls through to the next group key', () => {
    const rep = checkPostconditions(
      vs,
      o(),
      {},
      [pc('g', [{ all_of: 'x', any_of: [eq1('env.effect.m')] } as never, { any_of: 'y', not: eq1('env.effect.n') } as never])],
    );
    expect(rep.missing).toEqual(['env.effect.m', 'env.effect.n']);
    expect(rep.status).toBe('pending');
  });
  it('a group with a non-array all_of and nothing else contributes no leaves', () => {
    const rep = checkPostconditions(vs, o(), {}, [pc('g', [{ all_of: 'x' } as never])]);
    expect(rep.missing).toEqual([]);
    expect(rep.checked).toEqual(['g']);
  });
  it('a leaf with a non-string ref is treated as having no ref', () => {
    const rep = checkPostconditions(vs, o(), {}, [pc('r', [{ field: 'env.effect.a', op: 'eq', ref: 5 } as never])]);
    expect(rep.missing).toEqual(['env.effect.a']);
    expect(rep.notApplicable).toEqual([]);
  });
  it('a condition with no field is not a leaf; the evaluator fails it closed', () => {
    const rep = checkPostconditions(vs, o(), {}, [pc('nf', [{ op: 'eq', value: 1 } as never])]);
    expect(rep).toEqual({ status: 'violated', violated: ['nf'], missing: [], checked: ['nf'], notApplicable: [] });
  });
});

describe('effect path lookup is own-property and object-only', () => {
  it('does not read through strings, nulls or the prototype chain', () => {
    const rep = checkPostconditions(
      vs,
      o(),
      { a: 'str', n: null },
      [pc('p', [eq1('env.effect.a.length'), eq1('env.effect.n.b'), eq1('env.effect.constructor')])],
    );
    expect(rep.missing).toEqual(['env.effect.a.length', 'env.effect.constructor', 'env.effect.n.b']);
    expect(rep.status).toBe('pending');
  });
  it('reads a nested own value', () => {
    const rep = checkPostconditions(vs, o(), { a: { b: 1 } }, [pc('p', [eq1('env.effect.a.b')])]);
    expect(rep).toEqual({ status: 'ok', violated: [], missing: [], checked: ['p'], notApplicable: [] });
  });
});

describe('applicability and pending', () => {
  it('a clean report is exactly empty apart from checked; other verbs are skipped', () => {
    const rep = checkPostconditions(vs, o({ 'action.params.p': 7 }), { a: 7 }, [pc('ok1', [{ field: 'env.effect.a', op: 'eq', ref: 'action.params.p' }]), pc('other', [eq1('env.effect.zz')], 'w')]);
    expect(rep).toEqual({ status: 'ok', violated: [], missing: [], checked: ['ok1'], notApplicable: [] });
  });
  it('one clause naming an absent action parameter makes the whole postcondition not applicable', () => {
    const rep = checkPostconditions(vs, o(), { a: 1 }, [pc('na', [{ field: 'env.effect.a', op: 'eq', ref: 'action.params.q' }, eq1('env.effect.a')])]);
    expect(rep).toEqual({ status: 'ok', violated: [], missing: [], checked: [], notApplicable: ['na'] });
  });
  it('a ref into env.effect is never an action parameter: it is a missing effect field', () => {
    const rep = checkPostconditions(vs, o(), { a: 1 }, [pc('e', [{ field: 'env.effect.a', op: 'eq', ref: 'env.effect.b' }])]);
    expect(rep).toEqual({ status: 'pending', violated: [], missing: ['env.effect.b'], checked: [], notApplicable: [] });
  });
  it('only env.effect inputs can be pending; an absent action field is a failed clause', () => {
    const rep = checkPostconditions(vs, o(), {}, [pc('x', [{ field: 'action.params.p', op: 'gte', value: 0 }])]);
    expect(rep).toEqual({ status: 'violated', violated: ['x'], missing: [], checked: ['x'], notApplicable: [] });
  });
  it('missing fields are de-duplicated and sorted', () => {
    const rep = checkPostconditions(vs, o(), {}, [pc('s', [eq1('env.effect.z'), eq1('env.effect.m')]), pc('t', [eq1('env.effect.z')])]);
    expect(rep.missing).toEqual(['env.effect.m', 'env.effect.z']);
  });
});

describe('effectContext and verifyOutcome shape', () => {
  it('maps the outcome onto action / subject / env and adds the effect record', () => {
    const ctx = effectContext(vs, o({ 'action.params.amount': 1, 'action.resource': 'r1', 'env.hour': 5, 'subject.role': 'admin' }), { e: 1 });
    expect(ctx).toEqual({
      action: { verb: 'v', resource: 'r1', params: { amount: 1 }, reversibility_class: 'reversible' },
      subject: { role: 'admin' },
      env: { hour: 5, effect: { e: 1 } },
    });
  });
  it('without env or subject values only the effect is in env and no subject key exists', () => {
    const ctx = effectContext(vs, o({ 'action.params.amount': 1 }), { e: 1 });
    expect(ctx.env).toEqual({ effect: { e: 1 } });
    expect('subject' in ctx).toBe(false);
  });
  it('an unviolated outcome returns just the report', () => {
    const l = { omega: { v: 1, verbs: [vs], approximate: [] } } as unknown as IntentLearner;
    const pcs = [pc('ok1', [eq1('env.effect.a')])];
    const r = verifyOutcome(l, o(), { a: 1 }, pcs);
    expect(Object.keys(r)).toEqual(['report']);
    expect(r.report).toEqual(checkPostconditions(vs, o(), { a: 1 }, pcs));
    expect(r.report.status).toBe('ok');
  });
});
