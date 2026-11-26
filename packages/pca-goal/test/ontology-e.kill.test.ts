import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, checkOntology, ontologyForGoal, slotLits, toIrOntology, type IntentOntology, type OntVerb, type Template } from '../src';
import type { Goal } from '../src/ir';

const raw = <T>(x: unknown): T => JSON.parse(JSON.stringify(x));
const fresh = (): IntentOntology => raw<IntentOntology>(ALL_ONTOLOGIES.payments);
const tmpl = (o: IntentOntology, id: string): Template => {
  const t = o.templates.find((x) => x.id === id);
  if (!t) throw new Error(`no template ${id}`);
  return t;
};
const goal = (): Goal => raw<Goal>({
  v: 1, principal: 'p', ontDigest: '', nlDigest: '', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [],
});

describe('IR projection of money parameters', () => {
  // USD is allowed but not listed first, so the default can only come from the USD preference, not from the first currency
  const withVerb = (): IntentOntology => {
    const o = fresh();
    o.verbs.push(raw<OntVerb>({ id: 'pay2', effect: 'read', resource_type: 'charge', params: { z: { kind: 'count' }, amount: { kind: 'money', ccys: ['EUR', 'USD'] } } }));
    return o;
  };
  const params = (o: IntentOntology, ccy?: string) => toIrOntology(o, ccy !== undefined ? { ccy } : {}).verbs.find((v) => v.verb === 'pay2')?.params;
  const usd = { path: 'amount', ty: { k: 'q', u: { k: 'money', ccy: 'USD' } } };
  const cnt = { path: 'z', ty: { k: 'q', u: { k: 'count' } } };
  it('defaults to USD when USD is allowed, and lists parameters sorted by path', () => {
    expect(params(withVerb())).toEqual([usd, cnt]);
  });
  it('a requested currency the parameter does not allow falls back to USD', () => {
    expect(params(withVerb(), 'GBP')).toEqual([usd, cnt]);
  });
});

describe('ontologyForGoal', () => {
  it('declares no relation tables unless given', () => {
    expect(ontologyForGoal(fresh(), goal()).rels).toEqual([]);
  });
});

describe('slot references inside a one_of selector', () => {
  it('an undeclared $slot among one_of members is refused', () => {
    const o = fresh();
    const t = tmpl(o, 'read_customer_charges');
    t.example = {};
    t.grants[0]!.res = { k: 'oneof', ids: ['$ghost'] };
    expect(checkOntology(o).filter((i) => i.code === 'slot_undeclared')).toEqual([
      { code: 'slot_undeclared', where: 'template:read_customer_charges', msg: 'slot ghost is used but not declared' },
    ]);
  });
});

describe('slotLits enum slots', () => {
  it('a non-string value is ill-typed even when a malformed value list contains it', () => {
    const s = raw<Template['slots'][number]>({ name: 'e', kind: 'enum', values: [5], mandatory: true });
    expect(slotLits(fresh(), s, 5 as unknown as string)).toBe('ill-typed');
  });
});
