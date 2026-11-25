import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, checkOntology, toIrOntology, type IntentOntology, type OntVerb } from '../src';

// The validator returns a refusal for a currency-less money parameter; it never throws (the empty-Allow witness search used to type it).
const raw = <T>(x: unknown): T => JSON.parse(JSON.stringify(x));
const fresh = (): IntentOntology => raw<IntentOntology>(ALL_ONTOLOGIES.payments);
const verb = (id: string, params: Record<string, unknown>): OntVerb => raw<OntVerb>({ id, effect: 'read', resource_type: 'charge', params });
const refusal = (id: string) => [{ code: 'param_ccy', where: `${id}.amount`, msg: 'money parameter lists no currency' }];

describe('a money parameter with no currency', () => {
  it('the base fixture is well formed', () => { expect(checkOntology(fresh())).toEqual([]); });
  it('absent currencies are refused, not thrown', () => {
    const o = fresh(); o.verbs.push(verb('m1', { amount: { kind: 'money' } }));
    expect(checkOntology(o)).toEqual(refusal('m1'));
  });
  it('an empty currency list is refused, not thrown', () => {
    const o = fresh(); o.verbs.push(verb('m0', { amount: { kind: 'money', ccys: [] } }));
    expect(checkOntology(o)).toEqual(refusal('m0'));
  });
  it('after a well-formed parameter of the same verb it is still refused, not thrown', () => {
    const o = fresh(); o.verbs.push(verb('m3', { ok: { kind: 'enum', values: ['a'] }, amount: { kind: 'money' } }));
    expect(checkOntology(o)).toEqual(refusal('m3'));
  });
  it('typing it directly throws the named error', () => {
    const o = fresh(); o.verbs.push(verb('m4', { amount: { kind: 'money' } }));
    expect(() => toIrOntology(o, { ccy: 'USD' })).toThrow(/^money parameter lists no currency$/);
  });
});
