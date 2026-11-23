import { describe, expect, it } from 'vitest';
import { ALL_ONTOLOGIES, checkOntology, type IntentOntology, type OntologyIssue, type OntVerb, type Template, type TemplateSlot } from '../src';

// Every case starts from the valid payments ontology and breaks exactly one thing.
const raw = <T>(x: unknown): T => JSON.parse(JSON.stringify(x));
const fresh = (): IntentOntology => raw<IntentOntology>(ALL_ONTOLOGIES.payments);
const iss = (code: string, where: string, msg: string): OntologyIssue => ({ code, where, msg });
const byCode = (o: IntentOntology, code: string): OntologyIssue[] => checkOntology(o).filter((i) => i.code === code);
const verb = (id: string, params: Record<string, unknown>, extra: Record<string, unknown> = {}): OntVerb => raw<OntVerb>({ id, effect: 'read', resource_type: 'charge', params, ...extra });
const tmpl = (o: IntentOntology, id: string): Template => {
  const t = o.templates.find((x) => x.id === id);
  if (!t) throw new Error(`no template ${id}`);
  return t;
};
const slot = (s: Record<string, unknown>): TemplateSlot => raw<TemplateSlot>(s);
const TID = 'read_customer_charges';
const W = `template:${TID}`;

describe('base fixture', () => {
  it('is well formed', () => { expect(checkOntology(fresh())).toEqual([]); });
});

describe('relations', () => {
  it('refuses a duplicate relation id', () => {
    const o = fresh();
    o.relations.push({ id: 'charges_of', from: 'customer', to: 'charge' });
    expect(checkOntology(o)).toEqual([iss('dup_relation', 'charges_of', 'duplicate relation')]);
  });
  it('refuses a relation whose from or to type is undeclared', () => {
    const o = fresh();
    o.relations.push({ id: 'r_from', from: 'ghost', to: 'charge' }, { id: 'r_to', from: 'customer', to: 'ghost' });
    expect(checkOntology(o)).toEqual([
      iss('relation_type', 'r_from', 'relation endpoint type is not declared'),
      iss('relation_type', 'r_to', 'relation endpoint type is not declared'),
    ]);
  });
});

describe('verbs', () => {
  it('refuses a duplicate verb id', () => {
    const o = fresh();
    o.verbs.push(raw<OntVerb>(o.verbs.find((v) => v.id === 'read_charge')));
    expect(checkOntology(o)).toEqual([iss('dup_verb', 'read_charge', 'duplicate verb')]);
  });
  it('refuses an unknown effect class', () => {
    const o = fresh();
    o.verbs.push(verb('weird', {}, { effect: 'bogus' }));
    expect(checkOntology(o)).toEqual([iss('no_effect_class', 'weird', 'verb has no valid effect class')]);
  });
  it('refuses an undeclared resource type', () => {
    const o = fresh();
    o.verbs.push(verb('orphan', {}, { resource_type: 'ghost' }));
    expect(checkOntology(o)).toEqual([iss('verb_resource_type', 'orphan', 'resource type is not declared')]);
  });
  it('refuses a money parameter without currencies', () => {
    const o = fresh();
    o.verbs.push(verb('m1', { amount: { kind: 'money' } }));
    expect(checkOntology(o)).toEqual([iss('param_ccy', 'm1.amount', 'money parameter lists no currency')]);
  });
  it('refuses a money parameter with an empty currency list, and the refusal is returned, not thrown', () => {
    const o = fresh();
    o.verbs.push(verb('m0', { amount: { kind: 'money', ccys: [] } }));
    expect(checkOntology(o)).toEqual([iss('param_ccy', 'm0.amount', 'money parameter lists no currency')]);
  });
  it('a currency-less money parameter after a well-formed one is still refused, not thrown', () => {
    const o = fresh();
    o.verbs.push(verb('m3', { ok: { kind: 'enum', values: ['a'] }, amount: { kind: 'money' } }));
    expect(checkOntology(o)).toEqual([iss('param_ccy', 'm3.amount', 'money parameter lists no currency')]);
  });
  it('refuses a money parameter currency that is not a declared money unit', () => {
    const o = fresh();
    o.verbs.push(verb('m2', { amount: { kind: 'money', ccys: ['USD', 'ZZZ'] } }));
    expect(checkOntology(o)).toEqual([iss('unit_unknown', 'm2.amount', 'currency ZZZ is not a declared money unit')]);
  });
  it('refuses an enum parameter without values (absent or empty)', () => {
    const o = fresh();
    o.verbs.push(verb('e1', { mode: { kind: 'enum' }, tier: { kind: 'enum', values: [] }, ok: { kind: 'enum', values: ['a'] } }));
    expect(checkOntology(o)).toEqual([
      iss('param_enum', 'e1.mode', 'enum parameter has no values'),
      iss('param_enum', 'e1.tier', 'enum parameter has no values'),
    ]);
  });
  it('refuses an id parameter whose type is absent or undeclared', () => {
    const o = fresh();
    o.verbs.push(verb('i1', { ref: { kind: 'id' }, ref2: { kind: 'id', of: 'ghost' }, ref3: { kind: 'id', of: 'customer' } }));
    expect(checkOntology(o)).toEqual([
      iss('param_type', 'i1.ref', 'id parameter type is not declared'),
      iss('param_type', 'i1.ref2', 'id parameter type is not declared'),
    ]);
  });
  it('refuses a parameter kind with no declared unit of that kind, and accepts count and text', () => {
    const o = fresh();
    o.verbs.push(verb('d1', { n: { kind: 'count' }, note: { kind: 'text' }, wait: { kind: 'duration' } }));
    expect(checkOntology(o)).toEqual([iss('unit_unknown', 'd1.wait', 'no declared unit of kind duration')]);
  });
});

describe('aliases', () => {
  it('refuses a key that is not in normalized form', () => {
    const o = fresh();
    o.aliases['Refund'] = 'refund';
    expect(checkOntology(o)).toEqual([iss('alias_key', 'Refund', 'alias key is not in normalized form')]);
  });
  it('accepts a normalized key with a non-ASCII character', () => {
    const o = fresh();
    o.aliases['café'] = 'refund';
    expect(checkOntology(o)).toEqual([]);
  });
  it('refuses a key with an invisible character', () => {
    const o = fresh();
    const k = 'x​';
    o.aliases[k] = 'refund';
    expect(checkOntology(o)).toEqual([
      iss('alias_key', k, 'alias key is not in normalized form'),
      iss('alias_key', k, 'alias key contains invisible characters'),
    ]);
  });
  it('refuses two keys that collide after normalization', () => {
    const o = fresh();
    o.aliases['Pay'] = 'refund';
    o.aliases['pay'] = 'refund';
    expect(checkOntology(o)).toEqual([
      iss('alias_key', 'Pay', 'alias key is not in normalized form'),
      iss('alias_collision', 'pay', 'collides with Pay after normalization'),
    ]);
  });
  it('refuses a target that is not a canonical verb', () => {
    const o = fresh();
    o.aliases['zz'] = 'nope';
    expect(checkOntology(o)).toEqual([iss('alias_target', 'zz', 'alias target is not a canonical verb')]);
  });
  it('refuses a chain', () => {
    const o = fresh();
    o.aliases['a'] = 'b';
    o.aliases['b'] = 'refund';
    expect(checkOntology(o)).toEqual([
      iss('alias_target', 'a', 'alias target is not a canonical verb'),
      iss('alias_chain', 'a', 'alias target is itself an alias (chain or cycle)'),
    ]);
  });
  it('refuses an alias that shadows a canonical verb', () => {
    const o = fresh();
    o.aliases['refund'] = 'transfer';
    expect(byCode(o, 'alias_shadow')).toEqual([iss('alias_shadow', 'refund', 'alias shadows a canonical verb')]);
  });
  it('a verb aliased to itself is a chain, not a shadow', () => {
    const o = fresh();
    o.aliases['refund'] = 'refund';
    expect(byCode(o, 'alias_shadow')).toEqual([]);
    expect(checkOntology(o)).toContainEqual(iss('alias_chain', 'refund', 'alias target is itself an alias (chain or cycle)'));
  });
});

describe('templates', () => {
  it('refuses a duplicate template id', () => {
    const o = fresh();
    o.templates.push(raw<Template>(tmpl(o, 'refund_duplicate')));
    expect(checkOntology(o)).toEqual([iss('dup_template', 'template:refund_duplicate', 'duplicate template id')]);
  });
  it('refuses a duplicate slot', () => {
    const o = fresh();
    const t = tmpl(o, TID);
    t.slots.push(raw<TemplateSlot>(t.slots[0]));
    expect(byCode(o, 'dup_slot')).toEqual([iss('dup_slot', W, 'duplicate slot')]);
  });
  it('refuses a slot that is used but not declared', () => {
    const o = fresh();
    tmpl(o, TID).slots = [];
    expect(byCode(o, 'slot_undeclared')).toEqual([iss('slot_undeclared', W, 'slot customer is used but not declared')]);
  });
  it('refuses an id or id_list slot whose type is absent or undeclared', () => {
    const o = fresh();
    tmpl(o, TID).slots.push(
      slot({ name: 'a', kind: 'id', of: 'ghost', mandatory: true }),
      slot({ name: 'b', kind: 'id_list', of: 'ghost', mandatory: true }),
      slot({ name: 'c', kind: 'id', mandatory: true }),
      slot({ name: 'd', kind: 'id_list', mandatory: true }),
    );
    const m = 'id slot type is not declared';
    expect(byCode(o, 'slot_type')).toEqual([iss('slot_type', `${W}.a`, m), iss('slot_type', `${W}.b`, m), iss('slot_type', `${W}.c`, m), iss('slot_type', `${W}.d`, m)]);
  });
  it('refuses a money slot whose currency is absent or not a declared unit', () => {
    const o = fresh();
    o.units['Stryker was here!'] = { kind: 'money', exponent: 2 };
    tmpl(o, TID).slots.push(slot({ name: 'm1', kind: 'money', ccy: 'ZZZ', mandatory: true }), slot({ name: 'm2', kind: 'money', mandatory: true }), slot({ name: 'm3', kind: 'money', ccy: 'USD', mandatory: true }));
    const m = 'money slot currency is not a declared unit';
    expect(byCode(o, 'slot_ccy')).toEqual([iss('slot_ccy', `${W}.m1`, m), iss('slot_ccy', `${W}.m2`, m)]);
  });
  it('refuses an enum or enum_list slot without values', () => {
    const o = fresh();
    tmpl(o, TID).slots.push(
      slot({ name: 'e1', kind: 'enum', mandatory: true }),
      slot({ name: 'e2', kind: 'enum_list', mandatory: true, values: [] }),
      slot({ name: 'e3', kind: 'enum', mandatory: true, values: ['x'] }),
    );
    const m = 'enum slot has no values';
    expect(byCode(o, 'slot_enum')).toEqual([iss('slot_enum', `${W}.e1`, m), iss('slot_enum', `${W}.e2`, m)]);
  });
  it('refuses an optional slot without a default', () => {
    const o = fresh();
    tmpl(o, TID).slots.push(slot({ name: 'o1', kind: 'count', mandatory: false }), slot({ name: 'o2', kind: 'count', mandatory: false, default: { n: 1 } }), slot({ name: 'o3', kind: 'count', mandatory: true }));
    expect(byCode(o, 'slot_default')).toEqual([iss('slot_default', `${W}.o1`, 'optional slot needs a default (an unfilled slot must be a hole or a default)')]);
  });
});
