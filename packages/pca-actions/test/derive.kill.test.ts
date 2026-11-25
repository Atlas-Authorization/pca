// Kill tests for the derivation module: every assertion here is an exact outcome that a single mutation of the derivation changes.
// Each derivation is run inside the test body (never at collection time) so the per-test coverage sees it.
import { describe, expect, it, vi } from 'vitest';
import {
  ActionKitError, BUILTIN_DEFS, CORE_REGISTRY, action, cardOf, effectClass, extendRegistry, flattenParams, mcpAnnotationsOf, operationOf, p, paramByRole, predicatesOf,
  registryOfSchema, riskOf, schemaFloorError, schemaVerbFloorError, toOntology, toSchemaDoc, toSchemaVerb, traitsDigest,
  type ActionDef, type ReviewRef, type TraitDef,
} from '../src';
import type { ActionVerbDecl, SchemaConfirmation } from '@atlasauth/pca/ext/intent';
import { factsDigest, signReview } from '../src/confirmation';
import { TEST_PINS, TEST_REVIEWER, TEST_TS, confirmed, eff as effOf, testReview } from './reviewed';

const T = testReview();
const META = { site: 's', aud: 'a', version: '1' };
const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;
const invoice: ActionDef = {
  v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
  resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' },
  params: {
    invoice: { type: 'string', role: 'id.acme.invoice', max_len: 64 },
    to: { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 },
    note: { type: 'string', max_len: 500 },
  },
  bindings: { mcp: { tool: 'send_invoice' }, openapi: { operationId: 'sendInvoice' } },
  review: { state: 'authored' },
};
const R_SET: ActionDef['resource'] = { type: 'a.t', id: '*', scope: 'set' };
const od = (verb: string, resource: ActionDef['resource'], params: ActionDef['params'], more: Partial<ActionDef> = {}): ActionDef =>
  ({ v: 1, kind: 'pca-action-def', verb, title: 'Do a thing', effects: ['read'], resource, params, review: { state: 'authored' }, ...more });

const thrown = (f: () => unknown): ActionKitError => {
  try { f(); } catch (e) { if (e instanceof ActionKitError) return e; throw e; }
  throw new Error('expected an ActionKitError');
};

// The comparators handed to Array.prototype.sort while `run` executes, in call order (a comparator is checked by calling it, so the
// result does not depend on how the engine uses its value).
type Cmp = (a: unknown, b: unknown) => number;
const sortCmps = (run: () => void): Cmp[] => {
  const orig = Array.prototype.sort;
  const seen: Cmp[] = [];
  const spy = vi.spyOn(Array.prototype, 'sort').mockImplementation(function (this: unknown[], fn?: (a: unknown, b: unknown) => number) {
    if (fn) seen.push(fn);
    return orig.call(this, fn);
  });
  try {
    run();
  } finally {
    spy.mockRestore();
  }
  return seen;
};
const verbCmp = (cmp: Cmp): void => {
  const v = (verb: string) => ({ verb });
  expect(cmp(v('a.b.c'), v('a.b.d'))).toBe(-1);
  expect(cmp(v('a.b.d'), v('a.b.c'))).toBe(1);
  expect(cmp(v('a.b.c'), v('a.b.c'))).toBe(0);
};

describe('flattenParams', () => {
  it('keeps null, undefined, strings and arrays as leaves', () => {
    expect(flattenParams({ a: null })).toEqual({ a: null });
    const out = flattenParams({ a: undefined, b: 'ab', c: [1, [2]] });
    expect(Object.keys(out)).toEqual(['a', 'b', 'c']);
    expect(out.a).toBeUndefined();
    expect(out.b).toBe('ab');
    expect(out.c).toEqual([1, [2]]);
  });
  it('an array is a leaf even when its prototype is the plain object prototype', () => {
    const odd: unknown[] = [1, 2];
    Object.setPrototypeOf(odd, Object.prototype);
    const out = flattenParams({ a: odd });
    expect(Object.keys(out)).toEqual(['a']);
    expect(out.a).toBe(odd);
  });
  it('only plain objects and prototype-less objects are walked', () => {
    class Boxed { x = 1; }
    const boxed = new Boxed();
    const bare: Record<string, unknown> = Object.create(null);
    bare.x = 1;
    const out = flattenParams({ a: boxed, b: bare });
    expect(Object.keys(out)).toEqual(['a', 'b.x']);
    expect(out.a).toBe(boxed);
    expect(out['b.x']).toBe(1);
  });
  it('an empty object stays a leaf', () => {
    const out = flattenParams({ a: {} });
    expect(Object.keys(out)).toEqual(['a']);
    expect(out.a).toEqual({});
  });
  it('flattens down to the depth limit (3 segments) and no further', () => {
    expect(flattenParams({ a: { b: { c: { d: 1 } } } })).toEqual({ 'a.b.c': { d: 1 } });
    expect(flattenParams({ a: { b: { c: 1 } } })).toEqual({ 'a.b.c': 1 });
  });
  it('an empty top-level key adds no separator', () => {
    expect(flattenParams({ '': { x: 1 } })).toEqual({ x: 1 });
  });
});

describe('paramByRole errors carry their code', () => {
  it('no_param and ambiguous_param, with the verb and the role in the message', () => {
    const none = thrown(() => paramByRole({ verb: 'x.y', params: {} }, 'money.amount'));
    expect(none.code).toBe('no_param');
    expect(none.message).toBe("'x.y' has no parameter with role money.amount");
    const two = thrown(() => paramByRole({ verb: 'x.y', params: { a: { type: 'integer', role: 'money.amount' }, b: { type: 'integer', role: 'money.amount' } } }, 'money.amount'));
    expect(two.code).toBe('ambiguous_param');
    expect(two.message).toBe("'x.y' has several parameters with role money.amount");
  });
});

describe('effectClass', () => {
  it('a reversible write that sends nothing is reversible', () => {
    const customer = od('acme.customer.update', R_SET, { name: { type: 'string' } }, { effects: ['update'], reversibility: 'reversible' });
    expect(effectClass(customer)).toBe('reversible');
  });
  it('one sending effect among others makes it an external send; a send that is reversible is still one', () => {
    expect(effectClass({ ...invoice, effects: ['send', 'update'], reversibility: 'rate_limited' })).toBe('external_send');
    expect(effectClass({ ...invoice, reversibility: 'reversible' })).toBe('external_send');
    expect(effectClass(od('acme.thing.export', R_SET, {}, { effects: ['update', 'export'], reversibility: 'reversible' }))).toBe('external_send');
  });
});

describe('toSchemaVerb', () => {
  const byMode = (reversibility: ActionDef['reversibility']): ActionDef =>
    od('acme.draft.make', R_SET, { mode: { type: 'string', values: ['draft', 'final'] } }, { effects: ['create'], reversibility });
  it('non-money units are declared by their kind, in the param and in the units table', () => {
    const d = od('acme.thing.measure', R_SET, {
      size: { type: 'integer', unit: { kind: 'bytes' } },
      n: { type: 'integer', unit: { kind: 'count' } },
      amt: { type: 'integer', role: 'money.amount', unit: { kind: 'money', ccy: { from: 'cur' }, exp: 2 } },
      cur: { type: 'string', role: 'money.currency' },
    });
    const o = toSchemaVerb(d, CORE_REGISTRY);
    expect(o.verb.params['action.params.size']!.unit).toBe('bytes');
    expect(o.verb.params['action.params.n']!.unit).toBe('count');
    expect('unit' in o.verb.params['action.params.amt']!).toBe(false);
    expect(o.units).toEqual({ bytes: { kind: 'bytes' }, count: { kind: 'count' } });
  });
  it('a value-dependent reversibility becomes reversibility_by, with the default only when declared', () => {
    const withDefault = toSchemaVerb(byMode({ by: 'mode', map: { draft: 'reversible', final: 'rate_limited' }, default: 'irreversible' }), CORE_REGISTRY).verb;
    expect(withDefault.reversibility_by).toEqual({ param: 'action.params.mode', map: { draft: 'reversible', final: 'rate_limited' }, default: 'irreversible' });
    expect('reversibility' in withDefault).toBe(false);
    const noDefault = toSchemaVerb(byMode({ by: 'mode', map: { draft: 'reversible', final: 'rate_limited' } }), CORE_REGISTRY).verb;
    expect(Object.keys(noDefault.reversibility_by!).sort()).toEqual(['map', 'param']);
    expect(noDefault.reversibility_by!.map).toEqual({ draft: 'reversible', final: 'rate_limited' });
    const fixed = toSchemaVerb(byMode('rate_limited'), CORE_REGISTRY).verb;
    expect(fixed.reversibility).toBe('rate_limited');
    expect('reversibility_by' in fixed).toBe(false);
  });
  it('bindings are carried as the tool and operation names only, and omitted when absent', () => {
    const d: ActionDef = { ...invoice, bindings: { mcp: { tool: 'send_invoice' }, openapi: { operationId: 'sendInvoice', method: 'post', path: '/invoices/send' } } };
    const v = toSchemaVerb(d, CORE_REGISTRY).verb;
    expect(v.mcp).toEqual({ tool: 'send_invoice' });
    expect(v.openapi).toEqual({ operationId: 'sendInvoice' });
    const bare = toSchemaVerb({ ...invoice, bindings: undefined }, CORE_REGISTRY).verb;
    expect('mcp' in bare).toBe(false);
    expect('openapi' in bare).toBe(false);
  });
  it('the confirmation travels only when the def is confirmed AND carries a signed attestation', () => {
    const signed: ReviewRef = { def_digest: 'd', traits_digest: 't', facts_digest: 'f', final_traits: [], dismissed: [], reviewer_kid: 'k', ts: 1, sig: 'sig' };
    const unsigned: ReviewRef = { def_digest: 'd', traits_digest: 't', facts_digest: 'f', final_traits: [], dismissed: [], reviewer_kid: 'k', ts: 1 };
    const withReview = (attestation?: ReviewRef): ActionDef => ({ ...refund, review: { state: 'confirmed', ...(attestation ? { attestation } : {}) } });
    const yes = { attestationVerified: () => true };
    expect(toSchemaVerb(withReview(signed), CORE_REGISTRY, yes).verb.confirmation).toEqual(signed);
    expect('confirmation' in toSchemaVerb(withReview(unsigned), CORE_REGISTRY, yes).verb).toBe(false);
    expect('confirmation' in toSchemaVerb(withReview(), CORE_REGISTRY, yes).verb).toBe(false);
    expect('confirmation' in toSchemaVerb(withReview(signed), CORE_REGISTRY).verb).toBe(false);
  });
});

describe('toSchemaDoc', () => {
  const moneyDef = (verb: string, ccy: string, exp: number): ActionDef => od(verb, R_SET, { amt: { type: 'integer', role: 'money.amount', unit: { kind: 'money', ccy, exp } } });
  it('sorts the verbs by name whatever the input order', () => {
    const doc = toSchemaDoc([refund, invoice], CORE_REGISTRY, META);
    expect(doc.verbs.map((v) => v.verb)).toEqual(['acme.invoice.send', 'stripe.refund']);
  });
  it('the verb comparator orders by name, reverse, and equal', () => {
    const cmps = sortCmps(() => { toSchemaDoc([], CORE_REGISTRY, META); });
    expect(cmps.length).toBeGreaterThanOrEqual(1);
    verbCmp(cmps[0]!);
  });
  it('refuses a verb that appears twice, with the code and the verb', () => {
    const e = thrown(() => toSchemaDoc([invoice, invoice], CORE_REGISTRY, META));
    expect(e.code).toBe('duplicate_verb');
    expect(e.message).toBe("verb 'acme.invoice.send' appears twice");
  });
  it('refuses a unit redefined with another currency spelling or another exponent, and merges an identical one', () => {
    const c1 = thrown(() => toSchemaDoc([moneyDef('a.m.one', 'USD', 2), moneyDef('a.m.two', 'usd', 2)], CORE_REGISTRY, META));
    expect(c1.code).toBe('unit_conflict');
    expect(c1.message).toBe("unit 'money.usd' is declared with two different definitions");
    const c2 = thrown(() => toSchemaDoc([moneyDef('a.m.one', 'USD', 2), moneyDef('a.m.two', 'USD', 3)], CORE_REGISTRY, META));
    expect(c2.code).toBe('unit_conflict');
    const ok = toSchemaDoc([moneyDef('a.m.one', 'USD', 2), moneyDef('a.m.two', 'USD', 2)], CORE_REGISTRY, META);
    expect(ok.units).toEqual({ 'money.usd': { kind: 'money', currency: 'USD', exponent: 2 } });
  });
  it('a document whose verbs need no unit has no units member', () => {
    const doc = toSchemaDoc([od('a.b.c', R_SET, {})], CORE_REGISTRY, META);
    expect('units' in doc).toBe(false);
  });
  it('custom trait definitions travel sorted by id, whatever their order in the registry', () => {
    const mm = CORE_REGISTRY.traits.get('pca.money_moving')!;
    const custom = (id: string): TraitDef => ({ id, implies: ['pca.money_moving'], floor: { ...mm.floor, esc: 3 }, card_phrase: `does ${id}` });
    const reg = extendRegistry(CORE_REGISTRY, [custom('acme.zeta'), custom('acme.alpha'), custom('acme.mid')]);
    const doc = toSchemaDoc([], reg, META);
    expect((doc.trait_defs ?? []).map((t) => (t as TraitDef).id)).toEqual(['acme.alpha', 'acme.mid', 'acme.zeta']);
  });
});

describe('schemaVerbFloorError', () => {
  const verb = (d: ActionDef) => JSON.parse(JSON.stringify(toSchemaVerb(confirmed(d, CORE_REGISTRY), CORE_REGISTRY, T).verb)) as ReturnType<typeof toSchemaVerb>['verb'];
  it('a verb missing effects, traits or floors is not a v2 verb', () => {
    const noEffects = verb(refund);
    Reflect.deleteProperty(noEffects, 'effects');
    expect(schemaVerbFloorError(noEffects, CORE_REGISTRY, TEST_PINS)).toBe('schema_floor_forged: not a v2 verb');
    const noTraits = verb(refund);
    Reflect.deleteProperty(noTraits, 'traits');
    expect(schemaVerbFloorError(noTraits, CORE_REGISTRY, TEST_PINS)).toBe('schema_floor_forged: not a v2 verb');
    const noFloors = verb(refund);
    Reflect.deleteProperty(noFloors, 'floors');
    expect(schemaVerbFloorError(noFloors, CORE_REGISTRY, TEST_PINS)).toBe('schema_floor_forged: not a v2 verb');
  });
  it('a trait implied only by a parameter (its tag) is required', () => {
    const v = verb(invoice);
    v.traits = (v.traits ?? []).filter((t) => t !== 'pca.pii_access');
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toBe('schema_traits_forged: missing implied trait pca.pii_access');
  });
  it('the reversibility parameter is looked up by its bare name, so a fully mapped enum is only as bad as its worst value', () => {
    const d = action('acme.draft.create', {
      title: 'Create a draft', description: 'Saves a draft.', effects: ['create'], resource: 'acme.draft:dr_*',
      params: { box: p.text(40), body: p.message(500), mode: p.enum(['draft', 'final']) },
      reversibility: { by: 'mode', map: { draft: 'reversible', final: 'rate_limited' } }, since: '0.1.0',
    });
    expect(schemaVerbFloorError(verb(d), CORE_REGISTRY, TEST_PINS)).toBeNull();
  });
  it('floors.rev below the declared reversibility is refused with its own reason', () => {
    const d = action('acme.note.update', {
      title: 'Update a note', description: 'Edits a note.', effects: ['update'], resource: 'acme.note:nt_*',
      params: { note: p.id('acme.note'), body: p.text(500) }, reversibility: 'rate_limited', since: '0.1.0',
    });
    const v = verb(d);
    expect(v.floors!.rev).toBe('rate_limited');
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toBeNull();
    v.floors!.rev = 'reversible';
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toBe('schema_floor_forged: floors.rev is below the declared reversibility');
  });
});

describe('registryOfSchema and schemaFloorError', () => {
  it('an empty trait_defs list is the core registry itself', () => {
    expect(registryOfSchema({ trait_defs: [] })).toBe(CORE_REGISTRY);
    expect(registryOfSchema({})).toBe(CORE_REGISTRY);
  });
  it('a registry that cannot load is reported under bad_registry even when the failure has no code', () => {
    expect(schemaFloorError({ trait_defs: [null], verbs: [] })).toMatch(/^bad_registry: /);
  });
});

describe('operationOf', () => {
  const multi = od('a.m.touch', { type: 'a.thing', id: { prefix: 't_', class: 'alnum', len: [4, 12] }, scope: 'one' }, {
    zed: { type: 'string', role: 'id.a.thing' },
    alpha: { type: 'string', role: 'id.a.thing' },
    other: { type: 'string' },
  });
  it('projects declared params in name order, the first id parameter in name order names the resource, and an absent param is omitted', () => {
    const r = operationOf(multi, { params: { zed: 't_zzzz1111', alpha: 't_aaaa1111' } });
    if (!r.ok) throw new Error(r.reason);
    expect(r.op.resource).toBe('a.thing:t_aaaa1111');
    expect(Object.keys(r.op.params)).toEqual(['alpha', 'zed']);
  });
  it('a parameter literally named "undefined" is never taken for the id parameter', () => {
    const d = od('a.m.touch', { type: 'a.b', id: '*', scope: 'one' }, { undefined: { type: 'string' } });
    expect(operationOf(d, { params: { undefined: 'x' } })).toEqual({ ok: false, reason: 'a.m.touch needs a parameter with role id.a.b to name its resource' });
  });
});

describe('riskOf', () => {
  const eff = effOf(refund);
  const loose = (json: string): { kappa?: number; taint?: number } => JSON.parse(json);
  const blast = (params: Record<string, unknown>, opts: { kappa?: number; taint?: number }) => riskOf(refund, eff, params, opts).blastRadius;
  it('the money parameter is the first one by name', () => {
    const two: ActionDef = { ...refund, params: { zeta: { type: 'integer', role: 'money.amount' }, alpha: { type: 'integer', role: 'money.amount' } } };
    expect(riskOf(two, eff, { alpha: 50, zeta: 90_000 }, { kappa: 100 }).blastRadius).toBe(0.5);
  });
  it('zero is a valid amount, and the blast is amount / kappa', () => {
    expect(blast({ amount: 0 }, { kappa: 100 })).toBe(0);
    expect(blast({ amount: 50 }, { kappa: 100 })).toBe(0.5);
  });
  it('an amount that is not a finite number is the worst case', () => {
    expect(blast({ amount: '5000' }, { kappa: 100_000 })).toBe(1);
    expect(blast({ amount: Infinity }, { kappa: Infinity })).toBe(1);
    expect(blast({ amount: NaN }, { kappa: 100 })).toBe(1);
  });
  it('a kappa that is not a positive number is the worst case', () => {
    expect(blast({ amount: 5000 }, loose('{"kappa":"100000"}'))).toBe(1);
    expect(blast({ amount: 0 }, { kappa: 0 })).toBe(1);
    expect(blast({ amount: 5000 }, { kappa: -100 })).toBe(1);
    expect(blast({ amount: 5000 }, { kappa: 0 })).toBe(1);
  });
  it('the taint is carried only when it is a finite number, clamped to 0..1', () => {
    const base = { reversibility: 0, blastRadius: 1, confidence: 1 };
    expect(riskOf(refund, eff, {}, { taint: NaN })).toEqual(base);
    expect(riskOf(refund, eff, {}, { taint: Infinity })).toEqual(base);
    expect(riskOf(refund, eff, {}, loose('{"taint":"0.5"}'))).toEqual(base);
    expect(riskOf(refund, eff, {}, { taint: 0.5 })).toEqual({ ...base, taint: 0.5 });
  });
});

describe('predicatesOf and the resource matcher', () => {
  it('a limit of zero is allowed; a negative or fractional one is refused with bad_limit', () => {
    expect(predicatesOf(refund, { max_amount: 0 }).where).toEqual([
      { field: 'action.params.amount', op: 'lte', value: 0 },
      { field: 'action.params.amount', op: 'gte', value: 0 },
    ]);
    for (const bad of [-5, 1.5, NaN]) {
      const e = thrown(() => predicatesOf(refund, { max_amount: bad }));
      expect(e.code).toBe('bad_limit');
      expect(e.message).toBe('max_amount must be a non-negative safe integer');
    }
  });
  it('the matcher of a wildcard, an exact id and a prefix', () => {
    expect(predicatesOf(od('a.b.c', { type: 'a.b', id: '*', scope: 'set' }, {})).resource).toBe('a.b:*');
    expect(predicatesOf(od('a.b.c', { type: 'a.b', id: { exact: 'only' }, scope: 'one' }, {})).resource).toBe('a.b:only');
    expect(predicatesOf(od('a.b.c', { type: 'a.b', id: { prefix: 'p_', class: 'alnum', len: [4, 8] }, scope: 'one' }, {})).resource).toBe('a.b:p_*');
  });
});

describe('toOntology', () => {
  const ont = (d: ActionDef) => toOntology([d], CORE_REGISTRY);
  it('unit kinds of a parameter, and the units table', () => {
    const d = od('a.u.units', R_SET, {
      ttl: { type: 'integer', unit: { kind: 'duration' } },
      size: { type: 'integer', unit: { kind: 'bytes' } },
      pct: { type: 'integer', unit: { kind: 'ratio' } },
      n: { type: 'integer', unit: { kind: 'count' } },
    });
    const o = ont(d);
    expect(o.verbs[0]!.params).toEqual({ n: { kind: 'count' }, pct: { kind: 'ratio' }, size: { kind: 'bytes' }, ttl: { kind: 'duration' } });
    expect(o.units).toEqual({ duration: { kind: 'duration' }, bytes: { kind: 'bytes' }, ratio: { kind: 'ratio' }, count: { kind: 'count' } });
  });
  it('a money parameter whose currency is another parameter lists that parameter\'s values, sorted, and adds no unit', () => {
    const d = od('a.u.pay', R_SET, {
      amt: { type: 'integer', role: 'money.amount', unit: { kind: 'money', ccy: { from: 'cur' }, exp: 2 } },
      cur: { type: 'string', role: 'money.currency', format: 'iso_currency', values: ['USD', 'EUR'] },
      amt2: { type: 'integer', role: 'money.amount', unit: { kind: 'money', ccy: { from: 'cur2' }, exp: 2 } },
      cur2: { type: 'string', role: 'money.currency', format: 'iso_currency' },
    });
    const o = ont(d);
    expect(o.verbs[0]!.params.amt).toEqual({ kind: 'money', ccys: ['EUR', 'USD'] });
    expect(o.verbs[0]!.params.amt2).toEqual({ kind: 'money', ccys: [] });
    expect(o.units).toEqual({});
  });
  it('the kind of a parameter without a unit, from its role, format and type', () => {
    const d = od('a.u.kinds', R_SET, {
      dur: { type: 'duration' },
      dt: { type: 'datetime' },
      day: { type: 'date' },
      int: { type: 'integer' },
      flag: { type: 'boolean' },
      setv: { type: 'set', values: ['b', 'a'] },
      setNone: { type: 'set' },
      sval: { type: 'string', values: ['z', 'y'] },
      txt: { type: 'string' },
      arr: { type: 'array', items: 'string' },
      ref: { type: 'object_ref' },
      mail: { type: 'string', role: 'contact.email' },
      fmt: { type: 'string', format: 'email' },
      idRole: { type: 'string', role: 'id.acme.thing' },
      idFmt: { type: 'string', format: 'id:acme.customer' },
    });
    expect(ont(d).verbs[0]!.params).toEqual({
      arr: { kind: 'text' },
      day: { kind: 'instant' },
      dt: { kind: 'instant' },
      dur: { kind: 'duration' },
      flag: { kind: 'enum', values: ['false', 'true'] },
      fmt: { kind: 'text' },
      idFmt: { kind: 'id', of: 'acme.customer' },
      idRole: { kind: 'id', of: 'acme.thing' },
      int: { kind: 'count' },
      mail: { kind: 'text' },
      ref: { kind: 'text' },
      setNone: { kind: 'enum', values: [] },
      setv: { kind: 'enum', values: ['a', 'b'] },
      sval: { kind: 'enum', values: ['y', 'z'] },
      txt: { kind: 'text' },
    });
  });
  it('parameters are listed in name order', () => {
    const d = od('a.u.order', R_SET, { zz: { type: 'string' }, aa: { type: 'string' }, mm: { type: 'string' } });
    expect(Object.keys(ont(d).verbs[0]!.params)).toEqual(['aa', 'mm', 'zz']);
  });
  it('types and verbs come out in verb-name order, the first def of a type fixes its prefix, and a wildcard or exact id has an empty prefix', () => {
    const pre = (prefix: string): ActionDef['resource'] => ({ type: 'a.pre', id: { prefix, class: 'alnum', len: [4, 8] }, scope: 'one' });
    const defs = [
      od('a.c.second', pre('q_'), {}),
      od('a.z.star', { type: 'a.star', id: '*', scope: 'set' }, {}),
      od('a.y.exact', { type: 'a.exact', id: { exact: 'only' }, scope: 'one' }, {}),
      od('a.b.first', pre('p_'), {}),
    ];
    const o = toOntology(defs, CORE_REGISTRY);
    expect(o.verbs.map((v) => v.id)).toEqual(['a.b.first', 'a.c.second', 'a.y.exact', 'a.z.star']);
    expect(o.types).toEqual([{ id: 'a.pre', id_prefix: 'p_' }, { id: 'a.exact', id_prefix: '' }, { id: 'a.star', id_prefix: '' }]);
  });
  it('the verb comparator orders by name, reverse, and equal', () => {
    const cmps = sortCmps(() => { toOntology([], CORE_REGISTRY); });
    expect(cmps).toHaveLength(1);
    verbCmp(cmps[0]!);
  });
  it('an alias collision is refused with its code', () => {
    const e = thrown(() => toOntology([od('a.b.one', R_SET, {}, { aliases: ['dup'] }), od('a.b.two', R_SET, {}, { aliases: ['dup'] })], CORE_REGISTRY));
    expect(e.code).toBe('alias_collision');
    expect(e.message).toBe("alias 'dup' names two verbs");
  });
});

describe('cardOf and mcpAnnotationsOf', () => {
  it('the title becomes a sentence only when it does not already end like one', () => {
    const text = (title: string) => cardOf({ ...refund, title }, effOf(refund), CORE_REGISTRY).text;
    expect(text('Refund v1.2 charges')).toMatch(/^Refund v1\.2 charges\. This action /);
    expect(text('Refund charges!')).toMatch(/^Refund charges! This action /);
    expect(text('Refund charges?')).toMatch(/^Refund charges\? This action /);
  });
  it('the trait order comparator puts the riskier first, then the lower id', () => {
    const e = effOf(refund);
    const cmps = sortCmps(() => { cardOf(refund, e, CORE_REGISTRY); });
    const cmp = cmps[cmps.length - 1]!;
    const t = (risk: number, id: string) => ({ floor: { risk }, id });
    expect(cmp(t(3, 'z'), t(1, 'a'))).toBe(-2);
    expect(cmp(t(1, 'a'), t(3, 'z'))).toBe(2);
    expect(cmp(t(2, 'a'), t(2, 'b'))).toBe(-1);
    expect(cmp(t(2, 'b'), t(2, 'a'))).toBe(1);
    expect(cmp(t(2, 'a'), t(2, 'a'))).toBe(0);
  });
  it('a def that sends to people is open-world even without a network trait', () => {
    expect(mcpAnnotationsOf(invoice, effOf(invoice)).openWorldHint).toBe(true);
  });
});

describe('schemaVerbFloorError: a verb with no declared reversibility', () => {
  // the verb as a reviewer would sign it with the reversibility member absent: the default class comes from its kind
  const bare = (d: ActionDef): ActionVerbDecl => {
    const v = JSON.parse(JSON.stringify(toSchemaVerb(confirmed(d, CORE_REGISTRY), CORE_REGISTRY, T).verb)) as ActionVerbDecl;
    Reflect.deleteProperty(v, 'reversibility');
    Reflect.deleteProperty(v, 'confirmation');
    v.confirmation = signReview({
      def_digest: v.def!, traits_digest: traitsDigest(CORE_REGISTRY), facts_digest: factsDigest(v), final_traits: [], dismissed: [],
      reviewer_kid: TEST_REVIEWER.kid, ts: TEST_TS,
    }, TEST_REVIEWER.secret) as SchemaConfirmation;
    return v;
  };
  const readDef = action('acme.note.read', { title: 'Read a note', description: 'Reads a note.', effects: ['read'], resource: 'acme.note:nt_*', params: { note: p.id('acme.note') }, since: '0.1.0' });
  const writeDef = action('acme.note.update', { title: 'Update a note', description: 'Edits a note.', effects: ['update'], resource: 'acme.note:nt_*', params: { note: p.id('acme.note'), body: p.text(500) }, since: '0.1.0' });
  it('a read verb defaults to reversible: it needs no irreversible trait and floors.rev reversible passes', () => {
    const v = bare(readDef);
    expect(v.kind).toBe('read');
    expect(v.floors!.rev).toBe('reversible');
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toBeNull();
  });
  it('a write verb defaults to irreversible: it must carry the irreversible trait, and floors below it are refused', () => {
    const v = bare(writeDef);
    expect(v.kind).toBe('write');
    expect(v.traits).toContain('pca.irreversible');
    expect(v.floors!.rev).toBe('irreversible');
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toBeNull();
    for (const rev of ['reversible', 'rate_limited'] as const) {
      const low = bare(writeDef);
      low.floors!.rev = rev;
      expect(schemaVerbFloorError(low, CORE_REGISTRY, TEST_PINS)).toBe('schema_floor_forged: floors are below the floor of the carried traits');
    }
    const dropped = bare(writeDef);
    dropped.traits = (dropped.traits ?? []).filter((t) => t !== 'pca.irreversible');
    expect(schemaVerbFloorError(dropped, CORE_REGISTRY, TEST_PINS)).toBe('schema_traits_forged: missing implied trait pca.irreversible');
  });
  it('a failure that carries no code is reported under schema_floor_forged', () => {
    const v = bare(writeDef);
    Reflect.set(v, 'params', null);
    expect(schemaVerbFloorError(v, CORE_REGISTRY, TEST_PINS)).toMatch(/^schema_floor_forged: .+/);
  });
});

describe('derive leftovers', () => {
  it('the custom trait comparator puts an equal id after, a lower id before', () => {
    const cmps = sortCmps(() => { toSchemaDoc([], CORE_REGISTRY, META); });
    // the digest computed after the sorts sorts with comparators too, so the list is longer; the custom trait sort is the second call
    expect(cmps.length).toBeGreaterThanOrEqual(2);
    const cmp = cmps[1]!;
    expect(cmp({ id: 'a' }, { id: 'b' })).toBe(-1);
    expect(cmp({ id: 'b' }, { id: 'a' })).toBe(1);
    expect(cmp({ id: 'a' }, { id: 'a' })).toBe(1);
  });
  it('an unreviewed card with no trait phrases lists nothing', () => {
    const e = { ...effOf(refund), confirmed: false, traits: [] };
    expect(cardOf(refund, e, CORE_REGISTRY).text).toBe('Refund a charge. This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it .');
  });
  it('a money parameter whose currency parameter is not declared lists no currencies', () => {
    const d = od('a.u.ghost', R_SET, { amt: { type: 'integer', role: 'money.amount', unit: { kind: 'money', ccy: { from: 'ghost' }, exp: 2 } } });
    expect(toOntology([d], CORE_REGISTRY).verbs[0]!.params.amt).toEqual({ kind: 'money', ccys: [] });
  });
});
