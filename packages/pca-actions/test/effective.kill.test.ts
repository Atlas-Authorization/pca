// Kill tests for effective.ts: every structural parameter rule on its own, the declared risk, and the clamps of a declared profile.
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, declProfile, effective, profile, prulesViolations, requiredPrulesViolated, type ActionDef, type ParamDef, type ParamRuleId } from '../src';

const base: ActionDef = {
  v: 1, kind: 'pca-action-def', verb: 'acme.thing.make', title: 'Make a thing', effects: ['create'],
  resource: { type: 'acme.thing', id: '*', scope: 'set' }, params: {}, review: { state: 'authored' },
};
const def = (params: Record<string, ParamDef>, extra: Partial<ActionDef> = {}): ActionDef => ({ ...base, params, ...extra });
const rule = (d: ActionDef, id: ParamRuleId): ParamRuleId[] => prulesViolations(d, [id]);

describe('prulesViolations: a rule id with no rule is not a violation', () => {
  it('an unknown id is ignored', () => {
    expect(prulesViolations(base, ['no_such_rule' as never])).toEqual([]);
  });
});

describe('money_has_currency', () => {
  const amount: ParamDef = { type: 'integer', role: 'money.amount', min: 0, max: 100, unit: { kind: 'money', ccy: 'USD', exp: 2 } };
  const V: ParamRuleId[] = ['money_has_currency'];
  it('an amount or a fee with a money unit that names a currency passes', () => {
    expect(rule(def({ a: amount }), 'money_has_currency')).toEqual([]);
    expect(rule(def({ f: { type: 'integer', role: 'money.fee', unit: { kind: 'money', ccy: 'USD', exp: 2 } } }), 'money_has_currency')).toEqual([]);
  });
  it('an amount without a unit is a violation', () => {
    expect(rule(def({ a: { type: 'integer', role: 'money.amount', min: 0, max: 100 } }), 'money_has_currency')).toEqual(V);
  });
  it('a fee without a unit is a violation', () => {
    expect(rule(def({ f: { type: 'integer', role: 'money.fee' } }), 'money_has_currency')).toEqual(V);
  });
  it('one good money param does not excuse a bad one', () => {
    expect(rule(def({ a: amount, f: { type: 'integer', role: 'money.fee' } }), 'money_has_currency')).toEqual(V);
    expect(rule(def({ a: { type: 'integer', role: 'money.amount' }, f: { type: 'integer', role: 'money.fee', unit: { kind: 'money', ccy: 'USD', exp: 2 } } }), 'money_has_currency')).toEqual(V);
  });
  it('a currency taken from another param needs that param to be a money.currency in iso_currency format', () => {
    const from = (extra: Record<string, ParamDef>): ActionDef => def({ a: { ...amount, unit: { kind: 'money', ccy: { from: 'c' }, exp: 2 } }, ...extra });
    expect(rule(from({ c: { type: 'string', role: 'money.currency', format: 'iso_currency' } }), 'money_has_currency')).toEqual([]);
    expect(rule(from({}), 'money_has_currency')).toEqual(V);
    expect(rule(from({ c: { type: 'string', role: 'text.message', format: 'iso_currency' } }), 'money_has_currency')).toEqual(V);
    expect(rule(from({ c: { type: 'string', role: 'money.currency', format: 'iso_country' } }), 'money_has_currency')).toEqual(V);
    expect(rule(from({ c: { type: 'string', role: 'money.currency' } }), 'money_has_currency')).toEqual(V);
  });
});

describe('money_amount_bounded', () => {
  const V: ParamRuleId[] = ['money_amount_bounded'];
  const amt = (p: Partial<ParamDef>): ActionDef => def({ a: { type: 'integer', role: 'money.amount', ...p } });
  it('an integer amount with a min and a max passes', () => {
    expect(rule(amt({ min: 0, max: 100 }), 'money_amount_bounded')).toEqual([]);
  });
  it('an amount that is not an integer is a violation', () => {
    expect(rule(amt({ type: 'string', min: 0, max: 100 }), 'money_amount_bounded')).toEqual(V);
  });
  it('an amount missing its min, its max, or both is a violation', () => {
    expect(rule(amt({ max: 100 }), 'money_amount_bounded')).toEqual(V);
    expect(rule(amt({ min: 0 }), 'money_amount_bounded')).toEqual(V);
    expect(rule(amt({}), 'money_amount_bounded')).toEqual(V);
  });
  it('every amount must be bounded', () => {
    const ok: ParamDef = { type: 'integer', role: 'money.amount', min: 0, max: 100 };
    expect(rule(def({ a: ok, b: { type: 'integer', role: 'money.amount' } }), 'money_amount_bounded')).toEqual(V);
    expect(rule(def({ a: ok, b: { ...ok } }), 'money_amount_bounded')).toEqual([]);
  });
});

describe('recipient_param_declared', () => {
  const V: ParamRuleId[] = ['recipient_param_declared'];
  it('a payee param or a contact param declares the recipient', () => {
    expect(rule(def({ to: { type: 'string', role: 'party.payee' } }), 'recipient_param_declared')).toEqual([]);
    expect(rule(def({ to: { type: 'string', role: 'contact.email' } }), 'recipient_param_declared')).toEqual([]);
    expect(rule(def({ to: { type: 'string', role: 'contact.phone' } }), 'recipient_param_declared')).toEqual([]);
  });
  it('no recipient param is a violation, unless the audience is the resource itself', () => {
    expect(rule(def({}), 'recipient_param_declared')).toEqual(V);
    expect(rule(def({ x: { type: 'string', role: 'text.message' } }), 'recipient_param_declared')).toEqual(V);
    expect(rule(def({}, { audience: 'resource' }), 'recipient_param_declared')).toEqual([]);
  });
});

describe('array_bounded', () => {
  const V: ParamRuleId[] = ['array_bounded'];
  it('an array with max_items passes', () => {
    expect(rule(def({ xs: { type: 'array', items: 'string', max_items: 5 } }), 'array_bounded')).toEqual([]);
  });
  it('an array without max_items is a violation, even beside a bounded one', () => {
    expect(rule(def({ xs: { type: 'array', items: 'string' } }), 'array_bounded')).toEqual(V);
    expect(rule(def({ xs: { type: 'array', items: 'string', max_items: 5 }, ys: { type: 'array', items: 'string' } }), 'array_bounded')).toEqual(V);
  });
  it('a def with no array has nothing to bound', () => {
    expect(rule(def({ s: { type: 'string' } }), 'array_bounded')).toEqual([]);
  });
});

describe('export_bounded', () => {
  const V: ParamRuleId[] = ['export_bounded'];
  it('a def that touches one resource needs no limit', () => {
    expect(rule(def({}, { resource: { type: 'acme.thing', id: '*', scope: 'one' } }), 'export_bounded')).toEqual([]);
  });
  it('a wider def needs a count.limit param with a max', () => {
    expect(rule(def({ n: { type: 'integer', role: 'count.limit', max: 10 } }), 'export_bounded')).toEqual([]);
    expect(rule(def({}), 'export_bounded')).toEqual(V);
    expect(rule(def({ n: { type: 'integer', role: 'count.limit' } }), 'export_bounded')).toEqual(V);
  });
  it('a bound on a param with another role is not a limit', () => {
    expect(rule(def({ b: { type: 'integer', role: 'bytes.size', max: 10 } }), 'export_bounded')).toEqual(V);
  });
});

describe('secret_not_logged', () => {
  const V: ParamRuleId[] = ['secret_not_logged'];
  it('a credential param tagged secret passes', () => {
    expect(rule(def({ k: { type: 'string', role: 'credential.key', tags: ['secret'] } }), 'secret_not_logged')).toEqual([]);
  });
  it('a credential param without the secret tag is a violation, even beside a tagged one', () => {
    expect(rule(def({ k: { type: 'string', role: 'credential.key' } }), 'secret_not_logged')).toEqual(V);
    expect(rule(def({ k: { type: 'string', role: 'credential.key', tags: ['pii'] } }), 'secret_not_logged')).toEqual(V);
    expect(rule(def({ k: { type: 'string', role: 'credential.key', tags: ['secret'] }, t: { type: 'string', role: 'credential.token' } }), 'secret_not_logged')).toEqual(V);
  });
  it('a param with a role that is not a credential role is not checked', () => {
    expect(rule(def({ m: { type: 'string', role: 'text.message' } }), 'secret_not_logged')).toEqual([]);
  });
});

describe('declProfile: the declared risk', () => {
  it('a write is elevated, a read is low', () => {
    expect(declProfile(base).risk).toBe(1);
    expect(declProfile({ ...base, effects: ['read'] }).risk).toBe(0);
  });
  it('a param of critical sensitivity makes the declared risk critical, for a read as well', () => {
    const critical = { k: { type: 'string', role: 'credential.secret' } } as const;
    expect(declProfile(def(critical)).risk).toBe(2);
    expect(declProfile(def(critical, { effects: ['read'] })).risk).toBe(2);
    expect(declProfile(def({ s: { type: 'string', sensitivity: 'critical' } })).risk).toBe(2);
  });
  it('a param of material sensitivity does not', () => {
    expect(declProfile(def({ m: { type: 'string', role: 'text.message' } })).risk).toBe(1);
    expect(declProfile(def({ m: { type: 'string', role: 'text.message' } }, { effects: ['read'] })).risk).toBe(0);
  });
});

describe('effective: a declared value below the floor of its traits is reported as a clamp', () => {
  const read: ActionDef = { ...base, effects: ['read'], resource: { type: 'acme.thing', id: '*', scope: 'one' } };
  it('an undeclared reversibility is never a clamp', () => {
    const e = effective({ ...read, traits: ['pca.irreversible'] }, CORE_REGISTRY);
    expect(e.decl.rev).toBe('reversible');
    expect(e.hint.floor.rev).toBe('irreversible');
    expect(e.clamps).toEqual([]);
  });
  it('a declared reversibility below the floor is a clamp that names both', () => {
    expect(effective({ ...read, reversibility: 'reversible', traits: ['pca.irreversible'] }, CORE_REGISTRY).clamps).toEqual([{ field: 'rev', declared: 'reversible', floor: 'irreversible' }]);
    expect(effective({ ...read, reversibility: 'irreversible', traits: ['pca.irreversible'] }, CORE_REGISTRY).clamps).toEqual([]);
  });
  it('a declared blast equal to the floor is not a clamp; below it is', () => {
    const moving: ActionDef = { ...read, traits: ['pca.money_moving'] };
    expect(effective(moving, CORE_REGISTRY).hint.floor.blast_ppm).toBe(700_000);
    expect(effective({ ...moving, blast: { radius: 'one', ppm: 700_000 } }, CORE_REGISTRY).clamps).toEqual([]);
    expect(effective({ ...moving, blast: { radius: 'bounded' } }, CORE_REGISTRY).clamps).toEqual([{ field: 'blast_ppm', declared: 300_000, floor: 700_000 }]);
    expect(effective({ ...moving, blast: { radius: 'one', ppm: 700_001 } }, CORE_REGISTRY).clamps).toEqual([]);
  });
});

describe('requiredPrulesViolated', () => {
  it('returns the required rules the def does not satisfy, and none it does', () => {
    const unbounded = def({ xs: { type: 'array', items: 'string' } });
    expect(requiredPrulesViolated(unbounded, profile({ prules: ['array_bounded'] }))).toEqual(['array_bounded']);
    expect(requiredPrulesViolated(unbounded, profile({ prules: ['secret_not_logged'] }))).toEqual([]);
    expect(requiredPrulesViolated(unbounded, profile())).toEqual([]);
  });
});
