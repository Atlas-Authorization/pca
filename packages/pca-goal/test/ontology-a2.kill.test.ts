import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import { ALL_ONTOLOGIES, checkOntology, goalAnchors, goalCcy, ontologyDigest, ontologyForGoal, resolveVerb, toIrOntology, type IntentOntology, type OntologyIssue, type OntVerb, type Template, type TemplateSlot } from '../src';
import type { Goal } from '../src/ir';

const raw = <T>(x: unknown): T => JSON.parse(JSON.stringify(x));
const fresh = (): IntentOntology => raw<IntentOntology>(ALL_ONTOLOGIES.payments);
const iss = (code: string, where: string, msg: string): OntologyIssue => ({ code, where, msg });
const byCode = (o: IntentOntology, code: string): OntologyIssue[] => checkOntology(o).filter((i) => i.code === code);
const tmpl = (o: IntentOntology, id: string): Template => {
  const t = o.templates.find((x) => x.id === id);
  if (!t) throw new Error(`no template ${id}`);
  return t;
};
const goal = (parts: Record<string, unknown>): Goal => raw<Goal>({
  v: 1, principal: 'p', ontDigest: '', nlDigest: '', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [], ...parts,
});
const related = (rel: string, anchor: string): unknown => ({ k: 'related', rel, anchor });
const grantOn = (gid: string, res: unknown): unknown => ({ gid, verb: 'read_charge', res, cond: { k: 'true' } });
const anchor = (rel: string, a: string): { rel: string; anchor: string; members: string[] } => ({ rel, anchor: a, members: [] });

describe('digest', () => {
  it('binds the domain tag and the ontology', () => {
    const o = fresh();
    expect(ontologyDigest(o)).toBe(hashCanonical({ d: 'atlas-pca/goal-intent-ontology/v1', ontology: o }));
  });
});

describe('resolveVerb', () => {
  const o = fresh();
  it('trims the word, resolves canonical ids and declared aliases', () => {
    expect(resolveVerb(o, '  refund ')).toBe('refund');
    expect(resolveVerb(o, ' reimburse ')).toBe('refund');
    expect(resolveVerb(o, 'zzz')).toBeUndefined();
  });
  it('does not resolve inherited object properties as aliases', () => {
    expect(resolveVerb(o, 'toString')).toBeUndefined();
    expect(resolveVerb(o, 'constructor')).toBeUndefined();
  });
});

describe('alias normalization strips invisible characters before comparing', () => {
  it('an invisible-character key collides with its visible twin', () => {
    const o = fresh();
    const k = 'x​';
    o.aliases[k] = 'refund';
    o.aliases['x'] = 'refund';
    expect(checkOntology(o)).toEqual([
      iss('alias_key', k, 'alias key is not in normalized form'),
      iss('alias_key', k, 'alias key contains invisible characters'),
      iss('alias_collision', 'x', `collides with ${k} after normalization`),
    ]);
  });
});

describe('goal currency and the IR projection', () => {
  const eur = { k: 'cmp', op: 'lte', l: { k: 'param', path: 'amount', ty: { k: 'q', u: { k: 'money', ccy: 'EUR' } } }, r: { k: 'lit', v: { k: 'q', q: { u: { k: 'money', ccy: 'EUR' }, n: 5 } } } };
  const g = goal({ grants: [{ gid: 'g', verb: 'refund', res: { k: 'any', reason: 'x' }, cond: { k: 'not', c: eur } }] });
  it('finds the currency under a not', () => {
    expect(goalCcy(g)).toBe('EUR');
  });
  it('declares money parameters in the goal currency', () => {
    const refund = ontologyForGoal(fresh(), g).verbs.find((v) => v.verb === 'refund');
    expect(refund?.params).toEqual([{ path: 'amount', ty: { k: 'q', u: { k: 'money', ccy: 'EUR' } } }]);
  });
  it('an explicit allowed currency wins over USD', () => {
    const refund = toIrOntology(fresh(), { ccy: 'GBP' }).verbs.find((v) => v.verb === 'refund');
    expect(refund?.params).toEqual([{ path: 'amount', ty: { k: 'q', u: { k: 'money', ccy: 'GBP' } } }]);
  });
  it('has no relation tables unless given', () => {
    expect(toIrOntology(fresh()).rels).toEqual([]);
    expect(toIrOntology(fresh(), { rels: [anchor('r', 'a')] }).rels).toEqual([anchor('r', 'a')]);
  });
  it('a money parameter without currencies fails on the first currency, not on the lookup', () => {
    const o = fresh();
    o.verbs.push(raw<OntVerb>({ id: 'nomoney', effect: 'read', resource_type: 'charge', params: { amount: { kind: 'money' } } }));
    expect(() => toIrOntology(o, { ccy: 'USD' })).toThrow(/^money parameter lists no currency$/);
  });
});

describe('goal currency: every place a goal names money, the first one wins', () => {
  const money = (ccy: string): unknown => ({ k: 'q', q: { u: { k: 'money', ccy }, n: 5 } });
  const amount = { k: 'param', path: 'amount', ty: { k: 'q', u: { k: 'money', ccy: 'EUR' } } };
  const litLeft = (v: unknown): unknown => ({ k: 'cmp', op: 'lte', l: { k: 'lit', v }, r: amount });
  const litRight = (v: unknown, op = 'lte'): unknown => ({ k: 'cmp', op, l: amount, r: { k: 'lit', v } });
  const T = { k: 'true' };
  const grantIf = (cond: unknown): unknown => ({ gid: 'g', verb: 'refund', res: { k: 'any', reason: 'x' }, cond });
  const capIn = (u: unknown): unknown => ({
    bid: 'b', sel: { k: 'gids', gids: ['g'] }, agg: 'sum', value: amount, key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u, n: 9 }, onExceed: 'deny',
  });
  it('a literal on the left of a comparison', () => {
    expect(goalCcy(goal({ grants: [grantIf(litLeft(money('EUR')))] }))).toBe('EUR');
  });
  it('the first member of a literal set, not the last', () => {
    expect(goalCcy(goal({ grants: [grantIf(litRight({ k: 'set', items: [money('EUR'), money('GBP')] }, 'in'))] }))).toBe('EUR');
  });
  it('either side of and / or', () => {
    expect(goalCcy(goal({ grants: [grantIf({ k: 'and', a: litRight(money('EUR')), b: T })] }))).toBe('EUR');
    expect(goalCcy(goal({ grants: [grantIf({ k: 'or', a: T, b: litRight(money('GBP')) })] }))).toBe('GBP');
  });
  it('prohibitions and escalation conditions', () => {
    const p = { pid: 'p', target: { k: 'verb', verb: 'refund' }, res: { k: 'any', reason: 'x' }, cond: litRight(money('EUR')) };
    expect(goalCcy(goal({ prohibits: [p] }))).toBe('EUR');
    expect(goalCcy(goal({ escalateOn: [litRight(money('GBP'))] }))).toBe('GBP');
  });
  it('a bound cap, only when no condition names a currency first', () => {
    expect(goalCcy(goal({ bounds: [capIn({ k: 'money', ccy: 'GBP' })] }))).toBe('GBP');
    expect(goalCcy(goal({ grants: [grantIf(litRight(money('EUR')))], bounds: [capIn({ k: 'money', ccy: 'GBP' })] }))).toBe('EUR');
  });
  it('a quantity of another unit never names the currency, even one carrying a ccy member', () => {
    const count = { k: 'count', ccy: 'GBP' };
    expect(goalCcy(goal({ grants: [grantIf(litRight({ k: 'q', q: { u: count, n: 1 } }))], bounds: [capIn({ k: 'money', ccy: 'EUR' })] }))).toBe('EUR');
    expect(goalCcy(goal({ bounds: [capIn(count), capIn({ k: 'money', ccy: 'EUR' })] }))).toBe('EUR');
  });
  it('a currency list entry that is not a string never becomes the declared currency', () => {
    const o = fresh();
    const amt = o.verbs.find((v) => v.id === 'refund')!.params.amount!;
    amt.ccys = [undefined as unknown as string, ...amt.ccys!];
    expect(toIrOntology(o).verbs).toEqual(toIrOntology(fresh()).verbs);
  });
});

describe('goalAnchors', () => {
  const x = related('a', 'bc');
  const y = related('ab', 'c');
  it('sorts by relation then anchor, starting from the wrong order', () => {
    expect(goalAnchors(goal({ grants: [grantOn('g1', y), grantOn('g2', x)] }))).toEqual([anchor('a', 'bc'), anchor('ab', 'c')]);
  });
  it('keeps the sorted order, and does not merge (a, bc) with (ab, c)', () => {
    expect(goalAnchors(goal({ grants: [grantOn('g1', x), grantOn('g2', y)] }))).toEqual([anchor('a', 'bc'), anchor('ab', 'c')]);
  });
  it('collects anchors from prohibits and from all_of parts', () => {
    const p = { pid: 'p', target: { k: 'verb', verb: 'refund' }, res: { k: 'all_of', parts: [related('r', 'z'), related('r', 'y')] }, cond: { k: 'true' } };
    expect(goalAnchors(goal({ prohibits: [p] }))).toEqual([anchor('r', 'y'), anchor('r', 'z')]);
  });
});

describe('slot references are collected from every clause', () => {
  it('a literal resource id references no slot', () => {
    const o = fresh();
    tmpl(o, 'cancel_one_subscription').grants[0]!.res = { k: 'exact', id: 'sub_1' };
    expect(byCode(o, 'slot_undeclared')).toEqual([]);
  });
  it('a slot used only under a not is used', () => {
    const o = fresh();
    const gr = tmpl(o, 'refund_customer_charges').grants[0]!;
    gr.cond = { k: 'not', c: gr.cond };
    expect(byCode(o, 'slot_unused')).toEqual([]);
    expect(byCode(o, 'slot_undeclared')).toEqual([]);
  });
  it('a slot used only by a prohibit is used', () => {
    const o = fresh();
    const t = tmpl(o, 'read_customer_charges');
    t.slots.push(raw<TemplateSlot>({ name: 'blocked', kind: 'id', of: 'charge', mandatory: false, default: 'ch_1' }));
    t.prohibits.push({ pid: 'p2', target: { k: 'verb', verb: 'refund' }, res: { k: 'exact', id: '$blocked' }, cond: { k: 'true' } });
    expect(byCode(o, 'slot_unused')).toEqual([]);
    expect(byCode(o, 'slot_undeclared')).toEqual([]);
  });
});

describe('types and units', () => {
  it('refuses a duplicate type id', () => {
    const o = fresh();
    o.types.push({ id: 'customer', id_prefix: 'cus2_' });
    expect(checkOntology(o)).toEqual([iss('dup_type', 'customer', 'duplicate type id')]);
  });
  it('refuses a reused or empty id prefix', () => {
    const o = fresh();
    o.types.push({ id: 'extra', id_prefix: 'cus_' }, { id: 'extra2', id_prefix: '' });
    expect(checkOntology(o)).toEqual([
      iss('dup_prefix', 'extra', 'id prefix empty or reused'),
      iss('dup_prefix', 'extra2', 'id prefix empty or reused'),
    ]);
  });
  it('accepts money exponents 0..4 and refuses everything else', () => {
    const o = fresh();
    o.units['U0'] = { kind: 'money', exponent: 0 };
    o.units['U4'] = { kind: 'money', exponent: 4 };
    o.units['Ub1'] = { kind: 'money', exponent: -1 };
    o.units['Ub2'] = { kind: 'money', exponent: 5 };
    o.units['Ub3'] = { kind: 'money', exponent: 1.5 };
    o.units['Ub4'] = { kind: 'money' };
    const m = 'money unit needs an integer exponent 0..4';
    expect(checkOntology(o)).toEqual([iss('unit_exponent', 'Ub1', m), iss('unit_exponent', 'Ub2', m), iss('unit_exponent', 'Ub3', m), iss('unit_exponent', 'Ub4', m)]);
  });
  it('refuses an exponent on a non-money unit', () => {
    const o = fresh();
    o.units['count'] = { kind: 'count', exponent: 2 };
    expect(checkOntology(o)).toEqual([iss('unit_exponent', 'count', 'only money units carry an exponent')]);
  });
});
