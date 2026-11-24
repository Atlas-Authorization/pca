import { describe, expect, it } from 'vitest';
import { checkOntology, payments, type IntentOntology, type OntologyIssue, type TCond, type Template, type TemplateBound, type TemplateGrant } from '../src';

// Every case starts from the shipped payments ontology (well formed) and breaks exactly one thing.
const RD = 'refund_duplicate';
const RC = 'refund_customer_charges';
const RR = 'read_customer_charges';
const CS = 'cancel_one_subscription';
const READ = `template:${RR}.read`;

const run = (f: (o: IntentOntology) => void): OntologyIssue[] => { const o = structuredClone(payments); f(o); return checkOntology(o); };
const tpl = (o: IntentOntology, id: string): Template => { const t = o.templates.find((x) => x.id === id); if (!t) throw new Error(`no template ${id}`); return t; };
const g0 = (t: Template): TemplateGrant => { const g = t.grants[0]; if (!g) throw new Error('no grant'); return g; };
const verbOf = (o: IntentOntology, id: string): IntentOntology['verbs'][number] => { const v = o.verbs.find((x) => x.id === id); if (!v) throw new Error(`no verb ${id}`); return v; };
const only = (is: OntologyIssue[], code: string): OntologyIssue[] => is.filter((i) => i.code === code);
const at = (is: OntologyIssue[], where: string, code: string): OntologyIssue[] => is.filter((i) => i.code === code && i.where === where);
const COUNT_BOUND = (bid: string, over: string[] | 'all', capSlot?: string): TemplateBound => ({ bid, agg: 'count', over, cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny', ...(capSlot !== undefined ? { cap_slot: capSlot } : {}) });
const LIT_CMP: TCond = { k: 'cmp', op: 'eq', l: { k: 'lit', v: { k: 's', s: 'x' } }, r: { k: 'lit', v: { k: 's', s: 'y' } } };
const T: TCond = { k: 'true' };

describe('ontology template validator (grants, prohibits, bounds, example)', () => {
  it('the base fixture is well formed', () => {
    expect(run(() => {})).toStrictEqual([]);
  });

  it('a declared slot that nothing uses is refused', () => {
    const is = run((o) => { tpl(o, RR).slots.push({ name: 'x', kind: 'count', mandatory: true }); });
    expect(only(is, 'slot_unused')).toStrictEqual([{ code: 'slot_unused', where: `template:${RR}.x`, msg: 'declared slot is never used' }]);
  });

  it('a template with no grant is refused', () => {
    const is = run((o) => { tpl(o, RR).grants = []; });
    expect(only(is, 'empty_allow')).toStrictEqual([{ code: 'empty_allow', where: `template:${RR}`, msg: 'template has no grant (empty Allow set)' }]);
  });

  it('a duplicate grant id is refused', () => {
    const is = run((o) => { const t = tpl(o, RR); t.example = {}; t.grants.push({ ...g0(t) }); });
    expect(only(is, 'dup_gid')).toStrictEqual([{ code: 'dup_gid', where: `template:${RR}`, msg: 'duplicate grant id' }]);
  });

  it('a grant verb outside the ontology is refused and the grant is not checked further', () => {
    const is = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).verb = 'ghost_verb'; });
    expect(only(is, 'grant_verb')).toStrictEqual([{ code: 'grant_verb', where: READ, msg: 'grant verb is not in the ontology' }]);
  });

  it('resource checks report under the grant (template.gid)', () => {
    const bad = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'exact', id: 'zzz_1' }; });
    expect(only(bad, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: READ, msg: 'exact resource id has the wrong type prefix' }]);
    const good = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'exact', id: 'ch_1' }; });
    expect(only(good, 'resource_type')).toStrictEqual([]);
  });

  it('condition checks report under the grant (template.gid)', () => {
    const is = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).cond = LIT_CMP; });
    expect(only(is, 'cond_param')).toStrictEqual([{ code: 'cond_param', where: READ, msg: 'left side of a comparison must be a declared parameter of the verb' }]);
  });

  it('conditions are checked through and / or on both sides', () => {
    const mk = (k: 'and' | 'or', badSide: 'a' | 'b'): OntologyIssue[] => run((o) => {
      const t = tpl(o, RR); t.example = {};
      g0(t).cond = badSide === 'a' ? { k, a: LIT_CMP, b: T } : { k, a: T, b: LIT_CMP };
    });
    for (const k of ['and', 'or'] as const) for (const side of ['a', 'b'] as const) {
      expect(only(mk(k, side), 'cond_param'), `${k}.${side}`).toStrictEqual([{ code: 'cond_param', where: READ, msg: 'left side of a comparison must be a declared parameter of the verb' }]);
    }
  });

  it('a wildcard grant is unbounded unless it is a read under an aggregate bound', () => {
    const noBound = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'any', reason: 'x' }; });
    expect(only(noBound, 'unbounded')).toStrictEqual([{ code: 'unbounded', where: READ, msg: 'wildcard resource in a template' }]);
    const bounded = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'any', reason: 'x' }; t.bounds = [COUNT_BOUND('b', 'all')]; });
    expect(only(bounded, 'unbounded')).toStrictEqual([]);
  });

  it('a non-read grant on a related set needs a bound, an exact one does not', () => {
    const related = run((o) => { const t = tpl(o, RC); t.example = {}; t.bounds = []; });
    expect(only(related, 'unbounded')).toStrictEqual([{ code: 'unbounded', where: `template:${RC}.refund-any`, msg: 'non-read grant on a related set needs an aggregate bound' }]);
    const exact = run((o) => { const t = tpl(o, CS); t.example = {}; t.bounds = []; });
    expect(only(exact, 'unbounded')).toStrictEqual([]);
  });

  it('a prohibit naming a verb outside the ontology is refused; an effect target is not checked as a verb', () => {
    const ghost = run((o) => { const t = tpl(o, RR); t.example = {}; const p = t.prohibits[0]; if (!p) throw new Error('no prohibit'); p.target = { k: 'verb', verb: 'ghost_verb' }; });
    expect(only(ghost, 'prohibit_verb')).toStrictEqual([{ code: 'prohibit_verb', where: `template:${RR}.no-refund`, msg: 'prohibit verb is not in the ontology' }]);
    expect(only(ghost, 'prohibit_effect')).toStrictEqual([]);
    const eff = run((o) => { const t = tpl(o, RR); t.example = {}; const p = t.prohibits[0]; if (!p) throw new Error('no prohibit'); p.target = { k: 'effect', cls: 'irreversible' }; });
    expect(only(eff, 'prohibit_verb')).toStrictEqual([]);
    expect(only(eff, 'prohibit_effect')).toStrictEqual([]);
  });

  it('a prohibit naming an unknown effect class is refused', () => {
    const is = run((o) => { const t = tpl(o, RR); t.example = {}; const p = t.prohibits[0]; if (!p) throw new Error('no prohibit'); p.target = { k: 'effect', cls: 'bogus' }; });
    expect(only(is, 'prohibit_effect')).toStrictEqual([{ code: 'prohibit_effect', where: `template:${RR}.no-refund`, msg: 'unknown effect class' }]);
    expect(only(is, 'prohibit_verb')).toStrictEqual([]);
  });

  it('a bound that selects an unknown grant is refused even when it also names a known one', () => {
    const mixed = run((o) => { const t = tpl(o, RR); t.example = {}; t.bounds = [COUNT_BOUND('b1', ['read', 'nope'])]; });
    expect(only(mixed, 'bound_over')).toStrictEqual([{ code: 'bound_over', where: `template:${RR}.b1`, msg: 'bound selects an unknown grant' }]);
    const known = run((o) => { const t = tpl(o, RR); t.example = {}; t.bounds = [COUNT_BOUND('b1', ['read'])]; });
    expect(only(known, 'bound_over')).toStrictEqual([]);
  });

  it('a bound cap slot that is not declared is refused', () => {
    const is = run((o) => { const t = tpl(o, RR); t.example = {}; t.bounds = [COUNT_BOUND('b1', 'all', 'ghost')]; });
    expect(only(is, 'slot_undeclared')).toStrictEqual([
      { code: 'slot_undeclared', where: `template:${RR}`, msg: 'slot ghost is used but not declared' },
      { code: 'slot_undeclared', where: `template:${RR}`, msg: 'cap slot ghost is not declared' },
    ]);
    expect(only(is, 'bound_cap')).toStrictEqual([]);
  });

  it('a cap slot that is neither money nor count is refused (and a count bound needs a count slot)', () => {
    const is = run((o) => { const t = tpl(o, RD); t.example = {}; const b = t.bounds[0]; if (!b) throw new Error('no bound'); b.cap_slot = 'customer'; });
    const w = `template:${RD}.one-refund`;
    expect(only(is, 'bound_cap')).toStrictEqual([
      { code: 'bound_cap', where: w, msg: 'cap slot must be money or count' },
      { code: 'bound_cap', where: w, msg: 'count bound needs a count slot' },
    ]);
  });

  it('a count bound over a money slot is refused', () => {
    const is = run((o) => { const t = tpl(o, RD); t.example = {}; const b = t.bounds[0]; if (!b) throw new Error('no bound'); b.cap_slot = 'max_amount'; });
    expect(only(is, 'bound_cap')).toStrictEqual([{ code: 'bound_cap', where: `template:${RD}.one-refund`, msg: 'count bound needs a count slot' }]);
  });

  it('a sum bound over a count slot is refused', () => {
    const is = run((o) => { const t = tpl(o, RC); t.example = {}; const b = t.bounds.find((x) => x.bid === 'total'); if (!b) throw new Error('no bound'); b.cap_slot = 'max_count'; });
    expect(only(is, 'bound_cap')).toStrictEqual([{ code: 'bound_cap', where: `template:${RC}.total`, msg: 'sum bound over money needs a money slot' }]);
  });

  it('a bound without a cap slot is not checked against a slot (even when a malformed slot has no name)', () => {
    const is = run((o) => {
      const t = tpl(o, RD); t.example = {};
      const s = t.slots.find((x) => x.name === 'max_amount'); if (!s) throw new Error('no slot');
      Reflect.deleteProperty(s, 'name');
      s.default = { ccy: 'USD', minor: 1 };
    });
    expect(only(is, 'bound_cap')).toStrictEqual([]);
  });

  it('a sum bound with no value parameter is refused', () => {
    const is = run((o) => { const t = tpl(o, RC); t.example = {}; const b = t.bounds.find((x) => x.bid === 'total'); if (!b) throw new Error('no bound'); delete b.param; });
    expect(only(is, 'bound_value')).toStrictEqual([{ code: 'bound_value', where: `template:${RC}.total`, msg: 'sum bound has no value parameter' }]);
  });

  it('an example that leaves holes is refused, naming every hole in order', () => {
    const is = run((o) => { tpl(o, RD).example = {}; });
    expect(only(is, 'example_holes')).toStrictEqual([{ code: 'example_holes', where: `template:${RD}`, msg: 'example leaves holes: charge,customer,max_amount' }]);
  });

  it('an example instantiation that drops a grant is refused', () => {
    const is = run((o) => { g0(tpl(o, RR)).res = { k: 'related', rel: 'charges_of', anchor: '$ghost' }; });
    expect(only(is, 'empty_allow')).toStrictEqual([{ code: 'empty_allow', where: `template:${RR}`, msg: 'example instantiation dropped a grant' }]);
  });

  it('an instantiated template whose grant can never allow is refused', () => {
    const is = run((o) => { const g = g0(tpl(o, RD)); const c = g.cond; g.cond = { k: 'and', a: c, b: { k: 'not', c } }; });
    expect(only(is, 'empty_allow')).toStrictEqual([{ code: 'empty_allow', where: `template:${RD}`, msg: 'instantiated template has an empty Allow set' }]);
  });

  it('exact resource ids are checked against the verb resource type prefix', () => {
    // verb resource type not declared: no prefix, so only a `$slot` reference passes (an id that spells the word "undefined" must not)
    const ghost = run((o) => { verbOf(o, 'read_charge').resource_type = 'ghost'; const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'exact', id: 'undefined_1' }; });
    expect(at(ghost, READ, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: READ, msg: 'exact resource id has the wrong type prefix' }]);
    expect(only(ghost, 'verb_resource_type')).toStrictEqual([{ code: 'verb_resource_type', where: 'read_charge', msg: 'resource type is not declared' }]);
    const slot = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'exact', id: '$customer' }; });
    expect(at(slot, READ, 'resource_type')).toStrictEqual([]);
  });

  it('one_of: empty and wrong-prefix members are refused, right-prefix members pass', () => {
    const setIds = (ids: string[]) => run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'oneof', ids }; });
    const good = setIds(['ch_1', 'ch_2']);
    expect(at(good, READ, 'resource_type')).toStrictEqual([]);
    expect(at(good, READ, 'resource_empty')).toStrictEqual([]);
    const mixed = setIds(['ch_1', 'zzz_1']);
    expect(at(mixed, READ, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: READ, msg: 'one_of member has the wrong type prefix' }]);
    const empty = setIds([]);
    expect(at(empty, READ, 'resource_empty')).toStrictEqual([{ code: 'resource_empty', where: READ, msg: 'one_of is empty' }]);
    expect(at(empty, READ, 'resource_type')).toStrictEqual([]);
  });

  it('related: an undeclared relation and a relation to another type are refused', () => {
    const unknown = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'related', rel: 'ghost_rel', anchor: '$customer' }; });
    expect(at(unknown, READ, 'relation_unknown')).toStrictEqual([{ code: 'relation_unknown', where: READ, msg: 'relation ghost_rel is not declared' }]);
    expect(at(unknown, READ, 'relation_type')).toStrictEqual([]);
    const wrongTo = run((o) => { const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'related', rel: 'subscriptions_of', anchor: '$customer' }; });
    expect(at(wrongTo, READ, 'relation_type')).toStrictEqual([{ code: 'relation_type', where: READ, msg: 'relation target type differs from the verb resource type' }]);
    const declared = run((o) => { const t = tpl(o, RR); t.example = {}; });
    expect(at(declared, READ, 'relation_type')).toStrictEqual([]);
    expect(at(declared, READ, 'relation_unknown')).toStrictEqual([]);
  });

  it('related: the anchor must carry the prefix of the relation source type', () => {
    const withAnchor = (anchor: string, from = 'charge') => run((o) => {
      const r = o.relations.find((x) => x.id === 'charges_of'); if (!r) throw new Error('no relation');
      r.from = from; r.to = 'charge';
      const t = tpl(o, RR); t.example = {}; g0(t).res = { k: 'related', rel: 'charges_of', anchor };
    });
    expect(at(withAnchor('ch_1'), READ, 'resource_type')).toStrictEqual([]);
    expect(at(withAnchor('cus_1'), READ, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: READ, msg: 'relation anchor has the wrong type prefix' }]);
    // a relation whose source type is not declared has no prefix: the anchor is refused, not dereferenced
    expect(at(withAnchor('cus_1', 'ghost'), READ, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: READ, msg: 'relation anchor has the wrong type prefix' }]);
  });

  it('all_of: fewer than two parts is refused and every part is checked', () => {
    const w = `template:${RD}.refund-one`;
    const one = run((o) => { const t = tpl(o, RD); t.example = {}; const r = g0(t).res; if (r.k !== 'all_of') throw new Error('not all_of'); r.parts = r.parts.slice(0, 1); });
    expect(only(one, 'all_of_arity')).toStrictEqual([{ code: 'all_of_arity', where: w, msg: 'all_of needs at least two parts' }]);
    const badPart = run((o) => { const t = tpl(o, RD); t.example = {}; const r = g0(t).res; if (r.k !== 'all_of') throw new Error('not all_of'); r.parts = [{ k: 'exact', id: 'zzz_1' }, ...r.parts.slice(1)]; });
    expect(at(badPart, w, 'resource_type')).toStrictEqual([{ code: 'resource_type', where: w, msg: 'exact resource id has the wrong type prefix' }]);
    expect(only(badPart, 'all_of_arity')).toStrictEqual([]);
  });
});
