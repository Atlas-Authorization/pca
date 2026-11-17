// Trait selectors and role-addressed parameters (spec section 8): expansion, fail-closed rules, growth (T6), the $200/day example.
import { REVIEWED_PACK, REVIEW, reviewed } from './reviewed';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { CORE_PACK_DEFS, CORE_REGISTRY, toOntology } from '@atlasauth/pca-actions';
import { describe, expect, it } from 'vitest';
import type { Act, Goal, Hist, Ontology } from '../src/ir';
import { toIrOntology, type IntentOntology } from '../src/ontology';
import { refDecide } from '../src/refsem';
import {
  allowClassVerbs, classVerbs, compileSelGoal, floatClassVerbs, expandSelGoal, renderSelCard, selCatalogDigest, selCatalogOfDefs, selReasons, withRoleParams,
  type SelGoal,
} from '../src/selectors';

const haveGen = existsSync(resolve(__dirname, '../../pca-verified-core/generated/pca_goal.js'));
const cat = selCatalogOfDefs(REVIEWED_PACK, CORE_REGISTRY, REVIEW);
const ont: Ontology = toIrOntology({ verbs: toOntology(CORE_PACK_DEFS, CORE_REGISTRY).verbs } as unknown as IntentOntology);
const USD = { k: 'money', ccy: 'USD' } as const;
const usd = (n: number) => ({ u: USD, n });
const role = (r: string) => ({ k: 'role', role: r }) as const;
const lit = (n: number) => ({ k: 'lit', v: { k: 'q', q: usd(n) } }) as const;
const str = (s: string) => ({ k: 'lit', v: { k: 's', s } }) as const;

function goal(over: Partial<SelGoal> = {}, c = cat): SelGoal {
  return {
    v: 2, principal: 'P', ontDigest: 'o', catDigest: selCatalogDigest(c), nlDigest: 'n', sources: [],
    grants: [], prohibits: [], bounds: [],
    validity: { notBefore: 0, notAfter: 10 ** 9, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
    escalateOn: [], wildcardAck: [], holes: [], ...over,
  };
}
// "allow any money-moving action under $200/day": per-call ceiling, plus one shared bound over the class
const MONEY: SelGoal = goal({
  grants: [{ gid: 'pay', sel: { k: 'class', all_of: ['pca.money_moving'], none_of: [] }, res: { k: 'any', reason: 'test' }, cond: { k: 'cmp', op: 'lte', l: role('money.amount'), r: lit(20_000) } }],
  bounds: [{ bid: 'day', sel: { k: 'trait', all_of: ['pca.money_moving'], none_of: [] }, agg: 'sum', value: role('money.amount'), key: '', window: { k: 'sliding', ms: 86_400_000 }, scope: { k: 'principal' }, cap: usd(20_000), onExceed: 'deny' }],
  wildcardAck: ['pay'],
});
const act = (verb: string, params: Act['params'], t = 5): Act => ({ verb, res: 'r', params, t, sess: 's', prin: 'P', org: 'o', agent: 'a', depth: 0 });
const q = (n: number) => ({ k: 'q', q: usd(n) }) as const;
const hist: Hist = { adms: [], last: -1, aggs: {} };

describe('Class expansion (G-A4)', () => {
  it('the verbs of a class are exactly the set comprehension over the pinned catalog', () => {
    const want = cat.verbs.filter((v) => v.traits.includes('pca.money_moving')).map((v) => v.verb);
    expect(classVerbs(cat, ['pca.money_moving'], [])).toEqual(want);
    expect(want).toEqual(expect.arrayContaining(['stripe.charge', 'stripe.refund', 'stripe.payout', 'stripe.transfer', 'travel.book']));
    expect(classVerbs(cat, ['pca.money_moving'], ['pca.irreversible'])).toEqual(want.filter((v) => !cat.verbs.find((x) => x.verb === v)!.traits.includes('pca.irreversible')));
    expect(classVerbs(cat, [], [])).toHaveLength(cat.verbs.length);
  });
});

describe('the $200/day money-moving example', () => {
  const { goal: g, report } = expandSelGoal(MONEY, ont, cat);
  it('one grant per money verb, each with its own path; verbs with no unique money.amount are dropped and reported', () => {
    expect(selReasons(MONEY, ont, cat)).toEqual([]);
    const paths = Object.fromEntries(g.grants.map((x) => [x.verb, JSON.stringify(x.cond)]));
    expect(paths['stripe.refund']).toContain('"path":"amount"');
    expect(paths['travel.book']).toContain('"path":"price"');
    expect(g.grants.map((x) => x.gid)).toEqual([...g.grants.map((x) => x.gid)].sort());
    expect(report.grants[0]!.dropped).toEqual([]);
  });
  it('the shared bound selects every expanded grant and reads the role key (paths differ, type is one)', () => {
    expect(g.bounds).toHaveLength(1);
    expect(g.bounds[0]!.sel).toEqual({ k: 'gids', gids: g.grants.map((x) => x.gid) });
    expect(g.bounds[0]!.value).toEqual({ k: 'param', path: '@money.amount', ty: { k: 'q', u: USD } });
    expect(report.bounds[0]!.value).toBe('role_key');
  });
  it('golden: the expansion is pinned', () => {
    expect(g.grants.map((x) => x.gid)).toMatchInlineSnapshot(`
      [
        "pay.stripe.charge",
        "pay.stripe.payout",
        "pay.stripe.refund",
        "pay.stripe.transfer",
        "pay.travel.book",
      ]
    `);
  });
  it('semantics: under the ceiling allowed, over it denied, a verb outside the class denied, the daily total enforced', () => {
    const ok = withRoleParams(act('stripe.refund', { amount: q(15_000) }), cat);
    expect(refDecide(g, ont, ok, hist)).toBe(2);
    expect(refDecide(g, ont, withRoleParams(act('stripe.refund', { amount: q(25_000) }), cat), hist)).toBe(0);
    expect(refDecide(g, ont, withRoleParams(act('mail.send', {}), cat), hist)).toBe(0);
    const h2: Hist = { adms: [{ gid: 'pay.stripe.refund', act: withRoleParams(act('stripe.refund', { amount: q(15_000) }, 1), cat) }], last: 1, aggs: {} };
    expect(refDecide(g, ont, withRoleParams(act('travel.book', { price: q(10_000), destination: { k: 's', s: 'SFO' }, depart: q(0) }, 5), cat), h2)).not.toBe(2);
  });
  it('a caller cannot forge the role key', () => {
    const forged = withRoleParams(act('stripe.refund', { amount: q(15_000), '@money.amount': q(1) }), cat);
    expect(forged.params['@money.amount']).toEqual(q(15_000));
  });
  it.skipIf(!haveGen)('compiles through the proved compiler', () => {
    expect(compileSelGoal(MONEY, ont, cat).ok).toBe(true);
  });
});

describe('fail closed', () => {
  it('a grant verb without a unique role parameter is dropped, never widened', () => {
    const sg = goal({ grants: [{ gid: 'g', sel: { k: 'class', all_of: ['pca.external_communication'], none_of: [] }, res: { k: 'any', reason: 't' }, cond: { k: 'cmp', op: 'lte', l: role('money.amount'), r: lit(1) } }], wildcardAck: ['g'] });
    const { goal: g, report } = expandSelGoal(sg, ont, cat);
    expect(g.grants).toEqual([]);
    expect(report.grants[0]!.dropped.length).toBeGreaterThan(0);
  });
  it('a prohibition whose role term is unresolved applies unconditionally', () => {
    const sg = goal({ prohibits: [{ pid: 'no', target: { k: 'trait', all_of: ['pca.destructive'], none_of: [] }, res: { k: 'any', reason: 't' }, cond: { k: 'cmp', op: 'gt', l: role('money.amount'), r: lit(1) } }] });
    const { goal: g, report } = expandSelGoal(sg, ont, cat);
    expect(g.prohibits.every((p) => p.cond.k === 'true')).toBe(true);
    expect(report.prohibits[0]!.unconditional).toEqual(report.prohibits[0]!.verbs);
  });
  it('typing: negation on an allow selector, an empty one, an unknown trait, a stale pin, an unresolvable bound', () => {
    const g1 = (sel: SelGoal['grants'][0]['sel']) => goal({ grants: [{ gid: 'g', sel, res: { k: 'any', reason: 't' }, cond: { k: 'true' } }], wildcardAck: ['g'] });
    expect(selReasons(g1({ k: 'class', all_of: ['pca.destructive'], none_of: ['pca.bulk'] }), ont, cat)).toContain('bad_grant_selector');
    expect(selReasons(g1({ k: 'class', all_of: [], none_of: [] }), ont, cat)).toContain('bad_grant_selector');
    expect(selReasons(g1({ k: 'class', all_of: ['pca.nope'], none_of: [] }), ont, cat)).toContain('bad_grant_selector');
    expect(selReasons({ ...MONEY, catDigest: 'stale' }, ont, cat)).toContain('catalog_digest_mismatch');
    const bad = goal({ bounds: [{ ...MONEY.bounds[0]!, sel: { k: 'trait', all_of: ['pca.external_communication'], none_of: [] } }], grants: MONEY.grants });
    expect(selReasons(bad, ont, cat)).toContain('unresolved_role_bound');
    expect(selReasons(goal({ prohibits: [{ pid: 'a.b', target: { k: 'verb', verb: 'x' }, res: { k: 'any', reason: 't' }, cond: { k: 'true' } }] }), ont, cat)).toContain('bad_id');
  });
});

describe('T6: registry growth', () => {
  const extra = { ...CORE_PACK_DEFS.find((d) => d.verb === 'stripe.refund')!, verb: 'stripe.refund_all', aliases: [] };
  const cat2 = selCatalogOfDefs([...REVIEWED_PACK, reviewed(extra)], CORE_REGISTRY, REVIEW);
  const ont2: Ontology = toIrOntology({ verbs: toOntology([...CORE_PACK_DEFS, extra], CORE_REGISTRY).verbs } as unknown as IntentOntology);
  it('a floating prohibit covers the added verb; a pinned allow does not', () => {
    const sg = goal({
      grants: [{ gid: 'pay', sel: { k: 'class', all_of: ['pca.money_moving'], none_of: [] }, res: { k: 'any', reason: 't' }, cond: { k: 'true' } }], wildcardAck: ['pay'],
      prohibits: [{ pid: 'noirr', target: { k: 'trait', all_of: ['pca.destructive'], none_of: [] }, res: { k: 'any', reason: 't' }, cond: { k: 'true' } }],
    });
    // the pinned goal (old catalog): the added verb has no grant
    const a = expandSelGoal(sg, ont2, cat);
    expect(a.goal.grants.some((x) => x.verb === 'stripe.refund_all')).toBe(false);
    expect(refDecide(a.goal, ont2, act('stripe.refund_all', { amount: q(1) }), hist)).toBe(0);
    // re-expanded against the grown catalog, a prohibit selector covers more verbs, never fewer
    const old = classVerbs(cat, ['pca.money_moving'], []);
    expect(classVerbs(cat2, ['pca.money_moving'], [])).toEqual(expect.arrayContaining(old));
    const p1 = expandSelGoal(goal({ prohibits: [{ pid: 'm', target: { k: 'trait', all_of: ['pca.money_moving'], none_of: [] }, res: { k: 'any', reason: 't' }, cond: { k: 'true' } }] }, cat2), ont2, cat2);
    expect(p1.goal.prohibits.some((p) => p.target.k === 'verb' && p.target.verb === 'stripe.refund_all')).toBe(true);
  });
});

describe('unconfirmed means maximally dangerous: selectors', () => {
  // the same money verb, but nobody reviewed it: its closure is the top of the registry (it carries pca.unreviewed)
  const raw = { ...CORE_PACK_DEFS.find((d) => d.verb === 'stripe.refund')!, verb: 'stripe.refund_raw', aliases: [] };
  const mixed = selCatalogOfDefs([...REVIEWED_PACK, raw], CORE_REGISTRY, REVIEW);
  const ont3: Ontology = toIrOntology({ verbs: toOntology([...CORE_PACK_DEFS, raw], CORE_REGISTRY).verbs } as unknown as IntentOntology);
  const sel = (g: Partial<SelGoal>): SelGoal => goal(g, mixed);
  const any = { k: 'any', reason: 't' } as const;
  it('the unreviewed verb carries the whole top of the registry', () => {
    const v = mixed.verbs.find((x) => x.verb === 'stripe.refund_raw')!;
    expect(v.traits).toEqual(expect.arrayContaining(['pca.unreviewed', 'pca.money_moving', 'pca.code_execution', 'pca.credential_access']));
    expect(mixed.verbs.find((x) => x.verb === 'stripe.refund')!.traits).not.toContain('pca.unreviewed');
  });
  it('a class ALLOW never covers an unreviewed verb, even one that matches its traits', () => {
    expect(classVerbs(mixed, ['pca.money_moving'], [])).toContain('stripe.refund_raw');
    expect(allowClassVerbs(mixed, ['pca.money_moving'], [])).not.toContain('stripe.refund_raw');
    expect(allowClassVerbs(mixed, ['pca.money_moving'], [])).toContain('stripe.refund');
    const e = expandSelGoal(sel({ grants: [{ gid: 'pay', sel: { k: 'class', all_of: ['pca.money_moving'], none_of: [] }, res: any, cond: { k: 'true' } }], wildcardAck: ['pay'] }), ont3, mixed);
    expect(e.goal.grants.some((x) => x.verb === 'stripe.refund_raw')).toBe(false);
    expect(e.goal.grants.some((x) => x.verb === 'stripe.refund')).toBe(true);
  });
  it('a class PROHIBITION and a bound cover an unreviewed verb whatever their all_of and none_of say', () => {
    // a carve-out ("never X, except Y") names traits the unreviewed verb "has" in its top closure: it must still be covered
    for (const [all, none] of [[['pca.money_moving'], []], [['pca.money_moving'], ['pca.irreversible']], [['pca.pii_access'], ['pca.unreviewed']], [['pca.destructive'], [...mixed.known]]] as [string[], string[]][]) {
      expect(floatClassVerbs(mixed, all, none), `${all}|${none}`).toContain('stripe.refund_raw');
      const e = expandSelGoal(sel({ prohibits: [{ pid: 'p', target: { k: 'trait', all_of: all, none_of: none }, res: any, cond: { k: 'true' } }] }), ont3, mixed);
      expect(e.goal.prohibits.some((p) => p.target.k === 'verb' && p.target.verb === 'stripe.refund_raw')).toBe(true);
    }
  });
  it('a classifier miss changes nothing: dropping every machine trait from the raw def leaves it unreviewed, covered and not allowed', () => {
    const blind = { ...raw, traits: [], effects: ['read'] } as typeof raw;
    const m = selCatalogOfDefs([...REVIEWED_PACK, blind], CORE_REGISTRY, REVIEW);
    expect(m.verbs.find((x) => x.verb === 'stripe.refund_raw')!.traits).toContain('pca.money_moving');
    expect(allowClassVerbs(m, ['pca.money_moving'], [])).not.toContain('stripe.refund_raw');
    expect(floatClassVerbs(m, ['pca.money_moving'], [])).toContain('stripe.refund_raw');
  });
});

describe('policy card', () => {
  it('prints the selector in trait phrases with the verbs it covers, and warns about role keys', () => {
    const c = renderSelCard(MONEY, ont, cat);
    expect(c.lines.join('\n')).toContain('every action that moves money');
    expect(c.warnings.join('\n')).toContain('role key');
    expect(str('x').k).toBe('lit');
  });
  it('golden: the $200/day selector card', async () => {
    await expect(JSON.stringify(renderSelCard(MONEY, ont, cat), null, 1) + '\n').toMatchFileSnapshot('./golden/money-200-day.card.json');
  });
});

// T6 as a property: random added definitions, random trait-selector policies. Seeded LCG, fixed case count.
describe('T6 property: registry growth never raises a decision and a floating prohibit never covers fewer verbs', () => {
  const TRAITS = cat.known.filter((t) => t.startsWith('pca.'));
  const BASES = CORE_PACK_DEFS;
  const seed = { s: 20260501 };
  const next = (n: number): number => { seed.s = (Math.imul(seed.s, 1664525) + 1013904223) >>> 0; return seed.s % n; };
  const pick = <T,>(xs: readonly T[]): T => xs[next(xs.length)]!;
  const sel = () => ({ all_of: Array.from({ length: 1 + next(2) }, () => pick(TRAITS)), none_of: next(3) === 0 ? [pick(TRAITS)] : [] });
  const anyRes = { k: 'any', reason: 't' } as const;
  it('300 random (added defs, policy, action) cases', () => {
    for (let i = 0; i < 300; i++) {
      const added = Array.from({ length: 1 + next(3) }, (_, j) => ({ ...pick(BASES), verb: `x${i}.n${j}`, aliases: [] }));
      const defs2 = [...CORE_PACK_DEFS, ...added];
      const cat2 = selCatalogOfDefs(defs2.map((d) => (REVIEWED_PACK.includes(d) ? d : reviewed(d))), CORE_REGISTRY, REVIEW);
      const ont2: Ontology = toIrOntology({ verbs: toOntology(defs2, CORE_REGISTRY).verbs } as unknown as IntentOntology);
      const g = sel();
      const sg = goal({
        grants: [{ gid: 'a', sel: { k: 'class', all_of: [pick(TRAITS)], none_of: [] }, res: anyRes, cond: { k: 'true' } }, { gid: 'b', sel: { k: 'verb', verb: pick(cat.verbs).verb }, res: anyRes, cond: { k: 'true' } }],
        wildcardAck: ['a', 'b'],
        prohibits: next(2) === 0 ? [{ pid: 'p', target: { k: 'trait', all_of: g.all_of, none_of: g.none_of }, res: anyRes, cond: { k: 'true' } }] : [],
      });
      // (a) the floating selector covers a superset of verbs
      expect(classVerbs(cat2, g.all_of, g.none_of)).toEqual(expect.arrayContaining(classVerbs(cat, g.all_of, g.none_of)));
      const old = expandSelGoal(sg, ont2, cat).goal; // pinned to the old catalog
      const grown = { ...old, prohibits: expandSelGoal(sg, ont2, cat2).goal.prohibits }; // grants stay pinned, prohibits float
      for (const verb of defs2.map((d) => d.verb)) {
        const a = act(verb, { amount: q(1 + next(100)), price: q(1) }, 5);
        const dOld = refDecide(old, ont2, a, hist), dNew = refDecide(grown, ont2, a, hist);
        expect(dNew, `${verb}`).toBeLessThanOrEqual(dOld);
        if (added.some((d) => d.verb === verb)) expect(dNew, `new verb ${verb}`).toBe(0); // (b) pinned allows give a new verb nothing
      }
    }
  });
});
