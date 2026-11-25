// Selector layer: exact outputs of role resolution, expansion, typing, the card, the carrier form and the catalog tape,
// over a small hand-built catalog so every branch has a known answer.
import { hashCanonical } from '@atlasauth/pca';
import { CORE_PACK_DEFS, CORE_REGISTRY, DOMAIN_VERBS, domainRoles, effective, toOntology, type Registry } from '@atlasauth/pca-actions';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { compileGoal } from '../src/compiler';
import type { Act, Cond, Ontology, Term, Ty } from '../src/ir';
import { toIrOntology, type IntentOntology } from '../src/ontology';
import { renderCard } from '../src/card';
import {
  allowClassVerbs, classVerbs, compileSelGoal, encodeSelCatalog, expandSelGoal, floatClassVerbs, renderSelCard, resolveRole, selCarrier,
  selCatalogDigest, selCatalogOfDefs, selCatalogOfDomain, selGoalDigest, selReasons, withRoleParams,
  type CondX, type SelCatalog, type SelGoal, type TermX,
} from '../src/selectors';
import { REVIEWED_PACK, REVIEW } from './reviewed';

const USD = { k: 'money', ccy: 'USD' } as const;
const EUR = { k: 'money', ccy: 'EUR' } as const;
const tU: Ty = { k: 'q', u: USD };
const tE: Ty = { k: 'q', u: EUR };
const tS: Ty = { k: 's' };
const R = { k: 'exact', id: 'r' } as const;

const ont: Ontology = {
  verbs: [
    { verb: 'a', cls: 'pay', params: [{ path: 'amt', ty: tU }, { path: 'who', ty: tS }] },
    { verb: 'b', cls: 'pay', params: [{ path: 'price', ty: tU }] },
    { verb: 'c', cls: 'read', params: [] },
    { verb: 'd', cls: 'pay', params: [{ path: 'amt', ty: tU }, { path: 'amt2', ty: tU }] },
    { verb: 'e', cls: 'move', params: [{ path: 'x', ty: tE }] },
  ],
  rels: [],
};
const cat: SelCatalog = {
  known: ['pca.unreviewed', 't.money', 't.net', 't.read'],
  verbs: [
    { verb: 'a', traits: ['t.money', 't.net'], roles: { m: ['amt'] } },
    { verb: 'b', traits: ['t.money'], roles: { m: ['price'] } },
    { verb: 'c', traits: ['t.read'], roles: {} },
    { verb: 'd', traits: ['pca.unreviewed', 't.money'], roles: { m: ['amt', 'amt2'] } },
    { verb: 'e', traits: ['t.money'], roles: { m: ['x'] } },
  ],
};

const role = (r: string): TermX => ({ k: 'role', role: r });
const lit5: TermX = { k: 'lit', v: { k: 'q', q: { u: USD, n: 5 } } };
const lit5T: Term = { k: 'lit', v: { k: 'q', q: { u: USD, n: 5 } } };
const strT = (s: string): TermX => ({ k: 'lit', v: { k: 's', s } });
const param = (path: string, ty: Ty): TermX => ({ k: 'param', path, ty });
const lteRole: CondX = { k: 'cmp', op: 'lte', l: role('m'), r: lit5 };
const lteP = (path: string, ty: Ty): Cond => ({ k: 'cmp', op: 'lte', l: { k: 'param', path, ty }, r: lit5T });
const TRUE: CondX = { k: 'true' };

function sg(over: Partial<SelGoal> = {}, c: SelCatalog = cat): SelGoal {
  return {
    v: 2, principal: 'P', ontDigest: 'o', catDigest: selCatalogDigest(c), nlDigest: 'n', sources: [],
    grants: [], prohibits: [], bounds: [],
    validity: { notBefore: 0, notAfter: 10 ** 9, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
    escalateOn: [], wildcardAck: [], holes: [], ...over,
  };
}
const cls = (all: string[], none: string[] = []) => ({ k: 'class', all_of: all, none_of: none }) as const;
const prohOf = (pid: string, target: SelGoal['prohibits'][0]['target'], cond: CondX = TRUE) => ({ pid, target, res: R, cond });
const grantOf = (gid: string, sel: SelGoal['grants'][0]['sel'], cond: CondX = TRUE) => ({ gid, sel, res: R, cond });
const bd = (bid: string, sel: SelGoal['bounds'][0]['sel'], value: TermX): SelGoal['bounds'][0] => ({
  bid, sel, agg: 'max', value, key: 'kk', window: { k: 'sliding', ms: 7 }, scope: { k: 'fleet', agents: ['x'] }, cap: { u: USD, n: 100 }, onExceed: 'escalate',
});

describe('class helpers', () => {
  it('select by all_of / none_of, the allow form drops unreviewed, the float form adds it', () => {
    expect(classVerbs(cat, ['t.money'], [])).toEqual(['a', 'b', 'd', 'e']);
    expect(classVerbs(cat, ['t.money'], ['t.net'])).toEqual(['b', 'd', 'e']);
    expect(classVerbs(cat, [], [])).toEqual(['a', 'b', 'c', 'd', 'e']);
    expect(allowClassVerbs(cat, ['t.money'], [])).toEqual(['a', 'b', 'e']);
    expect(floatClassVerbs(cat, ['t.net'], [])).toEqual(['a', 'd']);
    expect(floatClassVerbs(cat, ['t.read'], ['t.read'])).toEqual(['d']);
    expect(floatClassVerbs(cat, ['t.money'], ['t.net'])).toEqual(['b', 'd', 'e']);
  });
});

describe('catalog of a domain', () => {
  const trust = { attestationVerified: () => true };
  it.each(Object.keys(DOMAIN_VERBS) as (keyof typeof DOMAIN_VERBS)[])('%s: NL ids, the closure of the def behind each, the domain roles', (domain) => {
    const roles = domainRoles(domain);
    const want = DOMAIN_VERBS[domain]
      .map((b) => ({ verb: b.id, traits: effective(CORE_PACK_DEFS.find((d) => d.verb === b.verb)!, CORE_REGISTRY, trust).closure, roles: roles[b.id] ?? {} }))
      .sort((x, y) => (x.verb < y.verb ? -1 : x.verb > y.verb ? 1 : 0));
    const got = selCatalogOfDomain(domain, CORE_REGISTRY, trust);
    expect(got.verbs).toEqual(want);
    expect(got.known).toEqual([...CORE_REGISTRY.traits.keys()].sort());
    expect(got.known.length).toBeGreaterThan(0);
  });
  it('payments: concrete shape', () => {
    const c = selCatalogOfDomain('payments', CORE_REGISTRY, trust);
    expect(c.verbs.map((v) => v.verb)).toEqual(['cancel_subscription', 'charge_customer', 'payout', 'read_charge', 'refund', 'transfer']);
    expect(c.verbs.find((v) => v.verb === 'refund')!.roles).toEqual({ 'money.amount': ['amount'] });
    expect(c.verbs.find((v) => v.verb === 'read_charge')!.roles).toEqual({});
    expect(c.verbs.find((v) => v.verb === 'refund')!.traits).toContain('pca.money_moving');
    expect(c.verbs.find((v) => v.verb === 'read_charge')!.traits).not.toContain('pca.money_moving');
    expect(selCatalogOfDomain('payments').verbs.every((v) => v.traits.includes('pca.unreviewed'))).toBe(true);
  });
  it('of defs: sorted verbs, roles by parameter name', () => {
    const c = selCatalogOfDefs([...REVIEWED_PACK].reverse(), CORE_REGISTRY, REVIEW);
    expect(c.verbs.map((v) => v.verb)).toEqual([...c.verbs.map((v) => v.verb)].sort());
    expect(c.known).toEqual([...CORE_REGISTRY.traits.keys()].sort());
    expect(c.verbs.find((v) => v.verb === 'stripe.refund')!.roles['money.amount']).toEqual(['amount']);
  });
});

describe('catalog of defs: ordering and roles', () => {
  const refund = CORE_PACK_DEFS.find((d) => d.verb === 'stripe.refund')!;
  const book = CORE_PACK_DEFS.find((d) => d.verb === 'travel.book')!;
  it('a role lists its carrier parameters in name order; a parameter without a role makes no entry', () => {
    const amount = refund.params['amount']!;
    const multi = { ...refund, verb: 'multi', params: { zeta: { ...amount }, ...refund.params, alpha: { ...amount } } };
    const c = selCatalogOfDefs([multi]);
    expect(c.verbs[0]!.roles['money.amount']).toEqual(['alpha', 'amount', 'zeta']);
    for (const v of selCatalogOfDefs(CORE_PACK_DEFS).verbs) expect(Object.keys(v.roles)).not.toContain('undefined');
  });
  it('verbs with the same id keep their given order', () => {
    const c = selCatalogOfDefs([{ ...refund, verb: 'dup' }, { ...book, verb: 'dup' }]);
    expect(c.verbs.map((v) => v.roles['money.amount'])).toEqual([['amount'], ['price']]);
  });
  it('many verbs in awkward arrangements come out in id order', () => {
    let s = 12345;
    const next = (): number => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s; };
    const ids = Array.from({ length: 400 }, (_, i) => `v${String(i % 7)}${String((i * 37) % 400).padStart(3, '0')}x${i}`);
    const blocks = [0, 1, 2, 3, 4, 5].flatMap((b) => ids.filter((_, i) => i % 6 === b).sort());
    const shuffled = [...ids].sort(() => (next() % 3) - 1);
    for (const order of [ids, [...ids].reverse(), blocks, [...blocks].reverse(), shuffled]) {
      const c = selCatalogOfDefs(order.map((id) => ({ ...refund, verb: id })));
      expect(c.verbs.map((v) => v.verb)).toEqual([...ids].sort());
    }
  });
});

describe('digests', () => {
  it('the goal digest is the canonical hash under its own domain tag', () => {
    const g = sg({ principal: 'Z' });
    expect(selGoalDigest(g)).toBe(hashCanonical({ d: 'atlas-pca/goal-ir-sel/v1', goal: g }));
    expect(selGoalDigest(g)).not.toBe(selGoalDigest(sg({ principal: 'Y' })));
  });
});

describe('resolveRole', () => {
  it('one declared carrier resolves with its declared type', () => {
    expect(resolveRole(ont, cat, 'a', 'm')).toEqual({ path: 'amt', ty: tU });
    expect(resolveRole(ont, cat, 'e', 'm')).toEqual({ path: 'x', ty: tE });
  });
  it('none, several, unknown verb, undeclared verb, undeclared path, inherited property name: undefined', () => {
    expect(resolveRole(ont, cat, 'c', 'm')).toBeUndefined();
    expect(resolveRole(ont, cat, 'a', 'other')).toBeUndefined();
    expect(resolveRole(ont, cat, 'd', 'm')).toBeUndefined();
    expect(resolveRole(ont, cat, 'zz', 'm')).toBeUndefined();
    expect(resolveRole({ verbs: [], rels: [] }, cat, 'a', 'm')).toBeUndefined();
    expect(resolveRole(ont, { known: [], verbs: [{ verb: 'a', traits: [], roles: { m: ['ghost'] } }] }, 'a', 'm')).toBeUndefined();
    expect(resolveRole(ont, { known: [], verbs: [] }, 'a', 'm')).toBeUndefined();
    expect(resolveRole(ont, cat, 'a', 'toString')).toBeUndefined();
    expect(resolveRole(ont, cat, 'a', 'constructor')).toBeUndefined();
  });
  it('an absent role never falls back to some parameter', () => {
    const odd: Ontology = { verbs: [{ verb: 'a', cls: 'pay', params: [{ path: 'Stryker was here', ty: tS }] }], rels: [] };
    expect(resolveRole(odd, cat, 'a', 'nope')).toBeUndefined();
  });
});

describe('condition resolution (through a prohibition on one verb)', () => {
  const one = (verb: string, cond: CondX) => {
    const e = expandSelGoal(sg({ prohibits: [prohOf('p', { k: 'verb', verb }, cond)] }), ont, cat);
    return { cond: e.goal.prohibits[0]!.cond, unconditional: e.report.prohibits[0]!.unconditional };
  };
  it('every term and connective is rewritten, roles become the verb own parameter', () => {
    const c: CondX = {
      k: 'and',
      a: lteRole,
      b: { k: 'or', a: { k: 'not', c: { k: 'cmp', op: 'eq', l: param('who', tS), r: strT('z') } }, b: { k: 'cmp', op: 'gt', l: { k: 'hist', bid: 'bb', u: USD }, r: role('m') } },
    };
    expect(one('a', c)).toEqual({
      unconditional: [],
      cond: {
        k: 'and',
        a: lteP('amt', tU),
        b: { k: 'or', a: { k: 'not', c: { k: 'cmp', op: 'eq', l: { k: 'param', path: 'who', ty: tS }, r: { k: 'lit', v: { k: 's', s: 'z' } } } }, b: { k: 'cmp', op: 'gt', l: { k: 'hist', bid: 'bb', u: USD }, r: { k: 'param', path: 'amt', ty: tU } } },
      },
    });
  });
  it('and / or keep their own kind', () => {
    expect(one('c', { k: 'and', a: TRUE, b: TRUE }).cond).toEqual({ k: 'and', a: { k: 'true' }, b: { k: 'true' } });
    expect(one('c', { k: 'or', a: TRUE, b: TRUE }).cond).toEqual({ k: 'or', a: { k: 'true' }, b: { k: 'true' } });
    expect(one('c', { k: 'not', c: TRUE }).cond).toEqual({ k: 'not', c: { k: 'true' } });
  });
  it('one unresolved role anywhere makes the whole condition unresolved: the prohibition applies unconditionally', () => {
    const bad = role('m');
    const conds: CondX[] = [
      { k: 'and', a: { k: 'cmp', op: 'eq', l: bad, r: lit5 }, b: TRUE },
      { k: 'and', a: TRUE, b: { k: 'cmp', op: 'eq', l: bad, r: lit5 } },
      { k: 'or', a: { k: 'cmp', op: 'eq', l: bad, r: lit5 }, b: TRUE },
      { k: 'or', a: TRUE, b: { k: 'cmp', op: 'eq', l: bad, r: lit5 } },
      { k: 'not', c: { k: 'cmp', op: 'eq', l: bad, r: lit5 } },
      { k: 'cmp', op: 'eq', l: bad, r: lit5 },
      { k: 'cmp', op: 'eq', l: lit5, r: bad },
    ];
    for (const c of conds) expect(one('c', c)).toEqual({ cond: { k: 'true' }, unconditional: ['c'] });
  });
});

describe('expansion', () => {
  const sgx = sg({
    principal: 'PP', ontDigest: 'od', nlDigest: 'nd', sources: ['s1'],
    grants: [
      grantOf('g1', { k: 'verb', verb: 'a' }, lteRole),
      grantOf('g2', cls(['t.money']), lteRole),
      grantOf('g3', cls(['t.read']), lteRole),
      grantOf('g4', { k: 'verb', verb: 'd' }, lteRole),
      grantOf('g5', { k: 'verb', verb: 'b' }),
    ],
    prohibits: [
      prohOf('p1', { k: 'verb', verb: 'a' }, lteRole),
      prohOf('p2', { k: 'verb', verb: 'c' }, lteRole),
      prohOf('p3', { k: 'effect', cls: 'pay' }, lteRole),
      prohOf('p4', { k: 'trait', all_of: ['t.net'], none_of: [] }),
    ],
    bounds: [
      bd('b1', { k: 'gids', gids: ['g1'] }, param('who', tS)),
      bd('b2', { k: 'gids', gids: ['g2'] }, role('m')),
      bd('b3', { k: 'gids', gids: ['g1'] }, role('m')),
      bd('b4', { k: 'trait', all_of: ['t.net'], none_of: [] }, role('m')),
      bd('b5', { k: 'gids', gids: ['g1', 'g5'] }, role('m')),
      bd('b6', { k: 'effect', cls: 'pay' }, lit5),
      bd('b7', { k: 'effect', cls: 'move' }, role('m')),
      bd('b8', { k: 'trait', all_of: ['t.read'], none_of: [] }, lit5),
      bd('b9', { k: 'gids', gids: ['nothing'] }, role('m')),
      bd('b10', { k: 'gids', gids: ['g1'] }, { k: 'hist', bid: 'b1', u: USD }),
      bd('b12', { k: 'gids', gids: ['g3'] }, lit5),
    ],
    deleg: { maxDepth: 2, narrowOnly: false, mayTouch: ['g2'] },
    escalateOn: [{ k: 'true' }],
    wildcardAck: ['g2', 'g5'],
    holes: [{ hid: 'h', q: 'q?', domain: ['x'], affects: ['g1'], global: false }, { hid: 'h2', q: 'q2', domain: [], affects: ['g2', 'zz'], global: true }],
  });
  // expanded inside each test: code run while the describe body is collected is attributed to no test, so the mutation run would see it uncovered
  const expanded = (): ReturnType<typeof expandSelGoal> => expandSelGoal(sgx, ont, cat);
  it('the traits to leave out ride joined by the same separator as the traits to require', () => {
    const one = selCarrier(sg({ grants: [grantOf('g', cls(['t.money', 't.net'], ['t.x', 't.y']))] }));
    expect(one.grants[0]!.verb).toBe('C\u0001t.money\u0002t.net\u0001t.x\u0002t.y');
  });
  const bf = { agg: 'max', key: 'kk', window: { k: 'sliding', ms: 7 }, scope: { k: 'fleet', agents: ['x'] }, cap: { u: USD, n: 100 }, onExceed: 'escalate' } as const;

  it('grants: one per verb with the verb own path, the allow form skips the unreviewed verb, unresolved verbs are dropped and reported', () => {
    const { goal, report } = expanded();
    expect(goal.grants).toEqual([
      { gid: 'g1', verb: 'a', res: R, cond: lteP('amt', tU) },
      { gid: 'g2.a', verb: 'a', res: R, cond: lteP('amt', tU) },
      { gid: 'g2.b', verb: 'b', res: R, cond: lteP('price', tU) },
      { gid: 'g2.e', verb: 'e', res: R, cond: lteP('x', tE) },
      { gid: 'g5', verb: 'b', res: R, cond: { k: 'true' } },
    ]);
    expect(report.grants).toEqual([
      { gid: 'g1', verbs: ['a'], dropped: [] },
      { gid: 'g2', verbs: ['a', 'b', 'e'], dropped: [] },
      { gid: 'g3', verbs: ['c'], dropped: [{ verb: 'c', reason: 'role_unresolved' }] },
      { gid: 'g4', verbs: ['d'], dropped: [{ verb: 'd', reason: 'role_unresolved' }] },
      { gid: 'g5', verbs: ['b'], dropped: [] },
    ]);
  });
  it('prohibitions: verb / effect / trait targets, unresolved roles apply unconditionally', () => {
    const { goal, report } = expanded();
    expect(goal.prohibits).toEqual([
      { pid: 'p1', target: { k: 'verb', verb: 'a' }, res: R, cond: lteP('amt', tU) },
      { pid: 'p2', target: { k: 'verb', verb: 'c' }, res: R, cond: { k: 'true' } },
      { pid: 'p3.a', target: { k: 'verb', verb: 'a' }, res: R, cond: lteP('amt', tU) },
      { pid: 'p3.b', target: { k: 'verb', verb: 'b' }, res: R, cond: lteP('price', tU) },
      { pid: 'p3.d', target: { k: 'verb', verb: 'd' }, res: R, cond: { k: 'true' } },
      { pid: 'p4.a', target: { k: 'verb', verb: 'a' }, res: R, cond: { k: 'true' } },
      { pid: 'p4.d', target: { k: 'verb', verb: 'd' }, res: R, cond: { k: 'true' } },
    ]);
    expect(report.prohibits).toEqual([
      { pid: 'p1', verbs: ['a'], unconditional: [] },
      { pid: 'p2', verbs: ['c'], unconditional: ['c'] },
      { pid: 'p3', verbs: ['a', 'b', 'd'], unconditional: ['d'] },
      { pid: 'p4', verbs: ['a', 'd'], unconditional: [] },
    ]);
  });
  it('bounds: literal / shared path / role key values, trait + gid + effect selectors, dropped and unresolvable ones', () => {
    const { goal, report } = expanded();
    expect(goal.bounds).toEqual([
      { bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, value: { k: 'param', path: 'who', ty: tS }, ...bf },
      { bid: 'b3', sel: { k: 'gids', gids: ['g1'] }, value: { k: 'param', path: 'amt', ty: tU }, ...bf },
      { bid: 'b4', sel: { k: 'gids', gids: ['g1', 'g2.a'] }, value: { k: 'param', path: 'amt', ty: tU }, ...bf },
      { bid: 'b5', sel: { k: 'gids', gids: ['g1', 'g5'] }, value: { k: 'param', path: '@m', ty: tU }, ...bf },
      { bid: 'b6', sel: { k: 'effect', cls: 'pay' }, value: lit5T, ...bf },
      { bid: 'b7', sel: { k: 'effect', cls: 'move' }, value: { k: 'param', path: 'x', ty: tE }, ...bf },
      { bid: 'b10', sel: { k: 'gids', gids: ['g1'] }, value: { k: 'hist', bid: 'b1', u: USD }, ...bf },
    ]);
    expect(report.bounds).toEqual([
      { bid: 'b1', gids: ['g1'], dropped: false, value: 'literal' },
      { bid: 'b3', gids: ['g1'], dropped: false, value: 'shared_path' },
      { bid: 'b4', gids: ['g1', 'g2.a'], dropped: false, value: 'shared_path' },
      { bid: 'b5', gids: ['g1', 'g5'], dropped: false, value: 'role_key' },
      { bid: 'b6', gids: [], dropped: false, value: 'literal' },
      { bid: 'b7', gids: [], dropped: false, value: 'shared_path' },
      { bid: 'b8', gids: [], dropped: true, value: 'literal' },
      { bid: 'b10', gids: ['g1'], dropped: false, value: 'literal' },
      { bid: 'b12', gids: [], dropped: true, value: 'literal' },
    ]);
  });
  it('the rest of the goal: header, ids rewritten to the expanded ids', () => {
    const { goal } = expanded();
    expect(goal.v).toBe(1);
    expect(goal.principal).toBe('PP');
    expect(goal.ontDigest).toBe('od');
    expect(goal.nlDigest).toBe('nd');
    expect(goal.sources).toEqual(['s1']);
    expect(goal.validity).toEqual({ notBefore: 0, notAfter: 10 ** 9, maxIdle: 0 });
    expect(goal.deleg).toEqual({ maxDepth: 2, narrowOnly: false, mayTouch: ['g2.a', 'g2.b', 'g2.e'] });
    expect(goal.escalateOn).toEqual([{ k: 'true' }]);
    expect(goal.wildcardAck).toEqual(['g2.a', 'g2.b', 'g2.e', 'g5']);
    expect(goal.holes).toEqual([
      { hid: 'h', q: 'q?', domain: ['x'], affects: ['g1'], global: false },
      { hid: 'h2', q: 'q2', domain: [], affects: ['g2.a', 'g2.b', 'g2.e'], global: true },
    ]);
  });
});

describe('a bound whose role cannot resolve for a selected verb', () => {
  it('is skipped by the expansion and typed as unresolved', () => {
    const g = sg({ grants: [grantOf('gc', { k: 'verb', verb: 'c' })], bounds: [bd('x', { k: 'gids', gids: ['gc'] }, role('m'))] });
    const e = expandSelGoal(g, ont, cat);
    expect(e.goal.bounds).toEqual([]);
    expect(e.report.bounds).toEqual([]);
    expect(selReasons(g, ont, cat)).toEqual(['unresolved_role_bound']);
  });
});

describe('selReasons', () => {
  const good = () => sg({
    grants: [grantOf('g1', { k: 'verb', verb: 'a' }), grantOf('g2', cls(['t.money']))],
    prohibits: [prohOf('p1', { k: 'verb', verb: 'a' }), prohOf('p2', { k: 'effect', cls: 'pay' }), prohOf('p3', { k: 'trait', all_of: ['t.money'], none_of: ['t.net'] })],
    bounds: [bd('b1', { k: 'gids', gids: ['g1', 'g2'] }, lit5), bd('b2', { k: 'effect', cls: 'nothing' }, lit5), bd('b3', { k: 'trait', all_of: ['t.money'], none_of: ['t.net'] }, lit5)],
  });
  it('a well typed goal has no reasons', () => {
    expect(selReasons(good(), ont, cat)).toEqual([]);
    expect(selReasons(sg(), ont, cat)).toEqual([]);
  });
  it('a stale pin', () => {
    expect(selReasons({ ...good(), catDigest: 'stale' }, ont, cat)).toEqual(['catalog_digest_mismatch']);
  });
  it('bad ids: one bad id of each kind among good ones', () => {
    const g = good();
    expect(selReasons({ ...g, grants: [...g.grants, grantOf('bad.id', { k: 'verb', verb: 'a' })] }, ont, cat)).toEqual(['bad_id']);
    expect(selReasons({ ...g, prohibits: [...g.prohibits, prohOf('', { k: 'verb', verb: 'a' })] }, ont, cat)).toEqual(['bad_id']);
    expect(selReasons({ ...g, bounds: [...g.bounds, bd('b'.repeat(65), { k: 'effect', cls: 'x' }, lit5)] }, ont, cat)).toEqual(['bad_id']);
    expect(selReasons({ ...g, grants: [...g.grants, grantOf('A_9' + 'z'.repeat(61), { k: 'verb', verb: 'a' })] }, ont, cat)).toEqual([]);
  });
  it('a catalog verb the ontology does not declare', () => {
    const cat2: SelCatalog = { ...cat, verbs: [...cat.verbs, { verb: 'zz', traits: [], roles: {} }] };
    expect(selReasons(sg({}, cat2), ont, cat2)).toEqual(['catalog_mismatch']);
  });
  it('grant selectors: positive, non-empty, known; a verb grant always fine', () => {
    const g = good();
    const bad = (sel: SelGoal['grants'][0]['sel'], c = cat) => selReasons({ ...sg({ grants: [...g.grants, grantOf('gx', sel)] }, c) }, ont, c);
    expect(bad(cls(['t.money'], ['t.net']))).toEqual(['bad_grant_selector']);
    expect(bad(cls([]))).toEqual(['bad_grant_selector']);
    expect(bad(cls(['nope']))).toEqual(['bad_grant_selector']);
    expect(bad(cls(['t.money', 'nope']))).toEqual(['bad_grant_selector']);
    expect(bad(cls(['t.money', 't.net']))).toEqual([]);
    const blank: SelCatalog = { ...cat, known: ['', ...cat.known] };
    expect(bad(cls(['']), blank)).toEqual(['bad_grant_selector']);
  });
  it('prohibition selectors: every trait named must be known, in all_of and in none_of', () => {
    const bad = (target: SelGoal['prohibits'][0]['target']) => selReasons(sg({ prohibits: [prohOf('ok', { k: 'verb', verb: 'a' }), prohOf('px', target)] }), ont, cat);
    expect(bad({ k: 'trait', all_of: ['nope'], none_of: [] })).toEqual(['bad_prohibit_selector']);
    expect(bad({ k: 'trait', all_of: ['nope'], none_of: ['t.net'] })).toEqual(['bad_prohibit_selector']);
    expect(bad({ k: 'trait', all_of: ['t.net'], none_of: ['nope'] })).toEqual(['bad_prohibit_selector']);
    expect(bad({ k: 'trait', all_of: [], none_of: ['nope'] })).toEqual(['bad_prohibit_selector']);
    expect(bad({ k: 'trait', all_of: ['t.net'], none_of: ['t.money'] })).toEqual([]);
    expect(bad({ k: 'trait', all_of: [], none_of: [] })).toEqual([]);
    expect(bad({ k: 'effect', cls: 'whatever' })).toEqual([]);
  });
  it('bound selectors: gids must exist, an effect is free, traits must be known in both lists', () => {
    const bad = (sel: SelGoal['bounds'][0]['sel']) => selReasons(sg({ grants: [grantOf('g1', { k: 'verb', verb: 'a' })], bounds: [bd('bok', { k: 'gids', gids: ['g1'] }, lit5), bd('bx', sel, lit5)] }), ont, cat);
    expect(bad({ k: 'gids', gids: ['g1', 'nope'] })).toEqual(['bad_bound_selector']);
    expect(bad({ k: 'gids', gids: ['g1'] })).toEqual([]);
    expect(bad({ k: 'gids', gids: [] })).toEqual([]);
    expect(bad({ k: 'effect', cls: 'nothing' })).toEqual([]);
    expect(bad({ k: 'trait', all_of: ['nope'], none_of: [] })).toEqual(['bad_bound_selector']);
    expect(bad({ k: 'trait', all_of: ['nope'], none_of: ['t.net'] })).toEqual(['bad_bound_selector']);
    expect(bad({ k: 'trait', all_of: ['t.net'], none_of: ['nope'] })).toEqual(['bad_bound_selector']);
    expect(bad({ k: 'trait', all_of: ['t.net'], none_of: ['t.money'] })).toEqual([]);
  });
  it('a role-addressed bound that cannot resolve for every selected verb', () => {
    const g = sg({
      grants: [grantOf('g1', { k: 'verb', verb: 'a' }), grantOf('g2', cls(['t.money']))],
      bounds: [bd('bok', { k: 'gids', gids: ['g1'] }, role('m')), bd('bx', { k: 'gids', gids: ['g2'] }, role('m'))],
    });
    expect(selReasons(g, ont, cat)).toEqual(['unresolved_role_bound']);
    expect(selReasons({ ...g, bounds: [g.bounds[0]!] }, ont, cat)).toEqual([]);
  });
  it('every reason at once, in the order of the model', () => {
    const cat2: SelCatalog = { ...cat, verbs: [...cat.verbs, { verb: 'zz', traits: [], roles: {} }] };
    const g = sg({
      catDigest: 'x',
      grants: [grantOf('bad id', cls(['t.money'], ['t.net']))],
      prohibits: [prohOf('p', { k: 'trait', all_of: ['nope'], none_of: [] })],
      bounds: [bd('b', { k: 'gids', gids: ['nope'] }, role('m'))],
    }, cat2);
    expect(selReasons({ ...g, catDigest: 'x' }, ont, cat2)).toEqual([
      'catalog_digest_mismatch', 'bad_id', 'catalog_mismatch', 'bad_grant_selector', 'bad_prohibit_selector', 'bad_bound_selector', 'unresolved_role_bound',
    ]);
  });
});

describe('compileSelGoal', () => {
  it('selector reasons come first and nothing is expanded', () => {
    expect(compileSelGoal(sg({ catDigest: 'x' }), ont, cat)).toEqual({ ok: false, reasons: ['catalog_digest_mismatch'] });
  });
});

describe('compileSelGoal through the proved compiler', () => {
  const haveGen = existsSync(resolve(__dirname, '../../pca-verified-core/generated/pca_goal.js'));
  const rcat = selCatalogOfDefs(REVIEWED_PACK, CORE_REGISTRY, REVIEW);
  const ront: Ontology = toIrOntology({ verbs: toOntology(CORE_PACK_DEFS, CORE_REGISTRY).verbs } as unknown as IntentOntology);
  const money = (ack: string[]): SelGoal => sg({
    grants: [{ gid: 'pay', sel: cls(['pca.money_moving']), res: { k: 'any', reason: 'test' }, cond: { k: 'cmp', op: 'lte', l: role('money.amount'), r: lit5 } }],
    wildcardAck: ack,
  }, rcat);
  it.skipIf(!haveGen)('ok: the expansion, its report and the compiled policy', () => {
    const sgx = money(['pay']);
    const r = compileSelGoal(sgx, ront, rcat);
    const e = expandSelGoal(sgx, ront, rcat);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const c = compileGoal(e.goal, ront);
    expect(r.goal).toEqual(e.goal);
    expect(r.report).toEqual(e.report);
    expect(c.ok).toBe(true);
    if (c.ok) expect(r.policy).toEqual(c.policy);
  });
  it.skipIf(!haveGen)('a core compiler rejection is returned as its reasons', () => {
    const sgx = money([]);
    const r = compileSelGoal(sgx, ront, rcat);
    const c = compileGoal(expandSelGoal(sgx, ront, rcat).goal, ront);
    expect(c.ok).toBe(false);
    if (c.ok) return;
    expect(c.reasons.length).toBeGreaterThan(0);
    expect(r).toEqual({ ok: false, reasons: c.reasons });
  });
});

describe('withRoleParams', () => {
  const act = (verb: string, params: Act['params']): Act => ({ verb, res: 'r', params, t: 3, sess: 's', prin: 'P', org: 'o', agent: 'ag', depth: 2 });
  const q = (n: number) => ({ k: 'q', q: { u: USD, n } }) as const;
  it('adds @role for a role with one supplied carrier, strips forged @ keys, keeps the rest', () => {
    const a = act('a', { amt: q(1), who: { k: 's', s: 'w' }, '@m': q(99), '@other': q(5), 'z@': q(7) });
    const r = withRoleParams(a, cat);
    expect(r.params).toEqual({ amt: q(1), who: { k: 's', s: 'w' }, '@m': q(1), 'z@': q(7) });
    expect({ ...r, params: {} }).toEqual({ ...a, params: {} });
  });
  it('no key when the carrier is not supplied, ambiguous, or the verb unknown', () => {
    expect(Object.keys(withRoleParams(act('b', { other: q(1) }), cat).params)).toEqual(['other']);
    expect(Object.keys(withRoleParams(act('d', { amt: q(1), amt2: q(2) }), cat).params).sort()).toEqual(['amt', 'amt2']);
    expect(withRoleParams(act('unknown', { '@m': q(1), p: q(2) }), cat).params).toEqual({ p: q(2) });
    expect(withRoleParams(act('b', { '@m': q(1) }), cat).params).toEqual({});
  });
});

describe('policy card', () => {
  const reg = { traits: new Map([['t.money', { card_phrase: 'moves money' }], ['t.net', { card_phrase: 'reaches the network' }], ['t.read', { card_phrase: 'reads data' }]]) } as unknown as Registry;
  const sgx = sg({
    grants: [grantOf('ga', cls(['t.money', 't.net']), lteRole), grantOf('gb', { k: 'verb', verb: 'c' }, lteRole), grantOf('ge', { k: 'verb', verb: 'b' }), grantOf('gg', { k: 'verb', verb: 'e' })],
    prohibits: [
      prohOf('pa', { k: 'trait', all_of: ['t.money'], none_of: ['t.net', 'zz'] }),
      prohOf('pb', { k: 'verb', verb: 'c' }, lteRole),
      prohOf('pc', { k: 'effect', cls: 'read' }),
      prohOf('pd', { k: 'trait', all_of: [], none_of: [] }),
      prohOf('pe', { k: 'trait', all_of: [], none_of: ['t.net'] }),
    ],
    bounds: [
      bd('ba', { k: 'trait', all_of: ['t.net'], none_of: [] }, role('m')),
      bd('bb', { k: 'trait', all_of: ['t.read'], none_of: [] }, lit5),
      bd('bc', { k: 'gids', gids: ['ga'] }, role('m')),
      bd('bd', { k: 'gids', gids: ['ge', 'ga'] }, role('m')),
      bd('bf', { k: 'trait', all_of: ['t.money'], none_of: [] }, role('m')),
    ],
  });
  it('one line per selector clause in trait phrases, warnings for what the principal must see, then the core card', () => {
    const c = renderSelCard(sgx, ont, cat, reg);
    const core = renderCard(expandSelGoal(sgx, ont, cat).goal);
    expect(c.lines).toEqual([
      'ALLOW "ga": every action that moves money and reaches the network [1 verb(s) in the pinned catalog: "a"]',
      'NEVER "pa": every action that moves money, except those that reaches the network or zz, today 3 verb(s) ["b", "d", "e"]; it also covers every verb added to the catalog later',
      'NEVER "pd": every action, today 5 verb(s) ["a", "b", "c", "d", "e"]; it also covers every verb added to the catalog later',
      'NEVER "pe": every action, except those that reaches the network, today 4 verb(s) ["b", "c", "d", "e"]; it also covers every verb added to the catalog later',
      'LIMIT "ba": over every action that reaches the network (1 grant(s))',
      'LIMIT "bb": over every action that reads data (0 grant(s))',
      ...core.lines,
    ]);
    expect(c.warnings).toEqual([
      'grant "gb" does not cover "c": it has no unique parameter for a role the condition names',
      'prohibition "pb" applies to "c" without its condition: the verb has no unique parameter for a role the condition names',
      'limit "bb" selects no grant and bounds nothing',
      'limit "bd" sums a role the verbs carry on different parameters: the action must supply the role key',
      ...core.warnings,
    ]);
  });
  it('a bound the expansion skipped has no report entry: no limit line, no warning, nothing throws', () => {
    const g = sg({ grants: [grantOf('ga', cls(['t.money', 't.net']), lteRole)], bounds: [bd('bz', { k: 'trait', all_of: ['t.read'], none_of: [] }, role('m'))] });
    const c = renderSelCard(g, ont, cat, reg);
    const core = renderCard(expandSelGoal(g, ont, cat).goal);
    expect(c.lines).toEqual(['ALLOW "ga": every action that moves money and reaches the network [1 verb(s) in the pinned catalog: "a"]', ...core.lines]);
    expect(c.warnings).toEqual(core.warnings);
  });
  it('the default registry names the traits by their own phrase', () => {
    const c = renderSelCard(sg({ grants: [grantOf('g', cls(['pca.money_moving']))] }, cat), ont, cat);
    expect(c.lines[0]).toContain('every action that moves money');
  });
});

describe('carrier form', () => {
  const ROLE = '\u0001role:';
  const cond: CondX = {
    k: 'and',
    a: { k: 'not', c: { k: 'cmp', op: 'gt', l: { k: 'hist', bid: 'hb', u: USD }, r: lit5 } },
    b: { k: 'or', a: TRUE, b: { k: 'cmp', op: 'eq', l: role('m'), r: param('who', tS) } },
  };
  const condC: Cond = {
    k: 'and',
    a: { k: 'not', c: { k: 'cmp', op: 'gt', l: { k: 'hist', bid: 'hb', u: USD }, r: lit5T } },
    b: { k: 'or', a: { k: 'true' }, b: { k: 'cmp', op: 'eq', l: { k: 'param', path: ROLE + 'm', ty: { k: 's' } }, r: { k: 'param', path: 'who', ty: tS } } },
  };
  const sgx = sg({
    sources: ['s1'],
    grants: [grantOf('g1', { k: 'verb', verb: 'a' }, cond), grantOf('g2', cls(['t.money', 't.net'], ['t.x']))],
    prohibits: [prohOf('p1', { k: 'verb', verb: 'a' }, cond), prohOf('p2', { k: 'effect', cls: 'pay' }), prohOf('p3', { k: 'trait', all_of: ['t.money'], none_of: [] })],
    bounds: [
      bd('b1', { k: 'gids', gids: ['g1'] }, role('m')),
      bd('b2', { k: 'effect', cls: 'pay' }, param('amt', tU)),
      bd('b3', { k: 'trait', all_of: ['t.money', 't.net'], none_of: ['t.x'] }, lit5),
      bd('b4', { k: 'gids', gids: [] }, { k: 'hist', bid: 'hb', u: USD }),
    ],
    deleg: { maxDepth: 3, narrowOnly: false, mayTouch: ['g1'] },
    escalateOn: [{ k: 'true' }],
    wildcardAck: ['g1'],
    holes: [{ hid: 'h', q: 'q', domain: ['d'], affects: ['g1'], global: true }],
  });
  const bf = { agg: 'max', key: 'kk', window: { k: 'sliding', ms: 7 }, scope: { k: 'fleet', agents: ['x'] }, cap: { u: USD, n: 100 }, onExceed: 'escalate' } as const;
  it('selectors ride in strings and roles in marked params', () => {
    expect(selCarrier(sgx)).toEqual({
      v: 1, principal: 'P', ontDigest: 'o', nlDigest: 'n', sources: ['s1'],
      grants: [
        { gid: 'g1', verb: 'V\u0001a', res: R, cond: condC },
        { gid: 'g2', verb: 'C\u0001t.money\u0002t.net\u0001t.x', res: R, cond: { k: 'true' } },
      ],
      prohibits: [
        { pid: 'p1', target: { k: 'verb', verb: 'V\u0001a' }, res: R, cond: condC },
        { pid: 'p2', target: { k: 'verb', verb: 'E\u0001pay' }, res: R, cond: { k: 'true' } },
        { pid: 'p3', target: { k: 'verb', verb: 'T\u0001t.money\u0001' }, res: R, cond: { k: 'true' } },
      ],
      bounds: [
        { bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, value: { k: 'param', path: ROLE + 'm', ty: { k: 's' } }, ...bf },
        { bid: 'b2', sel: { k: 'effect', cls: 'pay' }, value: { k: 'param', path: 'amt', ty: tU }, ...bf },
        { bid: 'b3', sel: { k: 'effect', cls: 'T\u0001t.money\u0002t.net\u0001t.x' }, value: lit5T, ...bf },
        { bid: 'b4', sel: { k: 'gids', gids: [] }, value: { k: 'hist', bid: 'hb', u: USD }, ...bf },
      ],
      validity: { notBefore: 0, notAfter: 10 ** 9, maxIdle: 0 },
      deleg: { maxDepth: 3, narrowOnly: false, mayTouch: ['g1'] },
      escalateOn: [{ k: 'true' }],
      wildcardAck: ['g1'],
      holes: [{ hid: 'h', q: 'q', domain: ['d'], affects: ['g1'], global: true }],
    });
  });
});

describe('catalog tape', () => {
  it('known ids, verb count, then per verb: verb, traits, role count, (role, paths)*', () => {
    const c: SelCatalog = {
      known: ['k1', 'k2'],
      verbs: [
        { verb: 'v1', traits: ['t1'], roles: { r1: ['p1', 'p2'], r2: ['p3'] } },
        { verb: 'v2', traits: [], roles: {} },
      ],
    };
    expect(encodeSelCatalog(c)).toEqual([
      ['i', 2], ['s', 'k1'], ['s', 'k2'],
      ['i', 2],
      ['s', 'v1'], ['i', 1], ['s', 't1'], ['i', 2],
      ['s', 'r1'], ['i', 2], ['s', 'p1'], ['s', 'p2'],
      ['s', 'r2'], ['i', 1], ['s', 'p3'],
      ['s', 'v2'], ['i', 0], ['i', 0],
    ]);
    expect(encodeSelCatalog({ known: [], verbs: [] })).toEqual([['i', 0], ['i', 0]]);
  });
});
