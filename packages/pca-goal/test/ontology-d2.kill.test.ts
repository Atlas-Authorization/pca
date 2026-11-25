// Kills the survivors of instantiateTemplate (resource, condition, prohibit and bound substitution, grant dropping) and of the
// human money parsers (parseHumanAmount, parseMoney). Every expectation is a whole value: the exact goal, hole, result or message.
import { describe, expect, it } from 'vitest';
import { instantiateTemplate, nlDigest, ontologyDigest, parseHumanAmount, parseMoney } from '../src';
import type { IntentOntology, SlotKind, SlotValue, TCond, Template, TemplateBound, TemplateGrant, TemplateProhibit, TemplateSlot, TTerm } from '../src';
import type { Goal, Op, Value } from '../src/ir';

// alpha is declared first: its `q` is text and its `amount` is JPY only. beta's `q` is a count and its `amount` accepts USD and EUR.
// A lookup that lands on the wrong verb therefore yields a visibly different type.
const O: IntentOntology = {
  id: 'o', version: 1, domain: 'o',
  types: [{ id: 'acct', id_prefix: 'ac_' }],
  units: { USD: { kind: 'money', exponent: 2 }, count: { kind: 'count' } },
  relations: [],
  verbs: [
    { id: 'alpha', effect: 'read', resource_type: 'acct', params: { q: { kind: 'text' }, amount: { kind: 'money', ccys: ['JPY'] } } },
    { id: 'beta', effect: 'irreversible', resource_type: 'acct', params: { q: { kind: 'count' }, amount: { kind: 'money', ccys: ['USD', 'EUR'] }, z: { kind: 'count' } } },
  ],
  aliases: {},
  templates: [],
};

const slot = (name: string, kind: SlotKind, extra: Partial<TemplateSlot> = {}): TemplateSlot => ({ name, kind, mandatory: true, ...extra });
const tpl = (id: string, slots: TemplateSlot[], grants: TemplateGrant[], prohibits: TemplateProhibit[], bounds: TemplateBound[]): Template =>
  ({ id, title: id, phrases: [], slots, grants, prohibits, bounds, example: {} });
const TRUE: TCond = { k: 'true' };
const ANY = { k: 'any' as const, reason: 'r' };
const cmpT = (op: Op, l: TTerm, r: TTerm): TCond => ({ k: 'cmp', op, l, r });
const cnt = (n: number): Value => ({ k: 'q', q: { u: { k: 'count' }, n } });
const grant = (gid: string, verb: string, res: TemplateGrant['res'], cond: TCond = TRUE): TemplateGrant => ({ gid, verb, res, cond });
const QCOUNT = { k: 'q', u: { k: 'count' } };
const EUR = { k: 'money', ccy: 'EUR' };
const pCount = (path: string) => ({ k: 'param', path, ty: QCOUNT });
const litCount = (n: number) => ({ k: 'lit', v: cnt(n) });
const OPTS = { principal: 'pr', nl: 'say' };

const hole = (hid: string, q: string) => ({ hid, q, domain: [], affects: [], global: false });

const A = slot('acct', 'id', { of: 'acct' });
const CAP_USD = slot('cap', 'money', { ccy: 'USD' });
const CAP_EUR = slot('cap', 'money', { ccy: 'EUR' });
const LIM = slot('lim', 'money', { ccy: 'EUR' });

const TEMPLATES: Template[] = [
  tpl('res', [A, slot('acct2', 'id', { of: 'acct' })], [
    grant('g1', 'alpha', { k: 'exact', id: '$acct' }),
    grant('g2', 'alpha', { k: 'exact', id: 'ac_lit' }),
    grant('g3', 'alpha', { k: 'oneof', ids: ['$acct', 'ac_lit2'] }),
    grant('g4', 'alpha', { k: 'related', rel: 'owns', anchor: '$acct' }),
    grant('g5', 'alpha', { k: 'all_of', parts: [{ k: 'exact', id: '$acct2' }, { k: 'oneof', ids: ['ac_l3', '$acct'] }] }),
    grant('g6', 'alpha', ANY),
  ], [], []),
  tpl('cond', [LIM], [
    grant('gc1', 'beta', ANY, { k: 'or', a: cmpT('lte', { k: 'param', path: 'amount' }, { k: 'slot', slot: 'lim' }), b: cmpT('gte', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(3) }) }),
    grant('gc2', 'beta', ANY, { k: 'not', c: cmpT('gte', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(3) }) }),
    grant('gc3', 'alpha', ANY, cmpT('eq', { k: 'param', path: 'z' }, { k: 'lit', v: cnt(1) })),
    grant('gc4', 'beta', ANY, { k: 'and', a: cmpT('lte', { k: 'param', path: 'amount' }, { k: 'slot', slot: 'lim' }), b: cmpT('gte', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(3) }) }),
  ], [], []),
  tpl('badp', [], [grant('g1', 'alpha', ANY, cmpT('eq', { k: 'param', path: 'nope' }, { k: 'lit', v: cnt(1) }))], [], []),
  tpl('proh', [A], [], [
    { pid: 'p1', target: { k: 'verb', verb: 'beta' }, res: ANY, cond: cmpT('eq', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(1) }) },
    { pid: 'p2', target: { k: 'effect', cls: 'irreversible' }, res: ANY, cond: cmpT('eq', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(2) }) },
    { pid: 'p3', target: { k: 'effect', cls: 'reversible' }, res: ANY, cond: cmpT('eq', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(3) }) },
    { pid: 'p4', target: { k: 'verb', verb: 'beta' }, res: { k: 'exact', id: '$acct' }, cond: cmpT('eq', { k: 'param', path: 'q' }, { k: 'lit', v: cnt(4) }) },
  ], []),
  tpl('dropall', [CAP_USD], [grant('g1', 'alpha', ANY), grant('g2', 'beta', ANY)], [],
    [{ bid: 'b1', agg: 'count', over: 'all', cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny', cap_slot: 'cap' }]),
  tpl('dropsome', [CAP_USD], [grant('g1', 'alpha', ANY), grant('g2', 'beta', ANY)], [],
    [{ bid: 'b1', agg: 'count', over: ['g1'], cap: { u: { k: 'count' }, n: 1 }, onExceed: 'deny', cap_slot: 'cap' }]),
  tpl('dup', [A], [grant('g1', 'alpha', { k: 'exact', id: '$acct' }), grant('g1', 'beta', ANY)], [], []),
  tpl('bnd', [CAP_EUR, slot('tier', 'enum', { values: ['gold'] })], [grant('gb1', 'alpha', ANY), grant('gb2', 'beta', ANY)], [], [
    { bid: 'bs', agg: 'sum', over: ['gb2'], param: 'amount', cap: { u: { k: 'money', ccy: 'USD' }, n: 1 }, onExceed: 'deny', cap_slot: 'cap' },
    { bid: 'bc', agg: 'count', over: 'all', cap: { u: { k: 'count' }, n: 4 }, onExceed: 'escalate', cap_slot: 'tier' },
  ]),
];
const OT: IntentOntology = { ...O, templates: TEMPLATES };
const goal = (over: Record<string, unknown>): Record<string, unknown> => ({
  v: 1, principal: 'pr', ontDigest: ontologyDigest(OT), nlDigest: nlDigest('say'), sources: [],
  grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: Number.MAX_SAFE_INTEGER, maxIdle: 0 }, deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [], ...over,
});
const inst = (id: string, values: Record<string, SlotValue>, opts: { principal: string; nl: string; sources?: string[] } = OPTS): Goal => instantiateTemplate(OT, id, values, opts);
const gr = (gid: string, verb: string, res: unknown, cond: unknown = TRUE) => ({ gid, verb, res, cond });

describe('instantiateTemplate', () => {
  it('an unknown template throws with its id', () => {
    expect(() => inst('nope', {})).toThrow(new Error('unknown template nope'));
  });

  it('substitutes slot references in every resource selector shape and leaves literal ids alone', () => {
    expect(inst('res', { acct: 'ac_1', acct2: 'ac_2' })).toEqual(goal({
      grants: [
        gr('g1', 'alpha', { k: 'exact', id: 'ac_1' }),
        gr('g2', 'alpha', { k: 'exact', id: 'ac_lit' }),
        gr('g3', 'alpha', { k: 'oneof', ids: ['ac_1', 'ac_lit2'] }),
        gr('g4', 'alpha', { k: 'related', rel: 'owns', anchor: 'ac_1' }),
        gr('g5', 'alpha', { k: 'all_of', parts: [{ k: 'exact', id: 'ac_2' }, { k: 'oneof', ids: ['ac_l3', 'ac_1'] }] }),
        gr('g6', 'alpha', ANY),
      ],
    }));
  });

  it('types parameters from their verb, hints money from the literal, and rebuilds or / not / and', () => {
    const tA = { k: 'cmp', op: 'lte', l: { k: 'param', path: 'amount', ty: { k: 'q', u: EUR } }, r: { k: 'lit', v: { k: 'q', q: { u: EUR, n: 5000 } } } };
    const tB = { k: 'cmp', op: 'gte', l: pCount('q'), r: litCount(3) };
    expect(inst('cond', { lim: { ccy: 'EUR', minor: 5000 } })).toEqual(goal({
      grants: [
        gr('gc1', 'beta', ANY, { k: 'or', a: tA, b: tB }),
        gr('gc2', 'beta', ANY, { k: 'not', c: tB }),
        gr('gc3', 'alpha', ANY, { k: 'cmp', op: 'eq', l: pCount('z'), r: litCount(1) }), // z is declared by beta only
        gr('gc4', 'beta', ANY, { k: 'and', a: tA, b: tB }),
      ],
    }));
  });

  it('a parameter no verb declares throws', () => {
    expect(() => inst('badp', {})).toThrow(new Error('parameter nope is not declared by any verb'));
  });

  it('prohibitions: typed by verb target or effect target, a hole widens to every resource', () => {
    const pr = (pid: string, target: unknown, res: unknown, cond: unknown) => ({ pid, target, res, cond });
    expect(inst('proh', {})).toEqual(goal({
      prohibits: [
        pr('p1', { k: 'verb', verb: 'beta' }, ANY, { k: 'cmp', op: 'eq', l: pCount('q'), r: litCount(1) }),
        pr('p2', { k: 'effect', cls: 'irreversible' }, ANY, { k: 'cmp', op: 'eq', l: pCount('q'), r: litCount(2) }),
        // no verb has the reversible effect, so the parameter is looked up across all verbs: alpha declares q first (text)
        pr('p3', { k: 'effect', cls: 'reversible' }, ANY, { k: 'cmp', op: 'eq', l: { k: 'param', path: 'q', ty: { k: 's' } }, r: litCount(3) }),
        pr('p4', { k: 'verb', verb: 'beta' }, { k: 'any', reason: 'hole' }, { k: 'true' }),
      ],
      holes: [hole('acct', 'What is the acct (id)? (missing)')],
    }));
  });

  it('a bound whose cap slot is a hole drops every grant it covers (over all)', () => {
    expect(inst('dropall', {})).toEqual(goal({ holes: [hole('cap', 'What is the cap (money USD)? (missing)')] }));
  });

  it('a bound whose cap slot is a hole drops only the grants it names', () => {
    expect(inst('dropsome', {})).toEqual(goal({ grants: [gr('g2', 'beta', ANY)], holes: [hole('cap', 'What is the cap (money USD)? (missing)')] }));
  });

  it('a grant id that was dropped stays dropped for a later grant with the same id', () => {
    expect(inst('dup', {})).toEqual(goal({ holes: [hole('acct', 'What is the acct (id)? (missing)')] }));
  });

  it('bounds: cap from the slot or the literal, value typed from the first named grant, fixed window, scope and key', () => {
    expect(inst('bnd', { cap: { ccy: 'EUR', minor: 700 }, tier: 'gold' }, { principal: 'pr', nl: 'say', sources: ['d1', 'd2'] })).toEqual(goal({
      sources: ['d1', 'd2'],
      grants: [gr('gb1', 'alpha', ANY), gr('gb2', 'beta', ANY)],
      bounds: [
        // a non-quantity cap slot falls back to the template's literal cap
        { bid: 'bc', sel: { k: 'gids', gids: ['gb1', 'gb2'] }, agg: 'count', value: { k: 'lit', v: cnt(1) }, key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: { k: 'count' }, n: 4 }, onExceed: 'escalate' },
        { bid: 'bs', sel: { k: 'gids', gids: ['gb2'] }, agg: 'sum', value: { k: 'param', path: 'amount', ty: { k: 'q', u: EUR } }, key: '', window: { k: 'lifetime' }, scope: { k: 'session' }, cap: { u: EUR, n: 700 }, onExceed: 'deny' },
      ],
    }));
  });
});

describe('parseHumanAmount', () => {
  const ok = (minor: number) => ({ ok: true, minor });
  const no = (reason: string) => ({ ok: false, reason });
  it('drops currency symbols and words around the digits', () => {
    expect(parseHumanAmount('$20', 2)).toEqual(ok(2000));
    expect(parseHumanAmount('20 dollars', 2)).toEqual(ok(2000));
  });
  it('input that is not a number', () => {
    for (const t of ['', 'abc', '.5', ',5', '1..5', '1,,5', '1.,5']) expect(parseHumanAmount(t, 2)).toEqual(no('not a number'));
  });
  it('a lone separator repeated or grouped irregularly is malformed grouping', () => {
    expect(parseHumanAmount('1,00,0', 2)).toEqual(no('malformed grouping'));
    expect(parseHumanAmount('1,000,000', 2)).toEqual(ok(100000000));
    expect(parseHumanAmount('1.000.000', 0, 'de')).toEqual(ok(1000000));
  });
  it('the first group of a thousands grouping is one to three digits', () => {
    expect(parseHumanAmount('1234,567', 2, 'en')).toEqual(no('malformed grouping'));
    expect(parseHumanAmount('123,456', 2, 'en')).toEqual(ok(12345600));
    expect(parseHumanAmount('1,234', 2, 'en')).toEqual(ok(123400));
    expect(parseHumanAmount('1.234', 2, 'de')).toEqual(ok(123400));
  });
  it('en and de read the separators opposite ways, and without a locale a bare group is ambiguous', () => {
    expect(parseHumanAmount('1,000.50', 2)).toEqual(ok(100050));
    expect(parseHumanAmount('1.000,50', 2)).toEqual(ok(100050));
    expect(parseHumanAmount('1,000', 2)).toEqual(no('ambiguous separator'));
    expect(parseHumanAmount('1,000', 2, 'de')).toEqual(no('more decimals than the currency allows'));
  });
  it('more decimals than the exponent allows, and out of range', () => {
    expect(parseHumanAmount('1.5', 0)).toEqual(no('more decimals than the currency allows'));
    expect(parseHumanAmount('1.5', 1)).toEqual(ok(15));
    expect(parseHumanAmount('9007199254740993', 0)).toEqual(no('out of range'));
    expect(parseHumanAmount('9007199254740991', 0)).toEqual(ok(9007199254740991));
  });
});

describe('parseMoney', () => {
  it('a currency symbol is accepted only at the start', () => {
    expect(parseMoney('5$', 2, null)).toEqual({ error: 'BAD_NUMBER' });
    expect(parseMoney('5€', 2, null)).toEqual({ error: 'BAD_NUMBER' });
    expect(parseMoney('£5', 2, null)).toEqual({ minor: 500 });
  });
});
