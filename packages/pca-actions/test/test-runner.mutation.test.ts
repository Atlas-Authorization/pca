/* eslint-disable @typescript-eslint/no-explicit-any */
import { stringify } from 'yaml';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Thin pass-through seams: every collaborator defaults to the real implementation; a test overrides one to observe or steer the runner.
const H = vi.hoisted(() => ({
  realConform: undefined as any, conform: undefined as any,
  realFloorOf: undefined as any, floorOf: undefined as any,
  realLeq: undefined as any, leq: undefined as any,
  realEffWith: undefined as any, effWith: undefined as any,
  realLoad: undefined as any, load: undefined as any,
  realSchema: undefined as any, schema: undefined as any,
}));
vi.mock('@atlasauth/pca/ext/intent', async (orig: () => Promise<any>) => {
  const m = await orig();
  H.realConform = m.conformAction;
  return { ...m, conformAction: (...a: any[]) => (H.conform ?? H.realConform)(...a) };
});
vi.mock('../src/traits', async (orig: () => Promise<any>) => {
  const m = await orig();
  H.realFloorOf = m.floorOf;
  H.realLeq = m.leq;
  return { ...m, floorOf: (...a: any[]) => (H.floorOf ?? H.realFloorOf)(...a), leq: (...a: any[]) => (H.leq ?? H.realLeq)(...a) };
});
vi.mock('../src/effective', async (orig: () => Promise<any>) => {
  const m = await orig();
  H.realEffWith = m.effWithTrait;
  return { ...m, effWithTrait: (...a: any[]) => (H.effWith ?? H.realEffWith)(...a) };
});
vi.mock('../src/author', async (orig: () => Promise<any>) => {
  const m = await orig();
  H.realLoad = m.loadActionsText;
  return { ...m, loadActionsText: (...a: any[]) => (H.load ?? H.realLoad)(...a) };
});
vi.mock('../src/derive', async (orig: () => Promise<any>) => {
  const m = await orig();
  H.realSchema = m.toSchemaDoc;
  return { ...m, toSchemaDoc: (...a: any[]) => (H.schema ?? H.realSchema)(...a) };
});

import { CAVEAT_KINDS, CORE_REGISTRY, CORE_TRAIT_IDS, decideExample, effective, loadActionsText, parseParamShorthand, runDefTests, testText, type ActionDef, type TestReport } from '../src';

const HELLO = `
ns: acme
since: 0.1.0
actions:
  - verb: acme.invoice.send
    title: Send an invoice
    description: Emails an existing invoice to the customer.
    effects: [send]
    resource: acme.invoice:inv_*
    params: {invoice: "id:acme.invoice", to: email, note: "message(500)"}
  - verb: acme.charge.refund
    title: Refund a charge
    description: Returns money.
    effects: [pay]
    resource: acme.charge:ch_*
    params: {charge: "id:acme.charge", amount: "money(USD, max=100000)"}
`;
const LOADED = loadActionsText(HELLO).defs;
const send = LOADED[0]!;
const refund = LOADED[1]!;
const READ = loadActionsText('ns: acme\nactions:\n  - {verb: acme.invoice.get, effects: read, resource: "acme.invoice:inv_*", params: {invoice: "id:acme.invoice"}}\n').defs[0]!;
const SEND = { invoice: 'inv_12345678', to: 'a@b.com', note: 'hi', idempotency_key: 'k_12345678' };
const FULL = { trait: 'external_communication', where: { 'to.domain': ['b.com'] }, caveats: ['rate_cap', 'resource_scope'], context: ['fresh_revocation'] };

beforeEach(() => {
  H.conform = undefined; H.floorOf = undefined; H.leq = undefined; H.effWith = undefined; H.load = undefined; H.schema = undefined;
});
const acceptAll = (): void => { H.conform = () => ({ ok: true }); };
const dec = (d: ActionDef, params: Record<string, unknown>, under?: unknown) =>
  decideExample(d, { params, ...(under !== undefined ? { under } : {}), expect: 'allow' } as any, CORE_REGISTRY, [d]);
const need = (why: string): string[] => why.replace('floor needs ', '').split(', ').sort();

describe('the example policy: malformed policies are a deny with the exact reason', () => {
  const ALLOW_MSG = 'bad example policy: under must be {allow: selector | [selector]}';
  const SEL_MSG = 'bad example policy: an allow selector has trait, verb, where, caveats, context';
  const ONE_MSG = 'bad example policy: an allow selector names exactly one of trait and verb';
  beforeEach(acceptAll);
  it('under is {allow} and nothing else', () => {
    for (const under of [null, [], 5, 'x', { allow: FULL, other: 1 }]) expect(dec(send, SEND, under)).toEqual({ got: 'deny', why: ALLOW_MSG });
  });
  it('a selector is an object with only the known members, naming exactly one of trait and verb', () => {
    for (const under of [{}, { allow: null }, { allow: [null] }, { allow: [FULL, 5] }, { allow: { trait: 'x', foo: 1 } }]) expect(dec(send, SEND, under)).toEqual({ got: 'deny', why: SEL_MSG });
    expect(dec(send, SEND, { allow: { trait: 'x', verb: 'y' } })).toEqual({ got: 'deny', why: ONE_MSG });
    expect(dec(send, SEND, { allow: { caveats: [] } })).toEqual({ got: 'deny', why: ONE_MSG });
    expect(dec(send, SEND, { allow: [FULL, { where: {} }] })).toEqual({ got: 'deny', why: ONE_MSG });
  });
  it('where must be an object and caveats must all be known kinds', () => {
    for (const where of [[], null, 'x', 5]) expect(dec(send, SEND, { allow: { trait: 'x', where } })).toEqual({ got: 'deny', why: 'bad example policy: where must be an object' });
    for (const caveats of [['rate_cap', 'bogus'], ['bogus', 'rate_cap'], 'rate_cap', {}]) expect(dec(send, SEND, { allow: { trait: 'x', caveats } })).toEqual({ got: 'deny', why: 'bad example policy: caveats must be known caveat kinds' });
    expect(dec(send, SEND, { allow: { trait: 'x', caveats: [...CAVEAT_KINDS] } }).why).not.toMatch(/bad example policy/);
  });
});

describe('the example policy: which selectors match and what they grant', () => {
  beforeEach(acceptAll);
  it('a full grant allows; no policy, or a non-matching trait or verb, escalates', () => {
    expect(dec(send, SEND, { allow: FULL })).toEqual({ got: 'allow', why: 'floor satisfied' });
    expect(dec(send, SEND, { allow: { ...FULL, trait: 'pca.external_communication' } }).got).toBe('allow');
    const none = dec(send, SEND);
    expect(none.got).toBe('escalate');
    expect(none.why.startsWith('floor needs ')).toBe(true);
    expect(need(none.why)).toEqual(['fresh_revocation', 'rate_cap', 'recipient_scope', 'resource_scope']);
    expect(dec(send, SEND, { allow: { ...FULL, trait: 'bulk' } }).got).toBe('escalate');
    const { trait: _t, ...noTrait } = FULL;
    void _t;
    expect(dec(send, SEND, { allow: { ...noTrait, verb: 'acme.other.verb' } }).got).toBe('escalate');
    expect(dec(send, SEND, { allow: { ...noTrait, verb: 'acme.invoice.send' } }).got).toBe('allow');
    expect(dec(send, SEND, { allow: [{ ...FULL, trait: 'bulk' }] }).got).toBe('escalate');
    expect(dec(send, SEND, { allow: [{ ...FULL, trait: 'bulk' }, FULL] }).got).toBe('allow');
  });
  it('the message names exactly what the grant and the call still lack', () => {
    expect(dec(send, SEND, { allow: { ...FULL, caveats: ['rate_cap'] } })).toEqual({ got: 'escalate', why: 'floor needs resource_scope' });
    expect(dec(send, SEND, { allow: { ...FULL, context: [] } })).toEqual({ got: 'escalate', why: 'floor needs fresh_revocation' });
  });
  it('a where key grants the caveat of the param role it constrains', () => {
    const lacks = (where: Record<string, unknown>): string[] => need(dec(send, SEND, { allow: { trait: 'external_communication', caveats: [], context: ['fresh_revocation'], where } }).why);
    expect(lacks({ to: ['a@b.com'] })).toEqual(['rate_cap', 'resource_scope']);
    expect(lacks({ 'to.domain': ['b.com'] })).toEqual(['rate_cap', 'resource_scope']);
    expect(lacks({ invoice: ['inv_12345678'] })).toEqual(['rate_cap', 'recipient_scope']);
    expect(lacks({ note: ['hi'] })).toEqual(['rate_cap', 'recipient_scope', 'resource_scope']);
    expect(lacks({ idempotency_key: ['k_12345678'] })).toEqual(['rate_cap', 'recipient_scope', 'resource_scope']);
    // a selector that does not match contributes neither caveats nor its context
    expect(lacks({ 'to.domain': ['x.com'] })).toEqual(['fresh_revocation', 'rate_cap', 'recipient_scope', 'resource_scope']);
  });
  it('the payee role grants recipient_scope; a count limit grants count_cap', () => {
    const payee = { ...READ, params: { ...READ.params, who: { type: 'string', role: 'party.payee', max_len: 64 } }, traits: ['pca.network_egress'] } as unknown as ActionDef;
    expect(dec(payee, { invoice: 'inv_12345678', who: 'bob' }, { allow: { trait: 'network_egress', where: { who: ['bob'] } } }).got).toBe('allow');
    expect(dec(payee, { invoice: 'inv_12345678', who: 'bob' }, { allow: { trait: 'network_egress', where: { who: ['eve'] } } }).got).toBe('escalate');
    const bulk = { ...READ, params: { ...READ.params, n: parseParamShorthand('count(10)') }, traits: ['pca.bulk'] } as unknown as ActionDef;
    const call = { invoice: 'inv_12345678', n: 5 };
    const sel = (where: unknown, extra: object = {}) => ({ allow: { trait: 'bulk', where, ...extra } });
    expect(dec(bulk, call, sel({ n: { max: 10 } }))).toEqual({ got: 'allow', why: 'floor satisfied' });
    expect(dec(bulk, call, sel({ invoice: ['inv_12345678'] })).got).toBe('escalate');
    expect(dec(bulk, call, sel({ invoice: ['inv_12345678'] }, { caveats: ['count_cap'] })).got).toBe('allow');
  });
  it('numeric bounds are inclusive; anything else than a list of strings or a bounds object does not match', () => {
    const bulk = { ...READ, params: { ...READ.params, n: parseParamShorthand('count(10)') }, traits: ['pca.bulk'] } as unknown as ActionDef;
    const call = { invoice: 'inv_12345678', n: 5 };
    const got = (where: unknown, params: Record<string, unknown> = call, extra: object = {}) => dec(bulk, params, { allow: { trait: 'bulk', where, ...extra } }).got;
    expect(got({ n: { max: 5 } })).toBe('allow');
    expect(got({ n: { max: 4 } })).toBe('escalate');
    expect(got({ n: { min: 5 } })).toBe('allow');
    expect(got({ n: { min: 6 } })).toBe('escalate');
    expect(got({ n: { min: 5, max: 5 } })).toBe('allow');
    expect(got({ n: { min: 1, max: 9 } })).toBe('allow');
    expect(got({ n: { min: 1, max: 4 } })).toBe('escalate');
    expect(got({ n: {} })).toBe('allow');
    expect(got({ n: [5] })).toBe('escalate');
    expect(got({ n: 5 })).toBe('escalate');
    expect(got({ n: null })).toBe('escalate');
    expect(got({ n: { max: 10 } }, { invoice: 'inv_12345678' })).toBe('escalate');
    expect(got({ invoice: { max: 5 } }, call, { caveats: ['count_cap'] })).toBe('escalate');
    expect(got({ invoice: ['inv_12345678'] }, call, { caveats: ['count_cap'] })).toBe('allow');
    // a key that is not a declared param never matches, even when the call carries it
    expect(got({ ghost: ['x'] }, { ...call, ghost: 'x' }, { caveats: ['count_cap'] })).toBe('escalate');
  });
  it('with nothing but an escalation tier left, the message names the tier', () => {
    const reg = { ...READ, traits: ['pca.regulated_data'] } as unknown as ActionDef;
    expect(dec(reg, { invoice: 'inv_12345678' })).toEqual({ got: 'escalate', why: 'floor needs escalation tier 1' });
    expect(dec(reg, { invoice: 'inv_12345678' }, { allow: { trait: 'regulated_data' } })).toEqual({ got: 'allow', why: 'floor satisfied' });
  });
});

describe('the example policy: idempotency context', () => {
  beforeEach(acceptAll);
  const ctx = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'revocable', 'sandbox_attested'];
  const under = { allow: { verb: 'acme.charge.refund', caveats: [...CAVEAT_KINDS], context: ctx } };
  const R = { charge: 'ch_12345678', amount: 2500, idempotency_key: 'k_12345678' };
  const withIdem = (idempotency: unknown): ActionDef => ({ ...refund, idempotency }) as unknown as ActionDef;
  it('natural idempotency and a supplied key satisfy the floor; none, a missing key, or no declaration do not', () => {
    expect(dec(withIdem({ mode: 'natural' }), R, under)).toEqual({ got: 'allow', why: 'floor satisfied' });
    expect(dec(withIdem({ mode: 'key_param', param: 'idempotency_key' }), R, under)).toEqual({ got: 'allow', why: 'floor satisfied' });
    const lacking = { got: 'escalate', why: 'floor needs idempotency' };
    expect(dec(withIdem({ mode: 'none' }), R, under)).toEqual(lacking);
    expect(dec(withIdem(undefined), R, under)).toEqual(lacking);
    expect(dec(withIdem({ mode: 'key_param', param: 'idempotency_key' }), { charge: 'ch_12345678', amount: 2500 }, under)).toEqual(lacking);
    expect(dec(withIdem({ mode: 'key_param' }), { ...R, undefined: 'v' }, under)).toEqual(lacking);
  });
});

describe('decideExample: the schema step', () => {
  it('a refused call is a deny carrying the code and the path', () => {
    H.conform = () => ({ ok: false, code: 'bad_thing', path: 'a.b' });
    expect(dec(send, SEND, { allow: FULL })).toEqual({ got: 'deny', why: 'schema_violation bad_thing (a.b)' });
    H.conform = () => ({ ok: false, code: 'bad_thing' });
    expect(dec(send, SEND, { allow: FULL })).toEqual({ got: 'deny', why: 'schema_violation bad_thing' });
  });
  it('the call is conformed against the derived schema of the pack with the fixed example site', () => {
    const calls: any[] = [];
    H.conform = (doc: unknown, verb: string, params: unknown) => { calls.push({ doc, verb, params }); return { ok: true }; };
    dec(send, { ...SEND, extra: { a: 1 } }, { allow: FULL });
    expect(calls).toHaveLength(1);
    expect(calls[0].doc).toMatchObject({ v: 2, kind: 'pca-action-schema', site: 'https://example.invalid', aud: 'example', version: '0' });
    expect(calls[0].verb).toBe('acme.invoice.send');
    expect(calls[0].params).toEqual({ ...SEND, 'extra.a': 1 });
  });
});

describe('runDefTests: property checks', () => {
  const ts = (): string[] => { const e: any = effective(send, CORE_REGISTRY); return [...e.hint.traits]; };
  const subsetDetail = (r: TestReport): string => r.props[1]!.detail;
  it('the default bound covers every subset; a bound smaller than 2^n is honoured', () => {
    expect(subsetDetail(runDefTests([send], CORE_REGISTRY))).toBe('8 subsets, 0 violations');
    expect(subsetDetail(runDefTests([send], CORE_REGISTRY, { propLimit: 4 }))).toBe('4 subsets, 0 violations');
    expect(subsetDetail(runDefTests([send], CORE_REGISTRY, { propLimit: 0 }))).toBe('0 subsets, 0 violations');
  });
  it('a subset whose floor is not below the whole is a counted violation, and only the first `limit` masks are tried', () => {
    const owner = new WeakMap<object, string[]>();
    let bad: string[] = [];
    H.floorOf = (reg: unknown, t: string[]) => { const p = H.realFloorOf(reg, t); if (p && typeof p === 'object') owner.set(p, [...t]); return p; };
    H.leq = (a: object, b: object) => { const t = owner.get(a); return t !== undefined && bad.includes(t.join('|')) ? false : H.realLeq(a, b); };
    const t = ts();
    expect(t.length).toBe(3);
    bad = [t[0]!];
    const hit = runDefTests([send], CORE_REGISTRY, { propLimit: 3 });
    expect(hit.props[1]).toEqual({ verb: 'acme.invoice.send', name: 'floors are monotone over trait subsets', ok: false, detail: '3 subsets, 1 violations' });
    expect(hit.ok).toBe(false);
    bad = [`${t[0]}|${t[1]}`];
    expect(subsetDetail(runDefTests([send], CORE_REGISTRY, { propLimit: 3 }))).toBe('3 subsets, 0 violations');
    bad = [t[1]!, `${t[0]}|${t[1]}`, ''];
    // masks 0..7 over the three traits: [t1] is mask 2 and [t0,t1] is mask 3, [] is mask 0
    expect(subsetDetail(runDefTests([send], CORE_REGISTRY))).toBe('8 subsets, 3 violations');
  });
  it('adding a core trait that lowers the profile is named and fails the property', () => {
    let lastEff: unknown;
    let lastT = '';
    H.effWith = (d: unknown, t: string, reg: unknown) => { lastEff = H.realEffWith(d, t, reg); lastT = t; return lastEff; };
    H.leq = (a: object, b: object) => (b === lastEff && ['pca.bulk', 'pca.scheduled'].includes(lastT) ? false : H.realLeq(a, b));
    const r = runDefTests([send], CORE_REGISTRY);
    expect(r.props[0]).toEqual({ verb: 'acme.invoice.send', name: 'adding a trait never lowers the profile', ok: false, detail: 'pca.bulk, pca.scheduled' });
    expect(r.ok).toBe(false);
    H.effWith = undefined; H.leq = undefined;
    expect(runDefTests([send], CORE_REGISTRY).props[0]).toEqual({ verb: 'acme.invoice.send', name: 'adding a trait never lowers the profile', ok: true, detail: '' });
    expect(CORE_TRAIT_IDS).toContain('pca.bulk');
  });
});

describe('runDefTests: one digest across the JSON and YAML forms', () => {
  const mk = (defs: ActionDef[], errors: { message: string }[]) => ({ defs, notes: [], errors, locs: {}, rules: {} });
  const run = (j: any, y: any) => {
    const seen: { text: string; fmt: unknown }[] = [];
    H.load = (text: string, fmt?: unknown) => { seen.push({ text, fmt }); return fmt === 'json' ? j : y; };
    const r = runDefTests([send], CORE_REGISTRY);
    return { prop: r.props[2]!, seen, ok: r.ok };
  };
  const prop = (ok: boolean, detail: string) => ({ verb: 'acme.invoice.send', name: 'one digest across JSON and YAML forms', ok, detail });
  it('both forms agree', () => {
    const r = run(mk([send], []), mk([send], []));
    expect(r.prop).toEqual(prop(true, ''));
    expect(r.seen).toEqual([{ text: JSON.stringify(send), fmt: 'json' }, { text: stringify({ ns: 'acme', actions: [send] }), fmt: 'yaml' }]);
  });
  it('each side fails on an error, on a missing def, or on a different digest, and says why', () => {
    expect(run(mk([send], [{ message: 'boom' }]), mk([send], [])).prop).toEqual(prop(false, 'json boom; yaml ok'));
    expect(run(mk([send], []), mk([], [])).prop).toEqual(prop(false, 'json ok; yaml digest differs'));
    expect(run(mk([refund], []), mk([send], [{ message: 'yy' }])).prop).toEqual(prop(false, 'json digest differs; yaml yy'));
    expect(run(mk([], []), mk([refund], [])).prop).toEqual(prop(false, 'json digest differs; yaml digest differs'));
    expect(run(mk([], [{ message: 'e1' }]), mk([], [{ message: 'e2' }])).prop).toEqual(prop(false, 'json e1; yaml e2'));
    expect(run(mk([send], [{ message: 'boom' }]), mk([send], [{ message: 'boom' }])).ok).toBe(false);
  });
});

describe('runDefTests: the schema round trip', () => {
  const EX: Record<string, unknown> = { zz_ghost: 'z', k_maxonly: 4, j_minonly: 3, invoice: 'inv_12345678', i_strint: 'abc', h_numstr: 7, g_plain: 'q', f_nomax: 3, e_arr: ['a'], d_bool: true, c_str: 'abc', b_enum: 'x', a_int: 5 };
  const D2 = {
    ...READ,
    params: {
      ...READ.params,
      a_int: { type: 'integer', min: 1, max: 10 },
      b_enum: { type: 'string', values: ['x', 'y'] },
      c_str: { type: 'string', max_len: 5 },
      d_bool: { type: 'boolean', required: false },
      e_arr: { type: 'array', items: 'string' },
      f_nomax: { type: 'integer' },
      g_plain: { type: 'string' },
      h_numstr: { type: 'string', min: 1, max: 5, values: ['a'], max_len: 3 },
      i_strint: { type: 'integer', min: 1, max: 5, values: ['a'], max_len: 3 },
      j_minonly: { type: 'integer', min: 2 },
      k_maxonly: { type: 'integer', max: 9 },
    },
    examples: [{ params: EX, expect: 'allow' }],
  } as unknown as ActionDef;
  const w = (k: string) => { const c = { ...EX }; delete c[k]; return c; };
  const s = (k: string, v: unknown) => ({ ...EX, [k]: v });
  const MUTATIONS: [string, Record<string, unknown>][] = [
    ['extra param', { ...EX, zz_undeclared: 'x' }],
    ['missing a_int', w('a_int')], ['type swap a_int', s('a_int', 'x')], ['above max a_int', s('a_int', 11)], ['below min a_int', s('a_int', 0)],
    ['missing b_enum', w('b_enum')], ['type swap b_enum', s('b_enum', 12345)], ['outside values b_enum', s('b_enum', 'not_a_listed_value_zz')],
    ['missing c_str', w('c_str')], ['type swap c_str', s('c_str', 12345)], ['too long c_str', s('c_str', 'xxxxxx')],
    ['type swap d_bool', s('d_bool', 'x')],
    ['missing e_arr', w('e_arr')], ['type swap e_arr', s('e_arr', {})],
    ['missing f_nomax', w('f_nomax')], ['type swap f_nomax', s('f_nomax', 'x')],
    ['missing g_plain', w('g_plain')], ['type swap g_plain', s('g_plain', 12345)],
    ['missing h_numstr', w('h_numstr')], ['type swap h_numstr', s('h_numstr', 'x')],
    ['missing i_strint', w('i_strint')], ['type swap i_strint', s('i_strint', 12345)],
    ['missing invoice', w('invoice')], ['type swap invoice', s('invoice', 12345)], ['too long invoice', s('invoice', 'x'.repeat(65))],
    ['missing j_minonly', w('j_minonly')], ['type swap j_minonly', s('j_minonly', 'x')], ['below min j_minonly', s('j_minonly', 1)],
    ['missing k_maxonly', w('k_maxonly')], ['type swap k_maxonly', s('k_maxonly', 'x')], ['above max k_maxonly', s('k_maxonly', 10)],
  ];
  const rt = (r: TestReport) => r.props.find((q) => q.name === 'schema round trip')!;
  beforeEach(() => { H.schema = () => ({ stub: true }); });

  it('builds exactly these mutations, in key order, from each conforming example', () => {
    const calls: Record<string, unknown>[] = [];
    H.conform = (_d: unknown, _v: string, p: Record<string, unknown>) => { calls.push(p); return { ok: true }; };
    runDefTests([D2], CORE_REGISTRY);
    expect(calls[0]).toEqual(EX);
    expect(calls[1]).toEqual(EX);
    expect(calls.slice(2)).toEqual(MUTATIONS.map(([, p]) => p));
    expect(MUTATIONS).toHaveLength(31);
  });
  it('names every accepted mutation once, in order, and fails', () => {
    acceptAll();
    const r = runDefTests([D2], CORE_REGISTRY);
    expect(rt(r)).toEqual({ verb: 'acme.invoice.get', name: 'schema round trip', ok: false, detail: `accepted: ${MUTATIONS.map(([n]) => n).join(', ')}` });
    expect(r.ok).toBe(false);
  });
  it('counts the mutations when every one is refused; a non-conforming example is skipped', () => {
    const only = JSON.stringify(EX);
    H.conform = (_d: unknown, _v: string, p: unknown) => ({ ok: JSON.stringify(p) === only });
    expect(rt(runDefTests([D2], CORE_REGISTRY))).toEqual({ verb: 'acme.invoice.get', name: 'schema round trip', ok: true, detail: '31 mutations refused' });
    const two = { ...D2, examples: [{ params: EX, expect: 'allow' }, { params: { invoice: 'inv_12345678' }, expect: 'deny' }] } as unknown as ActionDef;
    expect(rt(runDefTests([two], CORE_REGISTRY)).detail).toBe('31 mutations refused');
    const reversed = { ...D2, examples: [{ params: { invoice: 'inv_12345678' }, expect: 'deny' }, { params: EX, expect: 'allow' }] } as unknown as ActionDef;
    expect(rt(runDefTests([reversed], CORE_REGISTRY)).detail).toBe('31 mutations refused');
  });
  it('a def without examples skips the round trip', () => {
    expect(rt(runDefTests([READ], CORE_REGISTRY))).toEqual({ verb: 'acme.invoice.get', name: 'schema round trip', ok: true, detail: 'skipped: no examples' });
  });
});

describe('runDefTests: the report', () => {
  const withEx = (examples: unknown[]): ActionDef => ({ ...send, examples }) as unknown as ActionDef;
  it('examples are listed with their expectation, decision and reason, and a failing one fails the report', () => {
    const r = runDefTests([withEx([
      { params: SEND, under: { allow: FULL }, expect: 'allow' },
      { params: SEND, under: { allow: { ...FULL, caveats: ['rate_cap'] } }, expect: 'escalate' },
      { params: SEND, expect: 'allow' },
    ])], CORE_REGISTRY);
    expect(r.examples.slice(0, 2)).toEqual([
      { verb: 'acme.invoice.send', index: 0, expect: 'allow', got: 'allow', ok: true, why: 'floor satisfied' },
      { verb: 'acme.invoice.send', index: 1, expect: 'escalate', got: 'escalate', ok: true, why: 'floor needs resource_scope' },
    ]);
    expect(r.examples[2]).toMatchObject({ verb: 'acme.invoice.send', index: 2, expect: 'allow', got: 'escalate', ok: false });
    expect(need(r.examples[2]!.why)).toEqual(['fresh_revocation', 'rate_cap', 'recipient_scope', 'resource_scope']);
    expect(r.ok).toBe(false);
  });
  it('a pack whose examples and properties all hold is ok; a failing property alone fails it', () => {
    const good = withEx([{ params: SEND, under: { allow: FULL }, expect: 'allow' }]);
    expect(runDefTests([good], CORE_REGISTRY).ok).toBe(true);
    acceptAll();
    const r = runDefTests([good], CORE_REGISTRY);
    expect(r.examples.every((e) => e.ok)).toBe(true);
    expect(r.props.some((q) => q.ok)).toBe(true);
    expect(r.ok).toBe(false);
  });
});

describe('testText', () => {
  it('prints one line per result and a tally', () => {
    const report: TestReport = {
      examples: [
        { verb: 'a.b.c', index: 0, expect: 'allow', got: 'allow', ok: true, why: 'floor satisfied' },
        { verb: 'a.b.c', index: 1, expect: 'allow', got: 'escalate', ok: false, why: 'floor needs x' },
      ],
      props: [
        { verb: 'a.b.c', name: 'n1', ok: true, detail: '' },
        { verb: 'a.b.c', name: 'n2', ok: false, detail: 'd2' },
        { verb: 'a.b.c', name: 'n3', ok: true, detail: 'd3' },
      ],
      ok: false,
    };
    expect(testText(report)).toBe([
      'PASS  a.b.c example 1: expected allow, got allow (floor satisfied)',
      'FAIL  a.b.c example 2: expected allow, got escalate (floor needs x)',
      'PASS  a.b.c n1',
      'FAIL  a.b.c n2: d2',
      'PASS  a.b.c n3: d3',
      '3 passed, 2 failed',
    ].join('\n'));
    expect(testText({ examples: [], props: [], ok: true })).toBe('0 passed, 0 failed');
  });
});
