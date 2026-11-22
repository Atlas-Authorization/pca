import { describe, expect, it } from 'vitest';
import {
  ActionKitError, BUILTIN_DEFS, MAX_AUTHOR_BYTES, action, defaultTitle, expandAction, loadActionsText, loadActionsValue, p, parseParamShorthand, parseResourceShorthand,
  validateDef,
} from '../src';

const thrown = (f: () => unknown): ActionKitError => {
  try {
    f();
  } catch (e) {
    return e as ActionKitError;
  }
  throw new Error('did not throw');
};
const refused = (f: () => unknown, code: string, message: string): void => {
  const e = thrown(f);
  expect(e).toBeInstanceOf(ActionKitError);
  expect([e.code, e.message]).toEqual([code, message]);
};

const HELLO = `
ns: acme
actions:
  - verb: acme.invoice.send
    title: Send an invoice
    effects: [send]
    resource: acme.invoice:inv_*
    params:
      invoice: id:acme.invoice
      to: email
      note: text(500)
`;
const sendEntry = (verb = 'acme.invoice.send'): Record<string, unknown> => ({
  verb, title: 'Send an invoice', effects: ['send'], resource: 'acme.invoice:inv_*', params: { invoice: 'id:acme.invoice', to: 'email', note: 'text(500)' },
});
const base = { verb: 'acme.invoice.send', effects: 'read', resource: 'acme.invoice' };
const PROTO_MSG = "the document contains a '__proto__' member or nests deeper than 40";

describe('param shorthand: exact expansions', () => {
  it('every bare form', () => {
    const t = parseParamShorthand;
    expect(t('email')).toStrictEqual({ type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 });
    expect(t('phone')).toStrictEqual({ type: 'string', role: 'contact.phone', format: 'phone_e164', tags: ['pii'], max_len: 16 });
    expect(t('url')).toStrictEqual({ type: 'string', role: 'url.target', format: 'url', max_len: 2048 });
    expect(t('uuid')).toStrictEqual({ type: 'string', format: 'uuid', max_len: 36 });
    expect(t('ccy')).toStrictEqual({ type: 'string', role: 'money.currency', format: 'iso_currency', max_len: 3 });
    expect(t('country')).toStrictEqual({ type: 'string', format: 'iso_country', max_len: 2 });
    expect(t('secret')).toStrictEqual({ type: 'string', role: 'credential.secret', tags: ['secret'], max_len: 512 });
    expect(t('bool')).toStrictEqual({ type: 'boolean' });
    expect(t('date')).toStrictEqual({ type: 'date' });
    expect(t('datetime')).toStrictEqual({ type: 'datetime' });
    expect(t(' email ')).toStrictEqual(t('email'));
    expect(t('id:acme.x')).toStrictEqual({ type: 'string', role: 'id.acme.x', max_len: 64 });
  });
  it('bounded and unbounded forms', () => {
    const t = parseParamShorthand;
    expect(t('duration')).toStrictEqual({ type: 'duration' });
    expect(t('duration(5000)')).toStrictEqual({ type: 'duration', min: 0, max: 5000 });
    expect(t('text')).toStrictEqual({ type: 'string' });
    expect(t('text(5)?')).toStrictEqual({ type: 'string', max_len: 5, required: false });
    expect(t('string(5)')).toStrictEqual({ type: 'string', max_len: 5 });
    expect(t('message')).toStrictEqual({ type: 'string', role: 'text.message', tags: ['free_text_outbound'], max_len: 1024 });
    expect(t('int')).toStrictEqual({ type: 'integer' });
    expect(t('count')).toStrictEqual({ type: 'integer', role: 'count.limit', min: 1, unit: { kind: 'count' } });
    expect(t('count(9)')).toStrictEqual({ type: 'integer', role: 'count.limit', min: 1, max: 9, unit: { kind: 'count' } });
    expect(t('array(string)')).toStrictEqual({ type: 'array', items: 'string' });
    expect(t('array(integer, min=2, max=5)')).toStrictEqual({ type: 'array', items: 'integer', min_items: 2, max_items: 5 });
    expect(t('array(string, min=0)')).toStrictEqual({ type: 'array', items: 'string', min_items: 0 });
    expect(t('enum(a | b)')).toStrictEqual({ type: 'string', values: ['a', 'b'] });
    expect(t('set(a|b )')).toStrictEqual({ type: 'set', values: ['a', 'b'] });
  });
  it('money forms and argument whitespace', () => {
    const unit = (ccy: unknown, exp = 2) => ({ kind: 'money', ccy, exp });
    expect(parseParamShorthand('money(USD)')).toStrictEqual({ type: 'integer', role: 'money.amount', min: 1, unit: unit('USD'), provenance_min: 'first_party' });
    expect(parseParamShorthand('money( USD , max = 5, )')).toStrictEqual({ type: 'integer', role: 'money.amount', min: 1, max: 5, unit: unit('USD'), provenance_min: 'first_party' });
    expect(parseParamShorthand('money(@c, min=0, exp=3, provenance=agent)')).toStrictEqual({ type: 'integer', role: 'money.amount', min: 0, unit: unit({ from: 'c' }, 3), provenance_min: 'agent' });
  });
  it('a bare `=` is a positional argument, not an option', () => {
    refused(() => parseParamShorthand('text(=5)'), 'bad_shorthand', "text length must be an integer, got '=5'");
  });
  it('refusals carry the exact code and message', () => {
    const tab: [string, string][] = [
      ['text(1,2)', "'text' takes at most 1 positional argument(s)"],
      ['string(1,2)', "'string' takes at most 1 positional argument(s)"],
      ['text(x=1)', "'text' has no option 'x'"],
      ['string(x=1)', "'string' has no option 'x'"],
      ['duration(1,2)', "'duration' takes at most 1 positional argument(s)"],
      ['duration(x=1)', "'duration' has no option 'x'"],
      ['message(1,2)', "'message' takes at most 1 positional argument(s)"],
      ['message(x=1)', "'message' has no option 'x'"],
      ['int(1,2)', "'int' takes at most 1 positional argument(s)"],
      ['int(x=1)', "'int' has no option 'x'"],
      ['count(1,2)', "'count' takes at most 1 positional argument(s)"],
      ['count(x=1)', "'count' has no option 'x'"],
      ['money(USD,EUR)', "'money' takes at most 1 positional argument(s)"],
      ['money(USD, x=1)', "'money' has no option 'x'"],
      ['array(string,integer)', "'array' takes at most 1 positional argument(s)"],
      ['array(string, x=1)', "'array' has no option 'x'"],
      ['text(abc)', "text length must be an integer, got 'abc'"],
      ['string(abc)', "string length must be an integer, got 'abc'"],
      ['text(x12)', "text length must be an integer, got 'x12'"],
      ['text(12x)', "text length must be an integer, got '12x'"],
      ['duration(abc)', "duration max (ms) must be an integer, got 'abc'"],
      ['message(abc)', "message length must be an integer, got 'abc'"],
      ['count(abc)', "count max must be an integer, got 'abc'"],
      ['money(USD, max=abc)', "money max must be an integer, got 'abc'"],
      ['money(USD, min=abc)', "money min must be an integer, got 'abc'"],
      ['money(USD, exp=abc)', "money exp must be an integer, got 'abc'"],
      ['array(string, max=abc)', "array max must be an integer, got 'abc'"],
      ['array(string, min=abc)', "array min must be an integer, got 'abc'"],
      ['money(USD, provenance=nobody)', 'money provenance must be one of first_party, tool, agent'],
      ['money', 'money needs a currency: money(USD) or money(@currency_param)'],
      ['int(5)', 'int takes MIN..MAX, for example int(0..100)'],
      ['int(x1..5)', 'int takes MIN..MAX, for example int(0..100)'],
      ['int(1..5x)', 'int takes MIN..MAX, for example int(0..100)'],
      ['enum', 'enum needs values: enum(a|b|c)'],
      ['set', 'set needs values: set(a|b|c)'],
      ['enum()', "'enum' needs values separated by |"],
      ['enum(a|)', "'enum' needs values separated by |"],
      ['enum(|)', "'enum' needs values separated by |"],
      ['set(a||b)', "'set' needs values separated by |"],
      ['array(float)', 'array(items): items is string or integer'],
      ['nope', "unknown param shorthand 'nope'"],
      ['Nope', "unknown param shorthand 'Nope'"],
      ['1email', "unknown param shorthand '1email'"],
      ['email!', "unknown param shorthand 'email!'"],
      ['id:acme.x(1)', "'id:acme.x' takes no arguments"],
    ];
    for (const n of ['email', 'phone', 'url', 'uuid', 'ccy', 'country', 'secret', 'bool', 'date', 'datetime']) tab.push([`${n}(1)`, `'${n}' takes no arguments`]);
    for (const [s, msg] of tab) refused(() => parseParamShorthand(s), 'bad_shorthand', msg);
  });
});

describe('resource shorthand', () => {
  it('exact outputs at the edges', () => {
    expect(parseResourceShorthand(' acme.invoice ')).toStrictEqual({ type: 'acme.invoice', id: '*', scope: 'tenant' });
    expect(parseResourceShorthand(':foo')).toStrictEqual({ type: '', id: { exact: 'foo' }, scope: 'one' });
    expect(parseResourceShorthand('acme.x:*{hex,1..2}')).toStrictEqual({ type: 'acme.x', id: { prefix: '', class: 'hex', len: [1, 2] }, scope: 'one' });
    expect(parseResourceShorthand('acme.x@set:foo')).toStrictEqual({ type: 'acme.x@set', id: { exact: 'foo' }, scope: 'one' });
  });
  it('refusals carry code and message', () => {
    refused(() => parseResourceShorthand('acme.x@galaxy'), 'bad_shorthand', "unknown resource scope '@galaxy'");
    refused(() => parseResourceShorthand('acme.x:a*{nope,1..2}'), 'bad_shorthand', "resource id 'a*{nope,1..2}': expected prefix*{class,min..max}");
    refused(() => parseResourceShorthand('acme.x:a*z{hex,1..2}'), 'bad_shorthand', "resource id 'a*z{hex,1..2}': expected prefix*{class,min..max}");
    refused(() => parseResourceShorthand('acme.x:a*{hex,1..2}z'), 'bad_shorthand', "resource id 'a*{hex,1..2}z': expected prefix*{class,min..max}");
  });
});

describe('defaultTitle', () => {
  it('joins the action word and its nouns with spaces', () => {
    expect(defaultTitle('a.b.c.d')).toBe('D b c');
    expect(defaultTitle('acme.invoice.send')).toBe('Send invoice');
    expect(defaultTitle('send')).toBe('Send');
  });
});

describe('expandAction', () => {
  it('refusals carry code and message', () => {
    for (const bad of ['x', null, [], 5]) refused(() => expandAction(bad), 'bad_action', 'an action must be an object');
    refused(() => expandAction({ ...base, zzz: 1 }), 'bad_action', "unknown member 'zzz'");
    refused(() => expandAction({ ...base, v: 2 }), 'bad_action', 'unsupported def version');
    refused(() => expandAction({ ...base, kind: 'other' }), 'bad_action', "kind must be 'pca-action-def'");
    refused(() => expandAction({ effects: 'read' }), 'bad_action', 'verb is required');
    refused(() => expandAction({ ...base, verb: 5 }), 'bad_action', 'verb is required');
    refused(() => expandAction({ ...base, params: 'x' }), 'bad_action', 'params must be an object');
    refused(() => expandAction({ ...base, params: ['email'] }), 'bad_action', 'params must be an object');
    refused(() => expandAction({ ...base, blast: 'galaxy' }), 'bad_action', "unknown blast radius 'galaxy'");
    refused(() => expandAction({ ...base, title: 1.5 }), 'bad_action', 'not strict JSON: numbers must be safe integers (no floats, no -0)');
  });
  it('the full form is taken as written', () => {
    const full = { kind: 'pca-action-def', verb: 'acme.invoice.send', effects: ['send'] };
    expect(expandAction(full)).toStrictEqual({ def: { v: 1, ...full }, notes: [] });
    refused(() => expandAction({ ...full, title: 1.5 }), 'bad_action', 'not strict JSON: numbers must be safe integers (no floats, no -0)');
  });
  it('defaults and passthrough members', () => {
    expect(expandAction(base)).toStrictEqual({
      def: { v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send invoice', effects: ['read'], resource: { type: 'acme.invoice', id: '*', scope: 'tenant' }, params: {}, review: { state: 'authored' } },
      notes: [],
    });
    const full = expandAction({
      ...base, aliases: 'a.b.c', description: 'd', side_effects: ['x'], context: 'ctx', traits: 't', audience: 'resource', compensates: 'a.b.c', bindings: { k: 1 }, examples: [{ k: 1 }], source: { k: 1 }, since: '1.0',
    }).def as unknown as Record<string, unknown>;
    expect(full).toMatchObject({
      aliases: ['a.b.c'], description: 'd', side_effects: ['x'], context: ['ctx'], traits: ['t'], audience: 'resource', compensates: 'a.b.c', bindings: { k: 1 }, examples: [{ k: 1 }], source: { k: 1 }, since: '1.0',
    });
    expect(expandAction({ ...base, aliases: ['a.b.c', 'd.e.f'] }).def.aliases).toStrictEqual(['a.b.c', 'd.e.f']);
    expect(expandAction(base, { since: '2.0' }).def.since).toBe('2.0');
    expect(expandAction({ ...base, since: '3.0' }, { since: '2.0' }).def.since).toBe('3.0');
    expect(Object.keys(expandAction(base).def)).not.toContain('since');
  });
  it('an object resource is kept as is; a string blast is wrapped, an object blast is kept', () => {
    const res = { type: 'acme.invoice', id: '*', scope: 'global' };
    expect(expandAction({ ...base, resource: res }).def.resource).toStrictEqual(res);
    expect(expandAction({ ...base, blast: 'tenant' }).def.blast).toStrictEqual({ radius: 'tenant' });
    expect(expandAction({ ...base, blast: { radius: 'one', ppm: 5 } }).def.blast).toStrictEqual({ radius: 'one', ppm: 5 });
    expect(Object.keys(expandAction(base).def)).not.toContain('blast');
  });
  it('idempotency declarations', () => {
    const upd = { ...base, effects: 'update' };
    const keyed = expandAction({ ...upd, idempotency: 'key_param' });
    expect(keyed.def.idempotency).toStrictEqual({ mode: 'key_param', param: 'idempotency_key' });
    expect(keyed.def.params).toStrictEqual({ idempotency_key: { type: 'string', max_len: 64 } });
    expect(keyed.notes).toStrictEqual([]);
    const nat = expandAction({ ...upd, idempotency: 'natural' });
    expect(nat.def.idempotency).toStrictEqual({ mode: 'natural' });
    expect(nat.def.params).toStrictEqual({});
    // an object that names the mode natural, or another key param, never gets idempotency_key
    expect(expandAction({ ...upd, idempotency: { mode: 'natural', param: 'idempotency_key' } }).def.params).toStrictEqual({});
    expect(expandAction({ ...upd, idempotency: { mode: 'key_param', param: 'other' }, params: { other: 'text(5)' } }).def.params).toStrictEqual({ other: { type: 'string', max_len: 5 } });
    // a declared idempotency_key is kept
    expect(expandAction({ ...upd, idempotency: 'key_param', params: { idempotency_key: 'text(9)' } }).def.params).toStrictEqual({ idempotency_key: { type: 'string', max_len: 9 } });
  });
});

describe('loadActionsValue', () => {
  it('top-level refusals', () => {
    const only = (message: string) => ({ defs: [], notes: [], errors: [{ message }], locs: {}, rules: {} });
    expect(loadActionsValue([])).toStrictEqual(only('the document must be an object'));
    expect(loadActionsValue({ ns: 'acme', actions: [], zzz: 1 })).toStrictEqual(only("unknown top-level member 'zzz' (expected ns, since, actions)"));
    expect(loadActionsValue({ ns: 'Acme', actions: [] }).errors).toStrictEqual([{ message: 'ns must be a lowercase identifier' }]);
    expect(loadActionsValue({ ns: 'acme!', actions: [] }).errors).toStrictEqual([{ message: 'ns must be a lowercase identifier' }]);
    expect(loadActionsValue({ ns: 'acme', since: 5, actions: [] }).errors).toStrictEqual([{ message: 'since must be a string' }]);
    expect(loadActionsValue({ ns: 'acme', actions: 'x' }).errors).toStrictEqual([{ message: 'actions must be a list' }]);
  });
  it('a __proto__ member is refused, wherever it is', () => {
    expect(loadActionsValue(JSON.parse('{"ns":"acme","actions":[],"__proto__":{}}')).errors).toStrictEqual([{ message: PROTO_MSG }]);
    expect(loadActionsValue(JSON.parse('{"ns":"acme","actions":[{"verb":"a.b.c","__proto__":1}]}')).errors).toStrictEqual([{ message: PROTO_MSG }]);
  });
  const nest = (m: number, leaf: unknown, arrays = false): unknown => {
    let v = leaf;
    for (let i = 0; i < m; i++) v = arrays ? [v] : { a: v };
    return v;
  };
  const withTitle = (title: unknown) => loadActionsValue({ ns: 'acme', actions: [{ verb: 'acme.invoice.send', title }] });
  it('nesting is refused beyond depth 40 and not at 40 (the title sits at depth 3)', () => {
    const deepJson = [{ index: 0, verb: 'acme.invoice.send', message: 'not strict JSON: nesting deeper than 32' }];
    expect(withTitle(nest(37, 1)).errors).toStrictEqual(deepJson);
    expect(withTitle(nest(38, 1)).errors).toStrictEqual([{ message: PROTO_MSG }]);
    expect(withTitle(nest(37, {})).errors).toStrictEqual(deepJson);
    expect(withTitle(nest(38, {})).errors).toStrictEqual([{ message: PROTO_MSG }]);
    expect(withTitle(nest(37, [])).errors).toStrictEqual(deepJson);
    expect(withTitle(nest(38, [])).errors).toStrictEqual([{ message: PROTO_MSG }]);
    expect(withTitle(nest(37, 1, true)).errors).toStrictEqual(deepJson);
    expect(withTitle(nest(38, 1, true)).errors).toStrictEqual([{ message: PROTO_MSG }]);
  });
  it('a non-object entry is an error, not an exception', () => {
    for (const e of [null, 5]) expect(loadActionsValue({ ns: 'acme', actions: [e] }).errors).toStrictEqual([{ index: 0, message: 'an action must be an object' }]);
    expect(loadActionsValue({ ns: 'acme', actions: [{ verb: 5 }] }).errors).toStrictEqual([{ index: 0, message: 'verb is required' }]);
  });
  it('an unexpected exception inside one entry becomes a malformed-action error', () => {
    const entry = sendEntry();
    let n = 0;
    Object.defineProperty(entry, 'description', { enumerable: true, get() { if (++n > 1) throw new Error('boom'); return 'x'; } });
    const r = loadActionsValue({ ns: 'acme', actions: [entry] });
    expect(r.errors).toStrictEqual([{ index: 0, verb: 'acme.invoice.send', message: 'malformed action: boom' }]);
    expect(r.defs).toStrictEqual([]);
  });
  it('a bad rules block is reported against its action and the def is dropped', () => {
    const r = loadActionsValue({ ns: 'acme', actions: [{ ...sendEntry(), rules: 5 }, sendEntry('acme.invoice.resend')] });
    expect(r.errors).toStrictEqual([{ index: 0, verb: 'acme.invoice.send', message: 'rules must be an object' }]);
    expect(r.defs.map((d) => d.verb)).toStrictEqual(['acme.invoice.resend']);
    expect(r.rules).toStrictEqual({});
  });
  it('doc since reaches the defs; an invalid def is reported with its verb', () => {
    const r = loadActionsValue({ ns: 'acme', since: '1.5', actions: [sendEntry(), { ...sendEntry('acme.invoice.bad'), effects: ['nope'] }] });
    expect(r.defs.map((d) => d.since)).toStrictEqual(['1.5']);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0]).toMatchObject({ index: 1, verb: 'acme.invoice.bad' });
  });
});

describe('loadActionsText', () => {
  const failed = (r: ReturnType<typeof loadActionsText>) => {
    expect(r.defs).toStrictEqual([]);
    expect(r.notes).toStrictEqual([]);
    expect(r.locs).toStrictEqual({});
    expect(r.rules).toStrictEqual({});
    expect(r.errors).toHaveLength(1);
    return r.errors[0]!;
  };
  it('the size limit is inclusive', () => {
    const used = new TextEncoder().encode(HELLO).length;
    const exact = loadActionsText(HELLO + '#'.repeat(MAX_AUTHOR_BYTES - used));
    expect(exact.errors).toStrictEqual([]);
    expect(exact.defs).toHaveLength(1);
    const over = failed(loadActionsText(HELLO + '#'.repeat(MAX_AUTHOR_BYTES - used + 1)));
    expect(over).toStrictEqual({ message: `the file is larger than ${MAX_AUTHOR_BYTES} bytes`, line: 1, column: 1 });
  });
  it('malformed JSON and YAML fail at 1:1', () => {
    const j = failed(loadActionsText('{', 'json'));
    expect(j.message).toMatch(/^not JSON: /);
    expect([j.line, j.column]).toStrictEqual([1, 1]);
    const y = failed(loadActionsText('a: 1\na: 2\n'));
    expect(y.message).toMatch(/^not YAML: /);
    expect(y.message).not.toMatch(/ at line /);
    expect([y.line, y.column]).toStrictEqual([1, 1]);
  });
  it('YAML is parsed strictly: merge keys are plain keys, a 1100 char key is refused', () => {
    const m = loadActionsText('ns: acme\n<<: {x: 1}\nactions: []\n');
    expect(m.errors).toStrictEqual([{ message: "unknown top-level member '<<' (expected ns, since, actions)", line: 1, column: 1 }]);
    const long = failed(loadActionsText(`${'k'.repeat(1100)}: 1\nns: acme\nactions: []\n`));
    expect(long.message).toMatch(/^not YAML: /);
    expect([long.line, long.column]).toStrictEqual([1, 1]);
  });
  it('positions of actions, params and errors (YAML)', () => {
    const text = [
      'ns: acme', 'actions:', '  - verb: acme.invoice.send', '    effects: [send]', '    resource: acme.invoice:inv_*', '    params:', '      to: email', '  - verb: 5', '',
    ].join('\n');
    const r = loadActionsText(text);
    expect(r.defs.map((d) => d.verb)).toStrictEqual(['acme.invoice.send']);
    expect(r.locs).toStrictEqual({ 'acme.invoice.send': { line: 3, column: 5, params: { to: { line: 7, column: 7 } } } });
    expect(r.errors).toStrictEqual([{ index: 1, message: 'verb is required', line: 8, column: 5 }]);
    expect(loadActionsText(HELLO).locs['acme.invoice.send']).toStrictEqual({
      line: 4, column: 5, params: { invoice: { line: 9, column: 7 }, to: { line: 10, column: 7 }, note: { line: 11, column: 7 } },
    });
    // a non-map root has no positions, so its error carries no line/column
    expect(loadActionsText('[1]').errors).toStrictEqual([{ message: 'the document must be an object' }]);
  });
  it('a raw single def (JSON) gets the def position and its param positions', () => {
    const def = BUILTIN_DEFS.find((d) => Object.keys(d.params).length > 0)!;
    const text = JSON.stringify(def, null, 2);
    const lines = text.split('\n');
    const from = lines.indexOf('  "params": {');
    const params: Record<string, { line: number; column: number }> = {};
    for (const name of Object.keys(def.params)) params[name] = { line: lines.findIndex((l, i) => i > from && l === `    ${JSON.stringify(name)}: {`) + 1, column: 5 };
    const r = loadActionsText(text, 'json');
    expect(r.errors).toStrictEqual([]);
    expect(r.locs[def.verb]).toStrictEqual({ line: 1, column: 1, params });
  });
  it('positions come from the first of two duplicate `actions` members while the value is the last', () => {
    const mk = (verb: string) => sendEntry(verb);
    const two = JSON.stringify([mk('acme.invoice.one'), mk('acme.invoice.two')]);
    const three = JSON.stringify([mk('acme.invoice.a'), mk('acme.invoice.b'), mk('acme.invoice.c')]);
    const r3 = loadActionsText(`{"ns":"acme","actions":${two},"actions":${three}}`, 'json');
    expect(r3.errors).toStrictEqual([]);
    expect(r3.defs).toHaveLength(3);
    expect(Object.keys(r3.locs).sort()).toStrictEqual(['acme.invoice.a', 'acme.invoice.b']);
    // no positions at all: defs have no loc, indexed errors carry no line/column
    const r1 = loadActionsText(`{"ns":"acme","actions":[],"actions":${JSON.stringify([mk('acme.invoice.a')])}}`, 'json');
    expect(r1.defs).toHaveLength(1);
    expect(r1.locs).toStrictEqual({});
    const re = loadActionsText('{"ns":"acme","actions":[],"actions":[{"verb":5}]}', 'json');
    expect(re.errors).toStrictEqual([{ index: 0, message: 'verb is required' }]);
  });
});

describe('the TypeScript builder', () => {
  it('param constructors equal their shorthand, extras merge over', () => {
    expect(p.email()).toStrictEqual(parseParamShorthand('email'));
    expect(p.email({ max_len: 10 })).toStrictEqual({ ...parseParamShorthand('email'), max_len: 10 });
    expect(p.duration()).toStrictEqual({ type: 'duration' });
    expect(p.duration(5000)).toStrictEqual({ type: 'duration', min: 0, max: 5000 });
    expect(p.message()).toStrictEqual(parseParamShorthand('message'));
    expect(p.message(300)).toStrictEqual({ type: 'string', role: 'text.message', tags: ['free_text_outbound'], max_len: 300 });
    expect(p.text()).toStrictEqual({ type: 'string' });
    expect(p.text(9)).toStrictEqual({ type: 'string', max_len: 9 });
    expect(p.int()).toStrictEqual({ type: 'integer' });
    expect(p.int(0, 9)).toStrictEqual({ type: 'integer', min: 0, max: 9 });
    expect(p.int(1)).toStrictEqual({ type: 'integer' });
    expect(p.int(undefined, 9)).toStrictEqual({ type: 'integer' });
    expect(p.count()).toStrictEqual({ type: 'integer', role: 'count.limit', min: 1, unit: { kind: 'count' } });
    expect(p.count(7)).toStrictEqual({ type: 'integer', role: 'count.limit', min: 1, max: 7, unit: { kind: 'count' } });
    expect(p.array('string')).toStrictEqual({ type: 'array', items: 'string' });
    expect(p.array('integer', 5)).toStrictEqual({ type: 'array', items: 'integer', max_items: 5 });
    expect(p.id('acme.x')).toStrictEqual({ type: 'string', role: 'id.acme.x', max_len: 64 });
    expect(p.enum(['a', 'b'])).toStrictEqual({ type: 'string', values: ['a', 'b'] });
    expect(p.set(['a', 'b'])).toStrictEqual({ type: 'set', values: ['a', 'b'] });
    expect(p.optional(p.bool())).toStrictEqual({ type: 'boolean', required: false });
  });
  it('money options appear only when given', () => {
    const unit = (ccy: unknown, exp = 2) => ({ kind: 'money', ccy, exp });
    const m = (extra: object) => ({ type: 'integer', role: 'money.amount', provenance_min: 'first_party', ...extra });
    expect(p.money('USD')).toStrictEqual(m({ min: 1, unit: unit('USD') }));
    expect(p.money('USD', { max: 5 })).toStrictEqual(m({ min: 1, max: 5, unit: unit('USD') }));
    expect(p.money('USD', { min: 2 })).toStrictEqual(m({ min: 2, unit: unit('USD') }));
    expect(p.money('USD', { exp: 3 })).toStrictEqual(m({ min: 1, unit: unit('USD', 3) }));
    expect(p.money({ from: 'ccy' }, { max: 9, min: 0, exp: 0 })).toStrictEqual(m({ min: 0, max: 9, unit: unit({ from: 'ccy' }, 0) }));
  });
  it('action() refuses an invalid def with the verb and the validation reason', () => {
    const spec = { effects: 'bogus' as never, resource: 'acme.invoice' };
    const why = validateDef(expandAction({ verb: 'acme.invoice.send', ...spec }).def);
    expect(why).not.toBeNull();
    refused(() => action('acme.invoice.send', spec), 'bad_action', `acme.invoice.send: ${why}`);
    const ok = action('acme.invoice.send', { effects: 'read', resource: 'acme.invoice' });
    expect(ok).toStrictEqual(expandAction(base).def);
  });
});
