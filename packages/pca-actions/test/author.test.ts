import fc from 'fast-check';
import { stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, EFFECTS, MAX_AUTHOR_BYTES, action, defDigest, defaultTitle, expandAction, loadActionsText, loadActionsValue, p, parseParamShorthand, parseResourceShorthand,
  validateDef, type ActionDef, type ActionSpec, type ParamDef,
} from '../src';
import { runs } from './runs';

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

describe('YAML loader: shorthands expand to the strict def', () => {
  it('the hello world expands to the documented defaults', () => {
    const r = loadActionsText(HELLO);
    expect(r.errors).toEqual([]);
    expect(r.ns).toBe('acme');
    expect(r.notes).toEqual([{ verb: 'acme.invoice.send', message: 'idempotency_key auto-added' }]);
    expect(r.defs[0]).toEqual({
      v: 1, kind: 'pca-action-def', verb: 'acme.invoice.send', title: 'Send an invoice', effects: ['send'],
      resource: { type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' },
      params: {
        invoice: { type: 'string', role: 'id.acme.invoice', max_len: 64 },
        to: { type: 'string', role: 'contact.email', format: 'email', tags: ['pii'], max_len: 254 },
        note: { type: 'string', max_len: 500 },
        idempotency_key: { type: 'string', max_len: 64 },
      },
      idempotency: { mode: 'key_param', param: 'idempotency_key' },
      review: { state: 'authored' },
    });
    expect(validateDef(r.defs[0])).toBeNull();
  });
  it('every shorthand form', () => {
    const t = parseParamShorthand;
    expect(t('bool?')).toEqual({ type: 'boolean', required: false });
    expect(t('int(0..100)')).toEqual({ type: 'integer', min: 0, max: 100 });
    expect(t('int(-5..5)')).toEqual({ type: 'integer', min: -5, max: 5 });
    expect(t('int')).toEqual({ type: 'integer' });
    expect(t('count(50)')).toEqual({ type: 'integer', role: 'count.limit', min: 1, max: 50, unit: { kind: 'count' } });
    expect(t('money(USD, max=100000)')).toEqual({ type: 'integer', role: 'money.amount', min: 1, max: 100000, unit: { kind: 'money', ccy: 'USD', exp: 2 }, provenance_min: 'first_party' });
    expect(t('money(@ccy, max=9, min=0, exp=0)')).toEqual({ type: 'integer', role: 'money.amount', min: 0, max: 9, unit: { kind: 'money', ccy: { from: 'ccy' }, exp: 0 }, provenance_min: 'first_party' });
    expect(t('money(USD, max=5, provenance=tool)')).toMatchObject({ provenance_min: 'tool' });
    expect(t('enum(a|b|c)')).toEqual({ type: 'string', values: ['a', 'b', 'c'] });
    expect(t('set(x|y)')).toEqual({ type: 'set', values: ['x', 'y'] });
    expect(t('array(integer, max=5)')).toEqual({ type: 'array', items: 'integer', max_items: 5 });
    expect(t('ccy')).toMatchObject({ role: 'money.currency', format: 'iso_currency' });
    expect(t('secret')).toMatchObject({ role: 'credential.secret', tags: ['secret'] });
    expect(t('message(300)')).toEqual({ type: 'string', role: 'text.message', tags: ['free_text_outbound'], max_len: 300 });
    expect(t('duration(5000)')).toEqual({ type: 'duration', min: 0, max: 5000 });
    expect(t('id:acme.invoice')).toEqual({ type: 'string', role: 'id.acme.invoice', max_len: 64 });
    expect(t('text?')).toEqual({ type: 'string', required: false });
  });
  it('bad shorthands are refused with a reason', () => {
    for (const [s, re] of [['nope', /unknown param shorthand/], ['email(1)', /takes no arguments/], ['int(5)', /MIN\.\.MAX/], ['money', /needs a currency/], ['money(USD, bogus=1)', /no option 'bogus'/], ['money(USD, provenance=nobody)', /provenance must be/], ['enum', /needs values/], ['array(float)', /items is string or integer/], ['text(abc)', /must be an integer/], ['id:Bad', /unknown param shorthand/]] as const) {
      expect(() => parseParamShorthand(s), s).toThrow(re);
    }
  });
  it('resource shorthand', () => {
    expect(parseResourceShorthand('acme.invoice:inv_*')).toEqual({ type: 'acme.invoice', id: { prefix: 'inv_', class: 'alnum', len: [8, 32] }, scope: 'one' });
    expect(parseResourceShorthand('acme.invoice:inv_*{hex,10..20}@set')).toEqual({ type: 'acme.invoice', id: { prefix: 'inv_', class: 'hex', len: [10, 20] }, scope: 'set' });
    expect(parseResourceShorthand('acme.invoice:*')).toEqual({ type: 'acme.invoice', id: '*', scope: 'set' });
    expect(parseResourceShorthand('acme.invoice')).toEqual({ type: 'acme.invoice', id: '*', scope: 'tenant' });
    expect(parseResourceShorthand('acme.config:main')).toEqual({ type: 'acme.config', id: { exact: 'main' }, scope: 'one' });
    expect(parseResourceShorthand('acme.invoice:*@one')).toEqual({ type: 'acme.invoice', id: '*', scope: 'one' });
    expect(() => parseResourceShorthand('acme.x:a*{nope,1..2}')).toThrow(/expected prefix/);
    expect(() => parseResourceShorthand('acme.x@galaxy')).toThrow(/unknown resource scope/);
  });
  it('idempotency: auto-added for repeat-unsafe effects, respected when declared, never for a read', () => {
    const run = (e: Record<string, unknown>) => expandAction({ verb: 'acme.a.b', resource: 'acme.a', effects: 'update', ...e });
    expect(run({ effects: 'read' }).def.idempotency).toBeUndefined();
    expect(run({ effects: 'update' }).def.idempotency).toBeUndefined();
    expect(run({ effects: ['create'] }).def.idempotency).toEqual({ mode: 'key_param', param: 'idempotency_key' });
    expect(run({ effects: ['pay'], idempotency: 'none' }).def.idempotency).toEqual({ mode: 'none' });
    expect(run({ effects: ['send'], idempotency: 'natural' }).def.idempotency).toEqual({ mode: 'natural' });
    const own = run({ effects: ['send'], params: { idempotency_key: 'text(40)' } });
    expect(own.def.params.idempotency_key).toEqual({ type: 'string', max_len: 40 });
  });
  it('title defaults, scalar effects, file-level since, review default', () => {
    expect(defaultTitle('acme.invoice.send')).toBe('Send invoice');
    expect(defaultTitle('acme.customer.address.update')).toBe('Update customer address');
    const r = loadActionsText('ns: acme\nsince: 1.2.3\nactions:\n  - {verb: acme.a.get, effects: read, resource: "acme.a:x"}\n');
    expect(r.errors).toEqual([]);
    expect(r.defs[0]).toMatchObject({ title: 'Get a', effects: ['read'], since: '1.2.3', review: { state: 'authored' } });
  });
  it('the full form is taken exactly as written (no shorthands, no defaults)', () => {
    const full = loadActionsText(HELLO).defs[0]!;
    const { idempotency: _i, ...noIdem } = full;
    void _i;
    const r = loadActionsText(JSON.stringify({ ns: 'acme', actions: [noIdem] }), 'json');
    expect(r.errors).toEqual([]);
    expect(r.defs[0]).toEqual(noIdem);
    expect(r.notes).toEqual([]);
    const s = loadActionsText(JSON.stringify({ ns: 'acme', actions: [{ ...noIdem, params: { to: 'email' } }] }), 'json');
    expect(s.errors[0]!.message).toMatch(/declaration must be an object/);
  });
  it('errors point at the action and never throw', () => {
    const r = loadActionsText('ns: acme\nactions:\n  - {verb: acme.a.get, effects: [read], resource: "acme.a:x"}\n  - {verb: acme.a.put, effects: [teleport], resource: "acme.a:x"}\n  - {verb: acme.a.zap, title: t, bogus: 1}\n  - 7\n');
    expect(r.defs).toHaveLength(1);
    expect(r.errors.map((e) => [e.index, e.verb])).toEqual([[1, 'acme.a.put'], [2, 'acme.a.zap'], [3, undefined]]);
    expect(r.errors[1]!.message).toMatch(/unknown member 'bogus'/);
  });
});

describe('YAML loader: source positions', () => {
  it('actions and params carry their 1-based line and column; errors point at the entry', () => {
    const r = loadActionsText('ns: acme\nactions:\n  - verb: acme.a.get\n    effects: read\n    resource: acme.a\n    params:\n      x: int(0..1)\n      yy: bool\n  - {verb: acme.a.put, effects: [teleport], resource: "acme.a"}\n');
    expect(r.locs['acme.a.get']).toEqual({ line: 3, column: 5, params: { x: { line: 7, column: 7 }, yy: { line: 8, column: 7 } } });
    expect(r.errors[0]).toMatchObject({ index: 1, line: 9, column: 5 });
    expect(r.defs.map((d) => d.verb)).toEqual(['acme.a.get']);
  });
  it('positions follow the right entry when an earlier one failed, and work for JSON', () => {
    const r = loadActionsText('ns: acme\nactions:\n  - {verb: acme.a.put, effects: [teleport], resource: "acme.a"}\n  - {verb: acme.a.get, effects: read, resource: "acme.a"}\n');
    expect(r.locs['acme.a.get']).toMatchObject({ line: 4, column: 5 });
    const j = loadActionsText('{\n "ns": "acme",\n "actions": [\n  {"verb": "acme.a.get", "effects": "read", "resource": "acme.a"}\n ]\n}', 'json');
    expect(j.locs['acme.a.get']).toMatchObject({ line: 4, column: 3 });
  });
  it('a syntax error and a file-level error have a position', () => {
    expect(loadActionsText('ns: acme\nactions: [\n').errors[0]).toMatchObject({ line: expect.any(Number) });
    expect(loadActionsText('actions: []\n').errors[0]).toMatchObject({ line: 1, column: 1 });
  });
});

describe('YAML loader: hostile input', () => {
  const bad = (text: string, re: RegExp, format: 'yaml' | 'json' = 'yaml') => {
    const r = loadActionsText(text, format);
    expect(r.defs).toEqual([]);
    expect(r.errors[0]!.message, text).toMatch(re);
  };
  it('refuses aliases and anchors (no entity expansion), merge keys, duplicate keys and unknown tags', () => {
    bad('ns: acme\nx: &a [1]\nactions: *a\n', /alias|anchor|not YAML/i);
    bad('ns: acme\nactions:\n  - &base {verb: acme.a.b}\n  - <<: *base\n', /alias|anchor|not YAML/i);
    bad('ns: acme\nns: other\nactions: []\n', /not YAML|duplicate|unique/i);
    bad('ns: acme\nactions: !!binary AAAA\n', /list|tag|warning|not YAML/i);
    bad('ns: acme\nsince: !!binary AAAA\nactions: []\n', /since must|tag|warning|not YAML|JSON/i);
    bad('ns: acme\nactions: !foo []\n', /tag|warning|not YAML/i);
  });
  it('a billion-laughs document is refused quickly', () => {
    const lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]'];
    for (let i = 1; i < 9; i++) lines.push(`${String.fromCharCode(97 + i)}: &${String.fromCharCode(97 + i)} [${Array(9).fill(`*${String.fromCharCode(96 + i)}`).join(',')}]`);
    const t0 = Date.now();
    bad(`ns: acme\n${lines.join('\n')}\nactions: []\n`, /alias|anchor|not YAML/i);
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it("refuses a '__proto__' member anywhere, in YAML and in JSON", () => {
    bad('ns: acme\nactions:\n  - verb: acme.a.b\n    params: {__proto__: {type: boolean}}\n', /__proto__/);
    bad('{"ns":"acme","actions":[],"__proto__":{"x":1}}', /__proto__/, 'json');
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
  it('refuses floats, non-NFC and lone surrogates (strict JSON profile)', () => {
    bad('ns: acme\nactions:\n  - {verb: acme.a.b, effects: [read], resource: "acme.a:x", params: {n: {type: integer, min: 1.5, max: 3}}}\n', /safe integers/);
    bad(`ns: acme\nactions:\n  - {verb: acme.a.b, title: "é", effects: [read], resource: "acme.a:x"}\n`, /NFC/);
  });
  it('refuses unknown top-level members, a missing ns, non-list actions and non-objects', () => {
    bad('ns: acme\nextra: 1\nactions: []\n', /unknown top-level member 'extra'/);
    bad('actions: []\n', /ns must be/);
    bad('ns: Acme!\nactions: []\n', /ns must be/);
    bad('ns: acme\nactions: {}\n', /actions must be a list/);
    bad('- 1\n', /must be an object/);
    bad('', /must be an object/);
    bad('{not json', /not JSON/, 'json');
  });
  it('refuses a file above the size limit', () => {
    bad('ns: acme\n# ' + 'x'.repeat(MAX_AUTHOR_BYTES) + '\nactions: []\n', /larger than/);
  });
  it('deep nesting does not crash the loader', () => {
    bad('ns: acme\nactions: ' + '['.repeat(60) + ']'.repeat(60) + '\n', /nests deeper|actions must|not YAML|must be an object|ns must/);
  });
});

// ---- one action, one digest, whichever way it is written ------------------------------------------------------------------------

type Form = { src: string; build: () => ParamDef };
const arbForm: fc.Arbitrary<Form> = fc.oneof(
  fc.constantFrom<Form>(
    { src: 'email', build: () => p.email() }, { src: 'phone', build: () => p.phone() }, { src: 'url', build: () => p.url() }, { src: 'uuid', build: () => p.uuid() },
    { src: 'ccy', build: () => p.ccy() }, { src: 'country', build: () => p.country() }, { src: 'secret', build: () => p.secret() }, { src: 'bool', build: () => p.bool() },
    { src: 'date', build: () => p.date() }, { src: 'datetime', build: () => p.datetime() }, { src: 'text', build: () => p.text() }, { src: 'int', build: () => p.int() },
  ),
  fc.integer({ min: 1, max: 4000 }).map((n): Form => ({ src: `text(${n})`, build: () => p.text(n) })),
  fc.integer({ min: 1, max: 4000 }).map((n): Form => ({ src: `message(${n})`, build: () => p.message(n) })),
  fc.tuple(fc.integer({ min: -1000, max: 1000 }), fc.integer({ min: 0, max: 1000 })).map(([a, w]): Form => ({ src: `int(${a}..${a + w})`, build: () => p.int(a, a + w) })),
  fc.integer({ min: 1, max: 500 }).map((n): Form => ({ src: `count(${n})`, build: () => p.count(n) })),
  fc.integer({ min: 1, max: 99999 }).map((n): Form => ({ src: `money(USD, max=${n})`, build: () => p.money('USD', { max: n }) })),
  fc.integer({ min: 1, max: 99999 }).map((n): Form => ({ src: `duration(${n})`, build: () => p.duration(n) })),
  fc.uniqueArray(fc.constantFrom('a', 'b', 'c', 'd'), { minLength: 1, maxLength: 4 }).map((vs): Form => ({ src: `enum(${vs.join('|')})`, build: () => p.enum(vs) })),
  fc.uniqueArray(fc.constantFrom('a', 'b', 'c', 'd'), { minLength: 1, maxLength: 4 }).map((vs): Form => ({ src: `set(${vs.join('|')})`, build: () => p.set(vs) })),
  fc.integer({ min: 1, max: 50 }).map((n): Form => ({ src: `array(string, max=${n})`, build: () => p.array('string', n) })),
  fc.constantFrom('invoice', 'customer.record').map((t): Form => ({ src: `id:acme.${t}`, build: () => p.id(`acme.${t}`) })),
);
const arbSpec = fc.record({
  noun: fc.constantFrom('invoice', 'order', 'customer'),
  action: fc.constantFrom('send', 'get', 'refund', 'delete', 'update'),
  effects: fc.uniqueArray(fc.constantFrom(...EFFECTS), { minLength: 1, maxLength: 3 }),
  forms: fc.array(fc.tuple(fc.boolean(), arbForm), { maxLength: 6 }),
  title: fc.option(fc.constantFrom('Do a thing', 'Send it'), { nil: undefined }),
  blast: fc.option(fc.constantFrom('one', 'bounded', 'tenant', 'global'), { nil: undefined }),
  idem: fc.option(fc.constantFrom('natural', 'none', 'key_param'), { nil: undefined }),
  since: fc.option(fc.constant('0.1.0'), { nil: undefined }),
  resource: fc.constantFrom('acme.x:x_*', 'acme.x:*', 'acme.x', 'acme.x:y_*{hex,8..16}@set'),
});

describe('one action has one digest across authoring forms', () => {
  it('builder == YAML == JSON == full def for generated actions', () => {
    let accepted = 0;
    fc.assert(fc.property(arbSpec, (g) => {
      const verb = `acme.${g.noun}.${g.action}`;
      const shorthand: Record<string, unknown> = {};
      const built: Record<string, ParamDef> = {};
      g.forms.forEach(([opt, f], i) => {
        shorthand[`p${i}`] = opt ? `${f.src}?` : f.src;
        built[`p${i}`] = opt ? p.optional(f.build()) : f.build();
      });
      const common = { effects: g.effects, resource: g.resource, ...(g.title ? { title: g.title } : {}), ...(g.blast ? { blast: g.blast } : {}), ...(g.idem ? { idempotency: g.idem } : {}), ...(g.since ? { since: g.since } : {}) };
      const spec = { verb, ...common, params: shorthand };
      const viaYaml = loadActionsText(stringify({ ns: 'acme', actions: [spec] }), 'yaml');
      const viaJson = loadActionsText(JSON.stringify({ ns: 'acme', actions: [spec] }), 'json');
      if (viaYaml.errors.length > 0) {
        // a combination the strict def refuses: every form must refuse it alike
        let threw = false;
        try { action(verb, { ...(common as unknown as ActionSpec), params: built }); } catch (e) { threw = e instanceof ActionKitError; }
        return viaJson.errors.length > 0 && threw;
      }
      accepted++;
      const def = viaYaml.defs[0]!;
      const viaBuilder = action(verb, { ...(common as unknown as ActionSpec), params: built });
      const viaFull = loadActionsText(JSON.stringify(def), 'json');
      return (
        viaJson.errors.length === 0 && viaFull.errors.length === 0 &&
        defDigest(viaJson.defs[0]!) === defDigest(def) && defDigest(viaBuilder) === defDigest(def) && defDigest(viaFull.defs[0]!) === defDigest(def) &&
        JSON.stringify(viaBuilder) === JSON.stringify(def)
      );
    }), { seed: 4201, numRuns: runs(200) });
    expect(accepted).toBeGreaterThanOrEqual(Math.floor(runs(200) / 4));
  });
  it('the builder of the hello world has the digest of the YAML hello world', () => {
    const y = loadActionsText(HELLO).defs[0]!;
    const b = action('acme.invoice.send', { title: 'Send an invoice', effects: ['send'], resource: 'acme.invoice:inv_*', params: { invoice: p.id('acme.invoice'), to: p.email(), note: p.text(500) } });
    expect(defDigest(b)).toBe(defDigest(y));
    expect(b).toEqual(y);
  });
  it('the builder throws a typed error for a malformed spec', () => {
    expect(() => action('bad', { effects: ['read'], resource: 'a.b' })).toThrow(ActionKitError);
    expect(() => action('acme.a.b', { effects: ['read'], resource: 'acme.a', params: { x: 'nonsense' } })).toThrow(/unknown param shorthand/);
  });
  it('loadActionsValue takes an already parsed document', () => {
    expect(loadActionsValue({ ns: 'acme', actions: [{ verb: 'acme.a.get', effects: 'read', resource: 'acme.a' }] }).defs).toHaveLength(1);
    expect(loadActionsValue(null).errors[0]!.message).toMatch(/must be an object/);
  });
});

describe('the loader result is a valid def', () => {
  it('every loaded def passes validateDef and is not shared with the input', () => {
    const spec = { ns: 'acme', actions: [{ verb: 'acme.a.get', effects: ['read'], resource: 'acme.a', params: { a: 'int(0..1)' } }] };
    const r = loadActionsValue(spec);
    expect(validateDef(r.defs[0])).toBeNull();
    (r.defs[0] as ActionDef).params.a!.max = 99;
    expect(spec.actions[0]!.params.a).toBe('int(0..1)');
  });
});
