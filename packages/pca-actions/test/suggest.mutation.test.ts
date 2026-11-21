// @ts-nocheck
// Behaviour tests for the suggestion layer: rule-set validation messages, signed rule sets, the stemmer, the facts a def
// yields, rule matching, suggestion union and applying a suggestion. Exact outputs, boundaries on both sides.
import { canonicalBytesStrict, generateKeyPair, utf8, verifyB64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { ActionKitError, PARAM_TAGS } from '../src/def';
import { tokensOf } from '../src/import/common';
import {
  SUGGEST_RULES_DOMAIN, applySuggestion, factsOf, sealRules, signRules, stem, suggestRulesError, suggestWithRules, unionSuggestions, verifyRules,
} from '../src/import/suggest';

const R = (over = {}) => ({ id: 'SR-001', match: { name_tokens: ['refund'] }, adds: ['pca.bulk'], note: 'n', ...over });
const doc = (rules: unknown, over = {}) => ({ v: 1, kind: 'pca-suggest-rules', version: '1.0.0', rules, ...over });
const err = (over = {}, known?: Set<string>) => suggestRulesError(doc([R(over)]), known);
const rs = (...rules) => doc(rules);
const rule = (id: string, match: unknown, adds: string[] = ['pca.bulk']) => ({ id, match, adds, note: 'n' });

describe('suggestRulesError messages and boundaries', () => {
  it('top level shape', () => {
    for (const bad of [null, [], 'x', 5]) expect(suggestRulesError(bad)).toBe('rules must be an object');
    expect(suggestRulesError(doc([R()], { extra: 1 }))).toBe("unknown member 'extra'");
    expect(suggestRulesError(doc([R()], { digest: 'd', sig: { alg: 'ed25519' } }))).toBeNull();
    expect(suggestRulesError(doc([R()]))).toBeNull();
    expect(suggestRulesError(doc([R()], { v: 2 }))).toBe('not a suggest-rules document (v 1)');
    expect(suggestRulesError(doc([R()], { kind: 'other' }))).toBe('not a suggest-rules document (v 1)');
    expect(suggestRulesError({ ...doc([R()]), v: 2, kind: 'other' })).toBe('not a suggest-rules document (v 1)');
  });
  it('version must be semver, anchored, with multi-digit parts', () => {
    for (const v of [1, '1', '1.0', '1.0.0x', 'x1.0.0', '1.0.x', '1.x.0', '1.0.0.0']) expect(suggestRulesError(doc([R()], { version: v })), String(v)).toBe('version must be semver');
    for (const v of ['10.20.30', '0.0.0', '1.12.0', '1.0.12']) expect(suggestRulesError(doc([R()], { version: v })), v).toBeNull();
  });
  it('rule count is 1..1024', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => R({ id: `SR-${1000 + i}` }));
    expect(suggestRulesError(doc([]))).toBe('rules must be 1..1024 entries');
    expect(suggestRulesError(doc('x'))).toBe('rules must be 1..1024 entries');
    expect(suggestRulesError(doc(many(1025)))).toBe('rules must be 1..1024 entries');
    expect(suggestRulesError(doc(many(1024)))).toBeNull();
    expect(suggestRulesError(doc(many(1)))).toBeNull();
  });
  it('a rule is a closed object with a unique SR id', () => {
    for (const bad of [null, [], 'x', 5]) expect(suggestRulesError(doc([bad]))).toBe('a rule must be an object');
    expect(err({ zzz: 1 })).toBe("rule: unknown member 'zzz'");
    for (const id of [undefined, 5, 'SR-1', 'SR-12345', 'sr-001', 'SR-001x', 'xSR-001', 'SR-00a']) expect(err({ id }), String(id)).toBe('rule ids must be unique SR-nnn');
    expect(err({ id: 'SR-123' })).toBeNull();
    expect(err({ id: 'SR-1234' })).toBeNull();
    expect(suggestRulesError(doc([R(), R()]))).toBe('rule ids must be unique SR-nnn');
    expect(suggestRulesError(doc([R(), R({ id: 'SR-002' })]))).toBeNull();
    expect(suggestRulesError(doc([R(), R({ id: 'SR-002', note: '' })]))).toBe('SR-002: note must be 1..200 characters');
  });
  it('note is 1..200 characters', () => {
    for (const note of [undefined, 5, '', 'x'.repeat(201)]) expect(err({ note })).toBe('SR-001: note must be 1..200 characters');
    expect(err({ note: 'x'.repeat(200) })).toBeNull();
    expect(err({ note: 'x' })).toBeNull();
  });
  it('match is a non-empty object with known members', () => {
    for (const match of [null, undefined, [], {}, 'x', 5]) expect(err({ match }), String(match)).toBe('SR-001: match must be a non-empty object');
    expect(err({ match: { bogus: ['x'] } })).toBe("SR-001: unknown match member 'bogus'");
    expect(err({
      match: {
        methods: ['GET'], path_re: '^/a', name_tokens: ['a'], name_tokens_strict: ['a'], param_names: ['a'], param_names_all: ['a'], param_types: ['string'],
        param_formats: ['email'], roles: ['money.amount'], effects: ['create'],
      },
    })).toBeNull();
  });
  it('string lists are 1..64 entries of 1..64 characters', () => {
    for (const k of ['methods', 'name_tokens', 'name_tokens_strict', 'param_names', 'param_names_all', 'param_formats', 'roles']) {
      const msg = `SR-001: match.${k} must be 1..64 short strings`;
      for (const bad of [[], 'GET', [''], [1], [{ length: 3 }], ['GET', ''], ['GET', 1], Array(65).fill('GET'), ['X'.repeat(65)]]) expect(err({ match: { [k]: bad } }), `${k} ${JSON.stringify(bad)}`).toBe(msg);
      expect(err({ match: { [k]: Array(64).fill('GET') } }), k).toBeNull();
      expect(err({ match: { [k]: ['X'.repeat(64)] } }), k).toBeNull();
      expect(err({ match: { [k]: ['GET'] } }), k).toBeNull();
    }
  });
  it('methods are uppercase, all of them', () => {
    expect(err({ match: { methods: ['get'] } })).toBe('SR-001: methods are uppercase');
    expect(err({ match: { methods: ['GET', 'post'] } })).toBe('SR-001: methods are uppercase');
    expect(err({ match: { methods: ['GET', 'POST'] } })).toBeNull();
  });
  it('param_types is a list of the nine param types and needs a name or format matcher', () => {
    const msg = 'SR-001: match.param_types is not a list of param types';
    for (const bad of [[], 'string', ['bogus'], ['string', 'bogus'], ['string', ''], [1], Array(65).fill('string')]) expect(err({ match: { param_names: ['a'], param_types: bad } }), JSON.stringify(bad)).toBe(msg);
    for (const t of ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref']) expect(err({ match: { param_names: ['a'], param_types: [t] } }), t).toBeNull();
    expect(err({ match: { param_names: ['a'], param_types: ['string', 'integer', 'set'] } })).toBeNull();
    const needs = 'SR-001: param_types needs param_names, param_names_all or param_formats';
    expect(err({ match: { param_types: ['string'] } })).toBe(needs);
    expect(err({ match: { param_types: ['string'], name_tokens: ['a'] } })).toBe(needs);
    expect(err({ match: { param_types: ['string'], param_names: ['a'] } })).toBeNull();
    expect(err({ match: { param_types: ['string'], param_names_all: ['a'] } })).toBeNull();
    expect(err({ match: { param_types: ['string'], param_formats: ['email'] } })).toBeNull();
  });
  it('effects is 1..12 short strings', () => {
    const msg = 'SR-001: match.effects must be a list of effects';
    for (const bad of [[], 'create', [''], Array(13).fill('create')]) expect(err({ match: { effects: bad } }), JSON.stringify(bad)).toBe(msg);
    expect(err({ match: { effects: Array(12).fill('create') } })).toBeNull();
  });
  it('path_re: length, bounded subset, and well formed', () => {
    const len = 'SR-001: path_re must be 1..128 characters';
    for (const bad of [5, '', 'a'.repeat(129)]) expect(err({ match: { path_re: bad } }), String(bad)).toBe(len);
    expect(err({ match: { path_re: 'a'.repeat(128) } })).toBeNull();
    expect(err({ match: { path_re: 'a' } })).toBeNull();
    const bounded = 'SR-001: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)';
    for (const re of ['(a+)+', '(a*)+', '(a+)*', '(a+){2}', '(a|b)*', '(a|b)+', '(a|b){2}', '(a)\\1', '\\9', '(a)(b)\\2', '(?=a)', '(?!a)', '(?<=a)b', '(?<!a)b', '(?<n>a)']) expect(err({ match: { path_re: re } }), re).toBe(bounded);
    for (const re of ['(', '[', 'a{2,1}']) expect(err({ match: { path_re: re } }), re).toBe('SR-001: path_re is not a regular expression');
    for (const re of ['^/v[0-9]+/(a|b)$', '(?:a)b', '\\0', '(a)b+']) expect(err({ match: { path_re: re } }), re).toBeNull();
  });
  it('adds is 1..16 entries', () => {
    const msg = 'SR-001: adds must be 1..16 entries';
    for (const adds of [undefined, [], 'pca.bulk', [''], ['x'.repeat(65)], Array(17).fill('pca.bulk')]) expect(err({ adds }), JSON.stringify(adds)).toBe(msg);
    expect(err({ adds: Array(16).fill('pca.bulk') })).toBeNull();
  });
  it('tags, roles and traits in adds', () => {
    expect(err({ match: { param_names: ['a'] }, adds: ['tag:bogus'] })).toBe("SR-001: unknown tag 'tag:bogus'");
    expect(err({ match: { param_names: ['a'] }, adds: ['tag:'] })).toBe("SR-001: unknown tag 'tag:'");
    for (const t of PARAM_TAGS) expect(err({ match: { param_names: ['a'] }, adds: [`tag:${t}`] }), t).toBeNull();
    expect(err({ match: { name_tokens: ['x'] }, adds: ['tag:pii'] })).toBe('SR-001: a tag needs a param matcher');
    for (const adds of [['money.amount'], ['id.user'], ['x.acme.thing']]) expect(err({ match: { name_tokens: ['x'] }, adds }), adds[0]).toBe('SR-001: a role needs a param matcher');
    for (const match of [{ param_names: ['a'] }, { param_names_all: ['a'] }, { param_formats: ['email'] }, { roles: ['money.amount'] }]) {
      expect(err({ match, adds: ['tag:pii'] }), JSON.stringify(match)).toBeNull();
      expect(err({ match, adds: ['money.amount'] }), JSON.stringify(match)).toBeNull();
    }
    expect(err({ match: { param_types: ['string'], param_names: ['a'] }, adds: ['tag:pii'] })).toBeNull();
    expect(err({ adds: ['acme.thing'] })).toBeNull();
    expect(err({ adds: ['acme.thing'] }, new Set(['pca.bulk']))).toBe("SR-001: unknown trait 'acme.thing'");
    expect(err({ adds: ['acme.thing'] }, new Set(['acme.thing']))).toBeNull();
    expect(err({ adds: ['nonsense'] })).toBe("SR-001: 'nonsense' is not a trait, role or tag:");
    expect(err({ adds: ['Pca.bulk'] })).toBe("SR-001: 'Pca.bulk' is not a trait, role or tag:");
  });
});

describe('signed rule sets, byte exact', () => {
  const kp = generateKeyPair();
  const pk = Buffer.from(kp.publicKey).toString('base64url');
  const valid = () => doc([R()]);
  it('signRules signs the domain-separated digest and names the algorithm and key', () => {
    const signed = signRules(valid(), 'rules-1', kp.secretKey);
    expect(signed.sig.alg).toBe('ed25519');
    expect(signed.sig.kid).toBe('rules-1');
    expect(signed.digest).toBe(sealRules(valid()).digest);
    const dom = utf8(SUGGEST_RULES_DOMAIN + '\0');
    const body = canonicalBytesStrict({ digest: signed.digest });
    const msg = new Uint8Array(dom.length + body.length);
    msg.set(dom);
    msg.set(body, dom.length);
    expect(verifyB64u(pk, msg, signed.sig.value)).toBe(true);
    expect(verifyB64u(pk, body, signed.sig.value)).toBe(false);
    expect(verifyB64u(pk, dom, signed.sig.value)).toBe(false);
    expect(verifyRules(signed, [{ kid: 'rules-1', pk }])).toEqual({ ok: true });
  });
  it('signRules refuses a malformed set with code bad_rules and the reason', () => {
    let caught: unknown;
    try { signRules(doc([]), 'k', kp.secretKey); } catch (e) { caught = e; }
    expect(caught).toBeInstanceOf(ActionKitError);
    expect(caught.code).toBe('bad_rules');
    expect(caught.message).toBe('rules must be 1..1024 entries');
  });
  it('verifyRules reports the exact reason for every failure and never throws', () => {
    const signed = signRules(valid(), 'rules-1', kp.secretKey);
    expect(verifyRules(doc([]), [{ kid: 'rules-1', pk }])).toEqual({ ok: false, reason: 'rules must be 1..1024 entries' });
    expect(verifyRules(signed, [{ kid: 'other', pk }])).toEqual({ ok: false, reason: "no pinned rules key 'rules-1'" });
    expect(verifyRules(signed, [])).toEqual({ ok: false, reason: "no pinned rules key 'rules-1'" });
    expect(verifyRules({ ...signed, digest: 'x' }, [{ kid: 'rules-1', pk }])).toEqual({ ok: false, reason: 'digest does not match the rules' });
    expect(verifyRules(sealRules(valid()), [{ kid: 'rules-1', pk }])).toEqual({ ok: false, reason: 'the rule set is not signed' });
    const other = Buffer.from(generateKeyPair().publicKey).toString('base64url');
    expect(verifyRules(signed, [{ kid: 'rules-1', pk: other }])).toEqual({ ok: false, reason: 'rules signature invalid' });
    const boom = { ...signed };
    Object.defineProperty(boom, 'version', { enumerable: true, get() { throw new Error('boom'); } });
    expect(verifyRules(boom, [{ kid: 'rules-1', pk }])).toEqual({ ok: false, reason: 'rules verification error: boom' });
  });
});

describe('stem', () => {
  it('exact outputs at every length boundary', () => {
    const table: [string, string][] = [
      ['ies', 'ies'], ['bies', 'bie'], ['cries', 'cry'], ['policies', 'policy'],
      ['axes', 'axe'], ['axe', 'axe'], ['the', 'the'], ['taxes', 'tax'], ['boxes', 'box'], ['buzzes', 'buzz'], ['batches', 'batch'], ['dishes', 'dish'], ['passes', 'pass'],
      ['taxesx', 'taxesx'], ['process', 'process'], ['processes', 'process'], ['sms', 'sms'], ['keys', 'key'], ['items', 'item'],
      ['ing', 'ing'], ['bring', 'bring'], ['sending', 'send'], ['charging', 'charg'],
      ['ed', 'ed'], ['seed', 'seed'], ['charged', 'charg'], ['charges', 'charg'], ['charge', 'charg'],
    ];
    for (const [a, b] of table) expect(stem(a), a).toBe(b);
  });
});

describe('factsOf', () => {
  const mk = (over) => ({
    v: 1, kind: 'pca-action-def', verb: 'acme.thing.go', title: 'Go', effects: ['create'], resource: { type: 'acme.t', id: '*', scope: 'one' }, params: {}, review: { state: 'unreviewed' }, ...over,
  });
  const S = (a: string[]) => a.map(stem);
  const join = (srcs: string[][]) => srcs.flatMap((s, i) => (i ? ['|', ...S(s)] : S(s)));
  it('collects methods, locations, tokens, strict tokens and params from every binding kind', () => {
    const f = factsOf(mk({
      verb: 'acme.refund.create', aliases: ['payout_money'], title: 'Pay Out', effects: ['create', 'update'],
      params: { zeta: { type: 'string', format: 'email', role: 'contact.email' }, alpha: { type: 'integer' }, mid_two: { type: 'boolean' } },
      bindings: {
        openapi: { operationId: 'createRefund', method: 'post', path: '/v1/{id}/refunds' }, http: { method: 'put', path: '/h/items/{x}' }, mcp: { tool: 'do_thing' },
        graphql: { op: 'mutation', field: 'doIt' }, grpc: { service: 'Pay.Svc', method: 'Charge' }, asyncapi: { channel: 'q.events', op: 'send' },
      },
    }));
    expect(f.methods).toEqual(new Set(['POST', 'PUT', 'MUTATION', 'SEND']));
    expect(f.locs).toEqual(['/v1/{id}/refunds', '/h/items/{x}', 'do_thing', 'doIt', 'Pay.Svc/Charge', 'q.events']);
    const srcs = [['refund', 'create'], ['payout', 'money'], ['pay', 'out'], ['create', 'refund'], ['v1', 'refunds'], ['h', 'items'], ['do', 'thing'], ['do', 'it'], ['pay', 'svc'], ['charge'], ['q', 'events']];
    expect(f.tokens).toEqual(join(srcs));
    expect(f.strict).toEqual(join(srcs.filter((_, i) => i !== 4 && i !== 5)));
    expect(f.params).toStrictEqual([
      { name: 'alpha', tokens: ['alpha'], type: 'integer' },
      { name: 'mid_two', tokens: ['mid', 'two'], type: 'boolean' },
      { name: 'zeta', tokens: ['zeta'], type: 'string', format: 'email', role: 'contact.email' },
    ]);
    expect(f.effects).toEqual(new Set(['create', 'update']));
  });
  it('an empty first source adds no separator; a bare openapi operation adds no method or location', () => {
    const f = factsOf(mk({ verb: 'acme', title: 'Go', bindings: { openapi: { operationId: 'doThing' } } }));
    expect(f.tokens).toEqual(['go', '|', 'do', 'thing']);
    expect(f.strict).toEqual(['go', '|', 'do', 'thing']);
    expect(f.locs).toEqual([]);
    expect(f.methods).toEqual(new Set());
    expect(f.params).toEqual([]);
    const g = factsOf(mk({ verb: 'acme', title: 'Go' }));
    expect(g.tokens).toEqual(['go']);
    expect(g.strict).toEqual(['go']);
    expect(g.locs).toEqual([]);
  });
  it('a location is clipped to 512 characters', () => {
    const f = factsOf(mk({ bindings: { http: { method: 'get', path: '/' + 'a'.repeat(600) } } }));
    expect(f.locs).toEqual(['/' + 'a'.repeat(511)]);
  });
});

describe('suggestWithRules matching', () => {
  const D = (over = {}) => mk(over);
  const mk = (over) => ({
    v: 1, kind: 'pca-action-def', verb: 'acme.thing.go', title: 'Go', effects: ['create'], resource: { type: 'acme.t', id: '*', scope: 'one' }, params: {}, review: { state: 'unreviewed' }, ...over,
  });
  const fired = (d, match, adds = ['pca.bulk']) => suggestWithRules(d, rs(rule('SR-001', match, adds))).fired;
  const hit = ['SR-001'];

  it('methods and effects match when any listed value is present', () => {
    const d = D({ bindings: { http: { method: 'post', path: '/x' } } });
    expect(fired(d, { methods: ['GET', 'POST'] })).toEqual(hit);
    expect(fired(d, { methods: ['GET'] })).toEqual([]);
    expect(fired(d, { effects: ['delete', 'create'] })).toEqual(hit);
    expect(fired(d, { effects: ['delete'] })).toEqual([]);
  });
  it('path_re needs a location only when given, and any location may match', () => {
    const d = D({ bindings: { http: { method: 'get', path: '/v1/refunds' }, mcp: { tool: 'x_tool' } } });
    expect(fired(d, { path_re: '^/v1/' })).toEqual(hit);
    expect(fired(d, { path_re: '^nomatch' })).toEqual([]);
    expect(fired(D(), { name_tokens: ['go'] })).toEqual(hit);
  });
  it('name tokens: empty patterns never match, order and position matter', () => {
    const d = D({ verb: 'acme.thing.refund.create', params: { amount: { type: 'integer' } } });
    expect(fired(d, { name_tokens: ['__'] })).toEqual([]);
    expect(fired(d, { param_names: ['__'] })).toEqual([]);
    expect(fired(d, { name_tokens: ['refund create'] })).toEqual(hit);
    expect(fired(d, { name_tokens: ['create refund'] })).toEqual([]);
    expect(fired(d, { name_tokens: ['thing refund'] })).toEqual(hit);
    expect(fired(d, { name_tokens: ['refund'] })).toEqual(hit);
  });
  it('roles: some param must carry one of the listed roles', () => {
    const d = D({ params: { p1: { type: 'string', role: 'party.payee' }, p2: { type: 'string' } } });
    expect(fired(d, { roles: ['party.payee'] })).toEqual(hit);
    expect(fired(d, { roles: ['money.amount'] })).toEqual([]);
    expect(fired(D({ params: { p2: { type: 'string' } } }), { roles: ['party.payee'] })).toEqual([]);
    expect(fired(D({ params: { p1: { type: 'string', role: 'person.name' } } }), { roles: ['party.payee', 'money.amount'] })).toEqual([]);
  });
  it('param types and formats filter the matched params', () => {
    const d = D({ params: { amount: { type: 'string' } } });
    expect(fired(d, { param_names: ['amount'], param_types: ['integer'] })).toEqual([]);
    expect(fired(d, { param_names: ['amount'], param_types: ['integer', 'string'] })).toEqual(hit);
    const e = D({ params: { amount: { type: 'integer' } } });
    const s = suggestWithRules(e, rs(rule('SR-001', { param_names: ['amount'], param_types: ['integer'] }, ['money.amount'])));
    expect(s.fired).toEqual(hit);
    expect(s.roles).toEqual({ amount: 'money.amount' });
    const f = D({ params: { a: { type: 'string', format: 'email' }, b: { type: 'string', format: 'uri' }, c: { type: 'string' } } });
    const t = suggestWithRules(f, rs(rule('SR-001', { param_formats: ['email'] }, ['tag:pii'])));
    expect(t.fired).toEqual(hit);
    expect(t.tags).toEqual({ a: ['pii'] });
    expect(fired(D({ params: { b: { type: 'string', format: 'uri' }, c: { type: 'string' } } }), { param_formats: ['email'] })).toEqual([]);
  });
  it('param_names_all: every name must match, a type mismatch fails unless the param is a string', () => {
    const d = D({ params: { amount: { type: 'integer' }, currency: { type: 'string' }, flag: { type: 'boolean' } } });
    expect(fired(d, { param_names_all: ['amount', 'currency'] })).toEqual(hit);
    expect(fired(d, { param_names_all: ['amount', 'missing'] })).toEqual([]);
    expect(fired(d, { param_names_all: ['missing', 'amount'] })).toEqual([]);
    expect(fired(d, { param_names_all: ['flag'] })).toEqual(hit);
    expect(fired(d, { param_names_all: ['flag'], param_types: ['integer'] })).toEqual([]);
    expect(fired(d, { param_names_all: ['currency'], param_types: ['integer'] })).toEqual(hit);
    expect(fired(d, { param_names_all: ['amount'], param_types: ['integer'] })).toEqual(hit);
    expect(fired(d, { param_names_all: ['amount'], param_types: ['boolean'] })).toEqual([]);
    expect(fired(d, { param_names_all: ['amount', 'flag'], param_types: ['integer', 'boolean'] })).toEqual(hit);
  });
  it('a rule without a param matcher applies no roles or tags', () => {
    const d = D({ params: { amount: { type: 'integer' }, email: { type: 'string' } } });
    const s = suggestWithRules(d, rs(rule('SR-001', { name_tokens: ['go'] }, ['tag:pii', 'money.amount', 'contact.email'])));
    expect(s).toEqual({ traits: [], roles: {}, tags: {}, fired: hit });
  });
  it('the first role wins, traits and tags come out sorted, fired lists only the rules that matched', () => {
    const d = D({ params: { amount: { type: 'integer' }, zeta: { type: 'string' }, alpha: { type: 'string' } } });
    const s1 = suggestWithRules(d, rs(rule('SR-001', { param_names: ['amount'] }, ['money.amount']), rule('SR-002', { param_names: ['amount'] }, ['money.fee'])));
    expect(s1.roles).toEqual({ amount: 'money.amount' });
    expect(s1.fired).toEqual(['SR-001', 'SR-002']);
    const s2 = suggestWithRules(d, rs(
      rule('SR-001', { param_names: ['zeta'] }, ['pca.privilege_change', 'pca.bulk', 'tag:pii', 'tag:code']),
      rule('SR-002', { name_tokens: ['nomatch'] }, ['pca.destructive']),
      rule('SR-003', { param_names: ['alpha'] }, ['tag:sql']),
    ));
    expect(s2.traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    expect(Object.keys(s2.tags)).toEqual(['alpha', 'zeta']);
    expect(s2.tags).toEqual({ alpha: ['sql'], zeta: ['code', 'pii'] });
    expect(s2.fired).toEqual(['SR-001', 'SR-003']);
  });
  it('an add that merely ends in tag: is a trait, not a role or tag', () => {
    const d = D({ params: { amount: { type: 'integer' } } });
    expect(suggestWithRules(d, rs(rule('SR-001', { param_names: ['amount'] }, ['acme.tag:']))).traits).toEqual(['acme.tag:']);
  });
  it('a role only fits a compatible param type', () => {
    const table: [string, string, boolean][] = [
      ['money.amount', 'integer', true], ['money.amount', 'string', false], ['money.fee', 'integer', true], ['money.fee', 'boolean', false],
      ['count.limit', 'integer', true], ['count.limit', 'string', false], ['bytes.size', 'integer', true], ['bytes.size', 'string', false],
      ['time.not_before', 'date', true], ['time.not_before', 'datetime', true], ['time.not_before', 'integer', true], ['time.not_before', 'string', false], ['time.not_before', 'boolean', false],
      ['time.not_after', 'date', true], ['time.not_after', 'datetime', true], ['time.not_after', 'integer', true], ['time.not_after', 'string', false], ['time.not_after', 'boolean', false],
      ['contact.email', 'string', true], ['contact.email', 'integer', false], ['contact.email', 'boolean', false], ['contact.email', 'date', false],
    ];
    for (const [role, type, fits] of table) {
      const d = D({ params: { p: { type } } });
      expect(suggestWithRules(d, rs(rule('SR-001', { param_names: ['p'] }, [role]))).roles, `${role} ${type}`).toEqual(fits ? { p: role } : {});
      const out = applySuggestion(d, { traits: [], roles: { p: role }, tags: {}, fired: [] }, {});
      expect(out.params.p.role, `apply ${role} ${type}`).toBe(fits ? role : undefined);
    }
  });
});

describe('unionSuggestions', () => {
  it('unions traits (sorted), roles (first wins), tags (sorted per key) and fired (in order)', () => {
    const a = { traits: ['pca.privilege_change'], roles: { x: 'money.amount' }, tags: { p: ['pii'], q: ['sql'] }, fired: ['SR-002'] };
    const b = { traits: ['pca.bulk', 'pca.privilege_change'], roles: { x: 'money.fee', y: 'contact.email' }, tags: { p: ['code'], r: ['path'] }, fired: ['SR-001'] };
    expect(unionSuggestions(a, b)).toStrictEqual({
      traits: ['pca.bulk', 'pca.privilege_change'],
      roles: { x: 'money.amount', y: 'contact.email' },
      tags: { p: ['code', 'pii'], q: ['sql'], r: ['path'] },
      fired: ['SR-002', 'SR-001'],
    });
  });
});

describe('applySuggestion', () => {
  const S = (o = {}) => ({ traits: [], roles: {}, tags: {}, fired: [], ...o });
  const mk = (over = {}) => ({
    v: 1, kind: 'pca-action-def', verb: 'acme.thing.go', title: 'Go', effects: ['create'], resource: { type: 'acme.t', id: '*', scope: 'one' }, params: {}, review: { state: 'unreviewed' }, ...over,
  });
  it('adds roles only to role-less compatible params and only fresh tags', () => {
    const d = mk({
      params: {
        a: { type: 'integer' }, b: { type: 'string', role: 'party.payee' }, c: { type: 'string' },
        e: { type: 'string', tags: ['pii'] }, f: { type: 'string', tags: ['pii'] },
      },
    });
    const out = applySuggestion(d, S({ roles: { a: 'money.amount', b: 'contact.email', c: 'money.amount' }, tags: { e: ['pii', 'code'], f: ['pii'], c: ['sql', 'path'] } }), {});
    expect(out.params.a.role).toBe('money.amount');
    expect(out.params.b.role).toBe('party.payee');
    expect(out.params.c.role).toBeUndefined();
    expect(out.params.c.tags).toEqual(['path', 'sql']);
    expect(out.params.e.tags).toEqual(['code', 'pii']);
    expect(out.params.f).toBe(d.params.f);
    expect(out.review.suggested_by).toStrictEqual({ added: { traits: [], roles: { a: 'money.amount' }, tags: { c: ['path', 'sql'], e: ['code'] } } });
    expect(out.review.state).toBe('suggested');
    expect('traits' in out).toBe(false);
    expect('idempotency' in out).toBe(false);
  });
  it('traits: union sorted, and a def without traits gains the key only when something is added', () => {
    expect('traits' in applySuggestion(mk(), S(), {})).toBe(false);
    expect(applySuggestion(mk({ traits: ['pca.privilege_change', 'pca.bulk'] }), S(), {}).traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    const out = applySuggestion(mk({ traits: ['pca.privilege_change'] }), S({ traits: ['pca.bulk'] }), {});
    expect(out.traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    expect(out.review.suggested_by.added.traits).toEqual(['pca.bulk']);
    const two = applySuggestion(mk(), S({ traits: ['pca.privilege_change', 'pca.bulk'] }), {});
    expect(two.traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    expect(two.review.suggested_by.added.traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    const dup = applySuggestion(mk({ traits: ['pca.bulk'] }), S({ traits: ['pca.bulk'] }), {});
    expect(dup.review.suggested_by.added.traits).toEqual([]);
  });
  it('review state: unreviewed becomes suggested, everything else keeps its state', () => {
    for (const [from, to] of [['unreviewed', 'suggested'], ['suggested', 'suggested'], ['authored', 'authored'], ['confirmed', 'confirmed']]) {
      const out = applySuggestion(mk({ review: { state: from, attestation: { x: 1 } } }), S(), {});
      expect(out.review.state, from).toBe(to);
      expect(out.review.attestation).toEqual({ x: 1 });
    }
  });
  it('a money-moving action gets the optional idempotency key unless it is already safe to repeat', () => {
    const money = S({ traits: ['pca.money_moving'] });
    const key = { mode: 'key_param', param: 'idempotency_key' };
    const param = { type: 'string', max_len: 64, required: false };
    for (const idem of [undefined, { mode: 'none' }]) {
      const out = applySuggestion(mk(idem ? { idempotency: idem } : {}), money, {});
      expect(out.idempotency).toEqual(key);
      expect(out.params.idempotency_key).toStrictEqual(param);
    }
    for (const idem of [{ mode: 'natural' }, { mode: 'key_param', param: 'k' }]) {
      const out = applySuggestion(mk({ idempotency: idem }), money, {});
      expect(out.idempotency).toEqual(idem);
      expect(out.params.idempotency_key).toBeUndefined();
    }
    const own = { type: 'string', max_len: 10, required: true };
    const out = applySuggestion(mk({ idempotency: { mode: 'none' }, params: { idempotency_key: own } }), money, {});
    expect(out.idempotency).toEqual(key);
    expect(out.params.idempotency_key).toBe(own);
    expect(applySuggestion(mk({ idempotency: { mode: 'natural' } }), S(), {}).idempotency).toEqual({ mode: 'natural' });
    expect('idempotency' in applySuggestion(mk(), S(), {})).toBe(false);
  });
  it('suggested_by merges earlier suggestions, rules and models', () => {
    const m1 = { id: 'm1', prompt_digest: 'p', input_digest: 'i', output_digest: 'o', temperature: 0, traits: [] };
    const m2 = { ...m1, id: 'm2' };
    const prevRules = { version: '0.9.0', digest: 'old', fired: ['SR-001'] };
    const d = mk({
      params: { a: { type: 'integer' }, k: { type: 'string' }, z: { type: 'string', tags: ['pii'] } },
      review: {
        state: 'suggested',
        suggested_by: { rules: prevRules, models: [m1], added: { traits: ['pca.privilege_change'], roles: { a: 'money.amount' }, tags: { z: ['pii'], k: ['sql'] } } },
      },
    });
    const s = S({ traits: ['pca.bulk'], roles: { k: 'contact.email' }, tags: { k: ['code'], a: ['path'] } });
    const one = applySuggestion(d, s, {});
    const sb = one.review.suggested_by;
    expect(sb.rules).toEqual(prevRules);
    expect(sb.models).toEqual([m1]);
    expect(sb.added.traits).toEqual(['pca.bulk', 'pca.privilege_change']);
    expect(sb.added.roles).toEqual({ a: 'money.amount', k: 'contact.email' });
    expect(Object.keys(sb.added.tags)).toEqual(['a', 'k', 'z']);
    expect(sb.added.tags).toEqual({ a: ['path'], k: ['code', 'sql'], z: ['pii'] });
    const newRules = { version: '1.0.0', digest: 'new', fired: [] };
    const two = applySuggestion(d, S(), { rules: newRules, models: [m2] });
    expect(two.review.suggested_by.rules).toEqual(newRules);
    expect(two.review.suggested_by.models).toEqual([m1, m2]);
  });
  it('without earlier suggestions or models the record holds only what was added', () => {
    expect(applySuggestion(mk(), S(), {}).review.suggested_by).toStrictEqual({ added: { traits: [], roles: {}, tags: {} } });
    const rules = { version: '1.0.0', digest: 'd', fired: ['SR-001'] };
    expect(applySuggestion(mk(), S(), { rules }).review.suggested_by).toStrictEqual({ rules, added: { traits: [], roles: {}, tags: {} } });
  });
});
