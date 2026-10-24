/**
 * 0.4.2 r13 mutation kills (g5): oracle-facts.ts. Exact reasons for every fact wire / world policy / rule-16 refusal,
 * the inclusive bounds (16 worlds, 16 relational, 16 committed digests, t_obs / freshness / max_faulty / skew of 0,
 * a ratio exactly MAX_SAFE_INTEGER), operand-name tricks (a non-string name that stringifies to a valid one, a 10-char
 * prefix that is not `env.world.`, a self reference), multi-world selection, and the evaluation-error catch.
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  decideIntentWorld,
  factRef,
  FACT_REF_DOMAIN,
  intentWorldActive,
  lowerMedian,
  ratioPpm,
  signFact,
  validateFactWire,
  validateWorldPolicy,
  type IntentWorldInput,
  type IntentWorldPolicy,
  type PcaFact,
  type WorldPolicy,
} from './oracle-facts';
import { offerSetRef, signOfferSet, type OfferPolicy } from './offer-set';

const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g5-facts/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const O1 = key('o1');
const O2 = key('o2');
const O3 = key('o3');
const SITE = key('site');
const NOW = 1_800_000_000_000;
const SESSION = b64u(seed('session'));
const AUD = 'skyair.example';

const fact = (o: { sk: Uint8Array }, kid: string, name: string, value: number | string, t_obs = NOW - 1_000, subject = 'OF-2'): PcaFact =>
  signFact({ name, subject, value, t_obs, oracle: kid }, o.sk);
const world = (over: Partial<WorldPolicy> = {}): WorldPolicy => ({
  name: 'fare',
  subject_path: 'action.params.offer_id',
  oracles: [{ kid: 'o1', pk: O1.pk }, { kid: 'o2', pk: O2.pk }, { kid: 'o3', pk: O3.pk }],
  freshness_ms: 60_000,
  min_oracles: 1,
  max_faulty: 0,
  ...over,
});
const ACTION = { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900, s: '5', big: Number.MAX_SAFE_INTEGER, neg: -Number.MAX_SAFE_INTEGER } };
const input = (facts: unknown[], policy: unknown, over: Record<string, unknown> = {}): IntentWorldInput =>
  ({ now: NOW, aud: AUD, session: SESSION, action: ACTION, committed: { facts: facts.map((f) => factRef(f as PcaFact)) }, facts, policy, ...over }) as IntentWorldInput;
const why = (r: ReturnType<typeof decideIntentWorld>) => (r.ok ? 'OK' : r.reason);
const wireFact = (over: Record<string, unknown> = {}) => ({ ...fact(O1, 'o1', 'fare', 1), ...over });

describe('validateFactWire: exact reasons', () => {
  it('a signed fact is well-formed', () => {
    expect(validateFactWire(fact(O1, 'o1', 'fare', 1))).toBeNull();
    expect(validateFactWire(wireFact({ value: 'gold' }))).toBeNull();
    expect(validateFactWire(wireFact({ t_obs: 0 }))).toBeNull();
  });
  it('each member', () => {
    expect(validateFactWire(null)).toBe('fact must be an object');
    expect(validateFactWire([])).toBe('fact must be an object');
    expect(validateFactWire(wireFact({ extra: 1 }))).toBe("unknown member 'fact.extra'");
    const kind = 'fact must be {v: 1, kind: "pca-fact"}';
    expect(validateFactWire(wireFact({ v: 2 }))).toBe(kind);
    expect(validateFactWire(wireFact({ kind: 'pca-offer-set' }))).toBe(kind);
    const nm = "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$";
    expect(validateFactWire(wireFact({ name: 5 }))).toBe(nm);
    expect(validateFactWire(wireFact({ name: ['fare'] }))).toBe(nm);
    expect(validateFactWire(wireFact({ name: 'Fare' }))).toBe(nm);
    expect(validateFactWire(wireFact({ subject: '' }))).toBe("'fact.subject' must be a non-empty string (<= 256 bytes)");
    const vm = "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)";
    expect(validateFactWire(wireFact({ value: 1.5 }))).toBe(vm);
    expect(validateFactWire(wireFact({ value: '' }))).toBe(vm);
    const tm = "'fact.t_obs' must be a non-negative safe integer";
    expect(validateFactWire(wireFact({ t_obs: -1 }))).toBe(tm);
    expect(validateFactWire(wireFact({ t_obs: '1' }))).toBe(tm);
    expect(validateFactWire(wireFact({ oracle: '' }))).toBe("'fact.oracle' must be a non-empty string (<= 64 bytes)");
    expect(validateFactWire(wireFact({ sig: 1 }))).toBe("'fact.sig' must be a string");
  });
});

describe('factRef / lowerMedian / ratioPpm', () => {
  it('factRef is hashCanonical over {d, f}', () => {
    const f = fact(O1, 'o1', 'fare', 1);
    expect(factRef(f)).toBe(hashCanonical({ d: FACT_REF_DOMAIN, f }));
  });
  it('lowerMedian throws on empty', () => {
    expect(() => lowerMedian([])).toThrow('lowerMedian: empty');
    expect(lowerMedian([3, 1, 2, 4])).toBe(2);
  });
  it('ratioPpm returns a result of exactly MAX_SAFE_INTEGER', () => {
    expect(ratioPpm(Number.MAX_SAFE_INTEGER, 1_000_000)).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe('validateWorldPolicy: exact reasons', () => {
  const ok = (p: unknown) => expect(validateWorldPolicy(p as IntentWorldPolicy)).toBeNull();
  const bad = (p: unknown, m: string) => expect(validateWorldPolicy(p as IntentWorldPolicy)).toBe(m);
  it('container, members, skew', () => {
    ok({});
    ok({ skew_ms: 0 });
    ok({ skew_ms: 5 });
    bad(null, 'world policy must be an object');
    bad([], 'world policy must be an object');
    bad({ extra: 1 }, "unknown member 'policy.extra'");
    bad({ skew_ms: -1 }, 'skew_ms must be a non-negative safe integer');
    bad({ skew_ms: 1.5 }, 'skew_ms must be a non-negative safe integer');
  });
  it('worlds list', () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => world({ name: `w${i}` }));
    ok({ worlds: many(16) });
    bad({ worlds: many(17) }, 'worlds must be a list of at most 16');
    bad({ worlds: 'abc' }, 'worlds must be a list of at most 16');
    bad({ worlds: null }, 'worlds must be a list of at most 16');
    bad({ worlds: [null] }, 'world entry must be an object');
    bad({ worlds: [[]] }, 'world entry must be an object');
  });
  it('world entry members', () => {
    ok({ worlds: [world()] });
    bad({ worlds: [{ ...world(), extra: 1 }] }, "unknown member 'world.extra'");
    bad({ worlds: [{ ...world(), 'Stryker was here': 1 }] }, "unknown member 'world.Stryker was here'");
    const { max_faulty: _m, ...noMf } = world();
    bad({ worlds: [noMf] }, "missing member 'world.max_faulty'");
    bad({ worlds: [world({ name: 5 as never })] }, "dimension name '5' must match ^[a-z][a-z0-9_]{0,63}$");
    bad({ worlds: [world({ name: ['fare'] as never })] }, "dimension name 'fare' must match ^[a-z][a-z0-9_]{0,63}$");
    bad({ worlds: [world(), world()] }, "duplicate dimension name 'fare'");
    const sp = "world 'fare': subject_path must be rooted at action.";
    bad({ worlds: [world({ subject_path: 'params.offer_id' })] }, sp);
    bad({ worlds: [world({ subject_path: 5 as never })] }, sp);
    ok({ worlds: [world({ subject_path: 'action.resource' })] });
    const fm = "world 'fare': freshness_ms must be a non-negative safe integer";
    bad({ worlds: [world({ freshness_ms: -1 })] }, fm);
    bad({ worlds: [world({ freshness_ms: 1.5 })] }, fm);
    ok({ worlds: [world({ freshness_ms: 0 })] });
    const mf = "world 'fare': max_faulty must be a non-negative safe integer";
    bad({ worlds: [world({ max_faulty: -1 })] }, mf);
    bad({ worlds: [world({ max_faulty: 0.5 })] }, mf);
    const mo = "world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1";
    bad({ worlds: [world({ min_oracles: 2, max_faulty: 1 })] }, mo);
    bad({ worlds: [world({ min_oracles: '3' as never, max_faulty: 1 })] }, mo);
    ok({ worlds: [world({ min_oracles: 3, max_faulty: 1 })] });
    const fo = "world 'fare': fewer pinned oracles than min_oracles";
    bad({ worlds: [world({ min_oracles: 1, oracles: 'abc' as never })] }, fo);
    bad({ worlds: [world({ min_oracles: 4, max_faulty: 0 })] }, fo);
    ok({ worlds: [world({ min_oracles: 3 })] });
  });
  it('oracle pins', () => {
    const om = "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
    const w = (oracles: unknown[]) => ({ worlds: [world({ oracles: oracles as never })] });
    ok(w([{ kid: 'o1', pk: O1.pk, pq_pk: 'PQ' }]));
    ok(w([{ kid: 'o1', pk: O1.pk }, { kid: 'o2', pk: O2.pk }]));
    bad(w([null]), om);
    bad(w(['o1']), om);
    bad(w([{ kid: 'o1', pk: O1.pk, extra: 1 }]), om);
    bad(w([{ kid: 'o1' }]), om);
    bad(w([{ kid: '', pk: O1.pk }]), om);
    bad(w([{ kid: 'o1', pk: 'short' }]), om);
    bad(w([{ kid: 'o1', pk: O1.pk, pq_pk: '' }]), om);
    bad(w([{ kid: 'o1', pk: O1.pk }, { kid: 'o1', pk: O2.pk }]), om);
  });
  it('relational entries', () => {
    const rel = (r: Record<string, unknown>[], worlds: unknown[] = [world()]) => ({ worlds, relational: r });
    const many = (n: number) => Array.from({ length: n }, (_, i) => ({ name: `r${i}`, fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }));
    ok({ relational: many(16) });
    bad({ relational: many(17) }, 'relational must be a list of at most 16');
    bad({ relational: 'abc' }, 'relational must be a list of at most 16');
    bad({ relational: [null] }, 'relational entry must be an object');
    bad({ relational: [{ ...many(1)[0], extra: 1 }] }, "unknown member 'relational.extra'");
    bad({ relational: [{ ...many(1)[0], 'Stryker was here': 1 }] }, "unknown member 'relational.Stryker was here'");
    bad({ relational: [{ ...many(1)[0], name: 'fare' }], worlds: [world()] }, "duplicate dimension name 'fare'");
    bad({ relational: [{ ...many(1)[0], fn: 'mul' }] }, 'relational \'r0\': fn must be "sub" or "ratio_ppm"');
    ok({ relational: [{ ...many(1)[0], fn: 'ratio_ppm' }] });
    ok(rel([{ name: 'd', fn: 'sub', a: 'env.world.fare', b: 'action.params.quote' }]));
    const opm = (op: string, n = 'd') => `relational '${n}': operand '${op}' must be an action.params path or an earlier env.world dimension`;
    bad(rel([{ name: 'd', fn: 'sub', a: 'abcdefghijfare', b: 'action.params.quote' }]), opm('abcdefghijfare'));
    bad(rel([{ name: 'd', fn: 'sub', a: 5, b: 'action.params.quote' }]), opm('5'));
    bad(rel([{ name: 'd', fn: 'sub', a: 'env.world.nope', b: 'action.params.quote' }]), opm('env.world.nope'));
    bad(rel([{ name: 'd', fn: 'sub', a: 'env.world.d', b: 'action.params.quote' }]), opm('env.world.d'));
    bad(rel([{ name: 'd', fn: 'sub', a: 'action.params.quote', b: 'env.world.d' }]), opm('env.world.d'));
  });
  it('offers: validated and its name claimed', () => {
    const offers = (over: Record<string, unknown> = {}) => ({ name: 'excess', site_keys: [{ kid: 'k1', pk: SITE.pk }], max_age_ms: 1, offer_param: 'action.params.offer_id', filter: { query: {}, offer: {} }, ...over });
    ok({ offers: offers() });
    bad({ offers: offers({ max_age_ms: -1 }) }, 'offers policy: max_age_ms must be a non-negative safe integer');
    bad({ offers: null }, 'offers policy must be an object');
    bad({ worlds: [world()], offers: offers({ name: 'fare' }) }, "duplicate dimension name 'fare'");
    bad({ offers: offers({ name: 'Bad' }) }, "dimension name 'Bad' must match ^[a-z][a-z0-9_]{0,63}$");
  });
});

describe('intentWorldActive', () => {
  it('strict activity', () => {
    expect(intentWorldActive(null as never)).toBe(false);
    expect(intentWorldActive([] as never)).toBe(false);
    expect(intentWorldActive({})).toBe(false);
    expect(intentWorldActive({ committed: { facts: [] }, policy: { worlds: [], relational: [] } })).toBe(false);
    expect(intentWorldActive({ committed: { facts: ['x'] } })).toBe(true);
    expect(intentWorldActive({ committed: { offer_set: 'x' } })).toBe(true);
    expect(intentWorldActive({ committed: { offer_set: 1 } })).toBe(false);
    expect(intentWorldActive({ committed: { '': 'x' } })).toBe(false);
    expect(intentWorldActive({ policy: { worlds: [{}] } })).toBe(true);
    expect(intentWorldActive({ policy: { relational: [{}] } })).toBe(true);
    expect(intentWorldActive({ policy: { offers: {} } })).toBe(true);
    expect(intentWorldActive({ policy: { offers: [] } })).toBe(false);
    expect(intentWorldActive({ policy: { '': [1] } })).toBe(false);
    expect(intentWorldActive({ policy: { '': {} } })).toBe(false);
  });
});

describe('decideIntentWorld: exact reasons', () => {
  const one = () => [fact(O1, 'o1', 'fare', 39_800)];
  it('success, absent policy and absent params', () => {
    expect(decideIntentWorld(input(one(), { worlds: [world()] }))).toEqual({ ok: true, world: { fare: 39_800 }, single_source: ['fare'] });
    expect(decideIntentWorld({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r' } } as IntentWorldInput)).toEqual({ ok: true, world: {}, single_source: [] });
    expect(decideIntentWorld({ now: NOW, aud: AUD, session: SESSION, action: { verb: 'v', resource: 'r' }, policy: { relational: [{ name: 'r', fn: 'sub', a: 'env.world.x', b: 'env.world.x' }] } } as never)).toMatchObject({ ok: false });
  });
  it('input, policy, action, params, committed', () => {
    expect(why(decideIntentWorld(null as never))).toBe('facts: input must be an object');
    expect(why(decideIntentWorld(input([], { extra: 1 })))).toBe("facts: policy misconfigured (fail closed): unknown member 'policy.extra'");
    expect(why(decideIntentWorld(input([], null)))).toBe('facts: policy misconfigured (fail closed): world policy must be an object');
    expect(why(decideIntentWorld(input([], {}, { action: null })))).toBe('facts: action must be an object');
    expect(why(decideIntentWorld(input([], {}, { action: { verb: 'v', resource: 'r', params: null } })))).toBe('facts: action.params must be an object');
    expect(why(decideIntentWorld(input([], {}, { committed: null })))).toBe('facts: committed must be an object');
  });
  it('committed digests', () => {
    const cf = 'facts: committed facts must be a list of at most 16 digests';
    const digests = (n: number) => Array.from({ length: n }, (_, i) => b64u(seed(`d${i}`)));
    expect(why(decideIntentWorld(input([], {}, { committed: { facts: digests(17) } })))).toBe(cf);
    expect(why(decideIntentWorld(input([], {}, { committed: { facts: 'abc' } })))).toBe(cf);
    expect(why(decideIntentWorld(input([], {}, { committed: { facts: digests(16) } })))).toBe('facts: a committed fact was not supplied (or is malformed)');
    expect(why(decideIntentWorld(input([], {}, { committed: { facts: ['nope'] } })))).toBe('facts: a committed fact digest is not canonical base64url (32 bytes)');
    const d = b64u(seed('d'));
    expect(why(decideIntentWorld(input([], {}, { committed: { facts: [d, d] } })))).toBe('facts: duplicate committed fact digest');
    expect(why(decideIntentWorld(input([], {}, { committed: { offer_set: 'nope' } })))).toBe('facts: the committed offer_set is not canonical base64url (32 bytes)');
  });
  it('supplied facts and offer set', () => {
    expect(why(decideIntentWorld(input([], {}, { committed: {}, facts: {} })))).toBe('facts: facts must be an array');
    expect(why(decideIntentWorld(input([], {}, { offer_set: [] })))).toBe('facts: offer_set must be an object');
    // a malformed supplied fact is skipped even when its reference was committed (and even when it is otherwise valid)
    const malformed = { ...fact(O1, 'o1', 'fare', 1), extra: 1 };
    const signedMalformed = { ...signFact({ name: 'fare', subject: 'OF-2', value: 1, t_obs: NOW - 1_000, oracle: 'o1', extra: 1 } as never, O1.sk) };
    for (const m of [malformed, signedMalformed]) {
      expect(why(decideIntentWorld(input([m], { worlds: [world()] }, { committed: { facts: [factRef(m as never)] } })))).toBe('facts: a committed fact was not supplied (or is malformed)');
    }
  });
  it('per committed fact: suite, world, pin, signature, subject, pair', () => {
    const alg = { ...fact(O1, 'o1', 'fare', 1), alg: 'no-such-suite' };
    expect(why(decideIntentWorld(input([alg], { worlds: [world()] })))).toMatch(/^facts: fact signature suite: .*unsupported_suite/);
    expect(why(decideIntentWorld(input([fact(O1, 'o1', 'tier', 'gold')], { worlds: [world()] })))).toBe("facts: fact for undeclared world 'tier'");
    expect(why(decideIntentWorld(input([fact(O1, 'o9', 'fare', 1)], { worlds: [world()] })))).toBe("facts: oracle 'o9' is not pinned for world 'fare'");
    expect(why(decideIntentWorld(input([fact(O2, 'o1', 'fare', 1)], { worlds: [world()] })))).toBe("facts: bad oracle signature on a 'fare' fact");
    expect(why(decideIntentWorld(input([fact(O1, 'o1', 'fare', 1, NOW - 1_000, 'OF-1')], { worlds: [world()] })))).toBe("facts: a 'fare' fact names another subject");
    const noSubject = { ...ACTION, params: {} };
    expect(why(decideIntentWorld(input(one(), { worlds: [world()] }, { action: noSubject })))).toBe("facts: a 'fare' fact names another subject");
    const numSubject = { ...ACTION, params: { offer_id: 7 } };
    expect(why(decideIntentWorld(input(one(), { worlds: [world()] }, { action: numSubject })))).toBe("facts: a 'fare' fact names another subject");
    expect(why(decideIntentWorld(input([fact(O1, 'o1', 'fare', 1), fact(O1, 'o1', 'fare', 2, NOW - 2_000)], { worlds: [world()] })))).toBe("facts: two facts from oracle 'o1' for world 'fare'");
  });
  it('subject paths action.resource and action.verb', () => {
    const res = fact(O1, 'o1', 'fare', 3, NOW - 1_000, ACTION.resource);
    expect(decideIntentWorld(input([res], { worlds: [world({ subject_path: 'action.resource' })] }))).toEqual({ ok: true, world: { fare: 3 }, single_source: ['fare'] });
    const verb = fact(O1, 'o1', 'fare', 4, NOW - 1_000, ACTION.verb);
    expect(decideIntentWorld(input([verb], { worlds: [world({ subject_path: 'action.verb' })] }))).toEqual({ ok: true, world: { fare: 4 }, single_source: ['fare'] });
    const off = fact(O1, 'o1', 'fare', 4, NOW - 1_000, 'action.verb');
    expect(why(decideIntentWorld(input([off], { worlds: [world({ subject_path: 'action.verb' })] }, { action: { ...ACTION, verb: 5 } })))).toBe("facts: a 'fare' fact names another subject");
    expect(why(decideIntentWorld(input([res], { worlds: [world({ subject_path: 'action.resource' })] }, { action: { ...ACTION, resource: 5 } })))).toBe("facts: a 'fare' fact names another subject");
  });
  it('two worlds: facts are matched to their own world and counted only there', () => {
    const tier = world({ name: 'tier', subject_path: 'action.resource', oracles: [{ kid: 't1', pk: O3.pk }] });
    const facts = [fact(O1, 'o1', 'fare', 10), fact(O3, 't1', 'tier', 'gold', NOW - 1_000, ACTION.resource)];
    expect(decideIntentWorld(input(facts, { worlds: [world(), tier] }))).toEqual({ ok: true, world: { fare: 10, tier: 'gold' }, single_source: ['fare', 'tier'] });
  });
  it('freshness, counts and value kinds', () => {
    const three = [fact(O1, 'o1', 'fare', 1), fact(O2, 'o2', 'fare', 2), fact(O3, 'o3', 'fare', 3)];
    expect(decideIntentWorld(input(three, { worlds: [world({ min_oracles: 3, max_faulty: 1 })] }))).toEqual({ ok: true, world: { fare: 2 }, single_source: [] });
    expect(why(decideIntentWorld(input(three.slice(0, 2), { worlds: [world({ min_oracles: 3, max_faulty: 1 })] })))).toBe("facts: world 'fare' has 2 fresh fact(s), needs 3");
    const strs = [fact(O1, 'o1', 'fare', 'a'), fact(O2, 'o2', 'fare', 'b')];
    expect(why(decideIntentWorld(input(strs, { worlds: [world({ min_oracles: 2 })] })))).toBe("facts: world 'fare': string facts disagree");
    const mix = [fact(O1, 'o1', 'fare', 1), fact(O2, 'o2', 'fare', 'b')];
    expect(why(decideIntentWorld(input(mix, { worlds: [world({ min_oracles: 2 })] })))).toBe("facts: world 'fare': facts mix integer and string values");
    const mix2 = [fact(O1, 'o1', 'fare', 'b'), fact(O2, 'o2', 'fare', 1)];
    expect(why(decideIntentWorld(input(mix2, { worlds: [world({ min_oracles: 2 })] })))).toBe("facts: world 'fare': facts mix integer and string values");
  });
  it('relational operands and results', () => {
    const r = (rel: Record<string, unknown>, worlds: unknown[] = []) => why(decideIntentWorld(input([], { worlds, relational: [rel] }, { committed: {}, facts: [] })));
    const miss = (n: string) => `facts: relational '${n}': an operand is missing or not a safe integer`;
    expect(decideIntentWorld(input([], { relational: [{ name: 'd', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] }))).toEqual({ ok: true, world: { d: 38_900 }, single_source: [] });
    expect(r({ name: 'd', fn: 'sub', a: 'action.params.nope', b: 'action.params.quote' })).toBe(miss('d'));
    expect(r({ name: 'd', fn: 'sub', a: 'action.params.quote', b: 'action.params.nope' })).toBe(miss('d'));
    expect(r({ name: 'd', fn: 'sub', a: 'action.params.s', b: 'action.params.quote' })).toBe(miss('d'));
    expect(r({ name: 'd', fn: 'sub', a: 'action.params.quote', b: 'action.params.s' })).toBe(miss('d'));
    const range = (n: string) => `facts: relational '${n}': result undefined or outside the safe integer range`;
    expect(r({ name: 'd', fn: 'ratio_ppm', a: 'action.params.total', b: 'action.params.neg' })).toBe(range('d'));
    expect(r({ name: 'd', fn: 'sub', a: 'action.params.big', b: 'action.params.neg' })).toBe(range('d'));
    expect(decideIntentWorld(input([], { relational: [{ name: 'd', fn: 'ratio_ppm', a: 'action.params.total', b: 'action.params.quote' }] }))).toEqual({ ok: true, world: { d: 2_000_000 }, single_source: [] });
    // an env.world operand of a string world is not an integer
    const tier = world({ name: 'tier', subject_path: 'action.resource', oracles: [{ kid: 't1', pk: O3.pk }] });
    const f = [fact(O3, 't1', 'tier', 'gold', NOW - 1_000, ACTION.resource)];
    expect(why(decideIntentWorld(input(f, { worlds: [tier], relational: [{ name: 'd', fn: 'sub', a: 'env.world.tier', b: 'action.params.quote' }] })))).toBe(miss('d'));
  });
  it('offers: the excess becomes a world value; a refusal is prefixed', () => {
    const offers: OfferPolicy = { name: 'excess', site_keys: [{ kid: 'k1', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: {}, offer: {} } };
    const os = signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: {}, rank: 'price_asc', complete: true, offers: [{ offer_id: 'OF-1', price: 5 }, { offer_id: 'OF-2', price: 8 }], issued_at: NOW - 1, kid: 'k1' }, SITE.sk);
    expect(decideIntentWorld(input([], { offers }, { committed: { offer_set: offerSetRef(os) }, offer_set: os }))).toEqual({ ok: true, world: { excess: 3 }, single_source: [] });
    expect(why(decideIntentWorld(input([], { offers }, { committed: {}, offer_set: os })))).toBe('facts: offers: the PCActn commits no offer set but the policy requires one');
  });
  it('an internal throw is an evaluation error', () => {
    const i = input([], {}) as unknown as Record<string, unknown>;
    Object.defineProperty(i, 'policy', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(why(decideIntentWorld(i as never))).toBe('facts: evaluation error (fail closed): boom');
  });
});
