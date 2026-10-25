/**
 * 0.4.2 r13 mutation kills (g5): offer-set.ts. Exact reasons for every wire / policy refusal, the inclusive bounds
 * (32 query keys, 256 offers, 32 attributes, issued_at / price / max_age_ms of 0, issued_at == now + skew), the
 * evaluation-error catch (a throwing getter: Error and non-Error) and the strict-canonical refusal (a lone surrogate).
 */
import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { artifactSuiteError } from './intent-artifacts';
import {
  decideOfferSet,
  offerMatches,
  offerSetRef,
  OFFER_SET_DOMAIN,
  OFFER_SET_REF_DOMAIN,
  queryCovers,
  signOfferSet,
  validateOfferPolicy,
  validateOfferSetWire,
  type OfferPolicy,
  type PcaOfferSet,
} from './offer-set';

/** Capture a call's outcome: a throw becomes a compared value (an assertion failure), never an uncaught error. */
const settle = (f: () => unknown) => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? { name: e.name, message: e.message } : String(e) };
  }
};
const val = (f: () => unknown) => {
  const r = settle(f);
  return r.ok ? r.value : r;
};
const vw = (o: unknown) => val(() => validateOfferSetWire(o));
const vp = (p: unknown) => val(() => validateOfferPolicy(p));
const om = (o: unknown, f: unknown) => val(() => offerMatches(o as never, f as never));
const qc = (q: unknown, f: unknown) => val(() => queryCovers(q as never, f as never));
const seed = (l: string) => sha256(utf8(`atlas-pca-test/r13-g5-offer/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const SITE = key('site');
const SITE2 = key('site-2');
const NOW = 1_800_000_000_000;
const SESSION = b64u(seed('session'));
const AUD = 'skyair.example';
const Q = { from: 'SFO', to: 'JFK' };
const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, refundable: false },
  { offer_id: 'OF-2', price: 39_800, refundable: false },
  { offer_id: 'OF-3', price: 30_000, refundable: true },
];
type Body = Omit<PcaOfferSet, 'sig'>;
const body = (over: Partial<Body> = {}): Body => ({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: Q, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'k1', ...over });
const signed = (over: Partial<Body> = {}, sk = SITE.sk): PcaOfferSet => signOfferSet(body(over), sk);
/** Wire-only object (sig is just a string: validateOfferSetWire never verifies it). */
const wire = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ ...body(), sig: 'x', ...over });
const policy = (over: Record<string, unknown> = {}): OfferPolicy =>
  ({ name: 'excess', site_keys: [{ kid: 'k1', pk: SITE.pk }], max_age_ms: 600_000, offer_param: 'action.params.offer_id', filter: { query: Q, offer: { refundable: false } }, ...over }) as OfferPolicy;
const decide = (os: unknown, o: { params?: unknown; policy?: unknown; committed?: string | undefined; now?: number; skewMs?: number; aud?: string; session?: string } = {}) =>
  decideOfferSet({
    policy: (o.policy ?? policy()) as OfferPolicy,
    committed: 'committed' in o ? o.committed : offerSetRef(os as PcaOfferSet),
    offerSet: os,
    params: 'params' in o ? o.params : { offer_id: 'OF-2' },
    aud: o.aud ?? AUD,
    session: o.session ?? SESSION,
    now: 'now' in o ? (o.now as number) : NOW,
    skewMs: 'skewMs' in o ? (o.skewMs as number) : 60_000,
  });
const reason = (d: ReturnType<typeof decideOfferSet>) => (d.ok ? 'OK' : d.reason);
const attrs = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`a${i}`, i]));

describe('validateOfferSetWire: exact reasons', () => {
  it('a well-formed offer set is null', () => {
    expect(vw(wire())).toBeNull();
    expect(vw(signed())).toBeNull();
  });
  it('container and closed member set', () => {
    expect(vw(null)).toBe('offer set must be an object');
    expect(vw([])).toBe('offer set must be an object');
    expect(vw(wire({ extra: 1 }))).toBe("unknown member 'offer_set.extra'");
    const { kid: _k, ...noKid } = wire();
    expect(vw(noKid)).toBe("missing member 'offer_set.kid'");
    expect(vw(wire({ alg: 'ed25519' }))).toBeNull();
  });
  it('v / kind', () => {
    const m = 'offer set must be {v: 1, kind: "pca-offer-set"}';
    expect(vw(wire({ v: 2 }))).toBe(m);
    expect(vw(wire({ kind: 'pca-fact' }))).toBe(m);
    expect(vw(wire({ v: 2, kind: 'x' }))).toBe(m);
  });
  it('site / session', () => {
    expect(vw(wire({ site: '' }))).toBe("'offer_set.site' must be a non-empty string (<= 256 bytes)");
    expect(vw(wire({ site: 'a'.repeat(257) }))).toBe("'offer_set.site' must be a non-empty string (<= 256 bytes)");
    expect(vw(wire({ site: 'a'.repeat(256) }))).toBeNull();
    expect(vw(wire({ session: 'nope' }))).toBe("'offer_set.session' must be canonical base64url (32 bytes)");
  });
  it('query: object, at most 32 keys, scalar values with bounded keys', () => {
    const qm = "'offer_set.query' must be an object with <= 32 keys";
    expect(vw(wire({ query: 'xy' }))).toBe(qm);
    expect(vw(wire({ query: [] }))).toBe(qm);
    expect(vw(wire({ query: attrs(33) }))).toBe(qm);
    expect(vw(wire({ query: attrs(32) }))).toBeNull();
    expect(vw(wire({ query: { a: null } }))).toBe("'offer_set.query.a' must be a scalar");
    expect(vw(wire({ query: { a: 1.5 } }))).toBe("'offer_set.query.a' must be a scalar");
    expect(vw(wire({ query: { ['k'.repeat(65)]: 1 } }))).toBe(`'offer_set.query.${'k'.repeat(65)}' must be a scalar`);
    expect(vw(wire({ query: { ['k'.repeat(64)]: true } }))).toBeNull();
  });
  it('rank / complete', () => {
    expect(vw(wire({ rank: 'price_desc' }))).toBe("'offer_set.rank' must be \"price_asc\"");
    expect(vw(wire({ complete: 'true' }))).toBe("'offer_set.complete' must be a boolean");
    expect(vw(wire({ complete: false }))).toBeNull();
  });
  it('offers: 1..256', () => {
    const m = "'offer_set.offers' must hold 1..256 offers";
    expect(vw(wire({ offers: [] }))).toBe(m);
    expect(vw(wire({ offers: 'x' }))).toBe(m);
    expect(vw(wire({ offers: { length: 1, 0: OFFERS[0] } }))).toBe(m);
    const many = (n: number) => Array.from({ length: n }, (_, i) => ({ offer_id: `O${i}`, price: i }));
    expect(vw(wire({ offers: many(257) }))).toBe(m);
    expect(vw(wire({ offers: many(256) }))).toBeNull();
  });
  it('each offer: object, offer_id, unique, price, attributes', () => {
    expect(vw(wire({ offers: [OFFERS[0], 'x'] }))).toBe('offer 1 must be an object');
    expect(vw(wire({ offers: [null] }))).toBe('offer 0 must be an object');
    expect(vw(wire({ offers: [OFFERS[0], { offer_id: '', price: 1 }] }))).toBe("offer 1: 'offer_id' must be a non-empty string (<= 128 bytes)");
    expect(vw(wire({ offers: [{ offer_id: 'x'.repeat(129), price: 1 }] }))).toBe("offer 0: 'offer_id' must be a non-empty string (<= 128 bytes)");
    expect(vw(wire({ offers: [{ offer_id: 'x'.repeat(128), price: 1 }] }))).toBeNull();
    expect(vw(wire({ offers: [OFFERS[0], OFFERS[1], OFFERS[0]] }))).toBe('offer 2: duplicate offer_id');
    expect(vw(wire({ offers: [{ offer_id: 'a', price: -1 }] }))).toBe("offer 0: 'price' must be a non-negative safe integer");
    expect(vw(wire({ offers: [{ offer_id: 'a', price: 1.5 }] }))).toBe("offer 0: 'price' must be a non-negative safe integer");
    expect(vw(wire({ offers: [{ offer_id: 'a', price: '1' }] }))).toBe("offer 0: 'price' must be a non-negative safe integer");
    expect(vw(wire({ offers: [{ offer_id: 'a', price: 0 }] }))).toBeNull();
  });
  it('attributes: offer_id and price are not attributes; at most 32; scalar', () => {
    expect(vw(wire({ offers: [{ offer_id: 'a', price: 1, ...attrs(32) }] }))).toBeNull();
    expect(vw(wire({ offers: [{ offer_id: 'a', price: 1, ...attrs(33) }] }))).toBe('offer 0: more than 32 attributes');
    expect(vw(wire({ offers: [OFFERS[0], { offer_id: 'b', price: 1, bad: null }] }))).toBe("offer 1: attribute 'bad' must be a scalar");
    expect(vw(wire({ offers: [{ offer_id: 'b', price: 1, ['k'.repeat(65)]: 1 }] }))).toBe(`offer 0: attribute '${'k'.repeat(65)}' must be a scalar`);
  });
  it('issued_at / kid / sig', () => {
    const im = "'offer_set.issued_at' must be a non-negative safe integer";
    expect(vw(wire({ issued_at: -1 }))).toBe(im);
    expect(vw(wire({ issued_at: 'now' }))).toBe(im);
    expect(vw(wire({ issued_at: 0 }))).toBeNull();
    expect(vw(wire({ kid: '' }))).toBe("'offer_set.kid' must be a non-empty string (<= 64 bytes)");
    expect(vw(wire({ kid: 'k'.repeat(65) }))).toBe("'offer_set.kid' must be a non-empty string (<= 64 bytes)");
    expect(vw(wire({ sig: 7 }))).toBe("'offer_set.sig' must be a string");
  });
});

describe('offerSetRef / offerMatches / queryCovers', () => {
  it('offerSetRef is hashCanonical over {d, o}', () => {
    const os = signed();
    expect(offerSetRef(os)).toBe(hashCanonical({ d: OFFER_SET_REF_DOMAIN, o: os }));
    expect(OFFER_SET_REF_DOMAIN).toBe('atlas-pca/offer-set-ref/v1');
    expect(OFFER_SET_DOMAIN).toBe('atlas-pca/offer-set/v1\0');
  });
  it('offerMatches: non-objects never match; every filter key must be present and scalar-equal', () => {
    expect(om(null as never, {})).toBe(false);
    expect(om([] as never, {})).toBe(false);
    expect(om({}, null as never)).toBe(false);
    expect(om({}, [] as never)).toBe(false);
    expect(om({ a: 1 }, {})).toBe(true);
    expect(om({ a: 1 }, { a: 1 })).toBe(true);
    expect(om({ a: 1 }, { a: '1' })).toBe(false);
    expect(om({}, { a: 1 })).toBe(false);
  });
  it('queryCovers: non-objects never cover; every query key must be in the filter with an equal value', () => {
    expect(qc(null as never, {})).toBe(false);
    expect(qc([] as never, {})).toBe(false);
    expect(qc({}, null as never)).toBe(false);
    expect(qc({}, [] as never)).toBe(false);
    expect(qc({}, { a: 1 })).toBe(true);
    expect(qc({ a: 1 }, { a: 1 })).toBe(true);
    expect(qc({ a: 1 }, {})).toBe(false);
    expect(qc({ a: true }, { a: 'true' })).toBe(false);
  });
});

describe('validateOfferPolicy: exact reasons', () => {
  const sk = 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk';
  it('a well-formed policy is null (pq_pk is an allowed optional key member)', () => {
    expect(vp(policy())).toBeNull();
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk, pq_pk: 'PQ' }] }))).toBeNull();
    expect(vp(policy({ max_age_ms: 0 }))).toBeNull();
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk }, { kid: 'k2', pk: SITE2.pk }] }))).toBeNull();
  });
  it('container, closed member set', () => {
    expect(vp(null)).toBe('offers policy must be an object');
    expect(vp([])).toBe('offers policy must be an object');
    expect(vp(policy({ extra: 1 }))).toBe("unknown member 'offers.extra'");
    expect(vp(policy({ 'Stryker was here': 1 }))).toBe("unknown member 'offers.Stryker was here'");
    const { filter: _f, ...noFilter } = policy();
    expect(vp(noFilter)).toBe("missing member 'offers.filter'");
  });
  it('name, site keys', () => {
    expect(vp(policy({ name: 5 }))).toBe('offers policy needs a name');
    expect(vp(policy({ site_keys: [] }))).toBe('offers policy needs at least one pinned site key');
    expect(vp(policy({ site_keys: 'k' }))).toBe('offers policy needs at least one pinned site key');
    expect(vp(policy({ site_keys: { length: 1, 0: { kid: 'k1', pk: SITE.pk } } }))).toBe('offers policy needs at least one pinned site key');
    expect(vp(policy({ site_keys: [null] }))).toBe(sk);
    expect(vp(policy({ site_keys: ['k1'] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk, extra: 1 }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1' }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: '', pk: SITE.pk }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: 'short' }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk, pq_pk: '' }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk, pq_pk: 1 }] }))).toBe(sk);
    expect(vp(policy({ site_keys: [{ kid: 'k1', pk: SITE.pk }, { kid: 'k1', pk: SITE2.pk }] }))).toBe(sk);
  });
  it('max_age_ms, offer_param', () => {
    const mm = 'offers policy: max_age_ms must be a non-negative safe integer';
    expect(vp(policy({ max_age_ms: -1 }))).toBe(mm);
    expect(vp(policy({ max_age_ms: 1.5 }))).toBe(mm);
    const pm = 'offers policy: offer_param must be an action.params.* path';
    expect(vp(policy({ offer_param: 5 }))).toBe(pm);
    expect(vp(policy({ offer_param: 'offer_id' }))).toBe(pm);
    expect(vp(policy({ offer_param: 'action.offer_id' }))).toBe(pm);
  });
  it('filter: exactly {query: {}, offer: {}} with scalar values', () => {
    const fm = 'offers policy: filter must be exactly {query: {}, offer: {}}';
    expect(vp(policy({ filter: null }))).toBe(fm);
    expect(vp(policy({ filter: [] }))).toBe(fm);
    expect(vp(policy({ filter: { query: {} } }))).toBe(fm);
    expect(vp(policy({ filter: { query: {}, offer: {}, 'Stryker was here': {} } }))).toBe(fm);
    expect(vp(policy({ filter: { query: null, offer: {} } }))).toBe(fm);
    expect(vp(policy({ filter: { query: {}, offer: [] } }))).toBe(fm);
    expect(vp(policy({ filter: { query: {}, offer: {} } }))).toBeNull();
    const vm = 'offers policy: filter values must be scalars';
    expect(vp(policy({ filter: { query: { a: null }, offer: {} } }))).toBe(vm);
    expect(vp(policy({ filter: { query: {}, offer: { a: [1] } } }))).toBe(vm);
  });
});

describe('decideOfferSet: exact reasons in order', () => {
  it('success: excess over the cheapest offer satisfying the filter', () => {
    expect(decide(signed())).toEqual({ ok: true, excess: 900, chosen_price: 39_800, min_price: 38_900 });
    expect(decide(signed(), { params: { offer_id: 'OF-1' } })).toEqual({ ok: true, excess: 0, chosen_price: 38_900, min_price: 38_900 });
    // equal prices: the minimum is the shared price
    const tie = signed({ offers: [{ offer_id: 'A', price: 5, refundable: false }, { offer_id: 'B', price: 5, refundable: false }] });
    expect(decide(tie, { params: { offer_id: 'B' } })).toEqual({ ok: true, excess: 0, chosen_price: 5, min_price: 5 });
  });
  it('non-object input', () => {
    expect(decideOfferSet(null as never)).toEqual({ ok: false, reason: 'offers: input must be an object' });
    expect(decideOfferSet([] as never)).toEqual({ ok: false, reason: 'offers: input must be an object' });
  });
  it('an internal throw is an evaluation error (Error message, else unknown)', () => {
    const boom = policy();
    Object.defineProperty(boom, 'name', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(decide(signed(), { policy: boom })).toEqual({ ok: false, reason: 'offers: evaluation error (fail closed): boom' });
    const raw = policy();
    Object.defineProperty(raw, 'name', { enumerable: true, get: () => { throw 'raw'; } });
    expect(decide(signed(), { policy: raw })).toEqual({ ok: false, reason: 'offers: evaluation error (fail closed): unknown' });
  });
  it('policy, commitment, supply, wire', () => {
    expect(decide(signed(), { policy: policy({ max_age_ms: -1 }) })).toEqual({ ok: false, reason: 'offers: policy misconfigured (fail closed): offers policy: max_age_ms must be a non-negative safe integer' });
    expect(decide(signed(), { committed: undefined })).toEqual({ ok: false, reason: 'offers: the PCActn commits no offer set but the policy requires one' });
    expect(decide(undefined, { committed: offerSetRef(signed()) })).toEqual({ ok: false, reason: 'offers: the committed offer set was not supplied' });
    const bad = { ...signed(), extra: 1 };
    expect(decide(bad, { committed: offerSetRef(signed()) })).toEqual({ ok: false, reason: "offers: unknown member 'offer_set.extra'" });
  });
  it('a lone surrogate has no strict-canonical reference', () => {
    const os = { ...signed(), query: { from: '\uD800' } };
    expect(vw(os)).toBeNull();
    expect(decide(os, { committed: offerSetRef(signed()) })).toEqual({ ok: false, reason: 'offers: the offer set is not strictly canonical' });
  });
  it('reference, suite, pin, signature', () => {
    expect(decide(signed(), { committed: b64u(seed('other')) })).toEqual({ ok: false, reason: 'offers: the supplied offer set does not match the committed reference' });
    const alg = { ...signed(), alg: 'no-such-suite' };
    expect(artifactSuiteError(alg)).not.toBeNull();
    expect(decide(alg)).toEqual({ ok: false, reason: `offers: signature suite: ${artifactSuiteError(alg)}` });
    expect(decide(signed({ kid: 'k9' }))).toEqual({ ok: false, reason: "offers: signing key 'k9' is not pinned" });
    expect(decide(signed({}, SITE2.sk))).toEqual({ ok: false, reason: 'offers: bad site signature' });
    expect(decide(signed({ kid: 'k2' }, SITE2.sk), { policy: policy({ site_keys: [{ kid: 'k1', pk: SITE.pk }, { kid: 'k2', pk: SITE2.pk }] }) })).toMatchObject({ ok: true, excess: 900 });
  });
  it('audience, session, clock, freshness', () => {
    expect(decide(signed(), { aud: 'other.example' })).toEqual({ ok: false, reason: 'offers: the offer set was issued for another audience' });
    expect(decide(signed(), { session: b64u(seed('s2')) })).toEqual({ ok: false, reason: 'offers: the offer set is bound to another session' });
    const clock = 'offers: no usable clock (now must be a safe integer): the offer set counts as stale';
    expect(decide(signed(), { now: Number.NaN })).toEqual({ ok: false, reason: clock });
    expect(decide(signed(), { now: NOW + 0.5 })).toEqual({ ok: false, reason: clock });
    expect(decide(signed(), { skewMs: Number.NaN })).toEqual({ ok: false, reason: clock });
    expect(decide(signed({ issued_at: NOW + 60_001 }))).toEqual({ ok: false, reason: 'offers: the offer set is issued in the future' });
    expect(decide(signed({ issued_at: NOW + 60_000 }))).toMatchObject({ ok: true });
    expect(decide(signed({ issued_at: NOW - 600_001 }))).toEqual({ ok: false, reason: 'offers: the offer set is stale' });
    expect(decide(signed({ issued_at: NOW - 600_000 }))).toMatchObject({ ok: true });
  });
  it('completeness, coverage, chosen offer, filter', () => {
    expect(decide(signed({ complete: false }))).toEqual({ ok: false, reason: 'offers: the offer set is not declared complete' });
    expect(decide(signed({ query: { ...Q, stops: 0 } }))).toEqual({ ok: false, reason: 'offers: the search was narrowed beyond the intent filter (coverage)' });
    const noId = 'offers: the action names no offer id at the declared parameter';
    expect(decide(signed(), { params: {} })).toEqual({ ok: false, reason: noId });
    expect(decide(signed(), { params: { offer_id: 7 } })).toEqual({ ok: false, reason: noId });
    expect(decide(signed(), { params: { offer_id: 'OF-9' } })).toEqual({ ok: false, reason: 'offers: the chosen offer is not in the signed offer set' });
    expect(decide(signed(), { params: { offer_id: 'OF-3' } })).toEqual({ ok: false, reason: 'offers: the chosen offer does not satisfy the intent filter' });
  });
});
