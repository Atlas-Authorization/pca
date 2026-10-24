import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { b64u, sha256, utf8 } from './hash';
import { publicKeyOf } from './keys';
import { evaluatePredicates } from './predicates';
import {
  decideIntentWorld,
  factRef,
  lowerMedian,
  ratioPpm,
  signFact,
  validateWorldPolicy,
  type IntentWorldInput,
  type IntentWorldPolicy,
  type PcaFact,
} from './oracle-facts';
import { decideOfferSet, offerSetRef, queryCovers, signOfferSet, type OfferPolicy, type PcaOfferSet } from './offer-set';

// Intent Layer v2 milestone V6 (world facts, offer sets, optimality): rule 16, T19, T25.

const seed = (l: string) => sha256(utf8(`atlas-pca-test/intent-world/${l}`));
const key = (l: string) => ({ sk: seed(l), pk: b64u(publicKeyOf(seed(l))) });
const O1 = key('oracle-1');
const O2 = key('oracle-2');
const O3 = key('oracle-3');
const ROGUE = key('rogue');
const SITE = key('site');
const NOW = 1_800_000_000_000;
const SESSION = b64u(seed('session'));
const AUD = 'skyair.example';

const fact = (o: { sk: Uint8Array }, kid: string, name: string, value: number | string, t_obs = NOW - 1_000, subject = 'OF-2'): PcaFact =>
  signFact({ name, subject, value, t_obs, oracle: kid }, o.sk);

const fareWorld = (min = 3, f = 1, freshness = 60_000): IntentWorldPolicy['worlds'] => [
  { name: 'fare', subject_path: 'action.params.offer_id', oracles: [{ kid: 'o1', pk: O1.pk }, { kid: 'o2', pk: O2.pk }, { kid: 'o3', pk: O3.pk }], freshness_ms: freshness, min_oracles: min, max_faulty: f },
];

const input = (facts: PcaFact[], policy: IntentWorldPolicy, over: Partial<IntentWorldInput> = {}): IntentWorldInput => ({
  now: NOW,
  aud: AUD,
  session: SESSION,
  action: { verb: 'air.book', resource: 'skyair.example/bookings', params: { offer_id: 'OF-2', total: 77_800, quote: 38_900 } },
  committed: { facts: facts.map(factRef) },
  facts,
  policy,
  ...over,
});

describe('rule 16: oracle facts', () => {
  const three = () => [fact(O1, 'o1', 'fare', 39_800), fact(O2, 'o2', 'fare', 39_900), fact(O3, 'o3', 'fare', 1)];

  it('fills env.world with the lower median of fresh facts from distinct pinned oracles', () => {
    const r = decideIntentWorld(input(three(), { worlds: fareWorld() }));
    expect(r).toEqual({ ok: true, world: { fare: 39_800 }, single_source: [] });
  });

  it('the filled value is readable by the one predicate evaluator at env.world.<name>', () => {
    const r = decideIntentWorld(input(three(), { worlds: fareWorld() }));
    expect(r.ok).toBe(true);
    const env = { world: (r as { world: Record<string, number | string> }).world };
    const ctx = { action: { verb: 'air.book', resource: 'r' }, env };
    expect(evaluatePredicates([{ verb: 'air.book', where: [{ field: 'env.world.fare', op: 'lte', value: 40_000 }] }], ctx).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: 'air.book', where: [{ field: 'env.world.fare', op: 'lte', value: 39_000 }] }], ctx).allowed).toBe(false);
  });

  it('fails closed when fewer than min_oracles facts are fresh (stale and future facts are not counted)', () => {
    const facts = [fact(O1, 'o1', 'fare', 1, NOW - 60_001), fact(O2, 'o2', 'fare', 2, NOW + 60_001), fact(O3, 'o3', 'fare', 3)];
    const r = decideIntentWorld(input(facts, { worlds: fareWorld() }));
    expect(r.ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/1 fresh fact/);
  });

  it('freshness and skew bounds are inclusive', () => {
    const facts = [fact(O1, 'o1', 'fare', 5, NOW - 60_000), fact(O2, 'o2', 'fare', 6, NOW + 60_000), fact(O3, 'o3', 'fare', 7)];
    expect(decideIntentWorld(input(facts, { worlds: fareWorld() }))).toMatchObject({ ok: true, world: { fare: 6 } });
  });

  it('refuses an unpinned oracle, a key that is not the pinned one, another subject, a duplicate oracle and an undeclared world', () => {
    const base = three();
    const unpinned = fact(O1, 'o9', 'fare', 1);
    expect(decideIntentWorld(input([...base.slice(0, 2), unpinned], { worlds: fareWorld() })).ok).toBe(false);
    const forged = fact(ROGUE, 'o3', 'fare', 1);
    expect(decideIntentWorld(input([...base.slice(0, 2), forged], { worlds: fareWorld() })).ok).toBe(false);
    const other = fact(O3, 'o3', 'fare', 1, NOW - 1_000, 'OF-1');
    expect(decideIntentWorld(input([...base.slice(0, 2), other], { worlds: fareWorld() })).ok).toBe(false);
    const dup = fact(O1, 'o1', 'fare', 2, NOW - 2_000);
    expect(decideIntentWorld(input([...base, dup], { worlds: fareWorld() })).ok).toBe(false);
    const undeclared = fact(O1, 'o1', 'tier', 'gold');
    expect(decideIntentWorld(input([...base, undeclared], { worlds: fareWorld() })).ok).toBe(false);
  });

  it('only committed facts count: an uncommitted supplied fact is ignored, a committed unsupplied one fails', () => {
    const base = three();
    const extra = fact(ROGUE, 'o1', 'fare', 999_999);
    const r = decideIntentWorld({ ...input(base, { worlds: fareWorld() }), facts: [...base, extra] });
    expect(r).toMatchObject({ ok: true, world: { fare: 39_800 } });
    const missing = decideIntentWorld({ ...input(base, { worlds: fareWorld() }), facts: base.slice(0, 2) });
    expect(missing.ok).toBe(false);
  });

  it('a committed digest list must be distinct canonical digests', () => {
    const base = three();
    expect(decideIntentWorld({ ...input(base, { worlds: fareWorld() }), committed: { facts: [factRef(base[0]!), factRef(base[0]!)] } }).ok).toBe(false);
    expect(decideIntentWorld({ ...input(base, { worlds: fareWorld() }), committed: { facts: ['not-a-digest'] } }).ok).toBe(false);
  });

  it('a tampered fact no longer matches its commitment', () => {
    const base = three();
    const committed = { facts: base.map(factRef) };
    const tampered = base.map((f, i) => (i === 0 ? { ...f, value: 1 } : f));
    expect(decideIntentWorld({ ...input(base, { worlds: fareWorld() }), committed, facts: tampered }).ok).toBe(false);
  });

  it('string facts must all agree; a mix of strings and integers fails', () => {
    const tier = (v1: string, v2: string, v3: string | number) => [fact(O1, 'o1', 'fare', v1), fact(O2, 'o2', 'fare', v2), fact(O3, 'o3', 'fare', v3)];
    expect(decideIntentWorld(input(tier('gold', 'gold', 'gold'), { worlds: fareWorld() }))).toMatchObject({ ok: true, world: { fare: 'gold' } });
    expect(decideIntentWorld(input(tier('gold', 'gold', 'silver'), { worlds: fareWorld() })).ok).toBe(false);
    expect(decideIntentWorld(input(tier('gold', 'gold', 3), { worlds: fareWorld() })).ok).toBe(false);
  });

  it('reports single-source worlds', () => {
    const r = decideIntentWorld(input([fact(O1, 'o1', 'fare', 5)], { worlds: fareWorld(1, 0) }));
    expect(r).toMatchObject({ ok: true, single_source: ['fare'] });
  });

  it('policy sanity: min_oracles >= 2f+1, names, operands (fail closed)', () => {
    expect(validateWorldPolicy({ worlds: fareWorld(2, 1) })).toMatch(/2\*max_faulty\+1/);
    expect(decideIntentWorld(input(three(), { worlds: fareWorld(2, 1) })).ok).toBe(false);
    expect(validateWorldPolicy({ relational: [{ name: 'Bad', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] })).toMatch(/must match/);
    expect(validateWorldPolicy({ relational: [{ name: 'x', fn: 'sub', a: 'env.world.later', b: 'action.params.quote' }, { name: 'later', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] })).toMatch(/earlier/);
    expect(validateWorldPolicy({ worlds: fareWorld(), relational: [{ name: 'fare', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' }] })).toMatch(/duplicate/);
  });

  it('T19 (robust median): with n >= 2f+1 fresh facts and at most f arbitrary liars, the lower median lies within the honest range', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 4 }).chain((f) =>
          fc.tuple(
            fc.constant(f),
            fc.array(fc.integer({ min: -1e9, max: 1e9 }), { minLength: f + 1, maxLength: f + 6 }),
            fc.array(fc.integer({ min: -1e12, max: 1e12 }), { minLength: 0, maxLength: f }),
          ),
        ),
        ([f, honest, lies]) => {
          fc.pre(honest.length + lies.length >= 2 * f + 1);
          const m = lowerMedian([...honest, ...lies]);
          return m >= Math.min(...honest) && m <= Math.max(...honest);
        },
      ),
    );
  });

  it('T19 (freshness): an admitted world value is the value of a fact observed in [now − Δ, now + skew]', () => {
    fc.assert(
      fc.property(fc.array(fc.tuple(fc.integer({ min: -200_000, max: 200_000 }), fc.integer({ min: 0, max: 1_000_000 })), { minLength: 3, maxLength: 3 }), (spec) => {
        const facts = spec.map(([dt, v], i) => fact([O1, O2, O3][i]!, `o${i + 1}`, 'fare', v, NOW + dt));
        const r = decideIntentWorld(input(facts, { worlds: fareWorld(1, 0, 60_000) }));
        if (!r.ok) return facts.every((f) => f.t_obs > NOW + 60_000 || NOW - f.t_obs > 60_000);
        return facts.some((f) => f.value === r.world.fare && f.t_obs >= NOW - 60_000 && f.t_obs <= NOW + 60_000);
      }),
      { numRuns: 40 },
    );
  });
});

describe('rule 16: relational dimensions', () => {
  it('sub and ratio_ppm over parameters and earlier world values', () => {
    const facts = [fact(O1, 'o1', 'fare', 38_900)];
    const policy: IntentWorldPolicy = {
      worlds: fareWorld(1, 0),
      relational: [
        { name: 'excess_vs_quote', fn: 'sub', a: 'action.params.total', b: 'action.params.quote' },
        { name: 'vs_fare', fn: 'sub', a: 'action.params.quote', b: 'env.world.fare' },
        { name: 'ratio', fn: 'ratio_ppm', a: 'action.params.total', b: 'env.world.fare' },
      ],
    };
    expect(decideIntentWorld(input(facts, policy))).toMatchObject({ ok: true, world: { fare: 38_900, excess_vs_quote: 38_900, vs_fare: 0, ratio: 2_000_000 } });
  });

  it('ratio_ppm is exact integer floor division and fails on b <= 0, a < 0 or overflow', () => {
    expect(ratioPpm(1, 3)).toBe(333_333);
    expect(ratioPpm(2 ** 52, 1)).toBeNull();
    expect(ratioPpm(5, 0)).toBeNull();
    expect(ratioPpm(-5, 3)).toBeNull();
    fc.assert(fc.property(fc.integer({ min: 0, max: 1e9 }), fc.integer({ min: 1, max: 1e9 }), (a, b) => ratioPpm(a, b) === Number((BigInt(a) * 1_000_000n) / BigInt(b))));
  });

  it('a missing or non-integer operand fails closed', () => {
    const policy: IntentWorldPolicy = { relational: [{ name: 'x', fn: 'sub', a: 'action.params.total', b: 'action.params.nope' }] };
    expect(decideIntentWorld(input([], policy)).ok).toBe(false);
  });
});

// ---- offer sets (rule 16 step 6, T25) -------------------------------------------------------------------------

const OFFERS = [
  { offer_id: 'OF-1', price: 38_900, stops: 1, refundable: false },
  { offer_id: 'OF-2', price: 39_800, stops: 0, refundable: false },
  { offer_id: 'OF-3', price: 41_200, stops: 0, refundable: true },
];
const offerSet = (over: Partial<Omit<PcaOfferSet, 'sig'>> = {}, sk = SITE.sk): PcaOfferSet =>
  signOfferSet({ v: 1, kind: 'pca-offer-set', site: AUD, session: SESSION, query: { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 }, rank: 'price_asc', complete: true, offers: OFFERS, issued_at: NOW - 10_000, kid: 'skyair-2026', ...over }, sk);
const offerPolicy = (over: Partial<OfferPolicy> = {}): OfferPolicy => ({
  name: 'excess_cents',
  site_keys: [{ kid: 'skyair-2026', pk: SITE.pk }],
  max_age_ms: 600_000,
  offer_param: 'action.params.offer_id',
  filter: { query: { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2 }, offer: { refundable: false } },
  ...over,
});
const decide = (os: unknown, params: Record<string, unknown> = { offer_id: 'OF-2' }, policy = offerPolicy(), committed: string | undefined = offerSetRef(os as PcaOfferSet)) =>
  decideOfferSet({ policy, committed, offerSet: os, params, aud: AUD, session: SESSION, now: NOW, skewMs: 60_000 });

describe('rule 16: signed offer sets and the excess dimension', () => {
  it('excess = chosen price − cheapest offer that satisfies the intent filter (site-signed prices)', () => {
    expect(decide(offerSet())).toEqual({ ok: true, excess: 900, chosen_price: 39_800, min_price: 38_900 });
    expect(decide(offerSet(), { offer_id: 'OF-1' })).toMatchObject({ ok: true, excess: 0 });
  });

  it('search-not-narrowed: a query with a constraint the intent filter lacks (or a different value) is refused', () => {
    expect(decide(offerSet({ query: { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: 2, stops: 0 } })).ok).toBe(false);
    expect(decide(offerSet({ query: { from: 'SFO', to: 'JFK', date: '2026-11-21', pax: 2 } })).ok).toBe(false);
    expect(decide(offerSet({ query: { from: 'SFO', to: 'JFK', date: '2026-11-20', pax: '2' } })).ok).toBe(false);
    // broader is fine
    expect(decide(offerSet({ query: { from: 'SFO', to: 'JFK' } })).ok).toBe(true);
  });

  it('refuses incomplete sets, unpinned or wrong keys, another audience or session, stale or future sets', () => {
    expect(decide(offerSet({ complete: false })).ok).toBe(false);
    expect(decide(offerSet({ kid: 'other' })).ok).toBe(false);
    expect(decide(offerSet({}, ROGUE.sk)).ok).toBe(false);
    expect(decide(offerSet({ site: 'evil.example' })).ok).toBe(false);
    expect(decide(offerSet({ session: b64u(seed('other-session')) })).ok).toBe(false);
    expect(decide(offerSet({ issued_at: NOW - 600_001 })).ok).toBe(false);
    expect(decide(offerSet({ issued_at: NOW + 60_001 })).ok).toBe(false);
    expect(decide(offerSet({ issued_at: NOW - 600_000 })).ok).toBe(true);
  });

  it('refuses a missing commitment, a mismatching commitment, a chosen offer outside the set or the filter', () => {
    const uncommitted = decideOfferSet({ policy: offerPolicy(), committed: undefined, offerSet: offerSet(), params: { offer_id: 'OF-2' }, aud: AUD, session: SESSION, now: NOW, skewMs: 60_000 });
    expect(uncommitted.ok).toBe(false);
    expect(decide(offerSet(), undefined, offerPolicy(), b64u(seed('x'))).ok).toBe(false);
    expect(decide(offerSet(), { offer_id: 'OF-9' }).ok).toBe(false);
    expect(decide(offerSet(), { offer_id: 'OF-3' }).ok).toBe(false); // refundable: true does not satisfy the filter
    expect(decide(offerSet(), { offer_id: 7 }).ok).toBe(false);
  });

  it('wire: duplicate offer ids, non-integer prices and unknown members are refused', () => {
    expect(decide(offerSet({ offers: [OFFERS[0]!, OFFERS[0]!] })).ok).toBe(false);
    const bad = { ...offerSet(), extra: 1 };
    expect(decide(bad, undefined, offerPolicy(), offerSetRef(bad as PcaOfferSet)).ok).toBe(false);
  });

  it('decideIntentWorld writes the excess under the policy name and requires the commitment', () => {
    const os = offerSet();
    const r = decideIntentWorld({ ...input([], { offers: offerPolicy() }), committed: { offer_set: offerSetRef(os) }, offer_set: os });
    expect(r).toMatchObject({ ok: true, world: { excess_cents: 900 } });
    expect(decideIntentWorld({ ...input([], { offers: offerPolicy() }), committed: {}, offer_set: os }).ok).toBe(false);
  });

  it('T25: with a complete, covering signed set, every admitted choice with excess <= s costs at most min + s', () => {
    const arbOffer = fc.record({ price: fc.integer({ min: 0, max: 100_000 }), refundable: fc.boolean() });
    fc.assert(
      fc.property(fc.array(arbOffer, { minLength: 1, maxLength: 12 }), fc.nat(), fc.integer({ min: 0, max: 5_000 }), (offers, pick, s) => {
        const list = offers.map((o, i) => ({ offer_id: `OF-${i}`, ...o }));
        const os = offerSet({ offers: list });
        const chosen = list[pick % list.length]!;
        const r = decide(os, { offer_id: chosen.offer_id });
        const matching = list.filter((o) => o.refundable === false);
        if (!r.ok) return chosen.refundable === true; // the only refusal here: a choice outside the filter
        const min = Math.min(...matching.map((o) => o.price));
        return r.excess >= 0 && (r.excess > s || chosen.price <= min + s);
      }),
      { numRuns: 60 },
    );
  });

  it('coverage is exactly keys(q) ⊆ keys(F.query) with equal scalar values', () => {
    fc.assert(
      fc.property(fc.dictionary(fc.constantFrom('a', 'b', 'c'), fc.integer({ min: 0, max: 2 })), fc.dictionary(fc.constantFrom('a', 'b', 'c'), fc.integer({ min: 0, max: 2 })), (q, f) => {
        const expected = Object.entries(q).every(([k, v]) => k in f && f[k] === v);
        return queryCovers(q, f) === expected;
      }),
    );
  });
});
