// Exact-verdict kill tests for confirmation.ts: the dismissal order of the signed body, the pin-set checks, and every refusal
// reason of verbConfirmationError (each one asserted by its exact message, so no refusal can be swapped for another).
import { canonicalBytesStrict, utf8, verifyB64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, CORE_REGISTRY, factsDigest, toSchemaVerb, traitsDigest, verbConfirmationError, type ConfirmableVerb, type ReviewRef, type ReviewerPins } from '../src';
import { REVIEW_DOMAIN, reviewMessage, reviewerPinsError, signReview } from '../src/confirmation';
import { TEST_PINS, TEST_REVIEWER, TEST_REVIEWER_KEY, TEST_TS, confirmed, testReview } from './reviewed';

type Body = Omit<ReviewRef, 'sig'>;
type Dismissal = { trait: string; reason: string };

const refund = BUILTIN_DEFS.find((d) => d.verb === 'stripe.refund')!;

/** A verb as the signer sees it (no confirmation yet): it carries pca.irreversible and pca.money_moving. */
const baseVerb = (): ConfirmableVerb => {
  const v = JSON.parse(JSON.stringify(toSchemaVerb(confirmed(refund), CORE_REGISTRY, testReview()).verb)) as ConfirmableVerb;
  delete v.confirmation;
  return v;
};
const bodyFor = (v: ConfirmableVerb): Body => ({
  def_digest: v.def!,
  traits_digest: traitsDigest(CORE_REGISTRY),
  facts_digest: factsDigest(v),
  final_traits: ['pca.irreversible'],
  dismissed: [],
  reviewer_kid: TEST_REVIEWER.kid,
  ts: TEST_TS,
});
const conf = (v: ConfirmableVerb, over: Partial<Body> = {}): ReviewRef => signReview({ ...bodyFor(v), ...over }, TEST_REVIEWER.secret);
const withConf = (v: ConfirmableVerb, c: unknown): ConfirmableVerb => ({ ...v, confirmation: c as ReviewRef });
const verifyWith = (v: ConfirmableVerb, pins: ReviewerPins | undefined): string | null => verbConfirmationError(v, CORE_REGISTRY, pins);
const verify = (v: ConfirmableVerb, pins: ReviewerPins = TEST_PINS): string | null => verifyWith(v, pins);

const permutations = <T>(xs: readonly T[]): T[][] => (xs.length <= 1 ? [[...xs]] : xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((rest) => [x, ...rest])));

const D = [
  { trait: 'pca.bulk', reason: 'capped upstream' },
  { trait: 'pca.destructive', reason: 'only archives' },
  { trait: 'pca.scheduled', reason: 'runs once' },
];

/** The signed bytes, rebuilt independently: the domain, a NUL, and the strict canonical body with the given dismissal list as is. */
const expectedMessage = (b: Body, dismissed: Dismissal[]): Uint8Array => {
  const body = canonicalBytesStrict({
    def_digest: b.def_digest, traits_digest: b.traits_digest, facts_digest: b.facts_digest, final_traits: [...b.final_traits],
    dismissed, reviewer_kid: b.reviewer_kid, ts: b.ts,
  });
  const dom = utf8(`${REVIEW_DOMAIN}\0`);
  const out = new Uint8Array(dom.length + body.length);
  out.set(dom);
  out.set(body, dom.length);
  return out;
};

describe('the dismissal list of a review is signed in trait order', () => {
  const b = bodyFor(baseVerb());
  it('reviewMessage signs the dismissals sorted by trait, whatever order they arrive in', () => {
    for (const p of permutations(D)) expect(Array.from(reviewMessage({ ...b, dismissed: p }))).toEqual(Array.from(expectedMessage(b, D)));
  });
  it('two dismissals of one trait keep their given order (the sort is stable)', () => {
    const one = [{ trait: 'pca.bulk', reason: 'first reason' }, { trait: 'pca.bulk', reason: 'second reason' }];
    expect(Array.from(reviewMessage({ ...b, dismissed: one }))).toEqual(Array.from(expectedMessage(b, one)));
    const two = [one[1]!, one[0]!];
    expect(Array.from(reviewMessage({ ...b, dismissed: two }))).toEqual(Array.from(expectedMessage(b, two)));
  });
  it('signReview returns the dismissals sorted by trait', () => {
    for (const p of permutations(D)) expect(signReview({ ...b, dismissed: p }, TEST_REVIEWER.secret).dismissed).toEqual(D);
    expect(signReview({ ...b, dismissed: [D[0]!, D[1]!] }, TEST_REVIEWER.secret).dismissed).toEqual([D[0], D[1]]);
  });
  it('signReview keeps two dismissals of one trait in their given order', () => {
    const one = [{ trait: 'pca.bulk', reason: 'first reason' }, { trait: 'pca.bulk', reason: 'second reason' }];
    expect(signReview({ ...b, dismissed: one }, TEST_REVIEWER.secret).dismissed).toEqual(one);
  });
});

describe('a long dismissal list is signed in trait order (runs are merged by the engine sort)', () => {
  const b = bodyFor(baseVerb());
  const N = 300;
  const entry = (i: number): Dismissal => ({ trait: `pca.t${String(i).padStart(3, '0')}`, reason: `reason ${i}` });
  const all = Array.from({ length: N }, (_, i) => entry(i));
  const shapes: Record<string, Dismissal[]> = {
    'two interleaved descending runs': [...all.filter((_, i) => i % 2 === 0).reverse(), ...all.filter((_, i) => i % 2 === 1).reverse()],
    'two descending runs in blocks of 25': [
      ...all.filter((_, i) => Math.floor(i / 25) % 2 === 0).reverse(),
      ...all.filter((_, i) => Math.floor(i / 25) % 2 === 1).reverse(),
    ],
    'one descending run': [...all].reverse(),
    'a fixed shuffle': (() => {
      const xs = [...all];
      let seed = 12345;
      for (let i = xs.length - 1; i > 0; i--) {
        seed = (seed * 1103515245 + 12345) % 2147483648;
        const j = seed % (i + 1);
        [xs[i], xs[j]] = [xs[j]!, xs[i]!];
      }
      return xs;
    })(),
  };
  for (const [name, input] of Object.entries(shapes)) {
    it(`${name}: the signed bytes are those of the independently sorted list, and the signature verifies both ways`, () => {
      expect(input).toHaveLength(N);
      const want = expectedMessage(b, all);
      expect(Array.from(reviewMessage({ ...b, dismissed: input }))).toEqual(Array.from(want));
      const signed = signReview({ ...b, dismissed: input }, TEST_REVIEWER.secret);
      expect(signed.dismissed).toEqual(all);
      expect(verifyB64u(TEST_REVIEWER_KEY.pk, want, signed.sig!)).toBe(true);
      expect(verifyB64u(TEST_REVIEWER_KEY.pk, reviewMessage({ ...b, dismissed: input }), signed.sig!)).toBe(true);
    });
  }
  it('many dismissals of the same traits keep their given order (stable), across merged runs', () => {
    const twice: Dismissal[] = [];
    for (let i = N / 2 - 1; i >= 0; i--) twice.push({ trait: entry(i).trait, reason: `second ${i}` }, { trait: entry(i).trait, reason: `first ${i}` });
    const stable = Array.from({ length: N / 2 }, (_, i) => [{ trait: entry(i).trait, reason: `second ${i}` }, { trait: entry(i).trait, reason: `first ${i}` }]).flat();
    expect(Array.from(reviewMessage({ ...b, dismissed: twice }))).toEqual(Array.from(expectedMessage(b, stable)));
    expect(signReview({ ...b, dismissed: twice }, TEST_REVIEWER.secret).dismissed).toEqual(stable);
  });
});

describe('verbConfirmationError: members that are absent or throw', () => {
  const v = baseVerb();
  const good = conf(v);
  it('a verb without a def and a confirmation without a def digest do not match each other', () => {
    const w = withConf(v, { ...good, def_digest: undefined as never });
    delete w.def;
    expect(verify(w)).toBe('the confirmation covers a different def digest');
  });
  it('a verb without traits carries nothing, whatever the sentinel text of a signed trait', () => {
    const w = withConf(v, conf(v, { final_traits: ['Stryker was here'] }));
    delete w.traits;
    expect(verify(w)).toBe('the verb does not carry every trait the reviewer signed');
  });
  it('an error thrown while reading the verb is reported with its message, never as a pass', () => {
    const w = withConf(v, good);
    Object.defineProperty(w, 'traits', { enumerable: true, get: () => { throw new Error('boom'); } });
    expect(verify(w)).toBe('malformed confirmation: boom');
  });
});

describe('reviewerPinsError: every member of a pin set is checked exactly', () => {
  const key = TEST_REVIEWER_KEY;
  it('refuses a pin set that is not an object with a keys array', () => {
    expect(reviewerPinsError(undefined as never)).toBe('pins must be {keys: [...]}');
    expect(reviewerPinsError(null as never)).toBe('pins must be {keys: [...]}');
    expect(reviewerPinsError(5 as never)).toBe('pins must be {keys: [...]}');
    expect(reviewerPinsError({ keys: 'x' } as never)).toBe('pins must be {keys: [...]}');
    expect(reviewerPinsError({ keys: [key] })).toBeNull();
  });
  it('a key needs a string kid of 1..128 characters', () => {
    const msg = 'a pinned key needs a kid';
    expect(reviewerPinsError({ keys: [null as never] })).toBe(msg);
    expect(reviewerPinsError({ keys: [{ ...key, kid: 5 as never }] })).toBe(msg);
    expect(reviewerPinsError({ keys: [{ ...key, kid: '' }] })).toBe(msg);
    expect(reviewerPinsError({ keys: [{ ...key, kid: 'k'.repeat(129) }] })).toBe(msg);
    expect(reviewerPinsError({ keys: [{ ...key, kid: 'k'.repeat(128) }] })).toBeNull();
  });
  it('every role must be a known role', () => {
    expect(reviewerPinsError({ keys: [{ ...key, kid: 'k1', roles: ['reviewer', 'bogus' as never] }] })).toBe("key 'k1': roles must be distinct known roles");
    expect(reviewerPinsError({ keys: [{ ...key, kid: 'k1', roles: ['reviewer', 'publisher'] }] })).toBeNull();
  });
  it('a validity bound of zero is a valid non-negative integer; below zero is not', () => {
    expect(reviewerPinsError({ keys: [{ ...key, not_before: 0, not_after: 0 }] })).toBeNull();
    expect(reviewerPinsError({ keys: [{ ...key, not_before: -1 }] })).toBe(`key '${key.kid}': not_before must be a non-negative integer`);
    expect(reviewerPinsError({ keys: [{ ...key, not_after: -1 }] })).toBe(`key '${key.kid}': not_after must be a non-negative integer`);
  });
});

describe('verbConfirmationError: each refusal names its own reason', () => {
  const v = baseVerb();
  const good = conf(v);
  it('control: a confirmation signed by the pinned reviewer over this verb counts', () => {
    expect(v.traits).toEqual(['pca.irreversible', 'pca.money_moving']);
    expect(verify(withConf(v, good))).toBeNull();
  });
  it('no pins, or unsound pins, never count a confirmation', () => {
    expect(verifyWith(withConf(v, good), undefined)).toBe('no reviewer keys are pinned');
    const bad: ReviewerPins = { keys: [TEST_REVIEWER_KEY, { kid: '', pk: TEST_REVIEWER_KEY.pk, roles: ['reviewer'] }] };
    expect(verify(withConf(v, good), bad)).toBe('bad pins: a pinned key needs a kid');
  });
  it('a confirmation that is not an object', () => {
    for (const c of [null, 'text', 5, true]) expect(verify(withConf(v, c))).toBe('confirmation is not an object');
  });
  it('a confirmation without a signature is unsigned', () => {
    const c = { ...good };
    delete c.sig;
    expect(verify(withConf(v, c))).toBe('the confirmation is unsigned');
  });
  it('a confirmation of another def digest, or on a verb without one, is refused', () => {
    expect(verify({ ...withConf(v, good), def: 'B'.repeat(43) })).toBe('the confirmation covers a different def digest');
    const w = withConf(v, good);
    delete w.def;
    expect(verify(w)).toBe('the confirmation covers a different def digest');
  });
  it('a confirmation made against another trait registry is refused unless the pins accept that digest', () => {
    const msg = 'the confirmation was made against a different trait registry';
    expect(verify(withConf(v, { ...good, traits_digest: 'C'.repeat(43) }))).toBe(msg);
    const other = conf(v, { traits_digest: 'Stryker was here' });
    expect(verify(withConf(v, other))).toBe(msg);
    const earlier = conf(v, { traits_digest: 'an-earlier-registry' });
    expect(verify(withConf(v, earlier))).toBe(msg);
    expect(verify(withConf(v, earlier), { ...TEST_PINS, traits_digests: ['an-earlier-registry'] })).toBeNull();
  });
  it('a verb whose facts changed after confirmation is refused', () => {
    expect(verify({ ...withConf(v, good), description: 'changed after review' })).toBe('the verb facts differ from the facts the reviewer confirmed');
  });
  it('a confirmation with a malformed member is refused as malformed, never read further', () => {
    for (const bad of [
      { ...good, final_traits: 'pca.bulk' as never },
      { ...good, dismissed: 'x' as never },
      { ...good, ts: 1.5 },
      { ...good, reviewer_kid: 5 as never },
    ]) expect(verify(withConf(v, bad))).toBe('malformed confirmation');
  });
  it('the verb must carry every trait the reviewer signed', () => {
    const msg = 'the verb does not carry every trait the reviewer signed';
    expect(verify(withConf(v, conf(v, { final_traits: ['pca.bulk'] })))).toBe(msg);
    expect(verify(withConf(v, conf(v, { final_traits: ['pca.irreversible', 'pca.money_moving'] })))).toBeNull();
    // a signed final trait that is not a string is refused even when the verb lists the very same value
    const odd = { ...v, traits: [5 as never] };
    expect(verify(withConf(odd, conf(odd, { final_traits: [5 as never] })))).toBe(msg);
  });
  describe('dismissals', () => {
    const msg = 'a dismissed trait is also final, or has no reason';
    it('a dismissal of a trait that is not final, with a real reason, counts', () => {
      expect(verify(withConf(v, conf(v, { dismissed: [{ trait: 'pca.bulk', reason: 'capped upstream' }] })))).toBeNull();
      expect(verify(withConf(v, conf(v, { dismissed: [{ trait: 'pca.scheduled', reason: 'runs once' }, { trait: 'pca.bulk', reason: 'capped upstream' }] })))).toBeNull();
    });
    it('a dismissed trait that is also final is refused', () => {
      expect(verify(withConf(v, conf(v, { dismissed: [{ trait: 'pca.irreversible', reason: 'because' }] })))).toBe(msg);
    });
    it('a blank reason is refused', () => {
      for (const reason of ['', '   ', '\u001c\u001f', ' \t\n ']) expect(verify(withConf(v, conf(v, { dismissed: [{ trait: 'pca.bulk', reason }] }))), JSON.stringify(reason)).toBe(msg);
    });
    it('a dismissal that is not {trait: string, reason: string} is refused', () => {
      for (const d of [{ trait: 'pca.bulk', reason: 5 }, { trait: 5, reason: 'because' }, null, 'pca.bulk']) expect(verify(withConf(v, { ...good, dismissed: [d] })), JSON.stringify(d)).toBe(msg);
    });
  });
  describe('the validity window of the key', () => {
    const msg = 'the confirmation time is outside the key validity';
    const pinned = (w: { not_before?: number; not_after?: number }): ReviewerPins => ({ keys: [{ ...TEST_REVIEWER_KEY, ...w }] });
    it('before not_before is refused; at and after it counts', () => {
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS + 1 }))).toBe(msg);
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS }))).toBeNull();
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS - 1 }))).toBeNull();
    });
    it('after not_after is refused; at and before it counts', () => {
      expect(verify(withConf(v, good), pinned({ not_after: TEST_TS - 1 }))).toBe(msg);
      expect(verify(withConf(v, good), pinned({ not_after: TEST_TS }))).toBeNull();
      expect(verify(withConf(v, good), pinned({ not_after: TEST_TS + 100 }))).toBeNull();
    });
    it('inside a two-sided window counts', () => {
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS - 10, not_after: TEST_TS + 10 }))).toBeNull();
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS + 5, not_after: TEST_TS + 10 }))).toBe(msg);
      expect(verify(withConf(v, good), pinned({ not_before: TEST_TS - 10, not_after: TEST_TS - 5 }))).toBe(msg);
    });
  });
  it('a changed body fails the signature with its own reason', () => {
    expect(verify(withConf(v, { ...good, ts: good.ts + 1 }))).toBe('the confirmation signature is invalid');
  });
});
