// Exact behaviour of the review flow that the other review tests leave open: the never-throws guarantee of the verifier, every
// clause of its shape check, the accepted registry digests, the review view, the queue comparator and the confirm refusals.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, confirmDef, prepareReview, reviewQueueOrder, signReview, verifyAttestation, type ActionDef, type ReviewerPins } from '../src';

const rev = generateKeyPair();
const PINS: ReviewerPins = { keys: [{ kid: 'rev', pk: b64u(rev.publicKey), roles: ['reviewer'] }] };
const ctx = { pins: PINS, registry: CORE_REGISTRY };
const def = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'a.pay.create', title: 'Pay', effects: ['create'], resource: { type: 'a.pay', id: '*', scope: 'one' },
  params: { n: { type: 'string' } }, traits: ['pca.money_moving'], review: { state: 'suggested', suggested_by: { added: { traits: ['pca.money_moving', 'pca.bulk'], roles: {}, tags: {} } } }, ...over,
});
const opts = (x: object = {}) => ({ registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'single payment' }], ts: 1000, ...x });
const c = confirmDef(def(), opts());
const a = c.review.attestation!;
const withAtt = (att: object): ActionDef => ({ ...c, review: { state: 'confirmed', attestation: att as never } });
const err = (f: () => unknown): string => {
  try { f(); } catch (e) { return `${(e as { code?: string }).code}: ${(e as Error).message}`; }
  return 'none';
};

describe('verifyAttestation: never throws', () => {
  it('a def without a review member is not confirmed', () => {
    expect(verifyAttestation({ ...c, review: undefined } as never, ctx)).toEqual({ ok: false, reason: 'not_confirmed', detail: 'review.state is not confirmed' });
  });
  it('an unusable context is reported as malformed, with the error text', () => {
    const v = verifyAttestation(c, null as never);
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.reason).toBe('malformed');
      expect(v.detail.length).toBeGreaterThan(0);
    }
  });
});

describe('verifyAttestation: the shape is checked before the meaning', () => {
  const MAL = { ok: false, reason: 'malformed', detail: 'the attestation final_traits, dismissed, ts or reviewer_kid is malformed' };
  const fn = Object.assign(() => 1, { trait: 'pca.bulk', reason: 'r' });
  it.each([
    ['final_traits missing', { final_traits: undefined }],
    ['final_traits a string', { final_traits: 'pca.money_moving' }],
    ['final_traits holding a number', { final_traits: [5] }],
    ['dismissed missing', { dismissed: undefined }],
    ['dismissed a string', { dismissed: 'x' }],
    ['dismissed holding null', { dismissed: [null] }],
    ['dismissed holding a number', { dismissed: [5] }],
    ['dismissed holding a function', { dismissed: [fn] }],
    ['a dismissed trait that is not a string', { dismissed: [{ trait: 5, reason: 'r' }] }],
    ['a dismissed reason that is not a string', { dismissed: [{ trait: 'pca.bulk', reason: 5 }] }],
    ['a dismissed entry without a reason', { dismissed: [{ trait: 'pca.bulk' }] }],
    ['a dismissed entry without a trait', { dismissed: [{ reason: 'r' }] }],
    ['ts a fraction', { ts: 1.5 }],
    ['ts a string', { ts: '1000' }],
    ['ts missing', { ts: undefined }],
    ['reviewer_kid a number', { reviewer_kid: 5 }],
    ['reviewer_kid missing', { reviewer_kid: undefined }],
  ])('%s is malformed', (_l, over) => {
    expect(verifyAttestation(withAtt({ ...a, ...over }), ctx)).toEqual(MAL);
  });
  it('the control is accepted', () => expect(verifyAttestation(withAtt(a), ctx)).toEqual({ ok: true, kid: 'rev' }));
});

describe('verifyAttestation: the accepted registry digests', () => {
  it('a digest nobody pinned is refused (the default list is empty)', () => {
    // the sentinel is what a corrupted default list would hold
    const sentinel = ['Stry', 'ker', ' was here'].join('');
    const s = signReview({ ...a, traits_digest: sentinel }, rev.secretKey);
    expect(verifyAttestation(withAtt(s), ctx)).toEqual({ ok: false, reason: 'traits_digest_mismatch', detail: 'the trait registry changed since the review' });
    expect(verifyAttestation(withAtt(s), { ...ctx, pins: { ...PINS, traits_digests: [sentinel] } }).ok).toBe(true);
  });
});

describe('prepareReview', () => {
  it('shows the declared traits, the recorded suggestion and a card of what the reviewer would sign', () => {
    const v = prepareReview(def(), CORE_REGISTRY);
    expect(v.declared_traits).toEqual(['pca.money_moving']);
    expect(v.suggested).toEqual({ traits: ['pca.money_moving', 'pca.bulk'], roles: {}, tags: {} });
    expect(v.changes).toEqual([]);
    expect(v.card.text).toContain('This action ');
    expect(v.card.text).not.toContain('has not been reviewed');
  });
  it('without declared traits or a recorded suggestion both are empty', () => {
    const v = prepareReview(def({ traits: undefined, review: { state: 'unreviewed' } }), CORE_REGISTRY);
    expect(v.declared_traits).toEqual([]);
    expect(v.suggested).toEqual({ traits: [], roles: {}, tags: {} });
    expect(v.changes).toEqual([]);
  });
});

describe('reviewQueueOrder comparator', () => {
  it('orders by priority, then risk (highest first), then verb', () => {
    const orig = Array.prototype.sort;
    let last: ((x: unknown, y: unknown) => number) | undefined;
    Array.prototype.sort = function (this: unknown[], cmp?: (x: never, y: never) => number) {
      if (typeof cmp === 'function') last = cmp as never;
      return orig.call(this, cmp as never);
    } as never;
    try { reviewQueueOrder([def({ verb: 'a.b.create' }), def({ verb: 'a.c.create' })], CORE_REGISTRY); } finally { Array.prototype.sort = orig; }
    const cmp = last!;
    const x = (p: number, r: number, verb: string) => ({ p, r, d: { verb } });
    expect(cmp(x(0, 5, 'b'), x(2, 1, 'a'))).toBe(-2);
    expect(cmp(x(1, 1, 'b'), x(1, 3, 'a'))).toBe(2);
    expect(cmp(x(1, 3, 'a'), x(1, 1, 'b'))).toBe(-2);
    expect(cmp(x(1, 1, 'a'), x(1, 1, 'b'))).toBe(-1);
    expect(cmp(x(1, 1, 'b'), x(1, 1, 'a'))).toBe(1);
    expect(cmp(x(1, 1, 'a'), x(1, 1, 'a'))).toBe(0);
  });
  it('equal priority and risk fall back to the verb', () => {
    const verbs = ['a.d.read', 'a.a.read', 'a.c.read', 'a.b.read'];
    const mk = (verb: string): ActionDef => ({ v: 1, kind: 'pca-action-def', verb, title: verb, effects: ['read'], resource: { type: 'a.b', id: '*', scope: 'one' }, params: {}, review: { state: 'unreviewed' } });
    expect(reviewQueueOrder(verbs.map(mk), CORE_REGISTRY).map((d) => d.verb)).toEqual(['a.a.read', 'a.b.read', 'a.c.read', 'a.d.read']);
    expect(reviewQueueOrder(verbs.slice().reverse().map(mk), CORE_REGISTRY).map((d) => d.verb)).toEqual(['a.a.read', 'a.b.read', 'a.c.read', 'a.d.read']);
  });
});

describe('confirmDef: the remaining refusals', () => {
  it('a dismissal reason must be a string of 1..256 characters', () => {
    const msg = "bad_confirm: dismissed trait 'pca.bulk' needs a reason (1..256 characters)";
    expect(err(() => confirmDef(def(), opts({ dismissed: [{ trait: 'pca.bulk', reason: 5 }] })))).toBe(msg);
    expect(err(() => confirmDef(def(), opts({ dismissed: [{ trait: 'pca.bulk', reason: 'x'.repeat(257) }] })))).toBe(msg);
    expect(err(() => confirmDef(def(), opts({ dismissed: [{ trait: 'pca.bulk', reason: 'x'.repeat(256) }] })))).toBe('none');
  });
  it('a result that is not a valid def is refused with the reason', () => {
    expect(err(() => confirmDef({ ...def(), extra: 1 } as never, opts()))).toBe("bad_confirm: the confirmed def is invalid: unknown member 'extra'");
  });
});
