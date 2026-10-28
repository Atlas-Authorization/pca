// Exact outcomes for the confirm and attestation paths (kill tests for Stryker): every refusal code and message, the signed
// message bytes, the pin checks, the queue order. A mutant of review.ts that changes any of these changes a pinned value here.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { factsDigest, toSchemaVerb } from '../src';
import {
  ActionKitError, CORE_REGISTRY, attestationVerifier, confirmDef, defDigest, reviewMessage, reviewPriority, reviewQueueOrder, reviewStatus, reviewerPinsError, revertStale, signReview,
  traitsDigest, verifyAttestation, type ActionDef, type PinnedKey, type ReviewerPins,
} from '../src';

const rev = generateKeyPair(), imp = generateKeyPair(), oth = generateKeyPair();
const pk = (k: { publicKey: Uint8Array }): string => b64u(k.publicKey);
const PINS: ReviewerPins = { keys: [{ kid: 'rev', pk: pk(rev), roles: ['reviewer'] }, { kid: 'imp', pk: pk(imp), roles: ['importer', 'model'] }] };
const ctx = { pins: PINS, registry: CORE_REGISTRY };
const def = (over: Partial<ActionDef> = {}): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: 'a.pay.create', title: 'Pay', effects: ['create'], resource: { type: 'a.pay', id: '*', scope: 'one' },
  params: { n: { type: 'string' } }, traits: ['pca.money_moving'], review: { state: 'suggested', suggested_by: { added: { traits: ['pca.money_moving', 'pca.bulk'], roles: {}, tags: {} } } }, ...over,
});
const confirmed = (): ActionDef => confirmDef(def(), { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'single payment' }], ts: 1000 });
const err = (f: () => unknown): string => { try { f(); } catch (e) { return `${(e as ActionKitError).code}: ${(e as Error).message}`; } return 'none'; };
const withAtt = (d: ActionDef, a: object): ActionDef => ({ ...d, review: { state: 'confirmed', attestation: a as never } });

describe('confirmDef: exact refusals', () => {
  const o = (x: object = {}) => ({ registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'r' }], ts: 1, ...x });
  it('each refusal has its code and message', () => {
    expect(confirmDef(def({ review: { state: 'authored' } }), o({ dismissed: [] })).review.state).toBe('confirmed');
    expect(err(() => confirmDef(def(), o({ ts: -1 })))).toBe('bad_confirm: ts must be a non-negative integer');
    expect(err(() => confirmDef(def(), o({ ts: 1.5 })))).toBe('bad_confirm: ts must be a non-negative integer');
    expect(err(() => confirmDef(def(), o({ finalTraits: ['pca.money_moving', 'pca.money_moving'] })))).toBe('bad_confirm: final traits must be distinct');
    expect(err(() => confirmDef(def(), o({ finalTraits: ['pca.nope'] })))).toBe("bad_confirm: unknown trait 'pca.nope'");
    expect(err(() => confirmDef(def(), o({ finalTraits: ['pca.unreviewed'] })))).toBe("bad_confirm: 'pca.unreviewed' is the review marker, not a final trait");
    expect(err(() => confirmDef(def(), o({ dismissed: [{ trait: 'pca.bulk', reason: ' ' }] })))).toBe("bad_confirm: dismissed trait 'pca.bulk' needs a reason (1..256 characters)");
    expect(err(() => confirmDef(def(), o({ dismissed: [{ trait: 'pca.bulk', reason: 'x'.repeat(257) }] })))).toBe("bad_confirm: dismissed trait 'pca.bulk' needs a reason (1..256 characters)");
    expect(err(() => confirmDef(def(), o({ dismissed: [{ trait: 'pca.bulk', reason: 'a' }, { trait: 'pca.bulk', reason: 'b' }] })))).toBe("bad_confirm: trait 'pca.bulk' is dismissed twice");
    expect(err(() => confirmDef(def(), o({ finalTraits: ['pca.money_moving', 'pca.bulk'], dismissed: [{ trait: 'pca.bulk', reason: 'a' }] })))).toBe("bad_confirm: trait 'pca.bulk' is both final and dismissed");
    expect(err(() => confirmDef(def(), o({ dismissed: [{ trait: 'pca.bulk', reason: 'r' }, { trait: 'pca.pii_access', reason: 'a' }] })))).toBe("bad_confirm: trait 'pca.pii_access' was never suggested; nothing to dismiss");
    expect(err(() => confirmDef(def(), o({ dismissed: [] })))).toBe("undismissed_suggestion: trait 'pca.bulk' was suggested and is not in the final set: record it as dismissed with a reason");
  });
  it('pin checks', () => {
    const p = (x: ReviewerPins) => o({ pins: x });
    expect(err(() => confirmDef(def(), p({ keys: [{ kid: 'rev', pk: pk(rev), roles: ['reviewer', 'model'] }] })))).toBe("bad_confirm: key 'rev': an importer or model key cannot hold the reviewer role");
    expect(err(() => confirmDef(def(), p({ keys: [{ kid: 'zzz', pk: pk(rev), roles: ['reviewer'] }] })))).toBe("not_reviewer: key 'rev' is not pinned with the reviewer role");
    expect(err(() => confirmDef(def(), p({ keys: [{ kid: 'rev', pk: pk(rev), roles: ['publisher'] }] })))).toBe("not_reviewer: key 'rev' is not pinned with the reviewer role");
    expect(err(() => confirmDef(def(), p({ keys: [{ kid: 'rev', pk: pk(oth), roles: ['reviewer'] }] })))).toBe("not_reviewer: the secret does not belong to the pinned key 'rev'");
    expect(err(() => confirmDef(def(), p(PINS)))).toBe('none');
  });
  it('the result: state, final traits, attestation body, the digest it covers; the input is not mutated', () => {
    const d = def();
    const before = JSON.stringify(d);
    const c = confirmDef(d, { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'single payment' }], ts: 1000 });
    expect(JSON.stringify(d)).toBe(before);
    expect(c.review.state).toBe('confirmed');
    expect(c.review.suggested_by).toEqual(d.review.suggested_by);
    expect(c.traits).toEqual(['pca.money_moving']);
    const a = c.review.attestation!;
    expect({ ...a, sig: undefined }).toEqual({ def_digest: defDigest(c), traits_digest: traitsDigest(CORE_REGISTRY), facts_digest: factsDigest(toSchemaVerb(c, CORE_REGISTRY).verb), final_traits: ['pca.money_moving'], dismissed: [{ trait: 'pca.bulk', reason: 'single payment' }], reviewer_kid: 'rev', ts: 1000, sig: undefined });
    // no final traits: the member is omitted and the digest is over that def
    const none = confirmDef(def({ traits: undefined, review: { state: 'unreviewed' } }), { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: [], ts: 5 });
    expect('traits' in none).toBe(false);
    expect(none.review.attestation!.def_digest).toBe(defDigest(none));
    expect(verifyAttestation(none, ctx).ok).toBe(true);
  });
  it('a trait implied by the def itself need not be dismissed', () => {
    const d = def({ effects: ['pay'], traits: ['pca.money_moving'], review: { state: 'suggested', suggested_by: { added: { traits: ['pca.money_moving'], roles: {}, tags: {} } } } });
    expect(err(() => confirmDef(d, { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: [], ts: 1 }))).toBe('none');
  });
});

describe('verifyAttestation: exact verdicts', () => {
  const c = confirmed();
  const a = c.review.attestation!;
  const v = (d: ActionDef, x = ctx) => verifyAttestation(d, x);
  it('ok names the signer', () => expect(v(c)).toEqual({ ok: true, kid: 'rev' }));
  it('each failure has its reason and detail', () => {
    expect(v(def({ review: { state: 'suggested' } }))).toEqual({ ok: false, reason: 'not_confirmed', detail: 'review.state is not confirmed' });
    expect(v(withAtt(def(), undefined as never).review.attestation === undefined ? { ...c, review: { state: 'confirmed' } } : c)).toEqual({ ok: false, reason: 'no_attestation', detail: 'a confirmed def carries an attestation' });
    expect(v(withAtt(c, { ...a, sig: undefined }))).toEqual({ ok: false, reason: 'no_signature', detail: 'the attestation is unsigned' });
    expect(v({ ...c, title: 'Other' })).toEqual({ ok: false, reason: 'digest_mismatch', detail: 'the def changed after it was reviewed' });
    expect(v(withAtt(c, { ...a, traits_digest: 'x' }))).toEqual({ ok: false, reason: 'traits_digest_mismatch', detail: 'the trait registry changed since the review' });
    const sBad = signReview({ ...a, final_traits: ['pca.bulk'] }, rev.secretKey);
    expect(v(withAtt(c, sBad))).toEqual({ ok: false, reason: 'final_traits_mismatch', detail: "the attested final traits are not the def's declared traits" });
    const sDis = signReview({ ...a, dismissed: [{ trait: 'pca.money_moving', reason: 'x' }] }, rev.secretKey);
    expect(v(withAtt(c, sDis))).toEqual({ ok: false, reason: 'dismissed_conflict', detail: 'a dismissed trait is also final, or has no reason' });
    const sBlank = signReview({ ...a, dismissed: [{ trait: 'pca.bulk', reason: '  ' }] }, rev.secretKey);
    expect(v(withAtt(c, sBlank)).ok).toBe(false);
    expect(v(withAtt(c, { ...a, reviewer_kid: 'ghost' }))).toEqual({ ok: false, reason: 'unknown_reviewer', detail: "no pinned key 'ghost'" });
    expect(v(withAtt(c, { ...a, reviewer_kid: 'imp' }))).toEqual({ ok: false, reason: 'not_a_reviewer', detail: "key 'imp' does not hold the reviewer role" });
    expect(v(c, { ...ctx, pins: { keys: [{ ...PINS.keys[0]!, not_before: 1001 }] } })).toMatchObject({ reason: 'outside_validity', detail: 'the attestation time is outside the key validity' });
    expect(v(c, { ...ctx, pins: { keys: [{ ...PINS.keys[0]!, not_after: 999 }] } })).toMatchObject({ reason: 'outside_validity' });
    expect(v(c, { ...ctx, pins: { keys: [{ ...PINS.keys[0]!, not_before: 1000, not_after: 1000 }] } }).ok).toBe(true);
    expect(v(withAtt(c, { ...a, sig: b64u(new Uint8Array(64)) }))).toEqual({ ok: false, reason: 'bad_signature', detail: 'the attestation signature is invalid' });
    expect(v(c, { ...ctx, pins: { keys: [{ kid: 'rev', pk: 'x', roles: ['reviewer'] }] } })).toMatchObject({ reason: 'bad_pins' });
    expect(v(withAtt(c, 'garbage' as never))).toMatchObject({ ok: false });
  });
  it('the accepted registry digests extend the check', () => {
    expect(v(withAtt(c, signReview({ ...a, traits_digest: 'old' }, rev.secretKey)), { ...ctx, pins: { ...PINS, traits_digests: ['old'] } }).ok).toBe(true);
  });
  it('reviewStatus, revertStale and the verifier callback', () => {
    expect(reviewStatus(c, ctx)).toBe('confirmed');
    expect(reviewStatus({ ...c, title: 'x' }, ctx)).toBe('stale');
    expect(reviewStatus(def({ review: { state: 'authored' } }), ctx)).toBe('authored');
    expect(reviewStatus(def({ review: { state: 'unreviewed' } }), ctx)).toBe('unreviewed');
    expect(revertStale(c, ctx)).toBe(c);
    expect(revertStale({ ...c, title: 'x' }, ctx).review).toEqual({ state: 'unreviewed', suggested_by: c.review.suggested_by });
    expect(attestationVerifier(ctx)(c)).toBe(true);
    expect(attestationVerifier(ctx)({ ...c, title: 'x' })).toBe(false);
  });
});

describe('reviewMessage and pins: pinned', () => {
  const body = { def_digest: 'D', traits_digest: 'T', facts_digest: 'F', final_traits: ['pca.b', 'pca.a'], dismissed: [{ trait: 'pca.z', reason: 'r' }, { trait: 'pca.y', reason: 's' }], reviewer_kid: 'k', ts: 7 };
  it('the signed bytes are the domain, a NUL and the canonical sorted body', () => {
    expect(new TextDecoder().decode(reviewMessage(body))).toBe('atlas-pca/action-review/v2\0{"def_digest":"D","dismissed":[{"reason":"s","trait":"pca.y"},{"reason":"r","trait":"pca.z"}],"facts_digest":"F","final_traits":["pca.a","pca.b"],"reviewer_kid":"k","traits_digest":"T","ts":7}');
  });
  it('signReview sorts, and a changed member changes the signature', () => {
    const s = signReview(body, rev.secretKey);
    expect(s.final_traits).toEqual(['pca.a', 'pca.b']);
    expect(s.dismissed.map((d) => d.trait)).toEqual(['pca.y', 'pca.z']);
    for (const k of ['def_digest', 'traits_digest', 'facts_digest', 'reviewer_kid'] as const) expect(signReview({ ...body, [k]: 'other' }, rev.secretKey).sig).not.toBe(s.sig);
    expect(signReview({ ...body, ts: 8 }, rev.secretKey).sig).not.toBe(s.sig);
  });
  it('pin errors are exact', () => {
    const e = (keys: Partial<PinnedKey>[]) => reviewerPinsError({ keys: keys as PinnedKey[] });
    const good = { kid: 'a', pk: pk(rev), roles: ['reviewer'] as PinnedKey['roles'] };
    expect(reviewerPinsError(null as never)).toBe('pins must be {keys: [...]}');
    expect(e([{ ...good, kid: '' }])).toBe('a pinned key needs a kid');
    expect(e([{ ...good, kid: 'k'.repeat(129) }])).toBe('a pinned key needs a kid');
    expect(e([good, { ...good, pk: pk(oth) }])).toBe("kid 'a' is pinned twice");
    expect(e([{ ...good, pk: 'zz' }])).toBe("key 'a': pk is not canonical base64url (32 bytes)");
    expect(e([{ ...good, roles: [] }])).toBe("key 'a': roles must be distinct known roles");
    expect(e([{ ...good, roles: ['reviewer', 'reviewer'] }])).toBe("key 'a': roles must be distinct known roles");
    expect(e([{ ...good, roles: ['boss' as never] }])).toBe("key 'a': roles must be distinct known roles");
    expect(e([{ ...good, roles: ['reviewer', 'importer'] }])).toBe("key 'a': an importer or model key cannot hold the reviewer role");
    expect(e([{ ...good, not_after: -1 }])).toBe("key 'a': not_after must be a non-negative integer");
    expect(e([good, { kid: 'b', pk: pk(rev), roles: ['importer'] }])).toBe("key 'a': the same key material is pinned as an importer or model key");
    expect(e([good, { kid: 'b', pk: pk(oth), roles: ['importer'] }])).toBeNull();
  });
});

describe('review queue: exact order and priority', () => {
  const mk = (verb: string, effects: ActionDef['effects'], traits?: string[]): ActionDef => ({ v: 1, kind: 'pca-action-def', verb, title: verb, effects, resource: { type: 'a.b', id: '*', scope: 'one' }, params: {}, ...(traits ? { traits } : {}), review: { state: 'unreviewed' } });
  it('priority classes and order are fixed', () => {
    const list = [mk('a.z.read', ['read']), mk('a.y.update', ['update']), mk('a.x.cred', ['read'], ['pca.credential_access']), mk('a.w.priv', ['privilege']), mk('a.v.send', ['send']), mk('a.u.code', ['exec'])];
    expect(list.map((d) => reviewPriority(d, CORE_REGISTRY))).toEqual([2, 2, 1, 0, 0, 0]);
    expect(reviewQueueOrder(list, CORE_REGISTRY).map((d) => d.verb)).toEqual(['a.u.code', 'a.w.priv', 'a.v.send', 'a.x.cred', 'a.y.update', 'a.z.read']);
    expect(reviewQueueOrder([], CORE_REGISTRY)).toEqual([]);
  });
});
