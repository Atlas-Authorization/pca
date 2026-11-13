// Review: the one non-monotone step. An imported def stays at the unreviewed floor until a key pinned with the reviewer role
// signs THIS def digest; any change to the def or the registry, a forged or replayed attestation, a machine key and an
// unrecorded dismissal all leave it unreviewed (or refuse the confirmation).
import fc from 'fast-check';
import { b64u, generateKeyPair, publicKeyOf } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  ActionKitError, CORE_REGISTRY, CORE_TRAIT_IDS, applySuggestion, attestationVerifier, buildRegistry, confirmDef, defDigest, effective, extendRegistry, importOpenApi, prepareReview,
  reviewMessage, reviewPriority, reviewQueueOrder, reviewStatus, reviewerPinsError, revertStale, signReview, suggestWithRules, traitsDigest, traitsOf, hintTraits, verifyAttestation, DEFAULT_RULES,
  type ActionDef, type PinnedKey, type ReviewerPins, type VerifyCtx,
} from '../src';
import { arbDef } from './arb';
import { runs } from './runs';

const reviewer = generateKeyPair();
const importer = generateKeyPair();
const other = generateKeyPair();
const pk = (k: { publicKey: Uint8Array }): string => b64u(k.publicKey);
const pins = (extra: PinnedKey[] = []): ReviewerPins => ({ keys: [{ kid: 'rev-1', pk: pk(reviewer), roles: ['reviewer'] }, { kid: 'imp-1', pk: pk(importer), roles: ['importer'] }, ...extra] });
const ctx = (p: ReviewerPins = pins()): VerifyCtx => ({ pins: p, registry: CORE_REGISTRY });

const imported = (): ActionDef => {
  const r = importOpenApi({ openapi: '3.0.0', paths: { '/v1/refunds': { post: { operationId: 'createRefund', summary: 'Refund a charge', requestBody: { content: { 'application/json': { schema: { type: 'object', required: ['amount', 'currency'], properties: { amount: { type: 'integer', minimum: 1, maximum: 5000 }, currency: { type: 'string' } } } } } } } } } }, { ns: 'acme' });
  return applySuggestion(r.defs[0]!, suggestWithRules(r.defs[0]!, DEFAULT_RULES, CORE_REGISTRY), { rules: { version: '1.0.0', digest: 'd', fired: [] } });
};
const confirm = (d = imported(), over: Partial<Parameters<typeof confirmDef>[1]> = {}): ActionDef =>
  confirmDef(d, { registry: CORE_REGISTRY, reviewer: { kid: 'rev-1', secret: reviewer.secretKey }, pins: pins(), finalTraits: d.traits ?? [], ts: 1_700_000_000, ...over });

describe('confirm', () => {
  it('a suggested def stays unreviewed; a confirmed one with a valid attestation counts and loses only the review marker', () => {
    const d = imported();
    expect(d.review.state).toBe('suggested');
    expect(d.traits).toContain('pca.money_moving');
    const c = confirm(d);
    expect(c.review.state).toBe('confirmed');
    const v = attestationVerifier(ctx());
    expect(traitsOf(d, CORE_REGISTRY, { attestationVerified: v })).toContain('pca.unreviewed');
    const withReview = traitsOf(c, CORE_REGISTRY, { attestationVerified: v });
    expect(withReview).not.toContain('pca.unreviewed');
    // nothing else changed: the confirmed set is the unreviewed set minus the marker
    expect(withReview).toEqual(hintTraits(c));
    const e = effective(c, CORE_REGISTRY, { attestationVerified: v });
    expect(e.eff.blast_ppm).toBeLessThan(1_000_000);
    expect(e.closure).toContain('pca.money_moving');
    // without the callback a confirmed def is still unreviewed
    expect(traitsOf(c, CORE_REGISTRY)).toContain('pca.unreviewed');
  });
  it('the attestation binds the def digest, the registry digest, the final traits and the dismissals', () => {
    const c = confirm();
    const a = c.review.attestation!;
    expect(a).toMatchObject({ def_digest: defDigest(c), traits_digest: traitsDigest(CORE_REGISTRY), reviewer_kid: 'rev-1', ts: 1_700_000_000 });
    expect(a.final_traits).toEqual((c.traits ?? []).slice().sort());
    expect(verifyAttestation(c, ctx())).toEqual({ ok: true, kid: 'rev-1' });
    expect(reviewStatus(c, ctx())).toBe('confirmed');
  });
  it('a suggested trait left out must be dismissed with a reason', () => {
    const d = imported();
    const drop = 'pca.money_moving';
    const keep = (d.traits ?? []).filter((t) => t !== drop);
    // money_moving is not implied by this def's own facts (effect create), so leaving it out needs a reason
    expect(() => confirm(d, { finalTraits: keep })).toThrow(/dismissed with a reason/);
    expect(() => confirm(d, { finalTraits: keep, dismissed: [{ trait: drop, reason: '  ' }] })).toThrow(/needs a reason/);
    const c = confirm(d, { finalTraits: keep, dismissed: [{ trait: drop, reason: 'amount is a quota here, not money' }] });
    expect(c.review.attestation!.dismissed).toEqual([{ trait: drop, reason: 'amount is a quota here, not money' }]);
    expect(verifyAttestation(c, ctx()).ok).toBe(true);
    expect(traitsOf(c, CORE_REGISTRY, { attestationVerified: attestationVerifier(ctx()) })).not.toContain(drop);
  });
  it('refuses a dismissal of something never suggested, a trait both final and dismissed, an unknown trait, the review marker', () => {
    const d = imported();
    expect(() => confirm(d, { dismissed: [{ trait: 'pca.bulk', reason: 'x' }] })).toThrow(/never suggested/);
    expect(() => confirm(d, { dismissed: [{ trait: 'pca.money_moving', reason: 'x' }] })).toThrow(/both final and dismissed/);
    expect(() => confirm(d, { finalTraits: [...(d.traits ?? []), 'acme.nope'] })).toThrow(/unknown trait/);
    expect(() => confirm(d, { finalTraits: [...(d.traits ?? []), 'pca.unreviewed'] })).toThrow(/review marker/);
    expect(() => confirm(d, { finalTraits: ['pca.bulk', 'pca.bulk'] })).toThrow(/distinct/);
    expect(() => confirm(d, { ts: -1 })).toThrow(/ts must/);
    // an authored def is unconfirmed too: it can be signed like any other
    expect(confirm({ ...d, review: { state: 'authored' } }).review.state).toBe('confirmed');
  });
  it('the reviewer may add traits the suggestions missed', () => {
    const d = imported();
    const c = confirm(d, { finalTraits: [...(d.traits ?? []), 'pca.regulated_data'] });
    expect(c.traits).toContain('pca.regulated_data');
    expect(verifyAttestation(c, ctx()).ok).toBe(true);
  });
  it('refuses a reviewer key that is not pinned as a reviewer, or whose secret is not the pinned key', () => {
    expect(() => confirm(imported(), { reviewer: { kid: 'imp-1', secret: importer.secretKey } })).toThrow(/not pinned with the reviewer role/);
    expect(() => confirm(imported(), { reviewer: { kid: 'nobody', secret: other.secretKey } })).toThrow(ActionKitError);
    expect(() => confirm(imported(), { reviewer: { kid: 'rev-1', secret: other.secretKey } })).toThrow(/does not belong/);
  });
});

describe('what invalidates a confirmation', () => {
  const c = confirm();
  it('any change to the def after the review: the def reverts to unreviewed', () => {
    const changes: ((d: ActionDef) => ActionDef)[] = [
      (d) => ({ ...d, title: 'Refund everything' }),
      (d) => ({ ...d, effects: ['create', 'pay'] }),
      (d) => ({ ...d, params: { ...d.params, extra: { type: 'string' } } }),
      (d) => ({ ...d, params: { ...d.params, amount: { ...d.params['amount']!, max: 999999 } } }),
      (d) => ({ ...d, traits: [...(d.traits ?? []), 'pca.bulk'] }),
      (d) => ({ ...d, resource: { ...d.resource, scope: 'tenant' } }),
      (d) => ({ ...d, reversibility: 'reversible' }),
    ];
    for (const f of changes) {
      const m = f(c);
      expect(verifyAttestation(m, ctx())).toMatchObject({ ok: false });
      expect(reviewStatus(m, ctx())).toBe('stale');
      expect(traitsOf(m, CORE_REGISTRY, { attestationVerified: attestationVerifier(ctx()) })).toContain('pca.unreviewed');
      expect(revertStale(m, ctx()).review).toEqual({ ...m.review, state: 'unreviewed', attestation: undefined });
    }
  });
  it('members outside the digest (examples, source, since, suggested_by) do not invalidate it', () => {
    const m: ActionDef = { ...c, examples: [{ params: {}, expect: 'escalate' }], source: { kind: 'x', uri: 'u', spec_digest: 's', licence: 'l' }, since: '0.2', review: { ...c.review, suggested_by: { extra: 1 } } };
    expect(verifyAttestation(m, ctx()).ok).toBe(true);
    expect(revertStale(m, ctx())).toBe(m);
  });
  it('a changed trait registry (a raised floor) makes the attestation stale unless the pins accept the old digest', () => {
    const oldDigest = traitsDigest(CORE_REGISTRY);
    const grown = extendRegistry(CORE_REGISTRY, [{ id: 'acme.extra', implies: [], floor: CORE_REGISTRY.traits.get('pca.bulk')!.floor, card_phrase: 'x' }]);
    expect(verifyAttestation(c, { pins: pins(), registry: grown })).toMatchObject({ ok: false, reason: 'traits_digest_mismatch' });
    expect(verifyAttestation(c, { pins: { ...pins(), traits_digests: [oldDigest] }, registry: grown }).ok).toBe(true);
  });
  it('the attestation does not move to another def (replay)', () => {
    const d2 = importOpenApi({ openapi: '3.0.0', paths: { '/x': { post: { operationId: 'deleteEverything' } } } }, { ns: 'acme' }).defs[0]!;
    const replay: ActionDef = { ...d2, review: { state: 'confirmed', attestation: c.review.attestation! } };
    expect(verifyAttestation(replay, ctx())).toMatchObject({ ok: false, reason: 'digest_mismatch' });
    expect(traitsOf(replay, CORE_REGISTRY, { attestationVerified: attestationVerifier(ctx()) })).toContain('pca.unreviewed');
  });
  it('a forged signature, a tampered body, an unsigned attestation and a signature by a different key', () => {
    const a = c.review.attestation!;
    const flip = (s: string): string => s.slice(0, -2) + (s.endsWith('AA') ? 'BB' : 'AA');
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: { ...a, sig: flip(a.sig!) } } }, ctx())).toMatchObject({ ok: false, reason: 'bad_signature' });
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: { ...a, ts: a.ts + 1 } } }, ctx())).toMatchObject({ ok: false, reason: 'bad_signature' });
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: { ...a, dismissed: [{ trait: 'pca.bulk', reason: 'why not' }] } } }, ctx())).toMatchObject({ ok: false });
    const { sig: _s, ...unsigned } = a;
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: unsigned } }, ctx())).toMatchObject({ ok: false, reason: 'no_signature' });
    const forged = signReview({ def_digest: a.def_digest, traits_digest: a.traits_digest, facts_digest: a.facts_digest, final_traits: a.final_traits, dismissed: [], reviewer_kid: 'rev-1', ts: a.ts }, other.secretKey);
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: forged } }, ctx())).toMatchObject({ ok: false, reason: 'bad_signature' });
  });
  it('a machine key, an unknown key and a key outside its validity cannot confirm', () => {
    const a = c.review.attestation!;
    const byImporter = signReview({ ...a, reviewer_kid: 'imp-1' }, importer.secretKey);
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: byImporter } }, ctx())).toMatchObject({ ok: false, reason: 'not_a_reviewer' });
    const byUnknown = signReview({ ...a, reviewer_kid: 'ghost' }, other.secretKey);
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: byUnknown } }, ctx())).toMatchObject({ ok: false, reason: 'unknown_reviewer' });
    const early = ctx({ keys: [{ kid: 'rev-1', pk: pk(reviewer), roles: ['reviewer'], not_before: a.ts + 10 }] });
    expect(verifyAttestation(c, early)).toMatchObject({ ok: false, reason: 'outside_validity' });
    const late = ctx({ keys: [{ kid: 'rev-1', pk: pk(reviewer), roles: ['reviewer'], not_after: a.ts - 10 }] });
    expect(verifyAttestation(c, late)).toMatchObject({ ok: false, reason: 'outside_validity' });
    expect(verifyAttestation(c, ctx({ keys: [{ kid: 'rev-1', pk: pk(reviewer), roles: ['reviewer'], not_before: a.ts, not_after: a.ts }] })).ok).toBe(true);
  });
  it('the declared traits must be the attested final traits', () => {
    const a = c.review.attestation!;
    // an attestation over a different final set, signed by the real reviewer for the same def digest
    const other2 = signReview({ def_digest: a.def_digest, traits_digest: a.traits_digest, facts_digest: a.facts_digest, final_traits: [...a.final_traits, 'pca.bulk'], dismissed: [], reviewer_kid: 'rev-1', ts: a.ts }, reviewer.secretKey);
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: other2 } }, ctx())).toMatchObject({ ok: false, reason: 'final_traits_mismatch' });
    const both = signReview({ def_digest: a.def_digest, traits_digest: a.traits_digest, facts_digest: a.facts_digest, final_traits: a.final_traits, dismissed: [{ trait: a.final_traits[0]!, reason: 'x' }], reviewer_kid: 'rev-1', ts: a.ts }, reviewer.secretKey);
    expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: both } }, ctx())).toMatchObject({ ok: false, reason: 'dismissed_conflict' });
  });
  it('only a confirmed def can carry a valid attestation', () => {
    expect(verifyAttestation({ ...c, review: { state: 'suggested', attestation: c.review.attestation! } }, ctx())).toMatchObject({ ok: false, reason: 'not_confirmed' });
    expect(verifyAttestation({ ...c, review: { state: 'confirmed' } }, ctx())).toMatchObject({ ok: false, reason: 'no_attestation' });
    expect(reviewStatus({ ...c, review: { state: 'suggested' } }, ctx())).toBe('suggested');
  });
  it('the message is domain separated and covers every member', () => {
    const a = c.review.attestation!;
    const { sig: _s, ...body } = a;
    const m = reviewMessage(body);
    expect(new TextDecoder().decode(m.slice(0, 29))).toBe('atlas-pca/action-review/v2\0{"');
    for (const k of Object.keys(body) as (keyof typeof body)[]) {
      const mutated = { ...body, [k]: typeof body[k] === 'number' ? (body[k] as number) + 1 : k === 'final_traits' ? [] : k === 'dismissed' ? [{ trait: 'pca.bulk', reason: 'r' }] : 'zzz' };
      expect(Buffer.from(reviewMessage(mutated as never)).equals(Buffer.from(m)), k).toBe(false);
    }
  });
});

describe('pins', () => {
  it('a key cannot be both a reviewer and an importer or model; the same key material under another kid cannot smuggle it in', () => {
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['reviewer', 'importer'] }] })).toMatch(/cannot hold the reviewer role/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['reviewer', 'model'] }] })).toMatch(/cannot hold the reviewer role/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['reviewer'] }, { kid: 'b', pk: pk(reviewer), roles: ['model'] }] })).toMatch(/same key material/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['reviewer'] }, { kid: 'a', pk: pk(other), roles: ['publisher'] }] })).toMatch(/pinned twice/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: 'short', roles: ['reviewer'] }] })).toMatch(/canonical/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['boss' as never] }] })).toMatch(/roles/);
    expect(reviewerPinsError({ keys: [{ kid: 'a', pk: pk(reviewer), roles: ['reviewer'], not_before: -1 }] })).toMatch(/not_before/);
    expect(reviewerPinsError(pins())).toBeNull();
  });
  it('with a bad pin set nothing verifies and nothing is confirmed', () => {
    const c = confirm();
    const bad: ReviewerPins = { keys: [{ kid: 'rev-1', pk: pk(reviewer), roles: ['reviewer', 'importer'] }] };
    expect(verifyAttestation(c, ctx(bad))).toMatchObject({ ok: false, reason: 'bad_pins' });
    expect(() => confirm(imported(), { pins: bad })).toThrow(/cannot hold the reviewer role/);
    expect(publicKeyOf(reviewer.secretKey).length).toBe(32);
  });
});

describe('an unreviewed def never gets a confirmed floor without a valid attestation', () => {
  it('for any def claiming to be confirmed, with any garbage attestation, the review marker stays', () => {
    const c = confirm();
    const a = c.review.attestation!;
    const arbAtt = fc.record({
      def_digest: fc.oneof(fc.constant(a.def_digest), fc.string({ minLength: 43, maxLength: 43 })),
      traits_digest: fc.oneof(fc.constant(a.traits_digest), fc.string({ minLength: 43, maxLength: 43 })),
      facts_digest: fc.constant(a.facts_digest),
      final_traits: fc.subarray([...CORE_TRAIT_IDS]),
      dismissed: fc.constant([] as { trait: string; reason: string }[]),
      reviewer_kid: fc.constantFrom('rev-1', 'imp-1', 'x'),
      ts: fc.nat(),
      sig: fc.oneof(fc.constant(a.sig!), fc.string({ minLength: 1, maxLength: 90 })),
    });
    const v = attestationVerifier(ctx());
    fc.assert(fc.property(arbDef, arbAtt, (d, att) => {
      const forged: ActionDef = { ...d, review: { state: 'confirmed', attestation: att as never } };
      expect(traitsOf(forged, CORE_REGISTRY, { attestationVerified: v })).toContain('pca.unreviewed');
      expect(effective(forged, CORE_REGISTRY, { attestationVerified: v }).eff.blast_ppm).toBe(1_000_000);
    }), { seed: 93, numRuns: runs(2000) });
  });
  it('flipping any single byte of the attested message or signature fails verification', () => {
    const c = confirm();
    const a = c.review.attestation!;
    const sig = Buffer.from(a.sig!, 'base64url');
    for (let i = 0; i < sig.length; i += 7) {
      const t = Buffer.from(sig);
      t[i] = t[i]! ^ 0x01;
      expect(verifyAttestation({ ...c, review: { state: 'confirmed', attestation: { ...a, sig: t.toString('base64url') } } }, ctx()).ok, `byte ${i}`).toBe(false);
    }
  });
});

describe('the review queue', () => {
  const mk = (verb: string, effects: ActionDef['effects'], extra: Partial<ActionDef> = {}): ActionDef => ({
    v: 1, kind: 'pca-action-def', verb, title: verb, effects, resource: { type: 'a.b', id: '*', scope: 'one' }, params: {}, review: { state: 'unreviewed' }, ...extra,
  });
  it('puts money, privilege, code, destructive and outbound communication first, then other risky, then the rest', () => {
    const defs = [mk('a.x.read', ['read']), mk('a.x.pay', ['pay']), mk('a.x.cred', ['read'], { traits: ['pca.credential_access'] }), mk('a.x.del', ['delete']), mk('a.x.upd', ['update']), mk('a.x.exec', ['exec'])];
    expect(reviewQueueOrder(defs, CORE_REGISTRY).map((d) => d.verb)).toEqual(['a.x.exec', 'a.x.pay', 'a.x.del', 'a.x.cred', 'a.x.upd', 'a.x.read']);
    expect(reviewPriority(defs[0]!, CORE_REGISTRY)).toBe(2);
    expect(reviewPriority(defs[2]!, CORE_REGISTRY)).toBe(1);
    expect(reviewPriority(defs[1]!, CORE_REGISTRY)).toBe(0);
  });
  it('the review view shows declared, implied and suggested traits, the card and what changed', () => {
    const d = imported();
    const v = prepareReview(d, CORE_REGISTRY, { previous: { ...d, title: 'Old title', params: {} } });
    expect(v.def_digest).toBe(defDigest(d));
    expect(v.suggested.traits).toContain('pca.money_moving');
    expect(v.card.text).toContain('moves money');
    expect(v.changes).toEqual(['params', 'title']);
    expect(v.priority).toBe(0);
    expect(v.state).toBe('suggested');
  });
});

describe('custom registries', () => {
  it('a confirmation names the registry it was made against, custom traits included', () => {
    const reg = buildRegistry([...CORE_REGISTRY.traits.values()].map((t) => ({ ...t })), { core: true });
    const grown = extendRegistry(reg, [{ id: 'acme.hot', implies: ['pca.money_moving'], floor: reg.traits.get('pca.money_moving')!.floor, card_phrase: 'is hot' }]);
    const d = imported();
    const c = confirmDef(d, { registry: grown, reviewer: { kid: 'rev-1', secret: reviewer.secretKey }, finalTraits: [...(d.traits ?? []), 'acme.hot'], ts: 5 });
    expect(verifyAttestation(c, { pins: pins(), registry: grown }).ok).toBe(true);
    expect(verifyAttestation(c, { pins: pins(), registry: CORE_REGISTRY })).toMatchObject({ ok: false });
  });
});
