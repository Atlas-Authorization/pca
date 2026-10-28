// review.ts - the confirmation flow and signed review attestations (spec section 5.4). This is the ONE non-monotone step
// in the system: a def WITHOUT a valid attestation has the top of the registry as its effective traits (every high-risk trait
// and `pca.unreviewed`), and a valid one sets them to exactly what the reviewer signed. It counts only when a key pinned with
// the `reviewer` role has signed this exact def digest. Importer and model keys cannot hold the reviewer role. Any change to
// the def (its digest) or to the trait registry the reviewer saw makes the attestation stale and the def reverts to unconfirmed.

import { b64u, publicKeyOf, verifyB64u } from '@atlasauth/pca';
import { REVIEW_DOMAIN, KEY_ROLES, factsDigest, reviewMessage, reviewerPinsError, signReview, type KeyRole, type PinnedKey, type ReviewerPins } from '../confirmation';
export { REVIEW_DOMAIN, KEY_ROLES, reviewMessage, reviewerPinsError, signReview, type KeyRole, type PinnedKey, type ReviewerPins };
import { ActionKitError, TRAIT_ID_RE, type ActionDef, type ReviewRef, type TraitId } from '../def';
import { cardOf, toSchemaVerb, type CardOut } from '../derive';
import { defDigest, traitsDigest } from '../digest';
import { effective, impliedTraits, type Effective, type ReviewOpts, type TraitView } from '../effective';
import { normalize, sortUniq } from '../normalize';
import { closure, type Registry } from '../traits';
import { validateDef } from '../validate';
import type { SuggestedBy } from './suggest';

export type AttestationVerdict = { ok: true; kid: string } | { ok: false; reason: AttestationFailure; detail: string };
export type AttestationFailure =
  | 'not_confirmed' | 'no_attestation' | 'no_signature' | 'digest_mismatch' | 'traits_digest_mismatch' | 'final_traits_mismatch'
  | 'dismissed_conflict' | 'unknown_reviewer' | 'not_a_reviewer' | 'outside_validity' | 'bad_signature' | 'bad_pins' | 'malformed';

export interface VerifyCtx {
  pins: ReviewerPins;
  registry: Registry;
}

const fail = (reason: AttestationFailure, detail: string): AttestationVerdict => ({ ok: false, reason, detail });

/**
 * Is this def's confirmation valid? True only if: state is `confirmed`; the attestation covers THIS def digest and an
 * accepted registry digest; its final traits are the def's declared traits; the signer is pinned with the `reviewer` role
 * (and not as a machine key) and the timestamp is inside the key's validity; the signature verifies. Never throws.
 */
export function verifyAttestation(def: ActionDef, ctx: VerifyCtx): AttestationVerdict {
  try {
    const pe = reviewerPinsError(ctx.pins);
    if (pe) return fail('bad_pins', pe);
    if (def.review?.state !== 'confirmed') return fail('not_confirmed', 'review.state is not confirmed');
    const a = def.review.attestation;
    if (a === undefined) return fail('no_attestation', 'a confirmed def carries an attestation');
    if (typeof a.sig !== 'string') return fail('no_signature', 'the attestation is unsigned');
    if (a.def_digest !== defDigest(def)) return fail('digest_mismatch', 'the def changed after it was reviewed');
    const accepted = new Set([traitsDigest(ctx.registry), ...(ctx.pins.traits_digests ?? [])]);
    if (!accepted.has(a.traits_digest)) return fail('traits_digest_mismatch', 'the trait registry changed since the review');
    if (JSON.stringify(sortUniq(a.final_traits)) !== JSON.stringify(sortUniq(def.traits ?? []))) return fail('final_traits_mismatch', "the attested final traits are not the def's declared traits");
    const fin = new Set(a.final_traits);
    if (a.dismissed.some((d) => fin.has(d.trait) || d.reason.trim().length === 0)) return fail('dismissed_conflict', 'a dismissed trait is also final, or has no reason');
    const key = ctx.pins.keys.find((k) => k.kid === a.reviewer_kid);
    if (!key) return fail('unknown_reviewer', `no pinned key '${a.reviewer_kid}'`);
    if (!key.roles.includes('reviewer')) return fail('not_a_reviewer', `key '${key.kid}' does not hold the reviewer role`);
    if ((key.not_before !== undefined && a.ts < key.not_before) || (key.not_after !== undefined && a.ts > key.not_after)) return fail('outside_validity', 'the attestation time is outside the key validity');
    const { sig, ...body } = a;
    return verifyB64u(key.pk, reviewMessage(body), sig) ? { ok: true, kid: key.kid } : fail('bad_signature', 'the attestation signature is invalid');
  } catch (e) {
    return fail('malformed', (e as Error).message);
  }
}

/** The callback the algebra takes (`ReviewOpts.attestationVerified`): a confirmed def counts only if this says so. */
export const attestationVerifier = (ctx: VerifyCtx): NonNullable<ReviewOpts['attestationVerified']> => (d) => verifyAttestation(d, ctx).ok;

export type ReviewStatus = 'authored' | 'unreviewed' | 'suggested' | 'confirmed' | 'stale';

/** The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed). */
export function reviewStatus(def: ActionDef, ctx: VerifyCtx): ReviewStatus {
  if (def.review.state !== 'confirmed') return def.review.state;
  return verifyAttestation(def, ctx).ok ? 'confirmed' : 'stale';
}

/** Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped). Others are returned as they are. */
export function revertStale(def: ActionDef, ctx: VerifyCtx): ActionDef {
  if (reviewStatus(def, ctx) !== 'stale') return def;
  const { attestation: _a, ...rest } = def.review;
  return { ...def, review: { ...rest, state: 'unreviewed' } };
}

// ---- review view and confirm --------------------------------------------------------------------------------------------

export interface ReviewView {
  verb: string;
  def_digest: string;
  state: ActionDef['review']['state'];
  declared_traits: TraitId[];
  /** Traits implied by the def's own facts (effects, roles, tags, scope, reversibility). */
  implied_traits: TraitId[];
  /** Traits and roles the suggestion engine added; the reviewer must keep or dismiss each trait. */
  suggested: SuggestedBy['added'];
  effective: Effective;
  card: CardOut;
  /** Top-level members that differ from `previous`, when given. */
  changes: string[];
  priority: number;
}

const SUSPECT = ['pca.money_moving', 'pca.privilege_change', 'pca.code_execution', 'pca.destructive', 'pca.external_communication'];
const NEXT = ['pca.credential_access', 'pca.data_export', 'pca.regulated_data', 'pca.public_exposure', 'pca.infra_mutation', 'pca.legal_binding', 'pca.impersonation', 'pca.persistence'];

/** The profile the def would have once reviewed (its own facts and traits, without the review marker that every unreviewed def shares). */
const intrinsic = (def: ActionDef, registry: Registry): TraitView => effective(def, registry).hint;

/** Review queue priority: 0 = a core suspect trait (money, privilege, code, destructive, outbound communication), 1 = other risky, 2 = the rest. Lower first. */
export function reviewPriority(def: ActionDef, registry: Registry): number {
  const e = intrinsic(def, registry);
  const cl = new Set(e.closure);
  if (SUSPECT.some((t) => cl.has(t))) return 0;
  if (NEXT.some((t) => cl.has(t))) return 1;
  return 2;
}

/** Defs in review order: suspect traits first, then by risk (highest first), then by verb. Deterministic. */
export function reviewQueueOrder(defs: readonly ActionDef[], registry: Registry): ActionDef[] {
  return defs
    .map((d) => ({ d, p: reviewPriority(d, registry), r: intrinsic(d, registry).eff.risk }))
    .sort((a, b) => a.p - b.p || b.r - a.r || (a.d.verb < b.d.verb ? -1 : a.d.verb > b.d.verb ? 1 : 0))
    .map((x) => x.d);
}

export function prepareReview(def: ActionDef, registry: Registry, opts: { previous?: ActionDef } = {}): ReviewView {
  const eff = effective(def, registry);
  // the card shows what the reviewer would be signing (the hint), not the all-traits view that applies until they sign
  const shown: Effective = { ...eff, ...eff.hint, confirmed: true };
  const sb = (def.review.suggested_by ?? {}) as Partial<SuggestedBy>;
  const changes: string[] = [];
  if (opts.previous) {
    const strip = (d: ActionDef) => ({ ...d, review: undefined, examples: undefined, source: undefined, since: undefined }) as Record<string, unknown>;
    const a = strip(opts.previous), b = strip(def);
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) changes.push(k);
    changes.sort();
  }
  return {
    verb: def.verb,
    def_digest: defDigest(def),
    state: def.review.state,
    declared_traits: sortUniq(def.traits ?? []),
    implied_traits: impliedTraits(normalize(def)),
    suggested: sb.added ?? { traits: [], roles: {}, tags: {} },
    effective: eff,
    card: cardOf(def, shown, registry),
    changes,
    priority: reviewPriority(def, registry),
  };
}

export interface ConfirmOpts {
  registry: Registry;
  reviewer: { kid: string; secret: Uint8Array };
  /** When given, the reviewer must be pinned with the `reviewer` role under this key. */
  pins?: ReviewerPins;
  /** The final DECLARED trait set (the reviewer's decision). */
  finalTraits: TraitId[];
  /** Every suggested (or importer-declared) trait left out of the final set needs a reason. */
  dismissed?: { trait: TraitId; reason: string }[];
  ts: number;
}

/**
 * Review one def: validates the decision, writes the final traits, signs an attestation over the resulting digest and returns
 * the confirmed def. Throws ActionKitError (`bad_confirm`, `undismissed_suggestion`, `not_reviewer`) rather than guessing.
 */
export function confirmDef(def: ActionDef, o: ConfirmOpts): ActionDef {
  if (!Number.isSafeInteger(o.ts) || o.ts < 0) throw new ActionKitError('bad_confirm', 'ts must be a non-negative integer');
  const final = sortUniq(o.finalTraits);
  if (final.length !== o.finalTraits.length) throw new ActionKitError('bad_confirm', 'final traits must be distinct');
  for (const t of final) {
    if (!TRAIT_ID_RE.test(t) || !o.registry.traits.has(t)) throw new ActionKitError('bad_confirm', `unknown trait '${t}'`);
    if (t === 'pca.unreviewed') throw new ActionKitError('bad_confirm', "'pca.unreviewed' is the review marker, not a final trait");
  }
  const dismissed = [...(o.dismissed ?? [])];
  const dset = new Set<string>();
  for (const d of dismissed) {
    if (typeof d.reason !== 'string' || d.reason.trim().length === 0 || d.reason.length > 256) throw new ActionKitError('bad_confirm', `dismissed trait '${d.trait}' needs a reason (1..256 characters)`);
    if (dset.has(d.trait)) throw new ActionKitError('bad_confirm', `trait '${d.trait}' is dismissed twice`);
    dset.add(d.trait);
    if (final.includes(d.trait)) throw new ActionKitError('bad_confirm', `trait '${d.trait}' is both final and dismissed`);
  }
  // what the reviewer was shown: the importer's and the suggesters' traits, plus what the def already declares
  const sb = (def.review.suggested_by ?? {}) as Partial<SuggestedBy>;
  const shown = sortUniq([...(def.traits ?? []), ...(sb.added?.traits ?? [])]);
  const covered = new Set(closure(o.registry, sortUniq([...final, ...impliedTraits(normalize(def))])));
  for (const t of shown) {
    if (final.includes(t) || covered.has(t)) continue;
    if (!dset.has(t)) throw new ActionKitError('undismissed_suggestion', `trait '${t}' was suggested and is not in the final set: record it as dismissed with a reason`);
  }
  for (const t of dset) if (!shown.includes(t)) throw new ActionKitError('bad_confirm', `trait '${t}' was never suggested; nothing to dismiss`);
  if (o.pins) {
    const pe = reviewerPinsError(o.pins);
    if (pe) throw new ActionKitError('bad_confirm', pe);
    const key = o.pins.keys.find((k) => k.kid === o.reviewer.kid);
    if (!key || !key.roles.includes('reviewer')) throw new ActionKitError('not_reviewer', `key '${o.reviewer.kid}' is not pinned with the reviewer role`);
    if (key.pk !== b64u(publicKeyOf(o.reviewer.secret))) throw new ActionKitError('not_reviewer', `the secret does not belong to the pinned key '${o.reviewer.kid}'`);
  }
  const body = { ...def, traits: final };
  if (final.length === 0) delete (body as { traits?: unknown }).traits;
  const digest = defDigest(body as ActionDef);
  // the facts of the verb this definition publishes: the verifier will recompute them from the schema and compare
  const att = signReview({ def_digest: digest, traits_digest: traitsDigest(o.registry), facts_digest: factsDigest(toSchemaVerb(body as ActionDef, o.registry).verb), final_traits: final, dismissed, reviewer_kid: o.reviewer.kid, ts: o.ts }, o.reviewer.secret);
  const out: ActionDef = { ...(body as ActionDef), review: { ...def.review, state: 'confirmed', attestation: att } };
  const bad = validateDef(out);
  if (bad !== null) throw new ActionKitError('bad_confirm', `the confirmed def is invalid: ${bad}`);
  return out;
}
