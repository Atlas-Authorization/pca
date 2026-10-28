// confirmation.ts - the signed human confirmation of an action (spec section 5.4), the ONLY thing that can set an action's
// effective trait set below the top of the registry ("unconfirmed means maximally dangerous"). Pure and cycle-free: it reads
// the def digest and the trait digest only, so the trait algebra (effective.ts), the schema derivations (derive.ts) and the
// review flow (import/review.ts) can all depend on it.

import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, sign, utf8, verifyB64u } from '@atlasauth/pca';
import type { ReviewRef } from './def';
import { traitsDigest } from './digest';
import { sortUniq } from './normalize';
import type { Registry } from './traits';

export const REVIEW_DOMAIN = 'atlas-pca/action-review/v2';
export const VERB_FACTS_DOMAIN = 'atlas-pca/action-verb-facts/v1';

/**
 * Digest of what a schema verb SAYS about the action: the verb as published minus the members a confirmation decides or carries
 * (`traits`, `floors`, `confirmation`) and the def digest itself. The reviewer signs this next to the def digest, so a confirmation
 * applies only to a verb whose own visible facts (name, kind, parameters with roles/units/domains, effects, reversibility, bindings,
 * description) are exactly the ones they saw: edit any of them, or claim the digest of another definition, and it is unconfirmed.
 */
export const factsDigest = (verb: object): string => {
  const v: Record<string, unknown> = { ...(verb as Record<string, unknown>) };
  for (const k of ['traits', 'floors', 'confirmation', 'def']) delete v[k];
  return hashCanonical({ d: VERB_FACTS_DOMAIN, verb: v });
};

export const KEY_ROLES = ['reviewer', 'importer', 'model', 'publisher'] as const;
export type KeyRole = (typeof KEY_ROLES)[number];

/** A key pinned in the registry. */
export interface PinnedKey {
  kid: string;
  /** b64u Ed25519 public key (32 bytes). */
  pk: string;
  roles: KeyRole[];
  /** Seconds; an attestation timestamp outside [not_before, not_after] is refused. */
  not_before?: number;
  not_after?: number;
}

export interface ReviewerPins {
  keys: PinnedKey[];
  /** Registry digests besides the one in use that attestations may name (e.g. the previous release's). */
  traits_digests?: string[];
}

/** Null if the pin set is sound: distinct kids, canonical keys, known roles, and no key that is both a reviewer and a machine. */
export function reviewerPinsError(p: ReviewerPins): string | null {
  if (p === null || typeof p !== 'object' || !Array.isArray(p.keys)) return 'pins must be {keys: [...]}';
  const kids = new Set<string>();
  const machinePks = new Set<string>();
  for (const k of p.keys) {
    if (typeof k?.kid !== 'string' || k.kid.length === 0 || k.kid.length > 128) return 'a pinned key needs a kid';
    if (kids.has(k.kid)) return `kid '${k.kid}' is pinned twice`;
    kids.add(k.kid);
    if (decodeB64uStrict(k.pk, 32) === null) return `key '${k.kid}': pk is not canonical base64url (32 bytes)`;
    if (!Array.isArray(k.roles) || k.roles.length === 0 || !k.roles.every((r) => (KEY_ROLES as readonly string[]).includes(r)) || new Set(k.roles).size !== k.roles.length) return `key '${k.kid}': roles must be distinct known roles`;
    if (k.roles.includes('reviewer') && (k.roles.includes('importer') || k.roles.includes('model'))) return `key '${k.kid}': an importer or model key cannot hold the reviewer role`;
    for (const t of ['not_before', 'not_after'] as const) if (k[t] !== undefined && (!Number.isSafeInteger(k[t]) || (k[t] as number) < 0)) return `key '${k.kid}': ${t} must be a non-negative integer`;
    if (k.roles.includes('importer') || k.roles.includes('model')) machinePks.add(k.pk);
  }
  // the same key material under a second kid must not smuggle a machine key into the reviewer role
  for (const k of p.keys) if (k.roles.includes('reviewer') && machinePks.has(k.pk)) return `key '${k.kid}': the same key material is pinned as an importer or model key`;
  return null;
}

// ---- the attestation --------------------------------------------------------------------------------------------------

type Body = Omit<ReviewRef, 'sig'>;

/** Domain-separated message the reviewer signs: `REVIEW_DOMAIN \0 strictCanonical(body)`. */
export function reviewMessage(b: Body): Uint8Array {
  const body = canonicalBytesStrict({
    def_digest: b.def_digest,
    traits_digest: b.traits_digest,
    facts_digest: b.facts_digest,
    final_traits: sortUniq(b.final_traits),
    dismissed: [...b.dismissed].sort((x, y) => (x.trait < y.trait ? -1 : x.trait > y.trait ? 1 : 0)).map((d) => ({ trait: d.trait, reason: d.reason })),
    reviewer_kid: b.reviewer_kid,
    ts: b.ts,
  });
  const dom = utf8(REVIEW_DOMAIN + '\0');
  const out = new Uint8Array(dom.length + body.length);
  out.set(dom);
  out.set(body, dom.length);
  return out;
}

export function signReview(b: Body, secret: Uint8Array): ReviewRef {
  const norm: Body = { ...b, final_traits: sortUniq(b.final_traits), dismissed: [...b.dismissed].sort((x, y) => (x.trait < y.trait ? -1 : 1)) };
  return { ...norm, sig: b64u(sign(secret, reviewMessage(norm))) };
}


// ---- the confirmation as a verifier sees it: on a signed schema verb, with the pinned reviewer keys --------------------------

/** The part of a v2 schema verb a verifier reads to decide whether its confirmation counts. */
export interface ConfirmableVerb {
  def?: string;
  traits?: string[];
  confirmation?: ReviewRef;
  [member: string]: unknown;
}

/**
 * Null iff this verb carries a VALID human confirmation: an attestation over exactly the def digest the verb names, against an
 * accepted trait registry digest, whose final traits are carried by the verb, signed by a key pinned with the `reviewer` role
 * (inside its validity window). Anything else - absent, malformed, unsigned, unpinned key, wrong role, stale digest, bad
 * signature, no pins - is a reason string, and the verb is UNCONFIRMED: its effective traits are the top of the registry.
 * Never throws; every failure is a refusal to count the confirmation, never a pass.
 */
export function verbConfirmationError(v: ConfirmableVerb, reg: Registry, pins: ReviewerPins | undefined): string | null {
  try {
    if (pins === undefined) return 'no reviewer keys are pinned';
    const pe = reviewerPinsError(pins);
    if (pe) return `bad pins: ${pe}`;
    const a = v.confirmation;
    if (a === undefined) return 'no confirmation';
    if (typeof a !== 'object' || a === null) return 'confirmation is not an object';
    if (typeof a.sig !== 'string') return 'the confirmation is unsigned';
    if (typeof v.def !== 'string' || a.def_digest !== v.def) return 'the confirmation covers a different def digest';
    const accepted = new Set([traitsDigest(reg), ...(pins.traits_digests ?? [])]);
    if (!accepted.has(a.traits_digest)) return 'the confirmation was made against a different trait registry';
    if (typeof a.facts_digest !== 'string' || a.facts_digest !== factsDigest(v)) return 'the verb facts differ from the facts the reviewer confirmed';
    if (!Array.isArray(a.final_traits) || !Array.isArray(a.dismissed) || !Number.isSafeInteger(a.ts) || typeof a.reviewer_kid !== 'string') return 'malformed confirmation';
    const carried = new Set(v.traits ?? []);
    if (a.final_traits.some((t) => typeof t !== 'string' || !carried.has(t))) return 'the verb does not carry every trait the reviewer signed';
    const fin = new Set(a.final_traits);
    if (a.dismissed.some((d) => typeof d?.trait !== 'string' || typeof d.reason !== 'string' || fin.has(d.trait) || d.reason.trim().length === 0)) return 'a dismissed trait is also final, or has no reason';
    const key = pins.keys.find((k) => k.kid === a.reviewer_kid);
    if (!key) return `no pinned key '${a.reviewer_kid}'`;
    if (!key.roles.includes('reviewer')) return `key '${key.kid}' does not hold the reviewer role`;
    if ((key.not_before !== undefined && a.ts < key.not_before) || (key.not_after !== undefined && a.ts > key.not_after)) return 'the confirmation time is outside the key validity';
    const { sig, ...body } = a;
    return verifyB64u(key.pk, reviewMessage(body), sig) ? null : 'the confirmation signature is invalid';
  } catch (e) {
    return `malformed confirmation: ${(e as Error).message}`;
  }
}
