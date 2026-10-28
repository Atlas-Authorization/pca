// digest.ts - canonical digests (spec section 2.3). defDigest is the interoperability contract: every native computes
// the same bytes. Strict canonical JSON (safe integers only) from @atlasauth/pca.

import { hashCanonical, merkleProof, merkleRoot, verifyInclusion, type InclusionProof } from '@atlasauth/pca';
import { ActionKitError, CORE_ROLES, type ActionDef } from './def';
import { ROLE_SENSITIVITY_FLOOR, ROLE_TRAITS, TAG_SENSITIVITY_FLOOR, TAG_TRAITS, EFFECT_TRAITS } from './core-traits';
import { normalize } from './normalize';
import type { Registry } from './traits';

export const DEF_DIGEST_DOMAIN = 'atlas-pca/action-def/v1';
export const TRAITS_DIGEST_DOMAIN = 'atlas-pca/action-traits/v1';
export const ROLES_DIGEST_DOMAIN = 'atlas-pca/action-roles/v1';
export const PACK_DIGEST_DOMAIN = 'atlas-pca/action-pack/v1';

/** b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it. */
export const defDigest = (d: ActionDef): string => hashCanonical({ d: DEF_DIGEST_DOMAIN, def: normalize(d) });

/** Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`. Includes the implication tables for the core registry. */
export function traitsDigest(reg: Registry): string {
  const traits = [...reg.traits.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map((t) => ({ id: t.id, implies: [...t.implies].sort(), floor: t.floor, card_phrase: t.card_phrase }));
  return hashCanonical({ d: TRAITS_DIGEST_DOMAIN, traits });
}

/** Digest of the implication and sensitivity tables the trait expansion reads (effect/role/tag -> trait, role/tag -> floor). */
export function tablesDigest(): string {
  return hashCanonical({
    d: ROLES_DIGEST_DOMAIN,
    roles: [...CORE_ROLES],
    effect_traits: EFFECT_TRAITS,
    role_traits: ROLE_TRAITS,
    tag_traits: TAG_TRAITS,
    role_sensitivity: ROLE_SENSITIVITY_FLOOR,
    tag_sensitivity: TAG_SENSITIVITY_FLOOR,
  });
}

const leaf = (digest: string) => ({ d: PACK_DIGEST_DOMAIN, def: digest });
const sortedDigests = (digests: readonly string[]): string[] => {
  const s = [...new Set(digests)].sort();
  if (s.length !== digests.length) throw new ActionKitError('duplicate_def', 'a pack lists a def digest twice');
  if (s.length === 0) throw new ActionKitError('empty_pack', 'a pack has at least one def');
  return s;
};

/** Merkle root over the sorted def digests (RFC 6962 shape, domain separated leaves). */
export const packRoot = (digests: readonly string[]): string => merkleRoot(sortedDigests(digests).map(leaf));

/** Inclusion proof of `digest` in the pack made of `digests`. */
export function packProof(digests: readonly string[], digest: string): InclusionProof {
  const s = sortedDigests(digests);
  const i = s.indexOf(digest);
  if (i < 0) throw new ActionKitError('not_in_pack', 'the digest is not in the pack');
  return merkleProof(s.map(leaf), i);
}

/** Does `proof` show `digest` is in the pack with root `root`? */
export const verifyPackProof = (root: string, proof: InclusionProof, digest: string): boolean => verifyInclusion(root, proof, leaf(digest));
