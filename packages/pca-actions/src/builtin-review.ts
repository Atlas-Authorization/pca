// builtin-review.ts - how the hand-written built-in defs become CONFIRMED. A built-in is human-reviewed in this repository, but the
// algebra trusts only a signed attestation, so the release process signs each built-in def with the release reviewer key
// (scripts/sign-builtins.ts, key supplied in the environment at release time; no key lives in this repository) and writes the
// result to builtin-release.generated.ts together with the PUBLIC key as the pinned reviewer. Reading the built-ins from a build
// without that step yields unconfirmed defs, whose effective traits are the top of the registry.

import { confirmDef, attestationVerifier, type VerifyCtx } from './import/review';
import { BUILTIN_DEFS } from './builtin';
import { BUILTIN_RELEASE } from './builtin-release.generated';
import { CORE_REGISTRY } from './core-traits';
import type { ActionDef } from './def';
import type { ReviewOpts } from './effective';
import { sortUniq } from './normalize';
import type { Registry } from './traits';

/** The release pins and registry the built-in attestations verify against; null before the first release signing. */
export const builtinReleaseCtx = (reg: Registry = CORE_REGISTRY): VerifyCtx | null => (BUILTIN_RELEASE.pins === null ? null : { pins: BUILTIN_RELEASE.pins, registry: reg });

/** The built-in defs with their release attestation attached where the package carries one (others are returned unchanged and stay unconfirmed). */
export function releasedBuiltinDefs(defs: readonly ActionDef[] = BUILTIN_DEFS): ActionDef[] {
  return defs.map((d) => {
    const a = BUILTIN_RELEASE.attestations[d.verb];
    return a === undefined ? d : { ...d, traits: d.traits, review: { ...d.review, state: 'confirmed', attestation: a } };
  });
}

/** The review options under which the released built-ins count as confirmed: a signature by the pinned release key, nothing else. */
export function builtinReviewOpts(reg: Registry = CORE_REGISTRY): ReviewOpts {
  const ctx = builtinReleaseCtx(reg);
  return ctx === null ? {} : { attestationVerified: attestationVerifier(ctx) };
}

/** Release step: sign every built-in def. `secret` is the release reviewer key supplied by the caller; it is never stored. */
export function signBuiltins(args: { kid: string; secret: Uint8Array; ts: number; registry?: Registry; defs?: readonly ActionDef[] }): ActionDef[] {
  const registry = args.registry ?? CORE_REGISTRY;
  return (args.defs ?? BUILTIN_DEFS).map((d) => confirmDef(d, { registry, reviewer: { kid: args.kid, secret: args.secret }, finalTraits: sortUniq(d.traits ?? []), ts: args.ts }));
}
