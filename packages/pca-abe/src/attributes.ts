import { type Capability, readEnvelope } from '@atlasauth/pca';

/**
 * Canonical attribute strings derived from a real PCA capability (see `@atlasauth/pca`'s `Capability`
 * and the signed policy `Envelope`). An "attribute" is a lowercase `kind:value` token; a policy
 * references attributes by exactly these tokens, and `keygenForCapability` issues one BF-IBE decryption
 * key per token the capability carries.
 *
 * Four kinds are derived, matching the capability's authority surface (verb / resource / scopes /
 * holder):
 *   - `holder:<b64u key>`   the key the capability is bound to (`capability.holder`),
 *   - `verb:<v>`            every literal verb named in the signed envelope's predicates,
 *   - `resource:<r>`        every resource matcher named in those predicates,
 *   - `scope:<s>`           every scope carried in a `{ type:'scope', value }` or
 *                           `{ type:'scopes', values:[...] }` caveat.
 *
 * Because the envelope and caveats are SIGNED into the capability (and attenuation is append-only), the
 * attribute set a capability yields cannot be widened by a holder — it is exactly what the principal
 * authorised.
 */

export const Attr = {
  holder: (key: string): string => `holder:${key}`,
  verb: (v: string): string => `verb:${v}`,
  resource: (r: string): string => `resource:${r}`,
  scope: (s: string): string => `scope:${s}`,
} as const;

function addVerb(out: Set<string>, verb: unknown): void {
  if (typeof verb === 'string') out.add(Attr.verb(verb));
  else if (Array.isArray(verb)) for (const v of verb) if (typeof v === 'string') out.add(Attr.verb(v));
}

function addScopes(out: Set<string>, caveats: readonly { type: string; [k: string]: unknown }[]): void {
  for (const cv of caveats) {
    if (cv.type === 'scope' && typeof cv.value === 'string') out.add(Attr.scope(cv.value));
    if (cv.type === 'scopes' && Array.isArray(cv.values)) {
      for (const s of cv.values) if (typeof s === 'string') out.add(Attr.scope(s));
    }
  }
}

/**
 * Derive the canonical attribute set a capability possesses. Deterministic and total (never throws): a
 * capability with no signed envelope still yields its `holder:` attribute (plus any scope caveats).
 */
export function capabilityAttributes(cap: Capability): Set<string> {
  const out = new Set<string>();
  if (typeof cap.holder === 'string' && cap.holder.length > 0) out.add(Attr.holder(cap.holder));
  if (Array.isArray(cap.caveats)) addScopes(out, cap.caveats);
  const env = readEnvelope(cap);
  if (env !== null && Array.isArray(env.predicates)) {
    for (const p of env.predicates) {
      if (p === null || typeof p !== 'object') continue;
      addVerb(out, (p as { verb?: unknown }).verb);
      const r = (p as { resource?: unknown }).resource;
      if (typeof r === 'string') out.add(Attr.resource(r));
    }
  }
  return out;
}
