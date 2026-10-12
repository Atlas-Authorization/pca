import { type Capability, type CapabilityChain, readEnvelope, verifyChain } from '@atlasauth/pca';

/**
 * Canonical attribute strings derived from a real PCA capability (see `@atlasauth/pca`'s `Capability`
 * and the signed policy `Envelope`). An "attribute" is a lowercase `kind:value` token; a policy
 * references attributes by exactly these tokens, and `keygenForCapability` issues one per-attribute
 * decryption key (the collusion-resistant per-holder-randomised scheme in `index.ts`, not plain
 * Boneh-Franklin IBE) per token the capability carries.
 *
 * Four kinds are derived, matching the capability's authority surface (verb / resource / scopes /
 * holder):
 *   - `holder:<b64u key>`   the key the capability is bound to (`capability.holder`),
 *   - `verb:<v>`            every literal verb named in the signed envelope's predicates,
 *   - `resource:<r>`        every resource matcher named in those predicates,
 *   - `scope:<s>`           every scope carried in a `{ type:'scope', value }` or
 *                           `{ type:'scopes', values:[...] }` caveat.
 *
 *   - `act:["<v>","<r>"]`    a BOUND (verb, resource) pair, one per verb x resource of each predicate.
 *
 * With a single predicate the flat `verb:` / `resource:` tokens are exact and are also emitted. With
 * two or more predicates only the pair tokens (plus holder/scope) are emitted, so the pairing cannot
 * be recombined (RT-08, breaking). Predicate `where` conditions and non-predicate caveats are NOT
 * reflected in any token: a policy that depends on them must also require a `scope:` or `holder:`.
 *
 * `scope:` tokens, and (R3-09) the envelope predicates behind `act:`/`verb:`/`resource:`, come ONLY from the ROOT capability (R2-07). Attenuation may append ANY caveat, so a
 * delegated hop's own `scope` caveats are restrictions, never grants: reading them as positive attributes would let a
 * delegatee append `scope:admin` and obtain a key for it. A delegated capability (one with a `parent`) therefore yields
 * `scope:`/`act:`/`verb:`/`resource:` tokens only when the verified `chain` (root first, ending in that capability) is supplied, and then from
 * `chain[0]` alone. Without a chain a delegated capability gets no `scope:` tokens; a supplied chain that fails
 * verification yields NO attributes (fail closed).
 */

export interface CapabilityAttributeOpts {
  /** The capability chain, root first, whose last element is the capability. Required for `scope:` tokens on a delegated hop. */
  chain?: CapabilityChain;
  /** The principal key the root must be issued by (recommended: pin it; defaults to the chain's own root issuer). */
  principal?: string;
  /** verifier-side PQ pins by Ed25519 identity (R3-01). A pure-PQ / hybrid ROOT is accepted only if the root issuer has a pin equal to its `pq_pk` (a signed binding from `pqPinFor`, or your own registry); without one it is refused. */
  pqPins?: Readonly<Record<string, string>>;
}

export const Attr = {
  holder: (key: string): string => `holder:${key}`,
  verb: (v: string): string => `verb:${v}`,
  resource: (r: string): string => `resource:${r}`,
  scope: (s: string): string => `scope:${s}`,
  /** A bound (verb, resource) pair: only a predicate that grants exactly this verb ON exactly this resource yields it. */
  act: (verb: string, resource: string): string => `act:${JSON.stringify([verb, resource])}`,
} as const;

function addVerb(out: Set<string>, verb: unknown): void {
  if (typeof verb === 'string') out.add(Attr.verb(verb));
  else if (Array.isArray(verb)) for (const v of verb) if (typeof v === 'string') out.add(Attr.verb(v));
}

function verbsOf(verb: unknown): string[] {
  if (typeof verb === 'string') return [verb];
  if (Array.isArray(verb)) return verb.filter((v): v is string => typeof v === 'string');
  return [];
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
export function capabilityAttributes(cap: Capability, opts: CapabilityAttributeOpts = {}): Set<string> {
  const out = new Set<string>();
  let scopeSource: readonly { type: string; [k: string]: unknown }[] | undefined;
  // R3-09: the envelope (act/verb/resource tokens) is read from the ROOT only, like scopes: a delegatee may append
  // its own envelope caveat, which is a restriction, never a grant.
  let envSource: Capability | undefined;
  if (opts.chain !== undefined) {
    const chain = opts.chain;
    const root = chain[0];
    if (!Array.isArray(chain) || chain.length === 0 || chain[chain.length - 1]?.id !== cap.id || root === undefined) return out;
    const v = verifyChain(chain, opts.principal ?? root.issuer, { pqPins: opts.pqPins });
    if (!v.ok) return out;
    scopeSource = root.caveats;
    envSource = root;
  } else if (cap.parent === undefined) {
    scopeSource = cap.caveats; // a root capability
    envSource = cap;
  }
  if (typeof cap.holder === 'string' && cap.holder.length > 0) out.add(Attr.holder(cap.holder));
  if (Array.isArray(scopeSource)) addScopes(out, scopeSource);
  const env = envSource === undefined ? null : readEnvelope(envSource);
  if (env !== null && Array.isArray(env.predicates)) {
    const preds = env.predicates.filter((p) => p !== null && typeof p === 'object');
    // Paired tokens: one per (verb, resource) of each predicate. These are the ONLY tokens that
    // carry authority when the envelope holds more than one predicate (RT-08).
    for (const p of preds) {
      const verbs = verbsOf((p as { verb?: unknown }).verb);
      const r = (p as { resource?: unknown }).resource;
      if (typeof r === 'string') for (const v of verbs) out.add(Attr.act(v, r));
    }
    // Flat verb:/resource: tokens are exact only for a single predicate (verbs x ONE resource), so
    // they are emitted only then; with several predicates they would cross-pair (read of A + write
    // of B would also open "read B").
    if (preds.length === 1) {
      const p = preds[0] as { verb?: unknown; resource?: unknown };
      addVerb(out, p.verb);
      if (typeof p.resource === 'string') out.add(Attr.resource(p.resource));
    }
  }
  return out;
}
