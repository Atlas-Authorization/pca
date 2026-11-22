/**
 * SCOPES DERIVED FROM THE ACTION, for MCP and OAuth (the scope side of "credential brokering bound to the action"; the vault
 * side, proxy mode and release receipts are K7's `VaultAction` in `@atlasauth/pca-connect`, which uses the same field names).
 *
 * The scopes a request needs or a token may carry come from the reviewed ActionDef's `upstream` declaration, not from the caller
 * and not from the grant alone: `scopes = upstream.scopes_min`, and every one of them must lie inside the grant's scopes. A
 * definition without a valid signed confirmation (`confirmed: false`), an action this server does not know, a provider mismatch
 * or an empty scope list derives NOTHING: the answer is a refusal, never a guess and never a broader default.
 */
export interface ScopeAction {
  /** The ActionDef verb. */
  verb: string;
  /** `defDigest` of the definition this mapping was written for (informational pin). */
  def_digest: string;
  /** True iff the definition carries a valid signed confirmation. Unconfirmed: nothing is derived. */
  confirmed: boolean;
  upstream: { provider: string; scopes_min: readonly string[] };
}

export type ScopeDerivation =
  | { ok: true; scopes: string[]; provider: string; def_digest: string }
  | { ok: false; code: 'unknown_action' | 'unconfirmed' | 'provider_mismatch' | 'no_scopes' | 'bad_scope' | 'exceeds_grant' };

const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/; // RFC 6749 section 3.3 scope-token: no space, quote or backslash

/**
 * Derive the scopes for an action. `granted` is the scope set the grant (or the stored connection) allows; when given, every
 * derived scope must be in it (the action can ask for less than the grant, never more). `provider` pins the upstream.
 */
export function deriveActionScopes(action: ScopeAction | undefined, o: { provider?: string; granted?: readonly string[] } = {}): ScopeDerivation {
  if (action === undefined || action === null || typeof action !== 'object') return { ok: false, code: 'unknown_action' };
  if (action.confirmed !== true) return { ok: false, code: 'unconfirmed' };
  const up = action.upstream;
  if (o.provider !== undefined && up?.provider !== o.provider) return { ok: false, code: 'provider_mismatch' };
  const min = up?.scopes_min;
  if (!Array.isArray(min) || min.length === 0) return { ok: false, code: 'no_scopes' };
  if (!min.every((s) => typeof s === 'string' && s.length <= 256 && SCOPE_TOKEN.test(s))) return { ok: false, code: 'bad_scope' };
  const scopes = [...new Set(min)].sort();
  if (o.granted !== undefined) {
    const g = new Set(o.granted);
    if (!scopes.every((s) => g.has(s))) return { ok: false, code: 'exceeds_grant' };
  }
  return { ok: true, scopes, provider: up.provider, def_digest: action.def_digest };
}
