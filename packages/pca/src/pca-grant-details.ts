import { decodeB64uStrict, hashCanonical } from './hash';

/**
 * THE `pca_grant` AUTHORIZATION-DETAILS TYPE (OAuth Rich Authorization Requests, RFC 9396).
 *
 * Any OAuth authorization server can carry a PCA grant without implementing PCA: it issues an ordinary access token
 * whose `authorization_details` contains one object naming the grant by digest. The resource server resolves the chain
 * and STILL requires a per-action PCActn on every call. The token alone is never sufficient; the details type only says
 * which grant the token was issued for.
 *
 *   { "type": "pca_grant",
 *     "chain_digest": "<b64u sha-256 over the first chain_len capability ids>",
 *     "chain_len": 1,
 *     "chain_ref": "https://as.example/pca/grants/g_123",   (optional, where the chain can be fetched)
 *     "bundle_revision": 7,                                 (optional, policy bundle revision in force)
 *     "locations": ["https://api.example"] }                (optional, RFC 9396 section 2.2 resource servers)
 *
 * Profile rules (all fail closed):
 *  - `type`, `chain_digest` and `chain_len` are required. `chain_digest` is canonical unpadded base64url of 32 bytes.
 *  - Only the members above are allowed. RFC 9396 common members that would let an authorization server restate the
 *    authority in its own words (`actions`, `datatypes`, `identifier`, `privileges`) are refused: the grant is the
 *    authority, the details type is a pointer.
 *  - `chain_ref` and every `locations` entry are https URLs without credentials or fragment.
 *  - Details of other types in the same array are ignored by this profile; a malformed `pca_grant` entry, or a non-object
 *    entry, refuses the whole array.
 *  - At the resource server (checkPcaGrantPresentation): the presented chain must begin with the named hops (attenuation
 *    appends hops, so a delegated chain still matches), `locations` must include this resource when present, and a
 *    verified per-action proof is required.
 *
 * Specification: RFC 9396 (https://www.rfc-editor.org/rfc/rfc9396). Nothing here verifies a signature; the chain and the
 * PCActn are verified by the PCA verifier, which this check gates.
 */
export const PCA_GRANT_TYPE = 'pca_grant';
export const PCA_GRANT_DOMAIN = 'atlas-pca/pca-grant-chain/v1';
export const PCA_GRANT_MAX_DETAILS = 16;
export const PCA_GRANT_MAX_CHAIN_LEN = 16;
const MAX_URL = 2048;
const MAX_LOCATIONS = 8;
const MEMBERS = new Set(['type', 'chain_digest', 'chain_len', 'chain_ref', 'bundle_revision', 'locations']);
const RFC9396_COMMON_REFUSED = new Set(['actions', 'datatypes', 'identifier', 'privileges']);

export interface PcaGrantDetail {
  type: 'pca_grant';
  chain_digest: string;
  chain_len: number;
  chain_ref?: string;
  bundle_revision?: number;
  locations?: string[];
}

export type PcaGrantDetailCode =
  | 'not_an_array'
  | 'too_many_details'
  | 'bad_entry'
  | 'bad_type'
  | 'unknown_member'
  | 'refused_member'
  | 'bad_chain_digest'
  | 'bad_chain_len'
  | 'bad_chain_ref'
  | 'bad_bundle_revision'
  | 'bad_locations';

export type PcaGrantDetailResult = { ok: true; detail: PcaGrantDetail } | { ok: false; code: PcaGrantDetailCode };
export type PcaGrantDetailsResult = { ok: true; details: PcaGrantDetail[] } | { ok: false; code: PcaGrantDetailCode };

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

/**
 * https URL by a deliberately simple, portable rule (every verifier implements the same loop, so the vectors agree):
 * starts with `https://`, only printable ASCII (0x21-0x7e) without `#` or `\\`, at most 2048 characters, and an
 * authority (up to the first `/` or `?`) that is non-empty and has no `@` (no userinfo).
 */
export function isHttpsUrl(u: unknown): u is string {
  if (typeof u !== 'string' || u.length > MAX_URL || !u.startsWith('https://')) return false;
  for (let i = 0; i < u.length; i++) {
    const c = u.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || c === 0x23 || c === 0x5c) return false;
  }
  const rest = u.slice(8);
  const end = rest.search(/[/?]/);
  const authority = end === -1 ? rest : rest.slice(0, end);
  return authority.length > 0 && !authority.includes('@');
}

/** The digest an authorization server writes and a resource server recomputes: over the first hops' capability ids, in order. */
export function pcaChainDigest(capIds: readonly string[]): string {
  return hashCanonical({ d: PCA_GRANT_DOMAIN, ids: [...capIds] });
}

/** Validate one `authorization_details` object of type `pca_grant`. Never throws. */
export function validatePcaGrantDetail(x: unknown): PcaGrantDetailResult {
  if (!isObj(x)) return { ok: false, code: 'bad_entry' };
  if (x.type !== PCA_GRANT_TYPE) return { ok: false, code: 'bad_type' };
  for (const k of Object.keys(x)) {
    if (RFC9396_COMMON_REFUSED.has(k)) return { ok: false, code: 'refused_member' };
    if (!MEMBERS.has(k)) return { ok: false, code: 'unknown_member' };
  }
  if (typeof x.chain_digest !== 'string' || decodeB64uStrict(x.chain_digest, 32) === null) return { ok: false, code: 'bad_chain_digest' };
  const n = x.chain_len;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 1 || n > PCA_GRANT_MAX_CHAIN_LEN) return { ok: false, code: 'bad_chain_len' };
  if (x.chain_ref !== undefined && !isHttpsUrl(x.chain_ref)) return { ok: false, code: 'bad_chain_ref' };
  if (x.bundle_revision !== undefined && !(typeof x.bundle_revision === 'number' && Number.isSafeInteger(x.bundle_revision) && x.bundle_revision >= 0)) {
    return { ok: false, code: 'bad_bundle_revision' };
  }
  if (x.locations !== undefined) {
    const l = x.locations;
    if (!Array.isArray(l) || l.length === 0 || l.length > MAX_LOCATIONS || !l.every(isHttpsUrl)) return { ok: false, code: 'bad_locations' };
  }
  return { ok: true, detail: x as unknown as PcaGrantDetail };
}

/**
 * Read the `pca_grant` entries of an `authorization_details` array (a token claim or an introspection field). Entries of
 * other types are left to their owners. A malformed `pca_grant` entry or a non-object entry refuses the array.
 */
export function parsePcaGrantDetails(authorizationDetails: unknown): PcaGrantDetailsResult {
  if (!Array.isArray(authorizationDetails)) return { ok: false, code: 'not_an_array' };
  if (authorizationDetails.length > PCA_GRANT_MAX_DETAILS) return { ok: false, code: 'too_many_details' };
  const details: PcaGrantDetail[] = [];
  for (const e of authorizationDetails) {
    if (!isObj(e) || typeof e.type !== 'string') return { ok: false, code: 'bad_entry' };
    if (e.type !== PCA_GRANT_TYPE) continue;
    const r = validatePcaGrantDetail(e);
    if (!r.ok) return r;
    details.push(r.detail);
  }
  return { ok: true, details };
}

export type PcaGrantPresentationCode = 'no_detail' | 'proof_required' | 'chain_mismatch' | 'wrong_location';
export type PcaGrantPresentationResult = { allow: true; detail: PcaGrantDetail } | { allow: false; code: PcaGrantPresentationCode };

export interface PcaGrantPresentation {
  /** This resource server's identifier (RFC 8707). */
  resource: string;
  /** Capability ids of the chain the PCActn carries, root first. */
  chainIds: readonly string[];
  /** True only when the per-action PCActn was verified by the PCA verifier for this call. The token alone is never enough. */
  proofVerified: boolean;
}

/**
 * Gate the access token's `pca_grant` details against what the caller actually presented. Allow only when a verified
 * per-action proof is present AND some detail names a prefix of the presented chain AND (when it lists locations) this
 * resource. Every other case is a deny with the first failing reason; with several details, one passing detail is enough.
 */
export function checkPcaGrantPresentation(details: readonly PcaGrantDetail[], p: PcaGrantPresentation): PcaGrantPresentationResult {
  if (details.length === 0) return { allow: false, code: 'no_detail' };
  if (p.proofVerified !== true) return { allow: false, code: 'proof_required' };
  let reason: PcaGrantPresentationCode = 'chain_mismatch';
  for (const d of details) {
    if (p.chainIds.length < d.chain_len || pcaChainDigest(p.chainIds.slice(0, d.chain_len)) !== d.chain_digest) continue;
    if (d.locations !== undefined && !d.locations.includes(p.resource)) {
      reason = 'wrong_location';
      continue;
    }
    return { allow: true, detail: d };
  }
  return { allow: false, code: reason };
}
