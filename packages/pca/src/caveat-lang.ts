import { capHash, type Capability, type CapabilityChain, type Caveat } from './capability';
import { b64u, decodeB64uStrict, hashCanonical, sha256, utf8 } from './hash';
import {
  type PinnedSigner,
  artifactSuiteError,
  closedMembers,
  isBoundedString,
  isDigest,
  isPathSegment,
  isPlainObject,
  isSafeInt,
  isScalar,
  nullRecord,
  ownGet,
  resolveParamPath,
  scalarEq,
  signArtifact,
  verifyArtifactSig,
  type WireScalar,
} from './intent-artifacts';
import { holderPqCommitment, type SignerSuiteOpts } from './pq';
import type { PCActn } from './pcactn';
import type { ReplayStore } from './replay';

/**
 * CAVEAT LANGUAGE v2 (track K1; security contract C-220..C-229; docs/pca/specs/caveat-language.md).
 *
 * Six verifier-side features, all of them RESTRICTIONS (a caveat only ever removes authority, so every one of them is
 * conjunctive with the rest of the chain and a verifier that does not know a type refuses the chain: unknown caveat
 * types are unsatisfied):
 *
 *  - `needs_discharge`  a third-party caveat: valid only with a signed discharge from a key THE VERIFIER pinned. The verifier
 *                       never contacts the third party; the discharge travels with the action (Macaroons, Birgisson et
 *                       al., NDSS 2014 section 4, with Biscuit's third-party blocks for the "holder fetches it" flow).
 *  - `sealed`           no hop may be appended below the hop that carries it.
 *  - `narrow` (artifact) a holder-signed per-action or short-lived self-attenuation that rides BESIDE the PCActn (no new hop).
 *  - `max_uses`         a lifetime use count backed by the verifier's existing {@link ReplayStore} (n atomic first-use slots).
 *  - `derive`           a bounded, stratified, non-recursive derived-fact check evaluated in Kleene three-valued logic.
 *  - `spiffe_bound`     the presenting workload's verified SPIFFE ID must match.
 *
 * Everything here is total: a malformed caveat, discharge, narrow block or context is a `false`/refusal, never an exception
 * and never an allow.
 */

export const CAVEAT_NEEDS_DISCHARGE = 'needs_discharge';
export const CAVEAT_SEALED = 'sealed';
export const CAVEAT_MAX_USES = 'max_uses';
export const CAVEAT_DERIVE = 'derive';
export const CAVEAT_SPIFFE_BOUND = 'spiffe_bound';
/** Caveat types this module evaluates (they need the chain position, the discharges or a store, so the stock evaluators refuse them). */
export const K1_CAVEAT_TYPES: readonly string[] = [CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND];
export const isK1Caveat = (c: unknown): boolean => isPlainObject(c) && typeof c.type === 'string' && K1_CAVEAT_TYPES.includes(c.type);

export const DISCHARGE_DOMAIN = 'atlas-pca/discharge/v1\0';
export const DISCHARGE_REF_DOMAIN = 'atlas-pca/discharge-ref/v1';
export const DISCHARGE_ACTION_DOMAIN = 'atlas-pca/discharge-action/v1';
export const NARROW_DOMAIN = 'atlas-pca/narrow/v1\0';
export const MAX_USES_DOMAIN = 'atlas-pca/max-uses/v1\0';
/** A discharge or narrow block lives at most 24 hours. */
export const K1_MAX_LIFETIME_MS = 86_400_000;
export const MAX_USES_LIMIT = 256;
export const NARROW_MAX_CAVEATS = 16;
export const DERIVE_MAX_DEFS = 8;
export const DERIVE_MAX_NODES = 32;
export const DERIVE_MAX_DEPTH = 4;
export const DERIVE_MAX_WINDOW_MS = 30 * 86_400_000;
export const DERIVE_MAX_HISTORY = 10_000;
export const SPIFFE_MAX_ID_BYTES = 2048;

const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
// `artifact`: an attestation verifier that checked build provenance (track K9, provenance-gate.ts); no other class can stand in for it.
const ISSUER_CLASSES = ['human', 'org', 'workload', 'model', 'artifact'] as const;
const OPS = ['eq', 'neq', 'gte', 'lte', 'in'] as const;
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
const isStr256 = (v: unknown): v is string => isBoundedString(v, 256);

// ======================================================================================
// SPIFFE ID syntax (SPIFFE-ID.md, https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
// ======================================================================================

/**
 * Null when `s` is a valid SPIFFE ID: `spiffe://` + a trust domain of lowercase letters, digits, `.`, `-`, `_` + an optional
 * path of non-empty segments over `[A-Za-z0-9._-]` that are not `.` or `..`, no trailing slash, at most 2048 bytes, no query
 * or fragment. Same rules as `parseSpiffeId` in `@atlasauth/pca-spiffe` (a cross-check test pins the two together).
 */
export function spiffeIdError(s: unknown): string | null {
  if (typeof s !== 'string' || s.length === 0) return 'SPIFFE ID must be a non-empty string';
  if (utf8(s).length > SPIFFE_MAX_ID_BYTES) return 'SPIFFE ID is too long';
  if (!s.startsWith('spiffe://')) return 'SPIFFE ID must begin with spiffe://';
  const rest = s.slice(9);
  const slash = rest.indexOf('/');
  const td = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? '' : rest.slice(slash);
  if (td.length === 0 || td.length > 255 || !/^[a-z0-9._-]+$/.test(td)) return 'invalid trust domain';
  if (path === '') return null;
  if (path.endsWith('/')) return 'path must not end with a slash';
  for (const seg of path.split('/').slice(1)) {
    if (seg.length === 0 || seg === '.' || seg === '..' || !/^[A-Za-z0-9._-]+$/.test(seg)) return 'invalid path segment';
  }
  return null;
}

// ======================================================================================
// Hop analysis: which hop introduced a caveat
// ======================================================================================

export interface BoundCaveat {
  caveat: Caveat;
  /** Index of the hop that introduced the caveat (0 = the root grant). */
  hop: number;
  /** capHash() of that hop. */
  cap_hash: string;
}

/**
 * What the caveat language needs to know about a chain: how many hops, the leaf, and per hop its hash and the length of its (cumulative)
 * caveat list. A full chain gives it directly; a compact chain (`chain-compact.ts`) gives it from a verified memo without the middle hops.
 */
export interface ChainView {
  readonly n: number;
  readonly leaf: Capability;
  hash(i: number): string;
  count(i: number): number;
}
export type ChainInput = CapabilityChain | ChainView;
const isView = (c: unknown): c is ChainView => c !== null && typeof c === 'object' && !Array.isArray(c) && typeof (c as ChainView).hash === 'function';

/** The view of the hops the policy layer sees: the chain (root first), else the grant alone. */
export function chainView(grant: Capability, chain: ChainInput | undefined): ChainView {
  if (isView(chain)) return chain;
  const hops: Capability[] = Array.isArray(chain) && chain.length > 0 ? chain : [grant];
  const cache = new Map<number, string>();
  return {
    n: hops.length,
    leaf: hops[hops.length - 1]!,
    hash: (i) => {
      if (!cache.has(i)) cache.set(i, capHash(hops[i]!));
      return cache.get(i)!;
    },
    count: (i) => (Array.isArray(hops[i]?.caveats) ? hops[i]!.caveats.length : 0),
  };
}

/**
 * Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only (`verifyChain`
 * checks the prefix rule), so the caveat at position `p` was introduced by the first hop whose list is longer than `p`.
 * Returns null for a malformed chain. The leaf's caveats include the root grant's, `envelope` included.
 */
export function boundCaveats(grant: Capability, chain?: ChainInput): BoundCaveat[] | null {
  try {
    const v = chainView(grant, chain);
    const leaf = v.leaf;
    if (!leaf || !Array.isArray(leaf.caveats)) return null;
    const out: BoundCaveat[] = [];
    leaf.caveats.forEach((caveat, p) => {
      let h = -1;
      for (let i = 0; i < v.n; i++) if (v.count(i) > p) { h = i; break; }
      if (h < 0) h = v.n - 1;
      out.push({ caveat, hop: h, cap_hash: v.hash(h) });
    });
    return out;
  } catch {
    return null;
  }
}

// ======================================================================================
// needs_discharge: the third-party caveat and its discharge
// ======================================================================================

export interface ClaimRequirement {
  claim: string;
  op: (typeof OPS)[number];
  value: WireScalar | WireScalar[];
}
export interface NeedsDischargeCaveat {
  type: 'needs_discharge';
  /** Unique among the chain's `needs_discharge` caveats. */
  id: string;
  /** Label of the verifier's pin that must sign the discharge (the token never names a key). */
  issuer: string;
  /** The class the pin must have. A `model` pin can only discharge a caveat that says `model`: no key gets promoted. */
  issuer_class: (typeof ISSUER_CLASSES)[number];
  /** `chain_hop`: reusable until `not_after`. `action`: bound to one PCActn (spent by the replay counter that admits it). */
  bind: 'chain_hop' | 'action';
  /** Longest accepted `not_after - iat`, 1..86_400_000. */
  ttl_ms: number;
  /** Every requirement must hold over the discharge's `claims` (an absent claim fails). At most 16. */
  require: ClaimRequirement[];
  /** Optional: the pin must carry exactly this SPIFFE ID (a workload as the attested issuer). */
  issuer_spiffe?: string;
}

function requireError(r: unknown): string | null {
  if (!isPlainObject(r)) return 'requirement must be an object';
  const e = closedMembers(r, ['claim', 'op', 'value'], [], 'require');
  if (e) return e;
  if (typeof r.claim !== 'string' || !NAME_RE.test(r.claim)) return 'claim name is malformed';
  if (!(OPS as readonly unknown[]).includes(r.op)) return 'op must be eq, neq, gte, lte or in';
  if (r.op === 'in') {
    if (!Array.isArray(r.value) || r.value.length === 0 || r.value.length > 16 || !r.value.every(isScalarClaim)) return "'in' needs 1..16 scalar values";
  } else if (r.op === 'gte' || r.op === 'lte') {
    if (!isSafeInt(r.value)) return `'${r.op}' needs a safe integer`;
  } else if (!isScalarClaim(r.value)) return 'value must be a scalar';
  return null;
}
const isScalarClaim = (v: unknown): v is WireScalar => isScalar(v) && (typeof v !== 'string' || isStr256(v));

/** Null when the caveat is well-formed: closed members, canonical names, bounded sizes. */
export function needsDischargeError(c: unknown): string | null {
  if (!isPlainObject(c)) return 'caveat must be an object';
  const e = closedMembers(c, ['type', 'id', 'issuer', 'issuer_class', 'bind', 'ttl_ms', 'require'], ['issuer_spiffe'], 'needs_discharge');
  if (e) return e;
  if (c.type !== CAVEAT_NEEDS_DISCHARGE) return 'not a needs_discharge caveat';
  if (typeof c.id !== 'string' || !ID_RE.test(c.id)) return 'id is malformed';
  if (typeof c.issuer !== 'string' || !ID_RE.test(c.issuer)) return 'issuer label is malformed';
  if (!(ISSUER_CLASSES as readonly unknown[]).includes(c.issuer_class)) return 'issuer_class must be human, org, workload, model or artifact';
  if (c.bind !== 'chain_hop' && c.bind !== 'action') return "bind must be 'chain_hop' or 'action'";
  if (!(isSafeInt(c.ttl_ms) && c.ttl_ms >= 1 && c.ttl_ms <= K1_MAX_LIFETIME_MS)) return 'ttl_ms must be 1..86400000';
  if (!Array.isArray(c.require) || c.require.length > 16) return 'require must be an array of at most 16 requirements';
  for (const r of c.require) {
    const re = requireError(r);
    if (re) return re;
  }
  if (c.issuer_spiffe !== undefined) {
    const se = spiffeIdError(c.issuer_spiffe);
    if (se) return `issuer_spiffe: ${se}`;
  }
  return null;
}

/** A verifier-side pin for a discharge issuer. `label` is what caveats name; the keys never appear in a token. */
export interface DischargePin extends PinnedSigner {
  label: string;
  class: (typeof ISSUER_CLASSES)[number];
  spiffe_id?: string;
}

export interface DischargeBody {
  v: 1;
  kind: 'pca-discharge';
  caveat_id: string;
  issuer: string;
  /** capHash() of the hop that carries the caveat. */
  cap_hash: string;
  bind: 'chain_hop' | 'action';
  /** Present iff `bind` is `action`: {@link dischargeActionDigest} of the exact PCActn. */
  action_digest?: string;
  /** At most 16 named scalars. */
  claims: Record<string, WireScalar>;
  iat: number;
  not_after: number;
  nonce: string;
  alg?: string;
  pq_pk?: string;
}
export type Discharge = DischargeBody & { sig: string; pq_sig?: string };

/** The digest of the exact PCActn (counter and signature included): a bind-`action` discharge authorises that one action. */
export function dischargeActionDigest(pcactn: PCActn): string {
  return hashCanonical({ d: DISCHARGE_ACTION_DOMAIN, pcactn });
}
/** Content address of a discharge (signature included); what a revocation list names. */
export function dischargeDigest(d: unknown): string {
  return hashCanonical({ d: DISCHARGE_REF_DOMAIN, discharge: d });
}

const D_REQUIRED = ['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'claims', 'iat', 'not_after', 'nonce', 'sig'] as const;
const D_OPTIONAL = ['action_digest', 'alg', 'pq_pk', 'pq_sig'] as const;

/** Null = well-formed. */
export function dischargeShapeError(a: unknown): string | null {
  if (!isPlainObject(a)) return 'not an object';
  const e = closedMembers(a, D_REQUIRED, D_OPTIONAL, 'discharge');
  if (e) return e;
  if (a.v !== 1 || a.kind !== 'pca-discharge') return 'not a pca-discharge v1';
  if (typeof a.caveat_id !== 'string' || !ID_RE.test(a.caveat_id)) return 'caveat_id is malformed';
  if (typeof a.issuer !== 'string' || !ID_RE.test(a.issuer)) return 'issuer label is malformed';
  if (!isDigest(a.cap_hash)) return 'cap_hash must be canonical base64url (32 bytes)';
  if (a.bind !== 'chain_hop' && a.bind !== 'action') return "bind must be 'chain_hop' or 'action'";
  if (a.bind === 'action' ? !isDigest(a.action_digest) : a.action_digest !== undefined) return 'action_digest is required for bind action and forbidden for chain_hop';
  if (!isPlainObject(a.claims) || Object.keys(a.claims).length > 16) return 'claims must be an object of at most 16 members';
  for (const [k, v] of Object.entries(a.claims)) if (!NAME_RE.test(k) || !isScalarClaim(v)) return `claim '${k}' is malformed`;
  if (!(isSafeInt(a.iat) && a.iat >= 0) || !(isSafeInt(a.not_after) && a.not_after >= 0)) return 'iat and not_after must be non-negative safe integers';
  if (!(a.not_after > a.iat)) return 'not_after must be greater than iat';
  if (a.not_after - a.iat > K1_MAX_LIFETIME_MS) return `a discharge lives at most ${K1_MAX_LIFETIME_MS} ms`;
  const nb = typeof a.nonce === 'string' ? decodeB64uStrict(a.nonce) : null;
  if (nb === null || nb.length < 16) return 'nonce must be canonical base64url of at least 16 bytes';
  if (typeof a.sig !== 'string') return 'sig must be a string';
  return artifactSuiteError(a);
}

/** The pinned issuer signs the exact bindings. Throws on a malformed body (fail closed). */
export function signDischarge(body: DischargeBody, issuerSecret: Uint8Array, suite?: SignerSuiteOpts): Discharge {
  const signed = signArtifact(DISCHARGE_DOMAIN, body as unknown as Record<string, unknown>, issuerSecret, suite) as unknown as Discharge;
  const e = dischargeShapeError(signed);
  if (e) throw new Error(`signDischarge: ${e}`);
  return signed;
}

function claimHolds(r: ClaimRequirement, claims: Record<string, WireScalar>): boolean {
  const v = ownGet(claims, r.claim);
  if (v === undefined) return false;
  switch (r.op) {
    case 'eq':
      return scalarEq(v, r.value);
    case 'neq':
      return !scalarEq(v, r.value);
    case 'gte':
      return isSafeInt(v) && v >= (r.value as number);
    case 'lte':
      return isSafeInt(v) && v <= (r.value as number);
    case 'in':
      return (r.value as WireScalar[]).some((x) => scalarEq(v, x));
  }
}

export interface DischargeBinding {
  /** capHash() of the hop that carries the caveat. */
  cap_hash: string;
  /** {@link dischargeActionDigest} of the PCActn being decided (needed for bind `action`). */
  action_digest?: string;
  pins: readonly DischargePin[];
  now: number;
  /** {@link dischargeDigest} values the verifier has revoked. */
  revoked?: readonly string[];
}
export type DischargeVerdict = { ok: true; digest: string; claims: Record<string, WireScalar> } | { ok: false; reason: string };

/**
 * Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop
 * carrying the caveat (and for `action` to the PCActn); it must be inside its window and within the caveat's `ttl_ms`;
 * and its claims must satisfy every requirement. Total.
 */
export function verifyDischarge(discharge: unknown, caveat: unknown, bind: DischargeBinding): DischargeVerdict {
  try {
    if (!isSafeInt(bind.now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    const ce = needsDischargeError(caveat);
    if (ce) return { ok: false, reason: `malformed needs_discharge caveat: ${ce}` };
    const c = caveat as NeedsDischargeCaveat;
    const de = dischargeShapeError(discharge);
    if (de) return { ok: false, reason: `malformed discharge: ${de}` };
    const d = discharge as Discharge;
    if (d.caveat_id !== c.id) return { ok: false, reason: 'the discharge is for another caveat' };
    if (d.issuer !== c.issuer) return { ok: false, reason: 'the discharge names another issuer' };
    if (!Array.isArray(bind.pins)) return { ok: false, reason: 'no issuer is pinned' };
    const pins = bind.pins.filter((p) => isPlainObject(p) && p.label === c.issuer);
    if (pins.length === 0) return { ok: false, reason: 'the issuer is not pinned by this verifier' };
    if (pins.length > 1) return { ok: false, reason: 'the issuer label is pinned more than once (ambiguous)' };
    const pin = pins[0]!;
    if (pin.class !== c.issuer_class) return { ok: false, reason: 'the pinned issuer is not of the class the caveat requires' };
    if (c.issuer_spiffe !== undefined && pin.spiffe_id !== c.issuer_spiffe) return { ok: false, reason: 'the pinned issuer does not carry the SPIFFE ID the caveat requires' };
    if (!verifyArtifactSig(DISCHARGE_DOMAIN, d as unknown as Record<string, unknown>, { pk: pin.pk, ...(pin.pq_pk !== undefined ? { pq_pk: pin.pq_pk } : {}) })) return { ok: false, reason: 'discharge signature invalid' };
    if (d.bind !== c.bind) return { ok: false, reason: 'the discharge binds differently than the caveat requires' };
    if (d.cap_hash !== bind.cap_hash) return { ok: false, reason: 'the discharge is bound to another hop' };
    if (c.bind === 'action' && d.action_digest !== bind.action_digest) return { ok: false, reason: 'the discharge is bound to another action' };
    if (bind.now < d.iat) return { ok: false, reason: 'the discharge is from the future' };
    if (bind.now > d.not_after) return { ok: false, reason: 'the discharge has expired' };
    if (d.not_after - d.iat > c.ttl_ms) return { ok: false, reason: 'the discharge lives longer than the caveat allows' };
    const digest = dischargeDigest(d);
    if (Array.isArray(bind.revoked) && bind.revoked.includes(digest)) return { ok: false, reason: 'the discharge is revoked' };
    for (const r of c.require) if (!claimHolds(r, d.claims)) return { ok: false, reason: `claim '${r.claim}' does not satisfy the caveat` };
    return { ok: true, digest, claims: d.claims };
  } catch (err) {
    return { ok: false, reason: `discharge error (fail closed): ${err instanceof Error ? err.message : 'unknown'}` };
  }
}

/** The request an agent sends to the issuer (or shows its principal) to obtain a discharge. Carries no secret and no token. */
export interface DischargeRequest {
  v: 1;
  kind: 'pca-discharge-request';
  caveat_id: string;
  issuer: string;
  cap_hash: string;
  bind: 'chain_hop' | 'action';
  action_digest?: string;
  require: ClaimRequirement[];
  ttl_ms: number;
}
/** What a verifier that answered `escalate` for a missing discharge asks for (one request per undischarged caveat). */
export function dischargeRequests(grant: Capability, chain: ChainInput | undefined, actionDigest: string | undefined): DischargeRequest[] {
  const b = boundCaveats(grant, chain) ?? [];
  const out: DischargeRequest[] = [];
  for (const { caveat, cap_hash } of b) {
    if (caveat?.type !== CAVEAT_NEEDS_DISCHARGE || needsDischargeError(caveat) !== null) continue;
    const c = caveat as unknown as NeedsDischargeCaveat;
    out.push({ v: 1, kind: 'pca-discharge-request', caveat_id: c.id, issuer: c.issuer, cap_hash, bind: c.bind, ...(c.bind === 'action' && actionDigest !== undefined ? { action_digest: actionDigest } : {}), require: c.require, ttl_ms: c.ttl_ms });
  }
  return out;
}

// ======================================================================================
// narrow: holder-signed per-action self-attenuation (no new hop)
// ======================================================================================

export interface NarrowBody {
  v: 1;
  kind: 'pca-narrow';
  /** capHash() of the leaf hop. */
  cap_hash: string;
  /** The leaf holder's Ed25519 key (b64u): the signer. */
  holder: string;
  /** Extra caveats, conjunctive with the chain's. 1..16. */
  caveats: Caveat[];
  /** When present the narrow applies to that one PCActn only; absent = every action until `not_after`. */
  action_digest?: string;
  iat: number;
  not_after: number;
  nonce: string;
  alg?: string;
  pq_pk?: string;
}
export type Narrow = NarrowBody & { sig: string; pq_sig?: string };

/** Types a narrow block must not carry: structure that only a real hop can introduce, and nested narrowing. */
const NARROW_FORBIDDEN = new Set(['envelope', CAVEAT_SEALED, 'budget_alloc', 'intent_session']);
const N_REQUIRED = ['v', 'kind', 'cap_hash', 'holder', 'caveats', 'iat', 'not_after', 'nonce', 'sig'] as const;
const N_OPTIONAL = ['action_digest', 'alg', 'pq_pk', 'pq_sig'] as const;

export function narrowShapeError(a: unknown): string | null {
  if (!isPlainObject(a)) return 'not an object';
  const e = closedMembers(a, N_REQUIRED, N_OPTIONAL, 'narrow');
  if (e) return e;
  if (a.v !== 1 || a.kind !== 'pca-narrow') return 'not a pca-narrow v1';
  if (!isDigest(a.cap_hash)) return 'cap_hash must be canonical base64url (32 bytes)';
  if (!isBoundedString(a.holder, 64) || decodeB64uStrict(a.holder, 32) === null) return 'holder must be canonical base64url (32 bytes)';
  if (!Array.isArray(a.caveats) || a.caveats.length < 1 || a.caveats.length > NARROW_MAX_CAVEATS) return `caveats must be 1..${NARROW_MAX_CAVEATS} caveats`;
  for (const c of a.caveats) {
    if (!isPlainObject(c) || typeof c.type !== 'string') return 'every caveat must be an object with a string type';
    if (NARROW_FORBIDDEN.has(c.type)) return `a narrow block cannot carry a '${c.type}' caveat`;
  }
  if (a.action_digest !== undefined && !isDigest(a.action_digest)) return 'action_digest must be canonical base64url (32 bytes)';
  if (!(isSafeInt(a.iat) && a.iat >= 0) || !(isSafeInt(a.not_after) && a.not_after >= 0)) return 'iat and not_after must be non-negative safe integers';
  if (!(a.not_after > a.iat)) return 'not_after must be greater than iat';
  if (a.not_after - a.iat > K1_MAX_LIFETIME_MS) return `a narrow block lives at most ${K1_MAX_LIFETIME_MS} ms`;
  const nb = typeof a.nonce === 'string' ? decodeB64uStrict(a.nonce) : null;
  if (nb === null || nb.length < 16) return 'nonce must be canonical base64url of at least 16 bytes';
  if (typeof a.sig !== 'string') return 'sig must be a string';
  return artifactSuiteError(a);
}

/** The leaf holder signs. Throws on a malformed body. */
export function signNarrow(body: NarrowBody, holderSecret: Uint8Array, suite?: SignerSuiteOpts): Narrow {
  const signed = signArtifact(NARROW_DOMAIN, body as unknown as Record<string, unknown>, holderSecret, suite) as unknown as Narrow;
  const e = narrowShapeError(signed);
  if (e) throw new Error(`signNarrow: ${e}`);
  return signed;
}

export type NarrowVerdict = { ok: true; caveats: Caveat[] } | { ok: false; reason: string };

/**
 * Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key the
 * leaf's `holder_pq` commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window. The
 * caveats it carries then join the chain's. A narrow block can only ADD restrictions, so stripping one off restores authority
 * the holder chose to give up: it protects the holder (a prompt-injection firewall), not the verifier against the holder.
 */
export function verifyNarrow(narrow: unknown, grant: Capability, chain: ChainInput | undefined, bind: { now: number; action_digest?: string }): NarrowVerdict {
  try {
    if (!isSafeInt(bind.now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    const e = narrowShapeError(narrow);
    if (e) return { ok: false, reason: `malformed narrow block: ${e}` };
    const n = narrow as Narrow;
    const view = chainView(grant, chain);
    const leaf = view.leaf;
    if (n.holder !== leaf.holder) return { ok: false, reason: 'the narrow block is not signed by the leaf holder' };
    if (n.cap_hash !== view.hash(view.n - 1)) return { ok: false, reason: 'the narrow block is bound to another hop' };
    const pq = n.pq_pk !== undefined && leaf.holder_pq !== undefined && holderPqCommitment(n.pq_pk) === leaf.holder_pq ? { pq_pk: n.pq_pk } : {};
    if (!verifyArtifactSig(NARROW_DOMAIN, n as unknown as Record<string, unknown>, { pk: n.holder, ...pq })) return { ok: false, reason: 'narrow signature invalid' };
    if (n.action_digest !== undefined && n.action_digest !== bind.action_digest) return { ok: false, reason: 'the narrow block is bound to another action' };
    if (bind.now < n.iat) return { ok: false, reason: 'the narrow block is from the future' };
    if (bind.now > n.not_after) return { ok: false, reason: 'the narrow block has expired' };
    return { ok: true, caveats: n.caveats };
  } catch (err) {
    return { ok: false, reason: `narrow error (fail closed): ${err instanceof Error ? err.message : 'unknown'}` };
  }
}

// ======================================================================================
// max_uses: n atomic first-use slots in the verifier's replay store
// ======================================================================================

export interface MaxUsesCaveat {
  type: 'max_uses';
  id: string;
  /** 1..256 admitted uses over the caveat's life. */
  n: number;
  /** Epoch ms after which the caveat itself fails; also how long the store must remember each use. */
  until: number;
}
export function maxUsesError(c: unknown): string | null {
  if (!isPlainObject(c)) return 'caveat must be an object';
  const e = closedMembers(c, ['type', 'id', 'n', 'until'], [], 'max_uses');
  if (e) return e;
  if (c.type !== CAVEAT_MAX_USES) return 'not a max_uses caveat';
  if (typeof c.id !== 'string' || !ID_RE.test(c.id)) return 'id is malformed';
  if (!(isSafeInt(c.n) && c.n >= 1 && c.n <= MAX_USES_LIMIT)) return `n must be 1..${MAX_USES_LIMIT}`;
  if (!(isSafeInt(c.until) && c.until >= 0)) return 'until must be a non-negative safe integer';
  return null;
}
/** The store key of use slot `i` of caveat `id` carried by hop `capHashOfHop`: b64u(sha256(domain NUL cap NUL id NUL i)). */
export function maxUsesSlotKey(capHashOfHop: string, id: string, i: number): string {
  return b64u(sha256(utf8(`${MAX_USES_DOMAIN}${capHashOfHop}\0${id}\0${i}`)));
}

export type UsesVerdict = { ok: true; spent: number } | { ok: false; reason: string };
/**
 * Spend one use of every `max_uses` caveat in `bound`, in order, after the rest of the decision allows. Each caveat takes the
 * first free slot of its `n` (an atomic `consumeOnce`, so concurrent actions never share a slot, across processes when the
 * store is durable and shared). The first exhausted, expired or malformed caveat refuses; slots already taken stay spent
 * (a use is spent when the action is admitted, and a refusal after that cannot give it back: fail closed).
 */
export async function reserveMaxUses(store: ReplayStore, bound: readonly BoundCaveat[], now: number): Promise<UsesVerdict> {
  try {
    if (!isSafeInt(now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
    let spent = 0;
    const ids = new Set<string>();
    for (const { caveat, cap_hash } of bound) {
      if (caveat?.type !== CAVEAT_MAX_USES) continue;
      const err = maxUsesError(caveat);
      if (err) return { ok: false, reason: `malformed max_uses caveat: ${err}` };
      const c = caveat as unknown as MaxUsesCaveat;
      if (ids.has(`${cap_hash}\0${c.id}`)) return { ok: false, reason: `duplicate max_uses id '${c.id}'` };
      ids.add(`${cap_hash}\0${c.id}`);
      if (now >= c.until) return { ok: false, reason: `max_uses '${c.id}' has expired` };
      let took = false;
      for (let i = 0; i < c.n && !took; i++) took = await store.consumeOnce(maxUsesSlotKey(cap_hash, c.id, i), c.until, now);
      if (!took) return { ok: false, reason: `max_uses '${c.id}' is exhausted` };
      spent += 1;
    }
    return { ok: true, spent };
  } catch (err) {
    return { ok: false, reason: `max_uses error (fail closed): ${err instanceof Error ? err.message : 'unknown'}` };
  }
}

// ======================================================================================
// derive: bounded derived facts in Kleene three-valued logic
// ======================================================================================

/** A term is a reference to an earlier def or a constant; an expression is a comparison or a boolean combination. */
export type DeriveExpr =
  | { ref: string }
  | { const: WireScalar }
  | { op: 'eq' | 'neq' | 'lt' | 'lte' | 'gt' | 'gte'; a: DeriveExpr; b: DeriveExpr }
  | { op: 'and' | 'or'; args: DeriveExpr[] }
  | { op: 'not'; arg: DeriveExpr };
export type DeriveDef =
  | { name: string; kind: 'count'; window_ms: number; verb?: string; resource_prefix?: string }
  | { name: string; kind: 'param'; path: string }
  | { name: string; kind: 'action'; field: 'verb' | 'resource' }
  | { name: string; kind: 'claim'; caveat_id: string; claim: string }
  | { name: string; kind: 'expr'; expr: DeriveExpr };
export interface DeriveCaveat {
  type: 'derive';
  id: string;
  defs: DeriveDef[];
  check: DeriveExpr;
}
export interface HistoryEvent {
  t: number;
  verb: string;
  resource: string;
}

function exprError(x: unknown, names: ReadonlySet<string>, depth: number, count: { n: number }): string | null {
  if (depth > DERIVE_MAX_DEPTH) return `expression nests deeper than ${DERIVE_MAX_DEPTH}`;
  if (++count.n > DERIVE_MAX_NODES) return `more than ${DERIVE_MAX_NODES} expression nodes`;
  if (!isPlainObject(x)) return 'expression must be an object';
  if (hasOwn(x, 'ref')) {
    const e = closedMembers(x, ['ref'], [], 'ref');
    if (e) return e;
    return typeof x.ref === 'string' && names.has(x.ref) ? null : 'ref names no earlier def';
  }
  if (hasOwn(x, 'const')) {
    const e = closedMembers(x, ['const'], [], 'const');
    if (e) return e;
    return isScalarClaim(x.const) ? null : 'const must be a scalar';
  }
  const op = x.op;
  if (op === 'and' || op === 'or') {
    const e = closedMembers(x, ['op', 'args'], [], op);
    if (e) return e;
    if (!Array.isArray(x.args) || x.args.length < 1 || x.args.length > 8) return `${op} needs 1..8 arguments`;
    for (const a of x.args) {
      const r = exprError(a, names, depth + 1, count);
      if (r) return r;
    }
    return null;
  }
  if (op === 'not') {
    const e = closedMembers(x, ['op', 'arg'], [], 'not');
    return e ?? exprError(x.arg, names, depth + 1, count);
  }
  if (op === 'eq' || op === 'neq' || op === 'lt' || op === 'lte' || op === 'gt' || op === 'gte') {
    const e = closedMembers(x, ['op', 'a', 'b'], [], op);
    return e ?? exprError(x.a, names, depth + 1, count) ?? exprError(x.b, names, depth + 1, count);
  }
  return 'unknown expression';
}

/** Null when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it). */
export function deriveError(c: unknown): string | null {
  if (!isPlainObject(c)) return 'caveat must be an object';
  const e = closedMembers(c, ['type', 'id', 'defs', 'check'], [], 'derive');
  if (e) return e;
  if (c.type !== CAVEAT_DERIVE) return 'not a derive caveat';
  if (typeof c.id !== 'string' || !ID_RE.test(c.id)) return 'id is malformed';
  if (!Array.isArray(c.defs) || c.defs.length > DERIVE_MAX_DEFS) return `defs must be an array of at most ${DERIVE_MAX_DEFS}`;
  const names = new Set<string>();
  const count = { n: 0 };
  for (const d of c.defs) {
    if (!isPlainObject(d) || typeof d.name !== 'string' || !NAME_RE.test(d.name)) return 'def name is malformed';
    if (names.has(d.name)) return `def '${d.name}' is defined twice`;
    let de: string | null;
    switch (d.kind) {
      case 'count':
        de = closedMembers(d, ['name', 'kind', 'window_ms'], ['verb', 'resource_prefix'], 'count');
        if (!de && !(isSafeInt(d.window_ms) && d.window_ms >= 1 && d.window_ms <= DERIVE_MAX_WINDOW_MS)) de = 'window_ms out of range';
        if (!de && d.verb !== undefined && !isStr256(d.verb)) de = 'verb must be a non-empty string';
        if (!de && d.resource_prefix !== undefined && !isStr256(d.resource_prefix)) de = 'resource_prefix must be a non-empty string';
        break;
      case 'param':
        de = closedMembers(d, ['name', 'kind', 'path'], [], 'param');
        if (!de && !(typeof d.path === 'string' && d.path.split('.').length <= 4 && d.path.split('.').every(isPathSegment))) de = 'param path is malformed';
        break;
      case 'action':
        de = closedMembers(d, ['name', 'kind', 'field'], [], 'action');
        if (!de && d.field !== 'verb' && d.field !== 'resource') de = "field must be 'verb' or 'resource'";
        break;
      case 'claim':
        de = closedMembers(d, ['name', 'kind', 'caveat_id', 'claim'], [], 'claim');
        if (!de && !(typeof d.caveat_id === 'string' && ID_RE.test(d.caveat_id) && typeof d.claim === 'string' && NAME_RE.test(d.claim))) de = 'claim reference is malformed';
        break;
      case 'expr':
        de = closedMembers(d, ['name', 'kind', 'expr'], [], 'expr') ?? exprError(d.expr, names, 1, count);
        break;
      default:
        de = 'unknown def kind';
    }
    if (de) return `def '${d.name}': ${de}`;
    names.add(d.name);
  }
  return exprError(c.check, names, 1, count);
}

type Tri = true | false | null;
type Val = WireScalar | null;

function evalExpr(x: DeriveExpr, env: ReadonlyMap<string, Val>): Val {
  if ('ref' in x) return env.get(x.ref) ?? null;
  if ('const' in x) return x.const;
  if (x.op === 'not') {
    const v = evalExpr(x.arg, env);
    return typeof v === 'boolean' ? !v : null;
  }
  if (x.op === 'and' || x.op === 'or') {
    const stop = x.op === 'or';
    let unknown = false;
    for (const a of x.args) {
      const v = evalExpr(a, env);
      if (typeof v !== 'boolean') unknown = true;
      else if (v === stop) return stop;
    }
    return unknown ? null : !stop;
  }
  const cmp = x as { op: 'eq' | 'neq' | 'lt' | 'lte' | 'gt' | 'gte'; a: DeriveExpr; b: DeriveExpr };
  const a = evalExpr(cmp.a, env);
  const b = evalExpr(cmp.b, env);
  if (a === null || b === null) return null;
  if (cmp.op === 'eq') return scalarEq(a, b);
  if (cmp.op === 'neq') return !scalarEq(a, b);
  if (!isSafeInt(a) || !isSafeInt(b)) return null;
  return cmp.op === 'lt' ? a < b : cmp.op === 'lte' ? a <= b : cmp.op === 'gt' ? a > b : a >= b;
}

export interface DeriveInput {
  now: number;
  action?: { verb?: unknown; resource?: unknown; params?: unknown };
  history?: readonly HistoryEvent[];
  /** `caveat id -> claims` of the discharges that VERIFIED in this evaluation: the only claim source a `derive` may read. */
  claims: Readonly<Record<string, Record<string, WireScalar>>>;
}
/** Evaluate a well-formed derive caveat: true only when `check` is exactly true (false and unknown both refuse). */
export function evaluateDerive(c: DeriveCaveat, inp: DeriveInput): Tri {
  const env = new Map<string, Val>();
  const act = inp.action;
  for (const d of c.defs) {
    let v: Val = null;
    switch (d.kind) {
      case 'count': {
        const h = inp.history;
        if (!Array.isArray(h) || h.length > DERIVE_MAX_HISTORY) break;
        let n = 0;
        let bad = false;
        for (const e of h) {
          if (!isPlainObject(e) || !isSafeInt(e.t) || typeof e.verb !== 'string' || typeof e.resource !== 'string') {
            bad = true;
            break;
          }
          if (e.t > inp.now - d.window_ms && e.t <= inp.now && (d.verb === undefined || e.verb === d.verb) && (d.resource_prefix === undefined || e.resource.startsWith(d.resource_prefix))) n += 1;
        }
        v = bad ? null : n;
        break;
      }
      case 'param': {
        const r = resolveParamPath(act?.params, `action.params.${d.path}`);
        v = r.found && isScalarClaim(r.value) ? (r.value as WireScalar) : null;
        break;
      }
      case 'action': {
        const f = act?.[d.field];
        v = isStr256(f) ? f : null;
        break;
      }
      case 'claim': {
        const cl = ownGet(inp.claims as Record<string, Record<string, WireScalar>>, d.caveat_id);
        v = cl === undefined ? null : (ownGet(cl, d.claim) ?? null);
        break;
      }
      case 'expr':
        v = evalExpr(d.expr, env);
        break;
    }
    env.set(d.name, v);
  }
  const r = evalExpr(c.check, env);
  return typeof r === 'boolean' ? r : null;
}

// ======================================================================================
// spiffe_bound
// ======================================================================================

export function spiffeBoundError(c: unknown): string | null {
  if (!isPlainObject(c)) return 'caveat must be an object';
  const e = closedMembers(c, ['type'], ['spiffe_id', 'spiffe_prefix'], 'spiffe_bound');
  if (e) return e;
  if (c.type !== CAVEAT_SPIFFE_BOUND) return 'not a spiffe_bound caveat';
  if ((c.spiffe_id === undefined) === (c.spiffe_prefix === undefined)) return 'exactly one of spiffe_id and spiffe_prefix';
  return spiffeIdError(c.spiffe_id ?? c.spiffe_prefix);
}
/** `spiffe_id`: the peer must equal it. `spiffe_prefix`: the peer must equal it or lie below it (`prefix + "/"`). */
function spiffeSatisfied(c: Record<string, unknown>, peer: unknown): boolean {
  if (spiffeBoundError(c) !== null || spiffeIdError(peer) !== null) return false;
  const p = peer as string;
  if (c.spiffe_id !== undefined) return p === c.spiffe_id;
  const pre = c.spiffe_prefix as string;
  return p === pre || p.startsWith(`${pre}/`);
}

// ======================================================================================
// The K1 evaluator
// ======================================================================================

export interface K1Input {
  /** The verifier's pins for discharge issuers (never taken from the request). */
  pins?: readonly DischargePin[];
  /** Discharges presented with the action. */
  discharges?: readonly unknown[];
  /** A narrow block presented with the action. */
  narrow?: unknown;
  /** {@link dischargeActionDigest} of the PCActn being decided. */
  action_digest?: string;
  /** {@link dischargeDigest} values the verifier has revoked. */
  revoked_discharges?: readonly string[];
  /** The SPIFFE ID of the presenting workload, from an SVID the verifier verified (never from the request). */
  spiffe_id?: string;
  /** The verifier's own record of this holder's admitted actions. */
  history?: readonly HistoryEvent[];
}
export interface K1Result {
  ok: boolean;
  /** Types of the unsatisfied caveats, in order (`<malformed>` for one without a string type). */
  failed: string[];
  /** One reason per failure (same order). */
  reasons: string[];
  /** Verified narrow-block caveats that are NOT K1 types: the caller evaluates them with its stock evaluator. */
  plain: Caveat[];
  /** The caveats evaluated, with their hops: hand the `max_uses` ones to {@link reserveMaxUses} once everything allowed. */
  bound: BoundCaveat[];
}

/**
 * Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
 * evaluators. `needs_discharge`, `sealed` and `max_uses` ids must be unique over the chain and narrow block: a duplicate
 * fails every caveat that shares it. `max_uses` is only checked for well-formedness and expiry here; {@link reserveMaxUses}
 * spends it.
 */
export function evaluateK1(grant: Capability, chain: ChainInput | undefined, k1: K1Input | undefined, ctx: { now: number; action?: DeriveInput['action'] }): K1Result {
  const failed: string[] = [];
  const reasons: string[] = [];
  const fail = (c: unknown, why: string) => {
    failed.push(isPlainObject(c) && typeof c.type === 'string' ? c.type : '<malformed>');
    reasons.push(why);
  };
  const result = (plain: Caveat[], bound: BoundCaveat[]): K1Result => ({ ok: failed.length === 0, failed, reasons, plain, bound });
  try {
    const base = boundCaveats(grant, chain);
    if (base === null || !isSafeInt(ctx?.now)) {
      fail({ type: '<malformed>' }, base === null ? 'malformed capability chain' : 'the verifier clock is not a safe integer (fail closed)');
      return result([], []);
    }
    // No K1 input at all (not even `{}`): every K1 caveat is refused, whatever its type. A verifier that was never configured for the
    // caveat language must not let `sealed` or a constant `derive` pass by default.
    if (!isPlainObject(k1)) {
      const mine = base.filter((b) => isK1Caveat(b.caveat));
      for (const b of mine) fail(b.caveat, 'the caveat language is not configured (no k1 input)');
      return result([], mine);
    }
    const kin = k1 as K1Input;
    const view = chainView(grant, chain);
    const leafIndex = view.n - 1;
    let bound = base;
    const plain: Caveat[] = [];
    if (kin.narrow !== undefined) {
      const nv = verifyNarrow(kin.narrow, grant, chain, { now: ctx.now, ...(kin.action_digest !== undefined ? { action_digest: kin.action_digest } : {}) });
      if (!nv.ok) {
        fail({ type: 'narrow' }, nv.reason);
        return result([], bound.filter((b) => isK1Caveat(b.caveat)));
      }
      const leafHash = view.hash(leafIndex);
      bound = [...bound, ...nv.caveats.map((caveat) => ({ caveat, hop: leafIndex, cap_hash: leafHash }))];
      for (const c of nv.caveats) if (!isK1Caveat(c)) plain.push(c);
    }
    const k1Bound = bound.filter((b) => isK1Caveat(b.caveat));
    // ids are unique per type across the chain and narrow block
    const seen = new Map<string, number>();
    for (const { caveat } of k1Bound) {
      const id = typeof caveat.id === 'string' ? `${caveat.type}\0${caveat.id}` : undefined;
      if (id !== undefined) seen.set(id, (seen.get(id) ?? 0) + 1);
    }
    const now = ctx.now;
    const claims: Record<string, Record<string, WireScalar>> = nullRecord();
    // pass 1: discharges (derive reads their claims)
    const verdict = new Map<BoundCaveat, boolean>();
    for (const b of k1Bound) {
      if (b.caveat.type !== CAVEAT_NEEDS_DISCHARGE) continue;
      const bad = needsDischargeError(b.caveat);
      if (bad) {
        verdict.set(b, false);
        fail(b.caveat, bad);
        continue;
      }
      if ((seen.get(`${CAVEAT_NEEDS_DISCHARGE}\0${b.caveat.id as string}`) ?? 0) > 1) {
        verdict.set(b, false);
        fail(b.caveat, `duplicate needs_discharge id '${b.caveat.id as string}'`);
        continue;
      }
      let why = 'no discharge presented';
      let okd: DischargeVerdict | undefined;
      for (const d of Array.isArray(kin.discharges) ? kin.discharges : []) {
        if (!isPlainObject(d) || d.caveat_id !== b.caveat.id) continue;
        const v = verifyDischarge(d, b.caveat, { cap_hash: b.cap_hash, ...(kin.action_digest !== undefined ? { action_digest: kin.action_digest } : {}), pins: kin.pins ?? [], now, ...(kin.revoked_discharges !== undefined ? { revoked: kin.revoked_discharges } : {}) });
        if (v.ok) {
          okd = v;
          break;
        }
        why = v.reason;
      }
      if (okd?.ok) {
        claims[b.caveat.id as string] = okd.claims;
        verdict.set(b, true);
      } else {
        verdict.set(b, false);
        fail(b.caveat, why);
      }
    }
    // pass 2: everything else, in order
    for (const b of k1Bound) {
      const c = b.caveat;
      switch (c.type) {
        case CAVEAT_NEEDS_DISCHARGE:
          break;
        case CAVEAT_SEALED: {
          const e = closedMembers(c, ['type'], [], 'sealed');
          if (e) fail(c, e);
          else if (b.hop !== leafIndex) fail(c, 'a hop was appended below a sealed hop');
          break;
        }
        case CAVEAT_MAX_USES: {
          const e = maxUsesError(c);
          if (e) fail(c, e);
          else if ((seen.get(`${CAVEAT_MAX_USES}\0${c.id as string}`) ?? 0) > 1) fail(c, `duplicate max_uses id '${c.id as string}'`);
          else if (now >= (c.until as number)) fail(c, `max_uses '${c.id as string}' has expired`);
          break;
        }
        case CAVEAT_DERIVE: {
          const e = deriveError(c);
          if (e) fail(c, e);
          else if ((seen.get(`${CAVEAT_DERIVE}\0${c.id as string}`) ?? 0) > 1) fail(c, `duplicate derive id '${c.id as string}'`);
          else {
            const r = evaluateDerive(c as unknown as DeriveCaveat, { now, ...(ctx.action !== undefined ? { action: ctx.action } : {}), ...(kin.history !== undefined ? { history: kin.history } : {}), claims });
            if (r !== true) fail(c, r === null ? 'derive check is unknown (a fact is missing)' : 'derive check is false');
          }
          break;
        }
        case CAVEAT_SPIFFE_BOUND:
          if (!spiffeSatisfied(c, kin.spiffe_id)) fail(c, 'the presenting workload does not carry the required SPIFFE ID');
          break;
      }
    }
    return result(plain, k1Bound);
  } catch (err) {
    fail({ type: '<malformed>' }, `caveat language error (fail closed): ${err instanceof Error ? err.message : 'unknown'}`);
    return result([], []);
  }
}
