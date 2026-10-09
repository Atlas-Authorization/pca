/**
 * @atlasauth/pca-gnap — a GNAP (RFC 9635) bridge for Proof-Carrying Authority, defining the
 * ================= AGENT-GNAP PROFILE =================
 *
 * GNAP (Grant Negotiation and Authorization Protocol, RFC 9635) negotiates an access grant between a
 * client instance and an authorization server (AS) using a rich, structured `access` rights model,
 * key-bound requests, and a stateful *continuation* handle. No agent-delegation profile of GNAP exists
 * publicly yet. This package DEFINES one, because GNAP's primitives map almost 1:1 onto PCA's:
 *
 *   GNAP concept                          PCA concept
 *   ------------------------------------  ---------------------------------------------------------
 *   `access` rights array (§8)            Policy-envelope `Predicate[]` (verb/resource/where)
 *     - type                               → resource namespace  `gnap:<type>:<location>`
 *     - actions                            → predicate `verb` (list, or `*`)
 *     - locations                          → predicate `resource` (exact / prefix)
 *     - datatypes / identifier             → predicate `where` conditions on `action.params.*`
 *   client instance key (§7.1)            Capability `holder` (the bound key, `cnf`)
 *   grant request (§2)                    `mintGrant` (root) / `delegate` (a delegated hop)
 *   grant response access_token (§3.2)    A verifiable PCA capability chain (bound, attenuated)
 *   `continue` handle (§3.1, §5)          A PCA step-up: a FROST/CIBA co-signature folded into a PCActn
 *   `interact` (§3.3, §4)                 The tier-2/3 human/guardian step-up prompt
 *   key-bound proof `jwsd` (§7.3.4)       Detached-JWS proof that the request was signed by `holder`
 *
 * THE AGENT-GNAP PROFILE (multi-hop delegation). An agent-to-agent (A2A) task is a chain of grants:
 * each hop is a GNAP grant request from one agent to the next, and the AS issues a PCA capability that
 * is ATTENUATED — never wider than the issuing agent's own authority. Attenuation is structural: PCA
 * capability caveats are append-only and conjunctive (see `@atlasauth/pca` capability.ts), so a child
 * can only ever NARROW. Each hop records its granted `access` as a signed `gnap_access` caveat, and the
 * EFFECTIVE authority of the chain is the INTERSECTION of the root policy envelope and every hop's
 * recorded rights. A hop that requests more than its issuer held is clamped at issue time
 * (`clampToIssuer`) AND denied at action time (the issuer's narrower rights still gate every action),
 * so "never wider than the issuer" holds by construction across any number of hops.
 *
 * All verification FAILS CLOSED: a malformed token, a broken chain, a bad jwsd proof, a stale request,
 * or an action outside the granted rights denies. The machine-readable profile spec is exported as
 * {@link AGENT_GNAP_PROFILE}.
 */

import { FlattenedSign, flattenedVerify, importJWK, base64url, type JWSHeaderParameters } from 'jose';
import {
  type AgentBinding,
  type Capability,
  type CapabilityChain,
  type Caveat,
  type Condition,
  type PCActn,
  type PCActnBody,
  type PlanNode,
  type Predicate,
  type RiskPolicy,
  type Signer,
  type SignerRole,
  type ThresholdShare,
  type ThresholdSignature,
  type ThresholdVerdict,
  DEFAULT_RISK_POLICY,
  assembleThreshold,
  b64u,
  buildPCActn,
  canonicalizeStrict,
  decodeB64uStrict,
  delegate,
  evaluatePredicates,
  hashCanonical,
  mintGrant,
  readEnvelope,
  sha256,
  signShare,
  strictParse,
  thresholdMessage,
  unb64u,
  utf8,
  verifyChain,
  verifyThreshold,
} from '@atlasauth/pca';

// ============================================================================================
// GNAP wire types (RFC 9635, the subset this profile uses)
// ============================================================================================

/** A JWK (RFC 7517). This profile binds grants to an OKP/Ed25519 client key. */
export interface GnapJwk {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
  use?: string;
}

/** A client's key-proof binding (§7.1). This profile implements the `jwsd` detached-JWS method. */
export interface GnapKeyProof {
  /** The proof method. This profile verifies `jwsd`. */
  proof: 'jwsd' | 'httpsig' | 'mtls' | 'jwsd-vc' | string;
  /** The client instance's public key, as a JWK. */
  jwk?: GnapJwk;
}

/** A GNAP client instance (§2.3). */
export interface GnapClient {
  key: GnapKeyProof | string;
  class_id?: string;
  display?: { name?: string; uri?: string };
}

/** A single resource-access right (§8). A string is a reference to a named/pre-registered access. */
export type GnapAccessItem = GnapResourceAccess | string;

/** The object form of a resource-access right (§8.1). */
export interface GnapResourceAccess {
  type: string;
  actions?: string[];
  locations?: string[];
  datatypes?: string[];
  identifier?: string;
  privileges?: string[];
}

/** A single-access-token request (§2.1). Multi-token requests are out of this profile's scope. */
export interface GnapTokenRequest {
  access: GnapAccessItem[];
  label?: string;
  flags?: string[];
}

/** A GNAP interaction request (§2.5). */
export interface GnapInteractRequest {
  start: string[];
  finish?: { method: string; uri: string; nonce: string };
}

/** A GNAP subject request (§2.4). */
export interface GnapSubjectRequest {
  sub_id_formats?: string[];
  assertion_formats?: string[];
}

/** A GNAP grant request (§2). */
export interface GnapGrantRequest {
  access_token: GnapTokenRequest;
  client: GnapClient | string;
  subject?: GnapSubjectRequest;
  interact?: GnapInteractRequest;
}

/** An issued GNAP access token (§3.2). In this profile `value` carries a PCA capability chain. */
export interface GnapAccessToken {
  value: string;
  label?: string;
  access: GnapResourceAccess[];
  expires_in?: number;
  /** The bound key: the holder JWK, or `false` for a bearer token. */
  key?: GnapJwk | false;
  manage?: { uri: string };
}

/** A GNAP continuation handle (§3.1). The client returns here to complete a step-up. */
export interface GnapContinue {
  uri: string;
  wait?: number;
  access_token: { value: string; bound?: boolean };
}

/** A GNAP grant response (§3). */
export interface GnapGrantResponse {
  access_token?: GnapAccessToken;
  continue?: GnapContinue;
  instance_id?: string;
}

// ============================================================================================
// Errors + small guards
// ============================================================================================

/** Thrown by the issuance paths on a malformed request (the verify paths fail closed instead). */
export class GnapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GnapError';
  }
}

const isRecord = (x: unknown): x is Record<string, unknown> =>
  x !== null && typeof x === 'object' && !Array.isArray(x);

const strArr = (u: unknown): string[] | undefined =>
  Array.isArray(u) ? u.filter((s): s is string => typeof s === 'string') : undefined;

/** A canonical, unpadded base64url Ed25519 public key (exactly 32 bytes), or null. */
function asEd25519(x: unknown): string | null {
  return typeof x === 'string' && decodeB64uStrict(x, 32) !== null ? x : null;
}

const GNAP_RESOURCE_PREFIX = 'gnap';

/** The PCA `resource` string for a GNAP (type, location) pair — the namespace actions are matched in. */
export function gnapActionResource(type: string, location: string): string {
  return `${GNAP_RESOURCE_PREFIX}:${type}:${location}`;
}

// ============================================================================================
// Access-rights normalization + mapping onto PCA predicates
// ============================================================================================

/** Total, fail-closed normalization of one access item. Returns null for anything malformed. */
function tryNormalizeAccessItem(item: unknown): GnapResourceAccess | null {
  if (typeof item === 'string') return item.length > 0 ? { type: item } : null;
  if (!isRecord(item)) return null;
  const type = item.type;
  if (typeof type !== 'string' || type.length === 0) return null;
  const out: GnapResourceAccess = { type };
  const actions = strArr(item.actions);
  if (actions && actions.length > 0) out.actions = actions;
  const locations = strArr(item.locations);
  if (locations && locations.length > 0) out.locations = locations;
  const datatypes = strArr(item.datatypes);
  if (datatypes && datatypes.length > 0) out.datatypes = datatypes;
  if (typeof item.identifier === 'string') out.identifier = item.identifier;
  const privileges = strArr(item.privileges);
  if (privileges && privileges.length > 0) out.privileges = privileges;
  return out;
}

/** Normalize one access item, THROWING on malformed input (issuance path). */
function normalizeAccessItem(item: unknown): GnapResourceAccess {
  const n = tryNormalizeAccessItem(item);
  if (n === null) throw new GnapError('malformed access item (needs a non-empty string `type`)');
  return n;
}

/** Normalize an access array for issuance (throws on any malformed entry). */
export function normalizeAccess(items: readonly unknown[]): GnapResourceAccess[] {
  if (!Array.isArray(items)) throw new GnapError('access must be an array');
  return items.map(normalizeAccessItem);
}

/** Total, fail-closed read of a stored access array (reading signed caveats). Skips malformed entries. */
function readAccessArray(u: unknown): GnapResourceAccess[] {
  if (!Array.isArray(u)) return [];
  const out: GnapResourceAccess[] = [];
  for (const item of u) {
    const n = tryNormalizeAccessItem(item);
    if (n !== null) out.push(n);
  }
  return out;
}

/**
 * Map a GNAP access right onto PCA predicates (one per location). `type` namespaces the resource,
 * `actions` become verbs, `locations` become resources, and `datatypes`/`identifier` become `where`
 * conditions on the action's params. An absent `actions`/`locations` means "any" (verb `*` / a
 * prefix-matching `*` resource).
 */
export function accessToPredicates(access: GnapResourceAccess): Predicate[] {
  const verb: string | string[] = access.actions && access.actions.length > 0 ? [...access.actions] : '*';
  const locations = access.locations && access.locations.length > 0 ? access.locations : ['*'];
  const where: Condition[] = [];
  if (access.datatypes && access.datatypes.length > 0) {
    where.push({ field: 'action.params.datatype', op: 'in', value: [...access.datatypes] });
  }
  if (typeof access.identifier === 'string') {
    where.push({ field: 'action.params.identifier', op: 'eq', value: access.identifier });
  }
  return locations.map((loc) => {
    const p: Predicate = { verb, resource: gnapActionResource(access.type, loc) };
    if (where.length > 0) p.where = where.map((c) => ({ ...c }));
    return p;
  });
}

/** All predicates for an access array. */
function accessArrayToPredicates(access: GnapResourceAccess[]): Predicate[] {
  return access.flatMap(accessToPredicates);
}

// ============================================================================================
// Access-level containment (the AS's "is this request within my authority?" check)
// ============================================================================================

function coversStrings(sup: string[] | undefined, sub: string[] | undefined): boolean {
  if (sup === undefined) return true; // issuer allows all
  if (sub === undefined) return false; // request wants all, issuer has a concrete set
  return sub.every((s) => sup.includes(s));
}

function coversLocations(sup: string[] | undefined, sub: string[] | undefined): boolean {
  if (sup === undefined) return true;
  if (sub === undefined) return sup.includes('*');
  return sub.every((s) =>
    sup.some((g) => g === s || g === '*' || (g.endsWith('*') && s.startsWith(g.slice(0, -1)))),
  );
}

/** Does the issuer's granted right `g` fully contain the requested right `r`? */
export function accessContains(g: GnapResourceAccess, r: GnapResourceAccess): boolean {
  if (g.type !== r.type) return false;
  if (!coversStrings(g.actions, r.actions)) return false;
  if (!coversLocations(g.locations, r.locations)) return false;
  if (!coversStrings(g.datatypes, r.datatypes)) return false;
  if (r.identifier !== undefined && g.identifier !== undefined && g.identifier !== r.identifier) return false;
  return true;
}

/** Is `r` within the issuer's granted set `G` (covered by at least one of its rights)? */
export function accessWithin(G: GnapResourceAccess[], r: GnapResourceAccess): boolean {
  return G.some((g) => accessContains(g, r));
}

/** Split a requested access array into the subset within the issuer's authority and the rest. */
export function clampAccess(
  issuerGranted: GnapResourceAccess[],
  requested: GnapResourceAccess[],
): { granted: GnapResourceAccess[]; dropped: GnapResourceAccess[] } {
  const granted: GnapResourceAccess[] = [];
  const dropped: GnapResourceAccess[] = [];
  for (const r of requested) (accessWithin(issuerGranted, r) ? granted : dropped).push(r);
  return { granted, dropped };
}

// ============================================================================================
// GNAP provenance caveats (recorded in the signed capability)
// ============================================================================================

/** The caveat recorded inside a ROOT GNAP grant's policy envelope (grant provenance). */
export const GNAP_GRANT_CAVEAT = 'gnap_grant';
/** The caveat appended on each DELEGATED GNAP hop (the rights that hop was granted). */
export const GNAP_ACCESS_CAVEAT = 'gnap_access';

export interface GnapGrantCaveat extends Caveat {
  type: typeof GNAP_GRANT_CAVEAT;
  /** The client key this grant was issued to (the bound holder, b64u). */
  client_id: string;
  granted_access: GnapResourceAccess[];
  /** `hashCanonical` of the normalized request (tamper-evident provenance). */
  request_digest: string;
  /** Whether the grant followed a GNAP interaction. */
  interacted: boolean;
  ts: number;
}

export interface GnapAccessCaveat extends Caveat {
  type: typeof GNAP_ACCESS_CAVEAT;
  access: GnapResourceAccess[];
  predicates: Predicate[];
  request_digest: string;
  client_id: string;
  ts: number;
}

/** Read the root grant's GNAP provenance caveat (inside the policy envelope), or null. */
function readGnapGrant(root: Capability): GnapGrantCaveat | null {
  const env = readEnvelope(root);
  const cv = env?.caveats.find((c) => c?.type === GNAP_GRANT_CAVEAT);
  if (!cv) return null;
  const clientId = cv.client_id;
  const digest = cv.request_digest;
  if (typeof clientId !== 'string' || typeof digest !== 'string') return null;
  return {
    type: GNAP_GRANT_CAVEAT,
    client_id: clientId,
    granted_access: readAccessArray(cv.granted_access),
    request_digest: digest,
    interacted: cv.interacted === true,
    ts: typeof cv.ts === 'number' ? cv.ts : 0,
  };
}

/**
 * The EFFECTIVE granted access of a chain: the most-recent delegated hop's recorded rights, or (for a
 * root-only grant) the root's recorded rights. Because every hop is clamped to its issuer at issue
 * time, the leaf's recorded rights are the narrowest in the chain.
 */
export function grantedAccessOf(chain: CapabilityChain): GnapResourceAccess[] {
  if (!Array.isArray(chain) || chain.length === 0) return [];
  const leaf = chain[chain.length - 1]!;
  const caveats = Array.isArray(leaf.caveats) ? leaf.caveats : [];
  for (let i = caveats.length - 1; i >= 0; i--) {
    const cv = caveats[i]!;
    if (cv?.type === GNAP_ACCESS_CAVEAT) return readAccessArray(cv.access);
  }
  const grant = readGnapGrant(chain[0]!);
  return grant ? grant.granted_access : [];
}

// ============================================================================================
// Holder resolution (the GNAP client key becomes the PCA holder)
// ============================================================================================

/** Resolve the b64u Ed25519 holder key from a request's client key (or an explicit override). */
export function resolveHolder(req: GnapGrantRequest, holderOverride?: string): string {
  if (holderOverride !== undefined) {
    const h = asEd25519(holderOverride);
    if (h === null) throw new GnapError('holder override is not a canonical base64url Ed25519 public key');
    return h;
  }
  const client = req.client;
  const key = typeof client === 'object' && client !== null ? client.key : undefined;
  if (key && typeof key === 'object' && key.jwk && key.jwk.kty === 'OKP' && key.jwk.crv === 'Ed25519') {
    const x = asEd25519(key.jwk.x);
    if (x !== null) return x;
  }
  throw new GnapError('cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override');
}

/** The holder key, rendered as a GNAP JWK (for a bound access-token response). */
export function holderJwk(holder: string): GnapJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: holder, use: 'sig', alg: 'EdDSA' };
}

function accessOf(req: GnapGrantRequest): unknown[] {
  const at: unknown = req.access_token;
  if (isRecord(at) && Array.isArray(at.access)) return at.access;
  throw new GnapError('grant request must carry access_token.access (single-token request)');
}

function requestDigestOf(holder: string, granted: GnapResourceAccess[], interact: GnapInteractRequest | undefined): string {
  return hashCanonical({
    d: 'atlas-pca/gnap/request/v1',
    client_id: holder,
    access: granted,
    interact: interact ?? null,
  });
}

// ============================================================================================
// Grant request → PCA capability
// ============================================================================================

export interface GrantToCapabilityOptions {
  /** The key that signs this hop: the principal secret for a root grant, or the parent holder's secret. */
  issuerSecret: Uint8Array;
  /** The issuer's b64u public key (principal public for root; = `parent.holder` for a delegation). */
  issuerPublic: string;
  /** Present → DELEGATE from this capability; absent → MINT a new root grant. */
  parent?: Capability;
  /** The full issuer chain, used to compute the issuer's effective authority for clamping. */
  issuerChain?: CapabilityChain;
  /** Drop requested rights that exceed the issuer's authority (default true). */
  clampToIssuer?: boolean;
  /** Explicit holder override (else derived from the request's client key). */
  holder?: string;
  /** Whether this grant followed a GNAP interaction (recorded in provenance). */
  interacted?: boolean;
  now?: number;
  // --- root-grant only ---
  goal?: string;
  riskPolicy?: RiskPolicy;
  agentBinding?: AgentBinding;
  salt?: string;
}

export interface GrantToCapabilityResult {
  /** The newly issued hop (a root grant, or a delegated child). */
  grant: Capability;
  /** The full capability chain (issuer chain + the new hop). */
  chain: CapabilityChain;
  /** The bound holder key (b64u). */
  holder: string;
  /** The rights actually granted (after clamping). */
  grantedAccess: GnapResourceAccess[];
  /** Requested rights that exceeded the issuer's authority and were dropped. */
  droppedAccess: GnapResourceAccess[];
  /** The GNAP provenance caveat written into the capability. */
  provenance: GnapGrantCaveat | GnapAccessCaveat;
}

/**
 * Convert a GNAP grant request into a PCA capability bound to the client key, ATTENUATED to never
 * exceed the issuer. With no `parent` this MINTS a root grant whose policy-envelope predicates ARE the
 * requested access rights. With a `parent` it DELEGATES a narrower hop, recording the (clamped) rights
 * as an append-only `gnap_access` caveat — so the effective authority is the intersection of the whole
 * chain, and no hop can widen.
 */
export function grantRequestToCapability(req: GnapGrantRequest, opts: GrantToCapabilityOptions): GrantToCapabilityResult {
  const holder = resolveHolder(req, opts.holder);
  const requested = normalizeAccess(accessOf(req));
  const now = Math.floor(opts.now ?? Date.now());
  const interacted = opts.interacted === true;

  let granted = requested;
  let dropped: GnapResourceAccess[] = [];
  if (opts.parent) {
    const issuerChain = opts.issuerChain ?? [opts.parent];
    if (opts.clampToIssuer !== false) {
      const split = clampAccess(grantedAccessOf(issuerChain), requested);
      granted = split.granted;
      dropped = split.dropped;
    }
  }

  const requestDigest = requestDigestOf(holder, granted, req.interact);

  if (opts.parent) {
    const issuerChain = opts.issuerChain ?? [opts.parent];
    const provenance: GnapAccessCaveat = {
      type: GNAP_ACCESS_CAVEAT,
      access: granted,
      predicates: accessArrayToPredicates(granted),
      request_digest: requestDigest,
      client_id: holder,
      ts: now,
    };
    const child = delegate(opts.parent, holder, [provenance], opts.issuerSecret);
    return { grant: child, chain: [...issuerChain, child], holder, grantedAccess: granted, droppedAccess: dropped, provenance };
  }

  const provenance: GnapGrantCaveat = {
    type: GNAP_GRANT_CAVEAT,
    client_id: holder,
    granted_access: granted,
    request_digest: requestDigest,
    interacted,
    ts: now,
  };
  const { grant } = mintGrant({
    principalSecret: opts.issuerSecret,
    principalPublic: opts.issuerPublic,
    holder,
    goal: opts.goal ?? `gnap:grant:${holder}`,
    envelope: {
      predicates: accessArrayToPredicates(granted),
      caveats: [provenance],
      agent_binding: opts.agentBinding ?? {},
      risk_policy: opts.riskPolicy ?? DEFAULT_RISK_POLICY,
    },
    ...(opts.salt !== undefined ? { salt: opts.salt } : {}),
  });
  return { grant, chain: [grant], holder, grantedAccess: granted, droppedAccess: dropped, provenance };
}

// ============================================================================================
// Action authorization (effective authority = root envelope ∩ every hop's recorded rights)
// ============================================================================================

export interface GnapAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
  reversibility_class?: string;
}

export interface GnapAuthorizeResult {
  allowed: boolean;
  reason?: string;
}

/**
 * Decide whether `action` is authorized by a GNAP-issued capability chain. FAILS CLOSED. The chain must
 * verify structurally, the root policy envelope must permit the action, AND every delegated hop's
 * recorded `gnap_access` rights must permit it too (the per-hop intersection that enforces "never wider
 * than the issuer" across the whole chain).
 */
export function authorizeGnapAction(
  chain: CapabilityChain,
  action: GnapAction,
  opts: { expectedRootIssuer?: string } = {},
): GnapAuthorizeResult {
  if (!Array.isArray(chain) || chain.length === 0) return { allowed: false, reason: 'empty chain' };
  const vc = verifyChain(chain, opts.expectedRootIssuer);
  if (!vc.ok) return { allowed: false, reason: `capability chain invalid: ${vc.reason ?? 'unknown'}` };

  const env = readEnvelope(chain[0]!);
  if (!env) return { allowed: false, reason: 'root grant carries no policy envelope' };

  const ctx = {
    action: {
      verb: action.verb,
      resource: action.resource,
      ...(action.params !== undefined ? { params: action.params } : {}),
      ...(action.reversibility_class !== undefined ? { reversibility_class: action.reversibility_class } : {}),
    },
  };

  const rootDecision = evaluatePredicates(env.predicates, ctx);
  if (!rootDecision.allowed) {
    return { allowed: false, reason: `root authority denies: ${rootDecision.reason ?? 'no predicate matched'}` };
  }

  const leaf = chain[chain.length - 1]!;
  const caveats = Array.isArray(leaf.caveats) ? leaf.caveats : [];
  for (const cv of caveats) {
    if (cv?.type !== GNAP_ACCESS_CAVEAT) continue;
    const hopPreds = accessArrayToPredicates(readAccessArray(cv.access));
    const hopDecision = evaluatePredicates(hopPreds, ctx);
    if (!hopDecision.allowed) {
      return { allowed: false, reason: `delegated hop denies: ${hopDecision.reason ?? 'no predicate matched'}` };
    }
  }
  return { allowed: true };
}

// ============================================================================================
// Bound token: PCA capability chain ↔ GNAP access token
// ============================================================================================

/** Encode a capability chain as a GNAP access-token `value` (self-contained, re-verified on use). */
export function encodeBoundToken(chain: CapabilityChain): string {
  return b64u(utf8(JSON.stringify(chain)));
}

/** Structural guard: the required shape of a serialized capability hop (verifyChain re-checks crypto). */
function isCapabilityShape(x: unknown): x is Capability {
  if (!isRecord(x)) return false;
  return (
    typeof x.id === 'string' &&
    typeof x.issuer === 'string' &&
    typeof x.holder === 'string' &&
    typeof x.body_digest === 'string' &&
    typeof x.sig === 'string' &&
    Array.isArray(x.caveats) &&
    (x.parent === undefined || typeof x.parent === 'string') &&
    (x.alg === undefined || typeof x.alg === 'string') &&
    (x.pq_pk === undefined || typeof x.pq_pk === 'string') &&
    (x.pq_sig === undefined || typeof x.pq_sig === 'string')
  );
}

/** Total, fail-closed decode of a bound token back into a capability chain (null on any deviation). */
function decodeBoundToken(value: string): CapabilityChain | null {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(unb64u(value));
    const parsed = strictParse(text);
    if (!Array.isArray(parsed)) return null;
    const chain: Capability[] = [];
    for (const hop of parsed) {
      if (!isCapabilityShape(hop)) return null;
      chain.push(hop);
    }
    return chain;
  } catch {
    return null;
  }
}

export interface CapabilityToResponseOptions {
  expiresIn?: number;
  /** Emit the token as bearer (`key:false`) instead of key-bound to the holder. */
  bearer?: boolean;
  instanceId?: string;
  manageUri?: string;
  /** Attach a continuation handle to the response. */
  continue?: GnapContinue;
}

/** Render a (verified) PCA capability chain as a GNAP grant response with a bound access token. */
export function capabilityToGrantResponse(chain: CapabilityChain, opts: CapabilityToResponseOptions = {}): GnapGrantResponse {
  if (!Array.isArray(chain) || chain.length === 0) throw new GnapError('capabilityToGrantResponse: empty chain');
  const leaf = chain[chain.length - 1]!;
  const token: GnapAccessToken = {
    value: encodeBoundToken(chain),
    access: grantedAccessOf(chain),
    key: opts.bearer === true ? false : holderJwk(leaf.holder),
    ...(opts.expiresIn !== undefined ? { expires_in: opts.expiresIn } : {}),
    ...(opts.manageUri !== undefined ? { manage: { uri: opts.manageUri } } : {}),
  };
  return {
    access_token: token,
    ...(opts.continue !== undefined ? { continue: opts.continue } : {}),
    ...(opts.instanceId !== undefined ? { instance_id: opts.instanceId } : {}),
  };
}

export type GnapTokenVerifyResult =
  | { ok: true; principal: string; capability: Capability; chain: CapabilityChain; access: GnapResourceAccess[] }
  | { ok: false; reason: string };

/**
 * Verify an incoming GNAP bound token, mapping it back to a PCA principal + capability. FAILS CLOSED:
 * a token that is not a decodable chain, or whose chain does not verify (optionally against
 * `expectedRootIssuer`), returns `{ ok:false }`. The `principal` is the chain's root issuer key.
 */
export function verifyGnapToken(value: string, opts: { expectedRootIssuer?: string } = {}): GnapTokenVerifyResult {
  if (typeof value !== 'string' || value.length === 0) return { ok: false, reason: 'token value is empty' };
  const chain = decodeBoundToken(value);
  if (chain === null || chain.length === 0) return { ok: false, reason: 'token is not a decodable PCA capability chain' };
  const vc = verifyChain(chain, opts.expectedRootIssuer);
  if (!vc.ok) return { ok: false, reason: `capability chain invalid: ${vc.reason ?? 'unknown'}` };
  const root = chain[0]!;
  const leaf = chain[chain.length - 1]!;
  return { ok: true, principal: root.issuer, capability: leaf, chain, access: grantedAccessOf(chain) };
}

// ============================================================================================
// Key-bound requests: GNAP detached JWS (jwsd, §7.3.4), verified with `jose`
// ============================================================================================

/** The protected header of a GNAP `jwsd` detached JWS (§7.3.4). `created` is epoch SECONDS. */
export interface GnapJwsdHeader {
  alg: 'EdDSA';
  typ: 'gnap-binding-jwsd';
  kid?: string;
  htm: string;
  uri: string;
  created: number;
  /** base64url(SHA-256(access-token value)) — binds the proof to a token when one is in play. */
  ath?: string;
}

/** A raw Ed25519 key pair (the PCA key format: 32-byte seed secret, 32-byte public). */
export interface RawEd25519KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

const JWSD_TYP = 'gnap-binding-jwsd';

function athOf(accessTokenValue: string): string {
  return b64u(sha256(utf8(accessTokenValue)));
}

function toPlain(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function canonicalPayloadBytes(body: unknown): Uint8Array {
  return utf8(canonicalizeStrict(toPlain(body)));
}

export interface SignGnapRequestArgs {
  /** The request body the proof covers (typically the GNAP grant request). */
  body: unknown;
  key: RawEd25519KeyPair;
  htm: string;
  uri: string;
  /** Epoch SECONDS (default: now). */
  created?: number;
  kid?: string;
  /** When an access token is in play, bind the proof to it via the `ath` claim. */
  accessTokenValue?: string;
}

export interface SignGnapRequestResult {
  /** The compact detached JWS: `BASE64URL(header)..BASE64URL(signature)`. */
  detachedJws: string;
  header: GnapJwsdHeader;
  /** The b64u holder key this proof binds the request to. */
  holder: string;
}

/**
 * Produce a GNAP `jwsd` detached-JWS proof over `body`, signed by the client key (via `jose`). The JWS
 * payload is the canonical body; the compact detached form (payload omitted) is what travels in the
 * `Detached-JWS` header. The signing key's public half IS the PCA holder the grant binds to.
 */
export async function signGnapRequest(args: SignGnapRequestArgs): Promise<SignGnapRequestResult> {
  const created = args.created ?? Math.floor(Date.now() / 1000);
  const holder = b64u(args.key.publicKey);
  const header: GnapJwsdHeader = {
    alg: 'EdDSA',
    typ: JWSD_TYP,
    htm: args.htm.toUpperCase(),
    uri: args.uri,
    created,
    ...(args.kid !== undefined ? { kid: args.kid } : {}),
    ...(args.accessTokenValue !== undefined ? { ath: athOf(args.accessTokenValue) } : {}),
  };
  const payload = canonicalPayloadBytes(args.body);
  const privateJwk = { kty: 'OKP', crv: 'Ed25519', x: holder, d: b64u(args.key.secretKey) };
  const signingKey = await importJWK(privateJwk, 'EdDSA');
  // JWSHeaderParameters carries an index signature; copy the typed header into an object literal that
  // satisfies it (GnapJwsdHeader is a closed interface and is not directly assignable).
  const protectedHeader: JWSHeaderParameters = {
    alg: header.alg,
    typ: header.typ,
    htm: header.htm,
    uri: header.uri,
    created: header.created,
    ...(header.kid !== undefined ? { kid: header.kid } : {}),
    ...(header.ath !== undefined ? { ath: header.ath } : {}),
  };
  const jws = await new FlattenedSign(payload).setProtectedHeader(protectedHeader).sign(signingKey);
  return { detachedJws: `${jws.protected}..${jws.signature}`, header, holder };
}

export interface VerifyGnapRequestArgs {
  detachedJws: string;
  body: unknown;
  /** The b64u Ed25519 holder key the proof must verify under. */
  holder: string;
  htm: string;
  uri: string;
  /** Max accepted age of `created` in seconds (default 300). */
  maxAgeSec?: number;
  /** Epoch ms clock (default now). */
  now?: number;
  /** When set, the proof's `ath` must bind exactly this access-token value. */
  accessTokenValue?: string;
}

export type VerifyGnapRequestResult = { ok: true; holder: string; header: GnapJwsdHeader } | { ok: false; reason: string };

/**
 * Verify a GNAP `jwsd` detached-JWS proof (via `jose`) and bind the request to the holder key. FAILS
 * CLOSED on any deviation: a bad signature, a tampered body, a wrong holder, a mismatched `htm`/`uri`,
 * a stale/future `created`, or an `ath` that does not bind the named access token.
 */
export async function verifyGnapRequest(args: VerifyGnapRequestArgs): Promise<VerifyGnapRequestResult> {
  const fail = (reason: string): VerifyGnapRequestResult => ({ ok: false, reason });
  try {
    const parts = args.detachedJws.split('.');
    if (parts.length !== 3) return fail('not a compact JWS (expected three dot-separated parts)');
    const [protectedB64u, mid, signature] = parts;
    if (protectedB64u === undefined || signature === undefined || mid !== '') return fail('not a DETACHED compact JWS');

    const holder = asEd25519(args.holder);
    if (holder === null) return fail('holder is not a canonical base64url Ed25519 public key');

    const payloadB64u = base64url.encode(canonicalPayloadBytes(args.body));
    const verifyKey = await importJWK({ kty: 'OKP', crv: 'Ed25519', x: holder }, 'EdDSA');

    let header: JWSHeaderParameters | undefined;
    try {
      const res = await flattenedVerify({ protected: protectedB64u, payload: payloadB64u, signature }, verifyKey);
      header = res.protectedHeader;
    } catch {
      return fail('jwsd signature does not verify under the holder key (or body was tampered)');
    }
    if (header === undefined) return fail('jwsd carries no protected header');

    if (header.typ !== JWSD_TYP) return fail('unexpected typ (not gnap-binding-jwsd)');
    if (header.alg !== 'EdDSA') return fail('unexpected alg (not EdDSA)');

    const htm = header.htm;
    if (typeof htm !== 'string' || htm.toUpperCase() !== args.htm.toUpperCase()) return fail('htm does not match the request method');
    const uri = header.uri;
    if (typeof uri !== 'string' || uri !== args.uri) return fail('uri does not match the request target');
    const created = header.created;
    if (typeof created !== 'number' || !Number.isFinite(created)) return fail('missing or malformed created');

    const nowSec = Math.floor((args.now ?? Date.now()) / 1000);
    const maxAge = args.maxAgeSec ?? 300;
    if (created > nowSec + 60) return fail('created is in the future');
    if (nowSec - created > maxAge) return fail('jwsd proof is stale');

    const ath = header.ath;
    if (args.accessTokenValue !== undefined) {
      if (typeof ath !== 'string' || ath !== athOf(args.accessTokenValue)) return fail('ath does not bind the named access token');
    }

    const out: GnapJwsdHeader = {
      alg: 'EdDSA',
      typ: JWSD_TYP,
      htm,
      uri,
      created,
      ...(typeof header.kid === 'string' ? { kid: header.kid } : {}),
      ...(typeof ath === 'string' ? { ath } : {}),
    };
    return { ok: true, holder, header: out };
  } catch {
    return fail('malformed jwsd request');
  }
}

// ============================================================================================
// Continuation → step-up: a GNAP `continue` handle resolved by a FROST/CIBA co-signature
// ============================================================================================

/** A GNAP continuation mapped onto a PCA step-up (the tier-2/3 co-signature required to proceed). */
export interface GnapStepUpDescriptor {
  /** The PCA step-up tier: 2 = + guardian co-sign, 3 = + principal co-sign. */
  tier: 2 | 3;
  /** The threshold `t` the folded PCActn must reach. */
  t: 1 | 2 | 3;
  /** The signer set the co-signatures are verified against. */
  signerSet: Signer[];
  reason: string;
  /** The continuation access-token value the client returns with. */
  continueToken: string;
}

export interface GnapContinuationResult {
  /** A GNAP grant response carrying ONLY a `continue` handle (no token yet). */
  response: GnapGrantResponse;
  stepUp: GnapStepUpDescriptor;
}

export interface StepUpAssessment {
  required: boolean;
  reason: string;
  /** Requested rights that exceed the issuer's authority (each needs escalated authority). */
  beyond: GnapResourceAccess[];
  tier: 2 | 3;
}

/**
 * Decide whether a grant request needs a continuation/step-up: it does when GNAP interaction is
 * requested, when an explicit higher tier is asked for, or when (given the issuer's chain) the request
 * asks for rights BEYOND the issuer's own authority — which can only be unlocked by a human/guardian
 * co-signature, not minted by the agent alone.
 */
export function gnapRequestRequiresStepUp(
  req: GnapGrantRequest,
  opts: { issuerChain?: CapabilityChain; tier?: 2 | 3 } = {},
): StepUpAssessment {
  const beyond: GnapResourceAccess[] = [];
  if (opts.issuerChain) {
    const G = grantedAccessOf(opts.issuerChain);
    for (const r of normalizeAccess(accessOf(req))) if (!accessWithin(G, r)) beyond.push(r);
  }
  const interactRequested = req.interact !== undefined && Array.isArray(req.interact.start) && req.interact.start.length > 0;
  const required = interactRequested || beyond.length > 0 || (opts.tier !== undefined && opts.tier > 1);
  const tier: 2 | 3 = opts.tier ?? (beyond.length > 0 ? 3 : 2);
  const reason = !required
    ? 'no step-up required'
    : beyond.length > 0
      ? `requested rights exceed the issuer's authority (${beyond.length} right(s) beyond)`
      : interactRequested
        ? 'GNAP interaction requested'
        : `tier ${tier} step-up required`;
  return { required, reason, beyond, tier };
}

export interface BeginContinuationArgs {
  signerSet: Signer[];
  t: 1 | 2 | 3;
  tier: 2 | 3;
  continueUri: string;
  continueToken: string;
  wait?: number;
  reason?: string;
}

/** Begin a GNAP continuation: emit the `continue` handle + the PCA step-up it resolves through. */
export function beginGnapContinuation(args: BeginContinuationArgs): GnapContinuationResult {
  const cont: GnapContinue = {
    uri: args.continueUri,
    access_token: { value: args.continueToken, bound: true },
    ...(args.wait !== undefined ? { wait: args.wait } : {}),
  };
  return {
    response: { continue: cont },
    stepUp: {
      tier: args.tier,
      t: args.t,
      signerSet: args.signerSet,
      reason: args.reason ?? `tier ${args.tier} co-signature required to continue`,
      continueToken: args.continueToken,
    },
  };
}

/**
 * Produce one role's step-up co-signature share over the action's PCActn — the co-signature a
 * guardian/principal device returns through the GNAP continuation. For 'guardian'/'principal' it binds
 * the signer set + `t` (replay-safe); the 'agent' share is the PCActn's own leaf signature.
 */
export function gnapStepUpShare(
  body: PCActnBody,
  role: SignerRole,
  secret: Uint8Array,
  signerSet: Signer[],
  t: 1 | 2 | 3,
): ThresholdShare {
  return signShare(role, secret, thresholdMessage(body), { signerSet, t });
}

export interface CompleteContinuationArgs {
  grant: Capability;
  chain: CapabilityChain;
  plan: PlanNode[];
  nodeId: string;
  params?: Record<string, unknown>;
  counter: number;
  aud: string;
  now?: number;
  ttlMs?: number;
  /** The agent-leaf holder secret (produces the PCActn leaf signature = the 'agent' share). */
  agentLeafSecret: Uint8Array;
  signerSet: Signer[];
  t: 1 | 2 | 3;
  /** The guardian/principal secrets reached via the continuation, each folded in as a threshold share. */
  cosignSecrets: { role: SignerRole; secret: Uint8Array }[];
}

export interface CompleteContinuationResult {
  pcactn: PCActn;
  threshold: ThresholdSignature;
  verdict: ThresholdVerdict;
}

/**
 * Resolve a continuation: build the action's PCActn (agent leaf signature) and FOLD the step-up
 * co-signatures into its `threshold`, then verify the threshold `t` is reached. This is the concrete
 * realization of "a grant that needs more authority continues via a step-up co-signature folded into
 * the PCActn" — the multi-signature carrier; a FROST aggregate share slots in the same `agent`/group
 * position without changing the property.
 */
export function completeGnapContinuation(args: CompleteContinuationArgs): CompleteContinuationResult {
  if (!Array.isArray(args.chain) || args.chain.length === 0) throw new GnapError('completeGnapContinuation: empty chain');
  const pcactn = buildPCActn({
    grant: args.grant,
    chain: args.chain,
    plan: args.plan,
    nodeId: args.nodeId,
    counter: args.counter,
    signerSecret: args.agentLeafSecret,
    aud: args.aud,
    ...(args.params !== undefined ? { params: args.params } : {}),
    ...(args.now !== undefined ? { now: args.now } : {}),
    ...(args.ttlMs !== undefined ? { ttlMs: args.ttlMs } : {}),
  });
  const message = thresholdMessage(pcactn);
  // The agent's vote is a role-bound share like every other (a bare leaf signature is valid under any signer set / t and is rejected).
  const agentShare: ThresholdShare = signShare('agent', args.agentLeafSecret, message, { signerSet: args.signerSet, t: args.t });
  const cosignShares = args.cosignSecrets.map((cs) => signShare(cs.role, cs.secret, message, { signerSet: args.signerSet, t: args.t }));
  const threshold = assembleThreshold([agentShare, ...cosignShares]);
  const verdict = verifyThreshold(threshold, message, args.signerSet, args.t);
  return { pcactn: { ...pcactn, threshold }, threshold, verdict };
}

// ============================================================================================
// The Agent-GNAP profile, as a machine-readable spec object
// ============================================================================================

export interface AgentGnapMapping {
  gnap: string;
  pca: string;
  note: string;
}

export interface AgentGnapProfile {
  name: string;
  version: string;
  rfc: string;
  summary: string;
  /** How each GNAP primitive maps onto a PCA concept. */
  mapping: AgentGnapMapping[];
  /** Supported key-proof methods (§7.3). */
  proofMethods: string[];
  /** The multi-hop agent-delegation model. */
  multiHop: string;
  /** How a continuation resolves. */
  stepUp: string;
  /** The security properties this profile guarantees. */
  security: string[];
}

/** The machine-readable Agent-GNAP profile spec (see the module header for the full narrative). */
export const AGENT_GNAP_PROFILE: AgentGnapProfile = {
  name: 'agent-gnap',
  version: '1.0',
  rfc: 'RFC 9635',
  summary:
    'A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is ' +
    'issued as an attenuated, key-bound PCA capability, never wider than the issuing agent.',
  mapping: [
    { gnap: 'access[].type', pca: 'predicate resource namespace gnap:<type>:<location>', note: 'the resource family the rights live in' },
    { gnap: 'access[].actions', pca: 'predicate.verb (list, or * for any)', note: 'the operations permitted' },
    { gnap: 'access[].locations', pca: 'predicate.resource (exact or trailing-* prefix)', note: 'the resource targets' },
    { gnap: 'access[].datatypes / identifier', pca: "predicate.where on action.params.*", note: 'value-level constraints' },
    { gnap: 'client.key.jwk (OKP/Ed25519)', pca: 'capability.holder (cnf-bound key)', note: 'the proof-of-possession key' },
    { gnap: 'grant request (no prior grant)', pca: 'mintGrant → root capability', note: 'envelope predicates = requested access' },
    { gnap: 'grant request (delegated hop)', pca: 'delegate → child capability + gnap_access caveat', note: 'append-only attenuation' },
    { gnap: 'access_token (§3.2)', pca: 'a verifiable PCA capability chain (encodeBoundToken)', note: 'bound, self-verifying token' },
    { gnap: 'continue (§3.1) + interact (§3.3)', pca: 'PCA step-up: FROST/threshold co-signature folded into a PCActn', note: 'tier-2/3 escalation' },
    { gnap: 'jwsd detached JWS (§7.3.4)', pca: 'request proof binding the body to capability.holder', note: 'verified with jose' },
  ],
  proofMethods: ['jwsd'],
  multiHop:
    'An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, ' +
    'recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the ' +
    'intersection of the root policy envelope and every hop; PCA caveats are conjunctive and ' +
    'append-only, so no hop can widen — "never wider than the issuer" holds across any depth.',
  stepUp:
    'A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue ' +
    'handle instead of a token. The client returns with the action PCActn plus a guardian/principal ' +
    'co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or ' +
    'multi-signature) before the action is admitted.',
  security: [
    'Attenuation is structural and append-only: a delegated hop can only ever narrow authority.',
    'Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS.',
    'All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies.',
    'Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth).',
    'Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant.',
  ],
};
