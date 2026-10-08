/**
 * `@atlasauth/pca-idjag` — an ID-JAG / OAuth Cross-App-Access (XAA) bridge for Proof-Carrying Authority.
 *
 * ID-JAG is the Identity Assertion Authorization Grant of
 * {@link https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/ | draft-ietf-oauth-identity-assertion-authz-grant}
 * (the standards-track form of Okta's "Cross-App Access"). An ID-JAG is a JWT the enterprise IdP mints so
 * one app may act, on a named user's behalf, against ANOTHER app — scoped, time-boxed, single-audience:
 *
 *   iss  — the IdP that asserts the grant
 *   sub  — the HUMAN the grant is about
 *   act  — the AGENT/app doing the acting (RFC 8693 actor claim, `{ sub: "<agent>" , ... }`)
 *   aud  — the SINGLE resource app the grant is for
 *   scope— the authority being delegated
 *
 * That is exactly PCA's principal model: a human subject, an agent holder, a single audience, a scoped
 * authority. This package verifies an ID-JAG and projects it onto a PCA principal + a signed root
 * capability, so PCA drops into an Okta/Entra enterprise stack as the action verifier. It also builds the
 * two OAuth request shapes the XAA flow uses — RFC 8693 token-exchange (to OBTAIN an ID-JAG) and RFC 7523
 * jwt-bearer (to REDEEM one) — so PCA can both consume and participate in the flow.
 *
 * Verification REUSES `@atlasauth/pca-oidc`: `verifyIdToken` performs every crypto + registered-claim check
 * (signature, `iss`, `aud`, `exp`, `iat`, `nonce`, injectable JWKS), and `oidcPrincipal` performs the
 * identity → PCA-principal mapping. This module adds only the ID-JAG-specific rules (single audience, the
 * required `act` agent claim, scope parsing) and the capability projection.
 */
import { decodeJwt } from 'jose';
import {
  OidcVerificationError,
  oidcPrincipal,
  verifyIdToken,
  type OidcConfirmation,
  type OidcIdTokenClaims,
  type OidcPrincipal,
  type OidcPrincipalOptions,
  type OidcVerificationErrorCode,
  type OidcVerifyKey,
} from '@atlasauth/pca-oidc';
import { mintRoot, type CapSuiteOpts, type Capability, type Caveat } from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------------
// Verified ID-JAG grant
// ---------------------------------------------------------------------------------------------------

/** The RFC 8693 `act` (actor) claim identifying the AGENT the grant authorizes to act. */
export interface IdJagActor {
  /** The agent's identifier (required). */
  sub: string;
  [member: string]: unknown;
}

/** A verified ID-JAG grant. Every field here passed verification; a failure throws instead. */
export interface IdJagGrant {
  /** The IdP that asserted the grant (`iss`). */
  iss: string;
  /** The HUMAN the grant is about (`sub`). */
  sub: string;
  /** The AGENT the grant authorizes (`act`). */
  actor: IdJagActor;
  /** Convenience: `actor.sub`, the agent identifier. */
  agent: string;
  /** The SINGLE resource app the grant is for (`aud`). */
  audience: string;
  /** The delegated authority — the parsed `scope` (space-delimited) or `scopes` array. */
  scopes: string[];
  /** Issued-at (epoch seconds). */
  iat: number;
  /** Expiry (epoch seconds). */
  exp: number;
  /** JWT id, when present. */
  jti?: string;
  /** Round-tripped `nonce`, when the verifier required one. */
  nonce?: string;
  /** RFC 7800 `cnf` confirmation, when the grant binds a proof-of-possession key. */
  cnf?: OidcConfirmation;
  /** The verified OIDC base claims — fed straight to `oidcPrincipal` for the principal mapping. */
  oidcClaims: OidcIdTokenClaims;
}

/** A stable classification of why ID-JAG verification failed (the OIDC codes plus ID-JAG-specific ones). */
export type IdJagVerificationErrorCode = OidcVerificationErrorCode | 'actor' | 'scope' | 'grant';

/** The error thrown for any ID-JAG verification failure. `code` classifies the cause. */
export class IdJagVerificationError extends Error {
  override readonly name = 'IdJagVerificationError';
  readonly code: IdJagVerificationErrorCode;
  constructor(code: IdJagVerificationErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.code = code;
  }
}

export interface VerifyIdJagOptions {
  /** Expected `iss` — the exact IdP issuer identifier. Required. */
  issuer: string;
  /**
   * Expected `aud` — the SINGLE resource app this grant must be for. ID-JAG is single-audience: the token's
   * `aud` must be exactly this value (a string, or a one-element array equal to it), else verification fails.
   */
  audience: string;
  /** When set, the grant's `nonce` MUST be present and equal this value. */
  nonce?: string;
  /** When set, every scope here MUST be present in the grant, else verification fails. */
  requiredScopes?: string[];
  /** Clock skew tolerance in seconds (default 0). */
  clockToleranceSec?: number;
  /** When set, reject a grant whose `iat` is older than this many seconds. */
  maxTokenAgeSec?: number;
  /** Allowed JWS `alg`s. Defaults to the asymmetric set (never symmetric). */
  algorithms?: string[];
  /** Injectable key material (a key, JWK, or `createRemoteJWKSet` resolver). Preferred for tests. */
  key?: OidcVerifyKey;
  /** A JWKS endpoint URL to build a remote key set from (skips discovery). */
  jwksUri?: string;
  /** Resolve the JWKS endpoint from the issuer's `.well-known/openid-configuration` first. */
  discover?: boolean;
  /** Injectable `fetch` used for discovery (defaults to the global `fetch`). */
  fetch?: typeof fetch;
}

/**
 * Verify an ID-JAG JWT and return the parsed grant. Fails CLOSED: any signature / issuer / audience /
 * expiry / nonce failure, a missing or malformed `act` agent claim, a missing `scope`, or a missing
 * required scope throws {@link IdJagVerificationError}. The JWKS is injectable (`key` / `jwksUri` /
 * `discover`); `key` lets tests verify entirely in-memory.
 */
export async function verifyIdJag(jwt: string, opts: VerifyIdJagOptions): Promise<IdJagGrant> {
  if (typeof jwt !== 'string' || jwt.length === 0) {
    throw new IdJagVerificationError('invalid_token', 'verifyIdJag: jwt must be a non-empty string');
  }
  if (opts === null || typeof opts !== 'object') {
    throw new IdJagVerificationError('config', 'verifyIdJag: opts is required');
  }
  if (typeof opts.issuer !== 'string' || opts.issuer.length === 0) {
    throw new IdJagVerificationError('config', 'verifyIdJag: opts.issuer is required');
  }
  if (typeof opts.audience !== 'string' || opts.audience.length === 0) {
    throw new IdJagVerificationError('config', 'verifyIdJag: opts.audience is required (ID-JAG is single-audience)');
  }

  // Reuse the OIDC verifier for every crypto + registered-claim check. It maps each jose failure onto a
  // stable OIDC code; we re-wrap as an ID-JAG error preserving that code so callers see one error family.
  let base: OidcIdTokenClaims;
  try {
    base = await verifyIdToken(jwt, {
      issuer: opts.issuer,
      audience: opts.audience,
      ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
      ...(opts.clockToleranceSec !== undefined ? { clockToleranceSec: opts.clockToleranceSec } : {}),
      ...(opts.maxTokenAgeSec !== undefined ? { maxTokenAgeSec: opts.maxTokenAgeSec } : {}),
      ...(opts.algorithms !== undefined ? { algorithms: opts.algorithms } : {}),
      ...(opts.key !== undefined ? { key: opts.key } : {}),
      ...(opts.jwksUri !== undefined ? { jwksUri: opts.jwksUri } : {}),
      ...(opts.discover !== undefined ? { discover: opts.discover } : {}),
      ...(opts.fetch !== undefined ? { fetch: opts.fetch } : {}),
    });
  } catch (cause) {
    if (cause instanceof OidcVerificationError) {
      throw new IdJagVerificationError(cause.code, cause.message, { cause });
    }
    throw new IdJagVerificationError('invalid_token', 'ID-JAG verification failed', { cause });
  }

  // ID-JAG is SINGLE-AUDIENCE: the resource app must be the sole aud. `verifyIdToken` already confirmed the
  // expected audience is PRESENT; here we additionally reject any extra audience (a multi-aud grant).
  const audList = Array.isArray(base.aud) ? base.aud : [base.aud];
  if (audList.length !== 1 || audList[0] !== opts.audience) {
    throw new IdJagVerificationError(
      'audience',
      'ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)',
    );
  }

  // The signature is verified, so the payload is authentic: decode it to read the non-OIDC claims
  // (`act`, `scope`, `jti`) that the OIDC claim projection does not surface.
  let raw: Record<string, unknown>;
  try {
    raw = decodeJwt(jwt) as Record<string, unknown>;
  } catch (cause) {
    throw new IdJagVerificationError('invalid_token', 'ID-JAG payload could not be decoded', { cause });
  }

  const actor = asActor(raw.act);
  if (actor === undefined) {
    throw new IdJagVerificationError('actor', 'ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"');
  }

  const scopes = parseScopes(raw.scope, raw.scopes);
  if (scopes === undefined) {
    throw new IdJagVerificationError('scope', 'ID-JAG is missing the "scope" (or "scopes") claim');
  }
  if (Array.isArray(opts.requiredScopes)) {
    const have = new Set(scopes);
    for (const req of opts.requiredScopes) {
      if (!have.has(req)) {
        throw new IdJagVerificationError('scope', `ID-JAG does not grant the required scope "${req}"`);
      }
    }
  }

  const jti = typeof raw.jti === 'string' && raw.jti.length > 0 ? raw.jti : undefined;

  return {
    iss: base.iss,
    sub: base.sub,
    actor,
    agent: actor.sub,
    audience: opts.audience,
    scopes,
    iat: base.iat,
    exp: base.exp,
    ...(jti !== undefined ? { jti } : {}),
    ...(base.nonce !== undefined ? { nonce: base.nonce } : {}),
    ...(base.cnf !== undefined ? { cnf: base.cnf } : {}),
    oidcClaims: base,
  };
}

function asActor(v: unknown): IdJagActor | undefined {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return undefined;
  const rec = v as Record<string, unknown>;
  const sub = rec.sub;
  if (typeof sub !== 'string' || sub.length === 0) return undefined;
  return { ...rec, sub };
}

/** Parse the delegated authority from the `scope` (space-delimited string or array) / `scopes` claim. */
function parseScopes(scope: unknown, scopes: unknown): string[] | undefined {
  if (typeof scope === 'string') return scope.split(/\s+/).filter((s) => s.length > 0);
  if (Array.isArray(scope)) return scope.filter((s): s is string => typeof s === 'string' && s.length > 0);
  if (Array.isArray(scopes)) return scopes.filter((s): s is string => typeof s === 'string' && s.length > 0);
  return undefined;
}

// ---------------------------------------------------------------------------------------------------
// ID-JAG → PCA principal / capability
// ---------------------------------------------------------------------------------------------------

/**
 * Map a verified ID-JAG onto a PCA principal descriptor (the ROOT of a capability chain). Delegates to
 * `@atlasauth/pca-oidc`'s `oidcPrincipal` on the grant's OIDC base claims, so the human `iss`+`sub` becomes
 * a stable `principalId`, a signed `oidc_subject` caveat, and — when the grant binds a `cnf` Ed25519 key or
 * the caller supplies one via `opts.principalPublic` — the b64u Ed25519 key the chain roots at.
 */
export function idJagToPcaPrincipal(grant: IdJagGrant, opts: OidcPrincipalOptions = {}): OidcPrincipal {
  if (grant === null || typeof grant !== 'object') throw new TypeError('idJagToPcaPrincipal: grant is required');
  return oidcPrincipal(grant.oidcClaims, opts);
}

/** The caveat recording the authority (scopes + audience) delegated by an ID-JAG. */
export const IDJAG_AUTHORITY_CAVEAT = 'idjag_authority';
/** The caveat recording the ID-JAG provenance (who asserted it, for whom, by whom, when). */
export const IDJAG_PROVENANCE_CAVEAT = 'idjag_provenance';

/** A capability caveat whose `scopes` ARE the root capability's authority. */
export interface IdJagAuthorityCaveat extends Caveat {
  type: typeof IDJAG_AUTHORITY_CAVEAT;
  /** The delegated scopes — the authority of the root capability. */
  scopes: string[];
  /** The single resource audience the authority is for. */
  aud: string;
}

/** A capability caveat recording the ID-JAG this root capability was projected from. */
export interface IdJagProvenanceCaveat extends Caveat {
  type: typeof IDJAG_PROVENANCE_CAVEAT;
  /** The IdP that asserted the grant. */
  iss: string;
  /** The human subject. */
  sub: string;
  /** The agent (`act.sub`) the grant authorized. */
  agent: string;
  /** The single resource audience. */
  aud: string;
  /** Grant issued-at (epoch seconds). */
  iat: number;
  /** Grant expiry (epoch seconds). */
  exp: number;
  /** Grant JWT id, when present. */
  jti?: string;
}

export interface IdJagToCapabilityOptions extends OidcPrincipalOptions {
  /** The principal (human root) Ed25519 secret key that signs the root capability. */
  principalSecret: Uint8Array;
  /**
   * The b64u Ed25519 principal (human root) public key the chain roots at. When the ID-JAG binds a `cnf`
   * Ed25519 key, this MUST equal it (checked by `oidcPrincipal`), else a mismatch throws (fail closed).
   */
  principalPublic: string;
  /** The b64u Ed25519 key the capability is bound to — the AGENT (`act`) holder. */
  holder: string;
  /** Optional per-hop signature suite for the root (default ed25519). */
  suite?: CapSuiteOpts;
  /** Optional extra caveats appended after the authority / provenance / subject caveats. */
  extraCaveats?: Caveat[];
}

export interface IdJagCapabilityResult {
  /** The signed root capability: authority = scopes, holder = agent, subject = human. */
  capability: Capability;
  /** The PCA principal descriptor derived from the grant. */
  principal: OidcPrincipal;
  /** The delegated scopes, == the authority caveat's scopes. */
  scopes: string[];
}

/**
 * Project a verified ID-JAG onto a signed PCA ROOT capability:
 *   - authority = the grant's scopes (an {@link IdJagAuthorityCaveat});
 *   - holder    = the agent (`act`) — `opts.holder`, the agent's PCA key;
 *   - subject   = the human (`sub`) — recorded by the OIDC `oidc_subject` caveat;
 *   - provenance= an {@link IdJagProvenanceCaveat} recording iss/sub/agent/aud/iat/exp/jti.
 *
 * The capability is rooted at `opts.principalPublic` (the human's root key) and signed by
 * `opts.principalSecret`, so it anchors straight into `verifyChain([capability, ...], principalPublic)`.
 */
export function idJagToCapability(grant: IdJagGrant, opts: IdJagToCapabilityOptions): IdJagCapabilityResult {
  if (grant === null || typeof grant !== 'object') throw new TypeError('idJagToCapability: grant is required');
  if (opts === null || typeof opts !== 'object') throw new TypeError('idJagToCapability: opts is required');
  if (!(opts.principalSecret instanceof Uint8Array)) {
    throw new TypeError('idJagToCapability: opts.principalSecret must be a Uint8Array');
  }
  if (typeof opts.principalPublic !== 'string' || opts.principalPublic.length === 0) {
    throw new TypeError('idJagToCapability: opts.principalPublic is required');
  }
  if (typeof opts.holder !== 'string' || opts.holder.length === 0) {
    throw new TypeError('idJagToCapability: opts.holder (the agent key) is required');
  }

  // Derive the principal — this also validates principalPublic against the grant's cnf key when present.
  const principal = idJagToPcaPrincipal(grant, { principalPublic: opts.principalPublic });

  const authority: IdJagAuthorityCaveat = {
    type: IDJAG_AUTHORITY_CAVEAT,
    scopes: [...grant.scopes],
    aud: grant.audience,
  };
  const provenance: IdJagProvenanceCaveat = {
    type: IDJAG_PROVENANCE_CAVEAT,
    iss: grant.iss,
    sub: grant.sub,
    agent: grant.agent,
    aud: grant.audience,
    iat: grant.iat,
    exp: grant.exp,
    ...(grant.jti !== undefined ? { jti: grant.jti } : {}),
  };
  const caveats: Caveat[] = [authority, provenance, principal.subjectCaveat, ...(opts.extraCaveats ?? [])];

  const capability = mintRoot({
    principalSecret: opts.principalSecret,
    principalPublic: opts.principalPublic,
    holder: opts.holder,
    caveats,
    ...(opts.suite !== undefined ? { suite: opts.suite } : {}),
  });

  return { capability, principal, scopes: [...grant.scopes] };
}

/** Narrowing guard for an {@link IdJagAuthorityCaveat}. */
export function isIdJagAuthorityCaveat(cv: unknown): cv is IdJagAuthorityCaveat {
  if (cv === null || typeof cv !== 'object') return false;
  const rec = cv as { type?: unknown; scopes?: unknown; aud?: unknown };
  return (
    rec.type === IDJAG_AUTHORITY_CAVEAT &&
    Array.isArray(rec.scopes) &&
    rec.scopes.every((s) => typeof s === 'string') &&
    typeof rec.aud === 'string' &&
    rec.aud.length > 0
  );
}

/** Narrowing guard for an {@link IdJagProvenanceCaveat}. */
export function isIdJagProvenanceCaveat(cv: unknown): cv is IdJagProvenanceCaveat {
  if (cv === null || typeof cv !== 'object') return false;
  const rec = cv as { type?: unknown; iss?: unknown; sub?: unknown; agent?: unknown; aud?: unknown; iat?: unknown; exp?: unknown };
  return (
    rec.type === IDJAG_PROVENANCE_CAVEAT &&
    typeof rec.iss === 'string' &&
    typeof rec.sub === 'string' &&
    typeof rec.agent === 'string' &&
    typeof rec.aud === 'string' &&
    typeof rec.iat === 'number' &&
    typeof rec.exp === 'number'
  );
}

/** Read the {@link IdJagAuthorityCaveat} from a root capability, or null if absent/malformed. */
export function readIdJagAuthority(cap: Capability): IdJagAuthorityCaveat | null {
  const cv = cap?.caveats?.find((c) => c?.type === IDJAG_AUTHORITY_CAVEAT);
  return cv !== undefined && isIdJagAuthorityCaveat(cv) ? cv : null;
}

/** Read the {@link IdJagProvenanceCaveat} from a root capability, or null if absent/malformed. */
export function readIdJagProvenance(cap: Capability): IdJagProvenanceCaveat | null {
  const cv = cap?.caveats?.find((c) => c?.type === IDJAG_PROVENANCE_CAVEAT);
  return cv !== undefined && isIdJagProvenanceCaveat(cv) ? cv : null;
}

// ---------------------------------------------------------------------------------------------------
// XAA flow: RFC 8693 token-exchange + RFC 7523 jwt-bearer request shapes
// ---------------------------------------------------------------------------------------------------

/** RFC 8693 token-exchange grant type. */
export const GRANT_TYPE_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
/** RFC 7523 JWT-bearer grant type (redeem an assertion for an access token). */
export const GRANT_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
/** The ID-JAG requested-token-type (draft-ietf-oauth-identity-assertion-authz-grant). */
export const TOKEN_TYPE_ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';
/** RFC 8693 `id_token` token type. */
export const TOKEN_TYPE_ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
/** RFC 8693 `access_token` token type. */
export const TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
/** RFC 8693 generic `jwt` token type. */
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';
/** RFC 7523 client-assertion type (for authenticating the client with a JWT). */
export const CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** A ready-to-send `application/x-www-form-urlencoded` OAuth POST. */
export interface OAuthFormRequest {
  /** The token endpoint to POST to. */
  url: string;
  method: 'POST';
  headers: Record<string, string>;
  /** The form fields (empty values dropped). */
  params: Record<string, string>;
  /** The url-encoded request body (`params` serialized). */
  body: string;
}

function formRequest(url: string, params: Record<string, string | undefined>): OAuthFormRequest {
  const clean: Record<string, string> = {};
  for (const [k, v] of Object.entries(params)) {
    if (typeof v === 'string' && v.length > 0) clean[k] = v;
  }
  const search = new URLSearchParams(clean);
  return {
    url,
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    params: clean,
    body: search.toString(),
  };
}

/** Normalize a `scope` string or array to the space-delimited OAuth `scope` form, or undefined if empty. */
function scopeParam(scope: string | string[] | undefined): string | undefined {
  if (scope === undefined) return undefined;
  const parts = (Array.isArray(scope) ? scope : scope.split(/\s+/)).filter((s) => typeof s === 'string' && s.length > 0);
  return parts.length > 0 ? parts.join(' ') : undefined;
}

export interface TokenExchangeRequestOptions {
  /** The IdP token endpoint the exchange is POSTed to. */
  tokenEndpoint: string;
  /** The subject token being exchanged (e.g. the end-user's ID token). */
  subjectToken: string;
  /** The subject token type (default `urn:...:id_token`). */
  subjectTokenType?: string;
  /** An optional actor token (the agent app's own token), when delegating. */
  actorToken?: string;
  /** The actor token type (default `urn:...:jwt` when `actorToken` is present). */
  actorTokenType?: string;
  /** The logical name of the target resource app the ID-JAG is FOR (RFC 8693 `audience`). */
  audience?: string;
  /** The resource URI the ID-JAG is for (RFC 8693 `resource`). */
  resource?: string;
  /** The scopes to request (string or array). */
  scope?: string | string[];
  /** The requested token type (default the ID-JAG type). */
  requestedTokenType?: string;
  /** The requesting client id (the agent app). */
  clientId?: string;
  /** Extra form fields to merge in. */
  extra?: Record<string, string>;
}

/**
 * Build the RFC 8693 token-exchange request that OBTAINS an ID-JAG from the IdP (the first XAA leg): the
 * requesting app presents the user's subject token and asks the IdP to mint an ID-JAG for a single target
 * resource app. Defaults `requested_token_type` to the ID-JAG type and `subject_token_type` to `id_token`.
 */
export function tokenExchangeRequest(opts: TokenExchangeRequestOptions): OAuthFormRequest {
  if (opts === null || typeof opts !== 'object') throw new TypeError('tokenExchangeRequest: opts is required');
  if (typeof opts.tokenEndpoint !== 'string' || opts.tokenEndpoint.length === 0) {
    throw new TypeError('tokenExchangeRequest: opts.tokenEndpoint is required');
  }
  if (typeof opts.subjectToken !== 'string' || opts.subjectToken.length === 0) {
    throw new TypeError('tokenExchangeRequest: opts.subjectToken is required');
  }
  const hasActor = typeof opts.actorToken === 'string' && opts.actorToken.length > 0;
  return formRequest(opts.tokenEndpoint, {
    grant_type: GRANT_TYPE_TOKEN_EXCHANGE,
    subject_token: opts.subjectToken,
    subject_token_type: opts.subjectTokenType ?? TOKEN_TYPE_ID_TOKEN,
    requested_token_type: opts.requestedTokenType ?? TOKEN_TYPE_ID_JAG,
    ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    ...(opts.resource !== undefined ? { resource: opts.resource } : {}),
    ...(scopeParam(opts.scope) !== undefined ? { scope: scopeParam(opts.scope) } : {}),
    ...(hasActor ? { actor_token: opts.actorToken, actor_token_type: opts.actorTokenType ?? TOKEN_TYPE_JWT } : {}),
    ...(opts.clientId !== undefined ? { client_id: opts.clientId } : {}),
    ...(opts.extra ?? {}),
  });
}

export interface JwtBearerAssertionOptions {
  /** The target resource app's token endpoint the assertion is REDEEMED at. */
  tokenEndpoint: string;
  /** The assertion being presented — typically the ID-JAG obtained from the IdP. */
  assertion: string;
  /** The scopes to request at the resource app (string or array). */
  scope?: string | string[];
  /** The redeeming client id (the agent app). */
  clientId?: string;
  /** An optional RFC 7523 client-assertion JWT, to authenticate the client. */
  clientAssertion?: string;
  /** Extra form fields to merge in. */
  extra?: Record<string, string>;
}

/** The structured RFC 7523 jwt-bearer representation of an ID-JAG being redeemed. */
export interface JwtBearerAssertion {
  grantType: typeof GRANT_TYPE_JWT_BEARER;
  /** The assertion (the ID-JAG). */
  assertion: string;
  /** The requested scopes, space-delimited (when any). */
  scope?: string;
  /** The ready-to-send token request that redeems the assertion. */
  request: OAuthFormRequest;
}

/**
 * Build the RFC 7523 jwt-bearer representation + request that REDEEMS an ID-JAG at the target resource
 * app's token endpoint for an access token (the second XAA leg): `grant_type=...:jwt-bearer` with the
 * ID-JAG as the `assertion`. Pass `clientAssertion` to additionally authenticate the client with a JWT.
 */
export function jwtBearerAssertion(opts: JwtBearerAssertionOptions): JwtBearerAssertion {
  if (opts === null || typeof opts !== 'object') throw new TypeError('jwtBearerAssertion: opts is required');
  if (typeof opts.tokenEndpoint !== 'string' || opts.tokenEndpoint.length === 0) {
    throw new TypeError('jwtBearerAssertion: opts.tokenEndpoint is required');
  }
  if (typeof opts.assertion !== 'string' || opts.assertion.length === 0) {
    throw new TypeError('jwtBearerAssertion: opts.assertion is required');
  }
  const scope = scopeParam(opts.scope);
  const hasClientAssertion = typeof opts.clientAssertion === 'string' && opts.clientAssertion.length > 0;
  const request = formRequest(opts.tokenEndpoint, {
    grant_type: GRANT_TYPE_JWT_BEARER,
    assertion: opts.assertion,
    ...(scope !== undefined ? { scope } : {}),
    ...(opts.clientId !== undefined ? { client_id: opts.clientId } : {}),
    ...(hasClientAssertion
      ? { client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER, client_assertion: opts.clientAssertion }
      : {}),
    ...(opts.extra ?? {}),
  });
  return {
    grantType: GRANT_TYPE_JWT_BEARER,
    assertion: opts.assertion,
    ...(scope !== undefined ? { scope } : {}),
    request,
  };
}

export type { OidcPrincipal, OidcPrincipalOptions, OidcConfirmation, OidcVerifyKey } from '@atlasauth/pca-oidc';
