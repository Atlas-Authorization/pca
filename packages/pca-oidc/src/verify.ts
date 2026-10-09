/**
 * Verify an OpenID Connect ID token (OpenID Connect Core 1.0 §3.1.3.7) with
 * {@link https://github.com/panva/jose | jose}, then project it into a typed, verified claim set.
 *
 * The signature + the registered-claim checks (`iss`, `aud`, `exp`, `nbf`, token age) run inside
 * jose; this module adds the OIDC-specific checks jose does not do on its own — required `sub` / `iat`
 * / `exp`, the `nonce` binding, and the `azp` (authorized party) rule for multi-audience tokens — and
 * maps every jose failure onto a stable {@link OidcVerificationError} code.
 *
 * Keys are injectable: pass a key / JWK / `createRemoteJWKSet` resolver via `opts.key`, a `jwksUri`,
 * or `discover: true` to resolve the JWKS from the issuer's discovery document. Passing `opts.key`
 * lets tests verify entirely in-memory.
 */
import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
  type KeyLike,
} from 'jose';
import { discoverOidc } from './discovery';

/** Any key material jose's `jwtVerify` accepts: a key/secret, a JWK, or a dynamic key resolver. */
export type OidcVerifyKey = KeyLike | Uint8Array | JWK | JWTVerifyGetKey;

/** A stable classification of why ID-token verification failed. */
export type OidcVerificationErrorCode =
  | 'config'
  | 'invalid_token'
  | 'signature'
  | 'issuer'
  | 'audience'
  | 'expired'
  | 'issued_at'
  | 'not_before'
  | 'nonce'
  | 'azp'
  | 'claims';

/** The error thrown for any ID-token verification failure. `code` classifies the cause. */
export class OidcVerificationError extends Error {
  override readonly name = 'OidcVerificationError';
  readonly code: OidcVerificationErrorCode;
  constructor(code: OidcVerificationErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.code = code;
  }
}

/** RFC 7800 `cnf` confirmation claim. `jwk` (proof-of-possession public key) roots a PCA principal. */
export interface OidcConfirmation {
  /** A confirmation public key (e.g. an OKP Ed25519 JWK the human proved possession of at login). */
  jwk?: JWK;
  /** A JWK SHA-256 thumbprint confirmation (RFC 7638). */
  jkt?: string;
  [member: string]: unknown;
}

/**
 * A verified OIDC ID token's claims. `iss`, `sub`, `aud`, `iat` and `exp` are guaranteed present
 * (verification throws otherwise); the rest are the standard OIDC claims when the issuer sent them.
 */
export interface OidcIdTokenClaims extends JWTPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  iat: number;
  exp: number;
  nonce?: string;
  azp?: string;
  auth_time?: number;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  cnf?: OidcConfirmation;
}

export interface VerifyIdTokenOptions {
  /** Expected `iss` — the exact issuer identifier. Required. */
  issuer: string;
  /** Expected `aud` — your OIDC client id(s). Required. */
  audience: string | string[];
  /** When set, the token's `nonce` MUST be present and equal this value. */
  nonce?: string;
  /**
   * The authorized party (your client id) the token's `azp` MUST equal when `azp` is present.
   * Defaults to `audience` when that is a single string.
   */
  authorizedParty?: string;
  /** Clock skew tolerance in seconds (default 0). */
  clockToleranceSec?: number;
  /** When set, reject a token whose `iat` is older than this many seconds. */
  maxTokenAgeSec?: number;
  /** Allowed JWS `alg`s. Defaults to the asymmetric OIDC set (never symmetric, so a public JWKS cannot be confused with an HMAC secret). */
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

/** The asymmetric OIDC signing algorithms allowed by default (symmetric algs are excluded). */
export const DEFAULT_ID_TOKEN_ALGS: readonly string[] = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];

/** Verify an ID token and return its verified claims. Throws {@link OidcVerificationError}. */
export async function verifyIdToken(idToken: string, opts: VerifyIdTokenOptions): Promise<OidcIdTokenClaims> {
  if (typeof idToken !== 'string' || idToken.length === 0) {
    throw new OidcVerificationError('invalid_token', 'verifyIdToken: idToken must be a non-empty string');
  }
  if (opts === null || typeof opts !== 'object') {
    throw new OidcVerificationError('config', 'verifyIdToken: opts is required');
  }
  if (typeof opts.issuer !== 'string' || opts.issuer.length === 0) {
    throw new OidcVerificationError('config', 'verifyIdToken: opts.issuer is required');
  }
  if (typeof opts.audience !== 'string' && !Array.isArray(opts.audience)) {
    throw new OidcVerificationError('config', 'verifyIdToken: opts.audience is required');
  }

  const key = await resolveKey(opts);
  const verifyOptions: JWTVerifyOptions = {
    issuer: opts.issuer,
    audience: opts.audience,
    algorithms: [...(opts.algorithms ?? DEFAULT_ID_TOKEN_ALGS)],
    ...(opts.clockToleranceSec !== undefined ? { clockTolerance: opts.clockToleranceSec } : {}),
    ...(opts.maxTokenAgeSec !== undefined ? { maxTokenAge: opts.maxTokenAgeSec } : {}),
  };

  let payload: JWTPayload;
  try {
    // jose has distinct overloads for a static key vs. a dynamic resolver; branch so each is well-typed.
    const result =
      typeof key === 'function'
        ? await jwtVerify(idToken, key, verifyOptions)
        : await jwtVerify(idToken, key, verifyOptions);
    payload = result.payload;
  } catch (cause) {
    throw mapJoseError(cause);
  }

  return projectClaims(payload, opts);
}

async function resolveKey(opts: VerifyIdTokenOptions): Promise<OidcVerifyKey> {
  if (opts.key !== undefined) return opts.key;
  if (opts.jwksUri !== undefined) return createRemoteJWKSet(new URL(opts.jwksUri));
  if (opts.discover === true) {
    const meta = await discoverOidc(opts.issuer, opts.fetch !== undefined ? { fetch: opts.fetch } : {});
    return createRemoteJWKSet(new URL(meta.jwks_uri));
  }
  throw new OidcVerificationError('config', 'verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)');
}

function projectClaims(payload: JWTPayload, opts: VerifyIdTokenOptions): OidcIdTokenClaims {
  // jose already enforced iss/aud (and exp/nbf/age when present). Re-read defensively and enforce the
  // OIDC-required members jose does not mandate (sub, iat, exp).
  const iss = asString(payload.iss);
  if (iss === undefined) throw new OidcVerificationError('issuer', 'id token is missing the "iss" claim');
  const sub = asString(payload.sub);
  if (sub === undefined) throw new OidcVerificationError('claims', 'id token is missing the "sub" claim');
  const aud = payload.aud;
  if (aud === undefined) throw new OidcVerificationError('audience', 'id token is missing the "aud" claim');
  const iat = asFiniteNumber(payload.iat);
  if (iat === undefined) throw new OidcVerificationError('issued_at', 'id token is missing a numeric "iat" claim');
  const exp = asFiniteNumber(payload.exp);
  if (exp === undefined) throw new OidcVerificationError('expired', 'id token is missing a numeric "exp" claim');

  const nonce = asString(payload.nonce);
  const azp = asString(payload.azp);

  // nonce binding (OIDC Core §3.1.3.7): when the RP supplied a nonce it MUST round-trip exactly.
  if (opts.nonce !== undefined && nonce !== opts.nonce) {
    throw new OidcVerificationError(
      'nonce',
      nonce === undefined ? 'id token is missing the expected nonce' : 'id token nonce does not match the expected value',
    );
  }

  // azp (authorized party, OIDC Core §2 / §3.1.3.7): required when there is more than one audience,
  // and when present it MUST identify the relying party.
  const audList = Array.isArray(aud) ? aud : [aud];
  const expectedAzp = opts.authorizedParty ?? (typeof opts.audience === 'string' ? opts.audience : undefined);
  if (audList.length > 1 && azp === undefined) {
    throw new OidcVerificationError('azp', 'id token has multiple audiences but no azp (authorized party)');
  }
  if (azp !== undefined && expectedAzp !== undefined && azp !== expectedAzp) {
    throw new OidcVerificationError('azp', 'id token azp does not match the authorized party');
  }

  const cnf = asConfirmation(payload.cnf);
  const emailVerified = asBoolean(payload.email_verified);
  const authTime = asFiniteNumber(payload.auth_time);
  const email = asString(payload.email);
  const name = asString(payload.name);
  const preferredUsername = asString(payload.preferred_username);
  const givenName = asString(payload.given_name);
  const familyName = asString(payload.family_name);
  const picture = asString(payload.picture);

  return {
    iss,
    sub,
    aud,
    iat,
    exp,
    ...(nonce !== undefined ? { nonce } : {}),
    ...(azp !== undefined ? { azp } : {}),
    ...(authTime !== undefined ? { auth_time: authTime } : {}),
    ...(email !== undefined ? { email } : {}),
    ...(emailVerified !== undefined ? { email_verified: emailVerified } : {}),
    ...(name !== undefined ? { name } : {}),
    ...(preferredUsername !== undefined ? { preferred_username: preferredUsername } : {}),
    ...(givenName !== undefined ? { given_name: givenName } : {}),
    ...(familyName !== undefined ? { family_name: familyName } : {}),
    ...(picture !== undefined ? { picture } : {}),
    ...(cnf !== undefined ? { cnf } : {}),
  };
}

function mapJoseError(e: unknown): OidcVerificationError {
  if (e instanceof OidcVerificationError) return e;
  if (e instanceof joseErrors.JWTExpired) {
    // jose reuses JWTExpired for a maxTokenAge violation, flagging it with claim === 'iat'.
    if (e.claim === 'iat') return new OidcVerificationError('issued_at', 'id token is older than the maximum accepted age', { cause: e });
    return new OidcVerificationError('expired', 'id token has expired', { cause: e });
  }
  if (e instanceof joseErrors.JWTClaimValidationFailed) {
    const code: OidcVerificationErrorCode =
      e.claim === 'iss'
        ? 'issuer'
        : e.claim === 'aud'
          ? 'audience'
          : e.claim === 'iat'
            ? 'issued_at'
            : e.claim === 'nbf'
              ? 'not_before'
              : 'claims';
    return new OidcVerificationError(code, e.message, { cause: e });
  }
  if (e instanceof joseErrors.JWSSignatureVerificationFailed) {
    return new OidcVerificationError('signature', 'id token signature verification failed', { cause: e });
  }
  if (e instanceof joseErrors.JOSEError) {
    return new OidcVerificationError('invalid_token', e.message, { cause: e });
  }
  return new OidcVerificationError('invalid_token', 'id token verification failed', { cause: e });
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function asBoolean(v: unknown): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined;
}

function asFiniteNumber(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

function asConfirmation(v: unknown): OidcConfirmation | undefined {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return undefined;
  const rec: Record<string, unknown> = { ...v };
  const conf: OidcConfirmation = {};
  for (const [key, value] of Object.entries(rec)) conf[key] = value;
  return conf;
}
