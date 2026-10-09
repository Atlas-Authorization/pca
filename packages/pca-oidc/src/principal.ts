/**
 * Map a verified OIDC ID token onto a PCA principal descriptor — the root of a capability chain.
 *
 * In `@atlasauth/pca` a principal IS an Ed25519 public key (b64u): it is the `issuer` of the root
 * capability (`mintRoot` / `mintGrant`) and the `expectedRootIssuer` that `verifyChain` pins the chain
 * to. An OIDC human, by contrast, is named by `iss` + `sub`. This module bridges the two:
 *
 *   1. It derives a stable `principalId` (`<iss>#<sub>`) and a signed {@link OidcSubjectCaveat} that
 *      records WHICH human authorized the grant — embed it in the root envelope so the capability
 *      itself carries a verifiable, tamper-evident record of the authenticating subject.
 *   2. When the ID token proves possession of an Ed25519 key via a `cnf` OKP JWK (RFC 7800 /
 *      RFC 9449-style PoP), it surfaces that key as `principalPublic` — the exact b64u the core roots
 *      the chain at. The JWK's `x` member is already the base64url of the 32-byte raw public key, which
 *      is byte-for-byte the core's `principalPublic`, so the OIDC identity and the capability root are
 *      cryptographically the same key. A caller may also supply the bound key explicitly via
 *      `opts.principalPublic` (it must match the token's `cnf` key when both are present).
 */
import { base64url } from 'jose';
import type { Caveat } from '@atlasauth/pca';
import type { OidcConfirmation, OidcIdTokenClaims } from './verify';

/** The caveat type that records the authenticating OIDC subject inside a root grant. */
export const OIDC_SUBJECT_CAVEAT = 'oidc_subject';

/** A capability caveat binding a grant to the OIDC subject that authorized it. */
export interface OidcSubjectCaveat extends Caveat {
  type: typeof OIDC_SUBJECT_CAVEAT;
  /** OIDC issuer. */
  iss: string;
  /** OIDC subject (unique within the issuer). */
  sub: string;
}

/** A PCA principal descriptor derived from a verified OIDC ID token. */
export interface OidcPrincipal {
  /** OIDC issuer (`iss`). */
  iss: string;
  /** OIDC subject (`sub`) — unique within the issuer. */
  sub: string;
  /** Globally-unique, stable principal id across tokens: `<iss>#<sub>`. */
  principalId: string;
  /**
   * The b64u Ed25519 public key the capability chain roots at — present only when the ID token binds
   * one via a `cnf` OKP JWK (or the caller supplied it). Feed this to `mintRoot`/`mintGrant` as
   * `principalPublic` and to `verifyChain` as the `expectedRootIssuer`.
   */
  principalPublic?: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  preferredUsername?: string;
  /** Authentication time (`auth_time`, epoch seconds) when the token carried it. */
  authTime?: number;
  /** The caveat to embed in the root grant so the signed capability records the authenticating human. */
  subjectCaveat: OidcSubjectCaveat;
  /** The verified claims this descriptor was derived from. */
  claims: OidcIdTokenClaims;
}

export interface OidcPrincipalOptions {
  /**
   * The b64u Ed25519 public key to root the chain at, when the ID token does not carry a `cnf`
   * confirmation key (e.g. the human's device key bound out-of-band). When the token DOES carry a
   * `cnf` Ed25519 key, this must equal it, or an error is thrown.
   */
  principalPublic?: string;
}

/** Map verified OIDC claims onto a {@link OidcPrincipal}. Throws on missing `iss`/`sub` or a bad key. */
export function oidcPrincipal(claims: OidcIdTokenClaims, opts: OidcPrincipalOptions = {}): OidcPrincipal {
  const iss = claims.iss;
  const sub = claims.sub;
  if (typeof iss !== 'string' || iss.length === 0) {
    throw new TypeError('oidcPrincipal: claims.iss is required');
  }
  if (typeof sub !== 'string' || sub.length === 0) {
    throw new TypeError('oidcPrincipal: claims.sub is required');
  }

  const fromToken = ed25519PublicFromCnf(claims.cnf);
  let principalPublic = fromToken;
  if (opts.principalPublic !== undefined) {
    const provided = canonicalEd25519B64u(opts.principalPublic);
    if (provided === undefined) {
      throw new TypeError('oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key');
    }
    if (fromToken !== undefined && fromToken !== provided) {
      throw new Error('oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token');
    }
    principalPublic = provided;
  }

  const subjectCaveat: OidcSubjectCaveat = { type: OIDC_SUBJECT_CAVEAT, iss, sub };

  return {
    iss,
    sub,
    principalId: `${iss}#${sub}`,
    subjectCaveat,
    claims,
    ...(principalPublic !== undefined ? { principalPublic } : {}),
    ...(claims.email !== undefined ? { email: claims.email } : {}),
    ...(claims.email_verified !== undefined ? { emailVerified: claims.email_verified } : {}),
    ...(claims.name !== undefined ? { name: claims.name } : {}),
    ...(claims.preferred_username !== undefined ? { preferredUsername: claims.preferred_username } : {}),
    ...(claims.auth_time !== undefined ? { authTime: claims.auth_time } : {}),
  };
}

/** Narrowing guard for an {@link OidcSubjectCaveat} (e.g. when scanning a grant's caveats). */
export function isOidcSubjectCaveat(cv: unknown): cv is OidcSubjectCaveat {
  if (cv === null || typeof cv !== 'object') return false;
  const rec = cv as { type?: unknown; iss?: unknown; sub?: unknown };
  return (
    rec.type === OIDC_SUBJECT_CAVEAT &&
    typeof rec.iss === 'string' &&
    rec.iss.length > 0 &&
    typeof rec.sub === 'string' &&
    rec.sub.length > 0
  );
}

/** Extract the b64u Ed25519 public key from a `cnf` OKP JWK, or undefined if absent/not Ed25519. */
function ed25519PublicFromCnf(cnf: OidcConfirmation | undefined): string | undefined {
  if (cnf === undefined) return undefined;
  const jwk = cnf.jwk;
  if (jwk === undefined || jwk === null || typeof jwk !== 'object') return undefined;
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') return undefined;
  if (typeof jwk.x !== 'string') return undefined;
  return canonicalEd25519B64u(jwk.x);
}

/** Return `s` iff it is the canonical, unpadded base64url of exactly 32 bytes; else undefined. */
function canonicalEd25519B64u(s: string): string | undefined {
  if (typeof s !== 'string' || s.length === 0) return undefined;
  let raw: Uint8Array;
  try {
    raw = base64url.decode(s);
  } catch {
    return undefined;
  }
  if (raw.length !== 32) return undefined;
  // Reject non-canonical encodings (padding, alternate alphabet) so the key matches the core's b64u exactly.
  if (base64url.encode(raw) !== s) return undefined;
  return s;
}
