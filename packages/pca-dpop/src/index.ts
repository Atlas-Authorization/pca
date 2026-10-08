/**
 * `@atlasauth/pca-dpop` — sender-constrained proof-of-possession for PCA.
 *
 * Two PoP mechanisms, bound to a PCActn's REAL holder key so an action is tied to the holder it was
 * delegated to and interops with OAuth proof-of-possession:
 *
 *  - **RFC 9449 DPoP**: a holder-key-signed `dpop+jwt` proof over the HTTP method + target URI. The
 *    public key rides in the proof header (`jwk`); its RFC 7638 thumbprint is the `jkt`.
 *  - **RFC 8705 mTLS**: an `x5t#S256` certificate-thumbprint confirmation for the mutual-TLS channel.
 *
 * The PCActn's bound holder key is the LEAF of its capability chain — `cap_chain[last].holder` — a
 * base64url (no-pad) Ed25519 public key (see `@atlasauth/pca` `Capability.holder`, which the core leaf
 * signature is verified under). That raw key is exactly an OKP/Ed25519 JWK with `x = holder`, so a DPoP
 * proof signed by the holder key, embedding that OKP JWK, has a `jkt` equal to the PCActn's binding —
 * {@link bindPcaToDpop} computes that binding and {@link assertPcaDpop} enforces it against a proof.
 */

import { EmbeddedJWK, SignJWT, calculateJwkThumbprint, decodeProtectedHeader, jwtVerify } from 'jose';
import type { JWK, JWTPayload, KeyLike } from 'jose';
import { type PCActn, b64u, sha256 } from '@atlasauth/pca';

// ---- constants ---------------------------------------------------------------------------------

/** JWS algorithms a DPoP proof may use: asymmetric only, never `none` or a MAC (RFC 9449 §4.2). */
export const DPOP_ALLOWED_ALGS = ['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256', 'RS256'] as const;
export type DpopAlg = (typeof DPOP_ALLOWED_ALGS)[number];

/** DPoP proof type header (`typ`), RFC 9449 §4.2. */
export const DPOP_JWT_TYP = 'dpop+jwt';

/** Default accepted proof age (seconds) when a caller does not pass `maxAgeSec`. */
export const DPOP_DEFAULT_MAX_AGE_SEC = 300;

/** Clock-skew allowance (seconds) for a proof whose `iat` is slightly ahead of the verifier. */
export const DPOP_CLOCK_SKEW_SEC = 5;

// ---- errors ------------------------------------------------------------------------------------

/** A DPoP proof (or PCActn↔DPoP binding) that failed to verify. `code` names the specific check. */
export class DpopVerificationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'DpopVerificationError';
    this.code = code;
  }
}

// ---- types -------------------------------------------------------------------------------------

/** The claim set carried by a DPoP proof JWT (RFC 9449 §4.2), with the always-present claims typed. */
export interface DpopClaims extends JWTPayload {
  /** HTTP method of the request the proof is for (uppercase). */
  htm: string;
  /** HTTP target URI, query + fragment stripped (RFC 9449 §4.3). */
  htu: string;
  /** Issued-at, epoch SECONDS. */
  iat: number;
  /** Unique proof id (replay token). */
  jti: string;
  /** Optional server-provided DPoP nonce. */
  nonce?: string;
  /** Optional access-token hash: base64url(sha256(access token)). */
  ath?: string;
}

/** A replay store for `jti` values. A plain `Set<string>` satisfies this. */
export interface JtiSeenSet {
  has(jti: string): boolean;
  add(jti: string): unknown;
}

export interface CreateDpopProofInput {
  /** HTTP method (case-insensitive in; stored uppercased as `htm`). */
  method: string;
  /** Full request URL; `htu` is this with query + fragment removed. */
  url: string;
  /** The holder's PRIVATE key that signs the proof. */
  privateKey: KeyLike | Uint8Array | JWK;
  /** The holder's PUBLIC JWK, embedded in the proof header (`jwk`); drives the `alg`. */
  publicJwk: JWK;
  /** Optional server-issued DPoP nonce. */
  nonce?: string;
  /** Optional access-token hash (see {@link athFor}). */
  ath?: string;
  /** Override the issued-at (epoch seconds); default `now`. */
  iat?: number;
  /** Override the proof id; default a random UUID. */
  jti?: string;
}

export interface VerifyDpopProofOptions {
  method: string;
  url: string;
  /** Maximum accepted proof age in seconds (from `iat` to now). */
  maxAgeSec: number;
  /** If given, the embedded key's RFC 7638 thumbprint MUST equal this `jkt`. */
  expectedJkt?: string;
  /** If given, a repeated `jti` is rejected and a fresh one is recorded. */
  seenJti?: JtiSeenSet;
  /** Override "now" (epoch seconds) — for tests / fixed clocks. */
  nowSec?: number;
}

export interface DpopVerifyResult {
  /** The verified, type-checked DPoP claims. */
  claims: DpopClaims;
  /** The public JWK the proof was signed with (from the header). */
  jwk: JWK;
  /** RFC 7638 SHA-256 thumbprint of {@link DpopVerifyResult.jwk}. */
  jkt: string;
}

/** RFC 8705 §3.1 confirmation: the client certificate's SHA-256 thumbprint. */
export interface MtlsCnf {
  'x5t#S256': string;
}

// ---- helpers -----------------------------------------------------------------------------------

/** RFC 7638 JWK SHA-256 thumbprint (base64url), via jose. */
export function jwkThumbprint(jwk: JWK, digest: 'sha256' | 'sha384' | 'sha512' = 'sha256'): Promise<string> {
  return calculateJwkThumbprint(jwk, digest);
}

/** The JWS `alg` for a key, derived from its JWK `kty`/`crv`. Throws for unsupported/MAC keys. */
export function dpopAlgForJwk(jwk: JWK): DpopAlg {
  switch (jwk.kty) {
    case 'OKP':
      if (jwk.crv === 'Ed25519' || jwk.crv === 'Ed448') return 'EdDSA';
      throw new DpopVerificationError('unsupported_key', `unsupported OKP curve '${String(jwk.crv)}' for DPoP`);
    case 'EC':
      if (jwk.crv === 'P-256') return 'ES256';
      if (jwk.crv === 'P-384') return 'ES384';
      if (jwk.crv === 'P-521') return 'ES512';
      throw new DpopVerificationError('unsupported_key', `unsupported EC curve '${String(jwk.crv)}' for DPoP`);
    case 'RSA':
      return 'PS256';
    default:
      throw new DpopVerificationError('unsupported_key', `unsupported key type '${String(jwk.kty)}' for DPoP`);
  }
}

/** Project a JWK down to its PUBLIC members, so no private material is ever embedded in a proof. */
function toPublicJwk(jwk: JWK): JWK {
  const pub: JWK = { kty: jwk.kty };
  if (jwk.crv !== undefined) pub.crv = jwk.crv;
  if (jwk.x !== undefined) pub.x = jwk.x;
  if (jwk.y !== undefined) pub.y = jwk.y;
  if (jwk.n !== undefined) pub.n = jwk.n;
  if (jwk.e !== undefined) pub.e = jwk.e;
  return pub;
}

/** The HTTP target URI with query + fragment stripped (RFC 9449 §4.3), e.g. `https://host:443/path`. */
export function normalizeHtu(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host}${u.pathname}`;
}

/** The DPoP access-token hash `ath`: base64url(SHA-256(access token)), RFC 9449 §4.2. */
export function athFor(accessToken: string): string {
  return b64u(sha256(new TextEncoder().encode(accessToken)));
}

function freshJti(): string {
  return globalThis.crypto.randomUUID();
}

/** Message of a caught `unknown` without asserting its type. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---- DPoP proof: create / verify --------------------------------------------------------------

/** Build and sign a DPoP proof JWT (`typ: dpop+jwt`, embedded public `jwk`, claims htm/htu/iat/jti …). */
export async function createDpopProof(input: CreateDpopProofInput): Promise<string> {
  const publicJwk = toPublicJwk(input.publicJwk);
  const alg = dpopAlgForJwk(publicJwk);
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const claims: DpopClaims = {
    htm: input.method.toUpperCase(),
    htu: normalizeHtu(input.url),
    iat,
    jti: input.jti ?? freshJti(),
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
    ...(input.ath !== undefined ? { ath: input.ath } : {}),
  };
  return new SignJWT(claims).setProtectedHeader({ typ: DPOP_JWT_TYP, alg, jwk: publicJwk }).sign(input.privateKey);
}

/**
 * Verify a DPoP proof: signature under the embedded `jwk`, `typ`, that `htm`/`htu` match the request,
 * `iat` freshness, optional `jkt` match and optional `jti` replay rejection. Throws
 * {@link DpopVerificationError} on any failure; returns the verified claims + key thumbprint on success.
 */
export async function verifyDpopProof(proof: string, opts: VerifyDpopProofOptions): Promise<DpopVerifyResult> {
  // Reject a missing / non-public / absent-`jwk` header before trusting the signature.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch (e) {
    throw new DpopVerificationError('malformed', `not a JWS: ${errMsg(e)}`);
  }
  if (header.typ !== DPOP_JWT_TYP) {
    throw new DpopVerificationError('typ', `header typ must be '${DPOP_JWT_TYP}', got '${String(header.typ)}'`);
  }
  if (header.jwk === undefined) throw new DpopVerificationError('no_jwk', 'proof header has no embedded jwk');

  // Signature: EmbeddedJWK verifies under the header `jwk`; `algorithms` pins the asymmetric suite.
  let payload: JWTPayload;
  let jwk: JWK;
  try {
    const res = await jwtVerify(proof, EmbeddedJWK, { algorithms: [...DPOP_ALLOWED_ALGS], typ: DPOP_JWT_TYP });
    payload = res.payload;
    const resolved = res.protectedHeader.jwk;
    if (resolved === undefined) throw new DpopVerificationError('no_jwk', 'verified header has no embedded jwk');
    jwk = resolved;
  } catch (e) {
    if (e instanceof DpopVerificationError) throw e;
    throw new DpopVerificationError('signature', `DPoP signature did not verify: ${errMsg(e)}`);
  }

  // Claim shapes.
  const { htm, htu, iat, jti } = payload;
  if (typeof htm !== 'string') throw new DpopVerificationError('htm', 'htm is missing or not a string');
  if (typeof htu !== 'string') throw new DpopVerificationError('htu', 'htu is missing or not a string');
  if (typeof iat !== 'number' || !Number.isFinite(iat)) throw new DpopVerificationError('iat', 'iat is missing or not a number');
  if (typeof jti !== 'string' || jti.length === 0) throw new DpopVerificationError('jti', 'jti is missing or empty');

  // htm / htu bind the proof to this exact request.
  if (htm !== opts.method.toUpperCase()) throw new DpopVerificationError('htm', `htm '${htm}' does not match request method`);
  if (htu !== normalizeHtu(opts.url)) throw new DpopVerificationError('htu', `htu '${htu}' does not match request URL`);

  // Freshness.
  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  if (iat > now + DPOP_CLOCK_SKEW_SEC) throw new DpopVerificationError('iat_future', 'iat is in the future');
  if (now - iat > opts.maxAgeSec) throw new DpopVerificationError('iat_stale', `proof is older than ${opts.maxAgeSec}s`);

  // Key binding.
  const jkt = await jwkThumbprint(jwk);
  if (opts.expectedJkt !== undefined && jkt !== opts.expectedJkt) {
    throw new DpopVerificationError('jkt', 'embedded key thumbprint does not match expected jkt');
  }

  // Replay: reject a reused jti, then record this one.
  if (opts.seenJti !== undefined) {
    if (opts.seenJti.has(jti)) throw new DpopVerificationError('jti_replay', `jti '${jti}' has already been seen`);
    opts.seenJti.add(jti);
  }

  const nonce = typeof payload.nonce === 'string' ? payload.nonce : undefined;
  const ath = typeof payload.ath === 'string' ? payload.ath : undefined;
  const claims: DpopClaims = {
    ...payload,
    htm,
    htu,
    iat,
    jti,
    ...(nonce !== undefined ? { nonce } : {}),
    ...(ath !== undefined ? { ath } : {}),
  };
  return { claims, jwk, jkt };
}

// ---- RFC 8705 mTLS confirmation ---------------------------------------------------------------

/** PEM certificate body → DER bytes (base64, standard alphabet). */
function pemToDer(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
  const body = (match?.[1] ?? pem).replace(/[^A-Za-z0-9+/=]/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

/**
 * RFC 8705 §3.1 `cnf` confirmation for a mutual-TLS client certificate: `{ "x5t#S256": b64u(sha256(DER)) }`.
 * Accepts the certificate as DER bytes or as a PEM string.
 */
export function mtlsCnf(certDerOrPem: Uint8Array | string): MtlsCnf {
  const der = typeof certDerOrPem === 'string' ? pemToDer(certDerOrPem) : certDerOrPem;
  return { 'x5t#S256': b64u(sha256(der)) };
}

// ---- PCActn ↔ DPoP binding --------------------------------------------------------------------

/**
 * The OKP/Ed25519 public JWK of the PCActn's bound holder key — the LEAF of its capability chain
 * (`cap_chain[last].holder`, a base64url Ed25519 public key). Throws if the chain is empty.
 */
export function leafHolderJwk(p: PCActn): JWK {
  const chain = p.cap_chain;
  const leaf = chain[chain.length - 1];
  if (leaf === undefined) throw new DpopVerificationError('no_leaf', 'PCActn capability chain is empty; no bound holder key');
  return { kty: 'OKP', crv: 'Ed25519', x: leaf.holder };
}

/** The `cnf: { jkt }` confirmation for a PCActn's bound holder key (RFC 9449 §6 jkt binding). */
export async function bindPcaToDpop(p: PCActn): Promise<{ jkt: string }> {
  return { jkt: await jwkThumbprint(leafHolderJwk(p)) };
}

/**
 * Confirm a presented DPoP proof is held by the PCActn's bound holder key AND is for the given HTTP
 * target: verifies the proof with `expectedJkt` fixed to the PCActn's leaf-holder thumbprint. Throws
 * {@link DpopVerificationError} on any mismatch; returns the verified result on success.
 */
export async function assertPcaDpop(
  p: PCActn,
  dpopProof: string,
  opts: { method: string; url: string; maxAgeSec?: number; seenJti?: JtiSeenSet; nowSec?: number },
): Promise<DpopVerifyResult> {
  const { jkt } = await bindPcaToDpop(p);
  return verifyDpopProof(dpopProof, {
    method: opts.method,
    url: opts.url,
    maxAgeSec: opts.maxAgeSec ?? DPOP_DEFAULT_MAX_AGE_SEC,
    expectedJkt: jkt,
    ...(opts.seenJti !== undefined ? { seenJti: opts.seenJti } : {}),
    ...(opts.nowSec !== undefined ? { nowSec: opts.nowSec } : {}),
  });
}
