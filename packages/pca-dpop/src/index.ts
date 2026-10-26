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
import { assertCanonicalCompactJws } from '@atlasauth/pca';
import { type PCActn, b64u, sha256 } from '@atlasauth/pca';
import { createHmac, timingSafeEqual } from 'node:crypto';

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

/**
 * A durable, atomic `jti` replay store for DPoP proofs. `addIfAbsent` MUST be atomic: of N concurrent calls with the
 * same key exactly one returns `true`. The key passed in is `<jkt>.<jti>`, so one key holder cannot burn another's `jti`.
 * An entry may be dropped once `nowSec >= expiresAtSec`. Back it with a shared store (SQL unique key, Redis `SET NX EX`);
 * check it with {@link runDpopReplayStoreConformance}.
 */
export interface DpopReplayStore {
  addIfAbsent(key: string, expiresAtSec: number, nowSec: number): boolean | Promise<boolean>;
}

/** Single-process test double / small deployments only: state is lost on restart and not shared across processes. */
export function createInMemoryDpopReplayStore(): DpopReplayStore {
  const seen = new Map<string, number>();
  return {
    addIfAbsent(key, expiresAtSec, nowSec) {
      for (const [k, exp] of seen) if (nowSec >= exp) seen.delete(k);
      if (seen.has(key)) return false;
      seen.set(key, expiresAtSec);
      return true;
    },
  };
}

/** Conformance suite for a {@link DpopReplayStore}: returns the failed checks (empty = conformant). `make` returns a FRESH empty store. */
export async function runDpopReplayStoreConformance(make: () => DpopReplayStore): Promise<string[]> {
  const failures: string[] = [];
  const check = (ok: boolean, name: string): void => {
    if (!ok) failures.push(name);
  };
  const s = make();
  check((await s.addIfAbsent('a', 200, 100)) === true, 'first sight of a key returns true');
  check((await s.addIfAbsent('a', 200, 101)) === false, 'second sight of the same key returns false');
  check((await s.addIfAbsent('b', 200, 101)) === true, 'a different key is independent');
  check((await s.addIfAbsent('a', 200, 199)) === false, 'still seen one second before expiry');
  const t = make();
  await t.addIfAbsent('c', 200, 100);
  check((await t.addIfAbsent('c', 400, 200)) === true, 'an expired entry may be added again (nowSec >= expiresAtSec)');
  const u = make();
  const wins = (await Promise.all(Array.from({ length: 16 }, () => u.addIfAbsent('race', 200, 100)))).filter(Boolean).length;
  check(wins === 1, `16 concurrent adds of one key: exactly one wins (got ${wins})`);
  return failures;
}

/** Issues and checks stateless server DPoP nonces (RFC 9449 §8/§9): a timestamp MACed with a server secret. */
export interface DpopNonceIssuer {
  /** A fresh nonce to send in a `DPoP-Nonce` header. */
  issue(nowSec?: number): string;
  /** True only for a nonce this issuer minted that is at most `ttlSec` old (and not from the future). */
  check(nonce: unknown, nowSec?: number): boolean;
}

/** Create a {@link DpopNonceIssuer}. `secret` must be at least 32 bytes; `ttlSec` is the nonce lifetime (default 300). */
export function createDpopNonceIssuer(opts: { secret: Uint8Array; ttlSec?: number }): DpopNonceIssuer {
  if (!(opts?.secret instanceof Uint8Array) || opts.secret.length < 32) {
    throw new DpopVerificationError('misconfigured', 'nonce secret must be at least 32 bytes');
  }
  const ttl = opts.ttlSec ?? 300;
  if (!Number.isFinite(ttl) || ttl <= 0) throw new DpopVerificationError('misconfigured', 'nonce ttlSec must be positive');
  const mac = (ts: Buffer): Buffer => createHmac('sha256', opts.secret).update('dpop-nonce\0').update(ts).digest().subarray(0, 16);
  return {
    issue(nowSec = Math.floor(Date.now() / 1000)) {
      const ts = Buffer.alloc(8);
      ts.writeBigUInt64BE(BigInt(nowSec));
      return Buffer.concat([ts, mac(ts)]).toString('base64url');
    },
    check(nonce, nowSec = Math.floor(Date.now() / 1000)) {
      if (typeof nonce !== 'string') return false;
      const raw = Buffer.from(nonce, 'base64url');
      if (raw.length !== 24 || raw.toString('base64url') !== nonce) return false;
      const ts = raw.subarray(0, 8);
      if (!timingSafeEqual(raw.subarray(8), mac(ts))) return false;
      const issued = Number(ts.readBigUInt64BE());
      return issued <= nowSec + DPOP_CLOCK_SKEW_SEC && nowSec - issued <= ttl;
    },
  };
}

/** Largest accepted proof string (bytes). A real proof is well under 2 KiB; RSA keys are the largest. */
export const DPOP_MAX_PROOF_BYTES = 8192;

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
  /** Durable atomic replay store (see {@link DpopReplayStore}); keyed by `<jkt>.<jti>`. Preferred over `seenJti`. */
  replayStore?: DpopReplayStore;
  /**
   * When true, a verification with neither `replayStore` nor `seenJti` is refused (`replay_store_required`). Set it on
   * every resource server: the verifier cannot detect replay without your store. (Becomes the default in a future major.)
   */
  requireReplayStore?: boolean;
  /** Server nonce issuer: when given, the proof MUST carry a nonce this issuer minted and has not expired. */
  nonceIssuer?: DpopNonceIssuer;
  /** Override "now" (epoch seconds) — for tests / fixed clocks. */
  nowSec?: number;
  /** If given, the proof MUST carry exactly this server-issued `nonce` (RFC 9449 §8/§9). */
  expectedNonce?: string;
  /** If given, the proof MUST carry `ath` = base64url(SHA-256(accessToken)) (RFC 9449 §4.2/§7.1). */
  accessToken?: string;
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
  if (opts.requireReplayStore === true && opts.replayStore === undefined && opts.seenJti === undefined) {
    throw new DpopVerificationError('replay_store_required', 'no replay store configured; replay cannot be detected');
  }
  if (typeof proof !== 'string' || proof.length > DPOP_MAX_PROOF_BYTES) {
    throw new DpopVerificationError('oversize', `proof is not a string or exceeds ${DPOP_MAX_PROOF_BYTES} bytes`);
  }
  // Reject a missing / non-public / absent-`jwk` header before trusting the signature.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    // Canonical-spelling gate BEFORE jose: a DPoP proof string has exactly one accepted form (jti/replay keys).
    assertCanonicalCompactJws(proof);
    header = decodeProtectedHeader(proof);
  } catch (e) {
    throw new DpopVerificationError('malformed', `not a JWS: ${errMsg(e)}`);
  }
  if (header.typ !== DPOP_JWT_TYP) {
    throw new DpopVerificationError('typ', `header typ must be '${DPOP_JWT_TYP}', got '${String(header.typ)}'`);
  }
  if (header.jwk === undefined) throw new DpopVerificationError('no_jwk', 'proof header has no embedded jwk');
  // RFC 9449 §4.2: the header jwk MUST NOT contain a private key.
  const hj: unknown = header.jwk;
  if (typeof hj === 'object' && hj !== null && ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].some((m) => m in hj)) {
    throw new DpopVerificationError('private_jwk', 'proof header jwk contains private key material');
  }

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

  // Server nonce (RFC 9449 §8/§9): when required, an absent or different nonce is rejected.
  if (opts.expectedNonce !== undefined && payload.nonce !== opts.expectedNonce) {
    throw new DpopVerificationError('nonce', 'proof nonce is missing or does not match the expected nonce');
  }

  if (opts.nonceIssuer !== undefined && !opts.nonceIssuer.check(payload.nonce, now)) {
    throw new DpopVerificationError('nonce', 'proof nonce is missing, forged or expired');
  }

  // Access-token binding (RFC 9449 §4.2 / §7.1): when presented with an access token, `ath` must match.
  if (opts.accessToken !== undefined && payload.ath !== athFor(opts.accessToken)) {
    throw new DpopVerificationError('ath', 'proof ath is missing or does not match the access token');
  }

  // Replay: reject a reused jti, then record this one.
  if (opts.seenJti !== undefined) {
    if (opts.seenJti.has(jti)) throw new DpopVerificationError('jti_replay', `jti '${jti}' has already been seen`);
    opts.seenJti.add(jti);
  }

  if (opts.replayStore !== undefined) {
    let fresh: boolean;
    try {
      fresh = await opts.replayStore.addIfAbsent(`${jkt}.${jti}`, iat + opts.maxAgeSec + DPOP_CLOCK_SKEW_SEC, now);
    } catch (e) {
      throw new DpopVerificationError('replay_store_error', `replay store failed: ${errMsg(e)}`);
    }
    if (fresh !== true) throw new DpopVerificationError('jti_replay', `jti '${jti}' has already been seen`);
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
  opts: {
    method: string;
    url: string;
    maxAgeSec?: number;
    seenJti?: JtiSeenSet;
    replayStore?: DpopReplayStore;
    requireReplayStore?: boolean;
    nonceIssuer?: DpopNonceIssuer;
    nowSec?: number;
    expectedNonce?: string;
    accessToken?: string;
  },
): Promise<DpopVerifyResult> {
  const { jkt } = await bindPcaToDpop(p);
  return verifyDpopProof(dpopProof, {
    method: opts.method,
    url: opts.url,
    maxAgeSec: opts.maxAgeSec ?? DPOP_DEFAULT_MAX_AGE_SEC,
    expectedJkt: jkt,
    ...(opts.seenJti !== undefined ? { seenJti: opts.seenJti } : {}),
    ...(opts.replayStore !== undefined ? { replayStore: opts.replayStore } : {}),
    ...(opts.requireReplayStore !== undefined ? { requireReplayStore: opts.requireReplayStore } : {}),
    ...(opts.nonceIssuer !== undefined ? { nonceIssuer: opts.nonceIssuer } : {}),
    ...(opts.nowSec !== undefined ? { nowSec: opts.nowSec } : {}),
    ...(opts.expectedNonce !== undefined ? { expectedNonce: opts.expectedNonce } : {}),
    ...(opts.accessToken !== undefined ? { accessToken: opts.accessToken } : {}),
  });
}
