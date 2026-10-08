/**
 * @atlasauth/pca-spiffe — bridge PCA agent identity with SPIFFE/SPIRE workload identity.
 *
 * A SPIFFE workload (a non-human, attested identity) is exactly the kind of principal PCA calls an
 * *agent holder*: in the core, a capability is bound to a `holder` — a base64url Ed25519 public key
 * (`Capability.holder`, the `cnf` key that signs PCActns; see @atlasauth/pca `capability.ts`). This
 * package parses/verifies SPIFFE SVIDs (JWT-SVID and X.509-SVID), validates SPIFFE IDs per the
 * SPIFFE-ID standard, and maps a SPIFFE ID to/from that core holder identity so a SPIRE-attested
 * workload can be the holder of a PCA capability chain.
 */

import { X509Certificate } from 'node:crypto';
import {
  jwtVerify,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
  type KeyLike,
} from 'jose';
// Integrate with the REAL core identity primitives — the holder is an Ed25519 public key, encoded
// and validated exactly as the core does it.
import { b64u, decodeB64uStrict } from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------------

/** Error codes raised by this package. Stable identifiers for programmatic handling. */
export type SpiffeErrorCode =
  | 'malformed_spiffe_id'
  | 'empty_trust_domain'
  | 'trust_domain_too_long'
  | 'invalid_trust_domain'
  | 'invalid_path'
  | 'id_too_long'
  | 'missing_audience'
  | 'missing_exp'
  | 'invalid_subject'
  | 'trust_domain_mismatch'
  | 'no_uri_san'
  | 'multiple_uri_san'
  | 'invalid_holder_key';

/** A validation/parse failure with a stable `code`. */
export class SpiffeError extends Error {
  readonly code: SpiffeErrorCode;
  constructor(code: SpiffeErrorCode, message: string) {
    super(message);
    this.name = 'SpiffeError';
    this.code = code;
  }
}

// ---------------------------------------------------------------------------------------------------
// SPIFFE ID parsing  (https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md)
// ---------------------------------------------------------------------------------------------------

/** A parsed, validated SPIFFE ID. */
export interface SpiffeId {
  /** Canonical `spiffe://<trust-domain><path>` form. */
  readonly id: string;
  /** Trust domain (the authority), always lowercase, never empty. */
  readonly trustDomain: string;
  /** Workload path, including its leading `/`; empty string for a bare trust-domain ID. */
  readonly path: string;
}

const SPIFFE_SCHEME = 'spiffe://';
/** SPIFFE IDs are capped at 2048 bytes. */
const MAX_SPIFFE_ID_LENGTH = 2048;
/** Trust domains are capped at 255 bytes. */
const MAX_TRUST_DOMAIN_LENGTH = 255;
/** Trust domain charset: lowercase letters, digits, dot, dash, underscore. */
const TRUST_DOMAIN_RE = /^[a-z0-9._-]+$/;
/** Path-segment charset: letters, digits, dot, dash, underscore. */
const PATH_SEGMENT_RE = /^[a-zA-Z0-9._-]+$/;

/**
 * Validate and parse a SPIFFE ID of the form `spiffe://<trust-domain>/<path>`.
 *
 * Enforces the SPIFFE-ID standard: lowercase `spiffe://` scheme; a non-empty trust domain drawn from
 * `[a-z0-9._-]` (<= 255 bytes); path segments drawn from `[a-zA-Z0-9._-]` with no empty segment, no
 * `.`/`..` dot-segment and no trailing slash; total length <= 2048 bytes. Throws {@link SpiffeError}
 * on anything malformed. A bare `spiffe://trust-domain` (no path) is valid.
 */
export function parseSpiffeId(s: string): SpiffeId {
  if (typeof s !== 'string' || s.length === 0) {
    throw new SpiffeError('malformed_spiffe_id', 'SPIFFE ID must be a non-empty string');
  }
  if (s.length > MAX_SPIFFE_ID_LENGTH) {
    throw new SpiffeError('id_too_long', `SPIFFE ID exceeds ${MAX_SPIFFE_ID_LENGTH} bytes`);
  }
  if (!s.startsWith(SPIFFE_SCHEME)) {
    throw new SpiffeError('malformed_spiffe_id', `SPIFFE ID must begin with "${SPIFFE_SCHEME}"`);
  }

  const rest = s.slice(SPIFFE_SCHEME.length);
  const slash = rest.indexOf('/');
  const trustDomain = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? '' : rest.slice(slash); // keeps the leading '/'

  if (trustDomain.length === 0) {
    throw new SpiffeError('empty_trust_domain', 'SPIFFE ID has an empty trust domain');
  }
  if (trustDomain.length > MAX_TRUST_DOMAIN_LENGTH) {
    throw new SpiffeError('trust_domain_too_long', `trust domain exceeds ${MAX_TRUST_DOMAIN_LENGTH} bytes`);
  }
  if (!TRUST_DOMAIN_RE.test(trustDomain)) {
    throw new SpiffeError(
      'invalid_trust_domain',
      `trust domain "${trustDomain}" must be lowercase and contain only [a-z0-9._-]`,
    );
  }

  if (path !== '') {
    if (path.endsWith('/')) {
      throw new SpiffeError('invalid_path', 'SPIFFE ID path must not end with a trailing slash');
    }
    // path starts with '/', so split()[0] is '' — skip it and validate each real segment.
    const segments = path.split('/');
    for (let i = 1; i < segments.length; i++) {
      const seg = segments[i];
      if (seg === undefined || seg.length === 0) {
        throw new SpiffeError('invalid_path', 'SPIFFE ID path must not contain an empty segment');
      }
      if (seg === '.' || seg === '..') {
        throw new SpiffeError('invalid_path', 'SPIFFE ID path must not contain a "." or ".." segment');
      }
      if (!PATH_SEGMENT_RE.test(seg)) {
        throw new SpiffeError('invalid_path', `SPIFFE ID path segment "${seg}" contains an invalid character`);
      }
    }
  }

  return { id: SPIFFE_SCHEME + trustDomain + path, trustDomain, path };
}

/** Narrow a `string | SpiffeId` to a validated {@link SpiffeId}. */
function asSpiffeId(id: string | SpiffeId): SpiffeId {
  return typeof id === 'string' ? parseSpiffeId(id) : parseSpiffeId(id.id);
}

// ---------------------------------------------------------------------------------------------------
// JWT-SVID verification
// ---------------------------------------------------------------------------------------------------

/**
 * Key source for {@link verifyJwtSvid}. Injectable so tests can mint + verify against a local key,
 * and production can pass a JWKS resolver backed by the trust bundle:
 *   - a `KeyLike` / `Uint8Array` / `JWK` — a single verification key, or
 *   - a `JWTVerifyGetKey` — a dynamic resolver (e.g. jose `createLocalJWKSet` / `createRemoteJWKSet`).
 */
export type JwtSvidKeySource = KeyLike | Uint8Array | JWK | JWTVerifyGetKey;

/** Options for {@link verifyJwtSvid}. */
export interface VerifyJwtSvidOptions {
  /** REQUIRED. The audience(s) the SVID must be addressed to — a JWT-SVID MUST carry an `aud`. */
  audience: string | string[];
  /** Verification key or JWKS resolver (see {@link JwtSvidKeySource}). */
  key: JwtSvidKeySource;
  /** If set, the subject's trust domain MUST equal this value. */
  trustDomain?: string;
  /** Override the current time (for testing `exp`/`nbf`). */
  currentDate?: Date;
  /** Permitted signature algorithms (defaults to jose's set; `none` is always rejected). */
  algorithms?: string[];
  /** Clock skew tolerance, e.g. `"30s"` or a number of seconds. */
  clockTolerance?: string | number;
}

/** A verified JWT-SVID. */
export interface JwtSvid {
  /** The subject SPIFFE ID (`sub`), parsed + validated. */
  readonly spiffeId: SpiffeId;
  /** The full, verified JWT claim set. */
  readonly claims: JWTPayload;
  /** The audience(s) the SVID is addressed to. */
  readonly audience: readonly string[];
  /** Expiry (`exp`) as a UNIX timestamp in seconds. */
  readonly expiresAt: number;
}

/**
 * Verify a JWT-SVID with `jose`. Verifies the JWS signature against the injected key/JWKS, requires
 * and matches the `aud`, enforces `exp` (and `nbf` when present), and requires `sub` to be a valid
 * SPIFFE ID. Optionally pins the subject's trust domain. Resolves to the {@link JwtSvid}; rejects
 * (jose error or {@link SpiffeError}) on any failure.
 */
export async function verifyJwtSvid(token: string, opts: VerifyJwtSvidOptions): Promise<JwtSvid> {
  const audience = opts.audience;
  const audienceList = typeof audience === 'string' ? [audience] : audience;
  if (audienceList.length === 0 || audienceList.some((a) => a.length === 0)) {
    throw new SpiffeError('missing_audience', 'verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)');
  }

  const joseOpts = {
    audience,
    ...(opts.currentDate !== undefined ? { currentDate: opts.currentDate } : {}),
    ...(opts.algorithms !== undefined ? { algorithms: opts.algorithms } : {}),
    ...(opts.clockTolerance !== undefined ? { clockTolerance: opts.clockTolerance } : {}),
  };

  const { payload } =
    typeof opts.key === 'function'
      ? await jwtVerify(token, opts.key, joseOpts)
      : await jwtVerify(token, opts.key, joseOpts);

  if (typeof payload.exp !== 'number') {
    throw new SpiffeError('missing_exp', 'JWT-SVID is missing the required "exp" claim');
  }
  if (typeof payload.sub !== 'string') {
    throw new SpiffeError('invalid_subject', 'JWT-SVID "sub" must be a string SPIFFE ID');
  }

  let spiffeId: SpiffeId;
  try {
    spiffeId = parseSpiffeId(payload.sub);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new SpiffeError('invalid_subject', `JWT-SVID "sub" is not a valid SPIFFE ID: ${detail}`);
  }

  if (opts.trustDomain !== undefined && spiffeId.trustDomain !== opts.trustDomain) {
    throw new SpiffeError(
      'trust_domain_mismatch',
      `JWT-SVID trust domain "${spiffeId.trustDomain}" does not match expected "${opts.trustDomain}"`,
    );
  }

  const aud = payload.aud;
  const resolvedAudience = aud === undefined ? [] : typeof aud === 'string' ? [aud] : aud;

  return { spiffeId, claims: payload, audience: resolvedAudience, expiresAt: payload.exp };
}

// ---------------------------------------------------------------------------------------------------
// X.509-SVID parsing
// ---------------------------------------------------------------------------------------------------

/** A parsed X.509-SVID. */
export interface X509Svid {
  /** The SPIFFE ID extracted from the single URI SAN. */
  readonly spiffeId: SpiffeId;
  /** The parsed leaf certificate. */
  readonly certificate: X509Certificate;
  /** base64url SPKI DER of the certificate's subject public key. */
  readonly publicKeyDer: string;
}

const URI_SAN_PREFIX = 'URI:';

/** Extract the `URI:` entries from a Node `subjectAltName` string (`"URI:spiffe://…, DNS:foo"`). */
function uriSansOf(subjectAltName: string): string[] {
  return subjectAltName
    .split(', ')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith(URI_SAN_PREFIX))
    .map((entry) => entry.slice(URI_SAN_PREFIX.length));
}

/**
 * Parse an X.509-SVID (PEM text or DER bytes) and extract its SPIFFE ID from the URI SAN, using
 * `node:crypto`'s {@link X509Certificate}. Per the X509-SVID standard the certificate MUST contain
 * exactly ONE URI SAN, which MUST be a valid SPIFFE ID — this rejects a certificate with zero URI
 * SANs or more than one. Throws {@link SpiffeError} on violation.
 */
export function parseX509Svid(cert: string | Uint8Array): X509Svid {
  const certificate = new X509Certificate(cert);

  const san = certificate.subjectAltName;
  if (san === undefined) {
    throw new SpiffeError('no_uri_san', 'X.509-SVID certificate has no Subject Alternative Name');
  }

  const uris = uriSansOf(san);
  if (uris.length === 0) {
    throw new SpiffeError('no_uri_san', 'X.509-SVID certificate has no URI SAN');
  }
  if (uris.length > 1) {
    throw new SpiffeError(
      'multiple_uri_san',
      `X.509-SVID certificate must have exactly one URI SAN, found ${uris.length}`,
    );
  }

  const uri = uris[0];
  if (uri === undefined) {
    // Unreachable given the length checks above, but keeps noUncheckedIndexedAccess happy.
    throw new SpiffeError('no_uri_san', 'X.509-SVID certificate has no URI SAN');
  }
  const spiffeId = parseSpiffeId(uri);

  const publicKeyDer = b64u(certificate.publicKey.export({ type: 'spki', format: 'der' }));

  return { spiffeId, certificate, publicKeyDer };
}

// ---------------------------------------------------------------------------------------------------
// SPIFFE ID  <->  PCA agent-holder identity
// ---------------------------------------------------------------------------------------------------

/**
 * A PCA capability holder bound to a SPIFFE workload identity. `holder` is the core agent-holder
 * identity — a base64url Ed25519 public key usable directly as `Capability.holder` (pass it to the
 * core `mintRoot({ holder })` / `delegate(parent, holder, …)`), while the SPIFFE fields record which
 * SPIRE-attested workload it was bridged from.
 */
export interface SpiffeHolder {
  /** Core PCA holder identity: a base64url Ed25519 public key (`Capability.holder`). */
  readonly holder: string;
  /** Canonical SPIFFE ID this holder is bound to. */
  readonly spiffeId: string;
  /** Trust domain of {@link spiffeId}. */
  readonly trustDomain: string;
  /** Workload path of {@link spiffeId}. */
  readonly path: string;
}

/** Validate/normalise an Ed25519 holder key (b64u string or 32 raw bytes) to canonical base64url. */
function normalizeHolderKey(holderKey: string | Uint8Array): string {
  if (holderKey instanceof Uint8Array) {
    if (holderKey.length !== 32) {
      throw new SpiffeError('invalid_holder_key', 'holder key must be a 32-byte Ed25519 public key');
    }
    return b64u(holderKey);
  }
  const bytes = decodeB64uStrict(holderKey, 32);
  if (bytes === null) {
    throw new SpiffeError(
      'invalid_holder_key',
      'holder key must be a 32-byte Ed25519 public key encoded as base64url',
    );
  }
  return b64u(bytes);
}

/**
 * Bind a SPIFFE workload identity to a PCA agent-holder. Given a (validated) SPIFFE ID and the
 * workload's Ed25519 holder public key, produces a {@link SpiffeHolder} whose `.holder` plugs
 * straight into the core capability APIs. The holder key is the key the workload uses to sign
 * PCActns — e.g. the public key extracted from its X.509-SVID ({@link parseX509Svid}) when that key
 * is Ed25519, or a dedicated PCA holder key the attested workload controls.
 */
export function svidToHolder(spiffeId: string | SpiffeId, holderKey: string | Uint8Array): SpiffeHolder {
  const parsed = asSpiffeId(spiffeId);
  return {
    holder: normalizeHolderKey(holderKey),
    spiffeId: parsed.id,
    trustDomain: parsed.trustDomain,
    path: parsed.path,
  };
}

/** Recover the (validated, canonical) SPIFFE ID a {@link SpiffeHolder} was bridged from. */
export function holderToSpiffeId(holder: SpiffeHolder): string {
  return parseSpiffeId(holder.spiffeId).id;
}
