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
import { readCertFacts, type CertFacts } from './der';
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
  | 'invalid_holder_key'
  | 'malformed_certificate'
  | 'leaf_is_ca'
  | 'leaf_no_digital_signature'
  | 'leaf_cert_sign'
  | 'leaf_crl_sign'
  | 'leaf_root_path'
  | 'unsupported_critical_extension'
  | 'forbidden_algorithm'
  | 'invalid_typ'
  | 'chain_empty'
  | 'chain_trust_domain_mismatch'
  | 'chain_signature'
  | 'chain_not_ca'
  | 'chain_no_key_cert_sign'
  | 'chain_path_len'
  | 'chain_expired'
  | 'chain_untrusted_root'
  | 'chain_too_long';

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

/** Signature algorithms the JWT-SVID specification allows. */
export const JWT_SVID_ALGORITHMS: readonly string[] = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

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
  /**
   * Permitted signature algorithms. Defaults to the JWT-SVID set (RS/ES/PS 256, 384, 512). `none` and the
   * HMAC family (`HS*`) are always rejected, as the JWT-SVID specification forbids them.
   */
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

  const algorithms = opts.algorithms ?? [...JWT_SVID_ALGORITHMS];
  const bad = algorithms.find((a) => a === 'none' || a.toUpperCase().startsWith('HS'));
  if (bad !== undefined || algorithms.length === 0) {
    throw new SpiffeError('forbidden_algorithm', `JWT-SVIDs must not use ${bad ?? 'an empty algorithm list'}`);
  }

  const joseOpts = {
    audience,
    algorithms,
    ...(opts.currentDate !== undefined ? { currentDate: opts.currentDate } : {}),
    ...(opts.clockTolerance !== undefined ? { clockTolerance: opts.clockTolerance } : {}),
  };

  const { payload, protectedHeader } =
    typeof opts.key === 'function'
      ? await jwtVerify(token, opts.key, joseOpts)
      : await jwtVerify(token, opts.key, joseOpts);

  // JWT-SVID section 3: `typ`, when present, must be JWT or JOSE.
  if (protectedHeader.typ !== undefined && protectedHeader.typ !== 'JWT' && protectedHeader.typ !== 'JOSE') {
    throw new SpiffeError('invalid_typ', `JWT-SVID header typ must be JWT or JOSE, got '${protectedHeader.typ}'`);
  }

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

/** A DER certificate from a PEM string (first CERTIFICATE block) or DER bytes. */
function toCertificate(cert: string | Uint8Array): X509Certificate {
  try {
    return new X509Certificate(cert);
  } catch (e) {
    throw new SpiffeError('malformed_certificate', `cannot parse certificate: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function factsOf(certificate: X509Certificate): CertFacts {
  try {
    return readCertFacts(certificate.raw);
  } catch (e) {
    throw new SpiffeError('malformed_certificate', `cannot read certificate extensions: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Apply the X509-SVID leaf rules (SPIFFE X509-SVID section 4.3): exactly one URI SAN holding a valid SPIFFE
 * ID with a non-root path; `cA` false; `keyUsage` present with `digitalSignature` and without `keyCertSign`
 * or `cRLSign`; no unsupported critical extension. Throws {@link SpiffeError} on violation.
 */
function validateLeaf(certificate: X509Certificate): { spiffeId: SpiffeId; facts: CertFacts } {
  const facts = factsOf(certificate);
  if (facts.unknownCritical.length > 0) {
    throw new SpiffeError('unsupported_critical_extension', `certificate has an unsupported critical extension (${facts.unknownCritical.join(', ')})`);
  }
  if (facts.uriSans.length === 0) {
    throw new SpiffeError('no_uri_san', 'X.509-SVID certificate has no URI SAN');
  }
  if (facts.uriSans.length > 1) {
    throw new SpiffeError('multiple_uri_san', `X.509-SVID certificate must have exactly one URI SAN, found ${facts.uriSans.length}`);
  }
  const spiffeId = parseSpiffeId(facts.uriSans[0]!);
  if (spiffeId.path === '') {
    throw new SpiffeError('leaf_root_path', 'X.509-SVID leaf SPIFFE ID must have a non-root path');
  }
  if (facts.isCa) throw new SpiffeError('leaf_is_ca', 'leaf certificate must not have the CA flag set to true');
  if (!facts.digitalSignature) {
    throw new SpiffeError('leaf_no_digital_signature', "leaf certificate must have 'digitalSignature' set as key usage");
  }
  if (facts.keyCertSign) throw new SpiffeError('leaf_cert_sign', "leaf certificate must not have 'keyCertSign' set as key usage");
  if (facts.crlSign) throw new SpiffeError('leaf_crl_sign', "leaf certificate must not have 'cRLSign' set as key usage");
  return { spiffeId, facts };
}

/**
 * Parse an X.509-SVID (PEM text or DER bytes) and validate it as a SPIFFE leaf: see the leaf rules above.
 * The SPIFFE ID is read from the DER subjectAltName, not from a formatted string. This does NOT check the
 * certificate chain, validity period or revocation; use {@link verifyX509Svid} for that. Throws
 * {@link SpiffeError} on violation.
 */
export function parseX509Svid(cert: string | Uint8Array): X509Svid {
  const certificate = toCertificate(cert);
  const { spiffeId } = validateLeaf(certificate);
  const publicKeyDer = b64u(certificate.publicKey.export({ type: 'spki', format: 'der' }));
  return { spiffeId, certificate, publicKeyDer };
}

/** Options for {@link verifyX509Svid}. */
export interface VerifyX509SvidOptions {
  /** REQUIRED. Trust domain whose bundle `roots` belong to; the leaf's SPIFFE ID must be in it. */
  trustDomain: string;
  /** REQUIRED. The trust bundle's X.509 authorities (PEM text, which may hold several certificates, or DER). */
  roots: readonly (string | Uint8Array)[];
  /** Verification time (default now). */
  now?: Date;
  /** Maximum number of certificates in the presented chain (default 8). */
  maxChainLength?: number;
}

const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** Split PEM text into its certificates; DER input is a single certificate. */
function certsOf(input: string | Uint8Array): X509Certificate[] {
  if (typeof input === 'string') {
    const blocks = input.match(PEM_CERT_RE) ?? [];
    if (blocks.length === 0) throw new SpiffeError('malformed_certificate', 'no PEM certificate found');
    return blocks.map((b) => toCertificate(b));
  }
  return [toCertificate(input)];
}

/** A chain element must be a CA allowed to sign certificates. */
function validateSigner(cert: X509Certificate, label: string): CertFacts {
  const facts = factsOf(cert);
  if (facts.unknownCritical.length > 0) {
    throw new SpiffeError('unsupported_critical_extension', `${label} has an unsupported critical extension (${facts.unknownCritical.join(', ')})`);
  }
  if (!facts.isCa) throw new SpiffeError('chain_not_ca', `${label} must have the CA flag set to true`);
  if (facts.keyUsagePresent && !facts.keyCertSign) {
    throw new SpiffeError('chain_no_key_cert_sign', `${label} must have 'keyCertSign' set as key usage`);
  }
  if (!facts.keyUsagePresent) {
    throw new SpiffeError('chain_no_key_cert_sign', `${label} must have 'keyCertSign' set as key usage`);
  }
  return facts;
}

function withinValidity(cert: X509Certificate, now: Date): boolean {
  return now >= new Date(cert.validFrom) && now <= new Date(cert.validTo);
}

/**
 * Verify an X.509-SVID against a trust bundle (SPIFFE X509-SVID section 4): the leaf passes the leaf rules,
 * its SPIFFE ID is in the bundle's trust domain, every certificate is within its validity period, each
 * certificate is signed by the next, signing certificates have `cA` true and `keyCertSign`, any
 * `pathLenConstraint` is respected, and the chain ends at (or is signed by) a bundle authority. `chain` is
 * the leaf first, then its signing certificates (PEM text with several certificates, or an array). Node's
 * crypto checks the signatures; revocation is not checked. Throws {@link SpiffeError}; resolves to the
 * parsed leaf on success.
 */
export function verifyX509Svid(chain: string | readonly (string | Uint8Array)[], opts: VerifyX509SvidOptions): X509Svid {
  const now = opts.now ?? new Date();
  const items = typeof chain === 'string' ? certsOf(chain) : chain.flatMap((c) => certsOf(c));
  if (items.length === 0) throw new SpiffeError('chain_empty', 'certificate chain is empty');
  if (items.length > (opts.maxChainLength ?? 8)) throw new SpiffeError('chain_too_long', 'certificate chain is too long');
  const leaf = items[0]!;
  const { spiffeId } = validateLeaf(leaf);
  if (spiffeId.trustDomain !== opts.trustDomain) {
    throw new SpiffeError('chain_trust_domain_mismatch', `SPIFFE ID trust domain '${spiffeId.trustDomain}' is not '${opts.trustDomain}'`);
  }
  const roots = opts.roots.flatMap((r) => certsOf(r));
  if (roots.length === 0) throw new SpiffeError('chain_untrusted_root', 'trust bundle has no X.509 authorities');

  for (const c of items) {
    if (!withinValidity(c, now)) throw new SpiffeError('chain_expired', 'a certificate in the chain is not within its validity period');
  }

  // Structure first: every signing certificate must be a CA with keyCertSign and a satisfied pathLenConstraint.
  // `below` counts the signing certificates between the current one and the leaf.
  for (let i = 1; i < items.length; i++) {
    const f = validateSigner(items[i]!, `signing certificate #${i}`);
    if (f.pathLen !== null && i - 1 > f.pathLen) throw new SpiffeError('chain_path_len', `signing certificate #${i} pathLenConstraint exceeded`);
  }
  const below = items.length - 1;
  // Then signatures: each certificate must be issued and signed by the next.
  for (let i = 0; i + 1 < items.length; i++) {
    const cert = items[i]!;
    const next = items[i + 1]!;
    if (!cert.checkIssued(next) || !cert.verify(next.publicKey)) {
      throw new SpiffeError('chain_signature', `certificate #${i} is not signed by certificate #${i + 1}`);
    }
  }

  // The last presented certificate must BE a bundle authority, or be signed by one.
  const top = items[items.length - 1]!;
  if (items.length === 1 && roots.some((r) => r.raw.equals(leaf.raw))) {
    throw new SpiffeError('chain_untrusted_root', 'a leaf certificate cannot be its own trust anchor');
  }
  const topIsAnchor = items.length > 1 && roots.some((r) => r.raw.equals(top.raw));
  if (!topIsAnchor) {
    const signer = roots.find((r) => top.checkIssued(r) && top.verify(r.publicKey));
    if (signer === undefined) throw new SpiffeError('chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle');
    if (!withinValidity(signer, now)) throw new SpiffeError('chain_expired', 'the trust bundle authority is not within its validity period');
    const f = validateSigner(signer, 'trust bundle authority');
    if (f.pathLen !== null && below > f.pathLen) throw new SpiffeError('chain_path_len', 'trust bundle authority pathLenConstraint exceeded');
  }

  const publicKeyDer = b64u(leaf.publicKey.export({ type: 'spki', format: 'der' }));
  return { spiffeId, certificate: leaf, publicKeyDer };
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
