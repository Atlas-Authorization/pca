/**
 * L0 HARDWARE backend — GOOGLE CLOUD CONFIDENTIAL SPACE ATTESTATION-TOKEN VERIFIER.
 *
 * A pluggable attestation root (the `HardwareAttestationVerifier` seam declared in `attestation.ts`,
 * built to the SAME shape as `attest-amd-snp.ts` / `attest-intel-dcap.ts` / `attest-azure-maa.ts`) for
 * the GCP-NATIVE attestation path. On a Google Cloud Confidential VM running under Confidential Space,
 * the workload does not hand a raw SEV-SNP report or a raw Intel TDX DCAP quote to the relying party;
 * instead the Confidential Space launcher asks Google's attestation service
 * (`https://confidentialcomputing.googleapis.com`), which validates the underlying hardware evidence and
 * returns a signed **Confidential Space attestation token** (a JWT / JWS, RS256). Google issues this one
 * token shape for BOTH isolation technologies — AMD SEV / SEV-SNP (`hwmodel: "GCP_AMD_SEV"` /
 * `"GCP_AMD_SEV_SNP"`) and Intel TDX (`hwmodel: "GCP_INTEL_TDX"`) — so this ONE root natively covers both
 * on GCP, and slots into the multi-root N-of-M policy exactly like any other root (see `GCP_CS_SUITE`).
 *
 * ── WHAT THIS IS, HONESTLY. ─────────────────────────────────────────────────────────────────────────
 * This is the GCP-NATIVE attestation path: the trust root is Google's Confidential Space attestation
 * service signing chain (classical RS256; Google publishes its signing keys as a JWKS at the issuer's
 * OpenID `jwks_uri`). It is COMPLEMENTARY to, not a replacement for:
 *   - `attest-intel-dcap.ts` (`createIntelDcapVerifier`) — direct Intel DCAP quote + PCK→Root-CA verification;
 *   - `attest-amd-snp.ts` (`createAmdSnpVerifier`) — direct AMD VCEK→ASK→ARK verification of a raw report;
 *   - `attest-azure-maa.ts` (`createAzureMaaVerifier`) — the Azure-native MAA JWT path.
 * Using the Confidential Space token moves the raw-evidence verification to Google and roots trust in
 * Google's attestation-service signing keys instead of the CPU vendor's silicon chain. That is a
 * deliberate trust choice: you are trusting the configured Google attestation issuer (and the signing
 * keys pinned for it) to have faithfully verified the underlying SEV-SNP/TDX evidence. The suite is
 * CLASSICAL (Google signs RS256 today); its value in a multi-root policy is INDEPENDENCE from the
 * raw-DCAP / direct-SEV-SNP / Azure-MAA roots, not post-quantum strength.
 *
 * ── WHAT IS CRYPTOGRAPHICALLY VERIFIED (real crypto, exercised end-to-end by the tests). ─────────────
 *   1. JWS parse (header.payload.signature) and signature verification under the key identified by the
 *      header `kid`, located in Google's published JWKS (RSA `n`/`e`, or `x5c` when present). RS256 is
 *      verified with node/OpenSSL (RSA-SHA256); ES256 defensively via node/OpenSSL (`ieee-p1363`).
 *   2. The signing key is trusted ONLY when it is anchored to a CONFIGURED anchor — a pinned trusted
 *      JWKS (the operator pins Google's published keys), a pinned SPKI SHA-256 fingerprint, or (when the
 *      JWK carries an `x5c`) a chain to a configured root-CA PEM. The root of trust is NEVER taken from
 *      the evidence-supplied JWKS alone. At least one anchor is REQUIRED (construction throws otherwise —
 *      no accept-all). Unknown signer / untrusted key / broken chain → FAIL CLOSED.
 *   3. Standard claims: `iss` must equal a CONFIGURED trusted Google attestation issuer; the
 *      `exp`/`iat`/`nbf` window is enforced against the server clock (`nowMs`), with optional skew.
 *   4. Confidential Space claims: `submods.confidential_space` must be present (it IS a Confidential
 *      Space token); `swname` must match the configured expectation (default `CONFIDENTIAL_SPACE`); the
 *      `hwmodel` must map to a known isolation type (AMD SEV-SNP vs Intel TDX); `dbgstat` must be
 *      `disabled-since-boot` unless policy forbids-debug is relaxed; the measured workload image
 *      (`submods.container.image_digest`) is gated by a NON-EMPTY policy allowlist (no accept-all); and
 *      the `eat_nonce` claim is bound to the PCA challenge `attestationBinding({holder,grant,epoch,nonce})`.
 *   5. The measured identity (isolation type + measured image digest) flows back through the usual
 *      agent_binding match in `createAttestationVerifier`, exactly like the other roots (one GCP root
 *      covers both SEV-SNP and TDX on GCP).
 *
 * ── eat_nonce NUANCE (why `nonceHash` exists). ──────────────────────────────────────────────────────
 * The Confidential Space token echoes the guest-supplied nonce(s) in `eat_nonce` (a single string, or an
 * array of strings — Google permits up to six, each 10..74 bytes). The guest is expected to pass the PCA
 * `attestationBinding` as the nonce so the token's `eat_nonce` equals it. When the guest instead passes a
 * hash of it (e.g. to fit the byte-length window), set `nonceHash` to the hash it applies
 * (`sha256`/`sha512`) so the verifier compares `H(attestationBinding(expected))`. Default `none` (direct
 * equality). When `eat_nonce` is an array, ANY entry that binds is accepted (fail-closed if none do).
 *
 * NO NETWORK I/O: like the other roots, this module never reaches the network on its own. The token + the
 * issuer JWKS are supplied via the `resolveEvidence` seam (fetch them out-of-band from the token `jku` /
 * the issuer's OpenID `jwks_uri`). `fetchGcpConfidentialSpaceJwks` is a guarded, optional helper for that.
 *
 * References: Google Cloud — "Confidential Space attestation tokens" claim set (`submods.confidential_space`,
 * `submods.container.image_digest`, `hwmodel`, `swname`, `swversion`, `dbgstat`, `eat_nonce`, `secboot`);
 * RFC 7519 (JWT) / RFC 7515 (JWS) `kid`/`x5c`; RFC 7517 (JWK, RSA `n`/`e`); RFC 9711 (EAT `eat_nonce`).
 */
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from './hash';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** The signature suites a Google Confidential Space attestation token is signed with today (classical). */
export const GCP_CS_SUITES = ['RS256', 'ES256'] as const;
/** A JOSE `alg` this verifier accepts for a Confidential Space JWS. */
export type GcpCsAlg = (typeof GCP_CS_SUITES)[number];

/** Audit label of this root's suite family (classical — see the module header's honest-scope note). */
export const GCP_CS_SUITE = 'gcp-confidential-space-jwt' as const;

/** The canonical Google Confidential Space attestation issuer. */
export const GCP_CS_DEFAULT_ISSUER = 'https://confidentialcomputing.googleapis.com' as const;

/** The isolation (TEE) families a Confidential Space `hwmodel` can map to. */
export type GcpTeeType = 'sev-snp' | 'tdx';

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Small, dependency-free helpers (typed; no `any`).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Lowercase hex of a byte array. */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

/** Constant-time byte-array equality. */
function timingSafeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
function asNumber(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
function asStringArray(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const x of v) {
    if (typeof x !== 'string') return undefined;
    out.push(x);
  }
  return out;
}

/** First present, non-empty string claim across candidate keys. */
function firstString(rec: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const k of keys) {
    const v = asString(rec[k]);
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return undefined;
}

/** Collect `eat_nonce` into a list of candidate strings (Google permits a single string or an array). */
function nonceCandidates(v: unknown): string[] {
  if (typeof v === 'string') return v.length > 0 ? [v] : [];
  const arr = asStringArray(v);
  if (!arr) return [];
  return arr.filter((s) => s.length > 0);
}

function isHexString(s: string): boolean {
  return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

/**
 * Decode a byte-carrying claim flexibly: hex (optionally `0x`-prefixed), else base64url, else standard
 * base64. Returns null when the value decodes under none of them (caller fails closed). `eat_nonce` in a
 * Confidential Space token is typically base64 of the raw nonce bytes; the hex fallback makes the binding
 * robust to real-token variance the user will validate against a captured token.
 */
function decodeClaimBytes(value: string): Uint8Array | null {
  const trimmed = value.trim();
  const hx = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (isHexString(hx)) {
    const out = new Uint8Array(hx.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hx.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  for (const enc of ['base64url', 'base64'] as const) {
    try {
      const buf = Buffer.from(trimmed, enc);
      if (buf.length > 0) return new Uint8Array(buf);
    } catch {
      /* try next */
    }
  }
  return null;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// node:crypto (OpenSSL) — JWK→key, X.509 chain, RSA/ECDSA verify. Imported LAZILY (as in the sibling
// adapters) so the module core carries no hard top-level Node dependency.
// ════════════════════════════════════════════════════════════════════════════════════════════════

type NodeCrypto = typeof import('node:crypto');
let _nodeCryptoPromise: Promise<NodeCrypto> | null = null;
async function nodeCrypto(): Promise<NodeCrypto> {
  return (_nodeCryptoPromise ??= import('node:crypto'));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// JWS / JWK types.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** A parsed Confidential Space JWS header (the fields this verifier reads). */
export interface GcpCsJwsHeader {
  alg: string;
  kid?: string;
  /** JWKS URI the signing key lives at (the issuer's `jwks_uri`). Informational here. */
  jku?: string;
  /** X.509 cert chain (base64 DER, leaf first) — present only when Google carries it in the header. */
  x5c?: string[];
  typ?: string;
}

/** A parsed Confidential Space attestation token. */
export interface ParsedGcpCsJwt {
  header: GcpCsJwsHeader;
  /** The decoded claim set (opaque; narrowed by the verifier). */
  payload: Record<string, unknown>;
  /** ASCII bytes of `base64url(header).base64url(payload)` — exactly what the signature covers. */
  signingInput: Uint8Array;
  /** The decoded JWS signature bytes. */
  signature: Uint8Array;
}

/** One JWK in Google's JWKS (the fields this verifier reads). RSA keys carry `n`/`e`; some may carry `x5c`. */
export interface GcpJwk {
  kid?: string;
  kty?: string;
  alg?: string;
  use?: string;
  /** RSA modulus (base64url), present on Google's RSA signing keys. */
  n?: string;
  /** RSA public exponent (base64url). */
  e?: string;
  /** EC curve (defensive — Google signs RS256 today). */
  crv?: string;
  /** EC x coordinate (base64url). */
  x?: string;
  /** EC y coordinate (base64url). */
  y?: string;
  /** X.509 cert chain, base64 DER, leaf first (present only when the key is published as a cert). */
  x5c?: string[];
}

/** An issuer JWKS (`<issuer>/.well-known/openid-configuration` → `jwks_uri`). */
export interface GcpJwks {
  keys: GcpJwk[];
}

/**
 * Parse a compact JWS Confidential Space token into header/payload/signature + the signing input. FAILS
 * (throws) on a structurally invalid token; never verifies anything on its own.
 */
export function parseGcpCsJwt(token: string): ParsedGcpCsJwt {
  if (typeof token !== 'string' || token.length === 0) throw new TypeError('parseGcpCsJwt: empty token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new TypeError('parseGcpCsJwt: a compact JWS has exactly three dot-separated parts');
  const [h, p, s] = parts;
  if (!h || !p || s === undefined || s.length === 0) throw new TypeError('parseGcpCsJwt: empty JWS segment');
  let headerObj: unknown;
  let payloadObj: unknown;
  try {
    headerObj = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    payloadObj = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch (e) {
    throw new TypeError(`parseGcpCsJwt: malformed JSON segment: ${e instanceof Error ? e.message : 'unknown'}`);
  }
  const headerRec = asRecord(headerObj);
  const payloadRec = asRecord(payloadObj);
  if (!headerRec) throw new TypeError('parseGcpCsJwt: header is not a JSON object');
  if (!payloadRec) throw new TypeError('parseGcpCsJwt: payload is not a JSON object');
  const alg = asString(headerRec.alg);
  if (!alg) throw new TypeError('parseGcpCsJwt: header has no alg');
  const header: GcpCsJwsHeader = {
    alg,
    ...(asString(headerRec.kid) !== undefined ? { kid: asString(headerRec.kid) } : {}),
    ...(asString(headerRec.jku) !== undefined ? { jku: asString(headerRec.jku) } : {}),
    ...(asStringArray(headerRec.x5c) !== undefined ? { x5c: asStringArray(headerRec.x5c) } : {}),
    ...(asString(headerRec.typ) !== undefined ? { typ: asString(headerRec.typ) } : {}),
  };
  const signature = new Uint8Array(Buffer.from(s, 'base64url'));
  if (signature.length === 0) throw new TypeError('parseGcpCsJwt: empty signature');
  // signingInput is the ASCII bytes of the compact `header.payload` prefix.
  return { header, payload: payloadRec, signingInput: new Uint8Array(Buffer.from(`${h}.${p}`, 'ascii')), signature };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Trust anchors + signing-key resolution.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The configured anchor(s) the token's signing key must be rooted in. At least one anchor is REQUIRED
 * (construction throws otherwise — no accept-all). The root of trust is the CONFIGURED anchor, never a key
 * taken only from the evidence-supplied JWKS.
 */
export interface GcpCsTrustAnchors {
  /**
   * A PINNED JWKS of trusted signing keys — the operator pins Google's published Confidential Space
   * signing keys (fetched out-of-band and verified). A signing key is trusted when it is present here
   * (matched by `kid` with identical key material, or by material alone). This is the common anchor.
   */
  trustedJwks?: GcpJwks;
  /** Trusted signing-key SPKI SHA-256 fingerprints (lowercase hex) — pins the exact public key(s). */
  trustedKeySpki?: string[];
  /**
   * Trusted root-CA certificates (PEM) for the rare case Google publishes its signing key as an `x5c`
   * chain: the chain is anchored when its top cert is signed by one of these.
   */
  rootCertsPem?: string[];
}

interface ResolvedKey {
  key: import('node:crypto').KeyObject;
  spkiSha256: string;
  /** True iff this key was located in the configured `trustedJwks` (it IS the anchor). */
  fromTrustedJwks: boolean;
  /** The source JWK (to read its x5c for a chain anchor). */
  jwk: GcpJwk;
}

function spkiSha256OfKey(key: import('node:crypto').KeyObject, createHash: NodeCrypto['createHash']): string {
  const spki = new Uint8Array(key.export({ type: 'spki', format: 'der' }));
  return createHash('sha256').update(Buffer.from(spki)).digest('hex');
}

/** Build a public `KeyObject` from a JWK (RSA `n`/`e`, EC `x`/`y`, or the leaf of an `x5c` chain). */
function keyFromJwk(jwk: GcpJwk, nc: NodeCrypto): import('node:crypto').KeyObject | { reason: string } {
  const { createPublicKey, X509Certificate } = nc;
  try {
    if (typeof jwk.n === 'string' && typeof jwk.e === 'string') {
      return createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
    }
    if (jwk.kty === 'EC' && typeof jwk.crv === 'string' && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
      return createPublicKey({ key: { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
    }
    if (Array.isArray(jwk.x5c) && jwk.x5c.length > 0 && typeof jwk.x5c[0] === 'string') {
      const cert = new X509Certificate(Buffer.from(jwk.x5c[0], 'base64'));
      return cert.publicKey;
    }
    return { reason: 'JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate' };
  } catch (e) {
    return { reason: `JWKS key is not a usable public key: ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

function safeCertVerify(cert: import('node:crypto').X509Certificate, key: import('node:crypto').KeyObject): boolean {
  try {
    return cert.verify(key);
  } catch {
    return false;
  }
}

function certValid(cert: import('node:crypto').X509Certificate, nowMs: number, skewMs: number): boolean {
  const vf = Date.parse(cert.validFrom);
  const vt = Date.parse(cert.validTo);
  if (!Number.isFinite(vf) || !Number.isFinite(vt)) return false;
  return nowMs + skewMs >= vf && nowMs - skewMs <= vt;
}

/**
 * Verify a JWK's `x5c` chain (base64 DER, leaf first) to a configured root-CA PEM / SPKI anchor, enforcing
 * each cert's validity window. Fail-closed on an empty chain, a parse failure, an expired cert, a broken
 * link, or no anchor.
 */
async function verifyJwkX5cChain(
  x5c: readonly string[],
  anchors: GcpCsTrustAnchors,
  opts: { nowMs: number; skewMs: number },
): Promise<string | null> {
  const { X509Certificate, createHash, createPublicKey } = await nodeCrypto();
  if (!Array.isArray(x5c) || x5c.length === 0) return 'empty x5c certificate chain';
  const certs: import('node:crypto').X509Certificate[] = [];
  for (let i = 0; i < x5c.length; i++) {
    const b64 = x5c[i];
    if (typeof b64 !== 'string' || b64.length === 0) return `empty x5c entry at index ${i}`;
    let cert: import('node:crypto').X509Certificate;
    try {
      cert = new X509Certificate(Buffer.from(b64, 'base64'));
    } catch (e) {
      return `malformed x5c certificate at index ${i}: ${e instanceof Error ? e.message : 'unknown'}`;
    }
    if (!certValid(cert, opts.nowMs, opts.skewMs)) return `x5c certificate at index ${i} is outside its validity window`;
    certs.push(cert);
  }
  for (let i = 0; i < certs.length - 1; i++) {
    if (!safeCertVerify(certs[i]!, certs[i + 1]!.publicKey)) return `x5c link ${i} is not signed by the certificate above it`;
  }
  const spkiPins = new Set((anchors.trustedKeySpki ?? []).map((s) => s.toLowerCase()));
  for (const c of certs) {
    if (spkiPins.has(spkiSha256OfKey(c.publicKey, createHash))) return null; // a cert in the chain is a pinned key
  }
  const top = certs[certs.length - 1]!;
  for (const pem of anchors.rootCertsPem ?? []) {
    let rootKey: import('node:crypto').KeyObject;
    try {
      rootKey = new X509Certificate(pem).publicKey;
    } catch {
      try {
        rootKey = createPublicKey(pem);
      } catch {
        continue;
      }
    }
    if (safeCertVerify(top, rootKey)) return null;
  }
  return 'x5c chain does not anchor in a configured GCP trust root';
}

/**
 * Resolve the signing key for a parsed token and CONFIRM it is trusted. Looks in the evidence JWKS first,
 * then the configured trusted JWKS, matched by `kid` (or the sole key when no `kid`). A key from the
 * evidence JWKS is trusted only when it matches a configured anchor (pinned trusted JWKS by material, a
 * pinned SPKI fingerprint, or an `x5c` chain to a configured root). Fail-closed on anything else.
 */
async function resolveTrustedSigningKey(
  header: GcpCsJwsHeader,
  evidenceJwks: GcpJwks | undefined,
  anchors: GcpCsTrustAnchors,
  opts: { nowMs: number; skewMs: number },
): Promise<ResolvedKey | { reason: string }> {
  const nc = await nodeCrypto();
  const { createHash } = nc;

  const trustedKeys = Array.isArray(anchors.trustedJwks?.keys) ? anchors.trustedJwks!.keys : [];
  const evidenceKeys = Array.isArray(evidenceJwks?.keys) ? evidenceJwks!.keys : [];

  // Pick the JWK the token was signed under: by kid if present, else the sole key across sources.
  const pickFrom = (keys: GcpJwk[]): GcpJwk | undefined => {
    if (typeof header.kid === 'string' && header.kid.length > 0) return keys.find((k) => k.kid === header.kid);
    return keys.length === 1 ? keys[0] : undefined;
  };
  let jwk = pickFrom(evidenceKeys);
  let fromTrustedJwks = false;
  if (!jwk) {
    jwk = pickFrom(trustedKeys);
    fromTrustedJwks = jwk !== undefined;
  }
  // No kid and multiple keys across sources is ambiguous; a kid that matches nowhere is untrusted.
  if (!jwk && typeof header.kid === 'string' && header.kid.length > 0 && header.x5c && header.x5c.length > 0) {
    jwk = { x5c: header.x5c, ...(header.kid ? { kid: header.kid } : {}) };
  } else if (!jwk && (typeof header.kid !== 'string' || header.kid.length === 0) && header.x5c && header.x5c.length > 0) {
    jwk = { x5c: header.x5c };
  }
  if (!jwk) {
    if (typeof header.kid === 'string' && header.kid.length > 0) return { reason: `no JWKS key matches the token kid '${header.kid}' (untrusted signer)` };
    return { reason: 'no kid on the token and no unambiguous single signing key available' };
  }

  const built = keyFromJwk(jwk, nc);
  if ('reason' in built) return built;
  const key = built;
  const spki = spkiSha256OfKey(key, createHash);

  if (fromTrustedJwks) return { key, spkiSha256: spki, fromTrustedJwks: true, jwk };

  // Key came from the evidence JWKS / header — it must corroborate a configured anchor.
  const spkiPins = new Set((anchors.trustedKeySpki ?? []).map((s) => s.toLowerCase()));
  if (spkiPins.has(spki)) return { key, spkiSha256: spki, fromTrustedJwks: false, jwk };

  // Same public key present (by material) in the pinned trusted JWKS?
  for (const tk of trustedKeys) {
    const tb = keyFromJwk(tk, nc);
    if ('reason' in tb) continue;
    if (spkiSha256OfKey(tb, createHash) === spki) return { key, spkiSha256: spki, fromTrustedJwks: false, jwk };
  }

  // x5c chain to a configured root?
  if (Array.isArray(jwk.x5c) && jwk.x5c.length > 0 && ((anchors.rootCertsPem?.length ?? 0) > 0 || spkiPins.size > 0)) {
    const chainErr = await verifyJwkX5cChain(jwk.x5c, anchors, opts);
    if (chainErr === null) return { key, spkiSha256: spki, fromTrustedJwks: false, jwk };
    return { reason: `signing key not trusted: ${chainErr}` };
  }

  return { reason: 'signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)' };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// JWS signature verification under the resolved key.
// ════════════════════════════════════════════════════════════════════════════════════════════════

async function verifyJwsSignature(parsed: ParsedGcpCsJwt, key: import('node:crypto').KeyObject): Promise<string | null> {
  const alg = parsed.header.alg;
  const { verify } = await nodeCrypto();
  const jwk = key.export({ format: 'jwk' });
  if (alg === 'RS256') {
    if (jwk.kty !== 'RSA') return `RS256 token but signing key is ${String(jwk.kty)} (not RSA)`;
    let ok = false;
    try {
      ok = verify('RSA-SHA256', parsed.signingInput, key, parsed.signature);
    } catch {
      ok = false;
    }
    return ok ? null : 'JWS RS256 signature does not verify under the Confidential Space signing key';
  }
  if (alg === 'ES256') {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') return `ES256 token but signing key is ${String(jwk.kty)}/${String(jwk.crv)} (not EC P-256)`;
    if (parsed.signature.length !== 64) return `ES256 signature is ${parsed.signature.length} bytes (expected 64: r‖s)`;
    let ok = false;
    try {
      // JWS ES256 signatures are raw r‖s (IEEE P1363), not DER.
      ok = verify('sha256', parsed.signingInput, { key, dsaEncoding: 'ieee-p1363' }, parsed.signature);
    } catch {
      ok = false;
    }
    return ok ? null : 'JWS ES256 signature does not verify under the Confidential Space signing key';
  }
  return `unsupported JWS alg '${alg}' (Confidential Space uses RS256)`;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Confidential Space claim locations + acceptance policy.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** `hwmodel` values that mean AMD SEV / SEV-SNP. */
const SEVSNP_HWMODELS = new Set(['GCP_AMD_SEV', 'GCP_AMD_SEV_SNP', 'GCP_AMD_SEV_ES']);
/** `hwmodel` values that mean Intel TDX. */
const TDX_HWMODELS = new Set(['GCP_INTEL_TDX']);
/** The Google value of `dbgstat` that means "no debug" (confidentiality intact). */
const DBGSTAT_DISABLED = 'disabled-since-boot';

/** Map a Confidential Space `hwmodel` to the isolation (TEE) family, or `undefined` when unrecognized. */
export function teeTypeOfHwModel(hwmodel: string): GcpTeeType | undefined {
  if (SEVSNP_HWMODELS.has(hwmodel)) return 'sev-snp';
  if (TDX_HWMODELS.has(hwmodel)) return 'tdx';
  // Lenient prefix fallback for model names Google may add later.
  const up = hwmodel.toUpperCase();
  if (up.startsWith('GCP_AMD_SEV')) return 'sev-snp';
  if (up.startsWith('GCP_INTEL_TDX')) return 'tdx';
  return undefined;
}

/** Context a `deriveIdentity` override receives. */
export interface GcpCsIdentityContext {
  teeType: GcpTeeType;
  /** The raw `hwmodel` claim. */
  hwmodel: string;
  /** The measured workload image digest (`submods.container.image_digest`). */
  imageDigest: string;
  /** The `submods.container` subtree (or `{}`). */
  container: Record<string, unknown>;
  /** The full token payload. */
  payload: Record<string, unknown>;
}

/**
 * Acceptance policy. `imageDigests` MUST be a NON-EMPTY allowlist (construction throws otherwise — there is
 * no accept-all). All hex / digest comparisons are case-insensitive.
 */
export interface GcpCsPolicy {
  /** Allowed `submods.container.image_digest` values (e.g. `sha256:...`). REQUIRED + non-empty. */
  imageDigests: string[];
  /** Optional pin on the accepted isolation families (default: both `sev-snp` and `tdx`). */
  allowedTeeTypes?: GcpTeeType[];
  /** Expected `swname` (default `CONFIDENTIAL_SPACE`). A mismatch fails closed. */
  expectedSwName?: string;
  /** Optional allowlist of `swversion` entries (any intersection accepts). */
  allowedSwVersions?: string[];
  /** Accept a token whose `dbgstat` is not `disabled-since-boot` (debug build). Default false. */
  allowDebug?: boolean;
  /**
   * Hash applied to the PCA binding before comparing with the token's `eat_nonce` claim: `none` = direct
   * equality against `attestationBinding(expected)` (default); `sha256` / `sha512` = compare
   * `H(attestationBinding(expected))`.
   */
  nonceHash?: 'none' | 'sha256' | 'sha512';
  /** Map a verified token into the `MeasuredIdentity` agent_binding is checked against (override to customise). */
  deriveIdentity?: (ctx: GcpCsIdentityContext) => MeasuredIdentity;
}

export interface GcpConfidentialSpaceVerifierOptions {
  /**
   * CONFIGURED trusted Google attestation issuer URLs. The token's `iss` MUST equal one of these exactly.
   * REQUIRED and NON-EMPTY (construction throws otherwise). Default production value:
   * `https://confidentialcomputing.googleapis.com` (see {@link GCP_CS_DEFAULT_ISSUER}).
   */
  trustedIssuers: string[];
  /** The anchor(s) the token's signing key must root in (at least one required). */
  trustAnchors: GcpCsTrustAnchors;
  /** Acceptance policy (the image-digest allowlist is required + non-empty). */
  policy: GcpCsPolicy;
  /**
   * EVIDENCE SEAM: produce the Confidential Space token (and, when the signing key is located via the
   * issuer JWKS rather than a pinned trusted JWKS, that fetched JWKS) for an action. Production reads the
   * token carried with the attestation document and the JWKS fetched out-of-band from the token `jku` /
   * the issuer `jwks_uri`. If omitted, the verifier fails closed (no evidence).
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => GcpCsEvidence | undefined | Promise<GcpCsEvidence | undefined>;
  /** Allowed clock skew (ms) for the JWT time window + cert validity (default 0). */
  clockSkewMs?: number;
}

/** The evidence for one action: the Confidential Space token and (optionally) the issuer JWKS. */
export interface GcpCsEvidence {
  /** The compact Confidential Space JWS token. */
  token: string;
  /** The issuer JWKS (fetched from `jwks_uri`). Optional when a pinned trusted JWKS is configured. */
  jwks?: GcpJwks;
}

function transformBinding(binding: Uint8Array, mode: GcpCsPolicy['nonceHash']): Uint8Array {
  if (mode === 'sha256') return sha256(binding);
  if (mode === 'sha512') return sha512(binding);
  return binding;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// The GCP Confidential Space HardwareAttestationVerifier.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Build a `HardwareAttestationVerifier` backed by Google Cloud Confidential Space attestation. Given an
 * attestation document + context it resolves the token (+ issuer JWKS) via the evidence seam, then:
 *   1. parses the JWS;
 *   2. resolves the signing key (JWKS-by-kid) and confirms it is anchored to a CONFIGURED trust anchor;
 *   3. verifies the JWS signature under that key (RS256 via node OpenSSL; ES256 defensively);
 *   4. checks `iss` ∈ trusted issuers and the `exp`/`iat`/`nbf` window against `nowMs`;
 *   5. validates `submods.confidential_space`, `swname`/`swversion`, `hwmodel`→isolation type, `dbgstat`,
 *      binds `eat_nonce` to `attestationBinding(expected)`, and gates `submods.container.image_digest` by
 *      the NON-EMPTY policy allowlist;
 *   6. returns the measured identity — which `createAttestationVerifier` then matches against the grant's
 *      agent_binding (one GCP root covers both SEV-SNP and TDX on GCP).
 * Fails CLOSED with a specific reason on any mismatch or error.
 *
 * Wire it in: `createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: createGcpConfidentialSpaceVerifier(opts), resolveDocument })`,
 * or add it as one `AttestationRoot` in a `createMultiRootVerifier` policy.
 */
export function createGcpConfidentialSpaceVerifier(opts: GcpConfidentialSpaceVerifierOptions): HardwareAttestationVerifier {
  if (!opts || !Array.isArray(opts.trustedIssuers) || opts.trustedIssuers.length === 0) {
    throw new TypeError('createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs');
  }
  for (const iss of opts.trustedIssuers) {
    if (typeof iss !== 'string' || iss.length === 0) throw new TypeError('createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string');
  }
  const anchors = opts.trustAnchors;
  const anchorCount =
    (Array.isArray(anchors?.trustedJwks?.keys) ? anchors!.trustedJwks!.keys.length : 0) +
    (anchors?.trustedKeySpki?.length ?? 0) +
    (anchors?.rootCertsPem?.length ?? 0);
  if (anchorCount === 0) {
    throw new TypeError('createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted');
  }
  const policy = opts.policy;
  if (!policy || !Array.isArray(policy.imageDigests) || policy.imageDigests.length === 0) {
    throw new TypeError('createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  if (Array.isArray(policy.allowedTeeTypes) && policy.allowedTeeTypes.length === 0) {
    throw new TypeError('createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty');
  }
  const trustedIssuers = new Set(opts.trustedIssuers);
  const skew = Number.isFinite(opts.clockSkewMs) ? Math.max(0, opts.clockSkewMs as number) : 0;
  const allowedImages = new Set(policy.imageDigests.map((x) => x.toLowerCase()));
  const allowedTeeTypes = Array.isArray(policy.allowedTeeTypes) ? new Set(policy.allowedTeeTypes) : undefined;
  const expectedSwName = typeof policy.expectedSwName === 'string' ? policy.expectedSwName : 'CONFIDENTIAL_SPACE';
  const allowedSwVersions = Array.isArray(policy.allowedSwVersions) ? new Set(policy.allowedSwVersions) : undefined;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no GCP Confidential Space evidence resolver configured (fail closed)');
        const evidence = await opts.resolveEvidence(input.document, input.ctx);
        if (!evidence || typeof evidence.token !== 'string' || evidence.token.length === 0) {
          return fail('no GCP Confidential Space token for this action');
        }

        // (1) parse
        let parsed: ParsedGcpCsJwt;
        try {
          parsed = parseGcpCsJwt(evidence.token);
        } catch (e) {
          return fail(`Confidential Space token parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }
        if (parsed.header.alg !== 'RS256' && parsed.header.alg !== 'ES256') {
          return fail(`unsupported JWS alg '${parsed.header.alg}' (Confidential Space uses RS256)`);
        }

        // (2) resolve + anchor the signing key
        const resolved = await resolveTrustedSigningKey(parsed.header, evidence.jwks, anchors, { nowMs: input.nowMs, skewMs: skew });
        if ('reason' in resolved) return fail(`Confidential Space signing key invalid: ${resolved.reason}`);

        // (3) JWS signature under the resolved key
        const sigErr = await verifyJwsSignature(parsed, resolved.key);
        if (sigErr) return fail(sigErr);

        // (4) standard claims: iss + time window
        const iss = asString(parsed.payload.iss);
        if (!iss || !trustedIssuers.has(iss)) return fail(`token iss '${String(iss)}' is not a configured trusted Google attestation issuer`);
        const nowSec = Math.floor(input.nowMs / 1000);
        const skewSec = Math.ceil(skew / 1000);
        const exp = asNumber(parsed.payload.exp);
        const iat = asNumber(parsed.payload.iat);
        const nbf = asNumber(parsed.payload.nbf);
        if (exp === undefined) return fail('token has no exp (cannot bound validity — fail closed)');
        if (nowSec - skewSec > exp) return fail('Confidential Space token expired');
        if (nbf !== undefined && nowSec + skewSec < nbf) return fail('Confidential Space token not yet valid (nbf)');
        if (iat !== undefined && nowSec + skewSec < iat) return fail('Confidential Space token issued in the future (iat)');

        // (5) Confidential Space claims
        const submods = asRecord(parsed.payload.submods);
        const confidentialSpace = submods ? asRecord(submods['confidential_space']) : undefined;
        if (!confidentialSpace) return fail('token carries no submods.confidential_space (not a Confidential Space token)');

        const swname = asString(parsed.payload.swname);
        if (swname !== expectedSwName) return fail(`unexpected swname '${String(swname)}' (expected '${expectedSwName}')`);
        if (allowedSwVersions) {
          const versions = asStringArray(parsed.payload.swversion) ?? (asString(parsed.payload.swversion) ? [asString(parsed.payload.swversion)!] : []);
          if (!versions.some((v) => allowedSwVersions.has(v))) return fail('swversion not in policy allowlist');
        }

        const hwmodel = asString(parsed.payload.hwmodel);
        if (!hwmodel) return fail('token carries no hwmodel claim');
        const teeType = teeTypeOfHwModel(hwmodel);
        if (!teeType) return fail(`unrecognized hwmodel '${hwmodel}' (not a known AMD SEV-SNP / Intel TDX model)`);
        if (allowedTeeTypes && !allowedTeeTypes.has(teeType)) {
          return fail(`attestation type '${teeType}' (hwmodel '${hwmodel}') is not in the policy allowlist`);
        }

        // (5a) debug state
        const dbgstat = asString(parsed.payload.dbgstat);
        if (policy.allowDebug !== true && dbgstat !== DBGSTAT_DISABLED) {
          return fail(`token dbgstat '${String(dbgstat)}' is not '${DBGSTAT_DISABLED}' (debug build — no confidentiality)`);
        }

        // (5b) bind eat_nonce to the PCA challenge
        if (!input.expected) return fail('no expected attestation binding supplied');
        let bindingBytes: Uint8Array;
        try {
          bindingBytes = transformBinding(attestationBinding(input.expected), policy.nonceHash);
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        const candidates = nonceCandidates(parsed.payload.eat_nonce);
        if (candidates.length === 0) return fail('token carries no eat_nonce claim to bind the PCA challenge');
        let bound = false;
        for (const c of candidates) {
          const bytes = decodeClaimBytes(c);
          if (bytes && timingSafeEq(bytes, bindingBytes)) {
            bound = true;
            break;
          }
        }
        if (!bound) return fail('eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)');

        // (5c) measured workload image, gated by the non-empty allowlist
        const container = (submods ? asRecord(submods.container) : undefined) ?? {};
        const imageDigest = firstString(container, ['image_digest']);
        if (!imageDigest) return fail('token carries no submods.container.image_digest to measure the workload');
        if (!allowedImages.has(imageDigest.toLowerCase())) return fail('workload image_digest not in policy allowlist');

        // (6) measured identity
        const measured = policy.deriveIdentity
          ? policy.deriveIdentity({ teeType, hwmodel, imageDigest, container, payload: parsed.payload })
          : { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: imageDigest, operator: '' };
        const hostAsserted: Record<string, string> = { attestation_type: teeType, hwmodel, image_digest: imageDigest };
        const imageRef = firstString(container, ['image_reference']);
        if (imageRef) hostAsserted.image_reference = imageRef;
        return { ok: true, bound: true, measured, hostAsserted };
      } catch (e) {
        return fail(`gcp-confidential-space verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// GUARDED, OPTIONAL network helper (NEVER called by this module on its own).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Fetch the Google attestation issuer's JWKS (NETWORK I/O — never auto-invoked; wire it into your own
 * `resolveEvidence`). Resolves the issuer's OpenID configuration (`<issuer>/.well-known/openid-configuration`)
 * to its `jwks_uri` and fetches the keys, unless `jwksUri` is supplied directly. Returns the parsed
 * {@link GcpJwks}. Throws on a non-2xx response or malformed body.
 */
export async function fetchGcpConfidentialSpaceJwks(
  issuer: string,
  opts: { fetch?: typeof fetch; jwksUri?: string } = {},
): Promise<GcpJwks> {
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchGcpConfidentialSpaceJwks: no fetch implementation available');
  let jwksUri = opts.jwksUri;
  if (!jwksUri) {
    const base = issuer.replace(/\/+$/, '');
    const confUrl = `${base}/.well-known/openid-configuration`;
    const confRes = await f(confUrl);
    if (!confRes.ok) throw new Error(`Confidential Space OpenID config fetch failed: HTTP ${confRes.status} for ${confUrl}`);
    const conf: unknown = await confRes.json();
    const confRec = asRecord(conf);
    const uri = confRec ? asString(confRec.jwks_uri) : undefined;
    if (!uri) throw new Error('Confidential Space OpenID config carries no jwks_uri');
    jwksUri = uri;
  }
  const res = await f(jwksUri);
  if (!res.ok) throw new Error(`Confidential Space JWKS fetch failed: HTTP ${res.status} for ${jwksUri}`);
  const body: unknown = await res.json();
  const rec = asRecord(body);
  const keys = rec ? rec.keys : undefined;
  if (!Array.isArray(keys)) throw new Error('Confidential Space JWKS fetch: response has no keys array');
  const out: GcpJwk[] = [];
  for (const k of keys) {
    const kr = asRecord(k);
    if (!kr) continue;
    out.push({
      ...(asString(kr.kid) !== undefined ? { kid: asString(kr.kid) } : {}),
      ...(asString(kr.kty) !== undefined ? { kty: asString(kr.kty) } : {}),
      ...(asString(kr.alg) !== undefined ? { alg: asString(kr.alg) } : {}),
      ...(asString(kr.use) !== undefined ? { use: asString(kr.use) } : {}),
      ...(asString(kr.n) !== undefined ? { n: asString(kr.n) } : {}),
      ...(asString(kr.e) !== undefined ? { e: asString(kr.e) } : {}),
      ...(asString(kr.crv) !== undefined ? { crv: asString(kr.crv) } : {}),
      ...(asString(kr.x) !== undefined ? { x: asString(kr.x) } : {}),
      ...(asString(kr.y) !== undefined ? { y: asString(kr.y) } : {}),
      ...(asStringArray(kr.x5c) !== undefined ? { x5c: asStringArray(kr.x5c) } : {}),
    });
  }
  return { keys: out };
}
