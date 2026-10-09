/**
 * L0 HARDWARE backend — Microsoft Azure Attestation (MAA) JWT VERIFIER.
 *
 * A pluggable attestation root (the `HardwareAttestationVerifier` seam declared in `attestation.ts`,
 * built to the SAME shape as `attest-amd-snp.ts` / `attest-intel-dcap.ts`) for the AZURE-NATIVE
 * attestation path. On an Azure Confidential VM the guest does not hand a raw SEV-SNP report or a raw
 * Intel TDX DCAP quote to the relying party; instead it calls the Microsoft Azure Attestation service,
 * which validates the hardware evidence and returns a signed **MAA JWT** (a JWS). Azure issues an MAA
 * token for BOTH isolation technologies — AMD SEV-SNP (`x-ms-attestation-type: "sevsnpvm"`) and Intel
 * TDX (`"tdxvm"`) — so this ONE root natively covers both on Azure, and slots into the multi-root
 * N-of-M policy exactly like any other root (each root carrying its own suite label).
 *
 * ── WHAT THIS IS, HONESTLY. ─────────────────────────────────────────────────────────────────────────
 * This is the Azure-NATIVE attestation path: the trust root is the configured MAA instance's X.509
 * token-signing chain (MAA signs its JWTs with certs whose chain roots in a Microsoft/MAA CA). It is
 * COMPLEMENTARY to, not a replacement for:
 *   - `attest-amd-snp.ts` (`createAmdSnpVerifier`) — direct AMD VCEK→ASK→ARK
 *     verification of a raw SEV-SNP report, rooted in AMD's silicon chain;
 *   - `attest-intel-dcap.ts` (`createIntelDcapVerifier`) — direct Intel DCAP quote + PCK→Root-CA verification.
 * Using MAA moves the raw-evidence verification to Microsoft and roots trust in MAA's signing chain
 * instead of the CPU vendor's. That is a deliberate trust choice: you are trusting the configured MAA
 * instance (and the CA its token-signing cert chains to) to have faithfully verified the underlying
 * SEV-SNP/TDX evidence. The suite is CLASSICAL (MAA signs ES256 / RS256 today); its value in a multi-root
 * policy is INDEPENDENCE from the raw-DCAP / direct-SEV-SNP roots, not post-quantum strength.
 *
 * ── WHAT IS CRYPTOGRAPHICALLY VERIFIED (real crypto, exercised end-to-end by the tests). ─────────────
 *   1. JWS parse (header.payload.signature) and signature verification under the key identified by the
 *      header `kid`, located in the MAA instance's JWKS (`x5c`). ES256 is verified with @noble/curves
 *      P-256 over SHA-256; RS256 with node/OpenSSL (RSA-SHA256) — the same `node:crypto` X.509 engine
 *      `hardware-sevsnp.ts` uses for the AMD RSA chain.
 *   2. The signing cert's `x5c` chain is verified link-by-link (each cert signed by the next) UP TO a
 *      CONFIGURED trusted MAA root/instance anchor (by SPKI SHA-256 fingerprint, or an anchor cert that
 *      signs the chain top). The root of trust is NEVER taken from the chain itself. Cert validity windows
 *      are enforced. Untrusted issuer / broken chain / expired cert → FAIL CLOSED.
 *   3. Standard claims: `iss` must equal a CONFIGURED trusted MAA instance URL; the `exp`/`iat`/`nbf`
 *      window is enforced against the server clock (`nowMs`), with optional skew.
 *   4. Azure claims: `x-ms-isolation-tee.x-ms-attestation-type` ∈ {"sevsnpvm","tdxvm"}; the hardware
 *      measurement (`x-ms-sevsnpvm-launchmeasurement` / `x-ms-tdx-mrtd`) is gated by a NON-EMPTY policy
 *      allowlist (no accept-all); and the report-data claim (`x-ms-sevsnpvm-reportdata` / the TDX
 *      report-data) is bound to the PCA challenge `attestationBinding({holder,grant,epoch,nonce})`.
 *   5. The measured identity (isolation type + hardware measurement) flows back through the usual
 *      agent_binding match in `createAttestationVerifier`, exactly like the other roots.
 *
 * ── AZURE report-data NUANCE (why `reportDataHash` exists). ─────────────────────────────────────────
 * On an Azure CVM the guest does not always control the raw 64-byte SEV-SNP/TDX report_data directly —
 * the paravisor / guest-attestation client often places a HASH of the guest-supplied runtime data there
 * (see the AZURE CONFIDENTIAL-VM NUANCE note in `hardware-sevsnp.ts`). The MAA token reflects the
 * report-data it verified. So the guest is expected to put the PCA `attestationBinding` into the data it
 * hands the attestation call such that the token's report-data equals it — or, when the platform hashes
 * that data, set `reportDataHash` to the hash it applies (`sha256` / `sha512`) so the verifier compares
 * `H(attestationBinding(expected))` against the claim. Default `none` (direct equality).
 *
 * NO NETWORK I/O: like the other roots, this module never reaches the network on its own. The MAA JWT +
 * the instance JWKS are supplied via the `resolveEvidence` seam (fetch them out-of-band from the token's
 * `jku` / the issuer's `/certs` endpoint). `fetchMaaJwks` is a guarded, optional helper for that fetch.
 *
 * References: Microsoft Azure Attestation — "Examples of an attestation token" (SEV-SNP and TDX claim
 * sets, `x-ms-isolation-tee`, `x-ms-sevsnpvm-*` / `x-ms-tdx-*`); RFC 7515 (JWS) `x5c`/`kid`; RFC 7517 (JWK).
 */
import { p256 } from '@noble/curves/p256';
import { sha512 } from '@noble/hashes/sha512';
import { sha256, utf8 } from './hash';
import { attestationBinding } from './attestation';
import type {
  AttestationDocument,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** The signature suites a Microsoft Azure Attestation instance signs its JWTs with today (both classical). */
export const AZURE_MAA_SUITES = ['ES256', 'RS256'] as const;
/** A JOSE `alg` this verifier accepts for an MAA JWS. */
export type AzureMaaAlg = (typeof AZURE_MAA_SUITES)[number];

/** Audit label of this root's suite family (classical — see the module header's honest-scope note). */
export const AZURE_MAA_SUITE = 'azure-maa-jwt' as const;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Small, dependency-free helpers (typed; no `any`).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Lowercase hex of a byte array (stable identity string for measurements / report-data). */
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
function asBoolean(v: unknown): boolean | undefined {
  return typeof v === 'boolean' ? v : undefined;
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

/** `true` iff every byte is zero. */
function isHexString(s: string): boolean {
  return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

/**
 * Decode a byte-carrying claim flexibly: hex (optionally `0x`-prefixed), else base64url, else standard
 * base64. Returns null when the value decodes under none of them (caller fails closed). Report-data and
 * measurement claims in MAA tokens are hex; the base64 fallbacks make the binding robust to real-token
 * variance the user will validate against a captured token.
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

/** Left-pad (or validate) a big-endian field to exactly `n` bytes. Returns null if it is longer than `n`. */
function fixedWidthBE(bytes: Uint8Array, n: number): Uint8Array | null {
  if (bytes.length === n) return bytes;
  if (bytes.length > n) {
    // allow a single leading zero byte (DER-style) but nothing significant above width
    let i = 0;
    while (i < bytes.length - n && bytes[i] === 0) i++;
    if (bytes.length - i !== n) return null;
    return bytes.slice(i);
  }
  const out = new Uint8Array(n);
  out.set(bytes, n - bytes.length);
  return out;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// node:crypto (OpenSSL) — X.509 chain + RSA verify. Imported LAZILY so the @noble ES256 core carries no
// hard Node dependency; X.509 / RS256 are a Node deployment concern (as in hardware-sevsnp.ts).
// ════════════════════════════════════════════════════════════════════════════════════════════════

type NodeCrypto = typeof import('node:crypto');
let _nodeCryptoPromise: Promise<NodeCrypto> | null = null;
async function nodeCrypto(): Promise<NodeCrypto> {
  return (_nodeCryptoPromise ??= import('node:crypto'));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// JWS / JWK types.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** A parsed MAA JWS header (the fields this verifier reads). */
export interface MaaJwsHeader {
  alg: string;
  kid?: string;
  /** JWKS URI the signing key lives at (the MAA instance's `/certs`). Informational here. */
  jku?: string;
  /** X.509 cert chain (base64 DER, leaf first) — MAA may carry it in the header and/or the JWKS. */
  x5c?: string[];
  typ?: string;
}

/** A parsed MAA JWT. */
export interface ParsedMaaJwt {
  header: MaaJwsHeader;
  /** The decoded claim set (opaque; narrowed by the verifier). */
  payload: Record<string, unknown>;
  /** ASCII bytes of `base64url(header).base64url(payload)` — exactly what the signature covers. */
  signingInput: Uint8Array;
  /** The decoded JWS signature bytes. */
  signature: Uint8Array;
}

/** One JWK in an MAA JWKS (the fields this verifier reads). */
export interface MaaJwk {
  kid?: string;
  kty?: string;
  alg?: string;
  /** X.509 cert chain, base64 DER, leaf first. MAA JWKS carries the signing key as this chain. */
  x5c?: string[];
}

/** An MAA instance JWKS (`<issuer>/certs`). */
export interface MaaJwks {
  keys: MaaJwk[];
}

/**
 * Parse a compact JWS MAA token into header/payload/signature + the signing input. FAILS (throws) on a
 * structurally invalid token; never verifies anything on its own.
 */
export function parseMaaJwt(token: string): ParsedMaaJwt {
  if (typeof token !== 'string' || token.length === 0) throw new TypeError('parseMaaJwt: empty token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new TypeError('parseMaaJwt: a compact JWS has exactly three dot-separated parts');
  const [h, p, s] = parts;
  if (!h || !p || s === undefined || s.length === 0) throw new TypeError('parseMaaJwt: empty JWS segment');
  let headerObj: unknown;
  let payloadObj: unknown;
  try {
    headerObj = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
    payloadObj = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  } catch (e) {
    throw new TypeError(`parseMaaJwt: malformed JSON segment: ${e instanceof Error ? e.message : 'unknown'}`);
  }
  const headerRec = asRecord(headerObj);
  const payloadRec = asRecord(payloadObj);
  if (!headerRec) throw new TypeError('parseMaaJwt: header is not a JSON object');
  if (!payloadRec) throw new TypeError('parseMaaJwt: payload is not a JSON object');
  const alg = asString(headerRec.alg);
  if (!alg) throw new TypeError('parseMaaJwt: header has no alg');
  const header: MaaJwsHeader = {
    alg,
    ...(asString(headerRec.kid) !== undefined ? { kid: asString(headerRec.kid) } : {}),
    ...(asString(headerRec.jku) !== undefined ? { jku: asString(headerRec.jku) } : {}),
    ...(asStringArray(headerRec.x5c) !== undefined ? { x5c: asStringArray(headerRec.x5c) } : {}),
    ...(asString(headerRec.typ) !== undefined ? { typ: asString(headerRec.typ) } : {}),
  };
  const signature = new Uint8Array(Buffer.from(s, 'base64url'));
  if (signature.length === 0) throw new TypeError('parseMaaJwt: empty signature');
  return { header, payload: payloadRec, signingInput: utf8(`${h}.${p}`), signature };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Trust anchors + the x5c chain verifier.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The configured trust anchor(s) the MAA token-signing `x5c` chain must root in. At least one anchor is
 * REQUIRED (construction throws otherwise — no accept-all). The root of trust is the CONFIGURED anchor,
 * never a cert taken from the supplied chain.
 */
export interface AzureMaaTrustAnchors {
  /**
   * Trusted root CA certificates, PEM. The chain is anchored when its top cert is signed by one of these
   * (or a chain cert's SPKI matches one's). These are the MAA instance's / Microsoft's token-signing roots.
   */
  rootCertsPem?: string[];
  /**
   * Trusted SPKI SHA-256 fingerprints (lowercase hex). The chain is anchored when some cert in it has a
   * matching SPKI fingerprint (pins the exact key — e.g. a self-contained MAA signing cert / instance leaf).
   */
  rootSpkiSha256?: string[];
}

/** The outcome of x5c chain verification. */
export interface MaaChainResult {
  ok: boolean;
  reason?: string;
  /** The leaf (signing) certificate on success. */
  leaf?: import('node:crypto').X509Certificate;
  /** The leaf's SPKI SHA-256 fingerprint (lowercase hex), for audit. */
  leafSpkiSha256?: string;
}

interface ResolvedAnchors {
  fingerprints: Set<string>;
  rootKeys: import('node:crypto').KeyObject[];
}

async function resolveAnchors(anchors: AzureMaaTrustAnchors): Promise<ResolvedAnchors> {
  const { X509Certificate, createHash } = await nodeCrypto();
  const fingerprints = new Set<string>();
  for (const fp of anchors.rootSpkiSha256 ?? []) {
    if (typeof fp === 'string' && fp.length > 0) fingerprints.add(fp.toLowerCase());
  }
  const rootKeys: import('node:crypto').KeyObject[] = [];
  for (const pem of anchors.rootCertsPem ?? []) {
    const cert = new X509Certificate(pem);
    rootKeys.push(cert.publicKey);
    const spki = new Uint8Array(cert.publicKey.export({ type: 'spki', format: 'der' }));
    fingerprints.add(createHash('sha256').update(Buffer.from(spki)).digest('hex'));
  }
  return { fingerprints, rootKeys };
}

function spkiSha256(cert: import('node:crypto').X509Certificate, createHash: NodeCrypto['createHash']): string {
  const spki = new Uint8Array(cert.publicKey.export({ type: 'spki', format: 'der' }));
  return createHash('sha256').update(Buffer.from(spki)).digest('hex');
}

/** `true` iff `nowMs` (with skew) is inside the cert's validity window. */
function certValid(cert: import('node:crypto').X509Certificate, nowMs: number, skewMs: number): boolean {
  const vf = Date.parse(cert.validFrom);
  const vt = Date.parse(cert.validTo);
  if (!Number.isFinite(vf) || !Number.isFinite(vt)) return false;
  return nowMs + skewMs >= vf && nowMs - skewMs <= vt;
}

function safeCertVerify(cert: import('node:crypto').X509Certificate, key: import('node:crypto').KeyObject): boolean {
  try {
    return cert.verify(key);
  } catch {
    return false;
  }
}

/**
 * Verify an `x5c` chain (base64 DER, leaf first) to a configured trust anchor:
 *   1. every cert's validity window contains `nowMs` (± skew);
 *   2. if a cert's SPKI fingerprint matches a trusted anchor, that cert is the anchor and every link
 *      BELOW it must be signed by the one above it (leaf ⟵ … ⟵ anchor);
 *   3. otherwise the WHOLE chain must link (each cert signed by the next) AND the top cert must be signed
 *      by one of the configured external root keys.
 * FAILS CLOSED on an empty chain, a parse failure, an expired cert, a broken link, or no anchor.
 */
export async function verifyX5cChain(
  x5c: readonly string[],
  anchors: AzureMaaTrustAnchors,
  opts: { nowMs: number; clockSkewMs?: number },
): Promise<MaaChainResult> {
  try {
    const { X509Certificate, createHash } = await nodeCrypto();
    if (!Array.isArray(x5c) || x5c.length === 0) return { ok: false, reason: 'empty x5c certificate chain' };
    const skew = Number.isFinite(opts.clockSkewMs) ? Math.max(0, opts.clockSkewMs as number) : 0;

    const certs: import('node:crypto').X509Certificate[] = [];
    for (let i = 0; i < x5c.length; i++) {
      const b64 = x5c[i];
      if (typeof b64 !== 'string' || b64.length === 0) return { ok: false, reason: `empty x5c entry at index ${i}` };
      let cert: import('node:crypto').X509Certificate;
      try {
        cert = new X509Certificate(Buffer.from(b64, 'base64'));
      } catch (e) {
        return { ok: false, reason: `malformed x5c certificate at index ${i}: ${e instanceof Error ? e.message : 'unknown'}` };
      }
      if (!certValid(cert, opts.nowMs, skew)) return { ok: false, reason: `x5c certificate at index ${i} is outside its validity window` };
      certs.push(cert);
    }

    const resolved = await resolveAnchors(anchors);
    if (resolved.fingerprints.size === 0 && resolved.rootKeys.length === 0) {
      return { ok: false, reason: 'no MAA trust anchor configured (fail closed)' };
    }

    // (2) anchor by SPKI fingerprint of some cert in the chain.
    let anchorIdx = -1;
    for (let j = 0; j < certs.length; j++) {
      if (resolved.fingerprints.has(spkiSha256(certs[j]!, createHash))) {
        anchorIdx = j;
        break;
      }
    }
    if (anchorIdx >= 0) {
      for (let i = 0; i < anchorIdx; i++) {
        if (!safeCertVerify(certs[i]!, certs[i + 1]!.publicKey)) {
          return { ok: false, reason: `x5c link ${i} is not signed by the certificate above it` };
        }
      }
      const leaf = certs[0]!;
      return { ok: true, leaf, leafSpkiSha256: spkiSha256(leaf, createHash) };
    }

    // (3) no in-chain anchor: the whole chain must link and the top must be signed by an external root.
    for (let i = 0; i < certs.length - 1; i++) {
      if (!safeCertVerify(certs[i]!, certs[i + 1]!.publicKey)) {
        return { ok: false, reason: `x5c link ${i} is not signed by the certificate above it` };
      }
    }
    const top = certs[certs.length - 1]!;
    if (!resolved.rootKeys.some((k) => safeCertVerify(top, k))) {
      return { ok: false, reason: 'x5c chain does not anchor in a configured MAA trust root' };
    }
    const leaf = certs[0]!;
    return { ok: true, leaf, leafSpkiSha256: spkiSha256(leaf, createHash) };
  } catch (e) {
    return { ok: false, reason: `x5c chain verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// JWS signature verification under the leaf certificate's key (ES256 via @noble, RS256 via node/OpenSSL).
// ════════════════════════════════════════════════════════════════════════════════════════════════

async function verifyJwsSignature(parsed: ParsedMaaJwt, leaf: import('node:crypto').X509Certificate): Promise<string | null> {
  const alg = parsed.header.alg;
  if (alg === 'ES256') {
    const jwk = leaf.publicKey.export({ format: 'jwk' });
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') return `ES256 token but signing key is ${String(jwk.kty)}/${String(jwk.crv)} (not EC P-256)`;
    if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return 'ES256 signing key has no EC coordinates';
    const x = fixedWidthBE(new Uint8Array(Buffer.from(jwk.x, 'base64url')), 32);
    const y = fixedWidthBE(new Uint8Array(Buffer.from(jwk.y, 'base64url')), 32);
    if (!x || !y) return 'ES256 signing key coordinates are not 32 bytes';
    if (parsed.signature.length !== 64) return `ES256 signature is ${parsed.signature.length} bytes (expected 64: r‖s)`;
    const point = new Uint8Array(65);
    point[0] = 0x04;
    point.set(x, 1);
    point.set(y, 33);
    let ok = false;
    try {
      // lowS:false — JWS ES256 does not require low-S normalization.
      ok = p256.verify(parsed.signature, sha256(parsed.signingInput), point, { lowS: false });
    } catch {
      ok = false;
    }
    return ok ? null : 'JWS ES256 signature does not verify under the MAA signing key';
  }
  if (alg === 'RS256') {
    const jwk = leaf.publicKey.export({ format: 'jwk' });
    if (jwk.kty !== 'RSA') return `RS256 token but signing key is ${String(jwk.kty)} (not RSA)`;
    const { verify } = await nodeCrypto();
    let ok = false;
    try {
      ok = verify('RSA-SHA256', parsed.signingInput, leaf.publicKey, parsed.signature);
    } catch {
      ok = false;
    }
    return ok ? null : 'JWS RS256 signature does not verify under the MAA signing key';
  }
  return `unsupported JWS alg '${alg}' (MAA uses ES256 / RS256)`;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Azure claim locations + acceptance policy.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** The Azure isolation (TEE) types this root understands. */
export type AzureIsolationType = 'sevsnpvm' | 'tdxvm';

/** SEV-SNP launch-measurement claim keys (inside `x-ms-isolation-tee`). */
const SEVSNP_MEASUREMENT_KEYS = ['x-ms-sevsnpvm-launchmeasurement'] as const;
/** SEV-SNP report-data claim keys. */
const SEVSNP_REPORTDATA_KEYS = ['x-ms-sevsnpvm-reportdata'] as const;
/** SEV-SNP host-data claim keys. */
const SEVSNP_HOSTDATA_KEYS = ['x-ms-sevsnpvm-hostdata'] as const;
/** SEV-SNP debuggable claim key. */
const SEVSNP_DEBUG_KEY = 'x-ms-sevsnpvm-is-debuggable';
/** SEV-SNP reported-TCB SVN claims (name in policy → MAA claim key → hostAsserted key). */
const SEVSNP_TCB_CLAIMS = [
  ['bootloader', 'x-ms-sevsnpvm-bootloader-svn', 'bootloader_svn'],
  ['snp', 'x-ms-sevsnpvm-snpfw-svn', 'snpfw_svn'],
  ['microcode', 'x-ms-sevsnpvm-microcode-svn', 'microcode_svn'],
  ['tee', 'x-ms-sevsnpvm-tee-svn', 'tee_svn'],
] as const;
/** TDX MRTD claim keys. */
// Real MAA TDX tokens (api 2023-04-01-preview) use snake_case top-level `tdx_*` claims; older/preview shapes used `x-ms-tdx-*`.
const TDX_MRTD_KEYS = ['tdx_mrtd', 'x-ms-tdx-mrtd'] as const;
/** TDX report-data claim keys (Azure has used both spellings across previews). */
const TDX_REPORTDATA_KEYS = ['tdx_report_data', 'x-ms-tdx-report-data', 'x-ms-tdx-reportdata'] as const;
/** TDX RTMR0 claim keys. */
const TDX_RTMR0_KEYS = ['tdx_rtmr0', 'x-ms-tdx-rtmr0'] as const;

/** Context a `deriveIdentity` override receives. */
export interface AzureMaaIdentityContext {
  isolationType: AzureIsolationType;
  /** The hardware measurement (SEV-SNP launch measurement / TDX MRTD) as lowercase hex. */
  runtimeMeasurement: string;
  /** The TEE claim subtree (`x-ms-isolation-tee`, or the payload when absent). */
  teeClaims: Record<string, unknown>;
  /** The full token payload. */
  payload: Record<string, unknown>;
}

/**
 * Acceptance policy. At least one of `sevSnpMeasurements` / `tdxMrtds` MUST be a non-empty allowlist
 * (construction throws otherwise — there is no accept-all). A token whose isolation type has no
 * configured allowlist is rejected. All hex comparisons are lowercase.
 */
export interface AzureMaaPolicy {
  /** Allowed SEV-SNP launch measurements (hex). Required+non-empty to accept a `sevsnpvm` token. */
  sevSnpMeasurements?: string[];
  /** Allowed TDX MRTD values (hex). Required+non-empty to accept a `tdxvm` token. */
  tdxMrtds?: string[];
  /** Optional SEV-SNP HOST_DATA allowlist (hex). Host-asserted; a launch-config gate only. */
  sevSnpHostData?: string[];
  /** Optional TDX RTMR0 allowlist (hex). */
  tdxRtmrs?: string[];
  /**
   * SEV-SNP minimum reported TCB (SVNs from the MAA claims `x-ms-sevsnpvm-bootloader-svn` / `-snpfw-svn` /
   * `-microcode-svn` / `-tee-svn`). Each configured floor is a non-negative integer; the token's claim MUST be present,
   * an integer, and >= the floor (a missing/non-integer claim fails closed). Unset fields are not gated. The reported
   * values are surfaced in `hostAsserted` (`bootloader_svn`, `snpfw_svn`, `microcode_svn`, `tee_svn`) whenever present.
   */
  sevSnpMinTcb?: { bootloader?: number; snp?: number; microcode?: number; tee?: number };
  /** Accept a SEV-SNP token whose guest is debuggable (`x-ms-sevsnpvm-is-debuggable: true`). Default false. */
  allowDebug?: boolean;
  /**
   * Bind the PCA challenge through the guest's RUNTIME `user-data` instead of the raw `report_data` claim.
   * This is how Azure CVMs actually work: the paravisor sets the quote's `report_data` to
   * sha256(runtime data JSON) and the guest's 64-byte `user-data` lives inside that JSON. When the caller
   * submits the runtime data to MAA, the service validates sha256(runtimeData) == report_data[0:32] and only
   * then emits the `x-ms-runtime` claim — so a token carrying `x-ms-runtime.user-data` equal to
   * `attestationBinding(expected)` proves (under MAA's signature) that a genuine TD bound that value.
   * Default false (direct `report_data` equality, for guests that control report_data themselves).
   */
  runtimeUserDataBinding?: boolean;
  /**
   * TDX only: accepted values of the MAA `attester_tcb_status` claim (Intel TCB evaluation by MAA). Default
   * `['UpToDate','SWHardeningNeeded']`. Applied whenever the claim is present; a token without the claim
   * (older shapes) is not gated on it. The evaluated status is surfaced in `hostAsserted.tcb_status`.
   */
  tdxAllowedTcbStatuses?: string[];
  /**
   * Hash applied to the PCA binding before comparing with the token's report-data claim (see the AZURE
   * report-data NUANCE note): `none` = direct 64-byte equality (default); `sha256` / `sha512` = compare
   * `H(attestationBinding(expected))`.
   */
  reportDataHash?: 'none' | 'sha256' | 'sha512';
  /** Map a verified token into the `MeasuredIdentity` agent_binding is checked against (override to customise). */
  deriveIdentity?: (ctx: AzureMaaIdentityContext) => MeasuredIdentity;
}

export interface AzureMaaVerifierOptions {
  /**
   * CONFIGURED trusted MAA instance issuer URLs. The token's `iss` MUST equal one of these exactly.
   * REQUIRED and NON-EMPTY (construction throws otherwise). E.g.
   * `https://sharedeus.eus.attest.azure.net` or your private instance URL.
   */
  trustedIssuers: string[];
  /** The trust anchor(s) the token-signing `x5c` chain must root in (at least one required). */
  trustAnchors: AzureMaaTrustAnchors;
  /** Acceptance policy (SEV-SNP and/or TDX measurement allowlist — at least one required). */
  policy: AzureMaaPolicy;
  /**
   * EVIDENCE SEAM: produce the MAA JWT (and, when the signing `x5c` lives in the JWKS rather than the
   * header, the instance JWKS) for an action. Production reads the token carried with the attestation
   * document and the JWKS fetched out-of-band from the token `jku` / issuer `/certs`. If omitted, the
   * verifier fails closed (no evidence).
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => MaaEvidence | undefined | Promise<MaaEvidence | undefined>;
  /** Allowed clock skew (ms) for the JWT time window + cert validity (default 0). */
  clockSkewMs?: number;
}

/** The evidence for one action: the MAA JWT and (optionally) the instance JWKS. */
export interface MaaEvidence {
  /** The compact MAA JWS token. */
  token: string;
  /** The MAA instance JWKS (`<issuer>/certs`). Optional when the signing `x5c` is carried in the header. */
  jwks?: MaaJwks;
}

/** Resolve the signing `x5c` chain: JWKS entry matched by `kid`, else the header's own `x5c`. */
function resolveSigningX5c(header: MaaJwsHeader, jwks: MaaJwks | undefined): { x5c?: string[]; reason?: string } {
  if (jwks && Array.isArray(jwks.keys) && jwks.keys.length > 0) {
    if (typeof header.kid !== 'string' || header.kid.length === 0) {
      // No kid: only safe if exactly one key is published.
      const only = jwks.keys.length === 1 ? jwks.keys[0] : undefined;
      if (!only) return { reason: 'token has no kid and the JWKS publishes multiple keys (ambiguous)' };
      return only.x5c && only.x5c.length > 0 ? { x5c: only.x5c } : { reason: 'JWKS key carries no x5c chain' };
    }
    const match = jwks.keys.find((k) => k.kid === header.kid);
    if (!match) return { reason: `no JWKS key matches the token kid '${header.kid}' (untrusted signer)` };
    if (!match.x5c || match.x5c.length === 0) return { reason: `JWKS key '${header.kid}' carries no x5c chain` };
    return { x5c: match.x5c };
  }
  if (header.x5c && header.x5c.length > 0) return { x5c: header.x5c };
  return { reason: 'no signing x5c available (no JWKS and no header x5c)' };
}

function transformBinding(binding: Uint8Array, mode: AzureMaaPolicy['reportDataHash']): Uint8Array {
  if (mode === 'sha256') return sha256(binding);
  if (mode === 'sha512') return sha512(binding);
  return binding;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// The Azure MAA HardwareAttestationVerifier.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Build a `HardwareAttestationVerifier` backed by Microsoft Azure Attestation. Given an attestation
 * document + context it resolves the MAA JWT (+ instance JWKS) via the evidence seam, then:
 *   1. parses the JWS;
 *   2. resolves the signing `x5c` chain (JWKS-by-kid, else the header) and verifies it to a CONFIGURED
 *      MAA trust anchor, enforcing cert validity windows;
 *   3. verifies the JWS signature under the leaf cert (ES256 via @noble P-256 / RS256 via node OpenSSL);
 *   4. checks `iss` ∈ trusted instances and the `exp`/`iat`/`nbf` window against `nowMs`;
 *   5. reads `x-ms-isolation-tee.x-ms-attestation-type` (sevsnpvm | tdxvm), binds the report-data claim
 *      to `attestationBinding(expected)`, and gates the hardware measurement by the NON-EMPTY policy
 *      allowlist for that isolation type;
 *   6. returns the hardware-measured identity — which `createAttestationVerifier` then matches against
 *      the grant's agent_binding (one MAA root covers both SEV-SNP and TDX on Azure).
 * Fails CLOSED with a specific reason on any mismatch or error.
 *
 * Wire it in: `createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: createAzureMaaVerifier(opts), resolveDocument })`,
 * or add it as one `AttestationRoot` in a `createMultiRootVerifier` policy.
 */
export function createAzureMaaVerifier(opts: AzureMaaVerifierOptions): HardwareAttestationVerifier {
  if (!opts || !Array.isArray(opts.trustedIssuers) || opts.trustedIssuers.length === 0) {
    throw new TypeError('createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs');
  }
  for (const iss of opts.trustedIssuers) {
    if (typeof iss !== 'string' || iss.length === 0) throw new TypeError('createAzureMaaVerifier: every trusted issuer must be a non-empty URL string');
  }
  const anchors = opts.trustAnchors;
  const anchorCount = (anchors?.rootCertsPem?.length ?? 0) + (anchors?.rootSpkiSha256?.length ?? 0);
  if (anchorCount === 0) {
    throw new TypeError('createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted');
  }
  const policy = opts.policy;
  const hasSevSnp = Array.isArray(policy?.sevSnpMeasurements) && policy.sevSnpMeasurements.length > 0;
  const hasTdx = Array.isArray(policy?.tdxMrtds) && policy.tdxMrtds.length > 0;
  if (!policy || (!hasSevSnp && !hasTdx)) {
    throw new TypeError('createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)');
  }
  if (policy.sevSnpMinTcb !== undefined) {
    const m = policy.sevSnpMinTcb as Record<string, unknown>;
    if (typeof m !== 'object' || m === null || Array.isArray(m)) throw new TypeError('createAzureMaaVerifier: policy.sevSnpMinTcb must be an object');
    for (const [k, v] of Object.entries(m)) {
      if (!SEVSNP_TCB_CLAIMS.some(([name]) => name === k)) throw new TypeError(`createAzureMaaVerifier: policy.sevSnpMinTcb.${k} is not a known field (bootloader | snp | microcode | tee)`);
      if (v !== undefined && (typeof v !== 'number' || !Number.isInteger(v) || v < 0)) throw new TypeError(`createAzureMaaVerifier: policy.sevSnpMinTcb.${k} must be a non-negative integer`);
    }
  }
  const trustedIssuers = new Set(opts.trustedIssuers);
  const skew = Number.isFinite(opts.clockSkewMs) ? Math.max(0, opts.clockSkewMs as number) : 0;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no Azure MAA evidence resolver configured (fail closed)');
        const evidence = await opts.resolveEvidence(input.document, input.ctx);
        if (!evidence || typeof evidence.token !== 'string' || evidence.token.length === 0) {
          return fail('no Azure MAA token for this action');
        }

        // (1) parse
        let parsed: ParsedMaaJwt;
        try {
          parsed = parseMaaJwt(evidence.token);
        } catch (e) {
          return fail(`MAA token parse failed: ${e instanceof Error ? e.message : 'unknown'}`);
        }
        if (parsed.header.alg !== 'ES256' && parsed.header.alg !== 'RS256') {
          return fail(`unsupported JWS alg '${parsed.header.alg}' (MAA uses ES256 / RS256)`);
        }

        // (2) signing x5c chain to a configured MAA trust anchor
        const signing = resolveSigningX5c(parsed.header, evidence.jwks);
        if (!signing.x5c) return fail(signing.reason ?? 'no signing x5c available');
        const chain = await verifyX5cChain(signing.x5c, anchors, { nowMs: input.nowMs, clockSkewMs: skew });
        if (!chain.ok || !chain.leaf) return fail(`MAA signing chain invalid: ${chain.reason ?? 'untrusted'}`);

        // (3) JWS signature under the leaf cert
        const sigErr = await verifyJwsSignature(parsed, chain.leaf);
        if (sigErr) return fail(sigErr);

        // (4) standard claims: iss + time window
        const iss = asString(parsed.payload.iss);
        if (!iss || !trustedIssuers.has(iss)) return fail(`token iss '${String(iss)}' is not a configured trusted MAA instance`);
        const nowSec = Math.floor(input.nowMs / 1000);
        const skewSec = Math.ceil(skew / 1000);
        const exp = asNumber(parsed.payload.exp);
        const iat = asNumber(parsed.payload.iat);
        const nbf = asNumber(parsed.payload.nbf);
        if (exp === undefined) return fail('token has no exp (cannot bound validity — fail closed)');
        if (nowSec - skewSec > exp) return fail('MAA token expired');
        if (nbf !== undefined && nowSec + skewSec < nbf) return fail('MAA token not yet valid (nbf)');
        if (iat !== undefined && nowSec + skewSec < iat) return fail('MAA token issued in the future (iat)');

        // (5) Azure isolation-tee claims
        const isolation = asRecord(parsed.payload['x-ms-isolation-tee']);
        const teeClaims = isolation ?? parsed.payload;
        const isolationType = asString(teeClaims['x-ms-attestation-type']) ?? asString(parsed.payload['x-ms-attestation-type']);
        if (isolationType !== 'sevsnpvm' && isolationType !== 'tdxvm') {
          return fail(`unexpected x-ms-attestation-type '${String(isolationType)}' (expected sevsnpvm | tdxvm)`);
        }

        // (5a) bind the PCA challenge
        if (!input.expected) return fail('no expected attestation binding supplied');
        if (policy.runtimeUserDataBinding === true) {
          let rawBinding: Uint8Array;
          try {
            rawBinding = attestationBinding(input.expected);
          } catch (e) {
            return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
          }
          const runtime = asRecord(parsed.payload['x-ms-runtime']);
          if (!runtime) return fail('token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)');
          const userData = asString(runtime['user-data']);
          if (!userData) return fail('x-ms-runtime carries no user-data to bind the PCA challenge');
          const userDataBytes = decodeClaimBytes(userData);
          if (!userDataBytes || !timingSafeEq(userDataBytes, rawBinding)) {
            return fail('runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)');
          }
        } else {
          let bindingBytes: Uint8Array;
          try {
            bindingBytes = transformBinding(attestationBinding(input.expected), policy.reportDataHash);
          } catch (e) {
            return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
          }
          const reportDataClaim = firstString(teeClaims, isolationType === 'sevsnpvm' ? SEVSNP_REPORTDATA_KEYS : TDX_REPORTDATA_KEYS);
          if (!reportDataClaim) return fail('token carries no report-data claim to bind the PCA challenge');
          const reportDataBytes = decodeClaimBytes(reportDataClaim);
          if (!reportDataBytes) return fail('report-data claim is not decodable (hex/base64)');
          if (!timingSafeEq(reportDataBytes, bindingBytes)) {
            return fail('report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)');
          }
        }

        // (5b) isolation-type policy + measured identity
        if (isolationType === 'sevsnpvm') {
          if (!hasSevSnp) return fail('sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)');
          const measurement = firstString(teeClaims, SEVSNP_MEASUREMENT_KEYS);
          if (!measurement) return fail('sevsnpvm token carries no launch-measurement claim');
          const mHex = measurement.toLowerCase();
          if (!policy.sevSnpMeasurements!.map((x) => x.toLowerCase()).includes(mHex)) {
            return fail('SEV-SNP launch measurement not in policy allowlist');
          }
          const debuggable = asBoolean(teeClaims[SEVSNP_DEBUG_KEY]);
          if (policy.allowDebug !== true && debuggable === true) return fail('SEV-SNP guest is debuggable (no confidentiality)');
          const hostData = firstString(teeClaims, SEVSNP_HOSTDATA_KEYS);
          if (Array.isArray(policy.sevSnpHostData) && policy.sevSnpHostData.length > 0) {
            if (!hostData || !policy.sevSnpHostData.map((x) => x.toLowerCase()).includes(hostData.toLowerCase())) {
              return fail('SEV-SNP host-data not in policy allowlist');
            }
          }
          // reported-TCB floors (fail closed on a missing / non-integer claim whenever a floor is configured)
          const tcbReported: Record<string, string> = {};
          for (const [name, claim, hostKey] of SEVSNP_TCB_CLAIMS) {
            const raw = teeClaims[claim];
            const isSvn = typeof raw === 'number' && Number.isInteger(raw) && raw >= 0;
            if (isSvn) tcbReported[hostKey] = String(raw);
            const floor = policy.sevSnpMinTcb?.[name];
            if (floor === undefined) continue;
            if (!isSvn) return fail(`SEV-SNP ${name} SVN claim '${claim}' is missing or not a non-negative integer (policy requires a minimum)`);
            if (raw < floor) return fail(`SEV-SNP ${name} SVN ${raw} is below the policy minimum ${floor}`);
          }
          const measured = policy.deriveIdentity
            ? policy.deriveIdentity({ isolationType, runtimeMeasurement: mHex, teeClaims, payload: parsed.payload })
            : { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: mHex, operator: '' };
          const hostAsserted: Record<string, string> = { attestation_type: 'sevsnpvm', ...tcbReported };
          if (hostData) hostAsserted.host_data = hostData.toLowerCase();
          return { ok: true, bound: true, measured, hostAsserted };
        }

        // tdxvm
        if (!hasTdx) return fail('tdxvm token but policy configures no TDX MRTD allowlist (fail closed)');
        const mrtd = firstString(teeClaims, TDX_MRTD_KEYS);
        if (!mrtd) return fail('tdxvm token carries no MRTD claim');
        const mrtdHex = mrtd.toLowerCase();
        if (!policy.tdxMrtds!.map((x) => x.toLowerCase()).includes(mrtdHex)) {
          return fail('TDX MRTD not in policy allowlist');
        }
        // debug TDs have no confidentiality: reject unless explicitly allowed (fail closed on either signal)
        const tdDebug = asBoolean(teeClaims['tdx_td_attributes_debug']);
        const dbgstat = asString(teeClaims['dbgstat']);
        if (policy.allowDebug !== true && (tdDebug === true || (dbgstat !== undefined && dbgstat !== 'disabled'))) {
          return fail('TDX guest is debuggable (no confidentiality)');
        }
        const tcbStatus = asString(teeClaims['attester_tcb_status']);
        if (tcbStatus !== undefined) {
          const okStatuses = policy.tdxAllowedTcbStatuses ?? ['UpToDate', 'SWHardeningNeeded'];
          if (!okStatuses.includes(tcbStatus)) return fail(`TDX platform TCB status '${tcbStatus}' is not accepted by policy`);
        }
        const rtmr0 = firstString(teeClaims, TDX_RTMR0_KEYS);
        if (Array.isArray(policy.tdxRtmrs) && policy.tdxRtmrs.length > 0) {
          if (!rtmr0 || !policy.tdxRtmrs.map((x) => x.toLowerCase()).includes(rtmr0.toLowerCase())) {
            return fail('TDX RTMR0 not in policy allowlist');
          }
        }
        const measured = policy.deriveIdentity
          ? policy.deriveIdentity({ isolationType, runtimeMeasurement: mrtdHex, teeClaims, payload: parsed.payload })
          : { model_id: '', weights_digest: '', weights_measured: false, runtime_measurement: mrtdHex, operator: '' };
        const hostAsserted: Record<string, string> = { attestation_type: 'tdxvm' };
        if (tcbStatus) hostAsserted.tcb_status = tcbStatus;
        if (rtmr0) hostAsserted.rtmr0 = rtmr0.toLowerCase();
        return { ok: true, bound: true, measured, hostAsserted };
      } catch (e) {
        return fail(`azure-maa verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// GUARDED, OPTIONAL network helper (NEVER called by this module on its own).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Fetch an MAA instance's JWKS from its documented `/certs` endpoint (NETWORK I/O — never auto-invoked;
 * wire it into your own `resolveEvidence`). Returns the parsed {@link MaaJwks}. Throws on a non-2xx
 * response or malformed body.
 */
export async function fetchMaaJwks(issuer: string, opts: { fetch?: typeof fetch; certsPath?: string } = {}): Promise<MaaJwks> {
  const f = opts.fetch ?? (globalThis.fetch as typeof fetch | undefined);
  if (!f) throw new Error('fetchMaaJwks: no fetch implementation available');
  const base = issuer.replace(/\/+$/, '');
  const url = `${base}${opts.certsPath ?? '/certs'}`;
  const res = await f(url);
  if (!res.ok) throw new Error(`MAA JWKS fetch failed: HTTP ${res.status} for ${url}`);
  const body: unknown = await res.json();
  const rec = asRecord(body);
  const keys = rec ? rec.keys : undefined;
  if (!Array.isArray(keys)) throw new Error('MAA JWKS fetch: response has no keys array');
  const out: MaaJwk[] = [];
  for (const k of keys) {
    const kr = asRecord(k);
    if (!kr) continue;
    out.push({
      ...(asString(kr.kid) !== undefined ? { kid: asString(kr.kid) } : {}),
      ...(asString(kr.kty) !== undefined ? { kty: asString(kr.kty) } : {}),
      ...(asString(kr.alg) !== undefined ? { alg: asString(kr.alg) } : {}),
      ...(asStringArray(kr.x5c) !== undefined ? { x5c: asStringArray(kr.x5c) } : {}),
    });
  }
  return { keys: out };
}
