/**
 * @atlasauth/pca-attest-eat — per-session attestation FRESHNESS + CHANNEL-BINDING for PCA (roadmap T3.5).
 *
 * ── The gap this closes ─────────────────────────────────────────────────────────────────────────────
 * TEE evidence (an AMD SEV-SNP `ATTESTATION_REPORT`, a TDX quote, …) captured ONCE at provisioning is a
 * static blob: nothing in a bare report ties it to the TLS connection or the request it is presented on,
 * so a captured-once report can be REPLAYED or RELAYED onto another session. PCA's silicon-root
 * verification (`@atlasauth/pca` `hardware-sevsnp.ts` → `verifyGenuineSevSnpReport` / `createSevSnpVerifier`)
 * proves the report is genuine and TCB-sound, and `attestation.ts` binds it to a server-issued nonce +
 * holder/grant/epoch — but that binding lives inside the PCA envelope. This package adds the complementary,
 * interoperable IETF freshness layer:
 *
 *   • it EMITS the evidence as an EAT — Entity Attestation Token, RFC 9711 — a signed token carrying the
 *     RATS "common claims" (`eat_nonce`, `cnf`, `ueid`, `oemid`, `dbgstat`, `measurements`, …);
 *   • it BINDS that EAT to the LIVE channel + a FRESH per-session nonce per the IETF SEAT working group's
 *     model ("Secure Evidence and Attestation Transport") and RA-TLS ("Integrating Remote Attestation with
 *     Transport Layer Security"): {@link bindChannel} derives a `cnf` (RFC 7800) from the TLS channel id /
 *     exporter so the evidence cannot be lifted to another channel, and the `eat_nonce` + `iat` make a
 *     stale or replayed token fail closed;
 *   • it APPRAISES the token via the RATS architecture's Verifier / appraisal-policy split (RFC 9334):
 *     {@link appraise} takes EVIDENCE, REFERENCE VALUES and ENDORSEMENTS as the three distinct RATS inputs
 *     and returns an attestation result with a trust tier.
 *
 * ── Alignment with @atlasauth/pca (NO parallel types) ───────────────────────────────────────────────
 * This package does NOT re-invent the SEV-SNP / measurement model. It reuses PCA's own types:
 *   • {@link MeasuredIdentity} (PCA `attestation.ts`) is the measured-identity carried in and appraised
 *     from the EAT (model_id / weights_digest / weights_measured / runtime_measurement / operator);
 *   • {@link ParsedSevSnpReport} + `parseSevSnpReport` / `serializeSevSnpReport` / `toHex` /
 *     `SEV_SNP_POLICY_DEBUG_BIT` (PCA `hardware-sevsnp.ts`) are reused for the report-level evidence and
 *     the version-tolerant parse. {@link evidenceFromReport} / {@link measuredFromReport} project a
 *     `ParsedSevSnpReport` into JSON-safe EAT claims.
 *
 * ── HONESTY: what this is and is NOT ───────────────────────────────────────────────────────────────
 * This is the FRESHNESS / CHANNEL-BINDING / EAT-EMISSION / APPRAISAL layer AND it now verifies the AMD
 * SEV-SNP silicon root of trust directly, with `node:crypto` only. {@link verifySevSnpSignature} checks the
 * report's real ECDSA-P384/SHA-384 signature over the signed region [0x000,0x2A0) under the VCEK public
 * key (converting AMD's little-endian r‖s to the IEEE-P1363 form node's verifier needs);
 * {@link verifyAmdCertChain} verifies the VCEK→ASK→ARK X.509 chain (VCEK signed by ASK, ASK by ARK, ARK
 * self-signed), honours each certificate's validity period, and pins the ARK to a known/injectable AMD
 * root fingerprint; {@link verifyAmdAttestation} composes the two (+ optional measurement / debug gates)
 * into one verdict. {@link appraise} and {@link verifyFreshAttestedEAT} are WIRED to this: an attestation
 * whose AMD signature + chain verify appraises to the strictly-higher `affirming-hw-rooted` tier, above the
 * `affirming` tier a software-vouched EAT can reach.
 *
 * The one honest residual: the AMD hardware root of trust (the ARK) is itself a CLASSICAL ECDSA/RSA key —
 * a hardware-vendor fact, not a gap in this code. The signature verification is REAL (no longer skipped);
 * the root's classical nature is labelled (see {@link AMD_SEV_SNP_HARDWARE_ROOT_LABEL}) and surfaced in the
 * appraisal reasons, never silently upgraded to a post-quantum guarantee this layer cannot provide. The
 * synthetic-ECDSA relationship model in `@atlasauth/pca`'s `hardware-sevsnp.ts` (`verifyVcekChain`, the
 * `@noble/curves` core, and `verifyGenuineSevSnpReport`'s offline real-silicon path) remains the library's
 * portable core; this package adds the `node:crypto`-only X.509 chain + report-signature verifier and the
 * freshness / channel-binding / appraisal wrapper around it. PCA proves the evidence is REAL; this package
 * proves it is REAL, FRESH and on THIS channel.
 *
 * ── Crypto ──────────────────────────────────────────────────────────────────────────────────────────
 * EATs are emitted as a compact JWS (RFC 9711 §7.3.1 permits a JWT/CWT representation; the `typ` header is
 * `eat+jwt`). Signing/verification use ONLY Node's built-in `node:crypto` — EdDSA (Ed25519, default) or
 * ES256 (ECDSA P-256). No third-party crypto dependency. The claim set is a minimal deterministic JSON
 * object built in a fixed field order.
 *
 * References: RFC 9711 (EAT), RFC 9334 (RATS Architecture), RFC 7800 (`cnf` PoP), RFC 8446 §7.5 / RFC 5705
 * (TLS exporter), draft-mihalcea-seat-use-cases (IETF SEAT), RA-TLS.
 */
import {
  createHash,
  generateKeyPairSync,
  randomBytes as nodeRandomBytes,
  sign as nodeSign,
  timingSafeEqual,
  verify as nodeVerify,
  X509Certificate,
  type KeyObject,
} from 'node:crypto';
import {
  AMD_MILAN_ARK_SPKI_SHA384,
  type MeasuredIdentity,
  type ParsedSevSnpReport,
  SEV_SNP_POLICY_DEBUG_BIT,
  SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384,
  parseSevSnpReport,
  toHex,
} from '@atlasauth/pca';

// Re-export the reused PCA types so consumers of this package do not reach into @atlasauth/pca for them.
export type { MeasuredIdentity, ParsedSevSnpReport };
// Re-export the real, pinned AMD Milan ARK trust anchor (SHA-384 of its SPKI DER) so consumers can pin it.
export { AMD_MILAN_ARK_SPKI_SHA384 };

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Constants.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** EAT media type as a JWT `typ` header — RFC 9711 registers `application/eat+jwt`. */
export const EAT_TYP = 'eat+jwt';

/** The JWS algorithms an EAT may be signed/verified with (node:crypto only). EdDSA keeps the leaf signer consistent with PCA. */
export type EatAlg = 'EdDSA' | 'ES256';

/** Default signing algorithm. */
export const DEFAULT_EAT_ALG: EatAlg = 'EdDSA';

const SUPPORTED_ALGS: readonly EatAlg[] = ['EdDSA', 'ES256'];

/**
 * Default ceiling (ms) on an EAT's age (now − iat) at verification. Mirrors PCA's
 * `MAX_ATTESTATION_AGE_MS` (5 min): L0 attestation epochs are short and re-derived, so a token older than
 * this is treated as a stale (replayable) quote and rejected.
 */
export const DEFAULT_MAX_AGE_MS = 5 * 60_000;

/** Domain separator mixed into a channel-id before hashing it into a `cnf.tls_exporter` (RA-TLS binding). */
export const CHANNEL_BINDING_DOMAIN = 'atlas-pca/eat-channel/v1';

/**
 * The end (exclusive) of an AMD SEV-SNP `ATTESTATION_REPORT`'s signed region: bytes [0x000, 0x2A0). The
 * ECDSA-P384/SHA-384 report signature is computed over exactly these bytes (the fields after it are the
 * r‖s signature block itself). Mirrors PCA's `OFF.SIGNED_END`.
 */
export const AMD_SEV_SNP_SIGNED_REGION_END = 0x2a0;

/**
 * A label for the AMD SEV-SNP hardware root of trust, used in appraisal reasons and
 * {@link AmdAttestationResult}. HONEST by design: the VCEK→ASK→ARK chain is a CLASSICAL ECDSA/RSA root (a
 * hardware-vendor fact) — the signature verification here is real, but the root is not post-quantum, and
 * this label keeps that distinction visible rather than implying a PQ guarantee this layer cannot give.
 */
export const AMD_SEV_SNP_HARDWARE_ROOT_LABEL =
  'amd-sev-snp/ecdsa-p384 (VCEK→ASK→ARK; classical hardware root, not post-quantum)';

/**
 * The KNOWN AMD ARK (AMD Root Key) trust anchors, pinned as the SHA-384 of each ARK's DER
 * SubjectPublicKeyInfo — the same fingerprint {@link verifyAmdCertChain} computes from a supplied ARK and
 * compares against (so the root of trust is NEVER taken from the chain itself). `Milan` is the real,
 * published AMD EPYC Milan root (shared with `@atlasauth/pca`'s `AMD_MILAN_ARK_SPKI_SHA384`).
 *
 * Each AMD CPU generation (Genoa, Bergamo, Turin, …) has its OWN ARK with its own fingerprint, published at
 * the AMD KDS `…/cert_chain` endpoint. Those are pinned by INJECTING their fingerprint via
 * `verifyAmdCertChain`'s / {@link verifyAmdAttestation}'s `rootFingerprint` option. We deliberately do NOT
 * hard-code an UNVERIFIED Genoa/Bergamo value here: a wrong pin is a latent fail-closed/accept-wrong-root
 * bug, so only the fingerprints we can vouch for ship as constants, and the rest are injectable.
 */
export const KNOWN_AMD_ARK_SPKI_SHA384: Readonly<Record<string, string>> = {
  Milan: AMD_MILAN_ARK_SPKI_SHA384,
};

/** The order (n) of the NIST P-384 curve — used to range-check report signature scalars (fail closed). */
const P384_ORDER = BigInt(
  '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
);

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Claim model (RFC 9711 common claims).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The `cnf` confirmation claim (RFC 7800) used for CHANNEL / KEY binding, RA-TLS style. At least one
 * member binds the evidence to the live transport so it is non-transferable:
 *   • `tls_exporter` — a value derived from the live TLS connection (RFC 8446 / RFC 5705 exporter), so the
 *     attestation only validates on the exact channel it was produced for;
 *   • `jkt` — the JWK SHA-256 thumbprint (RFC 7638) of the holder key the attester possesses (DPoP-style).
 * A resource server supplies the value it OBSERVES on the live channel as the expected `cnf`; a mismatch
 * means the evidence was lifted from another channel and {@link verifyChannelBinding} rejects it.
 */
export interface EatCnf {
  /** base64url of a value derived from the live TLS channel id / exporter (RA-TLS channel binding). */
  tls_exporter?: string;
  /** JWK SHA-256 thumbprint (RFC 7638) of the attester's holder key (proof-of-possession binding). */
  jkt?: string;
}

/**
 * One RFC 9711 measurement entry (a simplified projection of the EAT `measurements` claim): a labelled
 * digest the Verifier compares against reference values. `type` is the slot label (e.g. `launch`,
 * `weights`, `runtime`); `value` is its digest (lowercase hex or base64url).
 */
export interface EatMeasurement {
  /** Measurement slot label, e.g. `launch` / `measurement`, `weights`, `runtime`. */
  type: string;
  /** The digest value (lowercase hex or base64url). */
  value: string;
}

/**
 * A TCB (Trusted Computing Base) version, modelled TOLERANTLY across vendor formats:
 *   • a `number` — a packed numeric TCB;
 *   • a decimal `string` — the packed u64 TCB (SEV-SNP REPORTED_TCB, as {@link evidenceFromReport} emits);
 *   • a structured object of the SEV-SNP components (bootloader / tee / snp / microcode).
 * {@link appraise}'s reference-value comparison packs either shape into a comparable integer. Any OTHER
 * shape is treated as an UNKNOWN format and fails closed — see the 2025-10-27 GCP firmware drift note.
 */
export type TcbVersion =
  | number
  | string
  | { bootloader?: number; tee?: number; snp?: number; microcode?: number };

/** RFC 9711 `dbgstat` (debug status) claim values. */
export type DebugStatus =
  | 'enabled'
  | 'disabled'
  | 'disabled-since-boot'
  | 'disabled-permanently'
  | 'disabled-fully-and-permanently';

/**
 * The SEV-SNP evidence block carried in an EAT: the appraisal-relevant, JSON-safe projection of a
 * {@link ParsedSevSnpReport} (see {@link evidenceFromReport}). This is NOT a parallel attestation model —
 * it is a serialization of PCA's parsed-report fields (bigints rendered as decimal strings so they survive
 * JSON). Values are lowercase hex unless noted.
 */
export interface EatSevSnpEvidence {
  /** The report format `version` (see the version-tolerant {@link parseReportTolerant}). */
  version: number;
  /** The launch MEASUREMENT register (48-byte digest), hex. Hardware-authoritative. */
  measurement: string;
  /** REPORTED_TCB — decimal string of the packed u64 (or any {@link TcbVersion} shape). */
  reported_tcb?: TcbVersion;
  /** GUEST_SVN (guest security version). */
  guest_svn?: number;
  /** CHIP_ID (hardware operator identity), hex. */
  chip_id?: string;
  /** Whether the guest POLICY DEBUG bit (19) was set (host can inspect the guest => no confidentiality). */
  debug?: boolean;
  /** The PCA-convention measured loaded-weights digest (hex), if the runtime reflected one (non-zero slot). */
  weights_measurement?: string;
  /** Set when the evidence came from a best-effort (degraded) parse — a short buffer or unknown version. */
  degraded?: boolean;
}

/**
 * The parsed EAT claim set (RFC 9711 common claims). `eat_nonce` and `cnf` are OPTIONAL by design: a
 * received token may legitimately lack them, and that is exactly the replayable / unbound case the
 * verifier must FAIL CLOSED on (see {@link verifyFreshness} / {@link verifyChannelBinding}).
 */
export interface EatClaims {
  /** Token issuer — the attesting environment / verifier-of-record (`iss`). */
  iss: string;
  /** Issued-at, seconds since epoch (`iat`). Freshness (now − iat) is derived from this. */
  iat: number;
  /** The server-issued, single-use freshness challenge echoed into the token (RFC 9711 `eat_nonce`). */
  eat_nonce?: string;
  /** Channel / key binding (RFC 7800 `cnf`) — RA-TLS style; see {@link EatCnf}. */
  cnf?: EatCnf;
  /** Universal Entity ID (`ueid`) — a stable device/entity identifier. */
  ueid?: string;
  /** Semi-permanent UEID (`sueid`) — a privacy-preserving, periodically-rotated entity id. */
  sueid?: string;
  /** Measurement entries (`measurements`). */
  measurements?: EatMeasurement[];
  /** Debug status (`dbgstat`). */
  dbgstat?: DebugStatus;
  /** OEM identifier (`oemid`). */
  oemid?: string;
  /** The PCA measured identity (reused type) this attestation establishes. */
  measured?: MeasuredIdentity;
  /** The SEV-SNP report-level evidence (projection of {@link ParsedSevSnpReport}). */
  sevsnp?: EatSevSnpEvidence;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Internal helpers (base64url via Buffer, constant-time compare, type guards).
// ════════════════════════════════════════════════════════════════════════════════════════════════

function b64uEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

function b64uDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function utf8(s: string): Buffer {
  return Buffer.from(s, 'utf8');
}

/** Constant-time string equality (length-checked `timingSafeEqual` over UTF-8 bytes). */
function strEq(a: string, b: string): boolean {
  const ba = utf8(a);
  const bb = utf8(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : 'unknown';
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isSupportedAlg(v: unknown): v is EatAlg {
  return typeof v === 'string' && SUPPORTED_ALGS.some((a) => a === v);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Keys + JWS sign/verify (node:crypto only).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** A node:crypto private key able to sign an EAT. */
export type SigningKey = KeyObject;
/** A node:crypto public key able to verify an EAT. */
export type VerifyKey = KeyObject;

/** Generate an EAT signing key pair for `alg` (EdDSA → Ed25519, ES256 → EC P-256). */
export function generateEatKeyPair(alg: EatAlg = DEFAULT_EAT_ALG): { publicKey: KeyObject; privateKey: KeyObject } {
  if (alg === 'EdDSA') return generateKeyPairSync('ed25519');
  if (alg === 'ES256') return generateKeyPairSync('ec', { namedCurve: 'P-256' });
  throw new Error(`generateEatKeyPair: unsupported alg '${String(alg)}'`);
}

function signJws(alg: EatAlg, key: SigningKey, signingInput: string): string {
  const data = utf8(signingInput);
  if (alg === 'EdDSA') return b64uEncode(nodeSign(null, data, key));
  // ES256: ECDSA P-256 over SHA-256, JWS wants raw r‖s (ieee-p1363), not DER.
  return b64uEncode(nodeSign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }));
}

function verifyJws(alg: EatAlg, key: VerifyKey, signingInput: string, sigB64u: string): boolean {
  const data = utf8(signingInput);
  const sig = b64uDecode(sigB64u);
  if (alg === 'EdDSA') return nodeVerify(null, data, key, sig);
  return nodeVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Nonce issuance (freshness challenge).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** A server-issued, single-use freshness challenge: the opaque `value` + the time it was issued. */
export interface IssuedNonce {
  /** The opaque nonce string the attester echoes into the EAT's `eat_nonce` claim. */
  value: string;
  /** Server-recorded issue time, epoch ms. */
  issuedAt: number;
}

/**
 * Mint a fresh, single-use nonce for an attestation challenge (anti-replay). The value is random AND
 * TIME-STAMPED (the issue time is appended, base-36, after a `.`), so a Verifier can also bound the
 * nonce's own age independently of the token `iat` if it wishes; the server should still remember and
 * consume it once. `bytes` is the random length (min 16; default 32).
 */
export function issueNonce(opts: { now?: number; bytes?: number } = {}): IssuedNonce {
  const now = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();
  const n = Math.max(16, opts.bytes ?? 32);
  const value = `${b64uEncode(nodeRandomBytes(n))}.${now.toString(36)}`;
  return { value, issuedAt: now };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Evidence projection from a PCA ParsedSevSnpReport.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** True iff every byte is zero (an unmeasured / ABSENT fixed-width slot). */
function isAllZero(b: Uint8Array): boolean {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return false;
  return true;
}

/**
 * Project a PCA {@link ParsedSevSnpReport} into the JSON-safe {@link EatSevSnpEvidence} carried in an EAT.
 * Reuses PCA's `toHex` and `SEV_SNP_POLICY_DEBUG_BIT`. `reported_tcb` is rendered as a decimal string so
 * the u64 survives JSON; an all-zero weights slot is treated as ABSENT (omitted).
 */
export function evidenceFromReport(report: ParsedSevSnpReport): EatSevSnpEvidence {
  const ev: EatSevSnpEvidence = {
    version: report.version,
    measurement: toHex(report.measurement),
    reported_tcb: report.reported_tcb.toString(),
    guest_svn: report.guest_svn,
    chip_id: toHex(report.chip_id),
    debug: (report.policy & SEV_SNP_POLICY_DEBUG_BIT) !== 0n,
  };
  if (!isAllZero(report.weights_measurement)) ev.weights_measurement = toHex(report.weights_measurement);
  return ev;
}

/**
 * Derive a PCA {@link MeasuredIdentity} from a {@link ParsedSevSnpReport}, mirroring PCA's default
 * hardware identity mapping: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID), and a
 * non-zero WEIGHTS_MEASUREMENT slot → a HARDWARE-MEASURED weights digest (`weights_measured: true`). An
 * absent (all-zero) slot yields `weights_digest: ''` with `weights_measured: false`. SEV-SNP carries no
 * model id, so `model_id` is '' (override at your launch convention).
 */
export function measuredFromReport(report: ParsedSevSnpReport): MeasuredIdentity {
  const wMeasured = !isAllZero(report.weights_measurement);
  return {
    model_id: '',
    weights_digest: wMeasured ? toHex(report.weights_measurement) : '',
    weights_measured: wMeasured,
    runtime_measurement: toHex(report.measurement),
    operator: toHex(report.chip_id),
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Version-tolerant SEV-SNP report parse.
// ════════════════════════════════════════════════════════════════════════════════════════════════

// AMD SEV-SNP ABI byte offsets for the version-STABLE fields (same across v2/v3). Mirrors PCA's private
// `OFF` table; kept here so the degraded path can read a short/odd buffer without PCA throwing.
const OFF_VERSION = 0x000;
const OFF_GUEST_SVN = 0x004;
const OFF_POLICY = 0x008;
const OFF_MEASUREMENT = 0x090; // 48 B
const OFF_REPORTED_TCB = 0x180; // u64
const OFF_CHIP_ID = 0x1a0; // 64 B
const OFF_WEIGHTS = 0x1e0; // 48 B (PCA convention)
/** Buffer length PCA's `parseSevSnpReport` requires (through the r‖s signature fields). */
const FULL_REPORT_MIN_LEN = 0x2e8 + 72;

/** Report format versions this parser recognizes as a stable, fully-mapped layout. */
export const KNOWN_REPORT_VERSIONS: readonly number[] = [2, 3];

/** The outcome of a version-tolerant report parse. Never throws. */
export interface TolerantParseResult {
  /** True once at least the stable header (version + launch measurement) could be read. */
  ok: boolean;
  /** The report format `version` (0 if the buffer was too short to even read it). */
  version: number;
  /** True iff `version` is one this parser maps fully ({@link KNOWN_REPORT_VERSIONS}). */
  known: boolean;
  /** True when a reduced / best-effort view was produced (short buffer or unknown version). */
  degraded: boolean;
  /** Human-readable notes about what was (or could not be) parsed. */
  notes: string[];
  /** The full PCA parse — present only for a known version with a complete buffer. */
  report?: ParsedSevSnpReport;
  /** The appraisal projection (best-effort; present whenever the stable header was readable). */
  evidence?: EatSevSnpEvidence;
}

function readU32le(b: Uint8Array, off: number): number | undefined {
  if (off + 4 > b.length) return undefined;
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
}

function readU64le(b: Uint8Array, off: number): bigint | undefined {
  if (off + 8 > b.length) return undefined;
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, true);
}

function readSlice(b: Uint8Array, off: number, len: number): Uint8Array | undefined {
  if (off + len > b.length) return undefined;
  return b.slice(off, off + len);
}

/**
 * Parse an AMD SEV-SNP `ATTESTATION_REPORT` DEFENSIVELY across format versions, DEGRADING GRACEFULLY
 * instead of throwing on an unknown/short input.
 *
 * WHY: the SEV-SNP report format drifts between firmware revisions — a GCP confidential-VM firmware roll
 * on 2025-10-27 changed version-specific fields and broke strict v3 parsers that threw on anything they
 * did not recognize. A strict parser that throws takes the whole verifier down on a benign firmware bump.
 * So:
 *   • a KNOWN version ({@link KNOWN_REPORT_VERSIONS}) with a complete buffer → PCA's full `parseSevSnpReport`
 *     (`report` + `evidence`, `degraded: false`);
 *   • an UNKNOWN version, or a buffer too short for the full signature block → read the VERSION-STABLE
 *     header fields (version, guest_svn, policy/debug, launch measurement, reported_tcb, chip_id, weights)
 *     at their fixed offsets, set `degraded: true` + a note, and return what could be read. Later
 *     appraisal of degraded evidence is downgraded to a `warning` tier, not silently affirmed.
 * Never throws: an input too short to even hold the version yields `{ ok: false }`.
 */
export function parseReportTolerant(bytes: Uint8Array): TolerantParseResult {
  const notes: string[] = [];
  if (!(bytes instanceof Uint8Array)) {
    return { ok: false, version: 0, known: false, degraded: true, notes: ['input is not a Uint8Array'] };
  }
  const version = readU32le(bytes, OFF_VERSION);
  if (version === undefined) {
    return { ok: false, version: 0, known: false, degraded: true, notes: ['buffer too short to read the report version'] };
  }
  const known = KNOWN_REPORT_VERSIONS.includes(version);

  // Happy path: a known version with a full buffer → PCA's authoritative parse.
  if (known && bytes.length >= FULL_REPORT_MIN_LEN) {
    try {
      const report = parseSevSnpReport(bytes);
      return { ok: true, version: report.version, known: true, degraded: false, notes, report, evidence: evidenceFromReport(report) };
    } catch (e) {
      notes.push(`full parse failed, falling back to the stable header: ${msg(e)}`);
    }
  } else if (!known) {
    notes.push(`unknown report version ${version} — parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, may relocate version-specific fields)`);
  } else {
    notes.push(`buffer length ${bytes.length} < full report ${FULL_REPORT_MIN_LEN} — degraded header-only parse`);
  }

  // Degraded path: read the version-stable fields at fixed offsets, skipping any that run past the buffer.
  const measurement = readSlice(bytes, OFF_MEASUREMENT, 48);
  if (measurement === undefined) {
    return { ok: false, version, known, degraded: true, notes: [...notes, 'buffer too short to read the launch measurement'] };
  }
  const evidence: EatSevSnpEvidence = { version, measurement: toHex(measurement), degraded: true };
  const guestSvn = readU32le(bytes, OFF_GUEST_SVN);
  if (guestSvn !== undefined) evidence.guest_svn = guestSvn;
  const policy = readU64le(bytes, OFF_POLICY);
  if (policy !== undefined) evidence.debug = (policy & SEV_SNP_POLICY_DEBUG_BIT) !== 0n;
  const tcb = readU64le(bytes, OFF_REPORTED_TCB);
  if (tcb !== undefined) evidence.reported_tcb = tcb.toString();
  const chip = readSlice(bytes, OFF_CHIP_ID, 64);
  if (chip !== undefined) evidence.chip_id = toHex(chip);
  const weights = readSlice(bytes, OFF_WEIGHTS, 48);
  if (weights !== undefined && !isAllZero(weights)) evidence.weights_measurement = toHex(weights);

  return { ok: true, version, known, degraded: true, notes, evidence };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Channel binding (RA-TLS) + bindChannel.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * Derive the `cnf.tls_exporter` for a TLS channel id / exporter value: `b64u(sha256(DOMAIN ‖ channelId))`.
 * Domain-separated and fixed-width, so a Verifier recomputes it from the exporter it OBSERVES on the live
 * connection and compares. (RA-TLS: the attestation is only valid on the channel it was produced for.)
 */
export function deriveChannelCnf(channelId: string, holderKeyThumbprint?: string): EatCnf {
  if (typeof channelId !== 'string' || channelId.length === 0) throw new Error('deriveChannelCnf: channelId is required');
  const exporter = createHash('sha256').update(utf8(CHANNEL_BINDING_DOMAIN)).update(utf8(channelId)).digest();
  const cnf: EatCnf = { tls_exporter: b64uEncode(exporter) };
  if (typeof holderKeyThumbprint === 'string' && holderKeyThumbprint.length > 0) cnf.jkt = holderKeyThumbprint;
  return cnf;
}

/** Attestation evidence bound to a live channel + a per-session freshness nonce (the output of {@link bindChannel}). */
export interface ChannelBoundEvidence<E> {
  /** The attestation evidence being bound (e.g. an {@link EatSevSnpEvidence} or {@link MeasuredIdentity}). */
  evidence: E;
  /** The per-session freshness nonce this evidence is bound to (becomes `eat_nonce`). */
  nonce: string;
  /** The channel binding derived from the channel id (becomes `cnf`). */
  cnf: EatCnf;
}

/**
 * Bind attestation `evidence` to a TLS channel id / exporter value + a per-session freshness `nonce`
 * (IETF SEAT / RA-TLS). Returns a {@link ChannelBoundEvidence} whose `cnf` + `nonce` are fed to
 * {@link buildEAT}. Verification ({@link verifyChannelBinding} / {@link verifyFreshness}, or the composed
 * {@link verifyFreshAttestedEAT}) rejects a token whose nonce is stale/mismatched or whose channel binding
 * does not match the live channel.
 */
export function bindChannel<E>(evidence: E, channelId: string, nonce: string): ChannelBoundEvidence<E> {
  if (typeof nonce !== 'string' || nonce.length === 0) throw new Error('bindChannel: a per-session nonce is required for freshness');
  return { evidence, nonce, cnf: deriveChannelCnf(channelId) };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// buildEAT / verifyEAT.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Arguments to {@link buildEAT}. */
export interface BuildEatArgs {
  /** The EAT issuer (`iss`). REQUIRED. */
  issuer: string;
  /** The attester's private key (node:crypto `KeyObject`). REQUIRED. */
  key: SigningKey;
  /** Signing algorithm (default {@link DEFAULT_EAT_ALG}). Must match `key`'s type. */
  alg?: EatAlg;
  /** The freshness challenge value (from {@link issueNonce}) — becomes `eat_nonce`. REQUIRED. */
  nonce: string;
  /** The live channel / holder-key binding — becomes `cnf`. Supply this OR {@link channelId}. */
  channelBinding?: EatCnf;
  /** A TLS channel id / exporter value to derive `cnf` from (RA-TLS). Supply this OR {@link channelBinding}. */
  channelId?: string;
  /** The PCA measured identity to carry (reused type). */
  measured?: MeasuredIdentity;
  /** The SEV-SNP report-level evidence block (projection of {@link ParsedSevSnpReport}). */
  sevsnp?: EatSevSnpEvidence;
  /** Measurement entries — becomes `measurements`. */
  measurements?: EatMeasurement[];
  /** Universal Entity ID (`ueid`). */
  ueid?: string;
  /** Semi-permanent UEID (`sueid`). */
  sueid?: string;
  /** Debug status (`dbgstat`). */
  dbgstat?: DebugStatus;
  /** OEM id (`oemid`). */
  oemid?: string;
  /** Pin the issue time (epoch ms) for a deterministic `iat` (testing). */
  now?: number;
}

function resolveCnf(args: Pick<BuildEatArgs, 'channelBinding' | 'channelId'>): EatCnf {
  const out: EatCnf = {};
  if (args.channelId !== undefined) {
    const derived = deriveChannelCnf(args.channelId);
    if (derived.tls_exporter !== undefined) out.tls_exporter = derived.tls_exporter;
  }
  const cb = args.channelBinding;
  if (cb !== undefined) {
    if (typeof cb.tls_exporter === 'string') out.tls_exporter = cb.tls_exporter;
    if (typeof cb.jkt === 'string') out.jkt = cb.jkt;
  }
  return out;
}

/**
 * Build a signed EAT (RFC 9711) over the given evidence. Emits a compact JWS with the `eat+jwt` typ header,
 * `iss`, `iat`, the `eat_nonce` freshness challenge, the `cnf` channel/key binding (RA-TLS), and the
 * optional measured identity / sevsnp evidence / measurements / ueid / dbgstat / oemid claims. Signs with
 * node:crypto (EdDSA by default, or ES256).
 *
 * It requires a `nonce` AND a channel binding (a `channelId` to derive from, or a `channelBinding` that
 * carries a TLS exporter or a holder-key thumbprint) — emitting an unbound EAT would re-open the very
 * replay gap this package closes.
 */
export function buildEAT(args: BuildEatArgs): string {
  if (typeof args.issuer !== 'string' || args.issuer.length === 0) throw new Error('buildEAT: issuer is required');
  if (typeof args.nonce !== 'string' || args.nonce.length === 0) throw new Error('buildEAT: nonce (eat_nonce) is required for freshness');
  const alg = args.alg ?? DEFAULT_EAT_ALG;
  if (!isSupportedAlg(alg)) throw new Error(`buildEAT: unsupported alg '${String(alg)}'`);
  const cnf = resolveCnf(args);
  if (cnf.tls_exporter === undefined && cnf.jkt === undefined) {
    throw new Error('buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence');
  }
  const iatMs = typeof args.now === 'number' && Number.isFinite(args.now) ? args.now : Date.now();

  // Deterministic claim object, built in a fixed field order.
  const claims: Record<string, unknown> = {
    iss: args.issuer,
    iat: Math.floor(iatMs / 1000),
    eat_nonce: args.nonce,
    cnf,
  };
  if (args.ueid !== undefined) claims.ueid = args.ueid;
  if (args.sueid !== undefined) claims.sueid = args.sueid;
  if (args.oemid !== undefined) claims.oemid = args.oemid;
  if (args.dbgstat !== undefined) claims.dbgstat = args.dbgstat;
  if (args.measurements !== undefined) claims.measurements = args.measurements;
  if (args.measured !== undefined) claims.measured = args.measured;
  if (args.sevsnp !== undefined) claims.sevsnp = args.sevsnp;

  const header = { alg, typ: EAT_TYP };
  const signingInput = `${b64uEncode(utf8(JSON.stringify(header)))}.${b64uEncode(utf8(JSON.stringify(claims)))}`;
  return `${signingInput}.${signJws(alg, args.key, signingInput)}`;
}

/** Options for {@link verifyEAT}. */
export interface VerifyEatOptions {
  /** Require this issuer (`iss`). */
  issuer?: string | string[];
  /** Restrict the accepted signing algorithms (default: all supported). */
  algorithms?: EatAlg[];
  /** Override the required `typ` header (default `eat+jwt`). */
  typ?: string;
  /** Set `false` to skip the `typ` check. */
  requireTyp?: boolean;
}

function parseCnf(v: unknown): EatCnf | undefined {
  if (!isRecord(v)) return undefined;
  const out: EatCnf = {};
  if (typeof v.tls_exporter === 'string') out.tls_exporter = v.tls_exporter;
  if (typeof v.jkt === 'string') out.jkt = v.jkt;
  return out.tls_exporter === undefined && out.jkt === undefined ? undefined : out;
}

function parseMeasurements(v: unknown): EatMeasurement[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: EatMeasurement[] = [];
  for (const e of v) {
    if (isRecord(e) && typeof e.type === 'string' && typeof e.value === 'string') out.push({ type: e.type, value: e.value });
  }
  return out.length > 0 ? out : undefined;
}

function parseTcbVersion(v: unknown): TcbVersion | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string') return v;
  if (isRecord(v)) {
    const o: { bootloader?: number; tee?: number; snp?: number; microcode?: number } = {};
    if (typeof v.bootloader === 'number') o.bootloader = v.bootloader;
    if (typeof v.tee === 'number') o.tee = v.tee;
    if (typeof v.snp === 'number') o.snp = v.snp;
    if (typeof v.microcode === 'number') o.microcode = v.microcode;
    return o;
  }
  return undefined;
}

function parseMeasured(v: unknown): MeasuredIdentity | undefined {
  if (!isRecord(v)) return undefined;
  if (typeof v.model_id !== 'string' || typeof v.weights_digest !== 'string' || typeof v.runtime_measurement !== 'string' || typeof v.operator !== 'string') {
    return undefined;
  }
  const out: MeasuredIdentity = {
    model_id: v.model_id,
    weights_digest: v.weights_digest,
    runtime_measurement: v.runtime_measurement,
    operator: v.operator,
  };
  if (typeof v.weights_measured === 'boolean') out.weights_measured = v.weights_measured;
  if (typeof v.system_prompt_digest === 'string') out.system_prompt_digest = v.system_prompt_digest;
  if (typeof v.tool_manifest_digest === 'string') out.tool_manifest_digest = v.tool_manifest_digest;
  return out;
}

function parseSevSnp(v: unknown): EatSevSnpEvidence | undefined {
  if (!isRecord(v) || typeof v.version !== 'number' || typeof v.measurement !== 'string') return undefined;
  const out: EatSevSnpEvidence = { version: v.version, measurement: v.measurement };
  const tcb = parseTcbVersion(v.reported_tcb);
  if (tcb !== undefined) out.reported_tcb = tcb;
  if (typeof v.guest_svn === 'number') out.guest_svn = v.guest_svn;
  if (typeof v.chip_id === 'string') out.chip_id = v.chip_id;
  if (typeof v.debug === 'boolean') out.debug = v.debug;
  if (typeof v.weights_measurement === 'string') out.weights_measurement = v.weights_measurement;
  if (typeof v.degraded === 'boolean') out.degraded = v.degraded;
  return out;
}

const DBGSTAT_VALUES: readonly DebugStatus[] = [
  'enabled',
  'disabled',
  'disabled-since-boot',
  'disabled-permanently',
  'disabled-fully-and-permanently',
];

function parseDbgstat(v: unknown): DebugStatus | undefined {
  return typeof v === 'string' ? DBGSTAT_VALUES.find((d) => d === v) : undefined;
}

/**
 * Verify an EAT's signature + `typ`/`iss` and parse it into {@link EatClaims}. Throws on an invalid
 * signature, wrong key, failed `iss`/`typ` check, an unsupported `alg`, or a missing `iss`/`iat`. Claims
 * with the wrong runtime type are dropped to `undefined` so downstream checks FAIL CLOSED rather than
 * trust a malformed value. This proves the token's AUTHENTICITY — freshness, channel binding and appraisal
 * are separate steps (see {@link verifyFreshness}, {@link verifyChannelBinding}, {@link appraise}).
 */
export function verifyEAT(eat: string, verifyKey: VerifyKey, opts: VerifyEatOptions = {}): EatClaims {
  if (typeof eat !== 'string') throw new Error('EAT invalid: token is not a string');
  const parts = eat.split('.');
  if (parts.length !== 3) throw new Error('EAT invalid: expected a compact JWS (header.payload.signature)');
  const [h, p, s] = parts;
  if (h === undefined || p === undefined || s === undefined || h.length === 0 || p.length === 0 || s.length === 0) {
    throw new Error('EAT invalid: empty JWS segment');
  }

  let header: unknown;
  try {
    header = JSON.parse(b64uDecode(h).toString('utf8'));
  } catch {
    throw new Error('EAT invalid: header is not valid JSON');
  }
  if (!isRecord(header) || !isSupportedAlg(header.alg)) throw new Error('EAT invalid: missing or unsupported `alg` header');
  const allowed = opts.algorithms ?? SUPPORTED_ALGS;
  if (!allowed.includes(header.alg)) throw new Error(`EAT invalid: alg ${header.alg} not in the allowed set`);
  if (opts.requireTyp !== false) {
    const wantTyp = opts.typ ?? EAT_TYP;
    if (header.typ !== wantTyp) throw new Error(`EAT invalid: typ ${String(header.typ)} is not ${wantTyp}`);
  }

  if (!verifyJws(header.alg, verifyKey, `${h}.${p}`, s)) throw new Error('EAT invalid: signature does not verify');

  let payload: unknown;
  try {
    payload = JSON.parse(b64uDecode(p).toString('utf8'));
  } catch {
    throw new Error('EAT invalid: payload is not valid JSON');
  }
  if (!isRecord(payload)) throw new Error('EAT invalid: payload is not an object');
  if (typeof payload.iss !== 'string') throw new Error('EAT invalid: missing or non-string `iss`');
  if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) throw new Error('EAT invalid: missing or non-numeric `iat`');
  if (opts.issuer !== undefined) {
    const allowedIss = Array.isArray(opts.issuer) ? opts.issuer : [opts.issuer];
    if (!allowedIss.includes(payload.iss)) throw new Error(`EAT invalid: iss ${payload.iss} is not an accepted issuer`);
  }

  const claims: EatClaims = { iss: payload.iss, iat: payload.iat };
  if (typeof payload.eat_nonce === 'string') claims.eat_nonce = payload.eat_nonce;
  const cnf = parseCnf(payload.cnf);
  if (cnf !== undefined) claims.cnf = cnf;
  if (typeof payload.ueid === 'string') claims.ueid = payload.ueid;
  if (typeof payload.sueid === 'string') claims.sueid = payload.sueid;
  const measurements = parseMeasurements(payload.measurements);
  if (measurements !== undefined) claims.measurements = measurements;
  const dbgstat = parseDbgstat(payload.dbgstat);
  if (dbgstat !== undefined) claims.dbgstat = dbgstat;
  if (typeof payload.oemid === 'string') claims.oemid = payload.oemid;
  const measured = parseMeasured(payload.measured);
  if (measured !== undefined) claims.measured = measured;
  const sevsnp = parseSevSnp(payload.sevsnp);
  if (sevsnp !== undefined) claims.sevsnp = sevsnp;
  return claims;
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Freshness + channel binding.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** The outcome of a single gate: ok, or a specific reason it failed closed. */
export interface CheckResult {
  ok: boolean;
  reason?: string;
}

/** Options for {@link verifyFreshness}. */
export interface FreshnessOptions {
  /** The server-issued / per-session nonce the token's `eat_nonce` MUST equal (anti-replay). */
  expectedNonce: string;
  /** Max acceptable age (ms) of the token, now − iat. */
  maxAgeMs: number;
  /** "Now", epoch ms (default `Date.now`). */
  now?: number;
  /** Allowed clock skew (ms), default 0. */
  clockSkewMs?: number;
}

/**
 * ANTI-REPLAY FRESHNESS. Reject the EAT unless its `eat_nonce` equals the server-issued challenge AND its
 * `iat` is within `[now − maxAgeMs, now]` (allowing `clockSkewMs`). An absent/mismatched nonce, a future
 * `iat`, or a token older than `maxAgeMs` all fail closed — so a report captured once (stale iat) or
 * relayed with the wrong challenge cannot be replayed. Operates on the already-verified {@link EatClaims};
 * run {@link verifyEAT} first for authenticity.
 */
export function verifyFreshness(eat: EatClaims, opts: FreshnessOptions): CheckResult {
  const now = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();
  const skew = Math.max(0, opts.clockSkewMs ?? 0);
  if (typeof opts.expectedNonce !== 'string' || opts.expectedNonce.length === 0) {
    return { ok: false, reason: 'no expected (server-issued) nonce supplied (fail closed)' };
  }
  if (typeof eat.eat_nonce !== 'string' || eat.eat_nonce.length === 0) {
    return { ok: false, reason: 'EAT carries no eat_nonce — cannot establish freshness (replayable)' };
  }
  if (!strEq(eat.eat_nonce, opts.expectedNonce)) {
    return { ok: false, reason: 'eat_nonce does not match the server-issued challenge (replayed or relayed evidence)' };
  }
  if (typeof eat.iat !== 'number' || !Number.isFinite(eat.iat)) {
    return { ok: false, reason: 'EAT has no valid iat (cannot establish age)' };
  }
  if (!Number.isFinite(opts.maxAgeMs) || opts.maxAgeMs <= 0) {
    return { ok: false, reason: 'invalid maxAgeMs' };
  }
  const iatMs = eat.iat * 1000;
  if (iatMs - skew > now) return { ok: false, reason: 'EAT iat is in the future' };
  if (now - iatMs > opts.maxAgeMs + skew) return { ok: false, reason: 'EAT is stale (iat older than maxAgeMs) — expired/replayed attestation' };
  return { ok: true };
}

/** Options for {@link verifyChannelBinding}: supply the live channel id to derive from, OR a raw expected cnf. */
export interface ChannelBindingOptions {
  /** The TLS channel id / exporter value observed on the live connection; its derived cnf must match the token. */
  channelId?: string;
  /** A raw expected `cnf` the resource server observes (alternative to {@link channelId}). */
  expectedCnf?: EatCnf;
}

/**
 * CHANNEL BINDING (RA-TLS). Reject the EAT unless its `cnf` matches the live channel/key the resource
 * server observes: every field present in the expected cnf (derived from `channelId`, and/or an explicit
 * `expectedCnf`) must be present and equal in the token's `cnf`. An EAT with no `cnf`, or one bound to a
 * different channel/key, fails closed — so evidence captured on one connection cannot be lifted onto another.
 */
export function verifyChannelBinding(eat: EatClaims, opts: ChannelBindingOptions): CheckResult {
  const exp: EatCnf = {};
  if (typeof opts.channelId === 'string' && opts.channelId.length > 0) {
    const d = deriveChannelCnf(opts.channelId);
    if (d.tls_exporter !== undefined) exp.tls_exporter = d.tls_exporter;
  }
  if (opts.expectedCnf !== undefined) {
    if (typeof opts.expectedCnf.tls_exporter === 'string') exp.tls_exporter = opts.expectedCnf.tls_exporter;
    if (typeof opts.expectedCnf.jkt === 'string') exp.jkt = opts.expectedCnf.jkt;
  }
  const expFields = (exp.tls_exporter !== undefined ? 1 : 0) + (exp.jkt !== undefined ? 1 : 0);
  if (expFields === 0) return { ok: false, reason: 'no expected channel binding supplied (fail closed)' };
  const cnf = eat.cnf;
  if (!cnf || (cnf.tls_exporter === undefined && cnf.jkt === undefined)) {
    return { ok: false, reason: 'EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)' };
  }
  if (exp.tls_exporter !== undefined && (cnf.tls_exporter === undefined || !strEq(cnf.tls_exporter, exp.tls_exporter))) {
    return { ok: false, reason: 'TLS-exporter channel binding mismatch (evidence lifted to another channel?)' };
  }
  if (exp.jkt !== undefined && (cnf.jkt === undefined || !strEq(cnf.jkt, exp.jkt))) {
    return { ok: false, reason: 'holder-key thumbprint (cnf.jkt) mismatch' };
  }
  return { ok: true };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// RATS appraisal (RFC 9334 Verifier / appraisal-policy split).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * RATS ENDORSEMENTS (RFC 9334 §3): out-of-band trust assertions about the ATTESTER — which issuers / OEMs /
 * hardware operators the Relying Party accepts. An empty endorsements block asserts nothing.
 */
export interface Endorsements {
  /** Accepted token issuers (the endorsed attesting environment / verifier-of-record). */
  issuers?: string[];
  /** Accepted OEM ids (`oemid`). */
  oemids?: string[];
  /** Accepted hardware operator identities (CHIP_ID hex / {@link MeasuredIdentity.operator}). */
  operators?: string[];
}

/**
 * RATS REFERENCE VALUES (RFC 9334 §3): known-good measurements / TCB the EVIDENCE must match or exceed.
 *
 * TCB-VERSION / FORMAT-DRIFT TOLERANCE (lesson: 2025-10-27 GCP confidential-VM firmware drift — a firmware
 * roll changed the shape/width of reported version fields and broke exact-match appraisers). The comparison
 * is TOLERANT of the version shape ({@link TcbVersion}: a packed integer, a decimal string, or the
 * structured SEV-SNP components) and compares by ORDER (`>= minTcb`) so a TCB UPGRADE still appraises. But
 * it FAILS CLOSED on an UNKNOWN shape rather than guessing.
 */
export interface ReferenceValues {
  /** Accepted launch measurements (lowercase hex). */
  measurements?: string[];
  /** Accepted model ids ({@link MeasuredIdentity.model_id}). */
  models?: string[];
  /** Accepted measured-weights digests (lowercase hex). */
  weightsMeasurements?: string[];
  /** Require the weights digest to be HARDWARE-MEASURED ({@link MeasuredIdentity.weights_measured} === true). */
  requireMeasuredWeights?: boolean;
  /** Minimum acceptable TCB version — evidence must be `>= this` (rejects downgrade / rollback). */
  minTcb?: TcbVersion;
  /** Minimum acceptable GUEST_SVN. */
  minGuestSvn?: number;
  /** Require debug to be disabled (any `disabled*` dbgstat, or `sevsnp.debug === false`). */
  requireDebugDisabled?: boolean;
}

/**
 * A RATS appraisal policy bundle — endorsements + reference values — for the composed
 * {@link verifyFreshAttestedEAT}. The standalone {@link appraise} takes the two as separate arguments (the
 * explicit RATS split).
 */
export interface AppraisalPolicy {
  endorsements?: Endorsements;
  referenceValues?: ReferenceValues;
}

/**
 * The RATS trustworthiness tier (modelled on RFC 9334 appraisal outcomes / AR4SI), highest first:
 *   • `affirming-hw-rooted` — everything `affirming` requires AND the AMD SEV-SNP report signature +
 *     VCEK→ASK→ARK chain were cryptographically verified for this evidence (see {@link verifyAmdAttestation}).
 *     This is the STRICTLY HIGHER tier a hardware-rooted attestation reaches over a software-vouched one;
 *   • `affirming` — evidence satisfied every endorsement + reference value from complete evidence, but the
 *     silicon signature was not (re-)verified in this appraisal;
 *   • `warning` — satisfied, but from DEGRADED evidence (e.g. an unknown/short SEV-SNP report version) —
 *     acceptable, surface for review;
 *   • `contraindicated` — the measured state is actively BAD (debug enabled, TCB downgrade, a measurement /
 *     weights / model / issuer / oem / operator that is not approved);
 *   • `rejected` — the policy was empty, or a required input was absent / in an unknown format (fail closed).
 */
export type AttestationTier = 'affirming-hw-rooted' | 'affirming' | 'warning' | 'contraindicated' | 'rejected';

/** The tiers a Relying Party may accept (highest three). The lower two always fail closed. */
const TRUSTWORTHY_TIERS: readonly AttestationTier[] = ['affirming-hw-rooted', 'affirming', 'warning'];
function tierTrustworthy(tier: AttestationTier): boolean {
  return TRUSTWORTHY_TIERS.includes(tier);
}

/** The outcome of {@link appraise} — a RATS attestation result. */
export interface AttestationResult {
  /** The trust tier. */
  tier: AttestationTier;
  /** Convenience: true iff the tier is acceptable (`affirming-hw-rooted`, `affirming` or `warning`). */
  trustworthy: boolean;
  /** Human-readable reasons — the satisfied checks, plus the deciding failure when not affirming. */
  reasons: string[];
}

/**
 * Out-of-band appraisal signals NOT carried inside the EAT: the Verifier supplies these from steps it ran
 * itself. Today the only signal is whether this Verifier cryptographically verified the AMD SEV-SNP report
 * signature + VCEK→ASK→ARK chain for this evidence — which, when true, lifts an otherwise-affirming result
 * to the hardware-rooted tier. {@link verifyFreshAttestedEAT} populates it by running
 * {@link verifyAmdAttestation}; it is kept a SEPARATE argument (not an EAT claim) precisely because an
 * attester cannot self-assert it.
 */
export interface AppraiseExtras {
  /** True iff the AMD SEV-SNP report signature + VCEK→ASK→ARK chain were verified by the Verifier for this evidence. */
  hardwareVerified?: boolean;
  /** Label for the verified hardware root (honest: classical, not PQ). Defaults to {@link AMD_SEV_SNP_HARDWARE_ROOT_LABEL}. */
  hardwareRootLabel?: string;
}

/** Pack a {@link TcbVersion} into a comparable bigint, or null if its shape is unknown (fail closed). */
function packTcb(v: TcbVersion): bigint | null {
  if (typeof v === 'number') return Number.isFinite(v) && v >= 0 ? BigInt(Math.floor(v)) : null;
  if (typeof v === 'string') {
    const t = v.trim();
    if (/^[0-9]+$/.test(t)) {
      try {
        return BigInt(t);
      } catch {
        return null;
      }
    }
    return null; // unknown / non-numeric format — fail closed (GCP firmware drift lesson)
  }
  const comp = (x: number | undefined): bigint | null =>
    x === undefined ? 0n : Number.isInteger(x) && x >= 0 && x <= 255 ? BigInt(x) : null;
  const bl = comp(v.bootloader);
  const tee = comp(v.tee);
  const snp = comp(v.snp);
  const uc = comp(v.microcode);
  if (bl === null || tee === null || snp === null || uc === null) return null;
  return bl | (tee << 8n) | (snp << 48n) | (uc << 56n);
}

const lc = (s: string): string => s.toLowerCase();

/** The launch measurement to appraise (the measured identity, else the sevsnp block, else a `launch`/`measurement` entry). */
function launchMeasurement(eat: EatClaims): string | undefined {
  if (eat.measured && typeof eat.measured.runtime_measurement === 'string' && eat.measured.runtime_measurement.length > 0) {
    return eat.measured.runtime_measurement;
  }
  if (eat.sevsnp && typeof eat.sevsnp.measurement === 'string') return eat.sevsnp.measurement;
  const m = eat.measurements?.find((e) => e.type === 'launch' || e.type === 'measurement');
  return m?.value;
}

/** The measured-weights digest to appraise (the measured identity, else the sevsnp block, else a `weights` entry). */
function weightsMeasurement(eat: EatClaims): string | undefined {
  if (eat.measured && typeof eat.measured.weights_digest === 'string' && eat.measured.weights_digest.length > 0) {
    return eat.measured.weights_digest;
  }
  if (eat.sevsnp && typeof eat.sevsnp.weights_measurement === 'string') return eat.sevsnp.weights_measurement;
  const m = eat.measurements?.find((e) => e.type === 'weights');
  return m?.value;
}

/** True/false if debug status is known, else null (unknown => caller fails closed). */
function isDebugDisabled(eat: EatClaims): boolean | null {
  if (eat.dbgstat !== undefined) return eat.dbgstat !== 'enabled';
  if (eat.sevsnp && typeof eat.sevsnp.debug === 'boolean') return eat.sevsnp.debug === false;
  return null;
}

/**
 * APPRAISE an EAT's EVIDENCE against RATS REFERENCE VALUES and ENDORSEMENTS (RFC 9334) — the three inputs
 * kept as distinct arguments (the RATS Verifier's appraisal-policy split). Returns an attestation result
 * with a {@link AttestationTier}:
 *   • ENDORSEMENTS gate WHO the attester is (issuer / OEM / operator); a mismatch → `rejected`.
 *   • REFERENCE VALUES gate WHAT state the evidence shows; an actively-bad value (debug on, TCB downgrade,
 *     an unapproved measurement / weights / model) → `contraindicated`, a required value that is absent or
 *     in an unknown format → `rejected` (fail closed).
 *   • DEGRADED evidence that otherwise passes → `warning` (acceptable, surfaced for review).
 *   • an EMPTY policy (no endorsements and no reference values) → `rejected` (fail closed).
 * Does NOT re-verify the AMD cert chain or report signature (that is PCA's `hardware-sevsnp.ts`); it decides
 * whether already-verified evidence meets policy.
 */
export function appraise(
  evidence: EatClaims,
  referenceValues: ReferenceValues = {},
  endorsements: Endorsements = {},
  extras: AppraiseExtras = {},
): AttestationResult {
  const reasons: string[] = [];
  const result = (tier: AttestationTier, reason: string): AttestationResult => ({
    tier,
    trustworthy: tierTrustworthy(tier),
    reasons: [...reasons, reason],
  });

  const hasEndorsements =
    (Array.isArray(endorsements.issuers) && endorsements.issuers.length > 0) ||
    (Array.isArray(endorsements.oemids) && endorsements.oemids.length > 0) ||
    (Array.isArray(endorsements.operators) && endorsements.operators.length > 0);
  const hasReferenceValues =
    (Array.isArray(referenceValues.measurements) && referenceValues.measurements.length > 0) ||
    (Array.isArray(referenceValues.models) && referenceValues.models.length > 0) ||
    (Array.isArray(referenceValues.weightsMeasurements) && referenceValues.weightsMeasurements.length > 0) ||
    referenceValues.requireMeasuredWeights === true ||
    referenceValues.minTcb !== undefined ||
    typeof referenceValues.minGuestSvn === 'number' ||
    referenceValues.requireDebugDisabled === true;
  if (!hasEndorsements && !hasReferenceValues) {
    return { tier: 'rejected', trustworthy: false, reasons: ['empty appraisal policy: no endorsements or reference values to appraise against (fail closed)'] };
  }

  // ── Endorsements (WHO) → rejected on mismatch. ──
  if (Array.isArray(endorsements.issuers) && endorsements.issuers.length > 0) {
    if (!endorsements.issuers.includes(evidence.iss)) return result('rejected', `issuer ${evidence.iss} is not an endorsed attester`);
    reasons.push('issuer endorsed');
  }
  if (Array.isArray(endorsements.oemids) && endorsements.oemids.length > 0) {
    if (typeof evidence.oemid !== 'string' || !endorsements.oemids.includes(evidence.oemid)) return result('rejected', 'oemid absent or not endorsed (fail closed)');
    reasons.push('oemid endorsed');
  }
  if (Array.isArray(endorsements.operators) && endorsements.operators.length > 0) {
    const op = evidence.measured?.operator;
    if (typeof op !== 'string' || op.length === 0 || !endorsements.operators.includes(op)) return result('rejected', 'hardware operator absent or not endorsed (fail closed)');
    reasons.push('operator endorsed');
  }

  // ── Reference values (WHAT): bad value → contraindicated; absent/unknown required → rejected. ──
  if (Array.isArray(referenceValues.measurements) && referenceValues.measurements.length > 0) {
    const m = launchMeasurement(evidence);
    if (m === undefined) return result('rejected', 'no launch measurement in evidence to compare against reference values (fail closed)');
    if (!referenceValues.measurements.map(lc).includes(m.toLowerCase())) return result('contraindicated', 'launch measurement not in reference values');
    reasons.push('launch measurement matches a reference value');
  }
  if (Array.isArray(referenceValues.models) && referenceValues.models.length > 0) {
    const model = evidence.measured?.model_id;
    if (typeof model !== 'string' || model.length === 0) return result('rejected', 'no model id in evidence (fail closed)');
    if (!referenceValues.models.includes(model)) return result('contraindicated', 'model id not in reference values (model swap?)');
    reasons.push('model id matches a reference value');
  }
  if (referenceValues.requireMeasuredWeights === true) {
    if (evidence.measured?.weights_measured !== true) return result('contraindicated', 'weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)');
    reasons.push('weights digest is hardware-measured');
  }
  if (Array.isArray(referenceValues.weightsMeasurements) && referenceValues.weightsMeasurements.length > 0) {
    const w = weightsMeasurement(evidence);
    if (w === undefined || w.length === 0) return result('rejected', 'no measured-weights digest in evidence (fail closed)');
    if (!referenceValues.weightsMeasurements.map(lc).includes(w.toLowerCase())) return result('contraindicated', 'weights measurement not in reference values (model swap / fine-tune?)');
    reasons.push('weights measurement matches a reference value');
  }
  if (referenceValues.minTcb !== undefined) {
    const min = packTcb(referenceValues.minTcb);
    if (min === null) return result('rejected', 'reference minTcb is not a comparable TCB version');
    const rawTcb = evidence.sevsnp?.reported_tcb;
    const got = rawTcb !== undefined ? packTcb(rawTcb) : null;
    if (got === null) return result('rejected', 'evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)');
    if (got < min) return result('contraindicated', 'reported TCB is below the reference minimum (downgrade / rollback)');
    reasons.push('TCB at or above reference minimum');
  }
  if (typeof referenceValues.minGuestSvn === 'number') {
    const svn = evidence.sevsnp?.guest_svn;
    if (typeof svn !== 'number' || !Number.isFinite(svn)) return result('rejected', 'guest_svn absent (fail closed)');
    if (svn < referenceValues.minGuestSvn) return result('contraindicated', `guest_svn ${svn} below reference minimum ${referenceValues.minGuestSvn}`);
    reasons.push('guest_svn at or above reference minimum');
  }
  if (referenceValues.requireDebugDisabled === true) {
    const disabled = isDebugDisabled(evidence);
    if (disabled === null) return result('rejected', 'debug status unknown — failing closed');
    if (!disabled) return result('contraindicated', 'debug is enabled (host can inspect the guest — no confidentiality)');
    reasons.push('debug disabled');
  }

  // All checks passed. Degraded evidence → warning (surfaced); a verified AMD silicon signature →
  // the strictly-higher hardware-rooted tier; otherwise plain affirming.
  if (evidence.sevsnp?.degraded === true) {
    return { tier: 'warning', trustworthy: true, reasons: [...reasons, 'evidence came from a degraded (version-tolerant) parse — review'] };
  }
  if (extras.hardwareVerified === true) {
    const label = extras.hardwareRootLabel ?? AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
    return {
      tier: 'affirming-hw-rooted',
      trustworthy: true,
      reasons: [...reasons, `AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — ${label}`],
    };
  }
  return { tier: 'affirming', trustworthy: true, reasons };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// AMD SEV-SNP hardware root of trust — REAL signature + certificate-chain verification (node:crypto).
//
// Closes the boundary the module header used to document ("does NOT verify the AMD signature"). This is
// the genuine AMD "Versioned Chip Endorsement Key" chain of trust, verified with node:crypto only:
//   report signature (ECDSA-P384/SHA-384 over [0x000,0x2A0))  ⟵ signed by ⟶  VCEK
//                                           VCEK  ⟵ signed by ⟶  ASK  ⟵ signed by ⟶  ARK (self-signed, pinned)
// Every function FAILS CLOSED (a structured {ok,reason}) — a parse error, a bad signature, a broken chain
// link, an untrusted root, an out-of-validity certificate, or a thrown exception all return ok:false.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** A certificate supplied either as DER bytes or as a PEM string (`-----BEGIN CERTIFICATE-----`…). */
export type CertInput = Uint8Array | string;

/** The outcome of {@link verifySevSnpSignature}: ok, or a specific reason it failed closed. */
export interface SevSnpSignatureResult {
  ok: boolean;
  reason?: string;
}

/** Interpret a little-endian byte array as a non-negative bigint (AMD stores r/s little-endian). */
function leBytesToBigInt(le: Uint8Array): bigint {
  let n = 0n;
  for (let i = le.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(le[i] ?? 0);
  return n;
}

/** Serialize a non-negative bigint to a fixed-width big-endian Buffer. Throws if it does not fit. */
function bigIntToBe(n: bigint, size: number): Buffer {
  const out = Buffer.alloc(size);
  let v = n;
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError('scalar does not fit in the target field width');
  return out;
}

/** A certificate input → a node:crypto value its `X509Certificate` constructor accepts (PEM string or DER Buffer). */
function toCertArg(input: CertInput): string | Buffer {
  if (typeof input === 'string') return input;
  return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
}

/** Parse a certificate input into an `X509Certificate`. Throws on malformed input (callers fail closed). */
function loadCert(input: CertInput): X509Certificate {
  return new X509Certificate(toCertArg(input));
}

/** Extract + validate the EC-secp384r1 public key from a certificate. Throws if it is not P-384 EC. */
function loadP384PublicKey(input: CertInput, label: string): KeyObject {
  const pk = loadCert(input).publicKey;
  if (pk.asymmetricKeyType !== 'ec') {
    throw new Error(`${label} is not an EC key (got ${String(pk.asymmetricKeyType)})`);
  }
  const curve = pk.asymmetricKeyDetails?.namedCurve;
  if (curve !== 'secp384r1') throw new Error(`${label} is not EC secp384r1 (got ${String(curve)})`);
  return pk;
}

/** SHA-384 (hex) of a certificate's DER SubjectPublicKeyInfo — the fingerprint an ARK pin compares. */
function spkiSha384Hex(cert: X509Certificate): string {
  const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha384').update(spki).digest('hex');
}

/** True iff `now` lies within the certificate's [notBefore, notAfter] window. */
function withinValidity(cert: X509Certificate, nowMs: number): boolean {
  const nb = new Date(cert.validFrom).getTime();
  const na = new Date(cert.validTo).getTime();
  if (!Number.isFinite(nb) || !Number.isFinite(na)) return false;
  return nowMs >= nb && nowMs <= na;
}

/**
 * Verify an AMD SEV-SNP `ATTESTATION_REPORT`'s ECDSA-P384/SHA-384 signature under the VCEK public key.
 *
 * The signature is over the report's signed region [0x000, 0x2A0) (see {@link AMD_SEV_SNP_SIGNED_REGION_END}).
 * AMD stores r and s as 72-byte LITTLE-ENDIAN fields (the P-384 scalars occupy the low 48 bytes); this
 * converts them to the IEEE-P1363 big-endian r‖s (48+48 = 96 bytes) form `node:crypto`'s verifier wants.
 * Reuses PCA's `parseSevSnpReport` for the report layout, so there is no parallel parser. FAILS CLOSED: a
 * parse error, an unexpected signature algorithm, a non-P384 VCEK, out-of-range scalars, or a bad signature
 * all return `{ ok:false, reason }`; never throws.
 */
export function verifySevSnpSignature(rawReport: Uint8Array, vcekCertDerOrPem: CertInput): SevSnpSignatureResult {
  try {
    let report: ParsedSevSnpReport;
    try {
      report = parseSevSnpReport(rawReport);
    } catch (e) {
      return { ok: false, reason: `report parse failed: ${msg(e)}` };
    }
    if (report.signature_algo !== SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384) {
      return { ok: false, reason: `unexpected signature_algo ${report.signature_algo} (expected ECDSA_P384_SHA384 = ${SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384})` };
    }

    let vcekKey: KeyObject;
    try {
      vcekKey = loadP384PublicKey(vcekCertDerOrPem, 'VCEK certificate');
    } catch (e) {
      return { ok: false, reason: `VCEK certificate invalid: ${msg(e)}` };
    }

    const r = leBytesToBigInt(report.signature.r);
    const s = leBytesToBigInt(report.signature.s);
    if (r <= 0n || r >= P384_ORDER || s <= 0n || s >= P384_ORDER) {
      return { ok: false, reason: 'report signature r/s is zero or >= the P-384 group order (structurally invalid)' };
    }

    let sig: Buffer;
    try {
      sig = Buffer.concat([bigIntToBe(r, 48), bigIntToBe(s, 48)]);
    } catch (e) {
      return { ok: false, reason: `report signature scalar does not fit P-384: ${msg(e)}` };
    }

    const ok = nodeVerify('sha384', report.signed, { key: vcekKey, dsaEncoding: 'ieee-p1363' }, sig);
    return ok ? { ok: true } : { ok: false, reason: 'ECDSA-P384 report signature does not verify under the VCEK public key' };
  } catch (e) {
    return { ok: false, reason: `sev-snp signature verification error (fail closed): ${msg(e)}` };
  }
}

/** Options for {@link verifyAmdCertChain}. */
export interface AmdCertChainOptions {
  /**
   * Pin the ARK: its SPKI SHA-384 (hex) must equal this, or be one of these. Default: the values of
   * {@link KNOWN_AMD_ARK_SPKI_SHA384} (currently the real AMD Milan root). Inject another generation's
   * published fingerprint (Genoa/Bergamo/Turin) here.
   */
  rootFingerprint?: string | readonly string[];
  /** "Now" (epoch ms) for the validity-period checks. Default `Date.now()`. */
  now?: number;
}

/** The outcome of {@link verifyAmdCertChain}: ok + the VCEK key, or a specific reason it failed closed. */
export interface AmdCertChainResult {
  ok: boolean;
  reason?: string;
  /** The VCEK EC-P384 public key (present iff the whole chain verified) — ready to verify the report under. */
  vcek?: KeyObject;
  /** The ARK SPKI SHA-384 (hex) that matched a pin (present iff the chain verified). */
  arkFingerprint?: string;
}

/** Resolve the effective set of accepted ARK fingerprints (hex) from the option (default: the known set). */
function resolveArkPins(fp?: string | readonly string[]): string[] {
  if (fp === undefined) return Object.values(KNOWN_AMD_ARK_SPKI_SHA384);
  const list = typeof fp === 'string' ? [fp] : fp;
  const out: string[] = [];
  for (const p of list) if (typeof p === 'string' && p.length > 0) out.push(p.toLowerCase());
  return out;
}

/**
 * Verify the AMD "Versioned Chip Endorsement Key" certificate chain of trust, with `node:crypto` only:
 *   1. every certificate (VCEK, ASK, ARK) is WITHIN its validity period at `now`;
 *   2. the ARK is SELF-SIGNED (`ark.verify(ark.publicKey)`);
 *   3. the ARK is the KNOWN AMD root — its SPKI SHA-384 equals a pinned fingerprint (default
 *      {@link KNOWN_AMD_ARK_SPKI_SHA384}, or an injected `rootFingerprint`); the root is NEVER trusted
 *      just because it is self-signed;
 *   4. the ASK is signed by the ARK (`ask.verify(ark.publicKey)`);
 *   5. the VCEK is signed by the ASK (`vcek.verify(ask.publicKey)`).
 * Each `X509Certificate.verify` is the OpenSSL-backed check, so it covers the real AMD mix (an EC-P384 VCEK
 * leaf under RSA-PSS ASK/ARK) as well as an all-ECDSA test chain. Returns the VCEK public key on success so
 * the caller can verify the report signature under exactly the chain-trusted key. FAILS CLOSED on any
 * broken link; never throws.
 */
export function verifyAmdCertChain(
  vcekCert: CertInput,
  askCert: CertInput,
  arkCert: CertInput,
  opts: AmdCertChainOptions = {},
): AmdCertChainResult {
  try {
    const nowMs = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();

    let vcek: X509Certificate;
    let ask: X509Certificate;
    let ark: X509Certificate;
    try {
      vcek = loadCert(vcekCert);
      ask = loadCert(askCert);
      ark = loadCert(arkCert);
    } catch (e) {
      return { ok: false, reason: `certificate parse failed: ${msg(e)}` };
    }

    const certs: ReadonlyArray<readonly [string, X509Certificate]> = [
      ['VCEK', vcek],
      ['ASK', ask],
      ['ARK', ark],
    ];
    for (const [label, c] of certs) {
      if (!withinValidity(c, nowMs)) return { ok: false, reason: `${label} certificate is outside its validity period` };
    }

    const pins = resolveArkPins(opts.rootFingerprint);
    if (pins.length === 0) return { ok: false, reason: 'no ARK trust-anchor fingerprint configured (fail closed)' };
    const arkFp = spkiSha384Hex(ark);
    if (!pins.some((p) => strEq(p, arkFp))) {
      return { ok: false, reason: 'ARK SPKI fingerprint does not match a pinned AMD root (untrusted root)' };
    }

    if (!ark.verify(ark.publicKey)) return { ok: false, reason: 'ARK is not self-signed' };
    if (!ask.verify(ark.publicKey)) return { ok: false, reason: 'ASK is not signed by ARK (broken chain link)' };
    if (!vcek.verify(ask.publicKey)) return { ok: false, reason: 'VCEK is not signed by ASK (broken chain link)' };

    let vcekKey: KeyObject;
    try {
      vcekKey = loadP384PublicKey(vcekCert, 'VCEK certificate');
    } catch (e) {
      return { ok: false, reason: `VCEK key invalid: ${msg(e)}` };
    }

    return { ok: true, vcek: vcekKey, arkFingerprint: arkFp };
  } catch (e) {
    return { ok: false, reason: `AMD chain verification error (fail closed): ${msg(e)}` };
  }
}

/** Input to {@link verifyAmdAttestation}: the raw report + its VCEK/ASK/ARK chain + optional policy gates. */
export interface AmdAttestationInput {
  /** The VCEK (leaf) certificate — DER or PEM. */
  vcek: CertInput;
  /** The ASK (intermediate) certificate — DER or PEM. */
  ask: CertInput;
  /** The ARK (root) certificate — DER or PEM. */
  ark: CertInput;
  /** Pin the ARK fingerprint(s) (default {@link KNOWN_AMD_ARK_SPKI_SHA384}). */
  rootFingerprint?: string | readonly string[];
  /** "Now" (epoch ms) for certificate validity checks. Default `Date.now()`. */
  now?: number;
  /** If set, the report's launch MEASUREMENT (48-byte, hex) must equal this (binds the claimed identity to silicon). */
  expectedMeasurement?: string;
  /** If true, the report's guest POLICY DEBUG bit (19) must be CLEAR (else no confidentiality). */
  requireDebugDisabled?: boolean;
}

/** The single verdict {@link verifyAmdAttestation} returns. */
export interface AmdAttestationResult {
  ok: boolean;
  reason?: string;
  /** Honest label of the hardware root verified — a CLASSICAL ECDSA/RSA chain, not post-quantum. */
  hardwareRoot: string;
  /** The parsed report (present once it parsed, even on a later-stage failure). */
  report?: ParsedSevSnpReport;
  /** The JSON-safe EAT evidence projection (present on success). */
  evidence?: EatSevSnpEvidence;
  /** The hardware-measured identity (present on success). */
  measured?: MeasuredIdentity;
  /** The matched ARK SPKI fingerprint (present on success). */
  arkFingerprint?: string;
}

/**
 * Compose the full AMD SEV-SNP hardware root of trust into one verdict:
 *   parse report → verify the VCEK→ASK→ARK chain (ARK pinned, validity honoured) → verify the report's
 *   ECDSA-P384 signature under the chain-trusted VCEK → (optional) check the launch measurement and the
 *   DEBUG policy bit.
 * On success it returns the parsed report plus its {@link evidenceFromReport} / {@link measuredFromReport}
 * projections, so a caller can emit a channel-bound EAT whose evidence is now silicon-verified and which
 * {@link verifyFreshAttestedEAT} will appraise to the hardware-rooted tier. FAILS CLOSED on any failure.
 */
export function verifyAmdAttestation(rawReport: Uint8Array, opts: AmdAttestationInput): AmdAttestationResult {
  const hardwareRoot = AMD_SEV_SNP_HARDWARE_ROOT_LABEL;
  try {
    let report: ParsedSevSnpReport;
    try {
      report = parseSevSnpReport(rawReport);
    } catch (e) {
      return { ok: false, reason: `report parse failed: ${msg(e)}`, hardwareRoot };
    }

    const chain = verifyAmdCertChain(opts.vcek, opts.ask, opts.ark, {
      ...(opts.rootFingerprint !== undefined ? { rootFingerprint: opts.rootFingerprint } : {}),
      ...(opts.now !== undefined ? { now: opts.now } : {}),
    });
    if (!chain.ok) return { ok: false, reason: `cert chain invalid: ${chain.reason ?? 'unknown'}`, hardwareRoot, report };

    const sig = verifySevSnpSignature(rawReport, opts.vcek);
    if (!sig.ok) return { ok: false, reason: sig.reason ?? 'report signature invalid', hardwareRoot, report };

    if (typeof opts.expectedMeasurement === 'string' && opts.expectedMeasurement.length > 0) {
      const got = toHex(report.measurement);
      if (!strEq(got, opts.expectedMeasurement.toLowerCase())) {
        return { ok: false, reason: 'report launch measurement does not match the expected measurement', hardwareRoot, report };
      }
    }
    if (opts.requireDebugDisabled === true && (report.policy & SEV_SNP_POLICY_DEBUG_BIT) !== 0n) {
      return { ok: false, reason: 'guest policy DEBUG bit (19) is set — host can inspect the guest (no confidentiality)', hardwareRoot, report };
    }

    return {
      ok: true,
      hardwareRoot,
      report,
      evidence: evidenceFromReport(report),
      measured: measuredFromReport(report),
      ...(chain.arkFingerprint !== undefined ? { arkFingerprint: chain.arkFingerprint } : {}),
    };
  } catch (e) {
    return { ok: false, reason: `AMD attestation verification error (fail closed): ${msg(e)}`, hardwareRoot };
  }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Composition: verify + freshness + channel binding + appraisal → one verdict.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * The AMD SEV-SNP hardware-root evidence a resource server can hand {@link verifyFreshAttestedEAT} so it
 * verifies the silicon signature + chain ITSELF (not trusting the attester's say-so) and, on success,
 * upgrades the verdict to the hardware-rooted tier.
 */
export interface FreshAttestedAmdInput {
  /** The raw AMD SEV-SNP `ATTESTATION_REPORT` bytes the EAT's evidence was projected from. */
  rawReport: Uint8Array;
  /** The VCEK (leaf) certificate — DER or PEM. */
  vcek: CertInput;
  /** The ASK (intermediate) certificate — DER or PEM. */
  ask: CertInput;
  /** The ARK (root) certificate — DER or PEM. */
  ark: CertInput;
  /** Pin the ARK fingerprint(s) (default {@link KNOWN_AMD_ARK_SPKI_SHA384}). */
  rootFingerprint?: string | readonly string[];
  /** If true, require the report's guest POLICY DEBUG bit to be clear. */
  requireDebugDisabled?: boolean;
  /**
   * The launch MEASUREMENT (hex) the report must carry. Defaults to the EAT's OWN claimed launch
   * measurement, so the verified silicon report is cross-bound to the identity the EAT asserts.
   */
  expectedMeasurement?: string;
}

/** Options for {@link verifyFreshAttestedEAT}. */
export interface VerifyFreshAttestedEatOptions {
  /** The attester's public key (node:crypto `KeyObject`). */
  verifyKey: VerifyKey;
  /**
   * OPTIONAL AMD SEV-SNP hardware root verification. When supplied, the raw report's ECDSA-P384 signature
   * and the VCEK→ASK→ARK chain are verified HERE: success upgrades the verdict to `affirming-hw-rooted`; a
   * failure fails the whole verdict closed (`contraindicated`). Omit it to appraise the EAT's evidence
   * without re-checking the silicon (the prior behaviour, capped at `affirming`).
   */
  amd?: FreshAttestedAmdInput;
  /** The server-issued / per-session nonce the token's `eat_nonce` must equal (anti-replay). */
  nonce: string;
  /** The TLS channel id / exporter value observed on the live connection (RA-TLS). Supply this OR {@link channelBinding}. */
  channelId?: string;
  /** A raw expected `cnf` observed on the live connection (alternative to {@link channelId}). */
  channelBinding?: EatCnf;
  /** The RATS appraisal policy (endorsements + reference values). */
  policy: AppraisalPolicy;
  /** "Now", epoch ms (default `Date.now`). */
  now?: number;
  /** Max token age (ms), now − iat (default {@link DEFAULT_MAX_AGE_MS}). */
  maxAgeMs?: number;
  /** Allowed clock skew (ms), default 0. */
  clockSkewMs?: number;
  /** Require this issuer (`iss`). */
  issuer?: string | string[];
  /** Restrict the accepted signing algorithms. */
  algorithms?: EatAlg[];
  /** Override the required `typ` header (default `eat+jwt`). */
  typ?: string;
  /** Set `false` to skip the `typ` check. */
  requireTyp?: boolean;
}

/** The single verdict {@link verifyFreshAttestedEAT} returns for a resource server. */
export interface FreshAttestedVerdict {
  /** True iff the EAT is authentic, fresh, channel-bound AND appraised acceptable (affirming or warning). */
  ok: boolean;
  /** The appraisal tier, once appraisal ran. */
  tier?: AttestationTier;
  /** Reasons — the gates passed on success, or the gate(s) that failed. */
  reasons: string[];
  /** The parsed claims (present once the signature verified). */
  claims?: EatClaims;
}

/**
 * The end-to-end check a resource server runs ALONGSIDE `requirePCA`: verify the EAT's signature, then its
 * FRESHNESS (nonce + iat), its CHANNEL BINDING (cnf vs the live channel, RA-TLS), and finally APPRAISE it
 * against the RATS policy. Returns a single {@link FreshAttestedVerdict}; the first failing gate stops the
 * pipeline and names the reason. Composes with — does not replace — PCA's hardware root verification: run
 * that to prove the evidence is genuine, then this to prove it is fresh + on-channel.
 */
export function verifyFreshAttestedEAT(eat: string, opts: VerifyFreshAttestedEatOptions): FreshAttestedVerdict {
  const reasons: string[] = [];
  let claims: EatClaims;
  try {
    claims = verifyEAT(eat, opts.verifyKey, {
      ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}),
      ...(opts.algorithms !== undefined ? { algorithms: opts.algorithms } : {}),
      ...(opts.typ !== undefined ? { typ: opts.typ } : {}),
      ...(opts.requireTyp !== undefined ? { requireTyp: opts.requireTyp } : {}),
    });
  } catch (e) {
    return { ok: false, reasons: [`EAT signature/claims invalid: ${msg(e)}`] };
  }
  reasons.push('signature + typ/iss verified');

  const now = typeof opts.now === 'number' && Number.isFinite(opts.now) ? opts.now : Date.now();
  const fresh = verifyFreshness(claims, {
    expectedNonce: opts.nonce,
    maxAgeMs: opts.maxAgeMs ?? DEFAULT_MAX_AGE_MS,
    now,
    ...(opts.clockSkewMs !== undefined ? { clockSkewMs: opts.clockSkewMs } : {}),
  });
  if (!fresh.ok) return { ok: false, reasons: [...reasons, fresh.reason ?? 'not fresh'], claims };
  reasons.push('fresh (nonce + iat within window)');

  const chan = verifyChannelBinding(claims, {
    ...(opts.channelId !== undefined ? { channelId: opts.channelId } : {}),
    ...(opts.channelBinding !== undefined ? { expectedCnf: opts.channelBinding } : {}),
  });
  if (!chan.ok) return { ok: false, reasons: [...reasons, chan.reason ?? 'channel binding failed'], claims };
  reasons.push('channel-bound (cnf matches live channel)');

  // OPTIONAL AMD silicon root: verify the report signature + VCEK→ASK→ARK chain ourselves. A failure is an
  // active bad signal (fail closed); success lifts the appraisal to the hardware-rooted tier.
  let extras: AppraiseExtras = {};
  if (opts.amd !== undefined) {
    const expectedMeasurement = opts.amd.expectedMeasurement ?? launchMeasurement(claims);
    const hw = verifyAmdAttestation(opts.amd.rawReport, {
      vcek: opts.amd.vcek,
      ask: opts.amd.ask,
      ark: opts.amd.ark,
      now,
      ...(opts.amd.rootFingerprint !== undefined ? { rootFingerprint: opts.amd.rootFingerprint } : {}),
      ...(opts.amd.requireDebugDisabled !== undefined ? { requireDebugDisabled: opts.amd.requireDebugDisabled } : {}),
      ...(expectedMeasurement !== undefined ? { expectedMeasurement } : {}),
    });
    if (!hw.ok) {
      return { ok: false, tier: 'contraindicated', reasons: [...reasons, `AMD hardware root verification failed: ${hw.reason ?? 'unknown'}`], claims };
    }
    reasons.push(`AMD SEV-SNP hardware root verified (${hw.hardwareRoot})`);
    extras = { hardwareVerified: true, hardwareRootLabel: hw.hardwareRoot };
  }

  const app = appraise(claims, opts.policy.referenceValues ?? {}, opts.policy.endorsements ?? {}, extras);
  return { ok: app.trustworthy, tier: app.tier, reasons: [...reasons, ...app.reasons], claims };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Post-quantum co-signature of a verified attestation verdict (see ./pqcosign.ts).
//
// Once the classical AMD SEV-SNP hardware root has been verified (above), PCA's INTERNAL propagation of the
// resulting verdict is bound under a POST-QUANTUM signature (ML-DSA-65 by default), so downstream PCA trust
// in the recorded verdict no longer rests on classical crypto after that initial hardware check. This does
// NOT make AMD's hardware root post-quantum; it makes the verdict record forward-secure against a future
// quantum break of the classical root. ADDITIVE — no existing export's behaviour changes.
// ════════════════════════════════════════════════════════════════════════════════════════════════
export * from './pqcosign';
