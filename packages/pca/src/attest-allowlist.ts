/**
 * Signed, versioned, expiring measurement-allowlist manifests for the hardware-attestation verifiers.
 *
 * WHY: the verifiers (Azure MAA, Intel DCAP, SEV-SNP, GCP Confidential Space, NVIDIA GPU-CC) each take a
 * NON-EMPTY allowlist of golden measurements (TDX MRTD, SEV-SNP launch measurement, workload image digest,
 * NVIDIA driver version, ...). Those values change per image / boot configuration, and hand-editing them in
 * code is how stale or attacker-chosen values end up trusted. This module lets an operator PUBLISH one signed
 * manifest and lets a relying party VERIFY it and PROJECT it into the exact policy field shapes.
 *
 * WHAT IS GUARANTEED (given the caller supplies a trustworthy `issuerKeys` registry and a trustworthy clock):
 *   - the manifest body was signed, over a domain-separated canonical encoding, by a REGISTERED issuer key under
 *     the algorithm registered FOR THAT ISSUER (no algorithm downgrade: the manifest's `alg` must equal the
 *     registered one). Suites come from `pq.ts` (`ed25519`, `ml-dsa-65`, hybrids, ...), so the manifest can be
 *     post-quantum signed; a hybrid requires BOTH components.
 *   - the manifest is inside its `[notBefore, expiresAt]` window (+ optional skew) and `version` is not older
 *     than `minVersion` / `lastSeenVersion` (rollback is rejected). Same version with a different body digest
 *     than `lastSeenDigest` is rejected as a conflict.
 *   - values are well-formed and unique per kind; unknown kinds / extra fields are rejected (fail closed).
 *   - revoked entries (tombstones) and per-entry-expired entries are NEVER projected into a policy.
 *
 * WHAT IS NOT GUARANTEED:
 *   - This does not decide who the issuer is; trust in `issuerKeys` is the caller's root of trust.
 *   - Rollback protection has THREE layers, each closing the gap the previous leaves:
 *       1. `lastSeenVersion` / `lastSeenDigest` / `minVersion` you pass in (stateless; you own persistence).
 *       2. `verifyAllowlistDurable` + `openDurableState` (durable-state.ts): the high-water mark is persisted
 *          crash-safely, hash-chained and cross-process serialised; corrupt or truncated state fails closed. It
 *          still resets if an attacker with write access wipes the WHOLE state directory (or restores an older
 *          journal+head pair when no `hmacKey` is used).
 *       3. `verifyAllowlistAnchored` (attest-allowlist-anchor.ts): the operator anchors {issuer, version, digest} in an
 *          append-only Merkle log; the verifier rejects any version below the highest anchored one with NO local
 *          state. That needs a log whose operator is not also the attacker: without a cached head and without
 *          witness cosignatures (`trust.witnesses`) a malicious log operator can still replay an old head inside
 *          `maxHeadAgeMs`. The log is only as honest as its witnesses.
 *     With none of the three, a fresh process can be served an older, still-unexpired manifest.
 *   - An allowlist says "this measurement is acceptable"; it does not say the measurement is secure. A revoked
 *     entry is only effective once the relying party has fetched a manifest that contains the tombstone.
 *   - Projections may be EMPTY (e.g. no SEV-SNP entries); verifiers that require a non-empty list will throw
 *     at construction - that is intentional.
 */
import { canonicalBytes, hashCanonical, utf8 } from './hash';
import type { DurableKv } from './durable-state';
import { SIG_SUITES, isKnownSigAlg, signWithSuite, verifyWithSuite, type SigAlg, type SuitePublicKeys, type SuiteSecretKeys } from './pq';

/** The closed set of allowlist entry kinds. */
export const ALLOWLIST_KINDS = [
  'tdx-mrtd',
  'tdx-rtmr',
  'sev-snp-measurement',
  'gcp-image-digest',
  'nvidia-measurement',
  'nvidia-driver-version',
  'maa-signing-spki',
  'maa-chain-root-spki',
  'maa-chain-intermediate-spki',
  'attest-corroboration',
] as const;
export type AllowlistKind = (typeof ALLOWLIST_KINDS)[number];

/** One allowlist entry. `revoked: true` is a tombstone: the value is explicitly NOT acceptable. */
export interface AllowlistEntry {
  kind: AllowlistKind;
  /**
   * Kind-specific canonical value: lowercase 96-hex (tdx-mrtd, tdx-rtmr, sev-snp-measurement,
   * nvidia-measurement); `sha256:<64 lowercase hex>` (gcp-image-digest); dotted version like `595.71.05`
   * (nvidia-driver-version); 64 lowercase hex SPKI SHA-256 (maa-signing-spki, maa-chain-root-spki,
   * maa-chain-intermediate-spki); 64 lowercase hex evidence digest (attest-corroboration).
   */
  value: string;
  /**
   * Human label. For `maa-signing-spki` it MUST be the MAA instance issuer URL the key belongs to. For
   * `attest-corroboration` it MUST be `vantages=<n>;method=<printable text>` (the signed record of how many
   * independent network vantage points agreed on the pins in this manifest).
   */
  label: string;
  /** Optional per-entry expiry (epoch ms). After it the entry is dropped from projections. */
  notAfter?: number;
  /** Tombstone: kills the value without waiting for manifest expiry. */
  revoked?: boolean;
}

/** The signed body of a manifest. All times are integer epoch milliseconds. */
export interface AllowlistManifestBody {
  /** Strictly monotone positive integer. */
  version: number;
  issuedAt: number;
  notBefore: number;
  expiresAt: number;
  entries: AllowlistEntry[];
}

/** A signed manifest as it travels on the wire. */
export interface SignedAllowlistManifest {
  body: AllowlistManifestBody;
  /** Issuer key id (lookup key in `issuerKeys`). */
  issuer: string;
  alg: SigAlg;
  sig: string;
  pq_sig?: string;
}

/** A registered issuer: the algorithm it signs with and its public key(s). */
export interface AllowlistIssuerKey {
  alg: SigAlg;
  keys: SuitePublicKeys;
  /** Optional: stop trusting this issuer key at this time (epoch ms). */
  notAfter?: number;
}

export type AllowlistErrorCode =
  | 'malformed'
  | 'unknown-issuer'
  | 'issuer-expired'
  | 'alg-mismatch'
  | 'bad-signature'
  | 'not-yet-valid'
  | 'expired'
  | 'rollback'
  | 'below-min-version'
  | 'conflict'
  | 'lifetime-too-long';

export interface VerifyAllowlistOptions {
  issuerKeys: Readonly<Record<string, AllowlistIssuerKey>>;
  nowMs: number;
  /** Deployment-shipped floor; versions below it are rejected. */
  minVersion?: number;
  /** Highest version this relying party has accepted before (persisted by the caller). */
  lastSeenVersion?: number;
  /** Digest (from a previous `ok` result) of the manifest at `lastSeenVersion`. */
  lastSeenDigest?: string;
  clockSkewMs?: number;
  /** Reject manifests whose `expiresAt - notBefore` exceeds this (bounds the rollback window). */
  maxLifetimeMs?: number;
}

export type VerifyAllowlistResult =
  | { ok: true; body: AllowlistManifestBody; issuer: string; alg: SigAlg; version: number; digest: string }
  | { ok: false; code: AllowlistErrorCode; reason: string };

const HEX96 = /^[0-9a-f]{96}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const DRIVER_VERSION = /^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$/;
const CORROBORATION_LABEL = /^vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}$/;
const ISSUER_URL = /^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/;
const B64U_DIGEST = /^[A-Za-z0-9_-]{43}$/;
const DOMAIN = 'pca-attest-allowlist/v1\n';
const BODY_KEYS = ['version', 'issuedAt', 'notBefore', 'expiresAt', 'entries'];
const ENTRY_KEYS = ['kind', 'value', 'label', 'notAfter', 'revoked'];
const MANIFEST_KEYS = ['body', 'issuer', 'alg', 'sig', 'pq_sig'];
const MAX_ENTRIES = 10_000;

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}
function onlyKeys(r: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(r).every((k) => allowed.includes(k));
}
function isEpoch(x: unknown): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
}

/** Validate a value for its kind. Returns an error string or null. */
function valueError(kind: AllowlistKind, value: string, label: string): string | null {
  switch (kind) {
    case 'tdx-mrtd':
    case 'tdx-rtmr':
    case 'sev-snp-measurement':
    case 'nvidia-measurement':
      return HEX96.test(value) ? null : `${kind} must be 96 lowercase hex chars`;
    case 'gcp-image-digest':
      return IMAGE_DIGEST.test(value) ? null : 'gcp-image-digest must be sha256:<64 lowercase hex>';
    case 'nvidia-driver-version':
      return DRIVER_VERSION.test(value) && value.length <= 16 ? null : 'nvidia-driver-version must be a dotted version of at most 16 chars';
    case 'maa-signing-spki':
      if (!HEX64.test(value)) return 'maa-signing-spki must be 64 lowercase hex chars';
      return ISSUER_URL.test(label) ? null : 'maa-signing-spki label must be the https issuer URL (no path, no trailing slash)';
    case 'maa-chain-root-spki':
    case 'maa-chain-intermediate-spki':
      return HEX64.test(value) ? null : `${kind} must be 64 lowercase hex chars`;
    case 'attest-corroboration':
      if (!HEX64.test(value)) return 'attest-corroboration must be a 64 lowercase hex evidence digest';
      return CORROBORATION_LABEL.test(label) ? null : 'attest-corroboration label must be vantages=<n>;method=<text>';
  }
}

/** Strictly validate and copy an untrusted body. Throws TypeError describing the first violation. */
function parseBody(x: unknown): AllowlistManifestBody {
  if (!isRecord(x) || !onlyKeys(x, BODY_KEYS)) throw new TypeError('body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries');
  const { version, issuedAt, notBefore, expiresAt, entries } = x;
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) throw new TypeError('version must be a positive integer');
  if (!isEpoch(issuedAt) || !isEpoch(notBefore) || !isEpoch(expiresAt)) throw new TypeError('issuedAt/notBefore/expiresAt must be integer epoch ms');
  if (!(notBefore < expiresAt)) throw new TypeError('notBefore must be before expiresAt');
  if (!(issuedAt <= expiresAt)) throw new TypeError('issuedAt must not be after expiresAt');
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) throw new TypeError('entries must be an array (bounded)');
  const seen = new Set<string>();
  const out: AllowlistEntry[] = [];
  for (const [i, e] of entries.entries()) {
    if (!isRecord(e) || !onlyKeys(e, ENTRY_KEYS)) throw new TypeError(`entry ${i}: unexpected shape`);
    const { kind, value, label, notAfter, revoked } = e;
    if (typeof kind !== 'string' || !(ALLOWLIST_KINDS as readonly string[]).includes(kind)) throw new TypeError(`entry ${i}: unknown kind`);
    if (typeof value !== 'string' || typeof label !== 'string') throw new TypeError(`entry ${i}: value and label must be strings`);
    if (label.length < 1 || label.length > 200 || /[\u0000-\u001f\u007f]/.test(label)) throw new TypeError(`entry ${i}: label must be 1..200 printable chars`);
    const k = kind as AllowlistKind;
    const ve = valueError(k, value, label);
    if (ve) throw new TypeError(`entry ${i}: ${ve}`);
    if (notAfter !== undefined && !isEpoch(notAfter)) throw new TypeError(`entry ${i}: notAfter must be integer epoch ms`);
    if (revoked !== undefined && revoked !== true) throw new TypeError(`entry ${i}: revoked, when present, must be true`);
    const dupKey = `${k}\u0000${k === 'maa-signing-spki' ? `${label}\u0000` : ''}${value}`;
    if (seen.has(dupKey)) throw new TypeError(`entry ${i}: duplicate ${k} value`);
    seen.add(dupKey);
    out.push({ kind: k, value, label, ...(notAfter !== undefined ? { notAfter } : {}), ...(revoked === true ? { revoked: true } : {}) });
  }
  return { version, issuedAt, notBefore, expiresAt, entries: out };
}

function signedBytes(body: AllowlistManifestBody): Uint8Array {
  const dom = utf8(DOMAIN);
  const c = canonicalBytes(body);
  const out = new Uint8Array(dom.length + c.length);
  out.set(dom, 0);
  out.set(c, dom.length);
  return out;
}

function fail(code: AllowlistErrorCode, reason: string): VerifyAllowlistResult {
  return { ok: false, code, reason };
}

/**
 * Verify a signed manifest. Never throws; every failure is a typed `{ok:false, code}`. See the module header
 * for exactly what an `ok` result does and does not mean.
 */
export function verifyAllowlistManifest(manifest: unknown, opts: VerifyAllowlistOptions): VerifyAllowlistResult {
  try {
    if (!isRecord(manifest) || !onlyKeys(manifest, MANIFEST_KEYS)) return fail('malformed', 'manifest has an unexpected shape');
    if (!Number.isSafeInteger(opts?.nowMs)) return fail('malformed', 'nowMs must be an integer');
    const { issuer, alg, sig } = manifest;
    const pqSig = manifest.pq_sig;
    if (typeof issuer !== 'string' || issuer.length === 0 || issuer.length > 200) return fail('malformed', 'issuer must be a string');
    if (typeof alg !== 'string' || !isKnownSigAlg(alg)) return fail('malformed', 'unknown signature alg');
    if (typeof sig !== 'string') return fail('malformed', 'sig must be a string');
    if (pqSig !== undefined && typeof pqSig !== 'string') return fail('malformed', 'pq_sig must be a string');
    if (!SIG_SUITES[alg].needsPqSig !== (pqSig === undefined)) return fail('malformed', 'pq_sig presence does not match the suite');
    let body: AllowlistManifestBody;
    try {
      body = parseBody(manifest.body);
    } catch (e) {
      return fail('malformed', e instanceof Error ? e.message : 'invalid body');
    }
    if (!Object.prototype.hasOwnProperty.call(opts.issuerKeys, issuer)) return fail('unknown-issuer', `issuer '${issuer}' is not registered`);
    const reg = opts.issuerKeys[issuer]!;
    if (reg.alg !== alg) return fail('alg-mismatch', `issuer is registered for '${reg.alg}', manifest claims '${alg}'`);
    if (reg.notAfter !== undefined && opts.nowMs > reg.notAfter) return fail('issuer-expired', 'issuer key is past its notAfter');
    if (!verifyWithSuite(alg, reg.keys, signedBytes(body), { sig, ...(pqSig !== undefined ? { pq_sig: pqSig } : {}) })) {
      return fail('bad-signature', 'signature does not verify under the registered issuer key');
    }
    // Signature is good from here on; remaining checks are policy over authentic content.
    const skew = Math.max(0, opts.clockSkewMs ?? 0);
    if (opts.nowMs + skew < body.notBefore) return fail('not-yet-valid', 'manifest is not yet valid');
    if (opts.nowMs - skew > body.expiresAt) return fail('expired', 'manifest has expired');
    if (opts.maxLifetimeMs !== undefined && body.expiresAt - body.notBefore > opts.maxLifetimeMs) return fail('lifetime-too-long', 'manifest lifetime exceeds maxLifetimeMs');
    if (opts.minVersion !== undefined && body.version < opts.minVersion) return fail('below-min-version', `version ${body.version} < minVersion ${opts.minVersion}`);
    const digest = hashCanonical(body);
    if (opts.lastSeenVersion !== undefined) {
      if (body.version < opts.lastSeenVersion) return fail('rollback', `version ${body.version} is older than last seen ${opts.lastSeenVersion}`);
      if (body.version === opts.lastSeenVersion && opts.lastSeenDigest !== undefined && opts.lastSeenDigest !== digest) {
        return fail('conflict', 'same version as last seen but a different body');
      }
    }
    return { ok: true, body, issuer, alg, version: body.version, digest };
  } catch (e) {
    return fail('malformed', e instanceof Error ? e.message : 'verification error');
  }
}

/** Persisted high-water mark per issuer. */
interface AllowlistHighWater {
  version: number;
  digest: string;
}
const highWaterKey = (issuer: string): string => `allowlist/${issuer}`;
function parseHighWater(x: unknown): AllowlistHighWater | undefined {
  if (!isRecord(x) || typeof x['version'] !== 'number' || !Number.isSafeInteger(x['version']) || typeof x['digest'] !== 'string' || !B64U_DIGEST.test(x['digest'])) return undefined;
  return { version: x['version'], digest: x['digest'] };
}

/**
 * {@link verifyAllowlistManifest} with the rollback high-water mark kept in durable state (`openDurableState`).
 * The stored (version, digest) per issuer is fed in as `lastSeen*`; an accepted manifest atomically advances it
 * (monotone: it can only ever move up; a concurrent newer acceptance by another process turns this one into a
 * `rollback`). Corrupt stored state fails closed with `malformed`. Deleting the state directory resets it, which
 * is what the transparency anchor (attest-allowlist-anchor) covers.
 */
export async function verifyAllowlistDurable(
  manifest: unknown,
  opts: Omit<VerifyAllowlistOptions, 'lastSeenVersion' | 'lastSeenDigest'>,
  kv: DurableKv,
): Promise<VerifyAllowlistResult> {
  try {
    const issuer = isRecord(manifest) && typeof manifest['issuer'] === 'string' && manifest['issuer'].length <= 200 ? manifest['issuer'] : undefined;
    if (issuer === undefined) return fail('malformed', 'issuer must be a string');
    const raw = await kv.get(highWaterKey(issuer));
    const prior = raw === undefined ? undefined : parseHighWater(raw);
    if (raw !== undefined && prior === undefined) return fail('malformed', 'persisted allowlist high-water mark is corrupt');
    const v = verifyAllowlistManifest(manifest, { ...opts, ...(prior ? { lastSeenVersion: prior.version, lastSeenDigest: prior.digest } : {}) });
    if (!v.ok) return v;
    const after = parseHighWater(
      await kv.update(highWaterKey(issuer), (cur) => {
        const c = cur === undefined ? undefined : parseHighWater(cur);
        if (cur !== undefined && c === undefined) return undefined; // leave a corrupt record for the next read to reject
        if (c !== undefined && (c.version > v.version || (c.version === v.version && c.digest === v.digest))) return undefined;
        return { version: v.version, digest: v.digest } satisfies AllowlistHighWater;
      }),
    );
    if (after === undefined || after.version > v.version) return fail('rollback', 'a newer manifest was accepted concurrently');
    if (after.version === v.version && after.digest !== v.digest) return fail('conflict', 'same version as the stored high-water mark but a different body');
    return v;
  } catch (e) {
    return fail('malformed', e instanceof Error ? e.message : 'durable verification error');
  }
}

/** Validate operator input and return a canonical body. THROWS on any violation (an operator-side tool). */
export function createAllowlistManifest(input: AllowlistManifestBody): AllowlistManifestBody {
  return parseBody(input);
}

/** Sign a body with an issuer key under `alg`. THROWS if key material for the suite is missing. */
export function signAllowlistManifest(
  body: AllowlistManifestBody,
  opts: { issuer: string; alg: SigAlg; secrets: SuiteSecretKeys },
): SignedAllowlistManifest {
  const clean = parseBody(body);
  const parts = signWithSuite(opts.alg, opts.secrets, signedBytes(clean));
  return { body: clean, issuer: opts.issuer, alg: opts.alg, sig: parts.sig, ...(parts.pq_sig !== undefined ? { pq_sig: parts.pq_sig } : {}) };
}

/**
 * Derive the next body that revokes `kind`/`value` (adds or flips a tombstone) with `version + 1`. The
 * result must be re-signed. THROWS if the value is not well-formed for its kind.
 */
export function revokeAllowlistEntry(
  prev: AllowlistManifestBody,
  rev: { kind: AllowlistKind; value: string; label?: string },
  times: { issuedAt: number; notBefore: number; expiresAt: number },
): AllowlistManifestBody {
  const entries = prev.entries.map((e) => ({ ...e }));
  const hit = entries.find((e) => e.kind === rev.kind && e.value === rev.value && (rev.kind !== 'maa-signing-spki' || e.label === rev.label));
  if (hit) hit.revoked = true;
  else entries.push({ kind: rev.kind, value: rev.value, label: rev.label ?? 'revoked', revoked: true });
  return parseBody({ version: prev.version + 1, ...times, entries });
}

/** The projection of a verified manifest into plain arrays shaped for the existing verifiers' policies. */
export interface AllowlistProjection {
  /** `AzureMaaPolicy.tdxMrtds`. */
  tdxMrtds: string[];
  /** `AzureMaaPolicy.tdxRtmrs` / `IntelDcapPolicy.rtmrs`. */
  tdxRtmrs: string[];
  /** `AzureMaaPolicy.sevSnpMeasurements` / SEV-SNP `policy.measurements`. */
  sevSnpMeasurements: string[];
  /** `GcpCsPolicy.imageDigests`. */
  imageDigests: string[];
  /** `NvidiaCcPolicy.measurements`. */
  nvidiaMeasurements: string[];
  /** Dotted driver versions (as `hostAsserted.driver_version` / RIM naming reports them). */
  nvidiaDriverVersions: string[];
  /** `NvidiaCcPolicy.driverVersions`: lowercase hex of the ASCII version zero-padded to the 16-byte slot. */
  nvidiaCcDriverVersions: string[];
  /** Approved MAA signing-key SPKI SHA-256 pins, by issuer URL (see attest-maa-keys re-pin). */
  maaSigningSpkis: Record<string, string[]>;
  /** SPKI SHA-256 pins of the CA roots under which Microsoft-chained MAA keys are accepted. */
  maaChainRootSpkis: string[];
  /** SPKI SHA-256 pins of an intermediate CA that every accepted chained key MUST also pass through. */
  maaChainIntermediateSpkis: string[];
  /** Signed multi-vantage corroboration records (`attest-corroboration`). */
  corroboration: Array<{ value: string; label: string }>;
  /** Tombstones: values that must be treated as DENIED (e.g. to also strip them from other lists). */
  revoked: Array<{ kind: AllowlistKind; value: string; label: string }>;
  /** Entries dropped because their own `notAfter` passed. */
  expired: Array<{ kind: AllowlistKind; value: string; label: string }>;
  version: number;
  manifestExpiresAt: number;
}

/** Zero-padded 16-byte-slot hex of a dotted driver version (matches `NvidiaCcPolicy.driverVersions`). */
export function driverVersionSlotHex(version: string): string {
  if (!DRIVER_VERSION.test(version) || version.length > 16) throw new TypeError('invalid driver version');
  return Buffer.from(version, 'ascii').toString('hex').padEnd(32, '0');
}

/**
 * Project a VERIFIED manifest into policy arrays at `nowMs`. Revoked entries and entries past their own
 * `notAfter` are excluded; a value that is revoked anywhere is excluded even if it appears elsewhere.
 * Accepts only an `ok` result from {@link verifyAllowlistManifest} (typed, so an unverified manifest cannot
 * be passed by accident - though TypeScript cannot stop a hand-forged `ok` object).
 */
export function projectAllowlist(verified: Extract<VerifyAllowlistResult, { ok: true }>, opts: { nowMs: number }): AllowlistProjection {
  const out: AllowlistProjection = {
    tdxMrtds: [],
    tdxRtmrs: [],
    sevSnpMeasurements: [],
    imageDigests: [],
    nvidiaMeasurements: [],
    nvidiaDriverVersions: [],
    nvidiaCcDriverVersions: [],
    maaSigningSpkis: {},
    maaChainRootSpkis: [],
    maaChainIntermediateSpkis: [],
    corroboration: [],
    revoked: [],
    expired: [],
    version: verified.body.version,
    manifestExpiresAt: verified.body.expiresAt,
  };
  const denied = new Set<string>();
  for (const e of verified.body.entries) {
    if (e.revoked === true) {
      denied.add(`${e.kind}\u0000${e.value}`);
      out.revoked.push({ kind: e.kind, value: e.value, label: e.label });
    }
  }
  for (const e of verified.body.entries) {
    if (e.revoked === true) continue;
    if (denied.has(`${e.kind}\u0000${e.value}`)) continue;
    if (e.notAfter !== undefined && opts.nowMs > e.notAfter) {
      out.expired.push({ kind: e.kind, value: e.value, label: e.label });
      continue;
    }
    switch (e.kind) {
      case 'tdx-mrtd':
        out.tdxMrtds.push(e.value);
        break;
      case 'tdx-rtmr':
        out.tdxRtmrs.push(e.value);
        break;
      case 'sev-snp-measurement':
        out.sevSnpMeasurements.push(e.value);
        break;
      case 'gcp-image-digest':
        out.imageDigests.push(e.value);
        break;
      case 'nvidia-measurement':
        out.nvidiaMeasurements.push(e.value);
        break;
      case 'nvidia-driver-version':
        out.nvidiaDriverVersions.push(e.value);
        out.nvidiaCcDriverVersions.push(driverVersionSlotHex(e.value));
        break;
      case 'maa-signing-spki':
        (out.maaSigningSpkis[e.label] ??= []).push(e.value);
        break;
      case 'maa-chain-root-spki':
        out.maaChainRootSpkis.push(e.value);
        break;
      case 'maa-chain-intermediate-spki':
        out.maaChainIntermediateSpkis.push(e.value);
        break;
      case 'attest-corroboration':
        out.corroboration.push({ value: e.value, label: e.label });
        break;
    }
  }
  return out;
}

/** Spreadable fields for `createAzureMaaVerifier({ policy })`. Empty lists are omitted. */
export function azureMaaPolicyFields(p: AllowlistProjection): { tdxMrtds?: string[]; sevSnpMeasurements?: string[]; tdxRtmrs?: string[] } {
  return {
    ...(p.tdxMrtds.length > 0 ? { tdxMrtds: [...p.tdxMrtds] } : {}),
    ...(p.sevSnpMeasurements.length > 0 ? { sevSnpMeasurements: [...p.sevSnpMeasurements] } : {}),
    ...(p.tdxRtmrs.length > 0 ? { tdxRtmrs: [...p.tdxRtmrs] } : {}),
  };
}

/** Spreadable fields for `createIntelDcapVerifier({ policy })`. `mrtds` is always present (may be empty => the verifier throws). */
export function intelDcapPolicyFields(p: AllowlistProjection): { mrtds: string[]; rtmrs?: string[] } {
  return { mrtds: [...p.tdxMrtds], ...(p.tdxRtmrs.length > 0 ? { rtmrs: [...p.tdxRtmrs] } : {}) };
}

/** Spreadable fields for the SEV-SNP verifiers' `policy`. */
export function sevSnpPolicyFields(p: AllowlistProjection): { measurements: string[] } {
  return { measurements: [...p.sevSnpMeasurements] };
}

/** Spreadable fields for `createGcpConfidentialSpaceVerifier({ policy })`. */
export function gcpCsPolicyFields(p: AllowlistProjection): { imageDigests: string[] } {
  return { imageDigests: [...p.imageDigests] };
}

/** Spreadable fields for `NvidiaCcPolicy` (driver gate omitted when no driver entries exist). */
export function nvidiaCcPolicyFields(p: AllowlistProjection): { measurements: string[]; driverVersions?: string[] } {
  return {
    measurements: [...p.nvidiaMeasurements],
    ...(p.nvidiaCcDriverVersions.length > 0 ? { driverVersions: [...p.nvidiaCcDriverVersions] } : {}),
  };
}
