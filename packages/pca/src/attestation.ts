/**
 * L0 — Attestation-derived workload identity for AI agents (spec §6 L0, Deep Dive I rows
 * "Model swap / malicious fine-tune" and "Agent RCE / key extraction").
 *
 * The spec's L0 says the agent has NO long-lived key: its per-epoch identity key is derived inside a
 * TEE from a remote-attestation quote that measures `model id + weights digest + runtime measurement
 * + operator identity`. Swap the model, tamper the runtime, or change the operator and the
 * measurement changes, so the identity evaporates. This module is the PROTOCOL + verifier for that
 * quote, with two honest modes:
 *
 *   - SOFTWARE mode (this file, `createDevAttestor`): a signed `AttestationDocument`. This is a real,
 *     checkable attestation for dev, CI and the "attested-VM equivalent" the spec sanctions — but the
 *     measurements are SELF-ASSERTED by the signer, not rooted in hardware. It proves "a key the RS
 *     trusts vouched for these measurements", NOT "this silicon is running exactly these weights".
 *   - HARDWARE mode (the `HardwareAttestationVerifier` seam): real SEV-SNP / TDX / SGX report
 *     verification (cert-chain to the CPU vendor root, measurement register checks, report_data/nonce
 *     binding). We deliberately DO NOT implement SEV-SNP/TDX quote parsing here — that is a large,
 *     vendor-specific, security-critical surface. We define the interface and the exact place it
 *     plugs in; `hardwareVerifier.verify()` returns the HARDWARE-measured identity, which then feeds
 *     the same freshness / nonce-binding / agent_binding checks as software mode. A production AMD
 *     SEV-SNP backend for this seam lives in `hardware-sevsnp.ts` (`createSevSnpVerifier`): it parses
 *     the ATTESTATION_REPORT, verifies the ECDSA-P384 report signature + the VCEK→ASK→ARK cert chain
 *     to a configured ARK trust anchor, and binds report_data to the nonce. Wire it in via
 *     `createAttestationVerifier({ hardwareVerifier: createSevSnpVerifier(...) })`.
 *
 * STANDARDIZATION GAP (spec §15 "Open problems" — "Standardizing weights-level attestation for hosted
 * models"): there is today NO cross-vendor standard for attesting a model's WEIGHTS digest from inside
 * a TEE. SEV-SNP/TDX attest the launch measurement of the confidential VM image, not "these specific
 * fp16 weights are loaded." Closing that gap needs either (a) the model runtime to measure the loaded
 * weights into a PCR/report field, or (b) a signed weights manifest the enclave verifies at load.
 *
 * HARDWARE-ROOTED WEIGHTS (approach (a), implemented in `hardware-sevsnp.ts`): the SEV-SNP backend
 * carries the model runtime's measured weights digest in a dedicated field INSIDE the report's signed
 * region, so the VCEK signature covers it and the host cannot alter it after the fact. The verifier
 * extracts it and returns it as `MeasuredIdentity.weights_digest` with `weights_measured: true`. A
 * grant that sets `agent_binding.require_measured_weights` then fails closed unless the matched digest
 * carries that silicon-measured provenance — so a self-asserted (software-mode) or host-asserted
 * (HOST_DATA) weights digest, even one that names an allowlisted value, is rejected. Without the flag,
 * `weights_allowlist` keeps its prior meaning: a value match, as strong as whatever produced the
 * document. `weights_allowlist` is the policy hook for pinning the digest; `require_measured_weights`
 * is the hook for demanding it be hardware-measured rather than merely vouched for.
 */
import { sha512 } from '@noble/hashes/sha512';
import { b64u, canonicalBytes, hashCanonical, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type MlDsaKeyPair,
  type SigAlg,
  bindSuiteFields,
  encodeMlDsaPublicKey,
  resolveSigAlg,
  signSuiteArtifact,
  verifyWithSuite,
} from './pq';
import type { AgentBinding } from './envelope';
import { readEnvelope } from './envelope';
import { TransparencyLedger, signTreeHead, type LedgerSuiteOpts, type SignedTreeHead } from './ledger';
import type { AttestationVerifier, HookResult, VerifyContext } from './pcactn';

const DOMAIN = 'atlas-pca/attest/v1\0';

/** Domain separator for the report_data binding hash (see `attestationBinding`). */
export const ATTEST_BIND_DOMAIN = 'atlas-pca/attest-bind/v1\0';

/**
 * Hard ceiling (ms) on the age of a server-issued attestation nonce at verification time. Hardware
 * mode derives freshness from `now - nonceIssuedAt` (server clock), NEVER from document dates; a
 * caller may tighten this via `maxNonceAgeMs` but never loosen it past this constant.
 */
export const MAX_ATTESTATION_AGE_MS = 5 * 60_000;

/**
 * What the SERVER expects an attestation to be bound to. All four fields are server-known values
 * (holder/grant/epoch come from the verified PCActn + grant; `nonce` was issued by the server and is
 * consumed once). `nonceIssuedAt` is the server's own record of when it issued the nonce (epoch ms).
 */
export interface ExpectedAttestationBinding {
  /** Encoded Ed25519 public key of the leaf holder the PCActn is signed by. */
  holderPub: string;
  /** The grant reference the PCActn acts under. */
  grantRef: string;
  /** The attestation epoch. */
  epoch: number;
  /** The server-issued, single-use nonce. */
  nonce: string;
  /** Server-recorded issue time of `nonce`, epoch ms. Freshness is derived from this. */
  nonceIssuedAt?: number;
}

function lp(s: string): Uint8Array {
  const b = utf8(s);
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false);
  out.set(b, 4);
  return out;
}

/**
 * The report_data / quote-bound value:
 *
 *   report_data = SHA-512( ATTEST_BIND_DOMAIN ‖ lp(holderPub) ‖ lp(grantRef) ‖ u64be(epoch) ‖ lp(nonce) )
 *
 * with lp(x) = u32be(len(x)) ‖ utf8(x) (unambiguous framing). 64 bytes = exactly the SEV-SNP
 * report_data width. A quote captured for one holder / grant / epoch / nonce cannot be relayed for
 * another: any change yields a different value. Throws on malformed expected fields.
 */
export function attestationBinding(exp: ExpectedAttestationBinding): Uint8Array {
  if (!exp || typeof exp.holderPub !== 'string' || exp.holderPub.length === 0) throw new TypeError('binding: holderPub required');
  if (typeof exp.grantRef !== 'string' || exp.grantRef.length === 0) throw new TypeError('binding: grantRef required');
  if (typeof exp.nonce !== 'string' || exp.nonce.length === 0) throw new TypeError('binding: nonce required');
  if (!Number.isSafeInteger(exp.epoch) || exp.epoch < 0) throw new TypeError('binding: epoch must be a non-negative safe integer');
  const parts = [utf8(ATTEST_BIND_DOMAIN), lp(exp.holderPub), lp(exp.grantRef), new Uint8Array(8), lp(exp.nonce)];
  new DataView(parts[3]!.buffer).setBigUint64(0, BigInt(exp.epoch), false);
  let n = 0;
  for (const p of parts) n += p.length;
  const buf = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return sha512(buf);
}

/** b64u form of `attestationBinding` (what software-mode documents carry in `binding`). */
export function attestationBindingB64u(exp: ExpectedAttestationBinding): string {
  return b64u(attestationBinding(exp));
}

/** Attestation mode. `software` = signed self-asserted doc; `hardware` = TEE-report-rooted. */
export type AttestationMode = 'software' | 'hardware';

/**
 * A remote-attestation document (the "quote" of spec §7's `attestation.quote_digest`). In software
 * mode it is signed by a `DevAttestor`; in hardware mode the same shape carries the fields a TEE
 * report yields, and the `HardwareAttestationVerifier` roots them in silicon.
 */
export interface AttestationDocument {
  /** Attested model identifier (matched against agent_binding.model_allowlist). */
  model_id: string;
  /** Digest of the loaded model weights (the field that moves on a model swap / fine-tune). */
  weights_digest: string;
  /** Runtime/launch measurement (matched against agent_binding.min_measurement). */
  runtime_measurement: string;
  /** Operator identity (matched against agent_binding.operator). */
  operator: string;
  /**
   * Optional measured digest of the agent's SYSTEM PROMPT / instructions ("provenance beyond
   * weights"). When present it is matched against agent_binding.system_prompt_allowlist. Absent =>
   * the document asserts no instructions measurement; a grant that pins system_prompt_allowlist then
   * fails closed. In hardware mode this comes from the TEE-measured identity, never a self-assertion.
   */
  system_prompt_digest?: string;
  /**
   * Optional measured digest of the agent's TOOL MANIFEST (the tools/functions it can call). When
   * present it is matched against agent_binding.tool_manifest_allowlist. Absent => no tool measurement;
   * a grant that pins tool_manifest_allowlist fails closed. Hardware-measured, never self-asserted,
   * under require_hardware.
   */
  tool_manifest_digest?: string;
  /**
   * Freshness/anti-replay challenge echoed into the quote. The PCActn binds to THIS document by
   * carrying `nonce` in its `attestation.quote_digest` field (see `nonceBinds`); a tampered nonce on
   * either side breaks the binding. In a real TEE this is the quote's report_data.
   */
  nonce: string;
  /** Issued-at (epoch ms). */
  issued_at: number;
  /** Expiry (epoch ms). Short-lived: L0 epochs are short and re-derived. */
  expires_at: number;
  /** b64u Ed25519 public key that signed this document (software mode). */
  attestor: string;
  /**
   * Software mode: b64u `attestationBinding({holderPub, grantRef, epoch, nonce})`, signed with the
   * rest of the body. Absent => the document is NOT bound and verification fails. (Hardware mode
   * carries the binding in the TEE report_data instead.)
   */
  binding?: string;
  /** Attestation mode this document claims. */
  mode: AttestationMode;
  /** b64u signature over the canonical body (all fields except `sig`/`pq_sig`). Ed25519 for ed25519/hybrid, ML-DSA-65 for pure. */
  sig: string;
  /**
   * Signature suite (crypto-agility). Absent == `ed25519` (byte-identical to pre-agility: software
   * documents sign and verify exactly as before). For `ml-dsa-65`/`hybrid` the suite + the attestor's
   * ML-DSA key `pq_pk` are SIGNED INTO the document body, and `pq_sig` carries the ML-DSA signature (hybrid).
   */
  alg?: SigAlg;
  /** b64u ML-DSA-65 public key of the software attestor — ml-dsa-65 / hybrid (body-bound). */
  pq_pk?: string;
  /** b64u ML-DSA-65 document signature — hybrid only. */
  pq_sig?: string;
}

export type AttestationBody = Omit<AttestationDocument, 'sig'>;

/** The canonical signed body EXCLUDES both signature fields (`sig`, `pq_sig`); `alg`/`pq_pk` are bound in and signed. */
function attestMessage(body: Omit<AttestationDocument, 'sig' | 'pq_sig'>): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/** base64url(sha256(canonical(document))) — a content address for the full signed quote. */
export function attestationDigest(doc: AttestationDocument): string {
  return hashCanonical(doc);
}

/** The claims a caller supplies to mint a document (everything but the signature/attestor/mode). */
export interface AttestationClaims {
  model_id: string;
  weights_digest: string;
  runtime_measurement: string;
  operator: string;
  /** Optional measured digest of the agent's system prompt / instructions (carried when supplied). */
  system_prompt_digest?: string;
  /** Optional measured digest of the agent's tool manifest (carried when supplied). */
  tool_manifest_digest?: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  /** When all three are supplied the document is bound (`binding`) to holder/grant/epoch + `nonce`. */
  holder_pub?: string;
  grant_ref?: string;
  epoch?: number;
}

export interface DevAttestor {
  /** b64u public key clients register in `trustedAttestorKeys`. */
  readonly publicKey: string;
  /** Sign a SOFTWARE-mode attestation document over the given claims. */
  attest(claims: AttestationClaims): AttestationDocument;
}

/**
 * A SOFTWARE-mode attestor for dev + CI: it signs `AttestationDocument`s with `secret`. This is the
 * sanctioned software/attested reference, NOT a hardware root of trust — see the file header. The RS
 * trusts a dev attestor by putting its `publicKey` in `createAttestationVerifier({ trustedAttestorKeys })`.
 */
export function createDevAttestor(secret: Uint8Array, suite?: { alg?: SigAlg; mlDsa?: MlDsaKeyPair }): DevAttestor {
  const publicKey = b64u(publicKeyOf(secret));
  if (resolveSigAlg(suite?.alg) === null) throw new Error(`createDevAttestor: unknown signature alg '${String(suite?.alg)}'`);
  const pqPk = suite?.mlDsa ? encodeMlDsaPublicKey(suite.mlDsa.publicKey) : undefined;
  return {
    publicKey,
    attest(claims: AttestationClaims): AttestationDocument {
      const body: AttestationBody = {
        model_id: claims.model_id,
        weights_digest: claims.weights_digest,
        runtime_measurement: claims.runtime_measurement,
        operator: claims.operator,
        nonce: claims.nonce,
        issued_at: claims.issued_at,
        expires_at: claims.expires_at,
        attestor: publicKey,
        mode: 'software',
      };
      // Additive, backward-compatible: only carry the instructions/tools digests when supplied, so a
      // document minted without them canonicalizes (and thus signs) byte-identically to before.
      if (claims.system_prompt_digest !== undefined) body.system_prompt_digest = claims.system_prompt_digest;
      if (claims.tool_manifest_digest !== undefined) body.tool_manifest_digest = claims.tool_manifest_digest;
      if (claims.holder_pub !== undefined && claims.grant_ref !== undefined && claims.epoch !== undefined) {
        body.binding = attestationBindingB64u({
          holderPub: claims.holder_pub,
          grantRef: claims.grant_ref,
          epoch: claims.epoch,
          nonce: claims.nonce,
        });
      }
      // Bind the suite (alg + attestor ML-DSA key) into the signed body; ed25519 is byte-identical.
      const signedBody = bindSuiteFields(body, suite?.alg, pqPk);
      const fields = signSuiteArtifact(suite?.alg, { edSecret: secret, mlDsa: suite?.mlDsa }, attestMessage(signedBody));
      return { ...signedBody, ...fields };
    },
  };
}

/** The identity a verifier (software or hardware) establishes for a document. */
export interface MeasuredIdentity {
  model_id: string;
  weights_digest: string;
  /**
   * Optional PROVENANCE flag for `weights_digest`: `true` iff the digest was HARDWARE-MEASURED by the
   * TEE (the model runtime measured the loaded weights into the signed attestation report), rather than
   * self-asserted by a software document or taken from a host-asserted field (e.g. SEV-SNP HOST_DATA).
   * A `HardwareAttestationVerifier` sets this; the software path never does (its weights are
   * self-asserted). It is what `agent_binding.require_measured_weights` gates on: a grant demanding a
   * hardware-measured weights digest fails closed unless this is `true`. Absent/`false` => the digest is
   * NOT silicon-measured and cannot satisfy a `require_measured_weights` pin (but still matches a plain
   * `weights_allowlist`, unchanged).
   */
  weights_measured?: boolean;
  runtime_measurement: string;
  operator: string;
  /**
   * Optional measured digest of the agent's system prompt / instructions. Present only when the
   * attestation (software doc or hardware report) measured it; matched against
   * agent_binding.system_prompt_allowlist. In hardware mode the `HardwareAttestationVerifier` is the
   * one that populates this, so it is silicon-measured, not self-asserted.
   */
  system_prompt_digest?: string;
  /**
   * Optional measured digest of the agent's tool manifest. Present only when measured; matched against
   * agent_binding.tool_manifest_allowlist. Hardware-populated under require_hardware.
   */
  tool_manifest_digest?: string;
}

export interface HardwareAttestationResult {
  ok: boolean;
  reason?: string;
  /**
   * The HARDWARE-measured identity. When present the verifier matches THIS against agent_binding
   * (never the document's self-asserted fields), so a lying document cannot pass a real TEE check.
   */
  measured?: MeasuredIdentity;
  /**
   * The verifier MUST set this true only after confirming the quote's bound value (report_data)
   * equals `attestationBinding(expected)`. `createAttestationVerifier` fails closed unless it is true.
   */
  bound?: boolean;
  /**
   * Fields that are HOST-asserted (not guest/silicon-attested), e.g. SEV-SNP HOST_DATA. Surfaced for
   * audit only; never matched against agent_binding as identity unless the verifier maps them.
   */
  hostAsserted?: Record<string, string>;
}

/**
 * SEAM for real TEE attestation. A production implementation parses a SEV-SNP / TDX / SGX report:
 * verifies the vendor cert chain to the CPU root, checks the launch/measurement registers, confirms
 * the report_data binds the expected nonce, and returns the measured identity. Intentionally not
 * implemented in THIS file (vendor-specific, security-critical). The AMD SEV-SNP implementation is in
 * `hardware-sevsnp.ts` (`createSevSnpVerifier`). Plug it in via
 * `createAttestationVerifier({ hardwareVerifier })`.
 */
export interface HardwareAttestationVerifier {
  verify(input: {
    document: AttestationDocument;
    ctx: VerifyContext;
    nowMs: number;
    /** The server-side expected binding the quote's report_data must equal. */
    expected: ExpectedAttestationBinding;
  }): HardwareAttestationResult | Promise<HardwareAttestationResult>;
}

/**
 * Resolve the full `AttestationDocument` for an action. The RS caches attestation quotes per epoch
 * (they are not per-action); the hook finds the one this PCActn binds to. `attestationRegistry`
 * builds the common resolver (index by nonce, match the PCActn's `attestation.quote_digest`).
 */
export type AttestationResolver = (ctx: VerifyContext) => AttestationDocument | undefined;

/**
 * A resolver over a set of known-good documents: it returns the document whose `nonce` equals the
 * PCActn's `attestation.quote_digest` (the action's declared attestation binding). Later duplicates
 * for a nonce overwrite earlier ones.
 */
export function attestationRegistry(docs: AttestationDocument[]): AttestationResolver {
  const byNonce = new Map<string, AttestationDocument>();
  for (const d of Array.isArray(docs) ? docs : []) {
    if (d && typeof d.nonce === 'string') byNonce.set(d.nonce, d);
  }
  return (ctx) => {
    const key = ctx?.pcactn?.attestation?.quote_digest;
    return typeof key === 'string' ? byNonce.get(key) : undefined;
  };
}

export interface AttestationVerifierOpts {
  /** b64u public keys trusted to sign SOFTWARE-mode documents. */
  trustedAttestorKeys: string[];
  /** Supplied => HARDWARE mode: delegate authenticity to this verifier instead of the signature. */
  hardwareVerifier?: HardwareAttestationVerifier;
  /** How to find the document for an action (default: `attestationRegistry([])` — resolves nothing). */
  resolveDocument?: AttestationResolver;
  /**
   * SERVER-SUPPLIED expected binding for this action (holder/grant/epoch from the verified PCActn,
   * nonce from the server's issued-nonce store). Required: without it the hook fails closed.
   */
  expectedBinding?: (ctx: VerifyContext) => ExpectedAttestationBinding | undefined | Promise<ExpectedAttestationBinding | undefined>;
  /**
   * LOUD OPT-OUT (legacy/dev only): derive the expected binding from the PCActn itself with the
   * PCActn's self-declared `quote_digest` as the nonce. This is NOT a server-issued nonce, so replay
   * protection is void; the verdict is still bound to holder/grant/epoch.
   */
  insecure_selfDeclaredNonce?: boolean;
  /** Max age (ms) of the server-issued nonce (clamped to MAX_ATTESTATION_AGE_MS). */
  maxNonceAgeMs?: number;
  /** Clock for freshness, epoch ms (default `Date.now`). Injectable for determinism. */
  now?: () => number;
  /** Allowed clock skew (ms) (default 0). */
  clockSkewMs?: number;
}

/**
 * Outcome of `verifyAttestation`. `present` = a document was supplied; `bound` = it was
 * authenticated AND its quote is bound to holder/grant/epoch/nonce. A server must fail closed when
 * `requiresAttestation(agent_binding)` and `!bound`.
 */
export interface AttestationVerdict {
  ok: boolean;
  present: boolean;
  bound: boolean;
  reason?: string;
  identity?: MeasuredIdentity;
}

/** True iff the grant's agent_binding constrains anything (=> an attestation is REQUIRED). */
export function requiresAttestation(binding: AgentBinding | undefined): boolean {
  const b = binding ?? {};
  return (
    (Array.isArray(b.model_allowlist) && b.model_allowlist.length > 0) ||
    hasMinMeasurement(b.min_measurement) ||
    (typeof b.operator === 'string' && b.operator.length > 0) ||
    (Array.isArray(b.weights_allowlist) && b.weights_allowlist.length > 0) ||
    (Array.isArray(b.system_prompt_allowlist) && b.system_prompt_allowlist.length > 0) ||
    (Array.isArray(b.tool_manifest_allowlist) && b.tool_manifest_allowlist.length > 0) ||
    b.require_hardware === true ||
    b.require_measured_weights === true
  );
}

/** True iff `doc.nonce` is the nonce the PCActn declares in `attestation.quote_digest`. */
export function nonceBinds(doc: AttestationDocument, ctx: VerifyContext): boolean {
  return typeof doc?.nonce === 'string' && doc.nonce === ctx?.pcactn?.attestation?.quote_digest;
}

/** True iff `min_measurement` actually constrains anything (non-empty string, or an `{ svn }` lower bound). */
function hasMinMeasurement(mm: AgentBinding['min_measurement']): boolean {
  if (typeof mm === 'string') return mm.length > 0;
  return !!mm && typeof mm === 'object' && typeof (mm as { svn?: unknown }).svn === 'number' && Number.isFinite((mm as { svn: number }).svn);
}

/**
 * Check the measured `runtime_measurement` against a `min_measurement` constraint. Two shapes:
 *   - string: EQUALITY against the pinned opaque digest (unchanged, default path);
 *   - `{ svn: number }`: MONOTONE ladder — the measurement is parsed as an integer SVN and must be
 *     `>= svn`, so an upgraded enclave at a higher SVN passes without re-minting, a downgrade fails.
 * Returns a reason on failure, else null.
 */
function checkMinMeasurement(mm: AgentBinding['min_measurement'], runtimeMeasurement: string): string | null {
  if (typeof mm === 'string') {
    if (mm.length > 0 && runtimeMeasurement !== mm) return `runtime_measurement does not match required min_measurement`;
    return null;
  }
  if (mm && typeof mm === 'object' && typeof (mm as { svn?: unknown }).svn === 'number') {
    const min = (mm as { svn: number }).svn;
    if (!Number.isFinite(min)) return null; // malformed lower bound: nothing to enforce
    const accepted = Number(runtimeMeasurement);
    if (runtimeMeasurement.trim() === '' || !Number.isInteger(accepted)) {
      return `runtime_measurement ${runtimeMeasurement} is not an integer SVN (required min svn ${min})`;
    }
    if (accepted < min) return `runtime_measurement svn ${accepted} is below required min svn ${min}`;
  }
  return null;
}

/** Match a measured identity against the grant's agent_binding. Returns a reason on failure, else null. */
export function matchAgentBinding(id: MeasuredIdentity, binding: AgentBinding | undefined): string | null {
  const b = binding ?? {};
  if (Array.isArray(b.model_allowlist) && b.model_allowlist.length > 0 && !b.model_allowlist.includes(id.model_id)) {
    return `model_id ${id.model_id} not in model_allowlist`;
  }
  // `min_measurement` is an opaque launch measurement pinned for EQUALITY (default), OR a monotone
  // `{ svn }` lower bound compared `>=` so an upgraded enclave need not re-mint the grant. Opaque
  // hashes keep "min" == "the required value"; only the structured form admits a numeric ordering.
  const mmErr = checkMinMeasurement(b.min_measurement, id.runtime_measurement);
  if (mmErr) return mmErr;
  if (typeof b.operator === 'string' && b.operator.length > 0 && id.operator !== b.operator) {
    return `operator ${id.operator} is not the bound operator`;
  }
  // WEIGHTS-LEVEL ATTESTATION. `weights_allowlist` pins acceptable weights digests; a model swap or
  // malicious fine-tune changes the digest. `require_measured_weights` additionally demands the digest
  // be HARDWARE-MEASURED (silicon-rooted) rather than self-asserted (software) or host-asserted
  // (e.g. SEV-SNP HOST_DATA): under it the match runs ONLY against a digest the verifier measured
  // (`weights_measured === true`), so whoever signed the document — or a lying host — cannot assert a
  // weights digest into the allowlist. Fail-closed when required but the digest is not measured. Without
  // the flag the allowlist is matched by value regardless of provenance (unchanged, backward-compatible).
  if (b.require_measured_weights === true && id.weights_measured !== true) {
    return `weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)`;
  }
  if (Array.isArray(b.weights_allowlist) && b.weights_allowlist.length > 0 && !b.weights_allowlist.includes(id.weights_digest)) {
    return `weights_digest not in weights_allowlist (model swap / fine-tune?)`;
  }
  // "Provenance beyond weights": the system prompt and tool manifest are part of the agent's identity.
  // Each is gated exactly like `weights_allowlist`, and FAILS CLOSED when the binding pins it but the
  // measured identity carries no such digest (absent-when-required), so a document that simply omits
  // the measurement cannot slip past a prompt/tools pin.
  if (Array.isArray(b.system_prompt_allowlist) && b.system_prompt_allowlist.length > 0) {
    if (typeof id.system_prompt_digest !== 'string' || !b.system_prompt_allowlist.includes(id.system_prompt_digest)) {
      return `system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)`;
    }
  }
  if (Array.isArray(b.tool_manifest_allowlist) && b.tool_manifest_allowlist.length > 0) {
    if (typeof id.tool_manifest_digest !== 'string' || !b.tool_manifest_allowlist.includes(id.tool_manifest_digest)) {
      return `tool_manifest_digest not in tool_manifest_allowlist (tools changed?)`;
    }
  }
  return null;
}

export type AttestationHookResult = HookResult & { present: boolean; bound: boolean };

/**
 * Core verification (no hook plumbing). Given the (optional) document, the PCActn context and the
 * SERVER-SUPPLIED expected binding it:
 *  1. requires a document (`present`);
 *  2. cross-checks the PCActn (grant_ref, attestation.epoch, quote_digest) against `expected`;
 *  3. requires the document's nonce === expected.nonce;
 *  4. ESTABLISHES IDENTITY + BINDING:
 *       - hardware: delegate; the verifier must confirm report_data = attestationBinding(expected)
 *         (`bound: true`); the document's self-asserted fields and DATES are ignored;
 *       - software: mode/attestor/signature, and `doc.binding === attestationBinding(expected)`;
 *  5. FRESHNESS: hardware = server nonce age (`nowMs - nonceIssuedAt` in [-skew, maxAge], required);
 *     software = signed validity window, plus nonce age when `nonceIssuedAt` is supplied;
 *  6. agent_binding match on the established identity.
 * Any failure => ok:false, bound:false.
 */
export async function verifyAttestation(input: {
  document: AttestationDocument | undefined;
  ctx: VerifyContext;
  expected: ExpectedAttestationBinding;
  nowMs: number;
  trustedAttestorKeys: Iterable<string>;
  hardwareVerifier?: HardwareAttestationVerifier;
  maxNonceAgeMs?: number;
  clockSkewMs?: number;
}): Promise<AttestationVerdict> {
  const doc = input.document;
  const present = !!doc && typeof doc === 'object';
  const fail = (reason: string): AttestationVerdict => ({ ok: false, present, bound: false, reason });
  try {
    if (!present || !doc) return fail('no attestation document for this action');
    const { ctx, expected, nowMs } = input;
    const trusted = new Set(input.trustedAttestorKeys);
    const skew = Number.isFinite(input.clockSkewMs) ? Math.max(0, input.clockSkewMs as number) : 0;
    const maxAge = Math.min(
      Number.isFinite(input.maxNonceAgeMs) && (input.maxNonceAgeMs as number) > 0 ? (input.maxNonceAgeMs as number) : MAX_ATTESTATION_AGE_MS,
      MAX_ATTESTATION_AGE_MS,
    );

    // (2) the PCActn must itself commit to the expected binding
    let expectedBinding: string;
    try {
      expectedBinding = attestationBindingB64u(expected);
    } catch (e) {
      return fail(`attestation binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
    }
    if (ctx?.pcactn?.grant_ref !== expected.grantRef) return fail('attestation binding: PCActn grant_ref differs from expected grant');
    if (ctx?.pcactn?.attestation?.epoch !== expected.epoch) return fail('attestation binding: PCActn attestation epoch differs from expected epoch');
    if (ctx?.pcactn?.attestation?.quote_digest !== expected.nonce) return fail('attestation nonce does not bind to this PCActn');

    // (3) document nonce
    if (doc.nonce !== expected.nonce) return fail('attestation nonce does not match the server-issued nonce');

    // (5a) nonce age (server clock) — mandatory in hardware mode
    const nonceAgeCheck = (): string | null => {
      if (typeof expected.nonceIssuedAt !== 'number' || !Number.isFinite(expected.nonceIssuedAt)) {
        return 'server nonce issue time unknown (cannot establish freshness)';
      }
      if (nowMs + skew < expected.nonceIssuedAt) return 'nonce issued in the future';
      if (nowMs - expected.nonceIssuedAt > maxAge + skew) return 'attestation nonce expired (stale quote)';
      return null;
    };

    // (4) identity + binding
    //
    // (4-pre) require_hardware: a grant may DEMAND a TEE-rooted attestation. When set we fail closed
    // unless a hardware verifier is present AND the document claims hardware mode — a software-mode
    // document, or no hardware verifier, is rejected regardless of trusted software attestor keys.
    const env = readEnvelope(ctx.grant);
    if (env?.agent_binding?.require_hardware === true) {
      if (!input.hardwareVerifier) return fail('agent_binding.require_hardware: no hardware verifier is configured (fail closed)');
      if (doc.mode !== 'hardware') return fail('agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)');
    }

    let identity: MeasuredIdentity;
    if (input.hardwareVerifier) {
      const nErr = nonceAgeCheck();
      if (nErr) return fail(nErr);
      const hw = await input.hardwareVerifier.verify({ document: doc, ctx, nowMs, expected });
      if (!hw.ok) return fail(`hardware attestation rejected: ${hw.reason ?? 'invalid'}`);
      if (hw.bound !== true) return fail('hardware verifier did not confirm report_data binding');
      if (!hw.measured) return fail('hardware verifier returned no measured identity');
      identity = hw.measured; // document fields and dates are self-asserted: never consulted
    } else {
      if (doc.mode !== 'software') return fail(`document mode ${String(doc.mode)} needs a hardwareVerifier`);
      if (typeof doc.attestor !== 'string' || !trusted.has(doc.attestor)) return fail('attestor key is not trusted');
      if (resolveSigAlg(doc.alg) === null) return fail('attestation declares an unknown signature alg');
      const { sig, pq_sig, ...body } = doc; // signed body keeps alg/pq_pk, drops both signatures
      // Suite-agile (ed25519 == verifyB64u(attestor, …, sig)); hybrid requires BOTH; pure ml-dsa under pq_pk.
      if (typeof sig !== 'string' || !verifyWithSuite(doc.alg, { edPub: doc.attestor, mlDsaPub: doc.pq_pk }, attestMessage(body), { sig, pq_sig })) {
        return fail('attestation signature does not verify');
      }
      if (typeof doc.binding !== 'string' || doc.binding.length === 0) return fail('attestation is not bound (binding absent)');
      if (doc.binding !== expectedBinding) return fail('attestation binding mismatch (holder/grant/epoch/nonce)');
      if (!Number.isFinite(doc.issued_at) || !Number.isFinite(doc.expires_at) || doc.expires_at < doc.issued_at) {
        return fail('malformed attestation validity window');
      }
      if (nowMs + skew < doc.issued_at) return fail('attestation not yet valid');
      if (nowMs - skew > doc.expires_at) return fail('attestation expired');
      if (typeof expected.nonceIssuedAt === 'number') {
        const nErr = nonceAgeCheck();
        if (nErr) return fail(nErr);
      }
      identity = {
        model_id: doc.model_id,
        weights_digest: doc.weights_digest,
        runtime_measurement: doc.runtime_measurement,
        operator: doc.operator,
        // Carried only when the (signed) document measured them, so an unpinned grant is unchanged.
        // Under require_hardware the software path is already rejected above, so these self-asserted
        // values can never satisfy a hardware-rooted grant.
        ...(typeof doc.system_prompt_digest === 'string' ? { system_prompt_digest: doc.system_prompt_digest } : {}),
        ...(typeof doc.tool_manifest_digest === 'string' ? { tool_manifest_digest: doc.tool_manifest_digest } : {}),
      };
    }

    // (6) agent_binding
    const bindErr = matchAgentBinding(identity, env?.agent_binding);
    if (bindErr) return fail(bindErr);

    return { ok: true, present: true, bound: true, identity };
  } catch (e) {
    return fail(`attestation verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}

/**
 * Build an `AttestationVerifier` hook (the L0/M5 hook in pcactn.ts) over `verifyAttestation`. The
 * expected binding comes from `opts.expectedBinding` (server-issued nonce); with neither that nor the
 * loud `insecure_selfDeclaredNonce` opt-out the hook fails closed. The returned result additionally
 * carries `present` / `bound` so the server can fail closed when agent_binding is non-empty.
 */
export function createAttestationVerifier(
  opts: AttestationVerifierOpts,
): (ctx: VerifyContext) => Promise<AttestationHookResult> {
  const trusted = Array.isArray(opts.trustedAttestorKeys) ? opts.trustedAttestorKeys : [];
  const resolve = opts.resolveDocument ?? attestationRegistry([]);
  const clock = opts.now ?? (() => Date.now());

  return async (ctx: VerifyContext): Promise<AttestationHookResult> => {
    const fin = (v: AttestationVerdict): AttestationHookResult => ({
      enforced: true,
      ok: v.ok,
      ...(v.reason ? { reason: v.reason } : {}),
      present: v.present,
      bound: v.bound,
    });
    try {
      const document = resolve(ctx);
      let expected: ExpectedAttestationBinding | undefined;
      if (opts.expectedBinding) {
        expected = await opts.expectedBinding(ctx);
      } else if (opts.insecure_selfDeclaredNonce === true) {
        const chain = ctx?.pcactn?.cap_chain;
        const leaf = Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : ctx?.grant;
        expected = {
          holderPub: typeof leaf?.holder === 'string' ? leaf.holder : '',
          grantRef: ctx?.pcactn?.grant_ref,
          epoch: ctx?.pcactn?.attestation?.epoch,
          nonce: ctx?.pcactn?.attestation?.quote_digest,
        };
      }
      if (!expected) {
        return fin({ ok: false, present: !!document, bound: false, reason: 'no server-issued attestation nonce/binding available (fail closed)' });
      }
      return fin(
        await verifyAttestation({
          document,
          ctx,
          expected,
          nowMs: clock(),
          trustedAttestorKeys: trusted,
          hardwareVerifier: opts.hardwareVerifier,
          maxNonceAgeMs: opts.maxNonceAgeMs,
          clockSkewMs: opts.clockSkewMs,
        }),
      );
    } catch (e) {
      return fin({ ok: false, present: false, bound: false, reason: `attestation verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` });
    }
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// MULTI-ROOT N-of-M ATTESTATION POLICY — remove sole dependence on one vendor's classical root.
//
// ── HONEST SCOPE. ─────────────────────────────────────────────────────────────────────────────────
// A single AMD SEV-SNP attestation is rooted ENTIRELY in AMD's classical (ECDSA-P384 / RSA-4096)
// silicon chain, and nothing at this layer can make that one attestation post-quantum (see
// hardware-sevsnp.ts). What this policy DOES is stop a single vendor's root being the SOLE point of
// failure: it requires corroborating evidence from >= k INDEPENDENT attestation roots — e.g. AMD
// SEV-SNP AND a second root such as Intel TDX or a PQ software/harness attestor. Each root carries its
// OWN suite, so one root can be PQ while another stays classical; a quantum break (or a
// cryptanalytic/implementation break) of ONE root's signature scheme no longer silently forges the
// whole attestation, because the other required roots must still corroborate. Fail-closed throughout:
// a missing or invalid REQUIRED root denies; falling below the threshold denies; roots that disagree on
// the measured identity deny (an attacker cannot mix a good root's identity with a lying root's).
// ════════════════════════════════════════════════════════════════════════════════════════════════

/**
 * One independent attestation root (a distinct hardware/software trust anchor) in a multi-root policy.
 * The `verifier` is the SAME `HardwareAttestationVerifier` seam; it resolves its OWN evidence from the
 * action's document/ctx (so a caller carries per-root evidence and each root's resolver picks its slice).
 */
export interface AttestationRoot {
  /** Stable id of the root, e.g. 'amd-sev-snp', 'intel-tdx', 'pq-harness'. Used for de-dup + audit. */
  id: string;
  /** The verifier for this root. */
  verifier: HardwareAttestationVerifier;
  /** When true, this root MUST verify (ok + bound). A required root that is missing/invalid denies. */
  required?: boolean;
  /** Audit-only label of the root's suite family, e.g. 'ecdsa-p384-sha384' or 'ml-dsa-65'. */
  suite?: string;
}

/** A policy requiring corroboration from >= `threshold` of `roots` independent attestation roots. */
export interface MultiRootAttestationPolicy {
  /** The independent roots. Each id must be distinct. */
  roots: AttestationRoot[];
  /** Minimum number of roots that must verify (ok + bound + measured). 1 <= threshold <= roots.length. */
  threshold: number;
}

/**
 * Reconcile the measured identities of the corroborating roots into one, FAIL-CLOSED on contradiction:
 * for each identity field, two roots asserting DIFFERENT non-empty values is a conflict (deny); a field
 * one root asserts and others leave empty is taken as-is. `weights_measured` is true only when the
 * chosen non-empty `weights_digest` came from a root that itself measured the weights in hardware.
 * Returns the merged identity, or a `{ conflict }` describing the first contradiction.
 */
function reconcileMeasuredIdentities(
  ids: ReadonlyArray<{ id: string; m: MeasuredIdentity }>,
): MeasuredIdentity | { conflict: string } {
  const pick = (field: 'model_id' | 'weights_digest' | 'runtime_measurement' | 'operator' | 'system_prompt_digest' | 'tool_manifest_digest'): string | { conflict: string } => {
    let chosen = '';
    let chosenBy = '';
    for (const { id, m } of ids) {
      const v = m[field];
      if (typeof v !== 'string' || v.length === 0) continue;
      if (chosen === '') {
        chosen = v;
        chosenBy = id;
      } else if (chosen !== v) {
        return { conflict: `roots '${chosenBy}' and '${id}' disagree on ${field}` };
      }
    }
    return chosen;
  };
  const model_id = pick('model_id');
  if (typeof model_id !== 'string') return model_id;
  const weights_digest = pick('weights_digest');
  if (typeof weights_digest !== 'string') return weights_digest;
  const runtime_measurement = pick('runtime_measurement');
  if (typeof runtime_measurement !== 'string') return runtime_measurement;
  const operator = pick('operator');
  if (typeof operator !== 'string') return operator;
  const system_prompt_digest = pick('system_prompt_digest');
  if (typeof system_prompt_digest !== 'string') return system_prompt_digest;
  const tool_manifest_digest = pick('tool_manifest_digest');
  if (typeof tool_manifest_digest !== 'string') return tool_manifest_digest;

  const weights_measured =
    weights_digest !== '' &&
    ids.some(({ m }) => m.weights_measured === true && m.weights_digest === weights_digest);

  return {
    model_id,
    weights_digest,
    weights_measured,
    runtime_measurement,
    operator,
    ...(system_prompt_digest !== '' ? { system_prompt_digest } : {}),
    ...(tool_manifest_digest !== '' ? { tool_manifest_digest } : {}),
  };
}

/**
 * Build a `HardwareAttestationVerifier` that enforces a multi-root N-of-M policy. Plugs into
 * `createAttestationVerifier({ hardwareVerifier })` exactly like a single-root verifier. On `verify` it:
 *   1. runs EVERY root's verifier against the same action (each resolves its own evidence);
 *   2. denies if any REQUIRED root did not verify (ok + bound + measured) — naming the root;
 *   3. denies if fewer than `threshold` roots verified;
 *   4. reconciles the corroborating roots' measured identities, denying on any contradiction;
 *   5. returns `bound: true` with the reconciled identity, so the usual agent_binding match runs on it.
 * Throws at CONSTRUCTION on an empty root set, a non-integer/out-of-range threshold, or duplicate ids.
 */
export function createMultiRootVerifier(policy: MultiRootAttestationPolicy): HardwareAttestationVerifier {
  if (!policy || !Array.isArray(policy.roots) || policy.roots.length === 0) {
    throw new TypeError('createMultiRootVerifier: at least one attestation root is required');
  }
  if (!Number.isInteger(policy.threshold) || policy.threshold < 1 || policy.threshold > policy.roots.length) {
    throw new TypeError('createMultiRootVerifier: threshold must be an integer in [1, roots.length]');
  }
  const ids = new Set<string>();
  for (const r of policy.roots) {
    if (!r || typeof r.id !== 'string' || r.id.length === 0) throw new TypeError('createMultiRootVerifier: each root needs a non-empty id');
    if (ids.has(r.id)) throw new TypeError(`createMultiRootVerifier: duplicate root id '${r.id}'`);
    ids.add(r.id);
  }

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        const passed: Array<{ id: string; m: MeasuredIdentity }> = [];
        const hostAsserted: Record<string, string> = {};
        for (const root of policy.roots) {
          let res: HardwareAttestationResult;
          try {
            res = await root.verifier.verify(input);
          } catch (e) {
            res = { ok: false, reason: `root '${root.id}' threw (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
          }
          const ok = res.ok === true && res.bound === true && !!res.measured;
          if (!ok) {
            if (root.required === true) return fail(`required attestation root '${root.id}' failed: ${res.reason ?? 'invalid'}`);
            continue;
          }
          passed.push({ id: root.id, m: res.measured! });
          if (res.hostAsserted) {
            for (const [k, v] of Object.entries(res.hostAsserted)) hostAsserted[`${root.id}.${k}`] = v;
          }
        }

        if (passed.length < policy.threshold) {
          return fail(`multi-root attestation below threshold (${passed.length}/${policy.threshold} independent roots corroborated)`);
        }

        const merged = reconcileMeasuredIdentities(passed);
        if ('conflict' in merged) return fail(`multi-root attestation identity conflict: ${merged.conflict}`);

        return { ok: true, bound: true, measured: merged, ...(Object.keys(hostAsserted).length > 0 ? { hostAsserted } : {}) };
      } catch (e) {
        return fail(`multi-root attestation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// PQ ACCOUNTABILITY ANCHORING — make a forged/anomalous attestation detectable + attributable.
//
// ── HONEST SCOPE. ─────────────────────────────────────────────────────────────────────────────────
// Anchoring does NOT prevent a quantum forgery of an AMD SEV-SNP attestation in real time (that is
// AMD's silicon root — see hardware-sevsnp.ts). What it adds is AFTER-THE-FACT accountability: the
// digest of each VERIFIED attestation is appended as an append-only transparency-log commitment and the
// resulting tree head is signed with a PQ-CAPABLE suite (ml-dsa-65 / hybrid). So if a forged or
// anomalous attestation is ever admitted — even one produced by breaking AMD's classical root — it is
// permanently recorded, consistency-checkable, and attributable to a point in the log that a
// quantum-resistant signature vouches for. Detection + attribution, not prevention.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/** Domain separator for the anchored attestation-evidence digest. */
export const ATTEST_ANCHOR_DOMAIN = 'atlas-pca/attest-anchor/v1\0';

/** The verified facts that get anchored: WHAT was proven, not the raw quote bytes. */
export interface VerifiedAttestationEvidence {
  /** The established (hardware/multi-root) measured identity. */
  identity: MeasuredIdentity;
  /** The holder/grant/epoch/nonce the attestation was bound to. */
  binding: ExpectedAttestationBinding;
  /** Which roots corroborated it (multi-root), for audit; order-insensitive. */
  rootIds?: string[];
  /** Audit label of the report/attestation suite(s), e.g. 'ecdsa-p384-sha384' or 'ml-dsa-65'. */
  suite?: string;
  /** When the attestation was verified (epoch ms). */
  verifiedAt: number;
}

/**
 * The canonical, domain-separated digest of a verified attestation — the opaque commitment leaf that is
 * appended to the transparency ledger. It binds the measured identity AND the holder/grant/epoch/nonce,
 * so two verifications that measured different identities (or bound to different actions) anchor to
 * different leaves, making a swap detectable.
 */
export function attestationEvidenceDigest(ev: VerifiedAttestationEvidence): string {
  return hashCanonical({
    domain: ATTEST_ANCHOR_DOMAIN,
    holder: ev.binding.holderPub,
    grant: ev.binding.grantRef,
    epoch: ev.binding.epoch,
    nonce: ev.binding.nonce,
    model_id: ev.identity.model_id,
    weights_digest: ev.identity.weights_digest,
    weights_measured: ev.identity.weights_measured === true,
    runtime_measurement: ev.identity.runtime_measurement,
    operator: ev.identity.operator,
    system_prompt_digest: ev.identity.system_prompt_digest ?? '',
    tool_manifest_digest: ev.identity.tool_manifest_digest ?? '',
    roots: [...(ev.rootIds ?? [])].sort(),
    suite: ev.suite ?? '',
    verified_at: ev.verifiedAt,
  });
}

/** Options for {@link anchorAttestationEvidence}. */
export interface AttestationAnchorOptions {
  /** The transparency ledger to anchor into (its `appendCommitment` is PQ-capable via the STH). */
  ledger: TransparencyLedger;
  /**
   * Guardian secret that signs the resulting signed tree head. Supply `suite` with an ml-dsa-65 / hybrid
   * key to make the accountability record POST-QUANTUM. Omitted => the commitment is still appended but
   * no STH is produced (allowed only when `required` is false).
   */
  guardianSecret?: Uint8Array;
  /** STH signature suite (ml-dsa-65 / hybrid => PQ accountability; default ed25519). */
  suite?: LedgerSuiteOpts;
  /** Instance id recorded in the STH (audit). */
  instanceId?: string;
  /** Clock for the STH timestamp (default `Date.now`). */
  now?: () => number;
  /** When true, anchoring MUST fully succeed (ledger present, commitment appended, STH signed) or throw. */
  required?: boolean;
}

/** The result of anchoring: the ledger index + commitment, and the PQ-capable signed tree head. */
export interface AttestationAnchor {
  /** The index of the appended commitment in the log. */
  index: number;
  /** The anchored evidence-digest commitment (the Merkle leaf). */
  commit: string;
  /** The signed tree head over the post-append head (present iff a guardian secret was supplied). */
  sth?: SignedTreeHead;
}

/**
 * Anchor a VERIFIED attestation into the transparency ledger for PQ accountability. Computes the
 * evidence digest, appends it as an opaque commitment (`appendCommitment`), and — when a guardian secret
 * is supplied — signs the resulting tree head with the (PQ-capable) suite so the record is vouched for
 * by a quantum-resistant signature. FAIL-CLOSED when `required`: a missing ledger, a missing guardian
 * secret, or a failed STH signature throws rather than silently skipping. Returns the anchor otherwise.
 */
export function anchorAttestationEvidence(ev: VerifiedAttestationEvidence, opts: AttestationAnchorOptions): AttestationAnchor {
  const required = opts?.required === true;
  const fail = (msg: string): never => {
    throw new Error(`attestation anchoring (fail closed): ${msg}`);
  };
  if (!opts || !(opts.ledger instanceof TransparencyLedger)) return fail('no transparency ledger available');
  if (required && !(opts.guardianSecret instanceof Uint8Array)) {
    return fail('required anchoring needs a guardian secret to sign the tree head');
  }
  const ledger = opts.ledger;
  const commit = attestationEvidenceDigest(ev);
  const prevRoot = ledger.head().root;
  const { index } = ledger.appendCommitment(commit);
  const head = ledger.head();

  let sth: SignedTreeHead | undefined;
  if (opts.guardianSecret instanceof Uint8Array) {
    const now = (opts.now ?? Date.now)();
    try {
      sth = signTreeHead(
        opts.guardianSecret,
        {
          instance_id: opts.instanceId ?? '',
          principal: ledger.principal,
          size: head.size,
          root: head.root,
          prev_root: prevRoot,
          timestamp: now,
        },
        opts.suite,
      );
    } catch (e) {
      if (required) return fail(`tree-head signing failed: ${e instanceof Error ? e.message : 'unknown'}`);
    }
  }

  return { index, commit, ...(sth ? { sth } : {}) };
}
