import { type Capability, type CapabilityChain, capHash, verifyChain } from './capability';
import { b64u, canonicalBytesStrict, __canonicalizeLenientServerOnly, hashCanonical, sha256, utf8 } from './hash';
import { strictParse } from './strict-json';
import { PCACTN_WIRE_VERSION, validateWireV2 } from './wire';
import { sign } from './keys';
import {
  type LessSuiteKey,
  type MlDsaKeyPair,
  type SigAlg,
  type SigSuite,
  type SlhDsaKeyPair,
  type SuiteSecretKeys,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeLessPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  resolveSigAlg,
  signWithSuite,
  verifyLeafSuite,
} from './pq';
import {
  type InclusionProof,
  type PlanNode,
  DEFAULT_REVERSIBILITY_CLASS,
  commitPlan,
  conditionsDigest,
  paramsDigest,
  planLeaf,
  verifyInclusion,
} from './merkle';
import type { ThresholdSignature } from './threshold';
import { BEACON_EPOCH_MS } from './beacons';
import { type TaintContext, computeTaint } from './taint';

/**
 * PCActn wire object (spec §7), WIRE FORMAT v2.
 *
 * v2 is a clean break from v1: PCActns are ephemeral (a signed intent for ONE action), so nothing persisted
 * is invalidated. Grants / capabilities / plans / ledger entries are unchanged. v2 adds the signed FRESHNESS
 * BINDING (`aud`, `iat`, `exp`, optional `nonce`; audit P0-5), the optional signed frontier slots
 * (`caution`, `rationale_commitment`, `progress_step`, `prohibition_evidence`, `tool_binding`), and the strict
 * canonical form (see `wire.ts` / `hash.ts` / `strict-json.ts`).
 */
export interface PCActn {
  ver: number;
  action: {
    verb: string;
    resource: string;
    params_digest: string;
    reversibility_class: string;
  };
  grant_ref: string;
  cap_chain: CapabilityChain;
  /** `conditions_digest` commits the node's pre/post (see merkle.conditionsDigest). */
  plan: { root: string; inclusion_proof: InclusionProof; node_id: string; conditions_digest?: string };
  attestation: { quote_digest: string; epoch: number; model_id: string; measurement: string; operator: string };
  provenance: { causal_hash: string; taint_level: number; trusted_refs: string[] };
  freshness: { beacon_ref: string; epoch: number; accumulator_witness: string };
  counter: number;
  risk_claim: { r: number; inputs: Record<string, unknown> };
  /** Audience: the resource server / Atlas instance this action is FOR (verifier compares to its own id). */
  aud: string;
  /** Issued-at, epoch MILLISECONDS (safe integer). */
  iat: number;
  /** Expiry, epoch MILLISECONDS (safe integer); `iat < exp <= iat + PCACTN_MAX_LIFETIME_MS`. */
  exp: number;
  /** Optional per-action nonce (uniqueness token a resource server MAY track). */
  nonce?: string;
  /**
   * Optional agent uncertainty attestation in [0,1]. MONOTONE: it can only RAISE the verifier's risk
   * (`r = max(server r, caution)`), never lower it.
   */
  caution?: number;
  /** Optional b64u(32) commitment to the agent's rationale (opened off-path; signed so it cannot be swapped). */
  rationale_commitment?: string;
  /** Optional signed proof-of-progress step (carried + signed; server tracks progress itself). */
  progress_step?: Record<string, unknown>;
  /** Optional prohibition evidence (carried + signed; the server's monitor is authoritative). */
  prohibition_evidence?: Record<string, unknown> | unknown[];
  /**
   * Optional b64u(32) digest of the tool signature the agent will dispatch to. When present the semantic
   * firewall (`tool_schema` caveat) is bound to it: a swapped / shadowed tool denies.
   */
  tool_binding?: string;
  /**
   * B4 crypto-agility (OPTIONAL, additive). Signature suite for the leaf signature. ABSENT means
   * `"ed25519"` — the pre-B4 default, byte-identical on the wire. The full registry (all SIGNED /
   * downgrade-protected, see pq.ts): `"ed25519"`; the lattice PQ suites `"ml-dsa-65"`, `"ml-dsa-87"`
   * (Cat-5) and their `"hybrid-ed25519-*"` forms; the SUF-CMA `"hybrid-nested-ed25519-ml-dsa-65"`; and the
   * hash-based PQ suites `"slh-dsa-sha2-128f"`, `"slh-dsa-sha2-256s"` (Cat-5) and their hybrids. The leaf
   * SIGNER (`signPCActnSuite`) and the leaf VERIFIER (`verifyLeafSuite`) both cover all of them.
   */
  alg?: SigAlg;
  /**
   * B4: the suite's PQ public key (b64u). ML-DSA-65 (1952 B) / ML-DSA-87 (2592 B) / SLH-DSA-SHA2-128f
   * (32 B) / SLH-DSA-SHA2-256s (64 B), per `alg`. SIGNED, so the Ed25519 holder signature (in a hybrid)
   * binds this key to the capability-chain leaf holder. Absent for ed25519.
   */
  pq_pk?: string;
  /**
   * M0 / B4: the PRIMARY signature (b64u) by the leaf capability holder. For `ed25519` and every `hybrid`
   * it is a 64-byte Ed25519 signature (the AGENT-LEAF baseline, an effective t=1 threshold — §6 L2); for a
   * PURE PQ suite it is the PQ signature (ML-DSA / SLH-DSA) verified under `pq_pk`.
   */
  sig: string;
  /**
   * B4: the PQ signature (b64u) for a HYBRID suite, over the SAME canonical message as `sig` (the nested
   * SUF-CMA hybrid signs `message ‖ sig_ed25519`). UNSIGNED (a signature cannot sign itself; stripped from
   * the signed body like `sig`/`threshold`). Present only for the `hybrid-*` suites; hybrid verification
   * requires BOTH `sig` and `pq_sig` (fail-closed).
   */
  pq_sig?: string;
  /**
   * M4 (L2/L3): the risk-adaptive threshold signature. When `requiredThreshold.t > 1` this field
   * carries the additional guardian/principal shares; at t=1 it may be omitted because the agent's
   * `sig` above already stands in as the single agent share. Every share here signs exactly the
   * bytes produced by `thresholdMessage(this)` — the SAME message `sig` covers. Optional and
   * backward-compatible: a PCActn with no `threshold` is a t=1 agent-only action.
   */
  threshold?: ThresholdSignature;
  zk_compliance?: unknown;
  bond_ref?: string;
}

export const PCACTN_VERSION = PCACTN_WIRE_VERSION; // 2
const SIG_DOMAIN = 'atlas-pca/actn/v2\0';
/** Longest `exp - iat` a verifier accepts (1 hour). */
export const PCACTN_MAX_LIFETIME_MS = 3_600_000;
/** How far in the future `iat` may be (clock skew allowance, 60 s). */
export const PCACTN_MAX_SKEW_MS = 60_000;
/** Default lifetime `buildPCActn` stamps (20 min: covers the 15-min principal step-up window). */
export const PCACTN_DEFAULT_TTL_MS = 20 * 60_000;

export type PCActnBody = Omit<PCActn, 'sig'>;

/**
 * The ONE canonical message every signature over a PCActn covers: the agent-leaf `sig` AND every
 * threshold share (guardian / principal, §6 L2) sign exactly these bytes, so the leaf and the extra
 * shares are provably over the same action. There is a single definition so the message cannot
 * drift between signer and verifier.
 *
 * It is `SIG_DOMAIN ‖ sha256(canonical(body))` where `body` is the PCActn WITHOUT the two signature
 * containers themselves — `sig` and `threshold`. Excluding `threshold` is what lets shares be added
 * after the message is fixed (the shares cannot sign a field that holds the shares). For any PCActn
 * that carries no `threshold` (every M0 object), this is byte-identical to the previous definition.
 */
export function thresholdMessage(p: PCActn | PCActnBody): Uint8Array {
  const { sig: _sig, threshold: _th, pq_sig: _pq, ...body } = p as PCActn;
  void _sig;
  void _th;
  void _pq; // B4: the ML-DSA signature is unsigned (absent in every pre-B4 object => identical bytes).
  const d = sha256(canonicalBytesStrict(body));
  const pre = utf8(SIG_DOMAIN);
  const m = new Uint8Array(pre.length + d.length);
  m.set(pre);
  m.set(d, pre.length);
  return m;
}

/** Sign the body with the leaf holder's key and return the complete PCActn (ed25519 suite — the default). */
export function signPCActn(body: PCActnBody, leafHolderSecret: Uint8Array): PCActn {
  return { ...body, sig: b64u(sign(leafHolderSecret, thresholdMessage(body))) };
}

/** Secret-key material a leaf signer may supply — one bundle covering every registered suite family. */
export interface LeafSuiteSecretKeys {
  /** Ed25519 leaf-holder secret (ed25519 + every hybrid suite). */
  edLeafSecret?: Uint8Array;
  /** ML-DSA-65 key pair (ml-dsa-65, hybrid-ed25519-ml-dsa-65, hybrid-nested-ed25519-ml-dsa-65). */
  mlDsa?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-128f key pair (slh-dsa-sha2-128f, hybrid-ed25519-slh-dsa-sha2-128f). */
  slhDsa?: SlhDsaKeyPair;
  /** ML-DSA-87 key pair (ml-dsa-87, hybrid-ed25519-ml-dsa-87 — Category-5 / CNSA 2.0). */
  mlDsa87?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-256s key pair (slh-dsa-sha2-256s, hybrid-ed25519-slh-dsa-sha2-256s — Category-5). */
  slhDsa256s?: SlhDsaKeyPair;
  /** LESS (category 1) key material + signSeed (less-cat1, hybrid-ed25519-less-cat1; OPTIONAL pca-less-wasm backend). */
  lessCat1?: LessSuiteKey;
}

/**
 * Resolve the b64u PQ public key (== `pq_pk`) a NON-ed25519 suite binds into its signed body, from whichever
 * key-material family the suite selects. THROWS a TypeError naming the missing family's key material so a
 * signer never silently emits a weaker/incomplete signature. The returned string is byte-identical to the
 * value the pq.ts seam (`signSuiteArtifact`) derives for the same suite + keys.
 */
function leafPqPublicKey(suite: SigSuite, keys: LeafSuiteSecretKeys): string {
  if (suite.hasMlDsa) {
    if (!keys.mlDsa) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires mlDsa key material`);
    return encodeMlDsaPublicKey(keys.mlDsa.publicKey);
  }
  if (suite.hasSlhDsa) {
    if (!keys.slhDsa) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires slhDsa key material`);
    return encodeSlhDsaPublicKey(keys.slhDsa.publicKey);
  }
  if (suite.hasMlDsa87) {
    if (!keys.mlDsa87) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires mlDsa87 key material`);
    return encodeMlDsa87PublicKey(keys.mlDsa87.publicKey);
  }
  if (suite.hasSlhDsa256s) {
    if (!keys.slhDsa256s) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires slhDsa256s key material`);
    return encodeSlhDsa256sPublicKey(keys.slhDsa256s.publicKey);
  }
  if (suite.hasLessCat1) {
    if (!keys.lessCat1) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires lessCat1 key material`);
    return encodeLessPublicKey(keys.lessCat1.publicKey);
  }
  // Unreachable: every non-ed25519 suite in the registry sets exactly one PQ family flag + needsPqPk.
  throw new TypeError(`signPCActnSuite: '${suite.alg}' has no PQ public key`);
}

/**
 * B4 crypto-agility: sign a PCActn under ANY registered signature suite (the leaf-signer parity to the
 * verify seam `verifyLeafSuite`, which already accepts all 10). ADDITIVE — the `ed25519` path produces an
 * object byte-identical to {@link signPCActn} (no `alg`/`pq_*` fields), so existing consumers are unaffected,
 * and the `ml-dsa-65` / `hybrid-ed25519-ml-dsa-65` / `slh-dsa-sha2-128f` paths stay byte-identical to the
 * previous hand-rolled branches (they now route through the shared pq.ts seam {@link signWithSuite}).
 *
 * Every non-ed25519 suite binds `alg` + the suite's `pq_pk` into the signed body, then signs
 * `thresholdMessage` of that body under the suite:
 *   - `ml-dsa-65` / `ml-dsa-87`                     pure lattice PQ: `sig` is the ML-DSA signature.
 *   - `slh-dsa-sha2-128f` / `slh-dsa-sha2-256s`     pure hash-based PQ: `sig` is the SLH-DSA signature.
 *   - `hybrid-ed25519-*`                            `sig` = Ed25519, `pq_sig` = the PQ signature, both over
 *                                                   the SAME canonical message (fail-closed: BOTH required).
 *   - `hybrid-nested-ed25519-ml-dsa-65`             SUF-CMA nested hybrid: `pq_sig` signs `message ‖ sig_ed25519`.
 *
 * FAIL-CLOSED: an unknown `alg`, or missing key material for the chosen suite, THROWS.
 */
export function signPCActnSuite(body: PCActnBody, opts: { alg?: SigAlg } & LeafSuiteSecretKeys): PCActn {
  const suite = resolveSigAlg(opts.alg ?? 'ed25519');
  if (suite === null) throw new Error(`signPCActnSuite: unknown alg ${String(opts.alg)}`);
  if (suite.alg === 'ed25519') {
    if (!opts.edLeafSecret) throw new TypeError("signPCActnSuite: 'ed25519' requires edLeafSecret");
    return signPCActn(body, opts.edLeafSecret); // byte-identical to the pre-B4 path (no alg field)
  }
  // Every hybrid suite needs the Ed25519 leaf secret; check FIRST so the error names `edLeafSecret`
  // (the signer-facing option) rather than the seam's generic `edSecret`.
  if (suite.hasEd25519 && !opts.edLeafSecret) throw new TypeError(`signPCActnSuite: '${suite.alg}' requires edLeafSecret`);
  const pqPk = leafPqPublicKey(suite, opts); // throws, naming the missing PQ family, if absent
  const withSuite: PCActnBody = { ...body, alg: suite.alg, pq_pk: pqPk };
  const msg = thresholdMessage(withSuite);
  const seamKeys: SuiteSecretKeys = {
    edSecret: opts.edLeafSecret,
    mlDsa: opts.mlDsa,
    slhDsa: opts.slhDsa,
    mlDsa87: opts.mlDsa87,
    slhDsa256s: opts.slhDsa256s,
    lessCat1: opts.lessCat1,
  };
  const parts = signWithSuite(suite.alg, seamKeys, msg);
  return parts.pq_sig !== undefined ? { ...withSuite, sig: parts.sig, pq_sig: parts.pq_sig } : { ...withSuite, sig: parts.sig };
}

export function encodePCActn(p: PCActn): string {
  return __canonicalizeLenientServerOnly(p);
}

/**
 * Decode a PCActn from its JSON text with the STRICT JSON profile (`strictParse`: no comments, bounded depth,
 * no duplicate keys, no lone surrogates, canonical numbers). Deterministic and independent of native
 * `JSON.parse`. Throws on any deviation.
 */
export function decodePCActn(s: string): PCActn {
  const v = strictParse(s) as PCActn;
  if (typeof v !== 'object' || v === null || Array.isArray(v)) throw new TypeError('decodePCActn: not an object');
  return v;
}

export function pcactnDigest(p: PCActn): string {
  return hashCanonical(p);
}

/**
 * Build a complete, signed PCActn for plan node `nodeId`. action = node's verb/resource/
 * reversibility_class; params_digest = paramsDigest(params) (the canonical rule in merkle.ts);
 * the node's own params_digest (if any) must match, else this throws (a silent non-match would
 * fail inclusion later). When the caller does not supply them, attestation/freshness/provenance
 * default to empty STRUCTURE stubs so the wire stays well-formed; the matching enforcement is now
 * REAL and OPT-IN on the verifier via `verifyPCActnCore(..., { enforce })`:
 *   - M1 taint gate   → `enforce.taint`        (empty/unverifiable provenance => fail closed);
 *   - M3 freshness    → `enforce.freshness`    (empty/stale freshness anchor => fail closed);
 *   - M5 attestation  → `enforce.attestation`  (absent/invalid TEE attestation => fail closed).
 * A verifier that does NOT pass `enforce` keeps the prior behaviour: those checks report
 * 'not-enforced' and a stub-bearing PCActn is accepted (structure only). A PCActn that must pass a
 * gate carries the corresponding REAL block (a server-issued attestation, a live beacon epoch, a
 * server-verifiable provenance lineage), not these stubs.
 */
export function buildPCActn(input: {
  grant: Capability;
  chain: CapabilityChain;
  plan: PlanNode[];
  nodeId: string;
  params?: Record<string, unknown>;
  counter: number;
  signerSecret: Uint8Array;
  provenance?: PCActn['provenance'];
  attestation?: PCActn['attestation'];
  freshness?: PCActn['freshness'];
  riskClaim?: PCActn['risk_claim'];
  /** REQUIRED audience (the resource server / instance id this action is for). */
  aud: string;
  /** Epoch ms used for `iat` (default `Date.now()`). */
  now?: number;
  /** Explicit issued-at / expiry (ms). Default: iat = now, exp = iat + ttlMs. */
  iat?: number;
  exp?: number;
  ttlMs?: number;
  nonce?: string;
  caution?: number;
  rationaleCommitment?: string;
  progressStep?: Record<string, unknown>;
  prohibitionEvidence?: Record<string, unknown> | unknown[];
  toolBinding?: string;
}): PCActn {
  if (typeof input.aud !== 'string' || input.aud.length === 0) throw new Error('buildPCActn: aud (audience) is required');
  const node = input.plan.find((n) => n.id === input.nodeId);
  if (!node) throw new Error(`buildPCActn: unknown plan node ${input.nodeId}`);
  const digest = paramsDigest(input.params);
  if (node.params_digest !== undefined && node.params_digest !== digest) {
    throw new Error(`buildPCActn: params do not match plan node ${node.id}'s params_digest`);
  }
  const committed = commitPlan(input.plan);
  const iat = input.iat ?? input.now ?? Date.now();
  const body: PCActnBody = {
    ver: PCACTN_VERSION,
    action: {
      verb: node.verb,
      resource: node.resource,
      params_digest: digest,
      reversibility_class: node.reversibility_class ?? DEFAULT_REVERSIBILITY_CLASS,
    },
    grant_ref: input.grant.id,
    cap_chain: input.chain,
    plan: {
      root: committed.root,
      inclusion_proof: committed.proofFor(node.id),
      node_id: node.id,
      conditions_digest: conditionsDigest(node.pre, node.post),
    },
    // Empty STRUCTURE stubs when the caller supplies none (wire stays well-formed). Enforcement is REAL
    // and opt-in on the verifier: M5 attestation (enforce.attestation), M3 freshness (enforce.freshness),
    // M1 taint gate (enforce.taint). A stub fails those gates closed; a real action carries real blocks.
    attestation: input.attestation ?? { quote_digest: '', epoch: 0, model_id: 'unattested', measurement: '', operator: 'unattested' },
    provenance: input.provenance ?? { causal_hash: '', taint_level: 0, trusted_refs: [] },
    freshness: input.freshness ?? { beacon_ref: '', epoch: 0, accumulator_witness: '' },
    counter: input.counter,
    risk_claim: input.riskClaim ?? { r: 0, inputs: {} },
    aud: input.aud,
    iat,
    exp: input.exp ?? iat + (input.ttlMs ?? PCACTN_DEFAULT_TTL_MS),
    ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
    ...(input.caution !== undefined ? { caution: input.caution } : {}),
    ...(input.rationaleCommitment !== undefined ? { rationale_commitment: input.rationaleCommitment } : {}),
    ...(input.progressStep !== undefined ? { progress_step: input.progressStep } : {}),
    ...(input.prohibitionEvidence !== undefined ? { prohibition_evidence: input.prohibitionEvidence } : {}),
    ...(input.toolBinding !== undefined ? { tool_binding: input.toolBinding } : {}),
  };
  return signPCActn(body, input.signerSecret);
}

// ---- later-milestone hooks ----------------------------------------------------------------

export type HookResult = { enforced: false } | { enforced: true; ok: boolean; reason?: string };
export interface VerifyContext {
  pcactn: PCActn;
  grant: Capability;
  nowEpoch?: number;
}
export type Hook = (ctx: VerifyContext) => HookResult | Promise<HookResult>;
export type AttestationVerifier = Hook; // L0 / M5
export type ThresholdVerifier = Hook; // L2 / M2, M4
export type RevocationChecker = Hook; // L5 / M3
export type ZkVerifier = Hook; // 9B / M6

export const notEnforced: Hook = () => ({ enforced: false });

export interface VerifyHooks {
  attestation?: AttestationVerifier;
  threshold?: ThresholdVerifier;
  revocation?: RevocationChecker;
  zk?: ZkVerifier;
}

// ---- opt-in enforcement gates (M1 taint / M3 freshness / M5 attestation) --------------------------
//
// These three dimensions used to be ACCEPTED-BUT-IGNORED: the wire carries `provenance`, `freshness`
// and `attestation`, but `verifyPCActnCore` reported the checks as 'not-enforced'. They are now REAL,
// independent checks a verifier turns on through `verifyPCActnCore(..., { enforce })`. Each gate is OFF
// by default (absent => the prior 'not-enforced' behaviour, byte-identical output), so wiring them in is
// strictly additive. When a gate is on it FAILS CLOSED: a stub / missing / stale / unverifiable value
// denies. The gate config names are `enforce.taint` (M1), `enforce.freshness` (M3) and
// `enforce.attestation` (M5).

/**
 * M3 freshness gate. Rejects a PCActn whose signed `freshness` anchor is missing or stale. The anchor's
 * wall-clock time is reconstructed from the beacon epoch (`freshness.epoch * epochMs`), matching the
 * beacon layout in `beacons.ts` (epoch = floor(issued_at / BEACON_EPOCH_MS)). Because the epoch names the
 * START of the beacon window, the computed age is a CONSERVATIVE upper bound on the true age (off by at
 * most one epoch toward "older"), which is the safe direction for a freshness gate.
 */
export interface FreshnessEnforcement {
  /** Reject when the freshness anchor is older than this many ms. */
  maxAgeMs: number;
  /** ms per freshness epoch, used to map `freshness.epoch` to a wall-clock anchor (default BEACON_EPOCH_MS). */
  epochMs?: number;
  /** Clock (epoch ms) for the age computation; defaults to the verifier's `nowEpoch`. */
  now?: number;
  /** Tolerated clock skew (ms) for an anchor that appears to be slightly in the future (default 0). */
  clockSkewMs?: number;
}

/**
 * M1 taint gate. Reuses the L4 information-flow taint functional (`taint.computeTaint`) verbatim: every
 * declared provenance ref is INDEPENDENTLY re-classified from facts the server holds (its trusted-input
 * registry + committed resource graph), never from the agent's own label, and the normalized join is the
 * taint. Denies when the lineage is not server-verifiable (fail-closed `valid: false`) or the computed
 * taint exceeds `maxTaint` (on the same `taintValue` scale deriveRisk/objectiveRisk use: trusted 0,
 * first_party 0.25, tool 0.5, web 0.75, agent/empty 1).
 */
export interface TaintEnforcement {
  /** Server-held trusted-input context (registry + optional committed resource graph). */
  ctx: TaintContext;
  /** Deny when the computed information-flow taint exceeds this (taintValue scale, 0..1). */
  maxTaint: number;
}

/**
 * M5 TEE attestation gate. Runs the REAL attestation verifier (`createAttestationVerifier` in
 * `attestation.ts`, optionally backed by the hardware SEV-SNP verifier in `hardware-sevsnp.ts`): it
 * authenticates the quote, binds it to holder/grant/epoch/nonce, enforces freshness from the server-issued
 * nonce, and cross-binds the measured identity to the grant's `agent_binding` (model / measurement /
 * weights / system-prompt / tools allowlists, require_hardware, require_measured_weights). When this gate
 * is on, a `not-enforced` / absent result is a FAIL (fail closed) unless `required` is explicitly false.
 */
export interface AttestationEnforcement {
  /** The real attestation verifier — typically `createAttestationVerifier({ ... })`. */
  verifier: AttestationVerifier;
  /** Fail closed when the verifier reports not-enforced / no document (default true). */
  required?: boolean;
}

/** Opt-in enforcement gates for `verifyPCActnCore`. Any gate left absent stays 'not-enforced'. */
export interface EnforcementGates {
  /** M3 freshness anchor staleness gate. */
  freshness?: FreshnessEnforcement;
  /** M1 information-flow taint / provenance gate. */
  taint?: TaintEnforcement;
  /** M5 TEE attestation gate. */
  attestation?: AttestationEnforcement;
}

export type CheckStatus = 'pass' | 'fail' | 'not-enforced';
export interface VerifyResult {
  allow: boolean;
  checks: Record<string, CheckStatus>;
  reason?: string;
}

/**
 * Appendix A, M0-available checks. Checks owned by later milestones (attestation, plan-root
 * authorization, taint gate, threshold, revocation, zk, bond) report 'not-enforced' unless a hook
 * is supplied. allow = no check failed; callers requiring a stronger rung must inspect `checks`.
 */
export async function verifyPCActnCore(
  p: PCActn,
  opts: {
    grant: Capability;
    nowEpoch?: number;
    /**
     * This verifier's own audience id, compared against the PCActn's signed `aud`:
     *  - a string            => must equal `aud`, else the `audience` check fails;
     *  - `null`              => deliberate opt-out ("I accept any audience"): reports 'not-enforced';
     *  - omitted/`undefined` => FAIL-CLOSED when the PCActn carries a signed `aud` (a verifier that
     *                           forgets its audience must not silently lose cross-instance binding).
     *                           Reports 'not-enforced' only when the PCActn has no `aud` at all.
     */
    audience?: string | null;
    hooks?: VerifyHooks;
    /**
     * Opt-in enforcement gates (M1 taint / M3 freshness / M5 attestation). Absent => every gate reports
     * 'not-enforced' and the output is byte-identical to before (strictly additive). Each gate FAILS
     * CLOSED when on. See {@link EnforcementGates}.
     */
    enforce?: EnforcementGates;
  },
): Promise<VerifyResult> {
  const checks: Record<string, CheckStatus> = {};
  let reason: string | undefined;
  const fail = (name: string, why: string) => {
    checks[name] = 'fail';
    reason ??= `${name}: ${why}`;
  };
  const now = opts.nowEpoch ?? Date.now();
  const ctx: VerifyContext = { pcactn: p, grant: opts.grant, nowEpoch: now };

  try {
    // NORMATIVE CHECK ORDER: wire, version, audience, validity, cap_chain, grant_ref_bound, plan_inclusion,
    // leaf_signature, counter, then hooks. A wire failure is terminal: nothing else is evaluated.
    const wire = validateWireV2(p);
    if (wire !== null) {
      checks.wire = 'fail';
      return { allow: false, checks, reason: `wire: ${wire}` };
    }
    checks.wire = 'pass';

    // 0. version
    if (p.ver === PCACTN_VERSION) checks.version = 'pass';
    else fail('version', `unsupported ver ${String(p.ver)} (this verifier requires ${PCACTN_VERSION})`);

    // 0a. freshness binding (audit P0-5): audience + validity window.
    // FAIL-CLOSED: a PCActn that carries a signed `aud` but whose verifier supplied NO audience would
    // silently lose its cross-instance binding, so that is a failure — not 'not-enforced'. A caller that
    // genuinely accepts any audience must opt out EXPLICITLY with `audience: null`. A PCActn with no `aud`
    // is unchanged (when no audience is supplied it stays 'not-enforced').
    const hasAud = typeof p.aud === 'string' && p.aud.length > 0;
    if (opts.audience === null) checks.audience = 'not-enforced';
    else if (opts.audience === undefined) {
      if (hasAud) fail('audience', 'PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)');
      else checks.audience = 'not-enforced';
    } else if (p.aud === opts.audience) checks.audience = 'pass';
    else fail('audience', 'aud does not match this resource server / instance');
    if (!(p.exp > p.iat)) fail('validity', 'exp must be greater than iat');
    else if (p.exp - p.iat > PCACTN_MAX_LIFETIME_MS) fail('validity', `lifetime exceeds ${PCACTN_MAX_LIFETIME_MS} ms`);
    else if (p.iat > now + PCACTN_MAX_SKEW_MS) fail('validity', 'iat is in the future (clock skew)');
    else if (now > p.exp) fail('validity', 'the PCActn has expired');
    else checks.validity = 'pass';

    // 1. capability chain, root == G
    const chain = p.cap_chain;
    if (!Array.isArray(chain) || chain.length === 0) {
      fail('cap_chain', 'empty chain');
    } else if (capHash(chain[0]!) !== capHash(opts.grant)) {
      fail('cap_chain', 'chain root is not the grant');
    } else {
      const r = verifyChain(chain, opts.grant.issuer);
      if (r.ok) checks.cap_chain = 'pass';
      else fail('cap_chain', r.reason ?? 'invalid');
    }

    // 1a. grant_ref binding (normative): the signed `grant_ref` MUST be a non-empty string byte-equal to the id of
    //     the ROOT capability of the presented chain (cap_chain[0].id). Replay state (nonce / counter / budget
    //     namespaces) is keyed on grant_ref, so an unbound value would let a holder mint fresh namespaces.
    //     Evaluated independently of the cap_chain verdict and FAIL-CLOSED on an empty / malformed chain.
    const chainRoot: unknown = Array.isArray(chain) && chain.length > 0 ? chain[0] : undefined;
    const rootId: unknown = typeof chainRoot === 'object' && chainRoot !== null ? (chainRoot as { id?: unknown }).id : undefined;
    if (typeof p.grant_ref === 'string' && p.grant_ref.length > 0 && typeof rootId === 'string' && p.grant_ref === rootId) {
      checks.grant_ref_bound = 'pass';
    } else {
      fail('grant_ref_bound', 'grant_ref is not the id of the root capability in cap_chain');
    }

    // 2. plan inclusion (L1): the leaf is recomputed from the action itself
    const cond = p.plan.conditions_digest ?? conditionsDigest();
    const leaf = planLeaf(p.plan.node_id, p.action, cond);
    if (verifyInclusion(p.plan.root, p.plan.inclusion_proof, leaf)) checks.plan_inclusion = 'pass';
    else fail('plan_inclusion', 'action is not a node of the committed plan');
    checks.plan_root_authorized = 'not-enforced'; // M1/M2

    // 3. leaf-holder signature over the canonical body (B4: dispatched by `alg` through the agility seam;
    //    no `alg` == ed25519, byte-identical to the pre-B4 verifyB64u(leaf.holder, message, sig) call).
    const leafCap = Array.isArray(chain) ? chain[chain.length - 1] : undefined;
    if (
      leafCap &&
      typeof p.sig === 'string' &&
      verifyLeafSuite({ alg: p.alg, holder: leafCap.holder, pqPublicKey: p.pq_pk, message: thresholdMessage(p), sig: p.sig, pqSig: p.pq_sig })
    ) {
      checks.leaf_signature = 'pass';
    } else {
      fail('leaf_signature', 'signature does not verify under the leaf holder key / suite');
    }

    // 4. counter (monotonicity vs. stored state is the RS's job; presence/type here)
    if (typeof p.counter === 'number' && Number.isSafeInteger(p.counter) && p.counter >= 0) checks.counter = 'pass';
    else fail('counter', 'missing or not a non-negative safe integer');

    // later milestones

    // M1 taint gate (enforce.taint). Reuses the L4 taint functional verbatim: the agent's own label is
    // never read; every declared ref is independently re-classified from server facts. Fails closed when
    // the lineage is unverifiable (valid:false => stub/empty/forged provenance) or the taint exceeds policy.
    if (opts.enforce?.taint) {
      const g = opts.enforce.taint;
      try {
        const t = computeTaint(p.provenance, g.ctx);
        if (!t.valid) fail('taint_gate', t.reason ?? 'provenance lineage is not server-verifiable (fail closed)');
        else if (!(g.maxTaint >= 0)) fail('taint_gate', 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)');
        else if (t.taint > g.maxTaint) fail('taint_gate', `information-flow taint ${t.taint} exceeds policy max ${g.maxTaint}`);
        else checks.taint_gate = 'pass';
      } catch (e) {
        fail('taint_gate', `taint gate error (fail closed): ${(e as Error).message}`);
      }
    } else {
      checks.taint_gate = 'not-enforced'; // M1 (off by default)
    }

    // M3 freshness gate (enforce.freshness). Rejects a missing / stub / stale signed freshness anchor.
    if (opts.enforce?.freshness) {
      const g = opts.enforce.freshness;
      const epochMs = g.epochMs ?? BEACON_EPOCH_MS;
      const fnow = g.now ?? now;
      const skew = Number.isFinite(g.clockSkewMs) ? Math.max(0, g.clockSkewMs as number) : 0;
      const fr = p.freshness;
      if (!(epochMs > 0) || !Number.isFinite(g.maxAgeMs) || g.maxAgeMs < 0) {
        fail('freshness', 'freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)');
      } else if (typeof fr?.beacon_ref !== 'string' || fr.beacon_ref.length === 0 || !Number.isSafeInteger(fr.epoch) || fr.epoch <= 0) {
        fail('freshness', 'freshness anchor is missing (empty beacon_ref or non-positive epoch stub)');
      } else {
        const anchor = fr.epoch * epochMs;
        if (anchor > fnow + skew) fail('freshness', 'freshness anchor is in the future');
        else if (fnow - anchor > g.maxAgeMs) fail('freshness', `freshness anchor is stale (older than ${g.maxAgeMs} ms)`);
        else checks.freshness = 'pass';
      }
    }

    const run = async (name: string, hook: Hook | undefined, applicable = true) => {
      if (!applicable) return;
      const res = await (hook ?? notEnforced)(ctx);
      if (!res.enforced) checks[name] = 'not-enforced';
      else if (res.ok) checks[name] = 'pass';
      else fail(name, res.reason ?? 'rejected');
    };
    // M5 attestation (enforce.attestation): run the real attestation verifier; when the gate is on, a
    // not-enforced / absent result is a FAIL (fail closed) unless `required` is explicitly false. The
    // gate's verifier takes the `attestation` slot in place of any hooks.attestation (a caller sets one
    // or the other); off by default this is byte-identical to the previous `hooks.attestation` path.
    const attGate = opts.enforce?.attestation;
    await run('attestation', attGate?.verifier ?? opts.hooks?.attestation);
    if (attGate && (attGate.required ?? true) && checks.attestation === 'not-enforced') {
      fail('attestation', 'attestation required but the verifier reported not-enforced / no document (fail closed)');
    }
    await run('threshold', opts.hooks?.threshold);
    await run('revocation', opts.hooks?.revocation);

    // §9B / M6 zk-compliance — FAIL CLOSED AT THE CORE.
    //
    // A PCActn that CARRIES a `zk_compliance` proof is asserting a cryptographic compliance guarantee. If
    // no zk verifier is available to check it, that guarantee is UNVERIFIED — and an unverified proof must
    // NEVER be silently accepted. Previously this reported 'not-enforced' whenever `hooks.zk` was absent,
    // so a bare `verifyPCActnCore` / `verifyPCActn` caller that supplied neither `hooks.zk` nor
    // `require:['zk_compliance']` would silently ACCEPT an unverified (even forged) proof. The guarantee
    // now lives in the CORE, not only in a host's `require` list: a present-but-unverifiable proof denies
    // here, for every caller.
    //
    // Back-compat is exact: a PCActn that carries NO `zk_compliance` sets no `zk_compliance` check at all
    // (byte-identical output to before). A present proof WITH a `hooks.zk` verifier runs the verifier
    // normally (pass => 'pass', reject => 'fail'); a verifier that declines to enforce a present proof is
    // itself a fail-closed deny (a present proof may not end up unenforced).
    if (p.zk_compliance !== undefined) {
      await run('zk_compliance', opts.hooks?.zk);
      if (checks.zk_compliance !== 'pass' && checks.zk_compliance !== 'fail') {
        fail('zk_compliance', 'PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof');
      }
    }

    if (p.bond_ref !== undefined) checks.bond = 'not-enforced';
  } catch (e) {
    reason ??= `malformed PCActn: ${(e as Error).message}`;
    checks.malformed = 'fail';
  }

  const allow = !Object.values(checks).includes('fail');
  return allow ? { allow, checks } : { allow, checks, reason };
}
