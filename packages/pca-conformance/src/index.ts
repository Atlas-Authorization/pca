/**
 * @atlasauth/pca-conformance
 * =========================================================================================
 * Canonical, VERSIONED conformance vectors for the PCActn (Proof-Carrying Action) verifier,
 * plus an SDK-agnostic differential harness. This is the interop boundary for the protocol:
 * every PCA verifier implementation (the TypeScript core in `@atlasauth/pca`, the zkVM, and
 * the language SDKs under `sdks/`) must agree, byte-for-byte on identical input, about which
 * actions it accepts and which it rejects — and WHY (the per-check verdict), not just the
 * final allow/deny.
 *
 * The vectors are produced through the REAL `@atlasauth/pca` builders with DETERMINISTIC keys
 * and a fixed clock (no randomness, no wall-clock), so regenerating yields identical bytes.
 * One canonical VALID action fully verifies; every other vector is that same action with a
 * single targeted mutation that trips exactly one failure mode (for the semantic/temporal
 * modes the leaf signature is re-computed over the mutated body so the failure is ISOLATED to
 * the one check under test; the two signature-tamper vectors deliberately do not re-sign).
 *
 * -----------------------------------------------------------------------------------------
 * vectors.json SCHEMA (format is stable; `version` = {@link CONFORMANCE_VERSION})
 * -----------------------------------------------------------------------------------------
 *   {
 *     "version":     string              // CONFORMANCE_VERSION (semver of the vector set)
 *     "generator":   string              // human note: how the bytes are produced
 *     "sig_domain":  string              // the PCActn signature domain tag (context)
 *     "check_order": string[]            // NORMATIVE order the core evaluates checks in;
 *                                        //   `firstFailedCheck` is the earliest 'fail' here
 *     "vectors": [
 *       {
 *         "id":          string          // stable identifier (also the failure-mode name)
 *         "description": string          // one line: what this vector proves
 *         "pcactn":      PCActn          // the signed action object (full wire form)
 *         "aud":         string | null   // the VERIFIER's own audience id (opts.audience);
 *                                        //   null = "accept any audience" (explicit opt-out)
 *         "verifyOptions": {
 *           "nowEpoch":  number          // the verifier clock, epoch ms (deterministic)
 *           "enforce"?:  {               // opt-in gates; absent = every gate 'not-enforced'
 *             "freshness"?:   { "maxAgeMs": number, "epochMs"?: number, "clockSkewMs"?: number }
 *             "taint"?:       { "maxTaint": number, "registry": "empty" }
 *             "attestation"?: { "required"?: boolean, "mode": "not-enforced" }
 *           }
 *           "intent"?:   {               // Intent Layer M2 policy; active iff require or a threshold is set
 *             "require"?: boolean, "min_fidelity_ppm"?: number, "max_residual_risk_ppm"?: number
 *           }
 *         }
 *         "expect": {
 *           "ok":              boolean                       // == VerifyResult.allow
 *           "firstFailedCheck": string | null               // first 'fail' in check_order
 *           "perCheck":        { [check: string]: "pass" | "fail" | "not-enforced" }
 *         }
 *       }, ...
 *     ]
 *   }
 *
 * A non-TypeScript runner loads the SAME bytes, feeds each `pcactn` to its own verifier with
 * the given `aud`/`verifyOptions`, and asserts its result matches `expect`. The declarative
 * `enforce` block (no functions, no host objects) is what each language translates into its
 * own enforcement wiring — e.g. `registry: "empty"` => the empty trusted-input registry,
 * `attestation.mode: "not-enforced"` => a verifier that yields no attestation document.
 * =========================================================================================
 */

import {
  type Capability,
  type CapabilityChain,
  type CheckStatus,
  type EnforcementGates,
  type KeyPair,
  type PCActn,
  type PCActnBody,
  type PlanNode,
  type VerifyResult,
  DEFAULT_RISK_POLICY,
  b64u,
  buildPCActn,
  delegate,
  mintGrant,
  mintRoot,
  notEnforced,
  paramsDigest,
  publicKeyOf,
  sha256,
  signPCActn,
  taint,
  unb64u,
  utf8,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  type EnvelopeIntent,
  type IntentPolicy,
  intentGoal,
  intentMapDigest,
} from '@atlasauth/pca/ext/intent';

/** Semver of the vector set. Bump on ANY change to the bytes of `vectors.json`. */
export const CONFORMANCE_VERSION = '1.2.0';

/** NORMATIVE order the core verifier evaluates checks in; `firstFailedCheck` is the earliest 'fail' here. */
export const CHECK_ORDER = [
  'wire',
  'version',
  'audience',
  'validity',
  'cap_chain',
  'grant_ref_bound',
  'plan_inclusion',
  'plan_root_authorized',
  'leaf_signature',
  'counter_format',
  // Intent Layer M2: reported only when the PCActn carries `intent` or the verifier's intent policy is active.
  'intent',
  'taint_gate',
  'freshness',
  'attestation',
  'threshold',
  'revocation',
] as const;

// ---- vector + harness types ----------------------------------------------------------------

/** Declarative, JSON-only form of the opt-in enforcement gates (materialized per language). */
export interface EnforceSpec {
  freshness?: { maxAgeMs: number; epochMs?: number; clockSkewMs?: number };
  taint?: { maxTaint: number; registry: 'empty' };
  attestation?: { required?: boolean; mode: 'not-enforced' };
}

/** The portion of a verifier's options that is not the audience id (which is the vector's `aud`). */
export interface VerifyOptionsSpec {
  /** Verifier clock, epoch ms. Deterministic (never `Date.now()`). */
  nowEpoch: number;
  /** Opt-in enforcement gates; absent => every gate reports 'not-enforced'. */
  enforce?: EnforceSpec;
  /** Intent Layer M2 policy (`{require?, min_fidelity_ppm?, max_residual_risk_ppm?}`); JSON-only, passed through as is. */
  intent?: IntentPolicy;
}

/** The authored expectation for a vector — the full per-check contract, not just allow/deny. */
export interface VectorExpectation {
  ok: boolean;
  firstFailedCheck: string | null;
  perCheck: Record<string, CheckStatus>;
}

/** One conformance vector. */
export interface ConformanceVector {
  id: string;
  description: string;
  pcactn: PCActn;
  /** The verifier's own audience id (opts.audience); `null` = accept any audience. */
  aud: string | null;
  verifyOptions: VerifyOptionsSpec;
  expect: VectorExpectation;
}

/** The full, serializable vector set written to `vectors.json`. */
export interface ConformanceVectorSet {
  version: string;
  generator: string;
  sig_domain: string;
  check_order: readonly string[];
  vectors: ConformanceVector[];
}

/** The verdict shape every verifier must return (the core's {@link VerifyResult} satisfies it). */
export interface HarnessVerifyResult {
  allow: boolean;
  checks: Record<string, string>;
  reason?: string;
}

/** The fully-resolved, JSON-expressible input a verify function receives from the harness. */
export interface ConformanceVerifyInput {
  /** The root Intent Grant (== `pcactn.cap_chain[0]`); the core verifier requires it explicitly. */
  grant: Capability;
  /** The verifier's own audience id, or `null` to accept any. */
  audience: string | null;
  nowEpoch: number;
  enforce?: EnforceSpec;
  /** Intent Layer M2 policy. */
  intent?: IntentPolicy;
}

/** Any verifier under test: a plain function of (action, input) -> verdict. SDK-mirrorable. */
export type HarnessVerify = (
  pcactn: PCActn,
  input: ConformanceVerifyInput,
) => HarnessVerifyResult | Promise<HarnessVerifyResult>;

/** Per-vector outcome of a harness run. */
export interface VectorRunResult {
  id: string;
  /** True iff the verifier's verdict matched `expect` exactly (allow + firstFailedCheck + perCheck). */
  matched: boolean;
  expected: VectorExpectation;
  actual: { allow: boolean; firstFailedCheck: string | null; checks: Record<string, string>; reason?: string };
  /** Human-readable reasons the verdict diverged (empty when matched). */
  divergences: string[];
}

/** Structured report of a full harness run. */
export interface ConformanceReport {
  version: string;
  total: number;
  passed: number;
  failed: number;
  /** True iff every vector matched. */
  ok: boolean;
  results: VectorRunResult[];
}

// ---- deterministic key + byte helpers ------------------------------------------------------

const SEED_DOMAIN = 'atlas-pca/conformance/v1/';

/** Deterministic Ed25519 key pair for `label` (secret = sha256(domain||label), a valid 32-byte seed). */
function kp(label: string): KeyPair {
  const secretKey = sha256(utf8(SEED_DOMAIN + label));
  return { secretKey, publicKey: publicKeyOf(secretKey) };
}

/** Flip one byte of a base64url blob so a signature (or any fixed-length field) stops verifying. */
function flipByte(b64: string): string {
  const bytes = unb64u(b64);
  const copy = new Uint8Array(bytes);
  const first = copy[0] ?? 0;
  copy[0] = (first ^ 0x01) & 0xff;
  return b64u(copy);
}

// ---- the canonical deterministic scenario --------------------------------------------------

const PRINCIPAL = kp('principal');
const AGENT = kp('agent');
const SUBAGENT = kp('subagent');

/** Root Intent Grant: principal -> agent. */
export const CANONICAL_GRANT: Capability = mintRoot({
  principalSecret: PRINCIPAL.secretKey,
  principalPublic: b64u(PRINCIPAL.publicKey),
  holder: b64u(AGENT.publicKey),
  caveats: [],
});

/** One delegation hop: agent -> sub-agent (the acting leaf). */
const DELEGATED: Capability = delegate(CANONICAL_GRANT, b64u(SUBAGENT.publicKey), [], AGENT.secretKey);

/** The two-hop capability chain the canonical action carries. */
const CHAIN: CapabilityChain = [CANONICAL_GRANT, DELEGATED];

const PARAMS = { amount: 42, currency: 'usd' };

/** A two-node committed plan; the action targets `refund`. */
const PLAN: PlanNode[] = [
  { id: 'preflight', verb: 'noop', resource: 'none' },
  {
    id: 'refund',
    verb: 'stripe.refund',
    resource: 'charge:ch_conformance',
    params_digest: paramsDigest(PARAMS),
    reversibility_class: 'reversible',
  },
];

const AUD = 'atlas:rs:conformance';
const OTHER_AUD = 'atlas:rs:elsewhere';
/** Fixed verifier clock (epoch ms). */
const NOW = 1_700_000_000_000;

/** The one canonical VALID, fully-verifying PCActn (leaf signed by the sub-agent). */
const VALID: PCActn = buildPCActn({
  grant: CANONICAL_GRANT,
  chain: CHAIN,
  plan: PLAN,
  nodeId: 'refund',
  params: PARAMS,
  counter: 1,
  signerSecret: SUBAGENT.secretKey,
  aud: AUD,
  iat: NOW,
  riskClaim: { r: 0, inputs: {} },
});

// ---- Intent Layer M2: a root grant minted for an intent goal, and an action carrying the bound `intent` slot ----

const INTENT_REF = b64u(sha256(utf8(SEED_DOMAIN + 'intent-statement')));
const INTENT_MAP_DIGEST = intentMapDigest({ v: 1, kind: 'pca-intent-map', intent_ref: INTENT_REF, metrics: { fidelity_est_ppm: 950_000, residual_risk_ppm: 12_000 } });
const INTENT_SALT = 'Y29uZm9ybWFuY2UtaW50ZW50';
const INTENT: EnvelopeIntent = { ref: INTENT_REF, map_digest: INTENT_MAP_DIGEST, goal_salt: INTENT_SALT, fidelity_ppm: 950_000, residual_risk_ppm: 12_000 };

/** Root Intent Grant whose envelope goal commits to `pca-intent:v1:<ref>:<map_digest>` (principal -> sub-agent, one hop). */
const INTENT_GRANT: Capability = mintGrant({
  principalSecret: PRINCIPAL.secretKey,
  principalPublic: b64u(PRINCIPAL.publicKey),
  holder: b64u(SUBAGENT.publicKey),
  envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  goal: intentGoal(INTENT_REF, INTENT_MAP_DIGEST),
  salt: INTENT_SALT,
}).grant;

const intentAction = (intent?: EnvelopeIntent): PCActn =>
  buildPCActn({
    grant: INTENT_GRANT,
    chain: [INTENT_GRANT],
    plan: PLAN,
    nodeId: 'refund',
    params: PARAMS,
    counter: 1,
    signerSecret: SUBAGENT.secretKey,
    aud: AUD,
    iat: NOW,
    riskClaim: { r: 0, inputs: {} },
    ...(intent !== undefined ? { intent } : {}),
  });

/** Re-sign a (mutated) action's body with the acting leaf's key, isolating the failure under test. */
function resign(p: PCActn): PCActn {
  const { sig: _dropped, ...body } = p;
  void _dropped;
  const rebuilt: PCActnBody = body;
  return signPCActn(rebuilt, SUBAGENT.secretKey);
}

/** Corrupt the acting leaf hop's capability signature, then re-sign the leaf over the mutated body. */
function withBrokenHopSig(p: PCActn): PCActn {
  const hops = p.cap_chain.map((c) => ({ ...c }));
  const leaf = hops[hops.length - 1];
  if (!leaf) throw new Error('conformance: chain has no leaf hop');
  leaf.sig = flipByte(leaf.sig);
  return resign({ ...p, cap_chain: hops });
}

// ---- authored per-check expectations -------------------------------------------------------

/** The SPEC's expected per-check verdict for the canonical valid action (authored, not derived). */
const BASE_CHECKS: Record<string, CheckStatus> = {
  wire: 'pass',
  version: 'pass',
  audience: 'pass',
  validity: 'pass',
  cap_chain: 'pass',
  grant_ref_bound: 'pass',
  plan_inclusion: 'pass',
  plan_root_authorized: 'not-enforced',
  leaf_signature: 'pass',
  counter_format: 'pass',
  taint_gate: 'not-enforced',
  attestation: 'not-enforced',
  threshold: 'not-enforced',
  revocation: 'not-enforced',
};

/** Expectation for a vector that fails exactly one of the BASE checks (rest unchanged). */
function failingBase(check: string, extra?: Record<string, CheckStatus>): VectorExpectation {
  const perCheck: Record<string, CheckStatus> = { ...BASE_CHECKS, ...(extra ?? {}), [check]: 'fail' };
  return { ok: false, firstFailedCheck: check, perCheck };
}

// ---- the vector set ------------------------------------------------------------------------

/**
 * Deterministically build the full vector set. Pure: same code => identical object => identical
 * `vectors.json` bytes. One VALID vector + exactly one vector per failure mode.
 */
export function generateVectorSet(): ConformanceVectorSet {
  const base = (over?: Partial<VerifyOptionsSpec>): VerifyOptionsSpec => ({ nowEpoch: NOW, ...(over ?? {}) });

  const vectors: ConformanceVector[] = [
    {
      id: 'valid',
      description: 'Canonical well-formed action: every applicable check passes; later-milestone gates report not-enforced.',
      pcactn: VALID,
      aud: AUD,
      verifyOptions: base(),
      expect: { ok: true, firstFailedCheck: null, perCheck: { ...BASE_CHECKS } },
    },
    {
      id: 'bad_wire',
      description: 'plan.root is not canonical base64url (a bad encoding): the wire check fails and is terminal (no other check is evaluated).',
      pcactn: { ...VALID, plan: { ...VALID.plan, root: 'not-a-canonical-base64url-value!!' } },
      aud: AUD,
      verifyOptions: base(),
      expect: { ok: false, firstFailedCheck: 'wire', perCheck: { wire: 'fail' } },
    },
    {
      id: 'wrong_version',
      description: 'ver != 2 (re-signed): the version check fails though the signature over the mutated body is valid.',
      pcactn: resign({ ...VALID, ver: 1 }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('version'),
    },
    {
      id: 'audience_mismatch',
      description: 'Signed aud names a different resource server than the verifier: the audience binding fails.',
      pcactn: resign({ ...VALID, aud: OTHER_AUD }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('audience'),
    },
    {
      id: 'expired',
      description: 'now > exp (iat/exp in the past, re-signed): the validity window fails (expired).',
      pcactn: resign({ ...VALID, iat: NOW - 1_800_000, exp: NOW - 600_000 }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('validity'),
    },
    {
      id: 'not_yet_valid',
      description: 'iat beyond the clock-skew allowance in the future (re-signed): the validity window fails (not yet valid).',
      pcactn: resign({ ...VALID, iat: NOW + 300_000, exp: NOW + 300_000 + 1_200_000 }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('validity'),
    },
    {
      id: 'grant_ref_not_root_id',
      description: 'grant_ref is a well-formed value that is NOT the id of cap_chain[0] (re-signed): only the grant_ref_bound check fails (replay namespaces are keyed on grant_ref).',
      pcactn: resign({ ...VALID, grant_ref: flipByte(VALID.grant_ref) }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('grant_ref_bound'),
    },
    {
      id: 'broken_cap_chain_sig',
      description: 'The acting leaf hop capability signature is corrupted (leaf re-signed): the cap_chain check fails.',
      pcactn: withBrokenHopSig(VALID),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('cap_chain'),
    },
    {
      id: 'plan_non_inclusion',
      description: "action.params_digest no longer matches the committed plan leaf (re-signed): plan inclusion fails.",
      pcactn: resign({ ...VALID, action: { ...VALID.action, params_digest: paramsDigest({ amount: 999 }) } }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('plan_inclusion'),
    },
    {
      id: 'bad_leaf_signature',
      description: 'The leaf-holder signature bytes are corrupted (NOT re-signed): the leaf_signature check fails.',
      pcactn: { ...VALID, sig: flipByte(VALID.sig) },
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('leaf_signature'),
    },
    {
      id: 'counter_invalid',
      description: 'Counter is negative (rolled-back / replayed, re-signed): the offline counter check fails. Stateful replay detection across actions is the resource server\'s job.',
      pcactn: resign({ ...VALID, counter: -1 }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('counter_format'),
    },
    {
      id: 'intent_bound',
      description: 'Intent Layer M2: the signed intent slot opens the root grant goal commitment (pca-intent:v1:<ref>:<map_digest>) and meets the policy floor/ceiling: the intent check passes.',
      pcactn: intentAction(INTENT),
      aud: AUD,
      verifyOptions: base({ intent: { require: true, min_fidelity_ppm: 950_000, max_residual_risk_ppm: 12_000 } }),
      expect: { ok: true, firstFailedCheck: null, perCheck: { ...BASE_CHECKS, intent: 'pass' } },
    },
    {
      id: 'intent_required_absent',
      description: 'Intent policy {require:true} but the action carries no intent slot: the intent check fails closed.',
      pcactn: intentAction(),
      aud: AUD,
      verifyOptions: base({ intent: { require: true } }),
      expect: failingBase('intent'),
    },
    {
      id: 'intent_binding_mismatch',
      description: "The intent slot's map_digest is not the one the root grant goal commits to: the intent check fails.",
      pcactn: intentAction({ ...INTENT, map_digest: INTENT_REF }),
      aud: AUD,
      verifyOptions: base(),
      expect: failingBase('intent'),
    },
    {
      id: 'intent_fidelity_below_min',
      description: 'Bound intent whose fidelity_ppm (950000) is below the policy min_fidelity_ppm (950001): the intent check fails.',
      pcactn: intentAction(INTENT),
      aud: AUD,
      verifyOptions: base({ intent: { min_fidelity_ppm: 950_001 } }),
      expect: failingBase('intent'),
    },
    {
      id: 'intent_residual_above_max',
      description: 'Bound intent whose residual_risk_ppm (12000) exceeds the policy max_residual_risk_ppm (11999): the intent check fails.',
      pcactn: intentAction(INTENT),
      aud: AUD,
      verifyOptions: base({ intent: { max_residual_risk_ppm: 11_999 } }),
      expect: failingBase('intent'),
    },
    {
      id: 'intent_bad_wire',
      description: 'The intent slot has fidelity_ppm 1000001 (out of [0, 1e6], re-signed): the wire check fails and is terminal.',
      pcactn: resign({ ...intentAction(INTENT), intent: { ...INTENT, fidelity_ppm: 1_000_001 } }),
      aud: AUD,
      verifyOptions: base(),
      expect: { ok: false, firstFailedCheck: 'wire', perCheck: { wire: 'fail' } },
    },
    {
      id: 'stale_freshness',
      description: 'GATED (enforce.freshness): the signed freshness anchor is a stub (empty beacon_ref / epoch 0), so the freshness gate fails closed.',
      pcactn: VALID,
      aud: AUD,
      verifyOptions: base({ enforce: { freshness: { maxAgeMs: 300_000 } } }),
      expect: {
        ok: false,
        firstFailedCheck: 'freshness',
        perCheck: { ...BASE_CHECKS, freshness: 'fail' },
      },
    },
    {
      id: 'taint_blocked',
      description: 'GATED (enforce.taint): with the empty trusted-input registry the provenance taint is the fail-closed worst case, exceeding the policy max, so the taint gate fails.',
      pcactn: VALID,
      aud: AUD,
      verifyOptions: base({ enforce: { taint: { maxTaint: 0.5, registry: 'empty' } } }),
      expect: failingBase('taint_gate'),
    },
    {
      id: 'missing_attestation',
      description: 'GATED (enforce.attestation, required): the verifier yields no attestation document, so the attestation gate fails closed.',
      pcactn: VALID,
      aud: AUD,
      verifyOptions: base({ enforce: { attestation: { required: true, mode: 'not-enforced' } } }),
      expect: failingBase('attestation'),
    },
  ];

  return {
    version: CONFORMANCE_VERSION,
    generator: '@atlasauth/pca-conformance generateVectorSet() — deterministic keys, fixed clock, real @atlasauth/pca builders',
    sig_domain: 'atlas-pca/actn/v2',
    check_order: CHECK_ORDER,
    vectors,
  };
}

/** The canonical vector set (built once, deterministically). */
export const VECTOR_SET: ConformanceVectorSet = generateVectorSet();

/** The vectors, for direct consumption. */
export const VECTORS: ConformanceVector[] = VECTOR_SET.vectors;

/** Canonical serialization of a vector set — the exact bytes written to `vectors.json` (stable, trailing newline). */
export function serializeVectorSet(set: ConformanceVectorSet): string {
  return JSON.stringify(set, null, 2) + '\n';
}

// ---- the differential harness --------------------------------------------------------------

/** Translate the declarative {@link EnforceSpec} into the core's real {@link EnforcementGates}. */
export function materializeEnforce(spec: EnforceSpec): EnforcementGates {
  const gates: EnforcementGates = {};
  if (spec.freshness) {
    gates.freshness = {
      maxAgeMs: spec.freshness.maxAgeMs,
      ...(spec.freshness.epochMs !== undefined ? { epochMs: spec.freshness.epochMs } : {}),
      ...(spec.freshness.clockSkewMs !== undefined ? { clockSkewMs: spec.freshness.clockSkewMs } : {}),
    };
  }
  if (spec.taint) {
    gates.taint = { maxTaint: spec.taint.maxTaint, ctx: { registry: taint.EMPTY_REGISTRY } };
  }
  if (spec.attestation) {
    gates.attestation = { verifier: notEnforced, required: spec.attestation.required ?? true };
  }
  return gates;
}

/**
 * The default verify adapter: wraps {@link verifyPCActnCore}, materializing the declarative enforce
 * spec into real gates. A foreign-language runner implements the mirror of this one function.
 */
export const coreVerify: HarnessVerify = (pcactn, input) => {
  const result: Promise<VerifyResult> = verifyPCActnCore(pcactn, {
    grant: input.grant,
    nowEpoch: input.nowEpoch,
    audience: input.audience,
    ...(input.enforce ? { enforce: materializeEnforce(input.enforce) } : {}),
    ...(input.intent ? { intent: input.intent } : {}),
  });
  return result;
};

/** First check (in insertion/evaluation order) whose status is 'fail', or null when none failed. */
export function firstFailedCheck(checks: Record<string, string>): string | null {
  for (const [name, status] of Object.entries(checks)) {
    if (status === 'fail') return name;
  }
  return null;
}

function sameChecks(a: Record<string, string>, b: Record<string, string>): boolean {
  const ak = Object.keys(a);
  const bk = Object.keys(b);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (a[k] !== b[k]) return false;
  }
  return true;
}

/**
 * Run every vector through `verify` and return a structured pass/fail report. A vector MATCHES when
 * the verifier's `allow`, its `firstFailedCheck` (per the evaluation order), and its full per-check
 * map all equal the authored expectation. SDK-agnostic: `verify` is a plain (action, input) -> verdict
 * function, so a Go / Rust / Python runner mirrors this harness over the same `vectors.json` bytes.
 */
export async function runConformance(
  verify: HarnessVerify = coreVerify,
  vectors: readonly ConformanceVector[] = VECTORS,
): Promise<ConformanceReport> {
  const results: VectorRunResult[] = [];
  for (const v of vectors) {
    // pca-unsafe-root: allow conformance runner over the harness's own bundled vectors, not caller input
    const grant = v.pcactn.cap_chain[0] ?? CANONICAL_GRANT;
    const input: ConformanceVerifyInput = {
      grant,
      audience: v.aud,
      nowEpoch: v.verifyOptions.nowEpoch,
      ...(v.verifyOptions.enforce ? { enforce: v.verifyOptions.enforce } : {}),
      ...(v.verifyOptions.intent ? { intent: v.verifyOptions.intent } : {}),
    };
    const verdict = await verify(v.pcactn, input);
    const actualFirst = firstFailedCheck(verdict.checks);
    const divergences: string[] = [];
    if (verdict.allow !== v.expect.ok) {
      divergences.push(`allow: expected ${v.expect.ok}, got ${verdict.allow}`);
    }
    if (actualFirst !== v.expect.firstFailedCheck) {
      divergences.push(`firstFailedCheck: expected ${String(v.expect.firstFailedCheck)}, got ${String(actualFirst)}`);
    }
    if (!sameChecks(verdict.checks, v.expect.perCheck)) {
      divergences.push(`perCheck: expected ${JSON.stringify(v.expect.perCheck)}, got ${JSON.stringify(verdict.checks)}`);
    }
    results.push({
      id: v.id,
      matched: divergences.length === 0,
      expected: v.expect,
      actual: {
        allow: verdict.allow,
        firstFailedCheck: actualFirst,
        checks: verdict.checks,
        ...(verdict.reason !== undefined ? { reason: verdict.reason } : {}),
      },
      divergences,
    });
  }
  const passed = results.filter((r) => r.matched).length;
  return {
    version: CONFORMANCE_VERSION,
    total: results.length,
    passed,
    failed: results.length - passed,
    ok: passed === results.length,
    results,
  };
}
