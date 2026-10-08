/**
 * §9B — Zero-knowledge proof-of-compliance (intent privacy from the Resource Server).
 *
 * The agent proves "action A is a valid derivation under policy P from committed plan Π" WITHOUT
 * revealing P, Π, or its reasoning to the RS. The RS learns only "authorized" — not why, not what the
 * principal is trying to do. The spec sanctions TWO realizations:
 *
 *   - A real SNARK over a compliance circuit (Groth16/BN254). IMPLEMENTED: `createGroth16SnarkBackend`
 *     verifies a real snarkjs Groth16 proof (circuit in `circuits/compliance.circom`) against the three
 *     commitments; `proveGroth16Compliance` generates one from a private policy/plan witness. The circuit
 *     proves, in zero-knowledge: commitment openings (knowledge of the attribute preimages), the release
 *     decision (plan-membership of the action verb AND risk<=budget => allow), and binds the proof to the
 *     RS's action/policy/plan commitments. See the circuit header for the exact statement — and for what it
 *     does NOT yet enforce (sha256-of-canonical-JSON in-circuit, and the full Policy VM). Plug it in via
 *     `createZkVerifier({ snarkBackend })`; it receives ONLY commitments as public inputs.
 *   - The cheaper ATTESTED-VM equivalent (this file's reference, `createAttestedComplianceProver`): a
 *     trusted attested VM runs the Policy VM `decide` and SIGNS a statement that it yielded release
 *     for the action. This is the spec's "attested-VM equivalent when ZK is too heavy." It gives the
 *     same PRIVACY property — the statement carries only COMMITMENTS (digests) to the policy and plan,
 *     never their plaintext — but a weaker trust model: the RS trusts the prover VM's key, rather than
 *     soundness of a circuit. (A real SNARK removes that trusted party.)
 *
 * The verifier in BOTH modes checks the proof against COMMITMENTS only, so it never needs the
 * plaintext policy or plan. `createZkVerifier` can be given the expected policy commitment(s) as bare
 * hashes — demonstrating that an RS can enforce policy it is not allowed to read.
 */
// `node:fs` / `node:path` are NOT imported statically — this module is re-exported from the package
// barrel, so a static Node-builtin import would break browser bundling. File reads use `readJsonFile`
// (lazy `await import('node:fs')`); path building uses the trivial `pjoin` below. Both are only ever
// reached on the server-side prove/verify paths.
const pjoin = (...parts: string[]): string => parts.join('/');
async function readJsonFile(path: string): Promise<object> {
  const { readFileSync } = await import('node:fs');
  return JSON.parse(readFileSync(path, 'utf8')) as object;
}
/** A cached, lazy verifying-key resolver: an explicit key, else the file read on first use. */
function lazyVkey(opts: { verificationKey?: object; verificationKeyPath?: string }, defaultPath: () => string): () => Promise<object> {
  let cached: object | undefined = opts.verificationKey;
  return async () => (cached ??= await readJsonFile(opts.verificationKeyPath ?? defaultPath()));
}
import { b64u, canonicalBytes, hashCanonical, sha256, unb64u, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';
import type { Capability } from './capability';
import { type PCActn, type HookResult, type VerifyContext, type ZkVerifier } from './pcactn';
import { type DecideInput, decide } from './policy-vm';

const DOMAIN = 'atlas-pca/zk-compliance/v1\0';

/** Commitment to the policy (what the RS is allowed to KNOW about G, not read): the grant's content address. */
export function policyCommitment(grant: Capability): string {
  // `grant.id` is `hashCanonical(body)` and the body includes the envelope caveat, so it is a binding
  // commitment to the whole policy without exposing predicates/caveats.
  return typeof grant?.id === 'string' ? grant.id : hashCanonical(grant);
}

/** Commitment to the action: content address of the PCActn's action descriptor. */
export function actionCommitment(pcactn: PCActn): string {
  return hashCanonical(pcactn?.action ?? null);
}

/**
 * The statement a compliance proof attests: "action A satisfies policy P over committed plan Π." It
 * carries ONLY commitments — the RS can verify it without learning the plaintext policy or plan.
 */
export interface ComplianceStatement {
  v: 1;
  mode: 'attested-vm';
  /** Commitment to the action proven compliant (`actionCommitment`). */
  action_commit: string;
  /** Commitment to the policy (`policyCommitment` of the grant). */
  policy_commit: string;
  /** Commitment to the committed plan Π (the PCActn's Merkle plan root). */
  plan_commit: string;
  /** The fact proven: the Policy VM released the guardian share for the action. Always true (an
   *  un-released action is unprovable). */
  released: true;
  /** The risk `r` the VM computed (public; does not reveal the policy). */
  r: number;
  issued_at: number;
  expires_at: number;
  /** b64u Ed25519 public key of the attested prover VM. */
  prover: string;
  /** b64u Ed25519 signature over the canonical body (all fields except `sig`). */
  sig: string;
}

export type ComplianceStatementBody = Omit<ComplianceStatement, 'sig'>;

function statementMessage(body: ComplianceStatementBody): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

export interface ProveOpts {
  pcactn: PCActn;
  /** The Policy VM inputs (incl. grant) the prover evaluates. Its grant commits `policy_commit`. */
  decideInput: DecideInput;
  issued_at: number;
  expires_at: number;
}

export interface AttestedComplianceProver {
  /** b64u public key the RS registers in `trustedProverKeys`. */
  readonly publicKey: string;
  /**
   * Run the Policy VM and, IFF it releases the guardian share, emit a signed `ComplianceStatement`
   * committing to the action/policy/plan. Throws if the action is NOT compliant — you cannot prove a
   * false statement.
   */
  prove(opts: ProveOpts): ComplianceStatement;
}

/**
 * The sanctioned ATTESTED-VM reference prover. It is the stand-in for a SNARK prover: instead of a
 * circuit proof it produces a signed attestation (by `attestorSecret`) that an attested VM ran the
 * Policy VM and got `released=true`. Only commitments go into the statement — never the plaintext
 * policy or plan.
 */
export function createAttestedComplianceProver(attestorSecret: Uint8Array): AttestedComplianceProver {
  const publicKey = b64u(publicKeyOf(attestorSecret));
  return {
    publicKey,
    prove(opts: ProveOpts): ComplianceStatement {
      const decision = decide(opts.decideInput);
      if (!decision.releaseGuardianShare) {
        throw new Error(`createAttestedComplianceProver: action is not compliant, nothing to prove (${decision.reasons.join('; ')})`);
      }
      const body: ComplianceStatementBody = {
        v: 1,
        mode: 'attested-vm',
        action_commit: actionCommitment(opts.pcactn),
        policy_commit: policyCommitment(opts.decideInput.grant),
        plan_commit: typeof opts.pcactn?.plan?.root === 'string' ? opts.pcactn.plan.root : '',
        released: true,
        r: decision.r,
        issued_at: opts.issued_at,
        expires_at: opts.expires_at,
        prover: publicKey,
      };
      return { ...body, sig: b64u(sign(attestorSecret, statementMessage(body))) };
    },
  };
}

/**
 * A real ZK backend verifies a proof against the public inputs (the three commitments). The reference
 * implementation is `createGroth16SnarkBackend` (real snarkjs Groth16 over `circuits/compliance.circom`).
 * Plug it in via `createZkVerifier({ snarkBackend })`; it receives ONLY commitments as public inputs,
 * preserving the privacy property.
 */
export interface SnarkBackend {
  verify(input: {
    /** The opaque proof carried in `pcactn.zk_compliance`. */
    proof: unknown;
    publicInputs: { action_commit: string; policy_commit: string; plan_commit: string };
    ctx: VerifyContext;
  }): boolean | Promise<boolean>;
}

export interface ZkVerifierOpts {
  /** b64u public keys of attested prover VMs trusted in attested-VM mode. */
  trustedProverKeys: string[];
  /**
   * The expected policy commitment(s), as bare hashes. When set, the verifier checks the statement
   * commits to one of these WITHOUT reading any plaintext policy — this is the intent-privacy path.
   * Omitted => the verifier derives the commitment from `ctx.grant` (non-private: the grant is in hand).
   */
  policyCommitments?: string[];
  /** Supplied => delegate proof verification to a real ZK backend (the statement is the proof). */
  snarkBackend?: SnarkBackend;
  /** Clock for freshness, epoch ms (default `Date.now`). */
  now?: () => number;
  /** Allowed clock skew (ms) for issued_at/expires_at (default 0). A statement with
   *  expires_at < issued_at is treated as malformed and rejected. */
  clockSkewMs?: number;
}

/**
 * Build a `ZkVerifier` hook (the §9B/M6 hook in pcactn.ts). The compliance proof is carried in
 * `pcactn.zk_compliance`. The hook BINDS the proof to this action and the committed plan, then:
 *   - SNARK mode (`snarkBackend` supplied): delegate to the backend with the three commitments as
 *     public inputs; accept iff the backend accepts AND the commitments bind to this PCActn/policy.
 *   - attested-VM mode: verify the statement is well-formed, its `prover ∈ trustedProverKeys`, its
 *     signature verifies, it is fresh, and its commitments match (action_commit = this action,
 *     plan_commit = this PCActn's plan root, policy_commit ∈ expected commitments).
 * In BOTH modes the verifier uses only commitments — never the plaintext policy or plan.
 */
export function createZkVerifier(opts: ZkVerifierOpts): ZkVerifier {
  const trusted = new Set(Array.isArray(opts.trustedProverKeys) ? opts.trustedProverKeys : []);
  const expectedPolicy = Array.isArray(opts.policyCommitments) ? new Set(opts.policyCommitments) : undefined;
  const clock = opts.now ?? (() => Date.now());
  const skew = Number.isFinite(opts.clockSkewMs) ? Math.max(0, opts.clockSkewMs as number) : 0;

  return async (ctx: VerifyContext): Promise<HookResult> => {
    const fail = (reason: string): HookResult => ({ enforced: true, ok: false, reason });
    try {
      const proof = ctx?.pcactn?.zk_compliance;
      if (proof === undefined || proof === null) return fail('no zk_compliance proof present');

      const actionCommit = actionCommitment(ctx.pcactn);
      const planCommit = typeof ctx.pcactn?.plan?.root === 'string' ? ctx.pcactn.plan.root : '';
      const wantPolicy = expectedPolicy ?? new Set([policyCommitment(ctx.grant)]);

      // SNARK seam: the proof is opaque; bind the public inputs to THIS action/plan, then delegate.
      if (opts.snarkBackend) {
        // policy_commit for the backend: the single expected commitment (or the grant-derived one).
        const policyCommit = expectedPolicy && expectedPolicy.size === 1 ? [...expectedPolicy][0]! : policyCommitment(ctx.grant);
        const ok = await opts.snarkBackend.verify({
          proof,
          publicInputs: { action_commit: actionCommit, policy_commit: policyCommit, plan_commit: planCommit },
          ctx,
        });
        return ok ? { enforced: true, ok: true } : fail('snark backend rejected the proof');
      }

      // attested-VM mode: the proof IS a ComplianceStatement.
      const st = proof as Partial<ComplianceStatement>;
      if (st.v !== 1 || st.mode !== 'attested-vm') return fail('unrecognized compliance statement');
      if (st.released !== true) return fail('statement does not assert release');
      if (typeof st.prover !== 'string' || !trusted.has(st.prover)) return fail('prover key is not trusted');

      const { sig, ...body } = st as ComplianceStatement;
      if (typeof sig !== 'string' || !verifyB64u(st.prover, statementMessage(body as ComplianceStatementBody), sig)) {
        return fail('compliance statement signature does not verify');
      }

      // freshness
      if (!Number.isFinite(st.issued_at) || !Number.isFinite(st.expires_at) || (st.expires_at as number) < (st.issued_at as number)) {
        return fail('malformed statement validity window');
      }
      const nowMs = clock();
      if (nowMs + skew < (st.issued_at as number)) return fail('compliance statement not yet valid');
      if (nowMs - skew > (st.expires_at as number)) return fail('compliance statement expired');

      // commitment binding — the ONLY policy/plan knowledge the verifier needs is these hashes.
      if (st.action_commit !== actionCommit) return fail('statement does not bind to this action');
      if (st.plan_commit !== planCommit) return fail('statement does not bind to this plan commitment');
      if (typeof st.policy_commit !== 'string' || !wantPolicy.has(st.policy_commit)) {
        return fail('statement policy commitment is not an expected policy');
      }

      return { enforced: true, ok: true };
    } catch (e) {
      return fail(`zk verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
    }
  };
}

/** Convenience: the policy commitment an RS pins when it is NOT allowed to read the grant's plaintext. */
export function pinnedPolicyCommitment(grant: Capability): string {
  return policyCommitment(grant);
}

// ===============================================================================================
// §9B — REAL Groth16 SNARK backend (circuits/compliance.circom, BN254).
//
// The circuit proves, in zero-knowledge over a private policy/plan witness:
//   (1) commitment OPENINGS: the prover knows attribute preimages opening the three Poseidon
//       commitments it outputs (policy/plan/action), with the (verb,resource) SHARED between the
//       policy opening and the action opening;
//   (2) the DECISION: the action verb equals the committed plan node's verb (plan membership) AND
//       risk<=budget, so allow = 1 (a deny witness makes `allow===1` unsatisfiable — a false
//       statement is unprovable);
//   (3) BINDING: the circuit's public binding tags (shaPolicy/shaPlan/shaAction) are the field
//       encodings of the RS's sha256 commitments, so Groth16 binds the proof to THIS (policy,plan,
//       action) — a proof minted for other commitments is cryptographically rejected.
//
// HONEST SCOPE (what it does NOT yet enforce):
//   - It does not recompute the RS's sha256(canonical(·)) commitments in-circuit from the full
//     canonical-JSON preimages (sha256-over-variable-length-JSON is out of scope here). The ZK
//     openings use Poseidon; the correspondence to the sha256 commitments is produced by the honest
//     prover (both derived from the same data), not proven in-circuit. So the private (verb,resource,
//     risk,budget) are not proven to be the literal sha256 preimages.
//   - The decision is a SUBSET of the full Policy VM (policy-vm.ts): plan-membership of the verb and
//     risk<=budget. It does not encode the full predicate/caveat/prohibition/attenuation logic.
// ===============================================================================================

/** BN254 scalar field modulus (the field snarkjs/circom public signals live in). */
const BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Map a b64u-encoded sha256 commitment (32 bytes = 256 bits) to a BN254 scalar-field element, as a
 * decimal string. This is the deterministic encoding used for the circuit's public binding tags
 * (shaPolicy/shaPlan/shaAction); the prover and the verifier derive it identically from the same
 * commitment string, so Groth16's public-input binding ties the proof to that exact commitment.
 * 256 bits are reduced mod the ~254-bit field (a binding tag, not a hiding commitment).
 */
export function commitmentField(b64uCommit: string): string {
  const bytes = unb64u(b64uCommit);
  let acc = 0n;
  for (const byte of bytes) acc = (acc << 8n) | BigInt(byte);
  return (acc % BN254_FR).toString();
}

/** The opaque proof carried in `pcactn.zk_compliance` in Groth16 mode. */
export interface Groth16ComplianceProof {
  system: 'groth16-bn254';
  circuit: 'pca-compliance-v1';
  /** snarkjs Groth16 proof object (`pi_a`/`pi_b`/`pi_c`/`protocol`/`curve`). */
  proof: unknown;
  /**
   * Public signals, in the circuit's order:
   *   [0] policyCommit [1] planCommit [2] actionCommit (Poseidon openings, outputs)
   *   [3] shaPolicy    [4] shaPlan    [5] shaAction    (sha256 binding tags, public inputs)
   *   [6] allow (== "1")
   */
  publicSignals: string[];
}

/** Indices of the circuit's public signals (outputs first, then public inputs — snarkjs order). */
const PUBLIC_SIGNAL = {
  policyCommit: 0,
  planCommit: 1,
  actionCommit: 2,
  shaPolicy: 3,
  shaPlan: 4,
  shaAction: 5,
  allow: 6,
} as const;
const PUBLIC_SIGNAL_COUNT = 7;

// ---- minimal snarkjs typing + lazy load (snarkjs is an OPTIONAL runtime dep; the attested-VM path
// and createZkVerifier itself never need it, so it is imported only when a Groth16 proof is made or
// verified). -----------------------------------------------------------------------------------
type Groth16Api = {
  verify(vk: object, publicSignals: string[], proof: unknown): Promise<boolean>;
  fullProve(
    input: Record<string, unknown>,
    wasmPath: string,
    zkeyPath: string,
  ): Promise<{ proof: unknown; publicSignals: string[] }>;
};

async function loadGroth16(): Promise<Groth16Api> {
  // String-typed specifier: snarkjs ships no type declarations, so a literal import would error
  // (implicit any). This also keeps snarkjs out of the module graph for consumers that never call it.
  const spec: string = 'snarkjs';
  const m = (await import(spec)) as unknown as { groth16?: Groth16Api; default?: { groth16?: Groth16Api } };
  const g = m.groth16 ?? m.default?.groth16;
  if (!g) throw new Error('snarkjs groth16 API not available (install the optional dependency "snarkjs")');
  return g;
}

// ---- fixture locations (generated by circuits/setup.sh; loaded from the package, works from both
// src under vitest/tsx and built dist). ---------------------------------------------------------
const circuitsBuild = (): string => pjoin(__dirname, '..', 'circuits', 'build');
/** Default path to the Groth16 verifying key (`verification_key.json`). */
export const DEFAULT_VKEY_PATH = (): string => pjoin(circuitsBuild(), 'verification_key.json');
/** Default path to the circuit witness calculator wasm. */
export const DEFAULT_WASM_PATH = (): string => pjoin(circuitsBuild(), 'compliance_js', 'compliance.wasm');
/** Default path to the Groth16 proving key (`compliance_final.zkey`). */
export const DEFAULT_ZKEY_PATH = (): string => pjoin(circuitsBuild(), 'compliance_final.zkey');

export interface Groth16BackendOpts {
  /** The verifying-key JSON object (snarkjs vkey). When omitted, loads `verificationKeyPath`. */
  verificationKey?: object;
  /** Path to a `verification_key.json`; defaults to the bundled circuit fixture. */
  verificationKeyPath?: string;
}

/**
 * The REAL Groth16 `SnarkBackend`. It:
 *   (i)   rejects anything that is not a well-formed `Groth16ComplianceProof`;
 *   (ii)  requires the released-allow public signal to be 1;
 *   (iii) BINDS the proof to this action/policy/plan: the circuit's public binding tags must equal
 *         `commitmentField(publicInputs.*)` for the RS's own commitments (so a proof for other
 *         commitments is rejected);
 *   (iv)  verifies the Groth16 proof against the verifying key (real cryptographic verification).
 * It uses ONLY the commitments as public inputs — it never sees the plaintext policy or plan.
 */
export function createGroth16SnarkBackend(opts: Groth16BackendOpts = {}): SnarkBackend {
  const getVkey = lazyVkey(opts, DEFAULT_VKEY_PATH);
  return {
    async verify({ proof, publicInputs }): Promise<boolean> {
      const env = proof as Partial<Groth16ComplianceProof> | null | undefined;
      if (!env || typeof env !== 'object') return false;
      if (env.system !== 'groth16-bn254' || env.circuit !== 'pca-compliance-v1') return false;
      const ps = env.publicSignals;
      const g16 = env.proof;
      if (!Array.isArray(ps) || ps.length !== PUBLIC_SIGNAL_COUNT || g16 == null) return false;
      // (ii) the released-allow bit
      if (ps[PUBLIC_SIGNAL.allow] !== '1') return false;
      // (iii) bind the proof to THIS action/policy/plan
      if (ps[PUBLIC_SIGNAL.shaPolicy] !== commitmentField(publicInputs.policy_commit)) return false;
      if (ps[PUBLIC_SIGNAL.shaPlan] !== commitmentField(publicInputs.plan_commit)) return false;
      if (ps[PUBLIC_SIGNAL.shaAction] !== commitmentField(publicInputs.action_commit)) return false;
      // (iv) real Groth16 verification
      const groth16 = await loadGroth16();
      return await groth16.verify(await getVkey(), ps, g16);
    },
  };
}

/** The private compliance witness (never revealed by the proof) + the public commitments to bind to. */
export interface Groth16ProverInputs {
  /** Commitments the proof must bind to (b64u sha256), e.g. from the PCActn/grant. */
  action_commit: string;
  policy_commit: string;
  plan_commit: string;
  /** Private: the verb/resource the policy permits and the action takes (shared), and the plan node's verb. */
  verb: number | string | bigint;
  resource: number | string | bigint;
  planVerb: number | string | bigint;
  /** Private blinding for the three Poseidon commitments. */
  policySalt: number | string | bigint;
  planSalt: number | string | bigint;
  actionSalt: number | string | bigint;
  /** Private: the Policy VM's risk and the committed budget (integer scale; risk<=budget => allow). */
  risk: number | string | bigint;
  budget: number | string | bigint;
}

export interface Groth16ProverOpts {
  /** Path to the circuit witness calculator wasm; defaults to the bundled fixture. */
  wasmPath?: string;
  /** Path to the Groth16 proving key; defaults to the bundled fixture. */
  zkeyPath?: string;
}

/**
 * Generate a REAL Groth16 compliance proof. THROWS on a non-compliant witness (verb mismatch or
 * risk>budget): the circuit's `allow===1` becomes unsatisfiable, so — like the attested-VM prover —
 * you cannot prove a false statement. The returned proof goes in `pcactn.zk_compliance` and is
 * verified by `createGroth16SnarkBackend` via `createZkVerifier`.
 */
export async function proveGroth16Compliance(inp: Groth16ProverInputs, opts: Groth16ProverOpts = {}): Promise<Groth16ComplianceProof> {
  const input: Record<string, string> = {
    verb: String(inp.verb),
    resource: String(inp.resource),
    planVerb: String(inp.planVerb),
    policySalt: String(inp.policySalt),
    planSalt: String(inp.planSalt),
    actionSalt: String(inp.actionSalt),
    risk: String(inp.risk),
    budget: String(inp.budget),
    shaPolicy: commitmentField(inp.policy_commit),
    shaPlan: commitmentField(inp.plan_commit),
    shaAction: commitmentField(inp.action_commit),
    allow: '1',
  };
  const groth16 = await loadGroth16();
  const { proof, publicSignals } = await groth16.fullProve(input, opts.wasmPath ?? DEFAULT_WASM_PATH(), opts.zkeyPath ?? DEFAULT_ZKEY_PATH());
  return { system: 'groth16-bn254', circuit: 'pca-compliance-v1', proof, publicSignals };
}

// ===============================================================================================
// §9B — FULL Policy-VM Groth16 SNARK backend (circuits/policyvm.circom, BN254).
//
// The successor to `createGroth16SnarkBackend`. The full circuit (151,585 non-linear constraints)
// closes the two documented gaps of compliance.circom:
//   (A) the action/policy/plan commitments are computed with sha256 IN-CIRCUIT over a fixed-layout,
//       quantized struct (each field a 64-bit big-endian integer) — the digest halves it exposes are
//       PROVEN = sha256(fields), not a prover-asserted Poseidon opening. `policyVmStructHash` below
//       reproduces that serialization + digest so a caller can bind the public halves to known fields.
//   (B) the decision encodes the Policy VM itself (risk.ts / policy-vm.ts / predicates.ts), quantized
//       to fixed-point S=1e6: the risk functional + clamp + monotone floor, the threshold ladder, the
//       budget-admission cost gate, the (verb,resource) predicate allowlist + one numeric `where`
//       bound, plan membership, the six conjunctive caveats, and the attenuation-chain narrowing
//       (budget_alloc monotonicity + depth bound). `allow` is DERIVED from all of these ANDed; a deny
//       witness makes `allow===1` UNSATISFIABLE — you cannot forge an allow.
//
// HONEST SCOPE (what it still does NOT enforce — see circuits/policyvm.circom header for the full list):
//   - sha256 is over a FIXED quantized struct, not the variable-length canonical-JSON `hashCanonical`
//     produces; the circuit proves commitment == sha256(committed FIELDS), not that those fields are the
//     canonical-JSON preimage. So the public halves bind to the fixed layout, not to `actionCommitment`.
//   - predicates are a single (verb,resource) allowlist entry + one numeric `where` (lte); the full
//     predicate DSL (OR'd predicates, `*`/prefix/`re:` matching, eq/ne/in/nin/prefix/exists) is not encoded.
//   - risk magnitude inputs + context are prover-supplied witnesses, not independently attested; the HARD
//     unforgeable guarantee is the release gate (predicate AND caveats AND chain), independent of them.
//   - no Ed25519 chain-signature verification, no in-circuit plan-geodesic BFS, no rate-window filtering.
// ===============================================================================================

/** Committed Policy-VM fixtures live under circuits/ (tracked). The big proving key + ptau are
 *  gitignored; regenerate with circuits/policyvm.setup.sh. */
const policyVmCircuits = (): string => pjoin(__dirname, '..', 'circuits');
/** Default path to the full Policy-VM Groth16 verifying key (committed fixture). */
export const POLICYVM_VKEY_PATH = (): string => pjoin(policyVmCircuits(), 'policyvm_vkey.json');
/** Default path to the committed sample proof + public signals (offline test fixture). */
export const POLICYVM_SAMPLE_PROOF_PATH = (): string => pjoin(policyVmCircuits(), 'policyvm_sample_proof.json');
/** Default path to the witness-calculator wasm (gitignored; produced by setup.sh). */
export const POLICYVM_WASM_PATH = (): string => pjoin(circuitsBuild(), 'policyvm_js', 'policyvm.wasm');
/** Default path to the Policy-VM Groth16 proving key (gitignored; produced by setup.sh). */
export const POLICYVM_ZKEY_PATH = (): string => pjoin(circuitsBuild(), 'policyvm_final.zkey');
/** Default path to the full Policy-VM Groth16 verifying key on the BLS12-381 curve (committed fixture). */
export const POLICYVM_BLS12381_VKEY_PATH = (): string => pjoin(policyVmCircuits(), 'policyvm_bls12381_vkey.json');
/** Default path to the committed BLS12-381 sample proof + public signals (offline test fixture). */
export const POLICYVM_BLS12381_SAMPLE_PROOF_PATH = (): string => pjoin(policyVmCircuits(), 'policyvm_bls12381_sample_proof.json');

/**
 * Public-signal layout (snarkjs order = circuit outputs in declaration order, then the 6 public inputs).
 * Outputs [0..8]: the three sha256 struct-hash halves, the computed risk r, the threshold t, the
 * auto-admit bit. Public inputs [9..14]: the asserted allow bit + the decision context.
 */
export const POLICYVM_PUBLIC_SIGNAL = {
  actionHi: 0, actionLo: 1, policyHi: 2, policyLo: 3, planHi: 4, planLo: 5,
  r: 6, t: 7, admit: 8,
  allow: 9, now: 10, blast: 11, delegationDepth: 12, recentCount: 13, allocChild: 14,
} as const;
export const POLICYVM_PUBLIC_SIGNAL_COUNT = 15;

/** The opaque proof carried in `pcactn.zk_compliance` in full-Policy-VM mode. */
export interface PolicyVmComplianceProof {
  system: 'groth16-bn254';
  circuit: 'pca-policyvm-v1';
  /** snarkjs Groth16 proof object. */
  proof: unknown;
  /** Public signals in `POLICYVM_PUBLIC_SIGNAL` order (length `POLICYVM_PUBLIC_SIGNAL_COUNT`). */
  publicSignals: string[];
}

/**
 * The same full Policy-VM proof minted over the BLS12-381 curve (128-bit security, the end-game plan's
 * P2 curve migration). Byte-for-byte identical public signals to the BN254 proof for a given witness —
 * the fixed-point public values are all small integers that encode identically in either scalar field —
 * but the proof group elements and verifying key are BLS12-381 points. snarkjs `groth16.verify` is
 * curve-agnostic given the matching vkey, so the verify path is shared; dispatch is on the `system` tag.
 */
export interface PolicyVmComplianceProofBls12381 {
  system: 'groth16-bls12-381';
  circuit: 'pca-policyvm-v1';
  /** snarkjs Groth16 proof object (BLS12-381 group elements). */
  proof: unknown;
  /** Public signals in `POLICYVM_PUBLIC_SIGNAL` order (length `POLICYVM_PUBLIC_SIGNAL_COUNT`). */
  publicSignals: string[];
}

/** Either curve's full Policy-VM proof envelope (dispatched on the `system` tag). */
export type AnyPolicyVmComplianceProof = PolicyVmComplianceProof | PolicyVmComplianceProofBls12381;

/** A sha256 digest split into the circuit's two 128-bit big-endian halves (decimal field strings). */
export interface DigestHalves {
  hi: string;
  lo: string;
}

/**
 * Serialize fixed-layout struct fields exactly as the circuit does (each a 64-bit UNSIGNED big-endian
 * integer, concatenated), sha256 it, and split the digest into the two 128-bit halves the circuit
 * exposes (hi = top 16 bytes big-endian, lo = bottom 16 bytes). This reproduces `Sha256Struct` in
 * policyvm.circom, so a verifier can bind the proof's public hash halves to a known field layout —
 * proving sha256-in-circuit correspondence, not just trusting the prover.
 */
export function policyVmStructHash(fields: Array<number | string | bigint>): DigestHalves {
  const bytes = new Uint8Array(fields.length * 8);
  fields.forEach((f, idx) => {
    let v = BigInt(f);
    if (v < 0n || v >= 1n << 64n) throw new Error('policyVmStructHash: field out of uint64 range');
    for (let b = 7; b >= 0; b--) {
      bytes[idx * 8 + b] = Number(v & 0xffn);
      v >>= 8n;
    }
  });
  const digest = sha256(bytes);
  let hi = 0n;
  let lo = 0n;
  for (let i = 0; i < 16; i++) hi = (hi << 8n) | BigInt(digest[i]!);
  for (let i = 16; i < 32; i++) lo = (lo << 8n) | BigInt(digest[i]!);
  return { hi: hi.toString(), lo: lo.toString() };
}

/** Decode the public signals into the proven statement (hashes + risk/threshold/admit + context). */
export function decodePolicyVmPublic(publicSignals: string[]): {
  actionHash: DigestHalves; policyHash: DigestHalves; planHash: DigestHalves;
  r: string; t: string; admit: string; allow: string;
  now: string; blast: string; delegationDepth: string; recentCount: string; allocChild: string;
} {
  const P = POLICYVM_PUBLIC_SIGNAL;
  const s = (i: number) => publicSignals[i]!;
  return {
    actionHash: { hi: s(P.actionHi), lo: s(P.actionLo) },
    policyHash: { hi: s(P.policyHi), lo: s(P.policyLo) },
    planHash: { hi: s(P.planHi), lo: s(P.planLo) },
    r: s(P.r), t: s(P.t), admit: s(P.admit), allow: s(P.allow),
    now: s(P.now), blast: s(P.blast), delegationDepth: s(P.delegationDepth),
    recentCount: s(P.recentCount), allocChild: s(P.allocChild),
  };
}

export interface PolicyVmVerifyOpts {
  /** The verifying-key JSON object; when omitted, loads `verificationKeyPath`. */
  verificationKey?: object;
  /** Path to a `policyvm_vkey.json`; defaults to the committed fixture. */
  verificationKeyPath?: string;
}

/**
 * Verify a full Policy-VM Groth16 proof OFFLINE against the committed verifying key. Rejects anything
 * that is not a well-formed envelope, requires the released-allow public signal to be 1 (a deny witness
 * is unprovable anyway), then runs real snarkjs Groth16 verification. Uses ONLY the verifying key +
 * public signals — no wasm/zkey, no network. Returns false (fail-closed) on any malformed input.
 *
 * Accepts BOTH curves: a `groth16-bn254` envelope (the back-compat default) and a `groth16-bls12-381`
 * envelope (the 128-bit P2 curve). Dispatch is on the proof's `system` tag; when no explicit vkey is
 * supplied the default fixture is selected per curve (the BLS12-381 vkey for a BLS proof). snarkjs's
 * `groth16.verify` is curve-agnostic given the matching vkey, so the verification itself is shared.
 */
export async function verifyPolicyVmProof(env: unknown, opts: PolicyVmVerifyOpts = {}): Promise<boolean> {
  const p = env as Partial<AnyPolicyVmComplianceProof> | null | undefined;
  if (!p || typeof p !== 'object') return false;
  if (p.circuit !== 'pca-policyvm-v1') return false;
  const isBls = p.system === 'groth16-bls12-381';
  if (p.system !== 'groth16-bn254' && !isBls) return false;
  const ps = p.publicSignals;
  if (!Array.isArray(ps) || ps.length !== POLICYVM_PUBLIC_SIGNAL_COUNT || p.proof == null) return false;
  if (ps[POLICYVM_PUBLIC_SIGNAL.allow] !== '1') return false;
  const defaultVkeyPath = isBls ? POLICYVM_BLS12381_VKEY_PATH : POLICYVM_VKEY_PATH;
  const vkey: object = opts.verificationKey ?? (await readJsonFile(opts.verificationKeyPath ?? defaultVkeyPath()));
  try {
    const groth16 = await loadGroth16();
    return await groth16.verify(vkey, ps, p.proof);
  } catch {
    return false;
  }
}

export interface PolicyVmBackendOpts extends PolicyVmVerifyOpts {
  /**
   * Optional in-circuit struct-hash binding. When set, the proof's public hash halves must equal these
   * — the RS recomputes them with `policyVmStructHash` over the fixed-layout fields it expects. This is
   * the full circuit's binding (sha256-of-fixed-struct), distinct from the canonical-JSON commitments
   * `createZkVerifier` carries, so these are supplied directly rather than via `publicInputs`.
   */
  expectActionHash?: DigestHalves;
  expectPolicyHash?: DigestHalves;
  expectPlanHash?: DigestHalves;
}

/** Two 128-bit halves at `hiIdx`/`loIdx` match the expected digest (or no expectation was set). */
function policyVmHalvesMatch(ps: string[], hiIdx: number, loIdx: number, want?: DigestHalves): boolean {
  return !want || (ps[hiIdx] === want.hi && ps[loIdx] === want.lo);
}

/** Shared struct-hash binding over the proof's public signals (used by both curve backends). */
function policyVmStructHashesMatch(ps: string[] | undefined, opts: PolicyVmBackendOpts): boolean {
  if (!Array.isArray(ps)) return true;
  const P = POLICYVM_PUBLIC_SIGNAL;
  return (
    policyVmHalvesMatch(ps, P.actionHi, P.actionLo, opts.expectActionHash) &&
    policyVmHalvesMatch(ps, P.policyHi, P.policyLo, opts.expectPolicyHash) &&
    policyVmHalvesMatch(ps, P.planHi, P.planLo, opts.expectPlanHash)
  );
}

/**
 * A `SnarkBackend` over the full Policy-VM circuit. It verifies the real Groth16 proof + allow==1, and,
 * when expected struct hashes are supplied, binds the proof's public hash halves to them. It does NOT
 * bind the canonical-JSON `publicInputs` (`action_commit`/…) — the circuit's commitments are sha256 of a
 * fixed-layout struct, a different preimage (documented gap); pass `expect*Hash` to bind instead.
 */
export function createPolicyVmSnarkBackend(opts: PolicyVmBackendOpts = {}): SnarkBackend {
  const getVkey = lazyVkey(opts, POLICYVM_VKEY_PATH);
  return {
    async verify({ proof }): Promise<boolean> {
      const env = proof as Partial<PolicyVmComplianceProof> | null | undefined;
      if (!policyVmStructHashesMatch(env?.publicSignals, opts)) return false;
      return verifyPolicyVmProof(env, { verificationKey: await getVkey() });
    },
  };
}

/**
 * The BLS12-381 (128-bit) counterpart of `createPolicyVmSnarkBackend`. Identical binding + verification
 * logic — it only defaults the verifying key to the committed BLS12-381 fixture and (via the shared
 * `verifyPolicyVmProof`) accepts the `groth16-bls12-381` envelope. The BN254 backend is unaffected.
 */
export function createPolicyVmSnarkBackendBls12381(opts: PolicyVmBackendOpts = {}): SnarkBackend {
  const getVkey = lazyVkey(opts, POLICYVM_BLS12381_VKEY_PATH);
  return {
    async verify({ proof }): Promise<boolean> {
      const env = proof as Partial<PolicyVmComplianceProofBls12381> | null | undefined;
      if (!policyVmStructHashesMatch(env?.publicSignals, opts)) return false;
      return verifyPolicyVmProof(env, { verificationKey: await getVkey() });
    },
  };
}

export interface PolicyVmProverOpts {
  /** Path to the witness-calculator wasm; defaults to the gitignored fixture (produced by setup.sh). */
  wasmPath?: string;
  /** Path to the Groth16 proving key; defaults to the gitignored fixture (produced by setup.sh). */
  zkeyPath?: string;
}

/**
 * Generate a REAL full-Policy-VM Groth16 proof from the complete fixed-point witness (all circuit
 * inputs, including the division witnesses rQ/rRem/costQ/costRem). THROWS on a non-compliant witness —
 * the circuit's `allow===1` becomes unsatisfiable, so you cannot prove a denied action. Requires the
 * proving key + wasm under circuits/build (regenerate with circuits/policyvm.setup.sh); the committed
 * verifying key + sample proof are sufficient to VERIFY offline without them.
 */
export async function provePolicyVmCompliance(
  witness: Record<string, number | string | bigint>,
  opts: PolicyVmProverOpts = {},
): Promise<PolicyVmComplianceProof> {
  const input: Record<string, string> = {};
  for (const [k, v] of Object.entries(witness)) input[k] = String(v);
  const groth16 = await loadGroth16();
  const { proof, publicSignals } = await groth16.fullProve(input, opts.wasmPath ?? POLICYVM_WASM_PATH(), opts.zkeyPath ?? POLICYVM_ZKEY_PATH());
  return { system: 'groth16-bn254', circuit: 'pca-policyvm-v1', proof, publicSignals };
}
