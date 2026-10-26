import { snapshotConfig } from './config-snapshot';
import { ceremonyOf, type CeremonyTranscript } from './zk-ceremony';
import { type AssuranceLabel, type ZkSystem, assuranceLabelOf, setAssuranceLabel } from './assurance';
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
import type { AttestationDocument, ExpectedAttestationBinding, HardwareAttestationVerifier } from './attestation';

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
/**
 * Assurance (0.5): a backend declares its proof system with `setAssuranceLabel(backend, { level: <ZkSystem> })`; the
 * library's own backends do. `createZkVerifier` reports that system on a pass (an unlabelled backend is `unknown`).
 */
export interface SnarkBackend {
  verify(input: {
    /** The opaque proof carried in `pcactn.zk_compliance`. */
    proof: unknown;
    publicInputs: { action_commit: string; policy_commit: string; plan_commit: string };
    ctx: VerifyContext;
  }): boolean | Promise<boolean>;
}

/** `grantRef` of the binding a prover VM's hardware quote carries (see {@link proverKeyBinding}). */
export const ZK_PROVER_BINDING_REF = 'atlas-pca/zk-prover/v1';

/**
 * The value the prover VM must put in its hardware quote's report_data so that the quote vouches for ITS key:
 * `attestationBinding(proverKeyBinding(proverPublicKey, epoch, nonce))`. A quote taken for another key, epoch or nonce
 * does not bind.
 */
export function proverKeyBinding(proverPublicKey: string, epoch: number, nonce: string): ExpectedAttestationBinding {
  return { holderPub: proverPublicKey, grantRef: ZK_PROVER_BINDING_REF, epoch, nonce };
}

/** Binds the attested-VM prover key to hardware evidence of the VM measurement. */
export interface ProverAttestationOpts {
  /**
   * A vendor verifier (SEV-SNP, TDX, Azure MAA, ...) or a multi-root verifier. It MUST carry a `hardware` or
   * `multi_root` assurance label: a software or unlabelled verifier is refused at construction. Its evidence resolver
   * receives a stub document whose `attestor` is the prover's public key, so it can look up that prover's quote.
   */
  hardwareVerifier: HardwareAttestationVerifier;
  /** The binding the quote must carry for this prover key (server-known epoch and nonce). Throwing denies. */
  expectedBinding(proverPublicKey: string): ExpectedAttestationBinding | Promise<ExpectedAttestationBinding>;
  /** REQUIRED, non-empty: accepted measured runtime measurements (the VM image). Accept-all is not permitted. */
  measurements: string[];
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
  /**
   * Prover keys that are no longer trusted (a retired or compromised prover VM). A statement signed by one is denied
   * even when the key is still listed in `trustedProverKeys`. Rotation = add the new key to `trustedProverKeys`, put
   * the old one here, then drop it from `trustedProverKeys` once its statements have expired.
   */
  revokedProverKeys?: string[];
  /**
   * ATTESTED-VM, HARDWARE-BOUND (0.5): require hardware evidence that the prover key lives in an attested VM with an
   * allowlisted measurement, instead of trusting the key alone. See {@link ProverAttestationOpts}. Attested-VM mode only
   * (ignored with `snarkBackend`). Absent => the prover key is trusted as configured, and the assurance label says so.
   */
  proverAttestation?: ProverAttestationOpts;
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
  opts = snapshotConfig(opts, { keep: ['snarkBackend', 'proverAttestation'] }); // freeze the configuration: later edits by the caller must not change what this verifier enforces
  // Assurance label (0.5) from the configuration: attested-VM mode is a signed statement, not a proof; SNARK mode is the
  // backend's declared system (`unknown` when it declares none).
  const pa = opts.snarkBackend ? undefined : opts.proverAttestation;
  if (pa !== undefined) {
    const hw = assuranceLabelOf(pa.hardwareVerifier);
    if (hw?.level !== 'hardware' && hw?.level !== 'multi_root') throw new TypeError('createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label');
    if (!Array.isArray(pa.measurements) || pa.measurements.length === 0 || pa.measurements.some((m) => typeof m !== 'string' || m === '')) throw new TypeError('createZkVerifier: proverAttestation.measurements must be a non-empty allowlist');
    if (typeof pa.expectedBinding !== 'function') throw new TypeError('createZkVerifier: proverAttestation.expectedBinding must be a function');
  }
  const hwLabel = pa ? assuranceLabelOf(pa.hardwareVerifier) : undefined;
  const label: AssuranceLabel = opts.snarkBackend
    ? (assuranceLabelOf(opts.snarkBackend) ?? { level: 'unknown' satisfies ZkSystem })
    : hwLabel
      ? { level: 'attested_vm_hw' satisfies ZkSystem, vendor: `hardware-bound:${hwLabel.vendor ?? hwLabel.level}` }
      : { level: 'attested_vm' satisfies ZkSystem };
  return setAssuranceLabel(zkHook(opts), label);
}

function zkHook(opts: ZkVerifierOpts): ZkVerifier {

  const trusted = new Set(Array.isArray(opts.trustedProverKeys) ? opts.trustedProverKeys : []);
  const revoked = new Set(Array.isArray(opts.revokedProverKeys) ? opts.revokedProverKeys : []);
  const pa = opts.snarkBackend ? undefined : opts.proverAttestation;
  const paMeasurements = pa ? new Set(pa.measurements) : undefined;
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
      if (revoked.has(st.prover)) return fail('prover key is revoked');

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

      // hardware binding of the prover key (last: it is the expensive check). Every outcome other than a bound,
      // measured, allowlisted identity denies.
      if (pa && paMeasurements) {
        const expected = await pa.expectedBinding(st.prover);
        const hw = await pa.hardwareVerifier.verify({ document: { attestor: st.prover, mode: 'hardware' } as unknown as AttestationDocument, ctx, nowMs, expected });
        if (!hw || hw.ok !== true) return fail(`prover hardware evidence invalid: ${hw ? (hw.reason ?? 'no reason given') : 'no result'}`);
        if (hw.bound !== true) return fail('prover hardware evidence does not bind the prover key');
        if (!hw.measured || typeof hw.measured.runtime_measurement !== 'string') return fail('prover hardware evidence carries no measured identity');
        if (!paMeasurements.has(hw.measured.runtime_measurement)) return fail('prover VM measurement is not allowlisted');
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
 *
 * R6-ALIAS-08 proof note (why reducing 256 bits into r ~ 2^253.6 still binds). Let r be the BN254 scalar modulus
 * (log2 r = 253.597) and f(c) = c mod r for a 256-bit commitment c. Since 2^256 = 5r + e with 0 < e < r, every
 * residue has exactly 5 or 6 preimages in [0, 2^256): f is at most 6-to-1, and two commitments share a tag iff they
 * differ by a multiple k*r with |k| <= 5. The commitments are SHA-256 outputs over canonical JSON (modelled as a
 * random oracle H), and the tag is T = f(H(m)). Then:
 *   - second preimage (a proof for the RS's own commitment H(m) reused for a different m'): each query hits one of
 *     at most 6 target values, so success after q queries is <= 6q / 2^256, i.e. ~2^253.4 work;
 *   - collision (the attacker authors both documents): f o H is a random function into r values, so the birthday
 *     bound is ~sqrt(pi r / 2) = 2^127.1 evaluations, against 2^128 for SHA-256 alone (a ~0.9-bit loss).
 * Both exceed the security of the Groth16/BN254 proof the tag sits in (BN254 pairings are estimated at ~100-110
 * bits after exTNFS), so the reduction is not the weakest link. Widening the tag to two field elements would need a
 * circuit change and a new trusted setup; it is not done. The 6-to-1 multiplicity is pinned in zk-binding-tag.test.ts.
 */
export function commitmentField(b64uCommit: string): string {
  const bytes = unb64u(b64uCommit);
  let acc = 0n;
  for (const byte of bytes) acc = (acc << 8n) | BigInt(byte);
  return (acc % BN254_FR).toString();
}

// ---- strict canonical Groth16 envelope gate ----------------------------------------------------------------
// snarkjs's verifier reduces every coordinate / public signal mod the field with `BigInt(...)`-style parsing, so a
// valid proof also verified with x+p, leading zeros, a `0x` hex form, an unreduced projective z or extra keys:
// the same proof had many accepted encodings (different `hashCanonical` of the carrying envelope). This gate
// accepts exactly the one canonical shape snarkjs emits and nothing else.

const BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BLS12381_FQ = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;
const BLS12381_FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
const CANON_DEC = /^(0|[1-9][0-9]*)$/;

function canonDecBelow(v: unknown, bound: bigint): boolean {
  return typeof v === 'string' && v.length <= 120 && CANON_DEC.test(v) && BigInt(v) < bound;
}
function sameKeys(o: object, keys: string[]): boolean {
  const k = Object.keys(o).sort();
  return k.length === keys.length && keys.slice().sort().every((x, i) => x === k[i]);
}

/** True iff `env` is exactly one canonical Groth16 envelope for `curve` (strings canonical decimals < field, z == 1). */
export function isCanonicalGroth16Envelope(env: unknown, curve: 'bn254' | 'bls12-381'): boolean {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return false;
  const e = env as { proof?: unknown; publicSignals?: unknown };
  if (!sameKeys(env, ['system', 'circuit', 'proof', 'publicSignals'])) return false;
  const fq = curve === 'bn254' ? BN254_FQ : BLS12381_FQ;
  const fr = curve === 'bn254' ? BN254_FR : BLS12381_FR;
  if (!Array.isArray(e.publicSignals) || !e.publicSignals.every((x) => canonDecBelow(x, fr))) return false;
  const pr = e.proof as { pi_a?: unknown; pi_b?: unknown; pi_c?: unknown; protocol?: unknown; curve?: unknown } | null;
  if (!pr || typeof pr !== 'object' || Array.isArray(pr)) return false;
  if (!sameKeys(pr, ['pi_a', 'pi_b', 'pi_c', 'protocol', 'curve'])) return false;
  if (pr.protocol !== 'groth16' || pr.curve !== (curve === 'bn254' ? 'bn128' : 'bls12381')) return false;
  const g1 = (a: unknown): boolean =>
    Array.isArray(a) && a.length === 3 && canonDecBelow(a[0], fq) && canonDecBelow(a[1], fq) && a[2] === '1';
  if (!g1(pr.pi_a) || !g1(pr.pi_c)) return false;
  const b = pr.pi_b;
  if (!Array.isArray(b) || b.length !== 3) return false;
  for (const row of [b[0], b[1]]) {
    if (!Array.isArray(row) || row.length !== 2 || !canonDecBelow(row[0], fq) || !canonDecBelow(row[1], fq)) return false;
  }
  return Array.isArray(b[2]) && b[2].length === 2 && b[2][0] === '1' && b[2][1] === '0';
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

/** Evidence that a verifying key came from a multi-party ceremony: the published transcript and its pinned SHA-256. */
export interface CeremonyEvidence {
  transcript: CeremonyTranscript;
  /** SHA-256 (hex) of the canonical transcript, published out of band by the coordinator. */
  sha256: string;
}

/** `multi-party` only for an explicit verifying key backed by pinned ceremony evidence; the bundled fixtures are single-party. */
function ceremonyLabel(opts: { verificationKey?: object; ceremony?: CeremonyEvidence }, circuit: string): 'single-party' | 'multi-party' {
  return ceremonyOf(opts.verificationKey, opts.ceremony && { ...opts.ceremony, circuit });
}

export interface Groth16BackendOpts {
  /** Ceremony evidence for `verificationKey`; without it the backend reports `ceremony: single-party`. */
  ceremony?: CeremonyEvidence;
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
  return setAssuranceLabel<SnarkBackend>({
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
      // (iv) real Groth16 verification, only over the ONE canonical encoding of the envelope
      if (!isCanonicalGroth16Envelope(env, 'bn254')) return false;
      const groth16 = await loadGroth16();
      return await groth16.verify(await getVkey(), ps, g16);
    },
  }, { level: 'groth16' satisfies ZkSystem, ceremony: ceremonyLabel(opts, 'pca-compliance-v1') });
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

// ===============================================================================================
// §9B — DETERMINISTIC action→quantized-struct binding (closes the proof↔action BINDING gap).
//
// The Policy-VM circuit hashes a FIXED, QUANTIZED struct (each field a 64-bit big-endian uint), NOT the
// canonical-JSON `actionCommitment`/`hashCanonical`. So `policyVmStructHash` alone can only bind a proof to
// hand-fed struct fields — nothing tied those fields to the SPECIFIC PCActn being adjudicated, which let a
// valid proof be replayed for a DIFFERENT action. This block closes that: it deterministically derives the
// circuit's quantized struct FROM the live canonical action (mirroring the prover's quantization), so an RS
// can require the proof's public hash halves to equal `policyVmStructHash(quantize(action))` and thereby
// bind proof↔action transitively (action → deterministic quantized struct → proof public input).
//
// HONEST SCOPE. This binds proof↔action via the deterministic quantization map below, collision-safe over
// the bound quantized fields (verb/resource code, reversibility-class index, param scalar). It is NOT
// sha256-over-canonical-JSON IN-CIRCUIT: the circuit proves `commitment == sha256(committed FIELDS)`, and
// this map reproduces those FIELDS byte-identically — it does not prove the quantized fields ARE the
// canonical-JSON preimage of `actionCommitment`. Proving that (sha256 over the full variable-length
// canonical JSON, inside the VM) remains the heavier zkVM / RISC-Zero gold path — a future enhancement,
// not claimed here.
// ===============================================================================================

/**
 * The reversibility-class ordering the circuit's `reversibility` field (action struct [2]) and `revMax`
 * caveat encode: reversible=0, rate_limited=1, irreversible=2. Mirrors predicates.ts `REVERSIBILITY_ORDER`
 * exactly, so the index the RS quantizes equals the class index the circuit/caveat compares against.
 */
export const POLICYVM_REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'] as const;
export type PolicyVmReversibilityClass = (typeof POLICYVM_REVERSIBILITY_ORDER)[number];

/** An omitted action reversibility class commits/quantizes as this default (mirrors DEFAULT_REVERSIBILITY_CLASS). */
const QUANTIZE_DEFAULT_REVERSIBILITY: PolicyVmReversibilityClass = 'reversible';

/** Exclusive upper bound of the circuit's per-field uint64 domain (each struct field is 8 big-endian bytes). */
const POLICYVM_U64_MAX = (1n << 64n) - 1n;

/** The live canonical ACTION fields the quantization reads (verb/resource strings, class, params plaintext). */
export interface QuantizableAction {
  verb: string;
  resource: string;
  reversibility_class?: string;
  /** Action params plaintext; the numeric `where`-bound scalar is read from `paramScalarField`. */
  params?: Record<string, unknown>;
}

/**
 * How the RS maps the live verb/resource strings to the circuit's uint64 codes. This MUST equal the map the
 * prover used to build the witness, or the recomputed struct hash will not match (fail-closed).
 */
export interface PolicyVmQuantizeOpts {
  /** Explicit verb-string → uint64 code (the shared catalog). A verb absent here is content-addressed
   *  unless `strictCatalog` is set. */
  verbCodes?: Readonly<Record<string, number | bigint>>;
  /** Explicit resource-string → uint64 code. */
  resourceCodes?: Readonly<Record<string, number | bigint>>;
  /** Require every verb/resource to be present in the explicit maps; a miss FAILS CLOSED (throws). Default
   *  false: a miss is content-addressed (sha256-truncated uint64 — deterministic, needs no shared catalog). */
  strictCatalog?: boolean;
  /** The action param whose non-negative-integer value is the circuit `paramScalar` (the `where` subject).
   *  Absent field → scalar 0. A present value that is not a uint64 non-negative integer FAILS CLOSED. */
  paramScalarField?: string;
}

/** uint64 content-address of a domain-tagged string: the top 8 bytes of sha256, big-endian. Total + deterministic. */
function contentAddressU64(domain: string, value: string): bigint {
  const digest = sha256(utf8(`atlas-pca/policyvm-quantize/${domain}:${value}`));
  let acc = 0n;
  for (let i = 0; i < 8; i++) acc = (acc << 8n) | BigInt(digest[i]!);
  return acc; // in [0, 2^64)
}

/** Coerce an explicit code / numeric field to a uint64 bigint, or FAIL CLOSED (throws) when out of domain. */
function toU64(v: number | bigint, what: string): bigint {
  const b = typeof v === 'bigint' ? v : Number.isInteger(v) ? BigInt(v) : undefined;
  if (b === undefined || b < 0n || b > POLICYVM_U64_MAX) throw new Error(`policyvm quantize: ${what} is not a uint64`);
  return b;
}

/** Map a verb/resource string to its circuit uint64 code (explicit catalog, else content-addressed). */
function codeFor(domain: 'verb' | 'resource', value: string, map: Readonly<Record<string, number | bigint>> | undefined, strict: boolean): bigint {
  if (typeof value !== 'string') throw new Error(`policyvm quantize: ${domain} must be a string`);
  if (map && Object.prototype.hasOwnProperty.call(map, value)) return toU64(map[value]!, `${domain} code`);
  if (strict) throw new Error(`policyvm quantize: ${domain} "${value}" is not in the catalog (strict)`);
  return contentAddressU64(domain, value);
}

/** Read the uint64 param scalar from the action params (0 when the field is unset; FAIL CLOSED otherwise). */
function paramScalarFrom(params: Record<string, unknown> | undefined, field: string | undefined): bigint {
  if (!field) return 0n;
  const v = params ? params[field] : undefined;
  if (v === undefined || v === null) return 0n;
  if (typeof v === 'bigint') return toU64(v, 'paramScalar');
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) throw new Error('policyvm quantize: paramScalar must be a non-negative integer');
    return toU64(v, 'paramScalar');
  }
  if (typeof v === 'string' && /^\d+$/.test(v)) return toU64(BigInt(v), 'paramScalar');
  throw new Error('policyvm quantize: paramScalar is not a non-negative integer');
}

/** Map a reversibility-class string to its circuit index, or FAIL CLOSED on an unknown class. */
function reversibilityIndex(rc: string, what: string): bigint {
  const idx = (POLICYVM_REVERSIBILITY_ORDER as readonly string[]).indexOf(rc);
  if (idx < 0) throw new Error(`policyvm quantize: unknown ${what} class "${rc}"`);
  return BigInt(idx);
}

/**
 * Deterministically quantize the live canonical ACTION to the circuit's fixed 4-field struct:
 *   [0] verb code  [1] resource code  [2] reversibility-class index  [3] param scalar.
 * THROWS (fail-closed) on anything that cannot be quantized: a non-string verb/resource, an unknown
 * reversibility class, a strict-catalog miss, or a param scalar outside the uint64 non-negative range.
 */
export function quantizeActionStruct(action: QuantizableAction, opts: PolicyVmQuantizeOpts = {}): [bigint, bigint, bigint, bigint] {
  if (!action || typeof action !== 'object') throw new Error('policyvm quantize: action is missing');
  const strict = opts.strictCatalog === true;
  const verb = codeFor('verb', action.verb, opts.verbCodes, strict);
  const resource = codeFor('resource', action.resource, opts.resourceCodes, strict);
  const rev = reversibilityIndex(action.reversibility_class ?? QUANTIZE_DEFAULT_REVERSIBILITY, 'reversibility');
  const paramScalar = paramScalarFrom(action.params, opts.paramScalarField);
  return [verb, resource, rev, paramScalar];
}

/** The live PLAN-node fields the plan struct commits: [planVerb, planResource, semanticDist, planSalt].
 *  `semanticDist` (quantized geodesic in [0,S]) and the hiding `planSalt` are prover-side — the RS does not
 *  hold the salt — so plan quantization is for provers / non-hiding deployments; an RS binds the ACTION. */
export interface QuantizablePlan {
  verb: string;
  resource: string;
  semanticDist: number | bigint;
  planSalt: number | bigint;
}

/** The POLICY fields laid out as the circuit's 20-field struct. Weights/thresholds/bounds are the policy's
 *  OWN quantized integers (scale S); verb/resource map via the shared code map and `revMax` via the order. */
export interface QuantizablePolicy {
  weights: { alpha: number | bigint; beta: number | bigint; gamma: number | bigint; delta: number | bigint; epsilon: number | bigint; zeta: number | bigint };
  theta1: number | bigint;
  theta2: number | bigint;
  kappa: number | bigint;
  budgetB: number | bigint;
  policyVerb: string;
  policyResource: string;
  policyParamBound: number | bigint;
  expiresAt: number | bigint;
  notBefore: number | bigint;
  maxBlast: number | bigint;
  maxDepth: number | bigint;
  revMax: string;
  rateMax: number | bigint;
  allocParent: number | bigint;
}

/** The quantized struct field arrays (bigint, uint64 domain) ready for `policyVmStructHash`. */
export interface PolicyVmQuantizedStructs {
  action: [bigint, bigint, bigint, bigint];
  plan?: [bigint, bigint, bigint, bigint];
  policy?: bigint[];
}

/** Quantize the plan node to the circuit's 4-field plan struct (FAIL CLOSED on out-of-domain fields). */
export function quantizePlanStruct(plan: QuantizablePlan, opts: PolicyVmQuantizeOpts = {}): [bigint, bigint, bigint, bigint] {
  const strict = opts.strictCatalog === true;
  return [
    codeFor('verb', plan.verb, opts.verbCodes, strict),
    codeFor('resource', plan.resource, opts.resourceCodes, strict),
    toU64(plan.semanticDist, 'semanticDist'),
    toU64(plan.planSalt, 'planSalt'),
  ];
}

/** Quantize the policy to the circuit's 20-field policy struct (FAIL CLOSED on out-of-domain fields / unknown revMax). */
export function quantizePolicyStruct(policy: QuantizablePolicy, opts: PolicyVmQuantizeOpts = {}): bigint[] {
  const strict = opts.strictCatalog === true;
  const w = policy.weights;
  return [
    toU64(w.alpha, 'wAlpha'),
    toU64(w.beta, 'wBeta'),
    toU64(w.gamma, 'wGamma'),
    toU64(w.delta, 'wDelta'),
    toU64(w.epsilon, 'wEpsilon'),
    toU64(w.zeta, 'wZeta'),
    toU64(policy.theta1, 'theta1'),
    toU64(policy.theta2, 'theta2'),
    toU64(policy.kappa, 'kappa'),
    toU64(policy.budgetB, 'budgetB'),
    codeFor('verb', policy.policyVerb, opts.verbCodes, strict),
    codeFor('resource', policy.policyResource, opts.resourceCodes, strict),
    toU64(policy.policyParamBound, 'policyParamBound'),
    toU64(policy.expiresAt, 'expiresAt'),
    toU64(policy.notBefore, 'notBefore'),
    toU64(policy.maxBlast, 'maxBlast'),
    toU64(policy.maxDepth, 'maxDepth'),
    reversibilityIndex(policy.revMax, 'revMax'),
    toU64(policy.rateMax, 'rateMax'),
    toU64(policy.allocParent, 'allocParent'),
  ];
}

/**
 * The umbrella quantization: derive the circuit's fixed action struct (always) and, when their inputs are
 * supplied, the plan + policy structs — the exact fixed layout `policyvm.circom`'s `Sha256Struct` hashes.
 * Deterministic and fail-closed (throws on any field that cannot be quantized).
 */
export function quantizePolicyVmInputs(
  inp: { action: QuantizableAction; plan?: QuantizablePlan; policy?: QuantizablePolicy },
  opts: PolicyVmQuantizeOpts = {},
): PolicyVmQuantizedStructs {
  return {
    action: quantizeActionStruct(inp.action, opts),
    ...(inp.plan ? { plan: quantizePlanStruct(inp.plan, opts) } : {}),
    ...(inp.policy ? { policy: quantizePolicyStruct(inp.policy, opts) } : {}),
  };
}

/**
 * The circuit's ACTION commitment (its two public hash halves `actionHi`/`actionLo`) recomputed from the
 * LIVE canonical action: `policyVmStructHash(quantizeActionStruct(action))`. An RS binds a Policy-VM proof
 * to THIS action by requiring the proof's `actionHi`/`actionLo` public signals to equal these halves — so a
 * proof minted for action A, presented for action B, mismatches and is rejected. FAIL CLOSED: propagates
 * the quantization throw when the live action cannot be deterministically quantized.
 */
export function policyVmCommitmentFromAction(action: QuantizableAction, opts: PolicyVmQuantizeOpts = {}): DigestHalves {
  return policyVmStructHash(quantizeActionStruct(action, opts));
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

/**
 * A pin on one public signal: an exact value (decimal string / number / bigint), or an inclusive
 * `{ min, max }` window (e.g. `now` within the verifier clock's skew).
 */
export type PolicyVmSignalPin = bigint | number | string | { min: bigint | number | string; max: bigint | number | string };

/**
 * RT-07: the context the verifier REQUIRES the proof to have been made for. The circuit evaluates its
 * caveats (`expires`, `not_before`, rate, blast radius, delegation depth, budget allocation) on
 * prover-supplied public inputs; without a pin, a valid proof only says "the gate passes for SOME now /
 * recentCount / ...". Every field is optional (unset = not pinned), but a verifier that serves real
 * traffic should pin at least `now` and `recentCount`, and set `requireAdmit` and `requireTier1`.
 */
export interface PolicyVmExpect {
  /** The verifier's clock in the circuit's `now` units, exact or as a window. */
  now?: PolicyVmSignalPin;
  blast?: PolicyVmSignalPin;
  delegationDepth?: PolicyVmSignalPin;
  /** Recent-action count from the verifier's own ledger. */
  recentCount?: PolicyVmSignalPin;
  allocChild?: PolicyVmSignalPin;
  /** Proven risk `r` (scaled). */
  r?: PolicyVmSignalPin;
  /** Threshold tier `t` (1 = release). */
  t?: PolicyVmSignalPin;
  /** Require the auto-admit output bit to be 1. */
  requireAdmit?: boolean;
  /** Require the threshold tier `t` to be 1 (the lowest-risk release tier). */
  requireTier1?: boolean;
}

/** A fixed expectation, or a function evaluated at each verification (so `now` can track a live clock). */
export type PolicyVmExpectSource = PolicyVmExpect | (() => PolicyVmExpect);

export interface PolicyVmVerifyOpts {
  /** The verifying-key JSON object; when omitted, loads `verificationKeyPath`. */
  verificationKey?: object;
  /** Path to a `policyvm_vkey.json`; defaults to the committed fixture. */
  verificationKeyPath?: string;
  /** RT-07: pin the public context signals; any mismatch makes verification return false. */
  expect?: PolicyVmExpectSource;
}

const POLICYVM_CONTEXT_BOUND = 1n << 64n;

function pinBigint(v: bigint | number | string): bigint | undefined {
  try {
    if (typeof v === 'number' && !Number.isSafeInteger(v)) return undefined;
    return BigInt(v);
  } catch {
    return undefined;
  }
}

function signalMatchesPin(signal: string | undefined, pin: PolicyVmSignalPin): boolean {
  if (signal === undefined || !/^(0|[1-9][0-9]*)$/.test(signal)) return false;
  const x = BigInt(signal);
  if (typeof pin === 'object') {
    const lo = pinBigint(pin.min);
    const hi = pinBigint(pin.max);
    return lo !== undefined && hi !== undefined && lo <= hi && x >= lo && x <= hi;
  }
  const want = pinBigint(pin);
  return want !== undefined && x === want;
}

/**
 * Do the proof's public signals satisfy `expect`? Also rejects (even with no pins) a context signal that
 * is not a canonical decimal below 2^64: the circuit's comparators run on un-range-checked public
 * inputs, so a field-negative `now` (p - k) would otherwise satisfy `now < expiresAt`.
 */
export function policyVmContextMatches(ps: string[], expectSrc?: PolicyVmExpectSource): boolean {
  const P = POLICYVM_PUBLIC_SIGNAL;
  for (const idx of [P.now, P.blast, P.delegationDepth, P.recentCount, P.allocChild]) {
    const sig = ps[idx];
    if (typeof sig !== 'string' || !/^(0|[1-9][0-9]*)$/.test(sig) || BigInt(sig) >= POLICYVM_CONTEXT_BOUND) return false;
  }
  if (expectSrc === undefined) return true;
  let e: PolicyVmExpect;
  try {
    e = typeof expectSrc === 'function' ? expectSrc() : expectSrc;
  } catch {
    return false;
  }
  if (e === null || typeof e !== 'object') return false;
  const pins: Array<[keyof PolicyVmExpect, number]> = [
    ['now', P.now], ['blast', P.blast], ['delegationDepth', P.delegationDepth],
    ['recentCount', P.recentCount], ['allocChild', P.allocChild], ['r', P.r], ['t', P.t],
  ];
  for (const [k, idx] of pins) {
    const pin = e[k] as PolicyVmSignalPin | undefined;
    if (pin !== undefined && !signalMatchesPin(ps[idx], pin)) return false;
  }
  if (e.requireAdmit && ps[P.admit] !== '1') return false;
  if (e.requireTier1 && ps[P.t] !== '1') return false;
  return true;
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
  if (!isCanonicalGroth16Envelope(p, isBls ? 'bls12-381' : 'bn254')) return false;
  if (!policyVmContextMatches(ps, opts.expect)) return false;
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
  /** Ceremony evidence for `verificationKey`; without it the backend reports `ceremony: single-party`. */
  ceremony?: CeremonyEvidence;
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

/**
 * Assurance label of a Policy-VM backend: `policyvm_snark` only when the proof is bound to this action, policy and plan
 * (all three `expect*Hash`); without them a valid proof may be for another compliant action, so the label is `unknown`.
 */
function policyVmLabel(opts: PolicyVmBackendOpts): AssuranceLabel {
  const ceremony = ceremonyLabel(opts, 'pca-policyvm-v1');
  return opts.expectActionHash && opts.expectPolicyHash && opts.expectPlanHash ? { level: 'policyvm_snark' satisfies ZkSystem, ceremony } : { level: 'unknown' satisfies ZkSystem, vendor: 'policyvm-unbound', ceremony };
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
  return setAssuranceLabel<SnarkBackend>({
    async verify({ proof }): Promise<boolean> {
      const env = proof as Partial<PolicyVmComplianceProof> | null | undefined;
      if (!policyVmStructHashesMatch(env?.publicSignals, opts)) return false;
      return verifyPolicyVmProof(env, { verificationKey: await getVkey(), expect: opts.expect });
    },
  }, policyVmLabel(opts));
}

/**
 * The BLS12-381 (128-bit) counterpart of `createPolicyVmSnarkBackend`. Identical binding + verification
 * logic — it only defaults the verifying key to the committed BLS12-381 fixture and (via the shared
 * `verifyPolicyVmProof`) accepts the `groth16-bls12-381` envelope. The BN254 backend is unaffected.
 */
export function createPolicyVmSnarkBackendBls12381(opts: PolicyVmBackendOpts = {}): SnarkBackend {
  const getVkey = lazyVkey(opts, POLICYVM_BLS12381_VKEY_PATH);
  return setAssuranceLabel<SnarkBackend>({
    async verify({ proof }): Promise<boolean> {
      const env = proof as Partial<PolicyVmComplianceProofBls12381> | null | undefined;
      if (!policyVmStructHashesMatch(env?.publicSignals, opts)) return false;
      return verifyPolicyVmProof(env, { verificationKey: await getVkey(), expect: opts.expect });
    },
  }, policyVmLabel(opts));
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
