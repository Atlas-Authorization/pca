/**
 * L0 SOFTWARE/HSM backend — the POST-QUANTUM attestation root.
 *
 * The genuinely post-quantum root for the multi-root N-of-M policy in `attestation.ts`. Where the AMD
 * SEV-SNP (`hardware-sevsnp.ts`), Intel TDX (`attest-intel-tdx.ts`) and NVIDIA GPU-CC (`attest-nvidia-cc.ts`)
 * roots are CLASSICAL (their silicon vendors sign with ECDSA today), this root is a software/HSM attestor
 * that signs an attestation statement over the measured harness/workload with a POST-QUANTUM signature
 * scheme — ML-DSA (FIPS-204) and/or SLH-DSA (FIPS-205), optionally in a classical+PQ hybrid — using the
 * project's own `@noble/post-quantum`-backed suite seam (`pq.ts`). Because the signing key is an
 * HSM-held root WE control and the math is post-quantum, this is the root that defeats the quantum-forgery
 * threat WITHOUT waiting on any hardware vendor's PQ roadmap.
 *
 * ── HONEST SCOPE — PQ STATUS: POST-QUANTUM (this is the one that is). ──────────────────────────────
 *   • PQ BY MATH: the statement is signed with ML-DSA / SLH-DSA (or a hybrid that also carries Ed25519),
 *     so forging it requires breaking a post-quantum scheme (and, for hybrid, Ed25519 as well). This is the
 *     quantum-resistant corroboration the classical hardware roots cannot provide.
 *   • SOFTWARE, NOT SILICON: this root is NOT a TEE. Its measurements are SOFTWARE-MEASURED by the harness
 *     and then signed by the HSM root; they are therefore NOT silicon-rooted. Consequently the measured
 *     identity it yields has `weights_measured: false` — it can satisfy a plain `weights_allowlist` but can
 *     NEVER by itself satisfy a grant's `require_measured_weights` (that needs a hardware TEE root). Honest:
 *     this root proves "our HSM root vouched, post-quantum, for these measurements", not "this silicon ran
 *     exactly these weights". Compose it WITH a hardware root in the N-of-M policy to get both properties.
 *   • HSM-HELD KEY: the signing key is PROVIDED / configured (modelling an HSM-resident root), never
 *     generated client-side in the hot path. The verifier only ever holds PUBLIC keys and trusts a fixed,
 *     configured set of them.
 *
 * The suites, their wire-field binding and the fail-closed rules are exactly those of `pq.ts`
 * (`signWithSuite` / `verifyWithSuite`): `alg` and the attestor public keys are SIGNED into the statement
 * body, so a suite downgrade or key swap invalidates the signature; a hybrid requires BOTH component
 * signatures to verify.
 */
import { b64u, canonicalBytes, utf8 } from './hash';
import { publicKeyOf } from './keys';
import {
  type MlDsaKeyPair,
  type SigAlg,
  type SigSuite,
  type SlhDsaKeyPair,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  resolveSigAlg,
  signWithSuite,
  verifyWithSuite,
} from './pq';
import { attestationBinding, attestationBindingB64u } from './attestation';
import type {
  AttestationDocument,
  ExpectedAttestationBinding,
  HardwareAttestationResult,
  HardwareAttestationVerifier,
  MeasuredIdentity,
} from './attestation';
import type { VerifyContext } from './pcactn';

/** Domain separator for the signed PQ attestation statement body. */
export const PQ_ATTEST_DOMAIN = 'atlas-pca/attest-pq/v1\0';

/**
 * A post-quantum attestation statement: the measured workload identity + the holder/grant/epoch/nonce
 * binding, signed by an HSM-held root under a PQ (or hybrid) suite. Every field except `sig` / `pq_sig` is
 * part of the canonical signed body — in particular `alg`, `pq_pk` and `attestor_ed25519` are SIGNED, so a
 * downgrade or key swap invalidates the statement.
 */
export interface PqAttestationStatement {
  /** The measured runtime/workload digest (software-measured by the harness, then PQ-signed). */
  measurement: string;
  /** Optional measured loaded-weights digest (software-measured — NOT silicon-rooted). */
  weights_digest?: string;
  /** Optional measured system-prompt / instructions digest. */
  system_prompt_digest?: string;
  /** Optional measured tool-manifest digest. */
  tool_manifest_digest?: string;
  /** Optional attested model id. */
  model_id?: string;
  /** Optional attested operator identity. */
  operator?: string;
  /** b64u `attestationBinding({holderPub, grantRef, epoch, nonce})` — binds the statement to the action. */
  binding: string;
  /** The PQ (or hybrid) signature suite this statement is signed under. */
  alg: SigAlg;
  /** b64u PQ public key of the HSM root (ML-DSA / SLH-DSA, per `alg`). Present for every PQ suite. */
  pq_pk?: string;
  /** b64u Ed25519 public key of the HSM root — hybrid suites only. */
  attestor_ed25519?: string;
  /** b64u primary signature (the PQ signature for a pure suite; the Ed25519 signature for a hybrid). */
  sig: string;
  /** b64u PQ signature — hybrid suites only. */
  pq_sig?: string;
}

/** The canonical signed body EXCLUDES both signature fields (`sig`, `pq_sig`); everything else is signed. */
type PqStatementBody = Omit<PqAttestationStatement, 'sig' | 'pq_sig'>;

function statementMessage(body: PqStatementBody): Uint8Array {
  const d = canonicalBytes(body);
  const p = utf8(PQ_ATTEST_DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/** True iff `suite` carries a post-quantum signature component. */
function suiteHasPq(suite: SigSuite): boolean {
  return suite.hasMlDsa || suite.hasSlhDsa || suite.hasMlDsa87 || suite.hasSlhDsa256s;
}

/** The HSM-root key material a PQ-software attestor signs with (PROVIDED, never generated here). */
export interface PqSoftwareAttestorKeys {
  /** The PQ (or hybrid) suite to sign under — MUST carry a PQ component. */
  alg: SigAlg;
  /** ML-DSA-65 key pair (for the ml-dsa-65 suites). */
  mlDsa?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-128f key pair (for the slh-dsa-sha2-128f suites). */
  slhDsa?: SlhDsaKeyPair;
  /** ML-DSA-87 key pair (for the Category-5 ml-dsa-87 suites). */
  mlDsa87?: MlDsaKeyPair;
  /** SLH-DSA-SHA2-256s key pair (for the Category-5 slh-dsa-sha2-256s suites). */
  slhDsa256s?: SlhDsaKeyPair;
  /** Ed25519 secret key of the HSM root (hybrid suites only; provided, not generated here). */
  edSecret?: Uint8Array;
}

/** Claims supplied to mint a PQ attestation statement. */
export interface PqAttestationClaims {
  measurement: string;
  weights_digest?: string;
  system_prompt_digest?: string;
  tool_manifest_digest?: string;
  model_id?: string;
  operator?: string;
  /** The holder/grant/epoch/nonce the statement is bound to. */
  holder_pub: string;
  grant_ref: string;
  epoch: number;
  nonce: string;
}

/** Resolve the b64u PQ public key for `keys` under `suite` (the key that becomes `pq_pk`). */
function pqPublicKeyFor(suite: SigSuite, keys: PqSoftwareAttestorKeys): string | undefined {
  if (suite.hasMlDsa && keys.mlDsa) return encodeMlDsaPublicKey(keys.mlDsa.publicKey);
  if (suite.hasSlhDsa && keys.slhDsa) return encodeSlhDsaPublicKey(keys.slhDsa.publicKey);
  if (suite.hasMlDsa87 && keys.mlDsa87) return encodeMlDsa87PublicKey(keys.mlDsa87.publicKey);
  if (suite.hasSlhDsa256s && keys.slhDsa256s) return encodeSlhDsa256sPublicKey(keys.slhDsa256s.publicKey);
  return undefined;
}

export interface PqSoftwareAttestor {
  /** The HSM root's PQ public key (b64u) that the verifier must trust. */
  readonly pqPublicKey: string;
  /** The HSM root's Ed25519 public key (b64u) — present for hybrid suites. */
  readonly ed25519PublicKey?: string;
  /** Mint a signed PQ attestation statement over the given claims. */
  attest(claims: PqAttestationClaims): PqAttestationStatement;
}

/**
 * Build a PQ-software attestor from an HSM-held key (the key is PROVIDED, never generated here). The suite
 * MUST carry a PQ component; a classical-only (`ed25519`) suite is rejected at construction, because this
 * is the post-quantum root. Hybrid suites additionally require `edSecret`.
 */
export function createPqSoftwareAttestor(keys: PqSoftwareAttestorKeys): PqSoftwareAttestor {
  const suite = resolveSigAlg(keys.alg);
  if (suite === null) throw new RangeError(`createPqSoftwareAttestor: unknown signature alg '${String(keys.alg)}'`);
  if (!suiteHasPq(suite)) throw new RangeError(`createPqSoftwareAttestor: '${suite.alg}' is classical; the PQ root requires a post-quantum suite`);
  const pqPk = pqPublicKeyFor(suite, keys);
  if (suite.needsPqPk && pqPk === undefined) throw new TypeError(`createPqSoftwareAttestor: '${suite.alg}' requires the matching PQ key material`);
  if (suite.hasEd25519 && !(keys.edSecret instanceof Uint8Array)) throw new TypeError(`createPqSoftwareAttestor: hybrid suite '${suite.alg}' requires edSecret`);
  const edPub = keys.edSecret instanceof Uint8Array ? b64u(publicKeyOf(keys.edSecret)) : undefined;

  return {
    pqPublicKey: pqPk ?? '',
    ...(edPub !== undefined ? { ed25519PublicKey: edPub } : {}),
    attest(claims: PqAttestationClaims): PqAttestationStatement {
      const binding = attestationBindingB64u({ holderPub: claims.holder_pub, grantRef: claims.grant_ref, epoch: claims.epoch, nonce: claims.nonce });
      const body: PqStatementBody = {
        measurement: claims.measurement,
        binding,
        alg: suite.alg,
        ...(pqPk !== undefined ? { pq_pk: pqPk } : {}),
        ...(edPub !== undefined ? { attestor_ed25519: edPub } : {}),
        ...(claims.weights_digest !== undefined ? { weights_digest: claims.weights_digest } : {}),
        ...(claims.system_prompt_digest !== undefined ? { system_prompt_digest: claims.system_prompt_digest } : {}),
        ...(claims.tool_manifest_digest !== undefined ? { tool_manifest_digest: claims.tool_manifest_digest } : {}),
        ...(claims.model_id !== undefined ? { model_id: claims.model_id } : {}),
        ...(claims.operator !== undefined ? { operator: claims.operator } : {}),
      };
      const parts = signWithSuite(suite.alg, { edSecret: keys.edSecret, mlDsa: keys.mlDsa, slhDsa: keys.slhDsa, mlDsa87: keys.mlDsa87, slhDsa256s: keys.slhDsa256s }, statementMessage(body));
      return { ...body, sig: parts.sig, ...(parts.pq_sig !== undefined ? { pq_sig: parts.pq_sig } : {}) };
    },
  };
}

/** Acceptance policy for a verified PQ statement. `measurements` is REQUIRED and NON-EMPTY (no accept-all). */
export interface PqSoftwarePolicy {
  /** Allowed measurement values. REQUIRED and NON-EMPTY. */
  measurements: string[];
  /** Allowed measured-weights digests. Omitted/empty => not gated here. */
  weightsMeasurements?: string[];
  /** Map a verified statement into the `MeasuredIdentity` agent_binding is checked against. */
  deriveIdentity?: (statement: PqAttestationStatement) => MeasuredIdentity;
}

export interface PqSoftwareVerifierOptions {
  /** Trusted HSM-root PQ public keys (b64u). The statement's `pq_pk` MUST be one of these. */
  trustedPqPublicKeys: string[];
  /** Trusted HSM-root Ed25519 public keys (b64u) — required to accept a hybrid statement. */
  trustedEd25519PublicKeys?: string[];
  /** Require the statement suite to carry a PQ component (default TRUE). A classical-only statement is denied. */
  requirePq?: boolean;
  /** Require a HYBRID suite (Ed25519 + PQ). Default false. A pure-PQ statement is denied when set. */
  requireHybrid?: boolean;
  /** Optional closed allowlist of accepted suites; omitted => any suite that satisfies requirePq/requireHybrid. */
  allowedSuites?: SigAlg[];
  /** Acceptance policy (measurement allowlist required). */
  policy: PqSoftwarePolicy;
  /**
   * EVIDENCE SEAM: produce the signed statement for an action. If omitted, the verifier fails closed.
   */
  resolveEvidence?: (
    document: AttestationDocument,
    ctx: VerifyContext,
  ) => PqAttestationStatement | undefined | Promise<PqAttestationStatement | undefined>;
}

/**
 * Build a `HardwareAttestationVerifier` backed by the PQ-software/HSM root. (It plugs into the SAME seam
 * as the hardware roots; "hardware" names the seam, not a claim that this is silicon.) Given an attestation
 * document + context it resolves the signed statement (the evidence seam), then:
 *   1. resolves the declared suite and ENFORCES the PQ requirement (classical-only => denied) and any
 *      hybrid / allowed-suite requirement;
 *   2. checks the statement's attestor public keys are in the configured TRUSTED set;
 *   3. verifies the PQ (or hybrid) signature over the canonical statement body (`verifyWithSuite`);
 *   4. confirms `binding === attestationBinding(expected)` (holder/grant/epoch/nonce);
 *   5. applies the acceptance policy and returns the measured identity (with `weights_measured: false` — a
 *      software root is not silicon-rooted; see the module header).
 * Fails CLOSED with a specific reason on any mismatch or error.
 */
export function createPqSoftwareVerifier(opts: PqSoftwareVerifierOptions): HardwareAttestationVerifier {
  if (!opts?.policy || !Array.isArray(opts.policy.measurements) || opts.policy.measurements.length === 0) {
    throw new TypeError('createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)');
  }
  const trustedPq = new Set(Array.isArray(opts.trustedPqPublicKeys) ? opts.trustedPqPublicKeys : []);
  if (trustedPq.size === 0) throw new TypeError('createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)');
  const trustedEd = new Set(Array.isArray(opts.trustedEd25519PublicKeys) ? opts.trustedEd25519PublicKeys : []);
  const requirePq = opts.requirePq !== false; // default true
  const requireHybrid = opts.requireHybrid === true;
  const allowed = Array.isArray(opts.allowedSuites) && opts.allowedSuites.length > 0 ? new Set<SigAlg>(opts.allowedSuites) : null;
  const policy = opts.policy;
  const deriveIdentity = policy.deriveIdentity ?? defaultPqIdentity;

  return {
    async verify(input): Promise<HardwareAttestationResult> {
      const fail = (reason: string): HardwareAttestationResult => ({ ok: false, reason });
      try {
        if (!opts.resolveEvidence) return fail('no PQ-software evidence resolver configured (fail closed)');
        const st = await opts.resolveEvidence(input.document, input.ctx);
        if (!st || typeof st !== 'object' || typeof st.alg !== 'string') return fail('no PQ-software attestation statement for this action');

        // (1) suite + PQ requirement
        const suite = resolveSigAlg(st.alg);
        if (suite === null) return fail(`PQ statement declares an unknown signature alg '${String(st.alg)}'`);
        if (requirePq && !suiteHasPq(suite)) return fail(`PQ required: a classical-only suite '${suite.alg}' is not accepted by the post-quantum root`);
        if (requireHybrid && !(suite.hasEd25519 && suiteHasPq(suite))) return fail(`hybrid required: suite '${suite.alg}' is not a classical+PQ hybrid`);
        if (allowed && !allowed.has(suite.alg)) return fail(`suite '${suite.alg}' is not in the allowed-suites list`);

        // (2) trusted attestor keys
        if (suite.needsPqPk) {
          if (typeof st.pq_pk !== 'string' || !trustedPq.has(st.pq_pk)) return fail('PQ attestor key is not trusted');
        }
        if (suite.hasEd25519) {
          if (typeof st.attestor_ed25519 !== 'string' || !trustedEd.has(st.attestor_ed25519)) return fail('hybrid Ed25519 attestor key is not trusted');
        }

        // (3) signature over the canonical statement body (excludes sig/pq_sig)
        const { sig, pq_sig, ...body } = st;
        const message = statementMessage(body);
        const pqPub = typeof st.pq_pk === 'string' ? st.pq_pk : undefined;
        const ok = verifyWithSuite(
          suite.alg,
          { edPub: st.attestor_ed25519, mlDsaPub: pqPub, slhDsaPub: pqPub, mlDsa87Pub: pqPub, slhDsa256sPub: pqPub },
          message,
          { sig, pq_sig },
        );
        if (!ok) return fail('PQ attestation signature does not verify');

        // (4) binding
        if (!input.expected) return fail('no expected attestation binding supplied');
        let expectedB64u: string;
        try {
          expectedB64u = b64u(attestationBinding(input.expected));
        } catch (e) {
          return fail(`binding not constructible: ${e instanceof Error ? e.message : 'invalid'}`);
        }
        if (typeof st.binding !== 'string' || st.binding.length === 0) return fail('PQ statement is not bound (binding absent)');
        if (st.binding !== expectedB64u) return fail('PQ statement binding mismatch (holder/grant/epoch/nonce)');

        // (5) policy
        if (Array.isArray(policy.measurements) && policy.measurements.length > 0 && !policy.measurements.includes(st.measurement)) {
          return fail('measurement not in policy allowlist');
        }
        if (Array.isArray(policy.weightsMeasurements) && policy.weightsMeasurements.length > 0) {
          if (typeof st.weights_digest !== 'string' || !policy.weightsMeasurements.includes(st.weights_digest)) {
            return fail('measured weights digest not in policy allowlist');
          }
        }

        const measured = deriveIdentity(st);
        return { ok: true, bound: true, measured, hostAsserted: { suite: suite.alg } };
      } catch (e) {
        return fail(`pq-software verification error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
      }
    },
  };
}

/**
 * Default identity mapping for a verified PQ statement. HONEST: `weights_measured` is ALWAYS false — a
 * software/HSM root is not a silicon TEE, so its weights digest is software-measured, not hardware-rooted,
 * and cannot by itself satisfy a `require_measured_weights` grant (compose with a hardware root for that).
 */
function defaultPqIdentity(st: PqAttestationStatement): MeasuredIdentity {
  return {
    model_id: typeof st.model_id === 'string' ? st.model_id : '',
    weights_digest: typeof st.weights_digest === 'string' ? st.weights_digest : '',
    weights_measured: false, // software/HSM-attested, NOT silicon-measured — see the header's honest scope
    runtime_measurement: st.measurement,
    operator: typeof st.operator === 'string' ? st.operator : '',
    ...(typeof st.system_prompt_digest === 'string' ? { system_prompt_digest: st.system_prompt_digest } : {}),
    ...(typeof st.tool_manifest_digest === 'string' ? { tool_manifest_digest: st.tool_manifest_digest } : {}),
  };
}
