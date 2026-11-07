import type { Capability } from './capability';
import type { CheckStatus, PCActn } from './pcactn';
import { resolveSigAlg } from './pq';

/**
 * Assurance labels (0.5, additive).
 *
 * A check's status (`pass` / `fail` / `not-enforced` / `unsupported`) says WHETHER it held; the assurance report says WHAT a pass
 * rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an Ed25519
 * signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names features the verifier does not
 * implement (`unsupported`), which are reported and never count as a pass.
 *
 * Labels come from the VERIFIER'S configuration, never from the presented evidence: a software attestation verifier
 * is `software` whatever the document claims, a SNARK backend is the system it was built for, a threshold verifier
 * is the scheme the server declared. A hook or backend without a label is `unknown`, which satisfies no requirement.
 *
 * `requireAssurance` turns the report into a gate: when the evidence is weaker, missing, failed (invalid or expired),
 * unlabelled, awaiting-audit or unsupported, the `assurance` check fails and the request is denied.
 */

/** Attestation levels, weakest first. `unknown` = an unlabelled verifier (satisfies nothing). */
export type AttestationLevel = 'unknown' | 'software' | 'hardware' | 'multi_root';
/**
 * Compliance proof systems. `attested_vm` is a statement signed by a trusted prover VM, not a proof; `attested_vm_hw` is
 * the same statement with the prover key bound to hardware evidence of the VM measurement. Still a trusted signer, not a proof.
 */
export type ZkSystem = 'groth16' | 'policyvm_snark' | 'stark' | 'zkvm' | 'attested_vm' | 'attested_vm_hw' | 'unknown';
/** Threshold schemes. Only `multisig` (independent shares) is production; the others are awaiting audit. */
export type ThresholdScheme = 'multisig' | 'frost' | 'frost_dkg' | 'mpc' | 'unknown';
/** Signature levels: `ed25519` (classical), `hybrid` (Ed25519 + a PQ suite), `pq` (PQ only). */
export type SignatureLevel = 'ed25519' | 'hybrid' | 'pq' | 'unbound_pq' | 'unknown';

/** The outcome of one check in the assurance report. `unsupported` is never a pass. */
export type AssuranceOutcome = CheckStatus;

/** What a hook, hardware verifier or SNARK backend declares about itself (see {@link setAssuranceLabel}). */
export interface AssuranceLabel {
  /** The level / system / scheme (see the types above). */
  level: string;
  /** Vendor or root id, e.g. `amd-sev-snp`. */
  vendor?: string;
  /** Crypto awaiting audit (not production): FROST, DKG, MPC. */
  awaiting_audit?: boolean;
  /** @deprecated Input alias of `awaiting_audit`, accepted for one release. */
  preview?: boolean;
  /** SNARK backends: how the verifying key was set up. `multi-party` only from a verified, pinned ceremony transcript. */
  ceremony?: 'single-party' | 'multi-party';
}

export interface CheckAssurance {
  outcome: AssuranceOutcome;
  /** Present only on a pass that rests on labelled evidence. */
  level?: string;
  vendor?: string;
  awaiting_audit?: true;
  /** @deprecated Input alias of `awaiting_audit` on a presented report, accepted for one release; never emitted. */
  preview?: true;
  /** `zk_compliance` on a SNARK backend: `single-party` unless a pinned ceremony transcript names the verifying key. */
  ceremony?: 'single-party' | 'multi-party';
  /** Signature checks: the suites involved (leaf, or root + hops). */
  suites?: string[];
  /** Threshold: the `t` the hook enforced. */
  t?: number;
  /** Why the outcome is `unsupported`, or why a passing check is `degraded`. */
  reason?: string;
  /**
   * A passing check that rests on a compatibility mode (0.5): e.g. `tighten` under `model_polarity: 'legacy'`, where a model-derived
   * value may still widen a grant. Any high-assurance requirement refuses it.
   */
  degraded?: true;
}

/** Per check: was it enforced, and on what evidence. Keys are the verdict's check names. */
export type AssuranceReport = Record<string, CheckAssurance>;

/** A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise `assurance` fails. */
export interface AssuranceRequirement {
  /** Minimum attestation level: `software` < `hardware` < `multi_root` (two independent hardware roots). */
  attestation?: 'software' | 'hardware' | 'multi_root';
  /**
   * Compliance proof: `attested_vm` accepts any enforced statement; `attested_vm_hardware` a statement whose prover key
   * is bound to hardware evidence (or any real proof); `proof` a cryptographic proof (Groth16, Policy-VM
   * SNARK, STARK, zkVM); `snark` only Groth16 / Policy-VM SNARK.
   */
  zk?: 'attested_vm' | 'attested_vm_hardware' | 'proof' | 'snark';
  /** `pq`: the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite. */
  signature?: 'pq';
  /** Accepted threshold schemes for the `threshold` check (which must pass on an enforced, labelled hook). */
  threshold?: readonly Exclude<ThresholdScheme, 'unknown'>[];
  /**
   * Accept passing evidence labelled awaiting audit (FROST, DKG, MPC) outside an explicit `threshold` list. Default false:
   * under a requirement, crypto awaiting audit denies.
   */
  allowAwaitingAudit?: boolean;
  /** @deprecated Input alias of `allowAwaitingAudit`, accepted for one release. */
  allowPreview?: boolean;
}

const LABELS = new WeakMap<object, AssuranceLabel>();

/**
 * Attach an assurance label to a verifier hook, a `HardwareAttestationVerifier` or a `SnarkBackend`. The library's own
 * constructors label what they build; label a custom one so a requirement can be met by it. Returns `target`.
 */
export function setAssuranceLabel<T extends object>(target: T, label: AssuranceLabel): T {
  LABELS.set(target, Object.freeze({ ...label }));
  return target;
}

/** The label attached to `target`, if any. */
export function assuranceLabelOf(target: unknown): AssuranceLabel | undefined {
  return (typeof target === 'object' && target !== null) || typeof target === 'function' ? LABELS.get(target as object) : undefined;
}

const ATT_RANK: Record<string, number> = { unknown: 0, software: 1, hardware: 2, multi_root: 3 };
const ZK_RANK: Record<string, number> = { unknown: 0, attested_vm: 1, attested_vm_hw: 1, stark: 2, zkvm: 2, groth16: 3, policyvm_snark: 3 };
const ZK_NEED: Record<NonNullable<AssuranceRequirement['zk']>, number> = { attested_vm: 1, attested_vm_hardware: 1, proof: 2, snark: 3 };
const AWAITING_AUDIT_SCHEMES = new Set<string>(['frost', 'frost_dkg', 'mpc']);

/** True for the threshold schemes awaiting audit (FROST, DKG, MPC). */
export function isAwaitingAuditScheme(s: string): boolean {
  return AWAITING_AUDIT_SCHEMES.has(s);
}

/**
 * The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can
 * contain (all required roots, filled up to `threshold` with the weakest optional ones). Two or more => `multi_root`,
 * one => `hardware`, none => the weakest level among the roots that could make up the quorum.
 */
export function multiRootLevel(roots: readonly { verifier: unknown; required?: boolean }[], threshold: number): AttestationLevel {
  const rank = (r: { verifier: unknown }) => ATT_RANK[assuranceLabelOf(r.verifier)?.level ?? 'unknown'] ?? 0;
  const req = roots.filter((r) => r.required === true);
  const opt = roots.filter((r) => r.required !== true).sort((a, b) => rank(a) - rank(b));
  const chosen = [...req, ...opt.slice(0, Math.max(0, threshold - req.length))];
  const hw = chosen.filter((r) => rank(r) >= ATT_RANK.hardware!).length;
  if (hw >= 2) return 'multi_root';
  if (hw === 1) return 'hardware';
  const min = Math.min(...chosen.map(rank));
  return min >= ATT_RANK.software! ? 'software' : 'unknown';
}

/** Classify one signature suite (absent = Ed25519). An unregistered suite is `unknown`. */
export function signatureLevel(alg: unknown): SignatureLevel {
  const a = alg ?? 'ed25519';
  if (a === 'ed25519') return 'ed25519';
  if (typeof a !== 'string' || resolveSigAlg(a) === null) return 'unknown';
  return a.startsWith('hybrid-') ? 'hybrid' : 'pq';
}

/** The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ. */
function weakest(levels: SignatureLevel[]): SignatureLevel {
  for (const l of ['unknown', 'ed25519', 'hybrid'] as const) if (levels.includes(l)) return l;
  return levels.length ? 'pq' : 'unknown';
}

/** What the report is built from: the checks, the presented PCActn, the verifier's hooks and its PQ policy. */
export interface AssuranceSources {
  checks: Record<string, CheckStatus>;
  pcactn?: PCActn;
  grant?: Capability;
  hooks?: { attestation?: unknown; zk?: unknown; threshold?: unknown; revocation?: unknown };
  /** The attestation hook actually used (the `enforce.attestation` verifier wins over `hooks.attestation`). */
  attestationHook?: unknown;
  /** The `t` the threshold hook reported. */
  thresholdT?: number;
  allowUnboundPq?: boolean;
  /** Passing checks that rest on a compatibility mode: check name -> why (see {@link CheckAssurance.degraded}). */
  degraded?: Readonly<Record<string, string>>;
}

/** Build the per-check assurance report (pure; never throws on odd input). */
export function assuranceReport(src: AssuranceSources): AssuranceReport {
  const out: AssuranceReport = {};
  const p = src.pcactn as (PCActn & { bond_ref?: unknown }) | undefined;
  for (const [name, status] of Object.entries(src.checks)) {
    const e: CheckAssurance = { outcome: status };
    if (status === 'unsupported') e.reason = `${name} is not implemented by this verifier`;
    if (status === 'pass') {
      const hook = name === 'attestation' ? (src.attestationHook ?? src.hooks?.attestation) : name === 'zk_compliance' ? src.hooks?.zk : name === 'threshold' ? src.hooks?.threshold : name === 'revocation' ? src.hooks?.revocation : undefined;
      const label = hook !== undefined ? assuranceLabelOf(hook) : undefined;
      if (name === 'attestation' || name === 'zk_compliance' || (name === 'threshold' && hook !== undefined)) {
        e.level = label?.level ?? 'unknown';
        if (label?.vendor !== undefined) e.vendor = label.vendor;
        if (name === 'zk_compliance' && label?.ceremony !== undefined) e.ceremony = label.ceremony;
        if (label?.awaiting_audit === true || label?.preview === true || (name === 'threshold' && isAwaitingAuditScheme(e.level))) e.awaiting_audit = true;
        if (name === 'threshold' && typeof src.thresholdT === 'number') e.t = src.thresholdT;
      } else if (label) {
        e.level = label.level;
        if (label.vendor !== undefined) e.vendor = label.vendor;
        if (label.awaiting_audit === true || label.preview === true) e.awaiting_audit = true;
      }
      if (name === 'leaf_signature' && p) {
        const alg = p.alg ?? 'ed25519';
        e.suites = [String(alg)];
        e.level = src.allowUnboundPq && alg !== 'ed25519' ? 'unbound_pq' : signatureLevel(alg);
      }
      if (name === 'cap_chain' && p && Array.isArray(p.cap_chain)) {
        const algs = p.cap_chain.map((c) => (c as { alg?: unknown })?.alg ?? 'ed25519');
        e.suites = algs.map(String);
        e.level = src.allowUnboundPq && algs.some((a) => a !== 'ed25519') ? 'unbound_pq' : weakest(algs.map(signatureLevel));
      }
    }
    out[name] = e;
  }
  for (const [name, why] of Object.entries(src.degraded ?? {})) if (out[name]?.outcome === 'pass') out[name] = { ...out[name]!, degraded: true, reason: why };
  // Features the library verifier does not implement: reported, never a pass.
  if (p && p.bond_ref !== undefined) out.bond = { outcome: 'unsupported', reason: 'bond verification is not implemented by this verifier' };
  return out;
}

/**
 * Refresh a report after more checks were decided (e.g. the replay counter, default-deny of required checks): a check
 * that is no longer `pass` loses its level, a new check is added, `unsupported` stays.
 */
export function refreshAssurance(report: AssuranceReport, checks: Record<string, CheckStatus>): AssuranceReport {
  for (const [name, status] of Object.entries(checks)) {
    const was = report[name];
    if (was?.outcome === 'unsupported') continue;
    if (status !== 'pass') report[name] = { outcome: status };
    else if (!was || was.outcome !== 'pass') report[name] = { outcome: 'pass' };
  }
  return report;
}

/**
 * Check a report against a requirement. Returns the reason of the first unmet dimension (prefixed `assurance:`), or
 * undefined when every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit and
 * unsupported evidence never meet a requirement.
 */
export function unmetAssurance(report: AssuranceReport, req: AssuranceRequirement): string | undefined {
  for (const [name, e] of Object.entries(report)) {
    if (e.outcome === 'unsupported') return `assurance: unsupported: ${name} (${e.reason ?? 'not implemented'}); a high-assurance policy never accepts it`;
  }
  for (const [name, e] of Object.entries(report)) {
    if (e.outcome === 'pass' && e.degraded === true) return `assurance: ${name} rests on a degraded compatibility mode (${e.reason ?? 'degraded'}); a high-assurance policy never accepts it`;
  }
  const need = (name: string, what: string): CheckAssurance | string => {
    const e = report[name];
    if (!e) return `assurance: ${what} required but there is no ${name} evidence`;
    if (e.outcome !== 'pass') return `assurance: ${what} required but the ${name} check is ${e.outcome}`;
    return e;
  };
  if (req.attestation !== undefined) {
    const e = need('attestation', `${req.attestation} attestation`);
    if (typeof e === 'string') return e;
    if ((ATT_RANK[e.level ?? 'unknown'] ?? 0) < (ATT_RANK[req.attestation] ?? 99)) return `assurance: ${req.attestation} attestation required but the evidence is ${e.level ?? 'unknown'}`;
  }
  if (req.zk !== undefined) {
    const e = need('zk_compliance', `zk compliance (${req.zk})`);
    if (typeof e === 'string') return e;
    // hardware-bound: the attested-VM statement with a hardware-bound prover key, or any real proof system
    if (req.zk === 'attested_vm_hardware' && (e.level === 'attested_vm' || e.level === 'unknown' || e.level === undefined)) return `assurance: zk compliance (${req.zk}) required but the prover key is not bound to hardware evidence`;
    if ((ZK_RANK[e.level ?? 'unknown'] ?? 0) < ZK_NEED[req.zk]) return `assurance: zk compliance (${req.zk}) required but the evidence is ${e.level ?? 'unknown'}`;
  }
  if (req.signature === 'pq') {
    for (const name of ['leaf_signature', 'cap_chain']) {
      const e = need(name, 'post-quantum signatures');
      if (typeof e === 'string') return e;
      if (e.level !== 'pq' && e.level !== 'hybrid') return `assurance: post-quantum signatures required but ${name} is ${e.level ?? 'unknown'}`;
    }
  }
  if (req.threshold !== undefined) {
    const e = need('threshold', `threshold (${req.threshold.join(' | ')})`);
    if (typeof e === 'string') return e;
    if (e.level === undefined) return `assurance: threshold (${req.threshold.join(' | ')}) required but no threshold verifier enforced it`;
    if (!(req.threshold as readonly string[]).includes(e.level)) return `assurance: threshold (${req.threshold.join(' | ')}) required but the scheme is ${e.level}`;
  }
  if (req.allowAwaitingAudit !== true && req.allowPreview !== true) {
    for (const [name, e] of Object.entries(report)) {
      if (e.outcome !== 'pass' || (e.awaiting_audit !== true && e.preview !== true)) continue;
      if (name === 'threshold' && req.threshold !== undefined && (req.threshold as readonly string[]).includes(e.level ?? '')) continue;
      return `assurance: ${name} rests on crypto awaiting audit (${e.level ?? 'unknown'}); set allowAwaitingAudit or list the scheme to accept it`;
    }
  }
  return undefined;
}
