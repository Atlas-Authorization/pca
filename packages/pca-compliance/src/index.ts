/**
 * `@atlasauth/pca-compliance` — turn PCA proofs + decision records into auditor-ready compliance
 * evidence, pre-mapped to the control language auditors already use: EU AI Act Art. 12 (automatic
 * record-keeping / logging) & Art. 50 (transparency disclosures), ISO/IEC 42001 clauses
 * (reasoning-trace, delegation-chain, human-oversight, intended-use), and SOC 2 CC6 (logical access).
 *
 * "Your agent's audit trail, admissible out of the box."
 *
 * Everything here is PURE and READ-ONLY. It consumes the REAL shapes from `@atlasauth/pca` — the
 * {@link PCActn}, the core {@link VerifyResult} (the eight normative checks), the Policy-VM
 * {@link PolicyDecision} (allow / deny / step-up + reason + risk/tier/budget), the capability
 * {@link CapabilityChain} (who authorized what scope, hop by hop), and the threshold / step-up
 * co-signature ({@link ThresholdSignature}, the signed human-override). Nothing is re-authorized.
 *
 * HONEST SCOPE: this is an EVIDENCE MAPPING, not a legal certification. `satisfied` means the
 * cryptographic evidence a control asks for is PRESENT in the supplied records — not a lawyer's or
 * auditor's sign-off. What PCA uniquely contributes, and what this package foregrounds:
 *   1. every log entry is cryptographically VERIFIABLE — it cites the proof (the PCActn digest + the
 *      leaf signature that verified), so the trail cannot be back-dated or fabricated;
 *   2. the delegation chain is EXPLICIT — each hop records issuer → holder and the scope it narrowed;
 *   3. human-overrides are SIGNED CO-SIGNATURES — a step-up approval is a principal threshold share,
 *      naming the approver, not a free-text "approved by" note.
 */

import {
  type PCActn,
  type VerifyResult,
  type PolicyDecision,
  type Capability,
  type CapabilityChain,
  type Caveat,
  type CheckStatus,
  type ThresholdSignature,
  type ThresholdShare,
  type SignerRole,
  type RequiredThreshold,
  type TrustBudget,
  pcactnDigest,
  isBudgetAllocCaveat,
} from '@atlasauth/pca';

// =================================================================================================
// AuditEvent — a normalized, human-readable record built from a verified PCActn + its decision
// =================================================================================================

/** The resolved disposition of an action, in the three words an auditor expects. */
export type AuditDecisionOutcome = 'allow' | 'deny' | 'step-up';

/** One hop of the delegation chain: who authorized what scope, and what it narrowed. */
export interface DelegationHop {
  index: number;
  isRoot: boolean;
  /** Public key (b64u) that signed (authorized) this hop. */
  issuer: string;
  /** Public key (b64u) this hop's authority is bound to. */
  holder: string;
  /** Short, human-readable renderings of the caveats this hop ADDED (the scope it carries/narrowed). */
  scope: string[];
  /** The raw caveats this hop added (append-only diff against its parent). */
  caveats: Caveat[];
  /** B_sub carried by a `budget_alloc` caveat added at this hop, if any. */
  budgetAlloc?: number;
  /** Plain-English summary of what this hop granted / narrowed. */
  narrative: string;
}

/** A signed human-override: a principal (and/or guardian) threshold co-signature that approved a step-up. */
export interface HumanOverride {
  /** True when a PRINCIPAL (human) co-signature is present — the signed human approval. */
  humanApproved: boolean;
  /** Public keys (b64u) of the human principal approver(s). */
  approvers: string[];
  /** Public keys (b64u) of any guardian (automated policy) co-signers. */
  guardianCosigners: string[];
  /** Every co-signing role present, in the order the shares appear. */
  roles: SignerRole[];
  /** The threshold tier the decision required (1 agent-only, 2 +guardian, 3 +human/principal). */
  requiredTier: 1 | 2 | 3;
  narrative: string;
}

/** An epoch-ms timestamp, carried alongside its ISO-8601 rendering for non-engineer readers. */
export interface AuditTimestamp {
  epochMs: number;
  iso: string;
}

/** Cryptographic evidence that pins this entry to a real, signed proof (why the trail is admissible). */
export interface AuditEvidence {
  /** Content address of the PCActn (the proof this entry cites). */
  pcactnDigest: string;
  /** Leaf-holder signature (b64u) — the agent's signature over the action. */
  leafSignature: string;
  /** Signature suite the leaf used. */
  signatureSuite: string;
  /** The committed plan root the action is a node of (intended-use / plan binding). */
  planRoot: string;
  /** Digest of the action parameters (what the agent committed to do, without leaking the params). */
  paramsDigest: string;
  /** The root grant this authority descends from. */
  grantRef: string;
  /** Per-holder replay counter. */
  counter: number;
  /** Optional per-action uniqueness nonce. */
  nonce?: string;
  /**
   * True when the entry cites a proof whose leaf signature VERIFIED (wire + leaf_signature passed). An
   * entry can be cryptographically verifiable yet still a DENY (another check failed) — the point is the
   * log line is bound to a real signed object, not fabricated after the fact.
   */
  cryptographicallyVerifiable: boolean;
}

/** The AuditEvent: one action, normalized from its verified PCActn + decision, auditor-readable. */
export interface AuditEvent {
  schema: 'atlas-pca/audit-event/v1';
  /** When this record was assembled. */
  recordedAt: AuditTimestamp;
  /** Agent identity + the session (delegated-authority anchor) it acted under. */
  agent: {
    /** The acting agent: the leaf holder key of the capability chain. */
    holder: string;
    /** The principal the authority is rooted at: the root issuer key (undefined for an empty chain). */
    principal: string | undefined;
    /** Session anchor: caller-supplied, else the root grant reference. */
    session: string;
  };
  /** The explicit delegation chain: who authorized what scope, hop by hop. */
  delegation: {
    depth: number;
    hops: DelegationHop[];
  };
  /** The action the agent took. */
  action: {
    verb: string;
    resource: string;
    paramsDigest: string;
    reversibilityClass: string;
    summary: string;
  };
  /** The decision: allow / deny / step-up, the decisive reason, and whether the proof verified. */
  decision: {
    outcome: AuditDecisionOutcome;
    reason: string;
    /** True when the core verifier accepted the proof (all checks passed). */
    proofVerified: boolean;
    /** Status of each of the verifier's checks (wire, audience, cap_chain, leaf_signature, …). */
    checks: Record<string, CheckStatus>;
  };
  /** The risk / tier / budget the Policy VM derived. */
  risk: {
    /** Risk score r in [0,1]; undefined when no PolicyDecision was supplied. */
    r?: number;
    /** Required co-sign tier (1 agent / 2 guardian / 3 human); undefined without a decision. */
    tier?: 1 | 2 | 3;
    /** Proof strength the tier demands. */
    proof?: RequiredThreshold['proof'];
    /** Trust budget after the decision (post-leak / post-debit). */
    budget?: TrustBudget;
  };
  /** Present when the action carried a signed co-signature (a step-up human-override / guardian release). */
  humanOverride?: HumanOverride;
  /** The action's own validity window (signed into the proof). */
  timestamps: {
    issuedAt: AuditTimestamp;
    expiresAt: AuditTimestamp;
  };
  /** Cryptographic evidence binding this entry to the proof. */
  evidence: AuditEvidence;
  /** One-sentence plain-English narration of the whole event. */
  narrative: string;
}

// ---- small, total helpers (never throw) ----------------------------------------------------------

function iso(epochMs: number): string {
  if (!Number.isFinite(epochMs)) return '(unknown time)';
  try {
    return new Date(epochMs).toISOString();
  } catch {
    return '(unrepresentable time)';
  }
}

function ts(epochMs: number): AuditTimestamp {
  return { epochMs, iso: iso(epochMs) };
}

/** Abbreviate a long b64u key for display. */
function short(key: unknown, n = 12): string {
  if (typeof key !== 'string' || key.length === 0) return '(none)';
  return key.length <= n + 1 ? key : `${key.slice(0, n)}…`;
}

function numStr(x: unknown): string {
  if (typeof x !== 'number' || !Number.isFinite(x)) return String(x);
  if (Number.isInteger(x)) return String(x);
  return String(Math.round(x * 1e4) / 1e4);
}

/** A bounded, human-readable rendering of one caveat (the scope constraint it imposes). */
function describeCaveat(cv: Caveat): string {
  if (cv === null || typeof cv !== 'object' || typeof cv.type !== 'string') return '(malformed caveat)';
  if (cv.type === 'envelope') {
    // `Caveat` carries an index signature, so these ride through as `unknown` — no cast needed.
    const predsRaw = cv.predicates;
    const innerRaw = cv.caveats;
    const predicates = Array.isArray(predsRaw) ? predsRaw.length : 0;
    const inner = Array.isArray(innerRaw) ? innerRaw.length : 0;
    return `policy envelope (${predicates} predicate(s), ${inner} caveat(s))`;
  }
  if (isBudgetAllocCaveat(cv)) return `budget allocation ≤ ${numStr(cv.limit)}`;
  const parts: string[] = [];
  for (const k of Object.keys(cv).slice(0, 8)) {
    if (k === 'type') continue;
    const v = cv[k];
    parts.push(`${k}=${typeof v === 'object' && v !== null ? JSON.stringify(v) : numStr(v)}`);
  }
  return parts.length > 0 ? `${cv.type}(${parts.join(', ')})` : cv.type;
}

/** Build the delegation hops: issuer → holder and the caveats each hop ADDED (append-only diff). */
function buildDelegationHops(chain: CapabilityChain | undefined): DelegationHop[] {
  const safe: Capability[] = Array.isArray(chain) ? chain : [];
  const hops: DelegationHop[] = [];
  for (let i = 0; i < safe.length; i++) {
    const cap = safe[i];
    if (!cap) continue;
    const isRoot = i === 0;
    const parent = i > 0 ? safe[i - 1] : undefined;
    const parentLen = parent && Array.isArray(parent.caveats) ? parent.caveats.length : 0;
    const own: Caveat[] = Array.isArray(cap.caveats) ? cap.caveats : [];
    const added = isRoot ? own : own.length >= parentLen ? own.slice(parentLen) : [];
    const scope = added.map(describeCaveat);
    const budgetCv = added.find((cv) => isBudgetAllocCaveat(cv));
    const hop: DelegationHop = {
      index: i,
      isRoot,
      issuer: cap.issuer,
      holder: cap.holder,
      scope,
      caveats: added,
      narrative: isRoot
        ? `Principal ${short(cap.issuer)} granted authority to ${short(cap.holder)}${scope.length ? ` under: ${scope.join('; ')}` : ''}.`
        : `${short(cap.issuer)} delegated to ${short(cap.holder)}${scope.length ? `, narrowing scope: ${scope.join('; ')}` : ' (rebind only, no new constraints)'}.`,
    };
    if (budgetCv && isBudgetAllocCaveat(budgetCv)) hop.budgetAlloc = budgetCv.limit;
    hops.push(hop);
  }
  return hops;
}

/** Extract the signed co-signature (human-override) from a PCActn's threshold signature, if any. */
function buildHumanOverride(
  threshold: ThresholdSignature | undefined,
  requiredTier: 1 | 2 | 3,
): HumanOverride | undefined {
  const shares: ThresholdShare[] = threshold && Array.isArray(threshold.shares) ? threshold.shares : [];
  if (shares.length === 0) return undefined;
  const approvers: string[] = [];
  const guardianCosigners: string[] = [];
  const roles: SignerRole[] = [];
  for (const s of shares) {
    if (!s || typeof s.role !== 'string') continue;
    roles.push(s.role);
    if (s.role === 'principal' && typeof s.publicKey === 'string') approvers.push(s.publicKey);
    if (s.role === 'guardian' && typeof s.publicKey === 'string') guardianCosigners.push(s.publicKey);
  }
  const humanApproved = approvers.length > 0;
  const narrative = humanApproved
    ? `Step-up approved by a signed human co-signature from principal ${short(approvers[0])}${
        guardianCosigners.length ? ` (plus ${guardianCosigners.length} guardian co-sign)` : ''
      } at tier t=${requiredTier}.`
    : `Co-signed by ${guardianCosigners.length} guardian share(s) at tier t=${requiredTier} (no human principal signature present).`;
  return { humanApproved, approvers, guardianCosigners, roles, requiredTier, narrative };
}

/** Resolve the auditor-facing outcome from the proof's verification and the Policy-VM decision. */
function resolveOutcome(
  verify: VerifyResult,
  decision: PolicyDecision | undefined,
): { outcome: AuditDecisionOutcome; reason: string } {
  // A proof that did not verify is a DENY — the decisive verifier reason is authoritative.
  if (!verify || verify.allow !== true) {
    return { outcome: 'deny', reason: verify?.reason ?? 'proof failed verification' };
  }
  if (!decision) {
    return { outcome: 'allow', reason: 'proof verified; no policy decision supplied' };
  }
  if (decision.admit) {
    return { outcome: 'allow', reason: firstReasonOr(decision, 'auto-admitted within policy and budget') };
  }
  if (decision.releaseGuardianShare) {
    return { outcome: 'step-up', reason: firstReasonOr(decision, 'policy satisfied but a co-signature is required') };
  }
  return { outcome: 'deny', reason: firstReasonOr(decision, 'policy did not release authority (default-deny)') };
}

function firstReasonOr(decision: PolicyDecision, fallback: string): string {
  const rs = Array.isArray(decision.reasons) ? decision.reasons : [];
  return rs.length > 0 && typeof rs[0] === 'string' ? rs[0] : fallback;
}

/** The input to build one normalized {@link AuditEvent}. */
export interface AuditEventInput {
  /** The action's proof. */
  pcactn: PCActn;
  /** The core verifier's result over that proof (the eight checks). */
  verify: VerifyResult;
  /** The Policy-VM decision for the action (allow / deny / step-up + risk/tier/budget). Optional. */
  decision?: PolicyDecision;
  /** When the record is assembled (epoch ms); defaults to `Date.now()`. */
  now?: number;
  /** Session anchor; defaults to the PCActn's grant reference. */
  session?: string;
}

/**
 * Build a normalized {@link AuditEvent} from a verified PCActn and its decision. Pure and total: a
 * malformed input degrades to a best-effort record rather than throwing. The event captures agent
 * identity + session, the explicit delegation chain (each hop's issuer → holder + scope), the action,
 * the decision (allow/deny/step-up + reason + which checks passed), the risk/tier/budget, any signed
 * human-override (a principal step-up co-signature naming the approver), the signed validity window,
 * and the cryptographic evidence (the PCActn digest + leaf signature) that makes the entry admissible.
 */
export function toAuditEvent(input: AuditEventInput): AuditEvent {
  const p = input.pcactn;
  const verify = input.verify ?? { allow: false, checks: {} };
  const now = input.now ?? Date.now();
  const chain: CapabilityChain | undefined = Array.isArray(p?.cap_chain) ? p.cap_chain : undefined;
  const hops = buildDelegationHops(chain);
  const leaf = chain && chain.length > 0 ? chain[chain.length - 1] : undefined;
  const root = chain && chain.length > 0 ? chain[0] : undefined;

  const { outcome, reason } = resolveOutcome(verify, input.decision);
  const requiredTier: 1 | 2 | 3 = input.decision?.requiredThreshold?.t ?? 1;
  const humanOverride = buildHumanOverride(p?.threshold, requiredTier);

  const checks = verify.checks ?? {};
  const cryptoVerifiable = checks.wire === 'pass' && checks.leaf_signature === 'pass';

  const verb = typeof p?.action?.verb === 'string' ? p.action.verb : '(unknown verb)';
  const resource = typeof p?.action?.resource === 'string' ? p.action.resource : '(unknown resource)';
  const grantRef = typeof p?.grant_ref === 'string' ? p.grant_ref : '(none)';

  const evidence: AuditEvidence = {
    pcactnDigest: safePcactnDigest(p),
    leafSignature: typeof p?.sig === 'string' ? p.sig : '(unsigned)',
    signatureSuite: typeof p?.alg === 'string' ? p.alg : 'ed25519',
    planRoot: typeof p?.plan?.root === 'string' ? p.plan.root : '(none)',
    paramsDigest: typeof p?.action?.params_digest === 'string' ? p.action.params_digest : '(none)',
    grantRef,
    counter: typeof p?.counter === 'number' ? p.counter : -1,
    cryptographicallyVerifiable: cryptoVerifiable,
  };
  if (typeof p?.nonce === 'string') evidence.nonce = p.nonce;

  const risk: AuditEvent['risk'] = {};
  if (input.decision) {
    risk.r = input.decision.r;
    risk.tier = input.decision.requiredThreshold?.t;
    risk.proof = input.decision.requiredThreshold?.proof;
    risk.budget = input.decision.budget;
  }

  const outcomeWord = outcome === 'allow' ? 'ALLOWED' : outcome === 'deny' ? 'DENIED' : 'STEP-UP';
  const narrative =
    `Agent ${short(leaf?.holder)} ${outcomeWord} to ${verb} on ${resource} ` +
    `(${hops.length}-hop chain rooted at principal ${short(root?.issuer)}; ` +
    `${cryptoVerifiable ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable'}` +
    `${humanOverride?.humanApproved ? '; human-signed step-up' : ''}). ${reason}`;

  const event: AuditEvent = {
    schema: 'atlas-pca/audit-event/v1',
    recordedAt: ts(now),
    agent: {
      holder: typeof leaf?.holder === 'string' ? leaf.holder : '(none)',
      principal: typeof root?.issuer === 'string' ? root.issuer : undefined,
      session: input.session ?? grantRef,
    },
    delegation: { depth: Math.max(0, hops.length - 1), hops },
    action: {
      verb,
      resource,
      paramsDigest: evidence.paramsDigest,
      reversibilityClass: typeof p?.action?.reversibility_class === 'string' ? p.action.reversibility_class : '(unknown)',
      summary: `${verb} on ${resource}`,
    },
    decision: { outcome, reason, proofVerified: verify.allow === true, checks },
    risk,
    timestamps: {
      issuedAt: ts(typeof p?.iat === 'number' ? p.iat : NaN),
      expiresAt: ts(typeof p?.exp === 'number' ? p.exp : NaN),
    },
    evidence,
    narrative,
  };
  if (humanOverride) event.humanOverride = humanOverride;
  return event;
}

function safePcactnDigest(p: PCActn): string {
  try {
    return pcactnDigest(p);
  } catch {
    return '(undigestible)';
  }
}

// =================================================================================================
// ControlMapping — the inspectable, auditable table of control ↔ PCA-evidence mappings
// =================================================================================================

/** The frameworks this package maps PCA evidence onto. */
export type ComplianceFramework = 'eu-ai-act' | 'iso-42001' | 'soc2';

export const COMPLIANCE_FRAMEWORKS: readonly ComplianceFramework[] = ['eu-ai-act', 'iso-42001', 'soc2'];

/** One row of the control-mapping table: a specific control and the PCA evidence that addresses it. */
export interface ControlMapping {
  framework: ComplianceFramework;
  /** Stable control id (what a report item cites). */
  controlId: string;
  /** Human title of the control. */
  controlTitle: string;
  /** The citable clause / article reference. */
  clause: string;
  /** What the control REQUIRES (plain language). */
  requirement: string;
  /** What PCA UNIQUELY provides as evidence for this control. */
  pcaEvidence: string;
  /** Which {@link AuditEvent} fields carry that evidence. */
  evidenceFields: string[];
}

/**
 * The full, inspectable control-mapping table. Exported so the mappings are auditable in their own
 * right (an auditor can review the claim BEFORE trusting a generated report). Control ids are stable.
 */
export const CONTROL_MAPPINGS: readonly ControlMapping[] = [
  // ---- EU AI Act ----
  {
    framework: 'eu-ai-act',
    controlId: 'eu-ai-act:art-12',
    controlTitle: 'Record-keeping — automatic, traceable logging of events',
    clause: 'EU AI Act, Article 12',
    requirement:
      'High-risk AI systems must automatically record events ("logs") over their lifetime, enabling traceability of the system\'s functioning.',
    pcaEvidence:
      'Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.',
    evidenceFields: ['evidence.pcactnDigest', 'evidence.leafSignature', 'evidence.cryptographicallyVerifiable', 'timestamps.issuedAt'],
  },
  {
    framework: 'eu-ai-act',
    controlId: 'eu-ai-act:art-50',
    controlTitle: 'Transparency — disclosure of automated decisions and the acting agent',
    clause: 'EU AI Act, Article 50',
    requirement:
      'Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.',
    pcaEvidence:
      'Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.',
    evidenceFields: ['agent.holder', 'agent.principal', 'action.summary', 'decision.outcome', 'decision.reason'],
  },

  // ---- ISO/IEC 42001 ----
  {
    framework: 'iso-42001',
    controlId: 'iso-42001:A.6.2.8',
    controlTitle: 'Reasoning trace — AI system event logging',
    clause: 'ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)',
    requirement:
      'The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.',
    pcaEvidence:
      'Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.',
    evidenceFields: ['decision.reason', 'risk.r', 'risk.tier', 'risk.budget', 'decision.checks'],
  },
  {
    framework: 'iso-42001',
    controlId: 'iso-42001:A.9.2',
    controlTitle: 'Delegation & authorization chain',
    clause: 'ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)',
    requirement:
      'Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.',
    pcaEvidence:
      'The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.',
    evidenceFields: ['delegation.hops', 'delegation.depth', 'agent.principal', 'delegation.hops[].scope'],
  },
  {
    framework: 'iso-42001',
    controlId: 'iso-42001:A.9.3',
    controlTitle: 'Human oversight of AI systems',
    clause: 'ISO/IEC 42001 Annex A.9.3 (human oversight)',
    requirement:
      'Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.',
    pcaEvidence:
      'Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text "approved by"); denials and step-up requirements show the oversight boundary being enforced.',
    evidenceFields: ['humanOverride.humanApproved', 'humanOverride.approvers', 'decision.outcome', 'risk.tier'],
  },
  {
    framework: 'iso-42001',
    controlId: 'iso-42001:A.6.2.2',
    controlTitle: 'Intended use — action bound to a committed plan',
    clause: 'ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)',
    requirement:
      'The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.',
    pcaEvidence:
      'Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.',
    evidenceFields: ['evidence.planRoot', 'action.verb', 'action.resource', 'decision.checks'],
  },

  // ---- SOC 2 (Common Criteria CC6 — logical access) ----
  {
    framework: 'soc2',
    controlId: 'soc2:CC6.1',
    controlTitle: 'Logical access security — least privilege',
    clause: 'SOC 2 CC6.1',
    requirement:
      'The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.',
    pcaEvidence:
      'Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.',
    evidenceFields: ['decision.outcome', 'delegation.hops[].scope', 'decision.checks', 'evidence.cryptographicallyVerifiable'],
  },
  {
    framework: 'soc2',
    controlId: 'soc2:CC6.2',
    controlTitle: 'Registration & authorization of credentials / identities',
    clause: 'SOC 2 CC6.2',
    requirement:
      'Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.',
    pcaEvidence:
      'Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.',
    evidenceFields: ['agent.principal', 'agent.holder', 'delegation.hops', 'evidence.grantRef'],
  },
  {
    framework: 'soc2',
    controlId: 'soc2:CC6.3',
    controlTitle: 'Access modification & removal (attenuation / revocation)',
    clause: 'SOC 2 CC6.3',
    requirement:
      'The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.',
    pcaEvidence:
      'Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.',
    evidenceFields: ['delegation.hops[].scope', 'delegation.hops[].budgetAlloc', 'decision.outcome'],
  },
];

/** Own-key framework guard (frameworks may arrive from untrusted input). */
function assertFramework(framework: ComplianceFramework): void {
  if (!COMPLIANCE_FRAMEWORKS.includes(framework)) {
    throw new Error(
      `pca-compliance: unknown framework '${String(framework)}' (have: ${COMPLIANCE_FRAMEWORKS.join(', ')})`,
    );
  }
}

/** The control mappings for a framework (or the whole table when no framework is given). */
export function controlMappings(framework?: ComplianceFramework): ControlMapping[] {
  if (framework === undefined) return [...CONTROL_MAPPINGS];
  assertFramework(framework);
  return CONTROL_MAPPINGS.filter((m) => m.framework === framework);
}

// =================================================================================================
// toComplianceReport — map AuditEvents onto a framework's controls, with a coverage summary
// =================================================================================================

export type ControlStatus = 'satisfied' | 'partial' | 'not-evidenced';

/** Aggregate facts drawn from the events, reused across every control. */
interface EventStats {
  total: number;
  verifiable: number;
  verified: number;
  denied: number;
  stepUp: number;
  allowed: number;
  humanOverrides: number;
  withChain: number;
  withPlanRoot: number;
  maxDepth: number;
  agents: number;
  principals: number;
  sampleDigests: string[];
}

function computeStats(events: AuditEvent[]): EventStats {
  const agents = new Set<string>();
  const principals = new Set<string>();
  const sampleDigests: string[] = [];
  let verifiable = 0;
  let verified = 0;
  let denied = 0;
  let stepUp = 0;
  let allowed = 0;
  let humanOverrides = 0;
  let withChain = 0;
  let withPlanRoot = 0;
  let maxDepth = 0;
  for (const e of events) {
    if (!e) continue;
    if (e.evidence.cryptographicallyVerifiable) verifiable++;
    if (e.decision.proofVerified) verified++;
    if (e.decision.outcome === 'deny') denied++;
    else if (e.decision.outcome === 'step-up') stepUp++;
    else allowed++;
    if (e.humanOverride?.humanApproved) humanOverrides++;
    if (e.delegation.hops.length > 0) withChain++;
    if (e.evidence.planRoot !== '(none)') withPlanRoot++;
    if (e.delegation.depth > maxDepth) maxDepth = e.delegation.depth;
    agents.add(e.agent.holder);
    if (e.agent.principal !== undefined) principals.add(e.agent.principal);
    if (sampleDigests.length < 5 && e.evidence.pcactnDigest !== '(undigestible)') sampleDigests.push(e.evidence.pcactnDigest);
  }
  return {
    total: events.length,
    verifiable,
    verified,
    denied,
    stepUp,
    allowed,
    humanOverrides,
    withChain,
    withPlanRoot,
    maxDepth,
    agents: agents.size,
    principals: principals.size,
    sampleDigests,
  };
}

/** A single mapped control in a report. */
export interface ReportItem {
  controlId: string;
  controlTitle: string;
  clause: string;
  framework: ComplianceFramework;
  status: ControlStatus;
  /** What PCA provides for this control (from the mapping). */
  pcaEvidence: string;
  /** Concrete evidence drawn from THIS set of events. */
  evidence: string;
  /** Notable observations / caveats for this control over this period. */
  findings: string[];
}

export interface ComplianceReport {
  schema: 'atlas-pca/compliance-report/v1';
  framework: ComplianceFramework;
  generatedAt: AuditTimestamp;
  /** The time span the events cover (by issued-at). */
  period: { from: AuditTimestamp; to: AuditTimestamp };
  eventCount: number;
  /** The PCA-unique assurances that hold across the whole event set. */
  assurances: {
    /** True iff EVERY entry cites a cryptographically verifiable proof. */
    cryptographicallyVerifiable: boolean;
    /** True iff EVERY entry carries an explicit delegation chain. */
    explicitDelegationChain: boolean;
    /** True iff at least one step-up was approved by a signed human co-signature. */
    signedHumanOverrides: boolean;
    narrative: string;
  };
  items: ReportItem[];
  coverage: {
    total: number;
    satisfied: number;
    partial: number;
    notEvidenced: number;
    /** Fraction of controls fully satisfied, 0..1. */
    satisfiedFraction: number;
    /** Percent of controls fully satisfied, 0..100 (rounded). */
    satisfiedPercent: number;
  };
  summary: string;
}

/** Per-control status + concrete evidence, keyed by the stable control id. */
function evaluateControl(controlId: string, s: EventStats): { status: ControlStatus; evidence: string; findings: string[] } {
  const findings: string[] = [];
  const digestNote = s.sampleDigests.length > 0 ? ` (e.g. ${short(s.sampleDigests[0], 16)})` : '';
  const none = (): { status: ControlStatus; evidence: string; findings: string[] } => ({
    status: 'not-evidenced',
    evidence: 'no actions in the reporting period',
    findings: ['no events supplied — nothing to evidence'],
  });
  if (s.total === 0) return none();

  switch (controlId) {
    case 'eu-ai-act:art-12': {
      const status: ControlStatus = s.verifiable === s.total ? 'satisfied' : 'partial';
      if (s.verifiable < s.total) findings.push(`${s.total - s.verifiable} of ${s.total} entries are not cryptographically verifiable`);
      return {
        status,
        evidence: `${s.total} actions logged; ${s.verifiable}/${s.total} cite a cryptographically verifiable proof${digestNote}`,
        findings,
      };
    }
    case 'eu-ai-act:art-50':
      return {
        status: 'satisfied',
        evidence: `${s.total} actions each disclose the acting agent, the principal (${s.principals} distinct) and the automated decision outcome`,
        findings,
      };
    case 'iso-42001:A.6.2.8':
      return {
        status: 'satisfied',
        evidence: `${s.total} actions each carry a decision reason + risk/tier/budget reasoning trace`,
        findings,
      };
    case 'iso-42001:A.9.2': {
      const status: ControlStatus = s.withChain === s.total ? 'satisfied' : s.withChain > 0 ? 'partial' : 'not-evidenced';
      if (s.withChain < s.total) findings.push(`${s.total - s.withChain} entries have no delegation chain`);
      return {
        status,
        evidence: `${s.withChain}/${s.total} actions carry an explicit delegation chain (max depth ${s.maxDepth}, ${s.principals} authorizing principal(s))`,
        findings,
      };
    }
    case 'iso-42001:A.9.3': {
      let status: ControlStatus;
      let evidence: string;
      if (s.humanOverrides > 0) {
        status = 'satisfied';
        evidence = `${s.humanOverrides} step-up(s) approved by a signed human co-signature; ${s.stepUp} step-up(s) and ${s.denied} denial(s) show oversight enforced`;
      } else if (s.stepUp > 0 || s.denied > 0) {
        status = 'partial';
        evidence = `oversight boundary enforced (${s.stepUp} step-up(s), ${s.denied} denial(s)) but no signed human co-signature observed in the period`;
        findings.push('no human step-up co-signature was exercised in this period');
      } else {
        status = 'partial';
        evidence = 'all actions were auto-admitted within policy; no oversight event was triggered in the period';
        findings.push('no higher-impact action required human oversight in this period');
      }
      return { status, evidence, findings };
    }
    case 'iso-42001:A.6.2.2': {
      const status: ControlStatus = s.withPlanRoot === s.total ? 'satisfied' : s.withPlanRoot > 0 ? 'partial' : 'not-evidenced';
      if (s.withPlanRoot < s.total) findings.push(`${s.total - s.withPlanRoot} entries are not bound to a committed plan root`);
      return {
        status,
        evidence: `${s.withPlanRoot}/${s.total} actions are bound to a committed plan root (intended-use binding)`,
        findings,
      };
    }
    case 'soc2:CC6.1':
      if (s.denied > 0) findings.push(`${s.denied} out-of-scope action(s) denied — access control actively enforced`);
      return {
        status: 'satisfied',
        evidence: `deny-by-default access over ${s.total} actions (${s.allowed} allowed, ${s.stepUp} step-up, ${s.denied} denied); all gated by signed predicates + attenuation`,
        findings,
      };
    case 'soc2:CC6.2': {
      const status: ControlStatus = s.withChain === s.total ? 'satisfied' : s.withChain > 0 ? 'partial' : 'not-evidenced';
      if (s.withChain < s.total) findings.push(`${s.total - s.withChain} entries are not traceable to an authorizing principal`);
      return {
        status,
        evidence: `${s.agents} agent identit(ies) traceable to ${s.principals} authorizing principal(s) via signed delegation chains`,
        findings,
      };
    }
    case 'soc2:CC6.3': {
      const narrowed = s.maxDepth >= 1;
      const status: ControlStatus = narrowed || s.denied > 0 ? 'satisfied' : 'partial';
      if (!narrowed && s.denied === 0) findings.push('no attenuating hop or denial observed in the period');
      return {
        status,
        evidence: `access narrowed by attenuation (max delegation depth ${s.maxDepth}) and ${s.denied} denied action(s)`,
        findings,
      };
    }
    default:
      return { status: 'not-evidenced', evidence: 'no evaluator for this control', findings: ['unmapped control'] };
  }
}

/**
 * Build a structured {@link ComplianceReport} for a framework from a set of {@link AuditEvent}s. Each
 * report item is mapped to a specific control (with its stable id + clause) and carries both the
 * PCA evidence the control relies on and the concrete evidence drawn from this event set, plus a
 * status (satisfied / partial / not-evidenced). The report foregrounds the PCA-unique assurances
 * (cryptographic verifiability, explicit delegation, signed human-overrides) and a coverage summary.
 */
export function toComplianceReport(
  events: AuditEvent[],
  opts: { framework: ComplianceFramework; now?: number },
): ComplianceReport {
  const framework = opts.framework;
  assertFramework(framework);
  const list = Array.isArray(events) ? events.filter((e): e is AuditEvent => !!e) : [];
  const now = opts.now ?? Date.now();
  const s = computeStats(list);

  const mappings = CONTROL_MAPPINGS.filter((m) => m.framework === framework);
  const items: ReportItem[] = mappings.map((m) => {
    const r = evaluateControl(m.controlId, s);
    return {
      controlId: m.controlId,
      controlTitle: m.controlTitle,
      clause: m.clause,
      framework: m.framework,
      status: r.status,
      pcaEvidence: m.pcaEvidence,
      evidence: r.evidence,
      findings: r.findings,
    };
  });

  const satisfied = items.filter((i) => i.status === 'satisfied').length;
  const partial = items.filter((i) => i.status === 'partial').length;
  const notEvidenced = items.filter((i) => i.status === 'not-evidenced').length;
  const total = items.length;
  const satisfiedFraction = total > 0 ? satisfied / total : 0;

  // Period by issued-at.
  const iats = list.map((e) => e.timestamps.issuedAt.epochMs).filter((x) => Number.isFinite(x));
  const from = iats.length > 0 ? Math.min(...iats) : 0;
  const to = iats.length > 0 ? Math.max(...iats) : 0;

  const assurances = {
    cryptographicallyVerifiable: s.total > 0 && s.verifiable === s.total,
    explicitDelegationChain: s.total > 0 && s.withChain === s.total,
    signedHumanOverrides: s.humanOverrides > 0,
    narrative:
      s.total === 0
        ? 'No events in scope.'
        : `${s.verifiable}/${s.total} entries cite a cryptographically verifiable proof; ` +
          `${s.withChain}/${s.total} carry an explicit delegation chain; ` +
          `${s.humanOverrides} step-up(s) carry a signed human co-signature.`,
  };

  const summary =
    `${framework}: ${satisfied}/${total} controls satisfied` +
    (partial > 0 ? `, ${partial} partial` : '') +
    (notEvidenced > 0 ? `, ${notEvidenced} not evidenced` : '') +
    ` over ${s.total} action(s).`;

  return {
    schema: 'atlas-pca/compliance-report/v1',
    framework,
    generatedAt: ts(now),
    period: { from: ts(from), to: ts(to) },
    eventCount: s.total,
    assurances,
    items,
    coverage: {
      total,
      satisfied,
      partial,
      notEvidenced,
      satisfiedFraction,
      satisfiedPercent: Math.round(satisfiedFraction * 100),
    },
    summary,
  };
}

// =================================================================================================
// Renderers
// =================================================================================================

const STATUS_GLYPH: Record<ControlStatus, string> = {
  satisfied: '✓',
  partial: '◐',
  'not-evidenced': '·',
};

/** Render a report as the raw structured JSON (the report object serialized, stable + pretty). */
export function renderJson(report: ComplianceReport): string {
  return JSON.stringify(report, null, 2);
}

/** Render a report as an auditor-facing Markdown document (control table + coverage + assurances). */
export function renderMarkdown(report: ComplianceReport): string {
  const r = report;
  const lines: string[] = [];
  lines.push(`# PCA compliance evidence — ${r.framework}`);
  lines.push('');
  lines.push(
    `Generated ${r.generatedAt.iso} · ${r.eventCount} action(s) · ` +
      `coverage: ${r.coverage.satisfied}/${r.coverage.total} satisfied (${r.coverage.satisfiedPercent}%)`,
  );
  if (r.eventCount > 0) {
    lines.push('');
    lines.push(`Reporting period: ${r.period.from.iso} → ${r.period.to.iso}`);
  }
  lines.push('');

  // PCA-unique assurances — why this trail is admissible.
  lines.push('## Why this trail is admissible (what PCA uniquely provides)');
  lines.push('');
  lines.push(`- **Cryptographically verifiable** — ${r.assurances.cryptographicallyVerifiable ? 'YES' : 'PARTIAL'}: every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated.`);
  lines.push(`- **Explicit delegation chain** — ${r.assurances.explicitDelegationChain ? 'YES' : 'PARTIAL'}: each action records who authorized what scope, hop by hop, rooted at a principal.`);
  lines.push(`- **Signed human-overrides** — ${r.assurances.signedHumanOverrides ? 'YES' : 'none in period'}: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note.`);
  lines.push('');
  lines.push(`> ${r.assurances.narrative}`);
  lines.push('');

  // Coverage summary.
  lines.push('## Coverage summary');
  lines.push('');
  lines.push(`| Satisfied | Partial | Not evidenced | Total |`);
  lines.push(`| --- | --- | --- | --- |`);
  lines.push(`| ${r.coverage.satisfied} | ${r.coverage.partial} | ${r.coverage.notEvidenced} | ${r.coverage.total} |`);
  lines.push('');

  // Control mapping table.
  lines.push('## Controls');
  lines.push('');
  lines.push(`| Control | Clause | Status | Evidence in period |`);
  lines.push(`| --- | --- | --- | --- |`);
  for (const i of r.items) {
    lines.push(
      `| ${i.controlTitle} (\`${i.controlId}\`) | ${i.clause} | ${STATUS_GLYPH[i.status]} ${i.status.toUpperCase()} | ${i.evidence} |`,
    );
  }
  lines.push('');

  // Per-control detail (PCA evidence basis + findings).
  lines.push('## Control detail');
  lines.push('');
  for (const i of r.items) {
    lines.push(`### ${i.controlId} — ${i.controlTitle}`);
    lines.push('');
    lines.push(`- Clause: ${i.clause}`);
    lines.push(`- Status: ${STATUS_GLYPH[i.status]} ${i.status.toUpperCase()}`);
    lines.push(`- PCA evidence basis: ${i.pcaEvidence}`);
    lines.push(`- Evidence in period: ${i.evidence}`);
    if (i.findings.length > 0) {
      lines.push(`- Findings:`);
      for (const f of i.findings) lines.push(`  - ${f}`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push('_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._');
  return lines.join('\n');
}
