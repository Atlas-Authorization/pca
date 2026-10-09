/**
 * `@atlasauth/pca-siem` — a SIEM export for PCA authorization decisions.
 *
 * Every PCA verify / deny becomes a first-class SECURITY EVENT an auditor (and a SOC) actually wants:
 * emitted in the standard schemas SIEMs already ingest — OCSF (the open normalized schema Splunk /
 * Amazon Security Lake / Sentinel consume), ArcSight CEF (the classic key=value syslog line), and
 * Elastic Common Schema (ECS, for Elasticsearch / Kibana / the Elastic Stack) — and streamable to any
 * HEC / bulk / intake endpoint (Splunk HEC, Elastic `_bulk`, Datadog logs intake, Microsoft Sentinel).
 *
 * This COMPLEMENTS PCA's existing OpenTelemetry traces: traces are for latency / spans / debugging; THIS
 * is the SECURITY-EVENT feed — the attributable, tamper-evident record of who was allowed to do what,
 * on whose authority, and why. The thing that makes a PCA security event unlike an ordinary auth log:
 *
 *   1. every event CITES THE CRYPTOGRAPHIC PROOF — the PCActn content digest + the leaf signature that
 *      verified — so a SIEM record is itself VERIFIABLE and cannot be back-dated or fabricated; and
 *   2. every event carries the FULL DELEGATION CHAIN — principal → … → acting agent, hop by hop — so an
 *      auditor sees exactly whose authority an action descended from.
 *
 * Everything here is PURE and READ-ONLY over the REAL shapes from `@atlasauth/pca`: the {@link PCActn}
 * (the signed intent), the core {@link VerifyResult} (the eight normative checks), the Policy-VM
 * {@link PolicyDecision} (allow / deny / step-up + risk / tier / budget), the {@link CapabilityChain}
 * (who authorized what, hop by hop), and the {@link ThresholdSignature} (the signed human step-up).
 * Nothing is re-authorized. (The AuditEvent field set is intentionally kin to `@atlasauth/pca-compliance`,
 * mirrored here rather than hard-depended so this package stays a thin PCA-only leaf.)
 *
 * FAIL-SAFE: shipping an event to a SIEM must NEVER throw into the caller's authorization path. Every
 * sink error is caught, reported through an optional `onError`, dropped, and surfaced as a result value.
 */

import {
  type Capability,
  type CapabilityChain,
  type Caveat,
  type CheckStatus,
  type PCActn,
  type PolicyDecision,
  type RequiredThreshold,
  type SignerRole,
  type ThresholdShare,
  type ThresholdSignature,
  type VerifyResult,
  pcactnDigest,
} from '@atlasauth/pca';

// =================================================================================================
// The decision record this package exports — a verified PCActn + its core result + Policy-VM decision
// =================================================================================================

/**
 * One PCA authorization decision, as the resource server observed it: the signed action, the core
 * verifier's result over it (the eight checks), and — when the Policy VM ran — its allow / deny /
 * step-up decision. This is the single input every exporter in this package consumes. Its field set
 * mirrors `@atlasauth/pca-compliance`'s `AuditEventInput` (kept in sync, not imported, so this package
 * depends only on `@atlasauth/pca`).
 */
export interface PcaDecisionRecord {
  /** The action's proof (signed intent). */
  pcactn: PCActn;
  /** The core verifier's result over that proof (wire, audience, cap_chain, leaf_signature, …). */
  verify: VerifyResult;
  /** The Policy-VM decision for the action (allow / deny / step-up + risk / tier / budget). Optional. */
  decision?: PolicyDecision;
  /** When the event is recorded (epoch ms); defaults to `Date.now()`. */
  now?: number;
  /** Session anchor; defaults to the PCActn's grant reference. */
  session?: string;
}

/** The resolved disposition of an action, in the three words an auditor expects. */
export type SiemOutcome = 'allow' | 'deny' | 'step-up';

// =================================================================================================
// Severity model (one source of truth, mapped per schema)
// =================================================================================================

interface Severity {
  /** OCSF `severity_id` (1 Informational … 6 Fatal). */
  readonly id: number;
  /** OCSF `severity` label. */
  readonly name: string;
  /** CEF / ECS numeric severity on the 0–10 scale. */
  readonly cef: number;
}

const SEV_INFO: Severity = { id: 1, name: 'Informational', cef: 1 };
const SEV_LOW: Severity = { id: 2, name: 'Low', cef: 3 };
const SEV_MEDIUM: Severity = { id: 3, name: 'Medium', cef: 5 };
const SEV_HIGH: Severity = { id: 4, name: 'High', cef: 8 };

/** Normative checks whose FAILURE means a real security event (tamper / forged authority), not a policy veto. */
const SECURITY_CHECKS = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'plan_inclusion', 'leaf_signature', 'counter'] as const;

// =================================================================================================
// Normalization — one total, never-throwing pass over the record, shared by all three exporters
// =================================================================================================

interface DelegationHopView {
  index: number;
  isRoot: boolean;
  /** Public key (b64u) that signed (authorized) this hop. */
  issuer: string;
  /** Public key (b64u) this hop's authority is bound to. */
  holder: string;
  /** Count of caveats this hop ADDED (append-only diff against its parent). */
  addedCaveats: number;
}

interface Normalized {
  now: number;
  outcome: SiemOutcome;
  reason: string;
  proofVerified: boolean;
  cryptographicallyVerifiable: boolean;
  checks: Record<string, CheckStatus>;
  agentHolder: string;
  principal: string | undefined;
  session: string;
  hops: DelegationHopView[];
  depth: number;
  chainString: string;
  verb: string;
  resource: string;
  paramsDigest: string;
  reversibilityClass: string;
  grantRef: string;
  counter: number;
  nonce: string | undefined;
  planRoot: string;
  signatureSuite: string;
  leafSignature: string;
  proofDigest: string;
  riskScore: number | undefined;
  tier: 1 | 2 | 3 | undefined;
  proofStrength: RequiredThreshold['proof'] | undefined;
  caution: number | undefined;
  bondRef: string | undefined;
  humanApproved: boolean;
  approvers: string[];
  guardianCosigners: string[];
  roles: SignerRole[];
  severity: Severity;
  iat: number;
  exp: number;
}

function str(v: unknown, fallback: string): string {
  return typeof v === 'string' && v.length > 0 ? v : fallback;
}

function finiteNum(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/** Abbreviate a long b64u key for display in narratives / CEF names. */
function shortKey(key: unknown, n = 12): string {
  if (typeof key !== 'string' || key.length === 0) return '(none)';
  return key.length <= n + 1 ? key : `${key.slice(0, n)}…`;
}

function safeDigest(p: PCActn): string {
  try {
    return pcactnDigest(p);
  } catch {
    return '(undigestible)';
  }
}

function firstReasonOr(decision: PolicyDecision, fallback: string): string {
  const rs = Array.isArray(decision.reasons) ? decision.reasons : [];
  const first = rs.length > 0 ? rs[0] : undefined;
  return typeof first === 'string' && first.length > 0 ? first : fallback;
}

function resolveOutcome(verify: VerifyResult, decision: PolicyDecision | undefined): { outcome: SiemOutcome; reason: string } {
  if (!verify || verify.allow !== true) {
    return { outcome: 'deny', reason: str(verify?.reason, 'proof failed verification') };
  }
  if (!decision) return { outcome: 'allow', reason: 'proof verified; no policy decision supplied' };
  if (decision.admit) return { outcome: 'allow', reason: firstReasonOr(decision, 'auto-admitted within policy and budget') };
  if (decision.releaseGuardianShare) return { outcome: 'step-up', reason: firstReasonOr(decision, 'policy satisfied but a co-signature is required') };
  return { outcome: 'deny', reason: firstReasonOr(decision, 'policy did not release authority (default-deny)') };
}

function buildHops(chain: Capability[]): DelegationHopView[] {
  const hops: DelegationHopView[] = [];
  for (let i = 0; i < chain.length; i++) {
    const cap = chain[i];
    if (!cap) continue;
    const parent = i > 0 ? chain[i - 1] : undefined;
    const parentLen = parent && Array.isArray(parent.caveats) ? parent.caveats.length : 0;
    const ownLen = Array.isArray(cap.caveats) ? cap.caveats.length : 0;
    const added = i === 0 ? ownLen : Math.max(0, ownLen - parentLen);
    hops.push({ index: i, isRoot: i === 0, issuer: str(cap.issuer, '(none)'), holder: str(cap.holder, '(none)'), addedCaveats: added });
  }
  return hops;
}

function readOverride(threshold: ThresholdSignature | undefined): { humanApproved: boolean; approvers: string[]; guardianCosigners: string[]; roles: SignerRole[] } {
  const shares: ThresholdShare[] = threshold && Array.isArray(threshold.shares) ? threshold.shares : [];
  const approvers: string[] = [];
  const guardianCosigners: string[] = [];
  const roles: SignerRole[] = [];
  for (const s of shares) {
    if (!s || typeof s.role !== 'string') continue;
    roles.push(s.role);
    if (s.role === 'principal' && typeof s.publicKey === 'string') approvers.push(s.publicKey);
    if (s.role === 'guardian' && typeof s.publicKey === 'string') guardianCosigners.push(s.publicKey);
  }
  return { humanApproved: approvers.length > 0, approvers, guardianCosigners, roles };
}

function severityFor(outcome: SiemOutcome, checks: Record<string, CheckStatus>, tier: 1 | 2 | 3 | undefined): Severity {
  if (outcome === 'deny') {
    const securityFailure = SECURITY_CHECKS.some((k) => checks[k] === 'fail');
    return securityFailure ? SEV_HIGH : SEV_MEDIUM;
  }
  if (outcome === 'step-up') return SEV_MEDIUM;
  // allow — scale with the co-sign tier the action required.
  return tier === 3 ? SEV_MEDIUM : tier === 2 ? SEV_LOW : SEV_INFO;
}

/** One total pass: extract everything the exporters need. Never throws; degrades to best-effort values. */
function normalize(record: PcaDecisionRecord): Normalized {
  const p = record.pcactn;
  const verify: VerifyResult = record.verify ?? { allow: false, checks: {} };
  const checks: Record<string, CheckStatus> = verify.checks ?? {};
  const now = finiteNum(record.now) ?? Date.now();
  const chain: Capability[] = Array.isArray(p?.cap_chain) ? (p.cap_chain as CapabilityChain) : [];
  const hops = buildHops(chain);
  const leaf = chain.length > 0 ? chain[chain.length - 1] : undefined;
  const root = chain.length > 0 ? chain[0] : undefined;

  const { outcome, reason } = resolveOutcome(verify, record.decision);
  const tier = record.decision?.requiredThreshold?.t;
  const override = readOverride(p?.threshold);

  const grantRef = str(p?.grant_ref, '(none)');
  const agentHolder = str(leaf?.holder, '(none)');
  const principal = typeof root?.issuer === 'string' && root.issuer.length > 0 ? root.issuer : undefined;

  const chainString = [principal ?? '(principal?)', ...hops.map((h) => h.holder)].map((k) => shortKey(k)).join(' -> ');

  return {
    now,
    outcome,
    reason,
    proofVerified: verify.allow === true,
    cryptographicallyVerifiable: checks.wire === 'pass' && checks.leaf_signature === 'pass',
    checks,
    agentHolder,
    principal,
    session: str(record.session, grantRef),
    hops,
    depth: hops.length > 0 ? hops.length - 1 : 0,
    chainString,
    verb: str(p?.action?.verb, '(unknown verb)'),
    resource: str(p?.action?.resource, '(unknown resource)'),
    paramsDigest: str(p?.action?.params_digest, '(none)'),
    reversibilityClass: str(p?.action?.reversibility_class, '(unknown)'),
    grantRef,
    counter: finiteNum(p?.counter) ?? -1,
    nonce: typeof p?.nonce === 'string' ? p.nonce : undefined,
    planRoot: str(p?.plan?.root, '(none)'),
    signatureSuite: str(p?.alg, 'ed25519'),
    leafSignature: str(p?.sig, '(unsigned)'),
    proofDigest: safeDigest(p),
    riskScore: finiteNum(record.decision?.r),
    tier,
    proofStrength: record.decision?.requiredThreshold?.proof,
    caution: finiteNum(p?.caution),
    bondRef: typeof p?.bond_ref === 'string' ? p.bond_ref : undefined,
    humanApproved: override.humanApproved,
    approvers: override.approvers,
    guardianCosigners: override.guardianCosigners,
    roles: override.roles,
    severity: severityFor(outcome, checks, tier),
    iat: finiteNum(p?.iat) ?? now,
    exp: finiteNum(p?.exp) ?? now,
  };
}

/** Drop keys whose value is `undefined` so serialized events stay clean. */
function prune<T extends Record<string, unknown>>(obj: T): T {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (v !== undefined) out[k] = v;
  }
  return out as T;
}

/** The PCA-specific block every schema carries verbatim (the cryptographic edge). */
function pcaExtensions(n: Normalized): Record<string, unknown> {
  return prune({
    proof_digest: n.proofDigest,
    leaf_signature: n.leafSignature,
    signature_suite: n.signatureSuite,
    cryptographically_verifiable: n.cryptographicallyVerifiable,
    plan_root: n.planRoot,
    params_digest: n.paramsDigest,
    grant_ref: n.grantRef,
    counter: n.counter,
    nonce: n.nonce,
    reversibility_class: n.reversibilityClass,
    risk_score: n.riskScore,
    risk_tier: n.tier,
    required_proof: n.proofStrength,
    caution: n.caution,
    bond_ref: n.bondRef,
    delegation_depth: n.depth,
    delegation_chain: n.hops.map((h) => ({ index: h.index, is_root: h.isRoot, issuer: h.issuer, holder: h.holder, added_caveats: h.addedCaveats })),
    checks: n.checks,
    human_override: n.humanApproved
      ? { human_approved: true, approvers: n.approvers, guardian_cosigners: n.guardianCosigners, roles: n.roles }
      : undefined,
  });
}

// =================================================================================================
// OCSF 1.x — Identity & Access Management › Authorize Session (class_uid 3003)
// =================================================================================================

/** PCA → OCSF `activity_id` for the Authorize Session class. The task's allow/deny disposition on activity. */
const OCSF_ACTIVITY = {
  allow: { id: 1, name: 'Allow' },
  deny: { id: 2, name: 'Deny' },
  'step-up': { id: 3, name: 'Step-Up' },
} as const;

/** OCSF `action_id` — the canonical normalized disposition on the base event. */
const OCSF_ACTION = {
  allow: { id: 1, name: 'Allowed' },
  deny: { id: 2, name: 'Denied' },
  'step-up': { id: 99, name: 'Other' },
} as const;

const OCSF_CATEGORY_UID = 3; // Identity & Access Management
const OCSF_CLASS_UID = 3003; // Authorize Session
const OCSF_SCHEMA_VERSION = '1.1.0';

export interface OcsfAuthorizeSessionEvent {
  /** OCSF schema version marker for consumers. */
  activity_id: number;
  activity_name: string;
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
  /** `class_uid * 100 + activity_id` (OCSF type_uid rule). */
  type_uid: number;
  type_name: string;
  /** Canonical allow/deny disposition (OCSF base event). */
  action_id: number;
  action: string;
  severity_id: number;
  severity: string;
  status_id: number;
  status: string;
  status_detail: string;
  /** Event occurrence time (epoch ms). */
  time: number;
  /** The acting agent + the authorizing principal. */
  actor: {
    user: { type_id: number; type: string; uid: string; name: string };
    /** The authorizing principal (root of the capability chain). */
    invoked_by: string;
    session: { uid: string; issuer: string | undefined };
    app_name: string;
  };
  /** The entity whose session/privileges were authorized — the authorizing principal (OCSF subject). */
  user: { type_id: number; type: string; uid: string; name: string };
  /** The resource the action targets. */
  resources: { type: string; name: string; uid: string }[];
  /** The API-style operation (the action verb). */
  api: { operation: string; service: { name: string } };
  metadata: {
    version: string;
    product: { name: string; vendor_name: string; version: string };
    logged_time: number;
    uid: string;
    labels: string[];
  };
  observables: { name: string; type: string; type_id: number; value: string }[];
  count: number;
  message: string;
  /** PCA-specifics that have no first-class OCSF home (proof digest, risk tier, delegation chain, …). */
  unmapped: Record<string, unknown>;
}

/**
 * Map a PCA decision to an OCSF 1.x **Authorize Session** event (Identity & Access Management, category
 * 3, class 3003). `activity_id` carries the allow / deny / step-up disposition; `action_id` carries the
 * OCSF-canonical Allowed / Denied; `status` reflects success / failure; `actor` names the agent AND the
 * authorizing principal; `resources` / `api` describe what was acted on; `metadata.product.name = "PCA"`;
 * and `unmapped` carries the PCA-specifics — the cryptographic proof digest, the risk tier, and the full
 * delegation chain — so the SIEM record stays verifiable.
 */
export function toOcsfEvent(record: PcaDecisionRecord): OcsfAuthorizeSessionEvent {
  const n = normalize(record);
  const activity = OCSF_ACTIVITY[n.outcome];
  const action = OCSF_ACTION[n.outcome];
  const className = 'Authorize Session';
  const status =
    n.outcome === 'allow'
      ? { id: 1, name: 'Success', detail: n.reason }
      : n.outcome === 'deny'
        ? { id: 2, name: 'Failure', detail: n.reason }
        : { id: 99, name: 'Other', detail: `step-up / co-signature required: ${n.reason}` };

  return {
    activity_id: activity.id,
    activity_name: activity.name,
    category_uid: OCSF_CATEGORY_UID,
    category_name: 'Identity & Access Management',
    class_uid: OCSF_CLASS_UID,
    class_name: className,
    type_uid: OCSF_CLASS_UID * 100 + activity.id,
    type_name: `${className}: ${activity.name}`,
    action_id: action.id,
    action: action.name,
    severity_id: n.severity.id,
    severity: n.severity.name,
    status_id: status.id,
    status: status.name,
    status_detail: status.detail,
    time: n.iat,
    actor: {
      user: { type_id: 99, type: 'Agent', uid: n.agentHolder, name: shortKey(n.agentHolder) },
      invoked_by: n.principal ?? '(none)',
      session: { uid: n.session, issuer: n.principal },
      app_name: 'PCA',
    },
    user: { type_id: 1, type: 'User', uid: n.principal ?? '(none)', name: shortKey(n.principal) },
    resources: [{ type: 'pca.resource', name: n.resource, uid: n.resource }],
    api: { operation: n.verb, service: { name: 'PCA' } },
    metadata: {
      version: OCSF_SCHEMA_VERSION,
      product: { name: 'PCA', vendor_name: 'Atlas', version: OCSF_SCHEMA_VERSION },
      logged_time: n.now,
      uid: n.proofDigest,
      labels: ['pca', `outcome:${n.outcome}`, `suite:${n.signatureSuite}`],
    },
    observables: [
      { name: 'actor.user.uid', type: 'User Name', type_id: 4, value: n.agentHolder },
      { name: 'pca.proof.digest', type: 'Hash', type_id: 8, value: n.proofDigest },
      { name: 'resources.uid', type: 'Resource UID', type_id: 10, value: n.resource },
    ],
    count: 1,
    message: narrative(n),
    unmapped: pcaExtensions(n),
  };
}

// =================================================================================================
// ArcSight CEF — `CEF:0|Atlas|PCA|<ver>|<signatureId>|<name>|<sev>|ext...`
// =================================================================================================

const CEF_VERSION = 0;
const CEF_VENDOR = 'Atlas';
const CEF_PRODUCT = 'PCA';

/** Escape a CEF HEADER field: backslash and pipe are reserved. */
function cefHeaderEscape(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

/** Escape a CEF EXTENSION VALUE: backslash, equals and newlines are reserved (keys never contain spaces). */
function cefExtValueEscape(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r\n|\r|\n/g, '\\n');
}

/** Render an ordered extension map as `k=v` pairs with CEF value escaping. Undefined values are dropped. */
function cefExtension(pairs: [string, string | number | boolean | undefined][]): string {
  const out: string[] = [];
  for (const [k, v] of pairs) {
    if (v === undefined) continue;
    out.push(`${k}=${cefExtValueEscape(String(v))}`);
  }
  return out.join(' ');
}

/**
 * Map a PCA decision to a single ArcSight **CEF** line:
 * `CEF:0|Atlas|PCA|<wireVer>|pca-authz-<outcome>|<name>|<sev>|ext...`. The extension carries the standard
 * CEF keys where they fit (`act`, `suser`, `duser`, `outcome`, `rt`, `start`, `end`, `msg`) plus the PCA
 * edge as custom string/number fields: the cryptographic proof digest (`cs1`), the full delegation chain
 * (`cs2`), the risk tier / proof strength, and the delegation depth.
 */
export function toCef(record: PcaDecisionRecord): string {
  const n = normalize(record);
  const wireVer = finiteNum(record.pcactn?.ver);
  const deviceVersion = wireVer !== undefined ? String(wireVer) : '2';
  const signatureId = `pca-authz-${n.outcome}`;
  const name = `PCA authorization ${n.outcome}: ${n.verb} on ${n.resource}`;

  const header = [
    `CEF:${CEF_VERSION}`,
    cefHeaderEscape(CEF_VENDOR),
    cefHeaderEscape(CEF_PRODUCT),
    cefHeaderEscape(deviceVersion),
    cefHeaderEscape(signatureId),
    cefHeaderEscape(name),
    String(n.severity.cef),
  ].join('|');

  const ext = cefExtension([
    ['act', n.outcome],
    ['outcome', n.outcome],
    ['suser', n.principal ?? '(none)'],
    ['suid', n.principal ?? '(none)'],
    ['duser', n.agentHolder],
    ['duid', n.agentHolder],
    ['destinationServiceName', n.verb],
    ['rt', n.now],
    ['start', n.iat],
    ['end', n.exp],
    ['externalId', n.nonce ?? String(n.counter)],
    ['request', n.resource],
    ['requestMethod', n.verb],
    // PCA edge — custom string (cs) + number (cn) fields, each with its label.
    ['cs1Label', 'pcaProofDigest'],
    ['cs1', n.proofDigest],
    ['cs2Label', 'pcaDelegationChain'],
    ['cs2', n.chainString],
    ['cs3Label', 'pcaProofStrength'],
    ['cs3', n.proofStrength ?? 'n/a'],
    ['cs4Label', 'pcaSignatureSuite'],
    ['cs4', n.signatureSuite],
    ['cs5Label', 'pcaVerifyChecks'],
    ['cs5', Object.entries(n.checks).map(([k, v]) => `${k}:${v}`).join(';')],
    ['cs6Label', 'pcaGrantRef'],
    ['cs6', n.grantRef],
    ['cn1Label', 'pcaRiskScore'],
    ['cn1', n.riskScore ?? ''],
    ['cn2Label', 'pcaDelegationDepth'],
    ['cn2', n.depth],
    ['cn3Label', 'pcaRiskTier'],
    ['cn3', n.tier ?? ''],
    ['flexString1Label', 'pcaHumanApproved'],
    ['flexString1', n.humanApproved ? 'true' : 'false'],
    ['cat', 'authorization'],
    ['msg', n.reason],
  ]);

  return `${header}|${ext}`;
}

// =================================================================================================
// Elastic Common Schema (ECS)
// =================================================================================================

const ECS_VERSION = '8.11.0';

/** ECS `event.type` keyword(s) for the disposition. */
const ECS_EVENT_TYPE: Record<SiemOutcome, string[]> = {
  allow: ['allowed'],
  deny: ['denied'],
  'step-up': ['info'],
};

/** ECS `event.outcome` keyword for the disposition. */
const ECS_OUTCOME: Record<SiemOutcome, 'success' | 'failure' | 'unknown'> = {
  allow: 'success',
  deny: 'failure',
  'step-up': 'unknown',
};

export interface EcsEvent {
  '@timestamp': string;
  'ecs.version': string;
  event: {
    kind: 'event';
    category: string[];
    type: string[];
    action: string;
    outcome: 'success' | 'failure' | 'unknown';
    module: string;
    dataset: string;
    provider: string;
    id: string;
    severity: number;
    reason: string;
    risk_score?: number;
  };
  /** The acting agent. */
  user: {
    id: string;
    name: string;
    roles: string[];
    /** The authority actually exercised — the authorizing principal. */
    effective: { id: string; name: string };
  };
  service: { name: string; type: string };
  related: {
    /** Every identity in the event, for correlation (agent + principal + approvers). */
    user: string[];
    /** The cryptographic proof digest + leaf signature, for correlation. */
    hash: string[];
  };
  message: string;
  /** PCA-specifics under a dedicated namespace (proof digest, risk tier, delegation chain, …). */
  pca: Record<string, unknown>;
}

/**
 * Map a PCA decision to an **Elastic Common Schema** event. `event.category = ['iam']`,
 * `event.type = ['allowed' | 'denied' | 'info']`, `event.outcome = success | failure | unknown`;
 * `event.action` is the PCA action verb; `user` is the acting agent with `user.effective` = the
 * authorizing principal; `related.user` and `related.hash` carry every identity and the proof digest
 * for correlation; and the PCA edge (proof digest, risk tier, full delegation chain) lives under `pca.*`.
 */
export function toEcs(record: PcaDecisionRecord): EcsEvent {
  const n = normalize(record);
  const relatedUsers = [n.agentHolder, ...(n.principal ? [n.principal] : []), ...n.approvers].filter((v, i, a) => a.indexOf(v) === i);
  const relatedHashes = [n.proofDigest, n.leafSignature].filter((v, i, a) => a.indexOf(v) === i);

  const event: EcsEvent['event'] = {
    kind: 'event',
    category: ['iam'],
    type: ECS_EVENT_TYPE[n.outcome],
    action: n.verb,
    outcome: ECS_OUTCOME[n.outcome],
    module: 'pca',
    dataset: 'pca.authorization',
    provider: 'pca',
    id: n.proofDigest,
    severity: n.severity.cef,
    reason: n.reason,
    ...(n.riskScore !== undefined ? { risk_score: n.riskScore } : {}),
  };

  return {
    '@timestamp': isoOf(n.iat),
    'ecs.version': ECS_VERSION,
    event,
    user: {
      id: n.agentHolder,
      name: shortKey(n.agentHolder),
      roles: ['agent'],
      effective: { id: n.principal ?? '(none)', name: shortKey(n.principal) },
    },
    service: { name: 'pca', type: 'authorization' },
    related: { user: relatedUsers, hash: relatedHashes },
    message: narrative(n),
    pca: prune({
      outcome: n.outcome,
      proof: prune({ digest: n.proofDigest, leaf_signature: n.leafSignature, signature_suite: n.signatureSuite, cryptographically_verifiable: n.cryptographicallyVerifiable, plan_root: n.planRoot, params_digest: n.paramsDigest }),
      risk: prune({ score: n.riskScore, tier: n.tier, required_proof: n.proofStrength, caution: n.caution }),
      delegation: { depth: n.depth, chain: n.chainString, hops: n.hops },
      grant_ref: n.grantRef,
      counter: n.counter,
      nonce: n.nonce,
      reversibility_class: n.reversibilityClass,
      bond_ref: n.bondRef,
      checks: n.checks,
      human_override: n.humanApproved ? { human_approved: true, approvers: n.approvers, guardian_cosigners: n.guardianCosigners, roles: n.roles } : undefined,
    }),
  };
}

function isoOf(epochMs: number): string {
  if (!Number.isFinite(epochMs)) return new Date(0).toISOString();
  try {
    return new Date(epochMs).toISOString();
  } catch {
    return new Date(0).toISOString();
  }
}

/** One-sentence plain-English narration of the whole event (shared across schemas). */
function narrative(n: Normalized): string {
  const word = n.outcome === 'allow' ? 'ALLOWED' : n.outcome === 'deny' ? 'DENIED' : 'STEP-UP';
  return (
    `Agent ${shortKey(n.agentHolder)} ${word} to ${n.verb} on ${n.resource} ` +
    `(${n.hops.length}-hop chain rooted at principal ${shortKey(n.principal)}; ` +
    `${n.cryptographicallyVerifiable ? 'cryptographically verifiable proof' : 'proof not cryptographically verifiable'}` +
    `${n.humanApproved ? '; human-signed step-up' : ''}). ${n.reason}`
  );
}

// =================================================================================================
// Sinks — pluggable delivery, batched, fail-safe
// =================================================================================================

export type SiemFormat = 'ocsf' | 'cef' | 'ecs';

/** A single serialized event ready to ship: the structured object (OCSF / ECS) plus a one-line payload. */
export interface SiemEvent {
  format: SiemFormat;
  /** The structured object for OCSF / ECS; undefined for the CEF string line. */
  object?: OcsfAuthorizeSessionEvent | EcsEvent;
  /** One line ready to POST: NDJSON (`JSON.stringify`) for OCSF / ECS, the CEF line for CEF. */
  line: string;
}

export interface SinkResult {
  ok: boolean;
  error?: string;
}

/**
 * A pluggable SIEM destination. `format` is the schema it expects; `deliver` ships a batch of
 * already-serialized events and returns a result. A sink SHOULD NOT throw — the exporters guard against
 * it regardless — and MUST NOT block the caller's authorization path.
 */
export interface SiemSink {
  readonly name: string;
  readonly format: SiemFormat;
  deliver(events: readonly SiemEvent[]): SinkResult | Promise<SinkResult>;
}

/** Serialize a decision record into the given schema, as a shippable {@link SiemEvent}. */
export function formatDecision(record: PcaDecisionRecord, format: SiemFormat): SiemEvent {
  if (format === 'cef') {
    return { format, line: toCef(record) };
  }
  const object: OcsfAuthorizeSessionEvent | EcsEvent = format === 'ocsf' ? toOcsfEvent(record) : toEcs(record);
  return { format, object, line: JSON.stringify(object) };
}

const CONTENT_TYPE: Record<SiemFormat, string> = {
  ocsf: 'application/x-ndjson',
  ecs: 'application/x-ndjson',
  cef: 'text/plain; charset=utf-8',
};

/** The minimal shape of a `fetch` response this package reads — so any fetch (global or injected) fits. */
export interface FetchLikeResponse {
  ok: boolean;
  status: number;
  statusText?: string;
}

/** An injectable `fetch`: the global one by default, or a mock in tests. */
export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<FetchLikeResponse>;

export interface HttpSinkOptions {
  format: SiemFormat;
  /** Extra headers (e.g. Splunk `Authorization: Splunk <token>`, a Datadog `DD-API-KEY`). */
  headers?: Record<string, string>;
  /** Injectable fetch; defaults to `globalThis.fetch`. */
  fetch?: FetchLike;
  /** Override the Content-Type (default: NDJSON for ocsf/ecs, text/plain for cef). */
  contentType?: string;
  /** Sink name for diagnostics (default `http:<format>`). */
  name?: string;
}

/**
 * An HTTP sink that batches events into one POST — NDJSON for OCSF / ECS (the Elastic `_bulk` / Datadog
 * intake / Splunk-HEC line shape), the raw CEF lines for CEF. The body is `events.map(e => e.line)`
 * joined by newlines. The `fetch` is injectable (default `globalThis.fetch`). Delivery NEVER throws:
 * a network error or a non-2xx status is caught and returned as `{ ok: false, error }`.
 */
export function httpSink(url: string, options: HttpSinkOptions): SiemSink {
  const format = options.format;
  const name = options.name ?? `http:${format}`;
  return {
    name,
    format,
    async deliver(events: readonly SiemEvent[]): Promise<SinkResult> {
      try {
        const doFetch = options.fetch ?? resolveGlobalFetch();
        if (!doFetch) return { ok: false, error: 'no fetch implementation available (pass options.fetch)' };
        const body = events.map((e) => e.line).join('\n');
        const headers: Record<string, string> = { 'content-type': options.contentType ?? CONTENT_TYPE[format], ...(options.headers ?? {}) };
        const res = await doFetch(url, { method: 'POST', headers, body });
        if (res.ok) return { ok: true };
        return { ok: false, error: `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ''}` };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
  };
}

function resolveGlobalFetch(): FetchLike | undefined {
  // The ES2022 lib does not declare `fetch`, so reach it structurally through globalThis. FetchLike is a
  // broad superset of the real fetch signature (any extra response fields are simply ignored here).
  const g = globalThis as { fetch?: FetchLike };
  return typeof g.fetch === 'function' ? g.fetch : undefined;
}

export interface ConsoleSinkOptions {
  /** Schema to serialize to (default `ocsf`). */
  format?: SiemFormat;
  /** Where lines go (default `console.log`). */
  logger?: (line: string) => void;
  name?: string;
}

/** A sink that writes each event's serialized line to a logger (default `console.log`). Never throws. */
export function consoleSink(options: ConsoleSinkOptions = {}): SiemSink {
  const format = options.format ?? 'ocsf';
  const logger = options.logger ?? ((line: string) => console.log(line));
  return {
    name: options.name ?? `console:${format}`,
    format,
    deliver(events: readonly SiemEvent[]): SinkResult {
      try {
        for (const e of events) logger(e.line);
        return { ok: true };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
  };
}

// =================================================================================================
// Export orchestration — fail-safe: a sink error never reaches the caller's auth path
// =================================================================================================

export interface ExportOptions {
  /** Called (log + drop) when delivery fails. Wrapped so it can never throw back into the caller. */
  onError?: (error: Error, context: { sink: string; count: number }) => void;
}

export interface ExportResult {
  ok: boolean;
  /** How many events the sink accepted (0 on any failure). */
  delivered: number;
  format: SiemFormat;
  error?: string;
}

function safeOnError(options: ExportOptions | undefined, error: Error, sink: string, count: number): void {
  const cb = options?.onError;
  if (!cb) return;
  try {
    cb(error, { sink, count });
  } catch {
    // An onError that itself throws must not escape — the whole point is to never touch the auth path.
  }
}

/**
 * Export one PCA decision to a sink. Fail-safe: formatting or delivery errors are caught, reported via
 * `onError` (log + drop), and returned as `{ ok: false, error }` — they NEVER throw into the caller.
 */
export async function exportDecision(record: PcaDecisionRecord, sink: SiemSink, options?: ExportOptions): Promise<ExportResult> {
  return exportBatch([record], sink, options);
}

/**
 * Export a batch of PCA decisions to a sink in ONE delivery (serialized in the sink's format). Fail-safe,
 * exactly like {@link exportDecision}: an error anywhere — serialization or delivery — is caught, reported,
 * and returned as a result, never thrown.
 */
export async function exportBatch(records: readonly PcaDecisionRecord[], sink: SiemSink, options?: ExportOptions): Promise<ExportResult> {
  const format = sink.format;
  let count = 0;
  try {
    const events = records.map((r) => formatDecision(r, format));
    count = events.length;
    const res = await sink.deliver(events);
    if (res.ok) return { ok: true, delivered: events.length, format };
    const err = new Error(res.error ?? 'sink reported a delivery failure');
    safeOnError(options, err, sink.name, events.length);
    return { ok: false, delivered: 0, format, error: err.message };
  } catch (e) {
    const err = e instanceof Error ? e : new Error(String(e));
    safeOnError(options, err, sink?.name ?? '(unknown sink)', count);
    return { ok: false, delivered: 0, format, error: err.message };
  }
}
