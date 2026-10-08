/**
 * `@atlasauth/pca-explain` — make PCA decisions self-explaining.
 *
 * A proof-carrying action is a cryptographic object: when it is allowed you want to know WHICH
 * capability granted it and under what bound; when it is denied you want the ONE decisive reason and a
 * concrete fix — not a boolean. This package turns the core verifier's {@link VerifyResult} (the eight
 * normative checks) and the Policy VM's {@link PolicyDecision} (predicate / caveat / risk / budget) into
 * a precise, human-readable proof-trace, plus an ordered attenuation trace for a delegation chain.
 *
 * Everything here is PURE and READ-ONLY: it consumes the REAL shapes from `@atlasauth/pca`, never
 * re-authorizes anything, and never throws (a malformed input degrades to a best-effort explanation).
 */

import {
  type PCActn,
  type VerifyResult,
  type CheckStatus,
  type PolicyDecision,
  type Envelope,
  type Predicate,
  type Condition,
  type Caveat,
  type Capability,
  type CapabilityChain,
  type ActionContext,
  type CaveatContext,
  type RequiredThreshold,
  type TrustBudget,
  type BudgetAllocNode,
  PCACTN_VERSION,
  PCACTN_MAX_LIFETIME_MS,
  PCACTN_MAX_SKEW_MS,
  verifyChain,
  evaluatePredicates,
  evaluateAgentCaveats,
  budgetAllocNodes,
  isBudgetAllocCaveat,
  cost as budgetCost,
} from '@atlasauth/pca';

export type Verdict = 'allow' | 'deny';

// ---- shared helpers -------------------------------------------------------------------------------

/** Abbreviate a long b64u key for display: first `n` chars + an ellipsis. */
function short(key: unknown, n = 10): string {
  if (typeof key !== 'string' || key.length === 0) return '<none>';
  return key.length <= n + 1 ? key : `${key.slice(0, n)}…`;
}

/** Compact number: integers stay integers, fractions round to 4 dp (trailing zeros trimmed). */
function num(x: unknown): string {
  if (typeof x !== 'number' || !Number.isFinite(x)) return String(x);
  if (Number.isInteger(x)) return String(x);
  return String(Math.round(x * 1e4) / 1e4);
}

/** A one-line, bounded rendering of a caveat's non-`type` fields (the "offending value"). */
function valueSummary(rest: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const k of Object.keys(rest).slice(0, 6)) {
    const v = rest[k];
    parts.push(`${k}=${typeof v === 'object' && v !== null ? JSON.stringify(v) : num(v)}`);
  }
  return parts.join(', ');
}

/** Split a caveat into its type tag and the rest of its fields. */
function caveatParts(cv: Caveat): { type: string; rest: Record<string, unknown> } {
  const type = typeof cv?.type === 'string' ? cv.type : '<malformed>';
  const rest: Record<string, unknown> = {};
  if (cv !== null && typeof cv === 'object') {
    for (const k of Object.keys(cv)) if (k !== 'type') rest[k] = (cv as Record<string, unknown>)[k];
  }
  return { type, rest };
}

/** Compact, depth-bounded rendering of a `where` condition (leaf or boolean grouping). */
function condToText(c: Condition, depth = 0): string {
  if (c === null || typeof c !== 'object') return '<malformed>';
  if (depth > 6) return '…';
  if ('all_of' in c && Array.isArray(c.all_of)) return `(${c.all_of.map((x) => condToText(x, depth + 1)).join(' AND ')})`;
  if ('any_of' in c && Array.isArray(c.any_of)) return `(${c.any_of.map((x) => condToText(x, depth + 1)).join(' OR ')})`;
  if ('not' in c) return `NOT ${condToText(c.not, depth + 1)}`;
  const leaf = c as { field?: unknown; op?: unknown; value?: unknown; ref?: unknown };
  const operand = leaf.ref !== undefined ? `→${String(leaf.ref)}` : 'value' in leaf ? num(leaf.value) : '';
  return `${String(leaf.field)} ${String(leaf.op)} ${operand}`.trim();
}

function whereSummary(where: Condition[] | undefined): string {
  if (!Array.isArray(where) || where.length === 0) return 'any (no where-bound)';
  return where.map((c) => condToText(c)).join(' AND ');
}

// =================================================================================================
// explainVerification — walk the eight normative checks
// =================================================================================================

/** The eight checks the offline verifier (`verifyPCActnCore`) evaluates, in NORMATIVE order. */
export const VERIFY_CHECK_ORDER = [
  'wire',
  'version',
  'audience',
  'validity',
  'cap_chain',
  'plan_inclusion',
  'leaf_signature',
  'counter',
] as const;
export type VerifyCheckName = (typeof VERIFY_CHECK_ORDER)[number];

const CHECK_TITLE: Record<string, string> = {
  wire: 'wire format',
  version: 'version',
  audience: 'audience binding',
  validity: 'freshness window',
  cap_chain: 'capability chain',
  plan_inclusion: 'plan inclusion',
  leaf_signature: 'leaf signature',
  counter: 'counter',
  plan_root_authorized: 'plan-root authorization',
  taint_gate: 'taint gate',
  attestation: 'agent attestation',
  threshold: 'threshold signature',
  revocation: 'revocation',
  zk_compliance: 'zk compliance',
  bond: 'bond',
  malformed: 'structure',
};

/** Status of a check as presented: the core statuses plus `skipped` (a terminal earlier failure stopped evaluation). */
export type PresentedStatus = CheckStatus | 'skipped';

export interface CheckExplanation {
  name: string;
  status: PresentedStatus;
  title: string;
  /** What held (pass) or precisely what failed (fail), with concrete values from the PCActn. */
  detail: string;
  /** Present on the decisive failing check: a concrete fix. */
  remedy?: string;
  /** The hop index a hop-specific failure (chain / leaf signature) points at. */
  hop?: number;
  /** True for the FIRST failing check (the one that determined the verdict). */
  decisive?: boolean;
}

function reasonTail(name: string, verifyResult: VerifyResult): string | undefined {
  const r = verifyResult.reason;
  if (typeof r !== 'string') return undefined;
  const pre = `${name}: `;
  return r.startsWith(pre) ? r.slice(pre.length) : undefined;
}

function validityPinpoint(p: PCActn, now: number | undefined): { detail: string; remedy: string } {
  const lifetime = p.exp - p.iat;
  if (!(p.exp > p.iat)) {
    return { detail: `exp ${p.exp} ≤ iat ${p.iat}: empty validity window`, remedy: 'set exp strictly greater than iat.' };
  }
  if (lifetime > PCACTN_MAX_LIFETIME_MS) {
    return {
      detail: `lifetime ${lifetime}ms exceeds the ${PCACTN_MAX_LIFETIME_MS}ms maximum`,
      remedy: `shorten the window to ≤ ${PCACTN_MAX_LIFETIME_MS}ms (buildPCActn ttlMs).`,
    };
  }
  if (now !== undefined) {
    if (p.iat > now + PCACTN_MAX_SKEW_MS) {
      return {
        detail: `iat ${p.iat} is ${p.iat - now}ms in the future (> ${PCACTN_MAX_SKEW_MS}ms clock-skew allowance)`,
        remedy: 'fix the signer clock; do not pre-date actions.',
      };
    }
    if (now > p.exp) {
      return {
        detail: `expired ${now - p.exp}ms ago (exp ${p.exp}, now ${now})`,
        remedy: 'build a fresh action — a PCActn lifetime is short by design.',
      };
    }
  }
  return { detail: 'validity window invalid', remedy: 'build a fresh action with a valid iat/exp window.' };
}

function capChainPinpoint(p: PCActn): { detail: string; remedy: string; hop?: number } {
  const chain = p.cap_chain;
  const res = Array.isArray(chain) ? verifyChain(chain) : { ok: false, reason: 'cap_chain is not an array' };
  const reason = res.ok ? 'chain root is not the grant this verifier expects' : (res.reason ?? 'capability chain invalid');
  let hop: number | undefined;
  const m = /hop (\d+)/.exec(reason);
  if (m && m[1] !== undefined) hop = Number(m[1]);
  let remedy = 'rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats.';
  if (reason.includes('root issuer') || reason.includes('not the grant')) {
    remedy = 'root the chain at the principal key that minted the grant.';
  } else if (reason.includes('widens')) {
    remedy = 'a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation.';
  } else if (reason.includes('caveat')) {
    remedy = 'attenuation is append-only: never drop, reorder or edit a parent caveat.';
  } else if (reason.includes('signature')) {
    remedy = 're-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite).';
  }
  return hop === undefined ? { detail: reason, remedy } : { detail: reason, remedy, hop };
}

function leafSigPinpoint(p: PCActn): { detail: string; remedy: string; hop?: number } {
  const chain = p.cap_chain;
  const idx = Array.isArray(chain) ? chain.length - 1 : -1;
  const leaf = idx >= 0 ? chain[idx] : undefined;
  const alg = p.alg ?? 'ed25519';
  const remedy =
    'sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to match the holder.';
  if (!leaf) return { detail: 'no leaf capability to check the signature against (empty/invalid chain)', remedy };
  const base = { detail: `leaf hop #${idx} signature (holder ${short(leaf.holder)}, suite ${alg}) does not verify`, remedy };
  return idx >= 0 ? { ...base, hop: idx } : base;
}

/** Pinpoint the decisive (first failing) check with a concrete detail + remedy. */
function pinpoint(name: string, p: PCActn, verifyResult: VerifyResult, now: number | undefined): { detail: string; remedy: string; hop?: number } {
  const tail = reasonTail(name, verifyResult);
  switch (name) {
    case 'wire':
      return { detail: tail ?? 'wire structure / strict-canonical-form check failed', remedy: 'do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK.' };
    case 'version':
      return { detail: tail ?? `unsupported ver ${num(p.ver)} (verifier requires ${PCACTN_VERSION})`, remedy: `re-mint the action at wire version ${PCACTN_VERSION}.` };
    case 'audience':
      return { detail: tail ?? `aud ${JSON.stringify(p.aud)} does not match this resource server / instance`, remedy: 'build the action with aud = this verifier’s instance id (or verify with audience:null to accept any).' };
    case 'validity': {
      const v = validityPinpoint(p, now);
      return { detail: tail ?? v.detail, remedy: v.remedy };
    }
    case 'cap_chain': {
      const c = capChainPinpoint(p);
      return { detail: tail ?? c.detail, ...(c.hop !== undefined ? { hop: c.hop } : {}), remedy: c.remedy };
    }
    case 'plan_inclusion':
      return {
        detail: tail ?? `action (verb ${JSON.stringify(p.action?.verb)} on ${JSON.stringify(p.action?.resource)}) is not node ${JSON.stringify(p.plan?.node_id)} of committed plan ${short(p.plan?.root)}`,
        remedy: 'rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn).',
      };
    case 'leaf_signature': {
      const l = leafSigPinpoint(p);
      return { detail: tail ?? l.detail, ...(l.hop !== undefined ? { hop: l.hop } : {}), remedy: l.remedy };
    }
    case 'counter':
      return { detail: tail ?? `counter ${num(p.counter)} is missing or not a non-negative safe integer`, remedy: 'use a strictly increasing per-holder counter; a repeated counter is a replay.' };
    case 'malformed':
      return { detail: tail ?? 'the PCActn is structurally malformed', remedy: 'rebuild the action with the SDK; do not construct the wire object by hand.' };
    default:
      return { detail: tail ?? `${name} check failed`, remedy: `satisfy the ${name} requirement (supply the corresponding verifier hook / proof).` };
  }
}

/** What held, for a PASS (concise, with the concrete value from the PCActn). */
function passDetail(name: string, p: PCActn): string {
  switch (name) {
    case 'wire':
      return 'wire structure + strict canonical form valid';
    case 'version':
      return `ver ${num(p.ver)} supported`;
    case 'audience':
      return `aud ${JSON.stringify(p.aud)} matches this resource server`;
    case 'validity':
      return `fresh: iat/exp window valid (lifetime ${num((p.exp - p.iat) / 1000)}s)`;
    case 'cap_chain': {
      const chain = p.cap_chain;
      const len = Array.isArray(chain) ? chain.length : 0;
      const root = Array.isArray(chain) ? chain[0] : undefined;
      return `${len}-hop chain verifies; root issuer ${short(root?.issuer)}`;
    }
    case 'plan_inclusion':
      return `action is node ${JSON.stringify(p.plan?.node_id)} of committed plan ${short(p.plan?.root)}`;
    case 'leaf_signature': {
      const chain = p.cap_chain;
      const leaf = Array.isArray(chain) && chain.length > 0 ? chain[chain.length - 1] : undefined;
      return `leaf holder ${short(leaf?.holder)} signature valid (suite ${p.alg ?? 'ed25519'})`;
    }
    case 'counter':
      return `counter ${num(p.counter)} well-formed`;
    default:
      return 'ok';
  }
}

export class VerificationExplanation {
  readonly kind = 'verification' as const;
  readonly verdict: Verdict;
  readonly allow: boolean;
  readonly checks: CheckExplanation[];
  readonly passed: string[];
  readonly failed: string[];
  readonly notEnforced: string[];
  readonly decisive: CheckExplanation | undefined;
  readonly summary: string;

  constructor(fields: {
    verdict: Verdict;
    allow: boolean;
    checks: CheckExplanation[];
    decisive: CheckExplanation | undefined;
    summary: string;
  }) {
    this.verdict = fields.verdict;
    this.allow = fields.allow;
    this.checks = fields.checks;
    this.passed = fields.checks.filter((c) => c.status === 'pass').map((c) => c.name);
    this.failed = fields.checks.filter((c) => c.status === 'fail').map((c) => c.name);
    this.notEnforced = fields.checks.filter((c) => c.status === 'not-enforced').map((c) => c.name);
    this.decisive = fields.decisive;
    this.summary = fields.summary;
  }

  toText(): string {
    const glyph: Record<PresentedStatus, string> = { pass: '✓', fail: '✗', 'not-enforced': '·', skipped: '–' };
    const lines: string[] = [];
    lines.push(`PCA verification — ${this.verdict.toUpperCase()}`);
    lines.push(this.summary);
    lines.push('');
    for (const c of this.checks) {
      const mark = c.decisive ? ' ◀ DECISIVE' : '';
      lines.push(`  ${glyph[c.status]} ${c.name.padEnd(16)} ${c.detail}${mark}`);
      if (c.decisive && c.remedy) lines.push(`      ↳ fix: ${c.remedy}`);
    }
    return lines.join('\n');
  }
}

/**
 * Explain the offline verification of a PCActn: walk the eight normative checks in order; for each PASS
 * summarize what held, and for the FIRST failing check pinpoint it precisely (which hop's signature,
 * which audience mismatch, which validity sub-case, counter replay, …) with a concrete remedy.
 *
 * `opts.now` (epoch ms) lets the `validity` pinpoint distinguish "expired" from "clock-skew" precisely;
 * omit it and the authoritative `verifyResult.reason` is used instead.
 */
export function explainVerification(pcActn: PCActn, verifyResult: VerifyResult, opts: { now?: number } = {}): VerificationExplanation {
  const statuses = verifyResult?.checks ?? {};
  const seen = new Set<string>();
  const ordered: string[] = [];
  for (const n of VERIFY_CHECK_ORDER) {
    ordered.push(n);
    seen.add(n);
  }
  // Later-milestone / extra checks (plan_root_authorized, taint_gate, attestation, …, malformed) appended.
  for (const n of Object.keys(statuses)) if (!seen.has(n)) ordered.push(n);

  // The decisive check: the first (in normative order) that FAILED.
  let decisiveName: string | undefined;
  for (const n of ordered) {
    if (statuses[n] === 'fail') {
      decisiveName = n;
      break;
    }
  }

  const checks: CheckExplanation[] = [];
  let decisive: CheckExplanation | undefined;
  for (const name of ordered) {
    const raw = statuses[name];
    const status: PresentedStatus = raw ?? 'skipped';
    const title = CHECK_TITLE[name] ?? name;
    let detail: string;
    let remedy: string | undefined;
    let hop: number | undefined;
    if (status === 'fail') {
      const pin = pinpoint(name, pcActn, verifyResult, opts.now);
      detail = pin.detail;
      remedy = pin.remedy;
      hop = pin.hop;
    } else if (status === 'pass') {
      detail = passDetail(name, pcActn);
    } else if (status === 'not-enforced') {
      detail = 'not enforced by this verifier (no hook / opt-out)';
    } else {
      detail = 'not reached (a terminal earlier check stopped evaluation)';
    }
    const entry: CheckExplanation = { name, status, title, detail };
    if (remedy !== undefined) entry.remedy = remedy;
    if (hop !== undefined) entry.hop = hop;
    if (name === decisiveName) {
      entry.decisive = true;
      decisive = entry;
    }
    checks.push(entry);
  }

  const verdict: Verdict = verifyResult?.allow ? 'allow' : 'deny';
  const summary = verdict === 'allow'
    ? `All ${checks.filter((c) => c.status === 'pass').length} evaluated checks passed (no check failed).`
    : decisive
      ? `Denied at the "${decisive.title}" check: ${decisive.detail}`
      : `Denied: ${verifyResult?.reason ?? 'a check failed'}`;

  return new VerificationExplanation({ verdict, allow: !!verifyResult?.allow, checks, decisive, summary });
}

// =================================================================================================
// explainDecision — which capability granted it, which caveat narrowed/denied, risk/tier/budget
// =================================================================================================

export interface GrantExplanation {
  granted: boolean;
  /** The capability that carries the granting predicate (the root grant). */
  capabilityId?: string;
  /** The predicate (in the grant's envelope) that permitted (verb, resource). */
  predicate?: Predicate;
  predicateIndex?: number;
  /** A readable rendering of that predicate's `where` bound. */
  where?: string;
  reason?: string;
}

export interface CaveatOutcome {
  type: string;
  satisfied: boolean;
  /** The caveat's non-`type` fields — the bound it imposes / the offending value. */
  value: Record<string, unknown>;
  detail: string;
  /** Present on a FAILED caveat: a concrete fix. */
  remedy?: string;
  /** True when this caveat came from a delegation hop, not the root grant. */
  delegated: boolean;
}

export interface RiskExplanation {
  r: number;
  tier: 1 | 2 | 3;
  proof: RequiredThreshold['proof'];
  optimisticAllowed: boolean;
  theta1?: number;
  theta2?: number;
  /** Which threshold band r landed in, with the boundary values. */
  band: string;
}

export interface AdmissionExplanation {
  admit: boolean;
  needStepUp: boolean;
  releaseGuardianShare: boolean;
  /** c(A) = κ·r — what a metered action costs against the trust budget (when the risk policy is known). */
  cost?: number;
  kappa?: number;
  /** The trust budget as returned by decide() (post-leak, post-debit if metered + released). */
  budget: TrustBudget;
  /** Human rendering of the admission path taken. */
  path: string;
}

function caveatRemedy(type: string, rest: Record<string, unknown>): string {
  switch (type) {
    case 'expires':
      return `the grant expired at ${num(rest.at)} (epoch ms); obtain a fresh grant or re-mint with a later 'expires'.`;
    case 'not_before':
      return `the grant is not valid until ${num(rest.at)} (epoch ms); retry after that time.`;
    case 'rate':
      return `rate limit ${num(rest.max)}/${num(rest.per_secs)}s reached; wait for the window to clear or raise the 'rate' caveat.`;
    case 'max_blast_radius':
      return `the action's blast radius exceeds the caveat max ${num(rest.max)}; narrow the action or raise 'max_blast_radius'.`;
    case 'reversibility_max':
      return `the action is more severe than the allowed class '${String(rest.class)}'; only that class or lower is permitted.`;
    case 'delegation_depth':
      return `delegation depth exceeds max ${num(rest.max)}; act from a shallower hop or raise 'delegation_depth'.`;
    default:
      return `caveat '${type}' is not satisfied; check its parameters against the action/context.`;
  }
}

function caveatDetail(type: string, rest: Record<string, unknown>, satisfied: boolean): string {
  const bound = valueSummary(rest);
  const verb = satisfied ? 'held' : 'NARROWED/DENIED';
  return bound.length > 0 ? `${type}(${bound}) ${verb}` : `${type} ${verb}`;
}

/** Parse the caveat types decide() reported as failed, from its `reasons` (grant + delegated). */
function failedCaveatTypesFromReasons(reasons: string[]): Set<string> {
  const out = new Set<string>();
  for (const r of reasons) {
    const m = /caveat\(s\) not satisfied: (.+)$/.exec(r);
    if (m && m[1] !== undefined) for (const t of m[1].split(',')) if (t.trim()) out.add(t.trim());
  }
  return out;
}

/** The composite context decide() was given, supplied so the explanation can pinpoint precisely. */
export interface DecisionContext {
  /** The action context (lets `explainDecision` name the granting predicate + evaluate `where`). */
  action?: ActionContext;
  /** The caveat context (now, blastRadius, reversibilityClass, delegationDepth, recentActionTimes). */
  caveat?: CaveatContext;
  /** The delegation chain decide() evaluated — for delegated (post-grant) caveats. */
  chain?: CapabilityChain;
}

function riskBand(r: number, theta1: number | undefined, theta2: number | undefined, tier: 1 | 2 | 3): string {
  if (theta1 === undefined || theta2 === undefined) return `effective tier t=${tier}`;
  if (r <= theta1) return `r ${num(r)} ≤ θ1 ${num(theta1)} → claim band (t=1)`;
  if (r <= theta2) return `θ1 ${num(theta1)} < r ${num(r)} ≤ θ2 ${num(theta2)} → standard band (t=2)`;
  return `r ${num(r)} > θ2 ${num(theta2)} → strong band (t=3)`;
}

export class DecisionExplanation {
  readonly kind = 'decision' as const;
  readonly verdict: Verdict;
  /** auto-admit (no human), step-up (guardian/human co-sign needed), or denied (guardian share withheld). */
  readonly disposition: 'auto-admit' | 'step-up' | 'denied';
  readonly grant: GrantExplanation;
  readonly caveats: CaveatOutcome[];
  readonly risk: RiskExplanation;
  readonly admission: AdmissionExplanation;
  /** The single decisive reason (and remedy) when not auto-admitted. */
  readonly decisive: { reason: string; remedy?: string } | undefined;
  readonly reasons: string[];
  readonly summary: string;

  constructor(fields: {
    verdict: Verdict;
    disposition: 'auto-admit' | 'step-up' | 'denied';
    grant: GrantExplanation;
    caveats: CaveatOutcome[];
    risk: RiskExplanation;
    admission: AdmissionExplanation;
    decisive: { reason: string; remedy?: string } | undefined;
    reasons: string[];
    summary: string;
  }) {
    this.verdict = fields.verdict;
    this.disposition = fields.disposition;
    this.grant = fields.grant;
    this.caveats = fields.caveats;
    this.risk = fields.risk;
    this.admission = fields.admission;
    this.decisive = fields.decisive;
    this.reasons = fields.reasons;
    this.summary = fields.summary;
  }

  toText(): string {
    const lines: string[] = [];
    lines.push(`PCA decision — ${this.verdict.toUpperCase()} (${this.disposition})`);
    lines.push(this.summary);
    lines.push('');

    // Authority
    if (this.grant.granted && this.grant.predicate) {
      const p = this.grant.predicate;
      const verbs = Array.isArray(p.verb) ? p.verb.join('|') : String(p.verb);
      lines.push(`  authority : predicate #${this.grant.predicateIndex} of grant ${short(this.grant.capabilityId)} grants ${verbs} on ${p.resource ?? '*'}`);
      lines.push(`              where ${this.grant.where}`);
    } else {
      lines.push(`  authority : NOT granted — ${this.grant.reason ?? 'no predicate permits this action'}`);
    }

    // Caveats
    if (this.caveats.length === 0) {
      lines.push('  caveats   : none');
    } else {
      for (const c of this.caveats) {
        const mark = c.satisfied ? '✓' : '✗';
        const src = c.delegated ? ' [delegated]' : '';
        lines.push(`  caveat ${mark}  : ${c.detail}${src}`);
        if (!c.satisfied && c.remedy) lines.push(`              ↳ fix: ${c.remedy}`);
      }
    }

    // Risk / tier / budget
    lines.push(`  risk      : ${this.risk.band}; proof=${this.risk.proof}, optimistic=${this.risk.optimisticAllowed}`);
    const a = this.admission;
    const costStr = a.cost !== undefined ? `, cost κ·r=${num(a.cost)} (κ=${num(a.kappa)})` : '';
    lines.push(`  budget    : ${a.path}${costStr}; B after=${num(a.budget.B)}`);

    if (this.decisive) {
      lines.push('');
      lines.push(`  ◀ DECISIVE: ${this.decisive.reason}`);
      if (this.decisive.remedy) lines.push(`      ↳ fix: ${this.decisive.remedy}`);
    }
    return lines.join('\n');
  }
}

/**
 * Explain a Policy-VM decision: which capability/predicate granted the (verb, resource) and under what
 * `where` bound; which caveats were evaluated and which one (with its type + offending value) narrowed
 * or DENIED; the risk value r, the threshold band/tier it landed in, and the budget/admission path
 * (cost vs budget). For anything short of auto-admit it names the single decisive reason + remedy.
 *
 * Supply `opts.envelope` and `opts.context` to pinpoint precisely (the granting predicate and each
 * caveat's individual outcome are re-derived from the REAL evaluators); without them it falls back to
 * the decision's own `reasons`.
 */
export function explainDecision(
  pcActn: PCActn,
  decision: PolicyDecision,
  opts: { envelope?: Envelope; context?: DecisionContext } = {},
): DecisionExplanation {
  const env = opts.envelope;
  const ctx = opts.context ?? {};
  const reasons = Array.isArray(decision?.reasons) ? decision.reasons : [];

  // Disposition + verdict. `admit` = autonomous allow (no human). Otherwise step-up (guardian share
  // released but a co-sign is needed) or denied (policy not satisfied, share withheld).
  const disposition: 'auto-admit' | 'step-up' | 'denied' = decision.admit
    ? 'auto-admit'
    : decision.releaseGuardianShare
      ? 'step-up'
      : 'denied';
  const verdict: Verdict = decision.admit ? 'allow' : 'deny';

  // ---- authority: the granting predicate ----
  const grant: GrantExplanation = { granted: decision.releaseGuardianShare };
  const rootCap: Capability | undefined = ctx.chain?.[0];
  if (rootCap) grant.capabilityId = rootCap.id;
  if (env && ctx.action) {
    const pr = evaluatePredicates(env.predicates, ctx.action);
    if (pr.allowed && pr.matched) {
      grant.granted = true;
      grant.predicate = pr.matched;
      grant.predicateIndex = env.predicates.indexOf(pr.matched);
      grant.where = whereSummary(pr.matched.where);
    } else {
      grant.granted = false;
      grant.reason = pr.reason ?? 'no predicate permits this action';
    }
  } else if (!decision.releaseGuardianShare) {
    grant.reason = reasons.find((r) => r.includes('predicate') || r.includes('not permitted')) ?? undefined;
  }

  // ---- caveats: per-caveat outcome ----
  const caveats: CaveatOutcome[] = [];
  const failedFromReasons = failedCaveatTypesFromReasons(reasons);
  const canEvalIndividually = env !== undefined && ctx.caveat !== undefined && ctx.action !== undefined;

  const grantCaveats = env?.caveats ?? [];
  // Delegated caveats mirror decide()'s `extra`: the LEAF capability's top-level caveats beyond the
  // ROOT capability's count (NOT the envelope's inner caveat count — those are the grant's semantic caveats).
  const rootCapCaveatCount = ctx.chain?.[0]?.caveats.length ?? 0;
  const delegatedCaveats: Caveat[] =
    ctx.chain && ctx.chain.length > 1
      ? (ctx.chain[ctx.chain.length - 1]?.caveats ?? []).slice(rootCapCaveatCount)
      : [];

  const classify = (cv: Caveat, delegated: boolean): CaveatOutcome => {
    const { type, rest } = caveatParts(cv);
    let satisfied: boolean;
    if (canEvalIndividually && ctx.caveat && ctx.action) {
      satisfied = evaluateAgentCaveats([cv], ctx.caveat, ctx.action).ok;
    } else {
      // Fall back to the decision's reasons: a type named as failed is unsatisfied; otherwise, if the
      // decision released the guardian share (policy OK), every caveat held.
      satisfied = failedFromReasons.has(type) ? false : decision.releaseGuardianShare;
    }
    const outcome: CaveatOutcome = { type, satisfied, value: rest, detail: caveatDetail(type, rest, satisfied), delegated };
    if (!satisfied) outcome.remedy = caveatRemedy(type, rest);
    return outcome;
  };
  for (const cv of grantCaveats) caveats.push(classify(cv, false));
  for (const cv of delegatedCaveats) caveats.push(classify(cv, true));

  // ---- risk / tier ----
  const rt = decision.requiredThreshold;
  const risk: RiskExplanation = {
    r: decision.r,
    tier: rt.t,
    proof: rt.proof,
    optimisticAllowed: rt.optimisticAllowed,
    band: riskBand(decision.r, env?.risk_policy.theta1, env?.risk_policy.theta2, rt.t),
  };
  if (env) {
    risk.theta1 = env.risk_policy.theta1;
    risk.theta2 = env.risk_policy.theta2;
  }

  // ---- admission / budget ----
  const kappa = env?.risk_policy.kappa;
  const costVal = kappa !== undefined ? budgetCost(decision.r, kappa) : undefined;
  const budgetDepleted = reasons.some((r) => r.includes('budget depleted'));
  let path: string;
  if (decision.admit) {
    path = `auto-admitted at t=${rt.t} (${rt.proof}); metered`;
  } else if (!decision.releaseGuardianShare) {
    path = 'guardian share withheld — policy not satisfied (no autonomous or guardian path)';
  } else if (budgetDepleted) {
    path = `trust budget cannot cover the cost — step-up to t=3 (human recharge) required`;
  } else {
    path = `step-up to t=${rt.t} (${rt.proof}) co-signature required`;
  }
  const admission: AdmissionExplanation = {
    admit: decision.admit,
    needStepUp: decision.needStepUp,
    releaseGuardianShare: decision.releaseGuardianShare,
    budget: decision.budget,
    path,
  };
  if (costVal !== undefined) admission.cost = costVal;
  if (kappa !== undefined) admission.kappa = kappa;

  // ---- the single decisive reason ----
  let decisive: { reason: string; remedy?: string } | undefined;
  if (!decision.admit) {
    if (!grant.granted) {
      decisive = { reason: grant.reason ?? 'action not permitted by the envelope predicates (default-deny)', remedy: 'grant a predicate that permits this verb+resource (and satisfies its where bound).' };
    } else {
      const firstFailed = caveats.find((c) => !c.satisfied);
      if (firstFailed) {
        decisive = { reason: `caveat '${firstFailed.type}' narrowed the authority away: ${firstFailed.detail}`, ...(firstFailed.remedy ? { remedy: firstFailed.remedy } : {}) };
      } else if (budgetDepleted) {
        decisive = { reason: `risk ${num(decision.r)} is admissible but the trust budget cannot cover cost κ·r${costVal !== undefined ? `=${num(costVal)}` : ''}`, remedy: 'recharge the budget with a human co-sign, or lower the action risk.' };
      } else {
        decisive = { reason: `risk ${num(decision.r)} exceeds the auto threshold → step-up to t=${rt.t} (${rt.proof})`, remedy: rt.t === 3 ? 'obtain a human step-up co-signature.' : 'obtain the guardian/principal co-signature for this tier.' };
      }
    }
  }

  const summary = decision.admit
    ? `Auto-admitted: ${grant.predicate ? `predicate #${grant.predicateIndex}` : 'policy'} grants it, all caveats held, risk r=${num(decision.r)} is in the t=${rt.t} band and the budget covers it.`
    : decisive
      ? `${verdict === 'deny' && disposition === 'denied' ? 'Denied' : 'Needs step-up'}: ${decisive.reason}`
      : `Not auto-admitted (t=${rt.t}).`;

  return new DecisionExplanation({ verdict, disposition, grant, caveats, risk, admission, decisive, reasons, summary });
}

// =================================================================================================
// explainChain — ordered attenuation trace (how authority flowed and shrank)
// =================================================================================================

export interface HopExplanation {
  index: number;
  isRoot: boolean;
  issuer: string;
  holder: string;
  issuerShort: string;
  holderShort: string;
  alg: string;
  /** Caveats introduced AT this hop (the diff against the parent's caveat prefix). */
  addedCaveats: Caveat[];
  addedCaveatTypes: string[];
  /** B_sub carried by a `budget_alloc` added at this hop, if any. */
  budgetAlloc?: number;
  /** Human summary of what this hop granted / narrowed. */
  narrowed: string;
}

function hopNarrowedSummary(isRoot: boolean, added: Caveat[]): string {
  const bits: string[] = [];
  for (const cv of added) {
    const { type, rest } = caveatParts(cv);
    if (type === 'envelope') {
      const predicates = Array.isArray(rest.predicates) ? rest.predicates.length : 0;
      const innerCaveats = Array.isArray(rest.caveats) ? rest.caveats.length : 0;
      bits.push(`envelope (${predicates} predicate(s), ${innerCaveats} caveat(s))`);
    } else if (isBudgetAllocCaveat(cv)) {
      bits.push(`budget_alloc(B_sub=${num(cv.limit)})`);
    } else {
      const bound = valueSummary(rest);
      bits.push(bound ? `+${type}(${bound})` : `+${type}`);
    }
  }
  if (bits.length === 0) return isRoot ? 'root grant (no caveats)' : 'rebind only (no new caveats)';
  return (isRoot ? 'grants ' : 'narrows: ') + bits.join(', ');
}

export class ChainExplanation {
  readonly kind = 'chain' as const;
  readonly depth: number;
  readonly hops: HopExplanation[];
  readonly rootIssuer: string | undefined;
  readonly leafHolder: string | undefined;
  readonly budgetNodes: BudgetAllocNode[];
  readonly summary: string;

  constructor(fields: {
    depth: number;
    hops: HopExplanation[];
    rootIssuer: string | undefined;
    leafHolder: string | undefined;
    budgetNodes: BudgetAllocNode[];
    summary: string;
  }) {
    this.depth = fields.depth;
    this.hops = fields.hops;
    this.rootIssuer = fields.rootIssuer;
    this.leafHolder = fields.leafHolder;
    this.budgetNodes = fields.budgetNodes;
    this.summary = fields.summary;
  }

  toText(): string {
    const lines: string[] = [];
    lines.push(`PCA delegation chain — ${this.depth} hop(s) (attenuation trace)`);
    lines.push(this.summary);
    lines.push('');
    for (const h of this.hops) {
      const tag = h.isRoot ? 'root ' : 'deleg';
      lines.push(`  #${h.index} ${tag} ${h.issuerShort} ──▶ ${h.holderShort}   ${h.narrowed}`);
    }
    if (this.budgetNodes.length > 0) {
      const tree = this.budgetNodes.map((n) => `depth ${n.depth} B_sub=${num(n.limit)}`).join(' → ');
      lines.push('');
      lines.push(`  budget subtree: ${tree}`);
    }
    return lines.join('\n');
  }
}

/**
 * Render a capability delegation chain as an ordered attenuation trace: issuer→holder per hop and what
 * each hop narrowed (caveats added, budget sub-allocation), so a developer can see how authority flowed
 * from the principal's root grant down to the acting leaf and shrank at every hop. Read-only; does not
 * verify signatures (run `verifyChain` for that).
 */
export function explainChain(chain: CapabilityChain): ChainExplanation {
  const hops: HopExplanation[] = [];
  const safeChain = Array.isArray(chain) ? chain : [];
  for (let i = 0; i < safeChain.length; i++) {
    const cap = safeChain[i];
    if (!cap) continue;
    const isRoot = i === 0;
    const parent = i > 0 ? safeChain[i - 1] : undefined;
    const parentLen = parent && Array.isArray(parent.caveats) ? parent.caveats.length : 0;
    const own = Array.isArray(cap.caveats) ? cap.caveats : [];
    const added = isRoot ? own : own.length >= parentLen ? own.slice(parentLen) : [];
    const budgetCv = added.find((cv) => isBudgetAllocCaveat(cv));
    const hop: HopExplanation = {
      index: i,
      isRoot,
      issuer: cap.issuer,
      holder: cap.holder,
      issuerShort: short(cap.issuer),
      holderShort: short(cap.holder),
      alg: cap.alg ?? 'ed25519',
      addedCaveats: added,
      addedCaveatTypes: added.map((cv) => caveatParts(cv).type),
      narrowed: hopNarrowedSummary(isRoot, added),
    };
    if (budgetCv && isBudgetAllocCaveat(budgetCv)) hop.budgetAlloc = budgetCv.limit;
    hops.push(hop);
  }

  const root = safeChain[0];
  const leaf = safeChain.length > 0 ? safeChain[safeChain.length - 1] : undefined;
  const budgetNodes = budgetAllocNodes(safeChain);
  const summary =
    safeChain.length === 0
      ? 'empty chain (no authority)'
      : `${short(root?.issuer)} (principal) delegated through ${safeChain.length - 1} hop(s) to the acting holder ${short(leaf?.holder)}; ${budgetNodes.length} budget node(s).`;

  return new ChainExplanation({
    depth: safeChain.length,
    hops,
    rootIssuer: root?.issuer,
    leafHolder: leaf?.holder,
    budgetNodes,
    summary,
  });
}
