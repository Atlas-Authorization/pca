/**
 * Verification of a proposal, before any human is asked to sign it:
 *  1. replay EVERY included trace through the real machinery (the policy simulator, then the real PCA verifier over a grant
 *     minted from the proposal with throwaway deterministic keys): all of them must pass;
 *  2. the excess-authority report: what ELSE the proposal admits beyond the traces (analyzer witnesses + the generalizations);
 *  3. the policy linter;
 *  4. a semantic diff against the policy in force, when there is one.
 * Pure of side effects and deterministic: the same proposal and traces always give the same report.
 */
import {
  CATALOG_REVERSIBILITY_SCORE, buildPCActn, b64u, hashCanonicalLenient, mintGrant, paramsDigest, publicKeyOf, sha256,
  utf8, verifyPCActn, type PlanNode, type TrustBudget,
} from '@atlasauth/pca';
import { simulate } from '@atlasauth/pca/ext/research';
import { diffPolicies, intentConformance, type Intent, type PolicyInput } from '@atlasauth/pca-analyzer';
import { lintPolicy, type Finding } from '@atlasauth/pca-policy-ci';
import { cleanText } from '@atlasauth/pca-explain';
import { includedTraces, intact, maxOf, pct, specOf, toCompiled } from './synth';
import type { Proposal, Trace, TraceSet } from './types';

export interface ReplayRow {
  id: string; verb: string; resource: string; at: number;
  /** The simulator's outcome (predicates, caveats, risk tier, budget). */
  policy: 'auto' | 'step_up' | 'deny';
  /** The real verifier's outcome over a signed proof: `step_up` = only the risk tier asks for a human. */
  verifier: 'allow' | 'step_up' | 'deny';
  failed: string[];
  ok: boolean;
}

export interface ExcessWitness { verb: string; kinds: string[]; resource: string; params: Record<string, unknown> }

export interface Report {
  v: 1;
  kind: 'pca-autopilot-report';
  proposalDigest: string;
  intact: boolean;
  basisMatches: boolean;
  replay: { total: number; passed: number; autonomous: number; humanSteps: number; failures: ReplayRow[]; ok: boolean };
  excess: { summary: string[]; witnesses: ExcessWitness[]; approximate: boolean };
  lint: Finding[];
  diff?: { equivalent: boolean; widens: boolean; narrows: boolean; summary: string[]; approximate: boolean };
  ok: boolean;
  digest: string;
}

const AUD = 'pca-autopilot-replay';
const seed = (label: string): Uint8Array => sha256(utf8(`pca-autopilot/replay/${label}`));
const MAX_FAILURES = 50;

/** Real-verifier replay of the included traces, in time order, threading the budget and the rate window exactly as a server would. */
async function replay(p: Proposal, traces: Trace[]): Promise<{ rows: ReplayRow[] }> {
  const compiled = toCompiled(p.policy, p.riskPolicy);
  const start = traces[0]?.at ?? 0;
  const sim = simulate(compiled, traces.map((t) => ({ verb: t.verb, resource: t.resource, params: t.params, at: t.at })), { start });
  const pSec = seed('principal'), hSec = seed('holder');
  const { grant } = mintGrant({
    principalSecret: pSec, principalPublic: b64u(publicKeyOf(pSec)), holder: b64u(publicKeyOf(hSec)), goal: 'autopilot replay', salt: b64u(new Uint8Array(16)),
    envelope: { predicates: p.policy.predicates, caveats: p.policy.caveats, agent_binding: {}, risk_policy: p.riskPolicy },
  });
  let budget: TrustBudget = { B: p.riskPolicy.bMax, tau: start, asOf: start };
  const admitted: number[] = [];
  const rows: ReplayRow[] = [];
  for (let i = 0; i < traces.length; i++) {
    const t = traces[i]!;
    const s = sim.results[i]!;
    const row: ReplayRow = { id: t.id, verb: t.verb, resource: cleanText(t.resource), at: t.at, policy: s.outcome, verifier: 'deny', failed: [], ok: false };
    try {
      const spec = specOf(t.verb);
      const cls = spec.reversibility;
      const bl = spec.blastRadius;
      const node: PlanNode = { id: 'n0', verb: t.verb, resource: t.resource, reversibility_class: cls, params_digest: paramsDigest(t.params) };
      const pc = buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n0', params: t.params, counter: i + 1, signerSecret: hSec, aud: AUD, riskClaim: { r: bl, inputs: { blastRadius: bl } }, now: t.at, nonce: `autopilot-${i}` });
      const v = await verifyPCActn(pc, {
        grant, audience: AUD, now: t.at, require: [],
        context: { params: t.params, plan: [node], planAuthorized: true, reversibilityClass: cls, budget, recentActionTimes: [...admitted], risk: { reversibility: CATALOG_REVERSIBILITY_SCORE[cls] ?? 0, blastRadius: bl, confidence: 1, semanticDistance: 0, taint: 0, age: 0 } },
      });
      row.failed = Object.entries(v.checks).filter(([, c]) => c === 'fail').map(([k]) => k).sort();
      if (v.allow) {
        row.verifier = 'allow';
        admitted.push(t.at);
        if (v.budget) budget = v.budget;
      } else if (row.failed.length > 0 && row.failed.every((k) => k === 'policy' || k === 'threshold') && s.outcome === 'step_up' && v.requiredThreshold.t > 1 && v.reasons.some((x) => /step-up|depleted/.test(x))) row.verifier = 'step_up'; // the risk tier asks a human; no check about the action itself failed
    } catch (e) {
      row.failed = [`error: ${cleanText(e instanceof Error ? e.message : String(e)).slice(0, 120)}`];
    }
    row.ok = row.policy !== 'deny' && row.verifier !== 'deny';
    rows.push(row);
  }
  return { rows };
}

/** What else the proposal permits: the analyzer's concrete witnesses beyond the exact observed envelope, plus each generalization. */
function excess(p: Proposal, traces: Trace[]): Report['excess'] {
  const summary: string[] = [];
  const witnesses: ExcessWitness[] = [];
  let approximate = false;
  const policy = { predicates: p.policy.predicates, caveats: p.policy.caveats } as PolicyInput;
  for (const verb of [...new Set(traces.map((t) => t.verb))].sort()) {
    const vt = traces.filter((t) => t.verb === verb);
    const nums = [...new Set(vt.flatMap((t) => Object.keys(t.params).filter((k) => typeof t.params[k] === 'number')))].filter((k) => vt.every((t) => typeof t.params[k] === 'number')).sort();
    const field = nums.includes('amount') ? 'amount' : nums[0];
    // two questions per verb, kept apart so one kind of excess cannot crowd the other out of the analyzer's witness cap:
    // what else on the resource axis (everything outside the exact observed resources), and what else on the amount axis
    const scope: Intent = { verbs: [verb], resourceScopes: [...new Set(vt.map((t) => t.resource))].sort() };
    const amount: Intent | undefined = field === undefined ? undefined : { verbs: [verb], maxAmount: maxOf(vt.map((t) => t.params[field] as number)), amountField: field };
    for (const intent of amount === undefined ? [scope] : [scope, amount]) {
      try {
        const c = intentConformance(policy, intent);
        if (c.approximate) approximate = true;
        for (const v of c.violations.slice(0, 3)) witnesses.push({ verb, kinds: v.kinds, resource: cleanText(v.action.resource), params: v.action.params ?? {} });
      } catch {
        approximate = true;
      }
    }
  }
  for (const r of p.rules) {
    if (r.rung === 1) summary.push(`${r.verb} on ${r.resource}: you saw ${r.observed} use(s) of ${r.observedResources.length} resource(s); this admits every resource under that parent, including ones never seen`);
    for (const n of r.params) if (/unconstrained/.test(n)) summary.push(`${r.verb}: ${n}`);
  }
  const caps = p.policy.predicates.filter((x) => (x.where ?? []).some((c) => (c as { op?: string }).op === 'lte')).length;
  if (p.margin > 0 && caps > 0) summary.push(`numeric caps include a ${pct(p.margin)}% margin over the largest value seen`);
  const rate = p.policy.caveats.find((c) => c.type === 'rate');
  if (rate) summary.push(`up to ${String(rate.max)} action(s) per ${String(rate.per_secs)}s are admitted (the observed peak plus the margin)`);
  if (witnesses.length === 0 && !approximate) summary.push('the analyzer found no admitted action outside the exact observed envelope');
  return { summary, witnesses, approximate };
}

/** Run every check. Never throws for a bad proposal: the report says what failed. */
export async function verifyProposal(p: Proposal, set: TraceSet, opts: { existing?: unknown } = {}): Promise<Report> {
  const isIntact = intact(p);
  const basisMatches = p.basis.traceSetDigest === set.digest;
  const traces = isIntact ? includedTraces(set, p) : [];
  let rows: ReplayRow[] = [];
  if (isIntact && traces.length > 0) {
    try { rows = (await replay(p, traces)).rows; } catch (e) {
      rows = traces.map((t) => ({ id: t.id, verb: t.verb, resource: cleanText(t.resource), at: t.at, policy: 'deny' as const, verifier: 'deny' as const, failed: [`error: ${cleanText(e instanceof Error ? e.message : String(e)).slice(0, 120)}`], ok: false }));
    }
  }
  const failures = rows.filter((r) => !r.ok);
  const replayRes = {
    total: rows.length, passed: rows.length - failures.length, autonomous: rows.filter((r) => r.ok && r.verifier === 'allow' && r.policy === 'auto').length,
    humanSteps: rows.filter((r) => r.ok && (r.verifier === 'step_up' || r.policy === 'step_up')).length,
    failures: failures.slice(0, MAX_FAILURES), ok: isIntact && rows.length > 0 && failures.length === 0,
  };
  const policy = { predicates: p.policy.predicates, caveats: p.policy.caveats };
  const lint = isIntact ? lintPolicy(policy) : [];
  let diff: Report['diff'];
  if (opts.existing !== undefined && isIntact) {
    try {
      const d = diffPolicies(opts.existing as PolicyInput, policy as PolicyInput, { limit: 4 });
      diff = { equivalent: d.equivalent, widens: d.widens, narrows: d.narrows, summary: d.summary.map((x) => cleanText(x)), approximate: d.approximate === true };
    } catch (e) {
      diff = { equivalent: false, widens: true, narrows: false, summary: [`the existing policy could not be compared (${cleanText(e instanceof Error ? e.message : String(e)).slice(0, 80)}): treat as wider`], approximate: true };
    }
  }
  const body = {
    v: 1 as const, kind: 'pca-autopilot-report' as const, proposalDigest: p.digest, intact: isIntact, basisMatches, replay: replayRes,
    excess: isIntact ? excess(p, traces) : { summary: ['proposal was modified after it was made; nothing was analyzed'], witnesses: [], approximate: true },
    lint, ...(diff ? { diff } : {}),
    ok: isIntact && basisMatches && replayRes.ok && !lint.some((f) => f.severity === 'error'),
  };
  const clean = JSON.parse(JSON.stringify(body)) as typeof body;
  return { ...clean, digest: hashCanonicalLenient(clean) };
}
