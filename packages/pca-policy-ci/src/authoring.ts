import type { PolicyInput } from './deps';
import { coverage, coverageGate, diffGate, diffPolicies, runPolicyTests, type PolicyTestDoc } from './deps';
import { normalizePolicyInput } from './normalize';

/**
 * Authoring gates built on the analyzer, for CI: `diff` (does this change widen authority or raise the most that can leave?),
 * `test` (a policy test document against a policy, pinned by digest), and `coverage` (which clauses and thresholds the tests or
 * traffic never exercise, and which mutations of the policy they cannot tell apart). Each returns the lines to print and an
 * exit code (0 ok, 1 a gate failed, 2 unusable input). None of them signs or changes anything.
 */

export interface AuthoringResult {
  ok: boolean;
  exitCode: 0 | 1 | 2;
  lines: string[];
}

const bad = (line: string): AuthoringResult => ({ ok: false, exitCode: 2, lines: [line] });
const isRecord = (x: unknown): x is Record<string, unknown> => x !== null && typeof x === 'object' && !Array.isArray(x);

/** A policy document as the analyzer reads it: any shape `lint` accepts, plus optional `vetoes` and `tighten` members. */
export function toAnalyzerPolicy(doc: unknown): { ok: true; policy: PolicyInput } | { ok: false; reason: string } {
  const n = normalizePolicyInput(doc);
  if (!n.ok) return n;
  const extra: Record<string, unknown> = {};
  if (isRecord(doc)) {
    if (Array.isArray(doc.vetoes)) extra.vetoes = doc.vetoes;
    if (Array.isArray(doc.tighten)) extra.tighten = doc.tighten;
  }
  return { ok: true, policy: { predicates: n.policy.predicates, caveats: n.policy.caveats, ...extra } };
}

export interface DiffCommandOptions {
  /** Accept a widening (a reviewer approved it). Default false. */
  allowWiden?: boolean;
  /** When given, also gate the most that can leave for this verb. */
  verb?: string;
  amountField?: string;
  integer?: boolean;
  windowSecs?: number;
  /** Largest allowed rise of the maximum exposure (default 0). */
  maxExposureIncrease?: number;
}

export function diffCommand(oldDoc: unknown, newDoc: unknown, o: DiffCommandOptions = {}): AuthoringResult {
  const a = toAnalyzerPolicy(oldDoc);
  const b = toAnalyzerPolicy(newDoc);
  if (!a.ok) return bad(`old policy: ${a.reason}`);
  if (!b.ok) return bad(`new policy: ${b.reason}`);
  const d = diffPolicies(a.policy, b.policy, o.verb !== undefined ? { exposure: { verb: o.verb, ...(o.amountField ? { amountField: o.amountField } : {}), ...(o.integer ? { integer: true } : {}), ...(o.windowSecs !== undefined ? { windowSecs: o.windowSecs } : {}) } } : {});
  const gate = diffGate(d, { widen: o.allowWiden === true, ...(o.maxExposureIncrease !== undefined ? { maxExposureIncrease: o.maxExposureIncrease } : {}) });
  const lines = d.equivalent ? ['no change in what is admitted'] : d.summary.length > 0 ? d.summary : ['no witness found'];
  if (!gate.ok) lines.push(...gate.reasons.map((r) => `FAIL: ${r}`));
  lines.push(gate.ok ? 'PASS' : 'FAIL');
  return { ok: gate.ok, exitCode: gate.ok ? 0 : 1, lines };
}

export function testCommand(policyDoc: unknown, testsDoc: unknown, o: { requireDigest?: boolean } = {}): AuthoringResult {
  const p = toAnalyzerPolicy(policyDoc);
  if (!p.ok) return bad(`policy: ${p.reason}`);
  if (!isRecord(testsDoc) || testsDoc.kind !== 'pca-policy-tests' || !Array.isArray(testsDoc.cases)) return bad('tests: not a pca-policy-tests document');
  const r = runPolicyTests(p.policy, testsDoc as unknown as PolicyTestDoc, o.requireDigest !== undefined ? { requireDigest: o.requireDigest } : {});
  const lines = r.failures.map((f) => `FAIL ${f.name}: expected ${f.expected}${f.expectedDecidedBy ? ` by ${f.expectedDecidedBy}` : ''}, got ${f.got} by ${f.decidedBy ?? 'no clause'}`);
  if (!r.digestMatch) lines.push(`${o.requireDigest ? 'FAIL' : 'note'}: the policy differs from the one the examples were confirmed against`);
  lines.push(`${r.passed}/${r.total} examples ${r.ok ? 'PASS' : 'FAIL'}`);
  return { ok: r.ok, exitCode: r.ok ? 0 : 1, lines };
}

export interface CoverageCommandOptions {
  minClauses?: number;
  minBoundaries?: number;
  minMutation?: number;
  maxSurvivors?: number;
}

export function coverageCommand(policyDoc: unknown, trafficDoc: unknown, o: CoverageCommandOptions = {}): AuthoringResult {
  const p = toAnalyzerPolicy(policyDoc);
  if (!p.ok) return bad(`policy: ${p.reason}`);
  // traffic: an array of actions, or a pca-policy-tests document (its cases are the traffic)
  const actions = Array.isArray(trafficDoc) ? trafficDoc : isRecord(trafficDoc) && Array.isArray(trafficDoc.cases) ? trafficDoc.cases.map((c: unknown) => (isRecord(c) ? c.action : c)) : undefined;
  if (actions === undefined || actions.some((a) => !isRecord(a) || typeof a.verb !== 'string' || typeof a.resource !== 'string')) return bad('traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document');
  const r = coverage(p.policy, actions as never);
  const gate = coverageGate(r, { ...(o.minClauses !== undefined ? { clauses: o.minClauses } : {}), ...(o.minBoundaries !== undefined ? { boundaries: o.minBoundaries } : {}), ...(o.minMutation !== undefined ? { mutation: o.minMutation } : {}), ...(o.maxSurvivors !== undefined ? { maxSurvivors: o.maxSurvivors } : {}) });
  const lines = [
    `clauses decisive ${(r.score.clauses * 100).toFixed(0)}%, boundaries covered ${(r.score.boundaries * 100).toFixed(0)}%, mutants killed ${(r.score.mutation * 100).toFixed(0)}% (${r.mutants.killed}/${r.mutants.total - r.mutants.equivalent})`,
    ...r.untested.map((id) => `untested: ${id}`),
    ...r.mutants.survivors.map((m) => `survives: ${m.description}${m.killer ? ` (kill with ${JSON.stringify(m.killer)})` : ''}`),
    ...gate.reasons.map((x) => `FAIL: ${x}`),
    gate.ok ? 'PASS' : 'FAIL',
  ];
  return { ok: gate.ok, exitCode: gate.ok ? 0 : 1, lines };
}
