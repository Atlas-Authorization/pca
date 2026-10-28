/**
 * Compliance export (spec Part 2.6 "the compliance wedge"). PCA's substrate — a signed policy, a
 * machine-checked blast-radius bound, an attributable action ledger, goal lineage and taint provenance —
 * is exactly what regulators ask for: provable, bounded, attributable autonomy. This maps that evidence
 * onto EU AI Act / SOC 2 / GDPR control language and emits a report enterprises can hand to an auditor.
 *
 * HONEST: this is an EVIDENCE MAPPING, not a legal certification. A `pass` means the structural evidence
 * for a control is present in the supplied records — it is not a lawyer's or auditor's sign-off.
 * Pure + offline over the records you feed it (the console activity stream + approval decisions + policy).
 */

import type { ActivityEvent } from '@atlasauth/pca/ext/research';
import type { ApprovalDecision } from '@atlasauth/pca';
import type { CompiledPolicy } from '@atlasauth/pca';
import { safetyBound } from '@atlasauth/pca';

export type FrameworkId = 'eu-ai-act' | 'soc2' | 'gdpr';

export interface FrameworkInput {
  policy: CompiledPolicy;
  events: ActivityEvent[];
  decisions?: ApprovalDecision[];
  /** Did the grant carry a goal commitment (purpose limitation / lineage)? */
  hasGoalCommitment?: boolean;
  /** Is an erasure / right-to-be-forgotten path wired (GDPR Art 17)? */
  erasureSupported?: boolean;
}

export type FrameworkControlStatus = 'pass' | 'warn' | 'fail';

export interface FrameworkControl {
  id: string;
  name: string;
  status: FrameworkControlStatus;
  evidence: string;
}

export interface FrameworkReport {
  framework: FrameworkId;
  generatedAt: number;
  period: { from: number; to: number };
  summary: {
    totalActions: number;
    autonomous: number;
    humanOverseen: number;
    denied: number;
    attributableAgents: number;
    /** The proven dollar/risk bound on autonomous action between human co-signs (bMax/κ · κ). */
    autonomousBound: number;
    maxTaintObserved: number;
  };
  controls: FrameworkControl[];
  /** True iff no control FAILED (warns are allowed). */
  pass: boolean;
}

function baseSummary(input: FrameworkInput): FrameworkReport['summary'] {
  const e = input.events;
  const p = input.policy.riskPolicy;
  return {
    totalActions: e.length,
    autonomous: e.filter((x) => x.outcome === 'auto' || x.outcome === 'executed').length,
    humanOverseen: e.filter((x) => x.outcome === 'step_up').length + (input.decisions?.length ?? 0),
    denied: e.filter((x) => x.outcome === 'deny').length,
    attributableAgents: new Set(e.map((x) => x.agent)).size,
    autonomousBound: safetyBound(p) * p.kappa,
    // a taint that is present but not a finite number is unknown, and unknown counts as the worst case
    maxTaintObserved: e.reduce((m, x) => Math.max(m, x.taint === undefined ? 0 : Number.isFinite(x.taint) ? x.taint : Number.POSITIVE_INFINITY), 0),
  };
}

const period = (events: ActivityEvent[]) => {
  const ats = events.map((e) => e.at).filter(Number.isFinite);
  return { from: ats.length ? Math.min(...ats) : 0, to: ats.length ? Math.max(...ats) : 0 };
};

function euAiActControls(input: FrameworkInput, s: FrameworkReport['summary']): FrameworkControl[] {
  const logged = s.totalActions > 0;
  const oversight = s.humanOverseen > 0 || Number.isFinite(s.autonomousBound);
  return [
    { id: 'art12-record-keeping', name: 'Automatic logging of events', status: logged ? 'pass' : 'warn', evidence: `${s.totalActions} attributable actions recorded` },
    { id: 'art14-human-oversight', name: 'Human oversight', status: oversight ? 'pass' : 'warn', evidence: `${s.humanOverseen} human-reviewed actions; autonomous bound ${s.autonomousBound}` },
    { id: 'art15-robustness', name: 'Bounded autonomy (accuracy/robustness)', status: Number.isFinite(s.autonomousBound) ? 'pass' : 'fail', evidence: `machine-checked safety bound = ${s.autonomousBound} between human co-signs` },
    { id: 'art13-transparency', name: 'Transparency / traceability', status: input.hasGoalCommitment ? 'pass' : 'warn', evidence: input.hasGoalCommitment ? 'every action binds to a signed goal commitment (lineage)' : 'no goal commitment supplied' },
  ];
}

function soc2Controls(input: FrameworkInput, s: FrameworkReport['summary']): FrameworkControl[] {
  const constrained = Array.isArray(input.policy?.predicates) && input.policy.predicates.length > 0;
  return [
    { id: 'cc6.1-access', name: 'Logical access — least privilege', status: constrained ? 'pass' : 'warn', evidence: constrained ? 'actions constrained by signed predicates + capability attenuation (deny by default)' : 'the supplied policy lists no predicates' },
    { id: 'cc7.2-monitoring', name: 'Monitoring of anomalies', status: s.totalActions > 0 ? 'pass' : 'warn', evidence: `${s.denied} denied + ${s.humanOverseen} escalated actions captured` },
    { id: 'cc7.3-audit-trail', name: 'Audit trail', status: s.totalActions > 0 ? 'pass' : 'warn', evidence: `${s.totalActions} content-addressed actions across ${s.attributableAgents} agents` },
    { id: 'cc8.1-change', name: 'Change management (policy integrity)', status: constrained ? 'pass' : 'warn', evidence: constrained ? 'policy is signed into the grant; tampering breaks verification' : 'the supplied policy lists no predicates' },
  ];
}

function gdprControls(input: FrameworkInput, s: FrameworkReport['summary']): FrameworkControl[] {
  return [
    { id: 'art5-purpose', name: 'Purpose limitation', status: input.hasGoalCommitment ? 'pass' : 'warn', evidence: input.hasGoalCommitment ? 'actions bound to a committed goal/purpose' : 'no goal commitment supplied' },
    { id: 'art5-minimization', name: 'Data minimisation', status: s.totalActions > 0 ? 'pass' : 'warn', evidence: `taint-gated data flows; max taint observed = ${s.maxTaintObserved}` },
    { id: 'art5-accountability', name: 'Accountability', status: s.attributableAgents > 0 ? 'pass' : 'warn', evidence: `${s.attributableAgents} attributable agent identities` },
    { id: 'art17-erasure', name: 'Right to erasure', status: input.erasureSupported ? 'pass' : 'warn', evidence: input.erasureSupported ? 'erasure path wired' : 'erasure path not asserted' },
  ];
}

const BUILDERS: Record<FrameworkId, (i: FrameworkInput, s: FrameworkReport['summary']) => FrameworkControl[]> = {
  'eu-ai-act': euAiActControls,
  soc2: soc2Controls,
  gdpr: gdprControls,
};

/** Build a compliance evidence report for a framework from the supplied records. */
export function frameworkReport(framework: FrameworkId, input: FrameworkInput, now: number = Date.now()): FrameworkReport {
  const summary = baseSummary(input);
  // Own-key lookup only. `framework` can arrive from untrusted input; a key like `constructor` would
  // otherwise resolve up the prototype chain to `Object` (a callable), and `BUILDERS[framework](...)`
  // would invoke it — a type confusion yielding a malformed report instead of a clean rejection.
  if (!Object.prototype.hasOwnProperty.call(BUILDERS, framework)) {
    throw new Error(`frameworkReport: unknown framework '${String(framework)}' (have: ${Object.keys(BUILDERS).join(', ')})`);
  }
  const controls = BUILDERS[framework](input, summary);
  return {
    framework,
    generatedAt: now,
    period: period(input.events),
    summary,
    controls,
    pass: controls.every((c) => c.status !== 'fail'),
  };
}

/** Render a report as a short Markdown block (for attaching to an audit package). */
export function frameworkReportToMarkdown(r: FrameworkReport): string {
  const lines = [
    `# PCA compliance evidence — ${r.framework}`,
    ``,
    `Generated ${new Date(r.generatedAt).toISOString()} · ${r.summary.totalActions} actions · ${r.summary.attributableAgents} agents · overall: ${r.pass ? 'PASS' : 'FAIL'}`,
    ``,
    `| Control | Status | Evidence |`,
    `| --- | --- | --- |`,
    ...r.controls.map((c) => `| ${c.name} (${c.id}) | ${c.status.toUpperCase()} | ${c.evidence} |`),
    ``,
    `_Evidence mapping, not a legal certification._`,
  ];
  return lines.join('\n');
}
