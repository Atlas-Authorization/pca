import { describe, expect, it } from 'vitest';
import { type ComplianceInput, complianceReport, reportToMarkdown } from './compliance';
import type { ActivityEvent } from './console';
import { compilePolicy } from './facade';

const events: ActivityEvent[] = [
  { at: 1, agent: 'agent-1', verb: 'stripe.refund', resource: 'c:1', outcome: 'auto', r: 0.1, taint: 0 },
  { at: 2, agent: 'agent-1', verb: 'stripe.refund', resource: 'c:2', outcome: 'step_up', r: 0.8, taint: 1 },
  { at: 3, agent: 'agent-2', verb: 'stripe.refund', resource: 'c:3', outcome: 'deny', r: 0.9, taint: 2 },
];

const input = (over: Partial<ComplianceInput> = {}): ComplianceInput => ({
  policy: compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' } }),
  events,
  hasGoalCommitment: true,
  erasureSupported: true,
  ...over,
});

describe('complianceReport', () => {
  it('summarizes attributable, bounded, overseen autonomy', () => {
    const r = complianceReport('eu-ai-act', input(), 1000);
    expect(r.summary.totalActions).toBe(3);
    expect(r.summary.attributableAgents).toBe(2);
    expect(r.summary.humanOverseen).toBeGreaterThanOrEqual(1);
    expect(r.summary.autonomousBound).toBe(500); // bMax/κ · κ
    expect(r.summary.maxTaintObserved).toBe(2);
    expect(r.pass).toBe(true);
  });

  it('EU AI Act bounded-autonomy control passes with a finite safety bound', () => {
    const r = complianceReport('eu-ai-act', input());
    const c = r.controls.find((x) => x.id === 'art15-robustness')!;
    expect(c.status).toBe('pass');
  });

  it('warns on missing goal commitment (transparency / purpose limitation)', () => {
    const eu = complianceReport('eu-ai-act', input({ hasGoalCommitment: false }));
    expect(eu.controls.find((c) => c.id === 'art13-transparency')!.status).toBe('warn');
    const gdpr = complianceReport('gdpr', input({ hasGoalCommitment: false }));
    expect(gdpr.controls.find((c) => c.id === 'art5-purpose')!.status).toBe('warn');
  });

  it('gdpr erasure warns when not asserted', () => {
    const r = complianceReport('gdpr', input({ erasureSupported: false }));
    expect(r.controls.find((c) => c.id === 'art17-erasure')!.status).toBe('warn');
    expect(r.pass).toBe(true); // warns don't fail
  });

  it('soc2 report covers access/audit/monitoring/change', () => {
    const r = complianceReport('soc2', input());
    expect(r.controls.map((c) => c.id)).toEqual(['cc6.1-access', 'cc7.2-monitoring', 'cc7.3-audit-trail', 'cc8.1-change']);
  });

  it('renders markdown', () => {
    const md = reportToMarkdown(complianceReport('soc2', input()));
    expect(md).toMatch(/# PCA compliance evidence/);
    expect(md).toMatch(/\| Control \| Status \| Evidence \|/);
    expect(md).toMatch(/not a legal certification/);
  });
});
