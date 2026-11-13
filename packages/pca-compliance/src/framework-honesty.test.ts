import { compilePolicy } from '@atlasauth/pca';
import type { ActivityEvent } from '@atlasauth/pca/ext/research';
import { describe, expect, it } from 'vitest';
import { frameworkReport, frameworkReportToMarkdown } from './framework-report';

// ---------------------------------------------------------------------------------------------- compliance
describe('compliance: statuses follow the evidence', () => {
  const policy = compilePolicy({ permissions: { github: ['read'] } });
  const ev = (over: Partial<ActivityEvent> = {}): ActivityEvent => ({ at: 1, agent: 'a', verb: 'github.read', resource: 'r', outcome: 'auto', ...over });
  const status = (r: ReturnType<typeof frameworkReport>) => Object.fromEntries(r.controls.map((c) => [c.id, c.status]));
  it('with no events, monitoring and minimisation are warnings, not passes', () => {
    expect(status(frameworkReport('soc2', { policy, events: [] }, 0))).toEqual({ 'cc6.1-access': 'pass', 'cc7.2-monitoring': 'warn', 'cc7.3-audit-trail': 'warn', 'cc8.1-change': 'pass' });
    expect(status(frameworkReport('gdpr', { policy, events: [] }, 0))['art5-minimization']).toBe('warn');
  });
  it('with events they pass', () => {
    expect(status(frameworkReport('soc2', { policy, events: [ev()] }, 0))).toEqual({ 'cc6.1-access': 'pass', 'cc7.2-monitoring': 'pass', 'cc7.3-audit-trail': 'pass', 'cc8.1-change': 'pass' });
    expect(status(frameworkReport('gdpr', { policy, events: [ev()] }, 0))['art5-minimization']).toBe('pass');
  });
  it('a policy without predicates does not evidence least privilege or change control', () => {
    const empty = { ...policy, predicates: [] };
    const s = status(frameworkReport('soc2', { policy: empty, events: [ev()] }, 0));
    expect([s['cc6.1-access'], s['cc8.1-change']]).toEqual(['warn', 'warn']);
  });
  it('an unknown taint is the worst case, and an unusable time does not poison the period', () => {
    const r = frameworkReport('gdpr', { policy, events: [ev({ taint: Number.NaN }), ev({ at: Number.NaN })] }, 0);
    expect(r.summary.maxTaintObserved).toBe(Infinity);
    expect(r.period).toEqual({ from: 1, to: 1 });
  });
  it('an unknown or inherited framework name is refused', () => {
    for (const f of ['constructor', '__proto__', 'toString', 'hipaa']) {
      expect(() => frameworkReport(f as never, { policy, events: [] })).toThrow(`frameworkReport: unknown framework '${f}' (have: eu-ai-act, soc2, gdpr)`);
    }
  });
  it('the markdown says it is an evidence mapping', () => {
    expect(frameworkReportToMarkdown(frameworkReport('eu-ai-act', { policy, events: [ev()] }, 0))).toContain('_Evidence mapping, not a legal certification._');
  });
});

