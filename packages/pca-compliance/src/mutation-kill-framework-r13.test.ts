/**
 * r13 mutation kills for compliance.ts: the EU AI Act oversight / robustness statuses when the autonomous bound is
 * unbounded (non-finite), the overall pass flag (any failed control fails the report) and the Markdown FAIL marker.
 */
import { describe, expect, it } from 'vitest';
import type { ActivityEvent } from '@atlasauth/pca';
import type { CompiledPolicy } from '@atlasauth/pca';
import { frameworkReport, frameworkReportToMarkdown } from './framework-report';
import { DEFAULT_RISK_POLICY } from '@atlasauth/pca';

const pol = (bMax: number) => ({ riskPolicy: { ...DEFAULT_RISK_POLICY, bMax } }) as unknown as CompiledPolicy;
const ev = (outcome: string) => ({ outcome, at: 1, agent: 'a' }) as unknown as ActivityEvent;
const status = (r: ReturnType<typeof frameworkReport>, id: string) => r.controls.find((c) => c.id === id)!.status;

describe('frameworkReport (eu-ai-act)', () => {
  it('an unbounded autonomy with no human review is warn / fail and fails the report', () => {
    const r = frameworkReport('eu-ai-act', { policy: pol(Infinity), events: [ev('auto')] }, 0);
    expect(status(r, 'art14-human-oversight')).toBe('warn');
    expect(status(r, 'art15-robustness')).toBe('fail');
    expect(r.pass).toBe(false);
    expect(frameworkReportToMarkdown(r)).toContain('overall: FAIL');
    expect(frameworkReportToMarkdown(r)).toContain('| Bounded autonomy (accuracy/robustness) (art15-robustness) | FAIL |');
  });
  it('human review alone satisfies oversight', () => {
    const r = frameworkReport('eu-ai-act', { policy: pol(Infinity), events: [ev('step_up')] }, 0);
    expect(status(r, 'art14-human-oversight')).toBe('pass');
  });
  it('a finite bound passes oversight and robustness', () => {
    const r = frameworkReport('eu-ai-act', { policy: pol(1), events: [ev('auto')], hasGoalCommitment: true }, 0);
    expect(status(r, 'art14-human-oversight')).toBe('pass');
    expect(r.pass).toBe(true);
    expect(frameworkReportToMarkdown(r)).toContain('overall: PASS');
  });
  it('warns do not fail the report', () => {
    const r = frameworkReport('gdpr', { policy: pol(1), events: [] }, 0);
    expect(r.controls.some((c) => c.status === 'warn')).toBe(true);
    expect(r.pass).toBe(true);
  });
});
