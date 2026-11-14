/**
 * 0.4.2 mutation kills: the compliance evidence reports are a contract with auditors, so every control id, name, status rule and
 * evidence text is pinned (testdata/framework-golden.json, reviewed by hand): a full record set and an empty one, per framework,
 * summary + period + controls + the rendered Markdown.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect, it } from 'vitest';
import { frameworkReport, frameworkReportToMarkdown, type FrameworkId } from './framework-report';
import { compilePolicy } from '@atlasauth/pca';

const GOLDEN = JSON.parse(readFileSync(resolve(__dirname, '..', 'testdata', 'framework-golden.json'), 'utf8'));
const events: never[] = [
  { at: 5, agent: 'agent-1', verb: 'v', resource: 'c:1', outcome: 'auto', r: 0.1, taint: 0 },
  { at: 2, agent: 'agent-1', verb: 'v', resource: 'c:2', outcome: 'step_up', r: 0.8, taint: 1 },
  { at: 9, agent: 'agent-2', verb: 'v', resource: 'c:3', outcome: 'deny', r: 0.9, taint: 2 },
  { at: 7, agent: 'agent-3', verb: 'v', resource: 'c:4', outcome: 'executed', r: 0.9 },
] as never[];
const policy = compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' } });

for (const fw of ['eu-ai-act', 'soc2', 'gdpr'] as FrameworkId[]) {
  for (const [name, input] of [
    ['full', { policy, events, hasGoalCommitment: true, erasureSupported: true, decisions: [{}, {}] as never }],
    ['bare', { policy, events: [] }],
  ] as const) {
    it(`${fw} / ${name}: report and Markdown are exactly the reviewed golden`, () => {
      const r = frameworkReport(fw, input as never, 1000);
      expect({ summary: r.summary, period: r.period, pass: r.pass, controls: r.controls, md: frameworkReportToMarkdown(r) }).toEqual(GOLDEN[`${fw}/${name}`]);
    });
  }
}

it('an unknown or inherited framework name is refused with the list of known ones', () => {
  for (const fw of ['nope', 'constructor', 'toString', '__proto__']) {
    expect(() => frameworkReport(fw as never, { policy, events: [] })).toThrow(`frameworkReport: unknown framework '${fw}' (have: eu-ai-act, soc2, gdpr)`);
  }
});
it('the report is stamped with the given time, and Date.now() by default', () => {
  expect(frameworkReport('soc2', { policy, events: [] }, 1234).generatedAt).toBe(1234);
  const t0 = Date.now();
  const g = frameworkReport('soc2', { policy, events: [] }).generatedAt;
  expect(g).toBeGreaterThanOrEqual(t0);
  expect(g).toBeLessThanOrEqual(Date.now());
});
