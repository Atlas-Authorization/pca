import { describe, expect, it } from 'vitest';
import type { WorkflowBody } from '@atlasauth/pca';
import { dagExposure } from './dag-exposure';

const step = (id: string, deps: string[] = [], o: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });
const edge = (f: string, t: string, o: Record<string, unknown> = {}) => ({ from: { step: f, field: 'x' }, to: { step: t, param: 'y' }, op: 'eq', unit: null, deny_labels: [], promise: null, ...o });
const wf = (steps: unknown[], edges: unknown[], budget = { max_steps: 10, caps: {} as Record<string, number> }): WorkflowBody =>
  ({ v: 1, id: 'w', principal: 'p', goal_digest: null, plan_root: null, issued_at: 0, expires_at: 1, steps, edges, budget }) as unknown as WorkflowBody;

describe('dagExposure', () => {
  it('a diamond: depth, width, paths, lineage and the unprotected sink', () => {
    const e = dagExposure(
      wf([step('a'), step('b', ['a']), step('c', ['a']), step('d', ['b', 'c'], { sink: 'external_communication' })], [edge('b', 'd'), edge('c', 'd')]),
    );
    expect(e).toMatchObject({ steps: 4, maxSteps: 4, depth: 3, levelWidth: 2, paths: 2, pathsCapped: false, unprotectedSinks: ['d'], orderingOnly: ['b', 'c'], pipelinable: [] });
    expect(e.sinks).toEqual([{ step: 'd', sink: 'external_communication', lineage: ['b', 'c'], protected: false }]);
  });
  it('a label rule on the step or on an incoming edge protects the sink', () => {
    const base = [step('a'), step('d', ['a'], { sink: 's', deny_labels: ['pii'] })];
    expect(dagExposure(wf(base, [edge('a', 'd')])).unprotectedSinks).toEqual([]);
    expect(dagExposure(wf([step('a'), step('d', ['a'], { sink: 's' })], [edge('a', 'd', { deny_labels: ['pii'] })])).unprotectedSinks).toEqual([]);
    expect(dagExposure(wf([step('a'), step('d', ['a'], { sink: 's' })], [edge('a', 'd')])).unprotectedSinks).toEqual(['d']);
  });
  it('budget: max spend is min(cap, total); never-runnable steps are named', () => {
    const e = dagExposure(
      wf([step('a', [], { cost: { money: 40 } }), step('b', ['a'], { cost: { money: 70 } }), step('c', ['b'])], [], { max_steps: 2, caps: { money: 60 } }),
    );
    expect(e.cost).toEqual({ money: { cap: 60, total: 110, maxSpend: 60 } });
    expect(e.maxSteps).toBe(2);
    expect(e.neverRunnable).toEqual([{ step: 'b', reason: 'cost_over_cap' }, { step: 'c', reason: 'needs_more_steps_than_budget' }]);
  });
  it('promised edges are pipelinable by index', () => {
    expect(dagExposure(wf([step('a'), step('b', ['a'])], [edge('a', 'b'), edge('a', 'b', { promise: 'dom' })])).pipelinable).toEqual([1]);
  });
  it('path count caps instead of overflowing', () => {
    const steps: unknown[] = [step('s0')];
    const edges: unknown[] = [];
    for (let i = 1; i <= 40; i++) {
      steps.push(step(`l${i}a`, [i === 1 ? 's0' : `j${i - 1}`]), step(`l${i}b`, [i === 1 ? 's0' : `j${i - 1}`]), step(`j${i}`, [`l${i}a`, `l${i}b`].sort()));
    }
    const e = dagExposure(wf(steps, edges, { max_steps: 200, caps: {} }));
    expect(e.paths).toBe(1_000_000);
    expect(e.pathsCapped).toBe(true);
  });
  it('rejects a cycle and an unknown dependency', () => {
    expect(() => dagExposure(wf([step('a', ['b']), step('b', ['a'])], []))).toThrow('cycle');
    expect(() => dagExposure(wf([step('a', ['ghost'])], []))).toThrow('unknown step ghost');
  });
});
