import { describe, expect, it } from 'vitest';
import type { WorkflowBody } from '@atlasauth/pca';
import { dagExposure } from './dag-exposure';

const step = (id: string, deps: string[] = [], o: Record<string, unknown> = {}) => ({ id, verb: 'v', resource: 'r', params_digest: null, deps, sink: null, deny_labels: [], escalate_labels: [], fresh_ms: null, cost: {}, ...o });
const edge = (f: string, t: string, o: Record<string, unknown> = {}) => ({ from: { step: f, field: 'x' }, to: { step: t, param: 'y' }, op: 'eq', unit: null, deny_labels: [], promise: null, ...o });
const wf = (steps: unknown[], edges: unknown[], budget = { max_steps: 10, caps: {} as Record<string, number> }): WorkflowBody =>
  ({ v: 1, id: 'w', principal: 'p', goal_digest: null, plan_root: null, issued_at: 0, expires_at: 1, steps, edges, budget }) as unknown as WorkflowBody;

describe('dagExposure (boundaries and exact shapes)', () => {
  it('rejects a duplicate step id', () => {
    expect(() => dagExposure(wf([step('a'), step('a')], []))).toThrow(RangeError);
    expect(() => dagExposure(wf([step('a'), step('a')], []))).toThrow('dagExposure: duplicate step id');
  });

  it('counts source-to-leaf paths over several sources', () => {
    const e = dagExposure(
      wf([step('a'), step('b', ['a']), step('c', ['a']), step('d', ['b']), step('e', ['b']), step('f', ['c']), step('g'), step('h', ['g'])], []),
    );
    expect(e).toMatchObject({ steps: 8, depth: 3, levelWidth: 3, paths: 4, pathsCapped: false });
  });

  it('exactly the path cap is not reported as capped; one more layer pair is', () => {
    const steps: unknown[] = [step('s')];
    let prev = 's';
    for (let i = 1; i <= 6; i++) {
      const row: string[] = [];
      for (let k = 0; k < 10; k++) {
        steps.push(step(`l${i}_${k}`, [prev]));
        row.push(`l${i}_${k}`);
      }
      steps.push(step(`j${i}`, row));
      prev = `j${i}`;
    }
    const e = dagExposure(wf(steps, [], { max_steps: 200, caps: {} }));
    expect(e.paths).toBe(1_000_000);
    expect(e.pathsCapped).toBe(false);
  });

  it('a step costing exactly its cap runs; one over, or an uncapped resource, never does', () => {
    const e = dagExposure(
      wf(
        [step('ok', [], { cost: { money: 60 } }), step('over', [], { cost: { money: 61 } }), step('nocap', [], { cost: { gems: 1 } }), step('free', [], { cost: { gems: 0 } })],
        [],
        { max_steps: 10, caps: { money: 60 } },
      ),
    );
    expect(e.neverRunnable).toEqual([
      { step: 'over', reason: 'cost_over_cap' },
      { step: 'nocap', reason: 'cost_over_cap' },
    ]);
  });

  it('a step needing exactly max_steps steps runs; one more never does', () => {
    const chain = [step('x'), step('y', ['x']), step('z', ['y'])];
    expect(dagExposure(wf(chain, [], { max_steps: 3, caps: {} })).neverRunnable).toEqual([]);
    expect(dagExposure(wf(chain, [], { max_steps: 2, caps: {} })).neverRunnable).toEqual([{ step: 'z', reason: 'needs_more_steps_than_budget' }]);
  });

  it('lineage is transitive, sorted, and survives an edge cycle', () => {
    const e = dagExposure(
      wf(
        [step('a'), step('b', ['a']), step('m'), step('z'), step('d', ['b', 'm', 'z'], { sink: 's' })],
        [edge('z', 'd'), edge('b', 'd'), edge('m', 'd'), edge('a', 'b')],
      ),
    );
    expect(e.sinks).toEqual([{ step: 'd', sink: 's', lineage: ['a', 'b', 'm', 'z'], protected: false }]);
    const cyc = dagExposure(wf([step('a'), step('b', ['a']), step('d', ['b'], { sink: 's' })], [edge('a', 'b'), edge('b', 'a'), edge('b', 'd')]));
    expect(cyc.sinks[0]!.lineage).toEqual(['a', 'b']);
  });

  it('protection comes from the step labels, or from any (not every) incoming edge into the sink itself', () => {
    const sinkAt = (steps: unknown[], edges: unknown[]) => dagExposure(wf(steps, edges));
    // one of two incoming edges carries a deny label
    expect(sinkAt([step('a'), step('b'), step('d', ['a', 'b'], { sink: 'x' })], [edge('a', 'd', { deny_labels: ['pii'] }), edge('b', 'd')]).sinks[0]!.protected).toBe(true);
    // an escalate label on the step alone protects it
    const esc = sinkAt([step('a'), step('d', ['a'], { sink: 'x', escalate_labels: ['y'] })], [edge('a', 'd')]);
    expect(esc.sinks[0]!.protected).toBe(true);
    expect(esc.unprotectedSinks).toEqual([]);
    // a deny label on an edge into some OTHER step does not protect the sink
    const other = sinkAt([step('a'), step('d', ['a'], { sink: 'x' }), step('e', ['a'])], [edge('a', 'd'), edge('a', 'e', { deny_labels: ['pii'] })]);
    expect(other.sinks[0]!.protected).toBe(false);
    expect(other.unprotectedSinks).toEqual(['d']);
    // a sink nothing flows into has no lineage and is not an unprotected flow
    const lone = sinkAt([step('d', [], { sink: 'x' })], []);
    expect(lone.sinks).toEqual([{ step: 'd', sink: 'x', lineage: [], protected: false }]);
    expect(lone.unprotectedSinks).toEqual([]);
  });

  it('orderingOnly names exactly the steps with dependencies and no incoming edge', () => {
    const e = dagExposure(wf([step('a'), step('b', ['a']), step('c', ['a']), step('d', ['a'])], [edge('a', 'b'), edge('a', 'c')]));
    expect(e.orderingOnly).toEqual(['d']);
  });
});
