import { describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY as P } from './risk';
import {
  DEFAULT_MAX_PARAM_LEAVES,
  DEFAULT_NATIVE_CONFIG,
  InMemoryInverseRegistry,
  ResourceGraph,
  canonicalAction,
  commitGoal,
  committedDistance,
  nativeHashEmbedder,
  objectiveRisk,
  type ObjAction,
  type ObjectiveRiskContext,
} from './objective-risk';

const native = nativeHashEmbedder();
const goalAction: ObjAction = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf' } };
const goal = commitGoal(native, goalAction);

const mkCtx = (embedder = native, g = goal): ObjectiveRiskContext => {
  const registry = new InMemoryInverseRegistry([]);
  const graph = new ResourceGraph().addNode({ id: 'sales/q3' });
  return {
    registry,
    authorizedKinds: new Set<string>(),
    graph,
    embedder,
    goal: g,
    commitments: { registryDigest: registry.digest(), graphDigest: graph.digest() },
    denominations: [],
    weights: P.weights,
    taint: 0,
    age: 0,
  };
};

const junk = (n: number): Record<string, number> => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));

describe('A2i: param-stuffing defense', () => {
  it('the protocol default cap is enforced even without explicit config', () => {
    expect(DEFAULT_MAX_PARAM_LEAVES).toBe(256);
  });

  it('a compliant action produces a real distance/risk', () => {
    const r = objectiveRisk({ verb: 'report.read', resource: 'sales/q3', params: { format: 'csv' } }, mkCtx());
    expect(r.valid).toBe(true);
    expect(r.r).toBeGreaterThanOrEqual(0);
    expect(r.r).toBeLessThanOrEqual(1);
  });

  it('a PARAM-STUFFED action cannot dilute/inflate — it fails CLOSED to r = 1', () => {
    const stuffed: ObjAction = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf', ...junk(DEFAULT_MAX_PARAM_LEAVES + 1) } };
    // the distance collapses to the worst case (1), never a favorable diluted value
    expect(committedDistance(stuffed, goal, native)).toBe(1);
    const r = objectiveRisk(stuffed, mkCtx());
    expect(r.valid).toBe(false);
    expect(r.r).toBe(1);
  });

  it('an explicit smaller cap is committed into the modelId and throws above the cap', () => {
    const capped = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 4 });
    expect(capped.modelId).not.toBe(native.modelId); // committed config ⇒ different id
    expect(() => capped.embed(canonicalAction({ verb: 'v', resource: 'r', params: junk(5) }))).toThrow();
    expect(() => capped.embed(canonicalAction({ verb: 'v', resource: 'r', params: junk(4) }))).not.toThrow();
  });

  it("paramMode:'digest' bounds params to ≤1 bucket, so stuffing cannot flood the vector", () => {
    const leafEmb = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 2000 });
    const digEmb = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, paramMode: 'digest', maxParamLeaves: 2000 });
    const base = canonicalAction({ verb: 'v', resource: 'r', params: { a: 1 } });
    const stuffed = canonicalAction({ verb: 'v', resource: 'r', params: { a: 1, ...junk(500) } });
    const diff = (x: number[], y: number[]) => x.reduce((n, xi, i) => n + (xi !== y[i] ? 1 : 0), 0);

    // leaf mode: stuffing perturbs MANY coordinates (it can steer the vector)
    expect(diff(leafEmb.embed(base), leafEmb.embed(stuffed))).toBeGreaterThan(2);
    // digest mode: all params collapse to a single token ⇒ at most 2 coordinates differ
    expect(diff(digEmb.embed(base), digEmb.embed(stuffed))).toBeLessThanOrEqual(2);
    // verb/resource still dominate identically (adding params never touches their buckets' values beyond ≤1)
    const noParam = canonicalAction({ verb: 'v', resource: 'r', params: {} });
    expect(diff(digEmb.embed(noParam), digEmb.embed(base))).toBeLessThanOrEqual(2);
  });

  it('rejects an invalid cap / paramMode in config (fail closed)', () => {
    expect(() => nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 0 })).toThrow();
    expect(() => nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, paramMode: 'bogus' as unknown as 'leaves' })).toThrow();
  });
});
