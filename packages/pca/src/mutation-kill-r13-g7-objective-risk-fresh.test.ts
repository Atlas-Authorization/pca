/**
 * r13 mutation kills for objective-risk.ts. Most survivors are module-level constants and helper arrows (clamp01, cmp,
 * maxComponent, NATIVE_SCHEME, DEFAULT_NATIVE_CONFIG, byoModelId, METRIC, DEFAULT_EPSILON, goalCommitInput,
 * calibrationDigest, WORST_INPUTS, isObjRecord, canonicalActionJson / Digest): static mutants, so every test re-evaluates
 * the module (vi.resetModules + dynamic import) and pins the result against an independent computation.
 */
import { describe, expect, it, vi } from 'vitest';
import { canonicalize, hashCanonicalLenient } from './hash';

async function fresh() {
  vi.resetModules();
  return import('./objective-risk');
}

describe('objective-risk module constants (fresh module)', () => {
  it('scheme, default config, metric and epsilon', async () => {
    const m = await fresh();
    expect(m.NATIVE_SCHEME).toBe('pca-native-hash-ngram-v1');
    expect(m.DEFAULT_NATIVE_CONFIG).toEqual({ dims: 256, ngramMin: 2, ngramMax: 4, seed: 'pca-native-v1', fieldWeights: { verb: 4, resource: 2, param: 1 } });
    expect(m.METRIC).toBe('half-chord-v1');
    expect(m.DEFAULT_EPSILON).toBe(1 / 4096);
    const e = m.nativeHashEmbedder();
    expect(e.modelId).toBe(
      `native:${hashCanonicalLenient({ scheme: 'pca-native-hash-ngram-v1', dims: 256, ngramMin: 2, ngramMax: 4, seed: 'pca-native-v1', fieldWeights: { verb: 4, resource: 2, param: 1 } })}`,
    );
  });
  it('byoModelId, canonicalActionJson and canonicalActionDigest', async () => {
    const m = await fresh();
    const d = { runtime: 'onnx', dims: 4, quantization: { bits: 8, scale: 1 }, inputEncoding: 'pca-canonical-action-json-v1' as const };
    expect(m.byoModelId(d as never)).toBe(`byo:${hashCanonicalLenient(d)}`);
    const c = m.canonicalAction({ verb: 'X', resource: 'r', params: { a: 1 } });
    expect(m.canonicalActionJson(c)).toBe(canonicalize(c));
    expect(m.canonicalActionDigest(c)).toBe(hashCanonicalLenient(c));
  });
  it('canonicalAction params are plain enumerable, writable, configurable data properties', async () => {
    const m = await fresh();
    const c = m.canonicalAction({ verb: 'v', resource: 'r', params: { a: { b: 1 } } });
    expect(Object.keys(c.params)).toEqual(['a']);
    expect(Object.getOwnPropertyDescriptor(c.params, 'a')).toEqual({ value: { b: 1 }, enumerable: true, writable: true, configurable: true });
  });
  it('goal commitment hashes exactly {embedderModelId, config, goalVector, metric, epsilon}', async () => {
    const m = await fresh();
    const e = m.nativeHashEmbedder();
    let g: ReturnType<typeof m.commitGoal> | undefined;
    let err: unknown;
    try {
      g = m.commitGoal(e, { verb: 'v', resource: 'r' });
    } catch (x) {
      err = x;
    }
    expect([err === undefined, String(err ?? '')]).toEqual([true, '']);
    expect(g!.metric).toBe('half-chord-v1');
    expect(g!.epsilon).toBe(1 / 4096);
    expect(g!.commit).toBe(hashCanonicalLenient({ embedderModelId: g!.embedderModelId, config: g!.config, goalVector: g!.goalVector, metric: 'half-chord-v1', epsilon: 1 / 4096 }));
  });
  it('calibrationDigest sorts numerically under {v: 1, scores}', async () => {
    const m = await fresh();
    expect(m.calibrationDigest([3, 10, 2])).toBe(hashCanonicalLenient({ v: 1, scores: [2, 3, 10] }));
  });
  it('vectorDistance is clamped (0 for equal vectors, at most 1)', async () => {
    const m = await fresh();
    expect(m.vectorDistance([1, 2, 3], [1, 2, 3])).toBe(0);
    expect(m.vectorDistance([1, 0], [-1, 0])).toBe(1);
  });
  it('validateVector bounds each component at floor(sqrt(MAX_SAFE / (2 dims)))', async () => {
    const m = await fresh();
    const lim = Math.floor(Math.sqrt(Number.MAX_SAFE_INTEGER / 4));
    expect(m.validateVector([lim, -lim], 2)).toEqual([lim, -lim]);
    expect(() => m.validateVector([lim + 1, 0], 2)).toThrow('vector component out of range');
  });
  it('registry and graph sort ids in code-unit order', async () => {
    const m = await fresh();
    const g = new m.ResourceGraph().addNode({ id: 'b' }).addNode({ id: 'a' }).addNode({ id: 'c' }).addEdge({ from: 'b', to: 'c', kind: 'k' }).addEdge({ from: 'b', to: 'a', kind: 'k' });
    expect(g.reachable('b')).toEqual(['a', 'b', 'c']);
    const g2 = new m.ResourceGraph().addNode({ id: 'a' }).addNode({ id: 'c' }).addNode({ id: 'b' }).addEdge({ from: 'b', to: 'a', kind: 'k' }).addEdge({ from: 'b', to: 'c', kind: 'k' });
    expect(g2.digest()).toBe(g.digest());
    const r1 = new m.InMemoryInverseRegistry(['z', 'a', 'm']);
    expect(r1.trustedVerifiers()).toEqual(['a', 'm', 'z']);
    const r2 = new m.InMemoryInverseRegistry(['m', 'z', 'a']);
    r1.register('y', { inverseKind: 'k', fidelity: 'exact' }).register('x', { inverseKind: 'k', fidelity: 'exact' });
    r2.register('x', { inverseKind: 'k', fidelity: 'exact' }).register('y', { inverseKind: 'k', fidelity: 'exact' });
    expect(r1.digest()).toBe(r2.digest());
  });
  it('a rejected evaluation reports the worst-case inputs', async () => {
    const m = await fresh();
    const e = m.nativeHashEmbedder();
    const res = m.objectiveRisk({ verb: 'v', resource: 'r' }, {
      registry: new m.InMemoryInverseRegistry(), authorizedKinds: new Set(), graph: new m.ResourceGraph(), embedder: e, goal: m.commitGoal(e, { verb: 'v', resource: 'r' }),
      commitments: { registryDigest: 'wrong', graphDigest: 'wrong' }, denominations: [], weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, taint: 0, age: 0,
    });
    expect(res.valid).toBe(false);
    expect(res.inputs).toEqual({ semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 });
  });
  it('the oracle passes object params through (and drops non-object ones)', async () => {
    const m = await fresh();
    const e = m.nativeHashEmbedder();
    const reg = new m.InMemoryInverseRegistry();
    const graph = new m.ResourceGraph().addNode({ id: 'r' });
    const goal = { verb: 'v', resource: 'r', params: { device: 'laptop' } };
    const o = m.objectiveRiskOracle({
      registry: reg, authorizedKinds: new Set(), graph, embedder: e, goal: m.commitGoal(e, goal),
      commitments: { registryDigest: reg.digest(), graphDigest: graph.digest() }, denominations: [], weights: { alpha: 1, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, taint: 0, age: 0,
    });
    const snap = (params: unknown) => ({ action: { action: { verb: 'v', resource: 'r', params } } }) as never;
    expect(o.resolve('semanticDistance', snap({ device: 'laptop' }))).toEqual({ input: 'semanticDistance', value: 0, valid: true });
    const dropped = o.resolve('semanticDistance', snap(['laptop']));
    expect(dropped).toEqual(o.resolve('semanticDistance', snap({})));
    expect((dropped as { value: number }).value).toBeGreaterThan(0);
  });
});
