import { describe, expect, it } from 'vitest';
import { hashCanonical, utf8 } from './hash';
import { DEFAULT_RISK_POLICY as P } from './risk';
import {
  DEFAULT_NATIVE_CONFIG,
  InMemoryInverseRegistry,
  ResourceGraph,
  blastRadius,
  byoEmbedder,
  byoModelId,
  calibrate,
  calibrationDigest,
  canonicalAction,
  canonicalActionJson,
  commitGoal,
  committedDistance,
  conformalThreshold,
  conformanceCheck,
  harmReport,
  nativeHashEmbedder,
  objectiveRisk,
  reversibility,
  vectorDistance,
  verifyGoalCommitment,
  type ByoDescriptor,
  type ObjAction,
  type ObjectiveRiskContext,
} from './objective-risk';

const native = nativeHashEmbedder();
const goalAction: ObjAction = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf', region: 'emea' } };
const goal = commitGoal(native, goalAction);

const mkGraph = () =>
  new ResourceGraph()
    .addNode({ id: 'api', harm: { rows: 0 } })
    .addNode({ id: 'orders', harm: { rows: 1000, usd: 5000 } })
    .addNode({ id: 'items', harm: { rows: 5000 } })
    .addNode({ id: 'audit', harm: { rows: 100 } })
    .addNode({ id: 'island', harm: { rows: 1 } })
    .addEdge({ from: 'api', to: 'orders', kind: 'rw' })
    .addEdge({ from: 'orders', to: 'items', kind: 'rw' })
    .addEdge({ from: 'items', to: 'audit', kind: 'log' })
    .addEdge({ from: 'audit', to: 'api', kind: 'log' }); // cycle

const ev = { verifierId: 'acme-replay', evidenceDigest: 'sha256:abc' };
const mkRegistry = () =>
  new InMemoryInverseRegistry(['acme-replay'])
    .register('db.delete', { inverseKind: 'db.restore', fidelity: 'exact', verification: ev })
    .register('mail.send', { inverseKind: 'mail.apologize', fidelity: 'partial', verification: ev })
    .register('fs.wipe', { inverseKind: 'fs.undelete', fidelity: 'exact' }) // no verification evidence
    .register('net.open', { inverseKind: 'net.close', fidelity: 'exact', verification: { verifierId: 'rogue', evidenceDigest: 'x' } });

const denoms = [
  { id: 'rows', ceiling: 10000, weight: 1 },
  { id: 'usd', ceiling: 10000, weight: 1 },
];

const act = (o: Partial<ObjAction> = {}): ObjAction => ({ verb: 'db.delete', resource: 'orders', params: { table: 'orders', where: 'id<10' }, ...o });

const ctx = (o: Partial<ObjectiveRiskContext> = {}): ObjectiveRiskContext => {
  const registry = o.registry ?? mkRegistry();
  const graph = o.graph ?? mkGraph();
  return {
    registry,
    authorizedKinds: new Set(['db.restore', 'mail.apologize', 'fs.undelete', 'net.close']),
    graph,
    embedder: native,
    goal,
    commitments: { registryDigest: mkRegistry().digest(), graphDigest: mkGraph().digest() },
    denominations: denoms,
    weights: P.weights,
    taint: 0.1,
    age: 0.2,
    ...o,
  };
};

function prng(seed: number) {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('canonical action', () => {
  it('collapses semantics-preserving re-encodings and rejects unencodable input', () => {
    const a = canonicalAction({ verb: ' DB.Delete ', resource: 'orders', params: { b: 1, a: { y: 2, x: 1 } } });
    const b = canonicalAction({ verb: 'db.delete', resource: 'orders', params: { a: { x: 1, y: 2 }, b: 1 } });
    expect(canonicalActionJson(a)).toBe(canonicalActionJson(b));
    expect(canonicalAction({ verb: 'v', resource: 'café' }).resource).toBe(canonicalAction({ verb: 'v', resource: 'café' }).resource);
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: { x: undefined } })).toThrow();
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: { x: NaN } })).toThrow();
    expect(() => canonicalAction({ verb: '', resource: 'r' })).toThrow();
  });
});

describe('native embedder', () => {
  it('is deterministic, integer-valued, and recomputable by an independent instance', () => {
    const e1 = nativeHashEmbedder();
    const e2 = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG });
    const c = canonicalAction(goalAction);
    const v = e1.embed(c);
    expect(v).toEqual(e2.embed(c));
    expect(e1.modelId).toBe(e2.modelId);
    expect(v).toHaveLength(256);
    expect(v.every(Number.isSafeInteger)).toBe(true);
    // golden vector digest: a cross-language implementation must reproduce this exactly
    expect(hashCanonical(v)).toBe(GOLDEN);
  });

  it('config is committed into modelId', () => {
    expect(nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, seed: 'other' }).modelId).not.toBe(native.modelId);
    expect(nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, dims: 128 }).modelId).not.toBe(native.modelId);
    expect(() => nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, dims: 3 })).toThrow();
  });

  it('semantics-preserving re-encoding gives the SAME vector; a different action gives a different one', () => {
    const base = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf', region: 'emea', nest: { a: 1, b: [1, 2] } } };
    const reenc = { verb: 'REPORT.READ ', resource: 'sales/q3', params: { nest: { b: [1, 2], a: 1 }, region: 'emea', format: 'pdf' } };
    expect(native.embed(canonicalAction(reenc))).toEqual(native.embed(canonicalAction(base)));
    expect(native.embed(canonicalAction({ ...base, params: { ...base.params, region: 'apac' } }))).not.toEqual(native.embed(canonicalAction(base)));
    expect(native.embed(canonicalAction({ verb: 'db.drop', resource: 'prod/users' }))).not.toEqual(native.embed(canonicalAction(base)));
  });

  it('near action is closer to the goal than a destructive unrelated one; identical is 0', () => {
    const near = committedDistance({ verb: 'report.read', resource: 'sales/q3', params: { format: 'csv', region: 'emea' } }, goal, native);
    const far = committedDistance({ verb: 'db.drop', resource: 'prod/users', params: { cascade: true } }, goal, native);
    expect(committedDistance(goalAction, goal, native)).toBe(0);
    expect(near).toBeGreaterThan(0);
    expect(far).toBeGreaterThan(near);
    expect(far).toBeLessThanOrEqual(1);
  });
});

describe('agent cannot move r except by changing the action', () => {
  it('extra agent-asserted properties are ignored', () => {
    const honest = objectiveRisk(act(), ctx());
    const rigged = {
      ...act(),
      features: ['report', 'read', 'sales'],
      kind: 'report.read',
      scope: { maxDepth: 0 },
      confidence: 1,
      reversible: true,
      taint: 0,
    } as unknown as ObjAction;
    const r = objectiveRisk(rigged, ctx());
    expect(r.r).toBe(honest.r);
    expect(r.evidenceDigest).toBe(honest.evidenceDigest);
  });

  it('changing the real action (verb, resource, params) does move it', () => {
    const base = objectiveRisk(act(), ctx());
    expect(objectiveRisk(act({ resource: 'api' }), ctx()).evidenceDigest).not.toBe(base.evidenceDigest);
    expect(objectiveRisk(act({ params: { table: 'orders', where: 'true' } }), ctx()).inputs.semanticDistance).not.toBe(base.inputs.semanticDistance);
    expect(objectiveRisk(act({ verb: 'report.read', params: goalAction.params, resource: 'sales/q3' }), ctx()).inputs.semanticDistance).toBe(0);
  });

  it('declared confidence cannot lower r; attested uncertainty only raises it', () => {
    const base = objectiveRisk(act(), ctx()).r;
    const withConf = objectiveRisk({ ...act(), confidence: 1 } as unknown as ObjAction, ctx()).r;
    expect(withConf).toBe(base);
    expect(objectiveRisk(act(), ctx({ attestedUncertainty: 0.5 })).r).toBeGreaterThan(base);
    expect(objectiveRisk(act(), ctx({ attestedUncertainty: -3 })).r).toBe(base); // cannot go negative
  });

  it('scope comes from the grant context, not the action', () => {
    const wide = objectiveRisk(act({ resource: 'api' }), ctx());
    const narrow = objectiveRisk(act({ resource: 'api' }), ctx({ scope: { maxDepth: 1 } }));
    expect(wide.blast.count).toBe(4);
    expect(narrow.blast.count).toBe(2);
  });
});

describe('BYO embedder', () => {
  const desc: ByoDescriptor = {
    name: 'mock-int8',
    version: '1',
    weightsDigest: 'sha256:weights-v1',
    runtime: 'mock-runtime@1',
    dims: 8,
    quantization: { bits: 8, scale: 1 / 64 },
    inputEncoding: 'pca-canonical-action-json-v1',
  };
  // mock "model": pure integer function of the canonical JSON bytes
  const infer = (json: string) => {
    const v = new Array<number>(8).fill(0);
    utf8(json).forEach((b, i) => (v[i % 8] = v[i % 8]! + (b % 7) - 3));
    return v;
  };
  const byo = byoEmbedder(desc, infer);

  it('modelId = hash(descriptor); a claimed id must match', () => {
    expect(byo.modelId).toBe(byoModelId(desc));
    expect(() => byoEmbedder(desc, infer, 'byo:forged')).toThrow();
    expect(byoEmbedder(desc, infer, byoModelId(desc)).modelId).toBe(byo.modelId);
    expect(byoModelId({ ...desc, weightsDigest: 'sha256:weights-v2' })).not.toBe(byo.modelId);
  });

  it('goal commitment binds the embedder; recompute matches; cross-embedder fails closed', () => {
    const g = commitGoal(byo, goalAction);
    expect(verifyGoalCommitment(g, byo)).toBeNull();
    expect(g.embedderModelId).toBe(byo.modelId);
    expect(committedDistance(goalAction, g, byo)).toBe(0);
    expect(committedDistance({ verb: 'db.drop', resource: 'prod/users' }, g, byo)).toBeGreaterThan(0);
    // same committed goal, different embedders => rejected
    expect(verifyGoalCommitment(g, native)).toBe('embedder modelId mismatch');
    expect(committedDistance(goalAction, g, native)).toBe(1);
    expect(verifyGoalCommitment(goal, byo)).toBe('embedder modelId mismatch');
    const other = byoEmbedder({ ...desc, weightsDigest: 'sha256:weights-v2' }, infer);
    expect(committedDistance(goalAction, g, other)).toBe(1);
    // tamper any committed field => hash mismatch
    expect(verifyGoalCommitment({ ...g, epsilon: 0.5 }, byo)).toBe('goal commitment hash mismatch');
    expect(verifyGoalCommitment({ ...g, goalVector: g.goalVector.map((x, i) => (i ? x : x + 1)) }, byo)).toBe('goal commitment hash mismatch');
    expect(verifyGoalCommitment({ ...g, metric: 'euclid' as never }, byo)).toBe('unknown metric');
  });

  it('enforces the determinism contract on outputs (fail closed)', () => {
    const g = commitGoal(byo, goalAction);
    const run = (fn: (j: string) => number[]) => committedDistance(act(), g, byoEmbedder(desc, fn));
    expect(run(infer)).toBeLessThanOrEqual(1);
    expect(run(() => [0.5, 0, 0, 0, 0, 0, 0, 0])).toBe(1); // non-integer
    expect(run(() => [1, 2, 3])).toBe(1); // wrong dims
    expect(run(() => [1000, 0, 0, 0, 0, 0, 0, 0])).toBe(1); // exceeds 8-bit quantization
    expect(run(() => [NaN, 0, 0, 0, 0, 0, 0, 0])).toBe(1);
    expect(run(() => { throw new Error('boom'); })).toBe(1);
  });

  it('conformance cases reproduce exactly or fail', () => {
    const cases = [goalAction, act()].map((a) => ({ action: a, vector: byo.embed(canonicalAction(a)) }));
    expect(conformanceCheck(byo, cases)).toBe(true);
    const drift = byoEmbedder(desc, (j) => infer(j).map((x) => x + 1));
    expect(conformanceCheck(drift, cases)).toBe(false);
  });

  it('works end to end through objectiveRisk', () => {
    const g = commitGoal(byo, goalAction);
    const r = objectiveRisk(act(), ctx({ embedder: byo, goal: g }));
    expect(r.valid).toBe(true);
    expect(objectiveRisk(act(), ctx({ embedder: byo, goal: g })).r).toBe(r.r);
  });
});

describe('committed registry and graph', () => {
  it('reversible only with trusted-verifier evidence AND an authorized inverse', () => {
    const auth = new Set(['db.restore', 'mail.apologize', 'net.close']);
    const reg = mkRegistry();
    expect(reversibility({ verb: 'db.delete' }, reg, auth).class).toBe('reversible');
    expect(reversibility({ verb: 'mail.send' }, reg, auth).class).toBe('compensable');
    expect(reversibility({ verb: 'fs.wipe' }, reg, auth).class).toBe('irreversible'); // no evidence
    expect(reversibility({ verb: 'net.open' }, reg, auth).class).toBe('irreversible'); // untrusted verifier
    expect(reversibility({ verb: 'nope' }, reg, auth).class).toBe('irreversible');
    expect(reversibility({ verb: 'db.delete' }, reg, new Set()).class).toBe('irreversible');
    expect(objectiveRisk(act(), ctx({ authorizedKinds: new Set() })).r).toBeGreaterThan(objectiveRisk(act(), ctx()).r);
  });

  it('a registry that differs from the committed digest is rejected (fail closed)', () => {
    const tampered = mkRegistry().register('db.delete', { inverseKind: 'db.noop', fidelity: 'exact', verification: ev });
    const r = objectiveRisk(act(), ctx({ registry: tampered, authorizedKinds: new Set(['db.noop']) }));
    expect(r.valid).toBe(false);
    expect(r.r).toBe(1);
    expect(r.reasons.join()).toMatch(/registry digest/);
    // widening the trusted-verifier set also changes the digest
    const widened = new InMemoryInverseRegistry(['acme-replay', 'rogue']).register('db.delete', { inverseKind: 'db.restore', fidelity: 'exact', verification: ev });
    expect(widened.digest()).not.toBe(mkRegistry().digest());
  });

  it('a graph that differs from the committed digest is rejected', () => {
    const smaller = new ResourceGraph().addNode({ id: 'orders', harm: { rows: 1 } });
    const r = objectiveRisk(act(), ctx({ graph: smaller }));
    expect(r.valid).toBe(false);
    expect(r.r).toBe(1);
    expect(r.reasons.join()).toMatch(/graph digest/);
    expect(mkGraph().digest()).toBe(mkGraph().digest());
  });

  it('goal/embedder mismatch and un-encodable actions fail closed without throwing', () => {
    const other = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, seed: 'x' });
    const r = objectiveRisk(act(), ctx({ embedder: other }));
    expect(r.valid).toBe(false);
    expect(r.r).toBe(1);
    const u = objectiveRisk(act({ params: { x: undefined } }), ctx());
    expect(u.valid).toBe(false);
    expect(u.r).toBe(1);
  });

  it('calibration set must match its committed digest', () => {
    const cal = [0.1, 0.2, 0.3];
    expect(objectiveRisk(act(), ctx({ calibration: cal })).valid).toBe(false); // no digest
    const c = { registryDigest: mkRegistry().digest(), graphDigest: mkGraph().digest(), calibrationDigest: calibrationDigest(cal) };
    expect(objectiveRisk(act(), ctx({ calibration: cal, commitments: c })).valid).toBe(true);
    expect(objectiveRisk(act(), ctx({ calibration: [0.1, 0.2, 0.9], commitments: c })).valid).toBe(false);
  });
});

describe('retained properties', () => {
  it('is deterministic: same inputs -> same r and evidence digest', () => {
    const a = objectiveRisk(act(), ctx());
    const b = objectiveRisk(act(), ctx());
    expect(a.valid).toBe(true);
    expect(a.r).toBe(b.r);
    expect(a.evidenceDigest).toBe(b.evidenceDigest);
    expect(Object.keys(a.inputs).sort()).toEqual(['age', 'blastRadius', 'confidence', 'reversibility', 'semanticDistance', 'taint']);
  });

  it('blast radius grows with the reachable set', () => {
    const g = mkGraph();
    const full = blastRadius({ resource: 'api' }, g);
    const rw = blastRadius({ resource: 'api' }, g, { edgeKinds: ['rw'] });
    const one = blastRadius({ resource: 'api' }, g, { maxDepth: 1 });
    expect([full.count, rw.count, one.count]).toEqual([4, 3, 2]);
    expect(full.normalized).toBeGreaterThan(rw.normalized);
    expect(rw.normalized).toBeGreaterThan(one.normalized);
    expect(blastRadius({ resource: 'missing' }, g).normalized).toBe(1);
    expect(full.harm).toEqual({ rows: 6100, usd: 5000 });
    const r = (res: string, scope?: { maxDepth: number }) => objectiveRisk(act({ resource: res }), ctx({ scope })).r;
    expect(r('api')).toBeGreaterThan(r('api', { maxDepth: 1 }));
    expect(r('api', { maxDepth: 1 })).toBeGreaterThanOrEqual(r('island'));
  });

  it('split-conformal calibration achieves target coverage', () => {
    const rnd = prng(42);
    const draw = () => Math.pow(rnd(), 2) * 0.8;
    const alpha = 0.1;
    let covered = 0, flagged = 0;
    const trials = 4000;
    for (let t = 0; t < trials; t++) {
      const cal = Array.from({ length: 99 }, draw);
      const x = draw();
      if (x <= conformalThreshold(cal, alpha)) covered++;
      if (calibrate(x, cal) > 1 - alpha) flagged++;
    }
    expect(covered / trials).toBeGreaterThanOrEqual(1 - alpha - 0.02);
    expect(flagged / trials).toBeLessThanOrEqual(alpha + 0.02);
    expect(calibrate(0.5, [])).toBe(1);
    expect(conformalThreshold([0.1], 0.01)).toBe(Infinity);
  });

  it('is monotone in taint/age/uncertainty/calibration/harm and in vectorDistance grid', () => {
    const cal = Array.from({ length: 50 }, (_, i) => i / 100);
    const commitments = { registryDigest: mkRegistry().digest(), graphDigest: mkGraph().digest(), calibrationDigest: calibrationDigest(cal) };
    for (const c of [ctx(), ctx({ calibration: cal, commitments })]) {
      const base = objectiveRisk(act(), c).r;
      expect(objectiveRisk(act(), { ...c, taint: 0.9 }).r).toBeGreaterThanOrEqual(base);
      expect(objectiveRisk(act(), { ...c, age: 0.9 }).r).toBeGreaterThanOrEqual(base);
      expect(objectiveRisk(act(), { ...c, attestedUncertainty: 0.9 }).r).toBeGreaterThanOrEqual(base);
    }
    let prev = -1;
    for (const s of [0, 0.1, 0.2, 0.3, 0.5, 0.9]) {
      const v = calibrate(s, [0.05, 0.15, 0.25, 0.4]);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
    const sets: Record<string, number>[] = [{ rows: 0 }, { rows: 100 }, { rows: 5000, usd: 10 }, { rows: 5000, usd: 9000 }];
    const h = sets.map((u) => harmReport(u, denoms).normalized);
    expect([...h].sort((a, b) => a - b)).toEqual(h);
    // distance: scaled copy is 0, orthogonal is sin(45deg), opposite is 1, rounded up to the grid
    expect(vectorDistance([1, 2], [2, 4])).toBe(0);
    expect(vectorDistance([1, 0], [0, 1], 1 / 4096)).toBeCloseTo(Math.SQRT1_2, 3);
    expect(vectorDistance([1, 0], [-1, 0])).toBe(1);
    expect(vectorDistance([0, 0], [1, 0])).toBe(1);
  });
});

const GOLDEN = '5R4YmeITYtFzCxpda_yVeXyBtiZpICEAlXBSh5nL5Ig';
