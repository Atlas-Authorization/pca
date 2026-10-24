/**
 * r13 mutation kills for objective-binding.ts: every readObjectiveCommitment refusal (exact message, including
 * array / null / non-string look-alikes that only the precise shape checks catch), and resolveObjectiveRisk's
 * exact mismatch reasons, empty instance defaults, calibration wiring, denominations and the fail-closed catch.
 */
import { describe, expect, it } from 'vitest';
import type { Capability } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import {
  calibrationDigest,
  commitGoal,
  DEFAULT_NATIVE_CONFIG,
  InMemoryInverseRegistry,
  nativeHashEmbedder,
  objectiveRisk,
  ResourceGraph,
} from './objective-risk';
import { readObjectiveCommitment, resolveObjectiveRisk, type ObjectiveRiskCommitment, type ObjectiveRiskInstanceConfig } from './objective-binding';

const P = generateKeyPair();
const A = generateKeyPair();
const native = nativeHashEmbedder();
const goalAction = { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } };
const act = goalAction;

const instanceCfg: ObjectiveRiskInstanceConfig = {
  registry: {
    trusted_verifiers: ['acme'],
    entries: [{ verb: 'revoke_session', inverse_kind: 'restore_session', fidelity: 'exact', verification: { verifier_id: 'acme', evidence_digest: 'e1' } }],
  },
  graph: {
    nodes: [{ id: '/acct/1/s', harm: { rows: 10 } }, { id: '/acct/1', harm: { rows: 100 } }, { id: '/other', harm: { rows: 1 } }],
    edges: [{ from: '/acct/1/s', to: '/acct/1', kind: 'owns' }],
  },
};
const directReg = () =>
  new InMemoryInverseRegistry(['acme']).register('revoke_session', { inverseKind: 'restore_session', fidelity: 'exact', verification: { verifierId: 'acme', evidenceDigest: 'e1' } });
const directGraph = () => new ResourceGraph().addNode({ id: '/acct/1/s', harm: { rows: 10 } }).addNode({ id: '/acct/1', harm: { rows: 100 } }).addNode({ id: '/other', harm: { rows: 1 } }).addEdge({ from: '/acct/1/s', to: '/acct/1', kind: 'owns' });
const EMPTY_REG = new InMemoryInverseRegistry([]).digest();
const EMPTY_GRAPH = new ResourceGraph().digest();

const commitment = (over: Record<string, unknown> = {}): ObjectiveRiskCommitment =>
  ({
    v: 1,
    embedder: { scheme: 'native', model_id: native.modelId, config: DEFAULT_NATIVE_CONFIG },
    goal: commitGoal(native, goalAction),
    registry_digest: directReg().digest(),
    graph_digest: directGraph().digest(),
    authorized_kinds: ['restore_session'],
    ...over,
  }) as ObjectiveRiskCommitment;

function grant(objective?: unknown): Capability {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
      caveats: [{ type: 'expires', at: 9e12 }] as never,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
      ...(objective !== undefined ? { objective_risk: objective } : {}),
    } as never,
  }).grant;
}
/** An unsigned grant-shaped object carrying an envelope caveat (readObjectiveCommitment reads, it does not verify). */
const fake = (objective: unknown): Capability =>
  ({ caveats: [{ type: 'envelope', goal_commit: 'g', predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, objective_risk: objective }] }) as unknown as Capability;
const read = (o: unknown) => readObjectiveCommitment(fake(o));
const arr = <T extends object>(props: T, items: unknown[] = []) => Object.assign([...items], props);

const M = {
  shape: 'objective_risk: unsupported shape/version',
  emb: 'objective_risk.embedder must be { scheme: "native", model_id, config }',
  goal: 'objective_risk.goal must be a goal commitment',
  dig: 'objective_risk needs registry_digest and graph_digest',
  cal: 'objective_risk.calibration_digest must be a string',
  kinds: 'objective_risk.authorized_kinds must be string[]',
  den: 'objective_risk.denominations must be an array',
  onm: 'objective_risk.on_mismatch must be "deny" or "heuristic"',
};

describe('readObjectiveCommitment', () => {
  it('no envelope / no field => {}', () => {
    expect(readObjectiveCommitment({ caveats: [] } as unknown as Capability)).toEqual({});
    expect(readObjectiveCommitment(grant())).toEqual({});
  });
  it('accepts a well-formed commitment (optional members absent or valid)', () => {
    const c = commitment();
    expect(read(c)).toEqual({ commitment: c });
    for (const over of [{ on_mismatch: 'deny' }, { on_mismatch: 'heuristic' }, { denominations: [] }, { calibration_digest: 'cd' }, { authorized_kinds: [] }]) {
      const x = commitment(over);
      expect(read(x)).toEqual({ commitment: x });
    }
  });
  it('shape / version', () => {
    expect(read(null)).toEqual({ malformed: M.shape });
    expect(read('x')).toEqual({ malformed: M.shape });
    expect(read(commitment({ v: 2 }))).toEqual({ malformed: M.shape });
    expect(read(arr({ ...commitment() }))).toEqual({ malformed: M.shape });
  });
  it('embedder', () => {
    const e = commitment().embedder;
    for (const embedder of [null, undefined, 'native', arr({ ...e }), { ...e, scheme: 'byo' }, { ...e, model_id: '' }, { ...e, model_id: 7 }, { ...e, model_id: ['m'] }, { ...e, config: 'x' }, { ...e, config: null }, { ...e, config: arr({ ...DEFAULT_NATIVE_CONFIG }) }]) {
      expect(read(commitment({ embedder }))).toEqual({ malformed: M.emb });
    }
  });
  it('goal', () => {
    const g = commitment().goal;
    for (const goal of [undefined, null, 'x', arr({ ...g }), { ...g, commit: '' }, { ...g, commit: ['c'] }]) {
      expect(read(commitment({ goal }))).toEqual({ malformed: M.goal });
    }
  });
  it('digests', () => {
    expect(read(commitment({ registry_digest: '' }))).toEqual({ malformed: M.dig });
    expect(read(commitment({ graph_digest: '' }))).toEqual({ malformed: M.dig });
    expect(read(commitment({ graph_digest: undefined }))).toEqual({ malformed: M.dig });
    expect(read(commitment({ calibration_digest: '' }))).toEqual({ malformed: M.cal });
    expect(read(commitment({ calibration_digest: 5 }))).toEqual({ malformed: M.cal });
  });
  it('authorized_kinds', () => {
    for (const authorized_kinds of [undefined, 'a', ['a', 5], [5]]) expect(read(commitment({ authorized_kinds }))).toEqual({ malformed: M.kinds });
  });
  it('denominations and on_mismatch', () => {
    expect(read(commitment({ denominations: 'x' }))).toEqual({ malformed: M.den });
    expect(read(commitment({ denominations: {} }))).toEqual({ malformed: M.den });
    expect(read(commitment({ on_mismatch: 'bogus' }))).toEqual({ malformed: M.onm });
    expect(read(commitment({ on_mismatch: '' }))).toEqual({ malformed: M.onm });
    expect(read(commitment({ on_mismatch: null }))).toEqual({ malformed: M.onm });
  });
});

describe('resolveObjectiveRisk', () => {
  it('a malformed commitment is a deny mismatch naming the reason', () => {
    expect(resolveObjectiveRisk({ grant: fake({ v: 2 }), action: act, instance: instanceCfg })).toEqual({ mode: 'mismatch', reasons: [M.shape], onMismatch: 'deny' });
  });
  it('no instance config', () => {
    expect(resolveObjectiveRisk({ grant: grant(commitment({ on_mismatch: 'heuristic' })), action: act, instance: undefined })).toEqual({
      mode: 'mismatch',
      reasons: ['the grant commits objective-risk facts but the instance holds no objective-risk config'],
      onMismatch: 'heuristic',
    });
  });
  it('re-reads the envelope and fails closed when it is gone on the second read', () => {
    const real = grant(commitment());
    let n = 0;
    const flaky = { ...real, get caveats() { return n++ === 0 ? real.caveats : []; } } as unknown as Capability;
    expect(resolveObjectiveRisk({ grant: flaky, action: act, instance: instanceCfg })).toEqual({ mode: 'mismatch', reasons: ['grant carries no valid envelope'], onMismatch: 'deny' });
  });
  it('embedder model mismatch', () => {
    const g = grant(commitment({ embedder: { scheme: 'native', model_id: 'native:other', config: DEFAULT_NATIVE_CONFIG } }));
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg })).toEqual({ mode: 'mismatch', reasons: ['embedder model_id does not match the committed one'], onMismatch: 'deny' });
  });
  it('an empty instance config builds an empty registry and graph', () => {
    const g = grant(commitment({ registry_digest: EMPTY_REG, graph_digest: EMPTY_GRAPH, authorized_kinds: [] }));
    const res = resolveObjectiveRisk({ grant: g, action: act, instance: {} });
    expect(res.mode).toBe('objective');
    const res2 = resolveObjectiveRisk({ grant: g, action: act, instance: { registry: {}, graph: {} } });
    expect(res2).toEqual(res);
  });
  it('digest mismatches carry the objectiveRisk reasons verbatim', () => {
    const g = grant(commitment());
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: {} })).toEqual({
      mode: 'mismatch',
      reasons: ['registry digest does not match the committed digest', 'graph digest does not match the committed digest'],
      onMismatch: 'deny',
    });
  });
  it('matches a direct objectiveRisk over the same facts, denominations included', () => {
    const dens = [{ id: 'rows', ceiling: 1, weight: 1 }];
    for (const denominations of [dens, undefined]) {
      const g = grant(commitment(denominations ? { denominations } : {}));
      const res = resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg, taint: 0.25, age: 0.5 });
      const reg = directReg();
      const gr = directGraph();
      const direct = objectiveRisk(act, {
        registry: reg, authorizedKinds: new Set(['restore_session']), graph: gr, embedder: native, goal: commitment().goal,
        commitments: { registryDigest: reg.digest(), graphDigest: gr.digest() }, denominations: denominations ?? [],
        weights: DEFAULT_RISK_POLICY.weights, taint: 0.25, age: 0.5,
      });
      expect(res).toEqual({
        mode: 'objective',
        inputs: { reversibility: direct.inputs.reversibility, blastRadius: direct.inputs.blastRadius, semanticDistance: direct.inputs.semanticDistance },
        r: direct.r,
        evidenceDigest: direct.evidenceDigest,
      });
    }
  });
  it('denominations change the blast radius (they are passed through)', () => {
    const a = resolveObjectiveRisk({ grant: grant(commitment({ denominations: [{ id: 'rows', ceiling: 1, weight: 1 }] })), action: act, instance: instanceCfg });
    const b = resolveObjectiveRisk({ grant: grant(commitment()), action: act, instance: instanceCfg });
    expect(a.mode === 'objective' && b.mode === 'objective' && a.inputs.blastRadius !== b.inputs.blastRadius).toBe(true);
  });
  it('calibration: committed digest must match, and the matching set calibrates r', () => {
    const scores = [0.0, 0.01, 0.02, 5, 6, 7];
    const g = grant(commitment({ calibration_digest: calibrationDigest(scores) }));
    const ok = resolveObjectiveRisk({ grant: g, action: act, instance: { ...instanceCfg, calibration: scores } });
    const reg = directReg();
    const gr = directGraph();
    const direct = objectiveRisk(act, {
      registry: reg, authorizedKinds: new Set(['restore_session']), graph: gr, embedder: native, goal: commitment().goal,
      commitments: { registryDigest: reg.digest(), graphDigest: gr.digest(), calibrationDigest: calibrationDigest(scores) }, denominations: [],
      weights: DEFAULT_RISK_POLICY.weights, taint: 1, age: 1, calibration: scores,
    });
    expect(ok).toEqual({
      mode: 'objective',
      inputs: { reversibility: direct.inputs.reversibility, blastRadius: direct.inputs.blastRadius, semanticDistance: direct.inputs.semanticDistance },
      r: direct.r,
      evidenceDigest: direct.evidenceDigest,
    });
    expect(direct.r).not.toBe(direct.raw);
    const CAL = { mode: 'mismatch', reasons: ['calibration set does not match the committed digest'], onMismatch: 'deny' };
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: { ...instanceCfg, calibration: [0.9] } })).toEqual(CAL);
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg })).toEqual(CAL);
  });
  it('an instance calibration set is ignored when the grant commits no digest', () => {
    const g = grant(commitment());
    const withCal = resolveObjectiveRisk({ grant: g, action: act, instance: { ...instanceCfg, calibration: [0.0, 0.01, 5] } });
    const without = resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg });
    expect(withCal.mode).toBe('objective');
    expect(withCal).toEqual(without);
  });
  it('fails closed with the error message on a throw, and names non-Error throws unknown', () => {
    const g = grant(commitment());
    const badEdge = { ...instanceCfg, graph: { nodes: [], edges: [{ from: 'a', to: 'b', kind: 'owns' }] } } as ObjectiveRiskInstanceConfig;
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: badEdge })).toEqual({
      mode: 'mismatch', reasons: ['objective risk evaluation error (fail closed): edge endpoints must exist'], onMismatch: 'deny',
    });
    const throwsStr = {
      registry: { entries: [{ verb: 'v', inverse_kind: 'k', fidelity: 'exact', get verification(): never { throw 'boom'; } }] },
    } as unknown as ObjectiveRiskInstanceConfig;
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: throwsStr })).toEqual({
      mode: 'mismatch', reasons: ['objective risk evaluation error (fail closed): unknown'], onMismatch: 'deny',
    });
  });
});
