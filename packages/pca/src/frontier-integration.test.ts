import { describe, expect, it } from 'vitest';
import { attenuate } from './capability';
import { decide, toolCallOf, type DecideInput } from './policy-vm';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import { predicatesCaveat, toolSchemaCaveat, describeEnvelope } from './agent-native';
import {
  InMemoryInverseRegistry,
  ResourceGraph,
  calibrationDigest,
  commitGoal,
  nativeHashEmbedder,
  objectiveRisk,
  DEFAULT_NATIVE_CONFIG,
} from './objective-risk';
import { readObjectiveCommitment, resolveObjectiveRisk, type ObjectiveRiskCommitment, type ObjectiveRiskInstanceConfig } from './objective-binding';

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;

const goalAction = { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } };
const native = nativeHashEmbedder();

const instanceCfg: ObjectiveRiskInstanceConfig = {
  registry: {
    trusted_verifiers: ['acme'],
    entries: [{ verb: 'revoke_session', inverse_kind: 'restore_session', fidelity: 'exact', verification: { verifier_id: 'acme', evidence_digest: 'e1' } }],
  },
  graph: {
    nodes: [{ id: '/acct/1/s', harm: { rows: 10 } }, { id: '/acct/1', harm: { rows: 100 } }, { id: '/acct/2', harm: { rows: 100 } }],
    edges: [{ from: '/acct/1/s', to: '/acct/1', kind: 'owns' }],
  },
};
const regDigest = (c: ObjectiveRiskInstanceConfig) => {
  const r = new InMemoryInverseRegistry(c.registry?.trusted_verifiers ?? []);
  for (const e of c.registry?.entries ?? [])
    r.register(e.verb, { inverseKind: e.inverse_kind, fidelity: e.fidelity, ...(e.verification ? { verification: { verifierId: e.verification.verifier_id, evidenceDigest: e.verification.evidence_digest } } : {}) });
  return r.digest();
};
const graphDigest = (c: ObjectiveRiskInstanceConfig) => {
  const g = new ResourceGraph();
  for (const n of c.graph?.nodes ?? []) g.addNode(n);
  for (const e of c.graph?.edges ?? []) g.addEdge(e);
  return g.digest();
};
const commitment = (over: Partial<ObjectiveRiskCommitment> = {}): ObjectiveRiskCommitment => ({
  v: 1,
  embedder: { scheme: 'native', model_id: native.modelId, config: DEFAULT_NATIVE_CONFIG },
  goal: commitGoal(native, goalAction),
  registry_digest: regDigest(instanceCfg),
  graph_digest: graphDigest(instanceCfg),
  authorized_kinds: ['restore_session'],
  denominations: [{ id: 'rows', ceiling: 1000, weight: 1 }],
  ...over,
});

function grant(objective?: unknown, caveats: Record<string, unknown>[] = [{ type: 'expires', at: 9e12 }]) {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
      caveats: caveats as never,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
      ...(objective !== undefined ? { objective_risk: objective } : {}),
    },
  }).grant;
}

const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const input = (over: Partial<DecideInput> = {}): DecideInput => ({
  grant: grant(),
  action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } } },
  risk: lowRisk,
  budget: { B: 1, tau: NOW, asOf: NOW },
  now: NOW,
  ...over,
});

describe('agent-native caveats are enforced by decide()', () => {
  const schema = toolSchemaCaveat('revoke_session', { props: { device: { type: 'string', enum: ['laptop'] } }, required: ['device'] });

  it('toolCallOf derives {tool,args} from the signed action verb + params', () => {
    expect(toolCallOf({ action: { verb: 'v', resource: 'r', params: { a: 1 } } })).toEqual({ tool: 'v', args: { a: 1 } });
    expect(toolCallOf({ action: { verb: 'v', resource: 'r' } })).toEqual({ tool: 'v', args: {} });
  });

  it('delegated tool_schema: conforming call allowed, violating call denied (fail closed)', () => {
    const g = grant();
    const leaf = attenuate(g, [schema], A.secretKey);
    const ok = decide(input({ grant: g, chain: [g, leaf] }));
    expect(ok.releaseGuardianShare).toBe(true);
    const bad = decide(
      input({ grant: g, chain: [g, leaf], action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'tablet' } } } }),
    );
    expect(bad.releaseGuardianShare).toBe(false);
    expect(bad.reasons.join(' ')).toMatch(/delegated caveat\(s\) not satisfied: tool_schema/);
    // extra, undeclared argument is also rejected (closed schema)
    const extra = decide(
      input({ grant: g, chain: [g, leaf], action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop', x: 1 } } } }),
    );
    expect(extra.releaseGuardianShare).toBe(false);
    // missing params => {} => required arg missing => denied
    const none = decide(input({ grant: g, chain: [g, leaf], action: { action: { verb: 'revoke_session', resource: '/acct/1/s' } } }));
    expect(none.releaseGuardianShare).toBe(false);
  });

  it('a caller cannot smuggle a different toolCall/action through caveatContext', () => {
    const g = grant();
    const leaf = attenuate(g, [schema], A.secretKey);
    const d = decide(
      input({
        grant: g,
        chain: [g, leaf],
        action: { action: { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'tablet' } } },
        caveatContext: { toolCall: { tool: 'revoke_session', args: { device: 'laptop' } } } as never,
      }),
    );
    expect(d.releaseGuardianShare).toBe(false);
  });

  it('delegated predicates caveat enforced', () => {
    const g = grant();
    const leaf = attenuate(g, [predicatesCaveat([{ verb: 'revoke_session', resource: '/acct/1/*' }])], A.secretKey);
    expect(decide(input({ grant: g, chain: [g, leaf] })).releaseGuardianShare).toBe(true);
    const out = decide(
      input({ grant: g, chain: [g, leaf], action: { action: { verb: 'revoke_session', resource: '/acct/2/s', params: { device: 'laptop' } } } }),
    );
    expect(out.releaseGuardianShare).toBe(false);
    expect(out.reasons.join(' ')).toMatch(/predicates/);
  });

  it('root envelope caveats may also carry the new types; existing caveats behave identically', () => {
    expect(decide(input({ grant: grant(undefined, [{ type: 'expires', at: NOW - 1 }]) })).releaseGuardianShare).toBe(false);
    expect(decide(input({ grant: grant(undefined, [{ type: 'expires', at: 9e12 }]) })).releaseGuardianShare).toBe(true);
    expect(decide(input({ grant: grant(undefined, [{ type: 'no_such_caveat' }]) })).releaseGuardianShare).toBe(false);
    expect(decide(input({ grant: grant(undefined, [schema]) })).releaseGuardianShare).toBe(true);
  });

  it('introspection reports the narrowed envelope (tools)', () => {
    const g = grant();
    const leaf = attenuate(g, [schema, predicatesCaveat([{ verb: 'revoke_session', resource: '/acct/1/*' }])], A.secretKey);
    const e = describeEnvelope([g, leaf], NOW, encodeKey(P.publicKey));
    expect(e.ok).toBe(true);
    expect(e.tools).toEqual(['revoke_session']);
    expect(e.verbs).toEqual(['revoke_session']);
    expect(e.unsatisfiable).toEqual([]);
  });
});

describe('objective-risk binding (resolveObjectiveRisk)', () => {
  const act = { verb: 'revoke_session', resource: '/acct/1/s', params: { device: 'laptop' } };

  it('commits nothing => mode none (heuristic fallback)', () => {
    expect(resolveObjectiveRisk({ grant: grant(), action: act, instance: instanceCfg })).toEqual({ mode: 'none' });
    expect(readObjectiveCommitment(grant())).toEqual({});
  });

  it('commitment is carried in the SIGNED envelope and reproduced from instance config', () => {
    const g = grant(commitment());
    expect(readObjectiveCommitment(g).commitment?.registry_digest).toBe(regDigest(instanceCfg));
    const res = resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg });
    expect(res.mode).toBe('objective');
    if (res.mode !== 'objective') return;
    // equals a direct objectiveRisk() over the same committed facts
    const reg = new InMemoryInverseRegistry(['acme']).register('revoke_session', { inverseKind: 'restore_session', fidelity: 'exact', verification: { verifierId: 'acme', evidenceDigest: 'e1' } });
    const g2 = new ResourceGraph().addNode({ id: '/acct/1/s', harm: { rows: 10 } }).addNode({ id: '/acct/1', harm: { rows: 100 } }).addNode({ id: '/acct/2', harm: { rows: 100 } }).addEdge({ from: '/acct/1/s', to: '/acct/1', kind: 'owns' });
    const direct = objectiveRisk(act, {
      registry: reg, authorizedKinds: new Set(['restore_session']), graph: g2, embedder: native, goal: commitment().goal,
      commitments: { registryDigest: reg.digest(), graphDigest: g2.digest() }, denominations: [{ id: 'rows', ceiling: 1000, weight: 1 }],
      weights: DEFAULT_RISK_POLICY.weights, taint: 1, age: 1,
    });
    expect(res.inputs.reversibility).toBe(direct.inputs.reversibility);
    expect(res.inputs.blastRadius).toBe(direct.inputs.blastRadius);
    expect(res.inputs.semanticDistance).toBe(direct.inputs.semanticDistance);
    expect(res.inputs.reversibility).toBe(1); // exact, trusted, authorized inverse
    expect(res.inputs.semanticDistance).toBe(0); // the goal action itself
    expect(res.evidenceDigest).toBe(direct.evidenceDigest);
  });

  it('different actions produce different inputs (distance grows away from the goal)', () => {
    const g = grant(commitment());
    const far = resolveObjectiveRisk({ grant: g, action: { verb: 'delete_account', resource: '/acct/2', params: { all: true } }, instance: instanceCfg });
    expect(far.mode).toBe('objective');
    if (far.mode === 'objective') expect(far.inputs.semanticDistance).toBeGreaterThan(0.1);
  });

  it('digest mismatch (tampered instance registry/graph) => mismatch, default deny', () => {
    const g = grant(commitment());
    const tamperedGraph: ObjectiveRiskInstanceConfig = { ...instanceCfg, graph: { ...instanceCfg.graph, nodes: [...instanceCfg.graph!.nodes!, { id: 'extra' }] } };
    const r1 = resolveObjectiveRisk({ grant: g, action: act, instance: tamperedGraph });
    expect(r1).toMatchObject({ mode: 'mismatch', onMismatch: 'deny' });
    const tamperedReg: ObjectiveRiskInstanceConfig = { ...instanceCfg, registry: { ...instanceCfg.registry, trusted_verifiers: ['acme', 'rogue'] } };
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: tamperedReg })).toMatchObject({ mode: 'mismatch' });
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: undefined })).toMatchObject({ mode: 'mismatch', onMismatch: 'deny' });
  });

  it('on_mismatch: heuristic is honoured; malformed commitments always deny', () => {
    const g = grant(commitment({ on_mismatch: 'heuristic' }));
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: undefined })).toMatchObject({ mode: 'mismatch', onMismatch: 'heuristic' });
    const bad = grant({ v: 1, embedder: 'nope' });
    expect(resolveObjectiveRisk({ grant: bad, action: act, instance: instanceCfg })).toMatchObject({ mode: 'mismatch', onMismatch: 'deny' });
    const wrongModel = grant(commitment({ embedder: { scheme: 'native', model_id: 'native:other', config: DEFAULT_NATIVE_CONFIG } }));
    expect(resolveObjectiveRisk({ grant: wrongModel, action: act, instance: instanceCfg })).toMatchObject({ mode: 'mismatch' });
  });

  it('calibration digest must match when committed', () => {
    const scores = [0.1, 0.2, 0.3];
    const g = grant(commitment({ calibration_digest: calibrationDigest(scores) }));
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: { ...instanceCfg, calibration: scores } }).mode).toBe('objective');
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: { ...instanceCfg, calibration: [0.9] } }).mode).toBe('mismatch');
    expect(resolveObjectiveRisk({ grant: g, action: act, instance: instanceCfg }).mode).toBe('mismatch');
  });
});
