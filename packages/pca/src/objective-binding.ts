import type { Capability } from './capability';
import { readEnvelope, type Envelope } from './envelope';
import type { RiskInputs } from './risk';
import {
  InMemoryInverseRegistry,
  ResourceGraph,
  calibrationDigest,
  nativeHashEmbedder,
  objectiveRisk,
  type Denomination,
  type GoalCommitment,
  type NativeEmbedderConfig,
  type ObjAction,
  type ResourceEdge,
  type ResourceNode,
  type Scope,
} from './objective-risk';

/**
 * Binding of the objective-risk functional to the LIVE decision path, without touching the signed PCActn.
 *
 * The facts live in the already-signed grant envelope, as an optional `objective_risk` field (covered by the
 * root signature: tampering breaks `verifyChain`). A grant that commits nothing is unaffected (the caller falls
 * back to the heuristic). The actual registry / resource graph / calibration set are INSTANCE-held config
 * ({@link ObjectiveRiskInstanceConfig}); their digests must equal the committed ones or the result is a
 * mismatch (fail closed per `on_mismatch`).
 */

export interface ObjectiveRiskCommitment {
  v: 1;
  /** Native deterministic embedder (BYO needs a runtime function, so it cannot be instance-config driven). */
  embedder: { scheme: 'native'; model_id: string; config: NativeEmbedderConfig };
  /** `objectiveRisk.commitGoal(...)` output; re-verified against the embedder. */
  goal: GoalCommitment;
  registry_digest: string;
  graph_digest: string;
  calibration_digest?: string;
  /** inverse kinds the capability authorizes (reversibility needs the inverse verb to be authorized). */
  authorized_kinds: string[];
  scope?: Scope;
  denominations?: Denomination[];
  /** What to do when the instance cannot reproduce the commitments. Default `deny` (risk := 1). */
  on_mismatch?: 'deny' | 'heuristic';
}

/** Instance-held, JSON-serializable inputs the commitments are checked against (`auth_config.pca.objectiveRisk`). */
export interface ObjectiveRiskInstanceConfig {
  registry?: {
    trusted_verifiers?: string[];
    entries?: {
      verb: string;
      inverse_kind: string;
      fidelity: 'exact' | 'partial';
      verification?: { verifier_id: string; evidence_digest: string };
    }[];
  };
  graph?: { nodes?: ResourceNode[]; edges?: ResourceEdge[] };
  calibration?: number[];
}

export type ObjectiveRiskResolution =
  /** The grant commits nothing: use the heuristic. */
  | { mode: 'none' }
  | {
      mode: 'objective';
      /** reversibility / blastRadius / semanticDistance computed from the committed facts */
      inputs: Pick<RiskInputs, 'reversibility' | 'blastRadius' | 'semanticDistance'>;
      r: number;
      evidenceDigest: string;
    }
  | { mode: 'mismatch'; reasons: string[]; onMismatch: 'deny' | 'heuristic' };

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

/** Read the committed `objective_risk` off a grant's envelope: `undefined` = not committed. Pure. */
export function readObjectiveCommitment(grant: Capability): { commitment?: ObjectiveRiskCommitment; malformed?: string } {
  const env = readEnvelope(grant) as Envelope | null;
  const raw = env?.objective_risk;
  if (raw === undefined) return {};
  if (!isObj(raw) || raw.v !== 1) return { malformed: 'objective_risk: unsupported shape/version' };
  const emb = raw.embedder;
  if (!isObj(emb) || emb.scheme !== 'native' || !isStr(emb.model_id) || !isObj(emb.config)) {
    return { malformed: 'objective_risk.embedder must be { scheme: "native", model_id, config }' };
  }
  if (!isObj(raw.goal) || !isStr(raw.goal.commit)) return { malformed: 'objective_risk.goal must be a goal commitment' };
  if (!isStr(raw.registry_digest) || !isStr(raw.graph_digest)) return { malformed: 'objective_risk needs registry_digest and graph_digest' };
  if (raw.calibration_digest !== undefined && !isStr(raw.calibration_digest)) return { malformed: 'objective_risk.calibration_digest must be a string' };
  if (!Array.isArray(raw.authorized_kinds) || !raw.authorized_kinds.every((k) => typeof k === 'string')) {
    return { malformed: 'objective_risk.authorized_kinds must be string[]' };
  }
  if (raw.denominations !== undefined && !Array.isArray(raw.denominations)) return { malformed: 'objective_risk.denominations must be an array' };
  if (raw.on_mismatch !== undefined && raw.on_mismatch !== 'deny' && raw.on_mismatch !== 'heuristic') {
    return { malformed: 'objective_risk.on_mismatch must be "deny" or "heuristic"' };
  }
  return { commitment: raw as unknown as ObjectiveRiskCommitment };
}

function buildRegistry(cfg: ObjectiveRiskInstanceConfig['registry']): InMemoryInverseRegistry {
  const reg = new InMemoryInverseRegistry(cfg?.trusted_verifiers ?? []);
  for (const e of cfg?.entries ?? []) {
    reg.register(e.verb, {
      inverseKind: e.inverse_kind,
      fidelity: e.fidelity,
      ...(e.verification ? { verification: { verifierId: e.verification.verifier_id, evidenceDigest: e.verification.evidence_digest } } : {}),
    });
  }
  return reg;
}

function buildGraph(cfg: ObjectiveRiskInstanceConfig['graph']): ResourceGraph {
  const g = new ResourceGraph();
  for (const n of cfg?.nodes ?? []) g.addNode(n);
  for (const e of cfg?.edges ?? []) g.addEdge(e);
  return g;
}

/**
 * Resolve the objective risk inputs for `action` under `grant`. Total (never throws).
 *  - nothing committed                      => `{ mode: 'none' }` (heuristic, unchanged)
 *  - committed + reproduced                 => `{ mode: 'objective', inputs, r }`
 *  - committed but not reproducible/invalid => `{ mode: 'mismatch', onMismatch }` (default `deny`)
 * `taint`/`age` are verifier-supplied (they only feed `r`; the caller keeps its own taint handling).
 */
export function resolveObjectiveRisk(args: {
  grant: Capability;
  action: ObjAction;
  instance: ObjectiveRiskInstanceConfig | undefined;
  taint?: number;
  age?: number;
}): ObjectiveRiskResolution {
  const { commitment, malformed } = readObjectiveCommitment(args.grant);
  if (malformed) return { mode: 'mismatch', reasons: [malformed], onMismatch: 'deny' };
  if (!commitment) return { mode: 'none' };
  const onMismatch = commitment.on_mismatch ?? 'deny';
  const miss = (...reasons: string[]): ObjectiveRiskResolution => ({ mode: 'mismatch', reasons, onMismatch });
  try {
    const env = readEnvelope(args.grant);
    if (!env) return miss('grant carries no valid envelope');
    if (!args.instance) return miss('the grant commits objective-risk facts but the instance holds no objective-risk config');
    const registry = buildRegistry(args.instance.registry);
    const graph = buildGraph(args.instance.graph);
    const embedder = nativeHashEmbedder(commitment.embedder.config);
    if (embedder.modelId !== commitment.embedder.model_id) return miss('embedder model_id does not match the committed one');
    const calibration = args.instance.calibration;
    if (commitment.calibration_digest !== undefined) {
      if (!calibration || calibrationDigest(calibration) !== commitment.calibration_digest) {
        return miss('calibration set does not match the committed digest');
      }
    }
    const res = objectiveRisk(args.action, {
      registry,
      authorizedKinds: new Set(commitment.authorized_kinds),
      graph,
      scope: commitment.scope,
      embedder,
      goal: commitment.goal,
      commitments: {
        registryDigest: commitment.registry_digest,
        graphDigest: commitment.graph_digest,
        ...(commitment.calibration_digest !== undefined ? { calibrationDigest: commitment.calibration_digest } : {}),
      },
      denominations: commitment.denominations ?? [],
      weights: env.risk_policy.weights,
      taint: args.taint ?? 1,
      age: args.age ?? 1,
      ...(commitment.calibration_digest !== undefined && calibration ? { calibration } : {}),
    });
    if (!res.valid) return miss(...res.reasons);
    return {
      mode: 'objective',
      inputs: {
        reversibility: res.inputs.reversibility,
        blastRadius: res.inputs.blastRadius,
        semanticDistance: res.inputs.semanticDistance,
      },
      r: res.r,
      evidenceDigest: res.evidenceDigest,
    };
  } catch (e) {
    return miss(`objective risk evaluation error (fail closed): ${e instanceof Error ? e.message : 'unknown'}`);
  }
}
