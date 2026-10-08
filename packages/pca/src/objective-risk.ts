// objective-risk digests are SERVER-ONLY (the language verifiers never recompute
// them) and carry high-precision floats (calibration scores, graph harm weights,
// risk inputs), so they use the LENIENT canonical hash, not the strict protocol one.
import { canonicalize, hashCanonicalLenient as hashCanonical, sha256, utf8 } from './hash';
import { riskScore, type RiskInputs, type RiskWeights } from './risk';
import type { DecideInput } from './policy-vm';
import type { DisputableInput, ObjectiveOracle, OracleResolution } from './optimistic';

/**
 * Objective risk functional (docs/pca-frontier/objective-risk.md).
 *
 * Every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL ACTION
 * (verb + resource + params, canonicalized like the PCActn). Nothing the agent merely asserts
 * (features, labels, scope, confidence) is read. Agent and verifier recompute the same r; the
 * grant commits the registry, graph, embedder and goal, and a mismatch fails closed (r = 1).
 * The output feeds the existing `riskScore`, so policy-vm sees the unchanged `RiskInputs` shape.
 */

const clamp01 = (x: number) => (Number.isFinite(x) ? (x < 0 ? 0 : x > 1 ? 1 : x) : 1);
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

// ---- canonical action --------------------------------------------------------------------

/** What the agent submits. Only these three fields are ever read; extra properties are ignored. */
export interface ObjAction {
  verb: string;
  resource: string;
  params?: Record<string, unknown>;
}

export interface CanonicalAction {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
}

/** The capability's scope. Comes from the grant, never from the agent's action. */
export interface Scope {
  edgeKinds?: string[];
  maxDepth?: number;
}

function normValue(v: unknown): unknown {
  if (typeof v === 'string') return v.normalize('NFC');
  if (Array.isArray(v)) return v.map(normValue);
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as object)) {
      const nk = k.normalize('NFC');
      if (nk in out) throw new TypeError('canonicalAction: duplicate key after NFC normalization');
      out[nk] = normValue((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/**
 * Canonical form: verb trimmed + lowercased, all strings/keys Unicode-NFC, params validated by the
 * same `canonicalize` the PCActn uses (rejects undefined, NaN, cycles, non-plain objects).
 * Re-encodings that do not change the action (key order, NFC/NFD, verb case) collapse to one form.
 * Throws TypeError on anything without a stable encoding.
 */
export function canonicalAction(a: ObjAction): CanonicalAction {
  if (typeof a?.verb !== 'string' || typeof a.resource !== 'string') throw new TypeError('canonicalAction: verb/resource must be strings');
  const verb = a.verb.normalize('NFC').trim().toLowerCase();
  const resource = a.resource.normalize('NFC').trim();
  if (!verb || !resource) throw new TypeError('canonicalAction: empty verb/resource');
  const params = normValue(a.params ?? {}) as Record<string, unknown>;
  if (params === null || typeof params !== 'object' || Array.isArray(params)) throw new TypeError('canonicalAction: params must be an object');
  const c = { verb, resource, params };
  canonicalize(c); // validate
  return c;
}

export const canonicalActionJson = (c: CanonicalAction): string => canonicalize(c);
export const canonicalActionDigest = (c: CanonicalAction): string => hashCanonical(c);

// ---- 1. reversibility: a committed registry of verified inverses -------------------------

export type ReversibilityClass = 'reversible' | 'compensable' | 'irreversible';

export interface InverseVerification {
  /** who verified the inverse (must be in the registry's committed trusted-verifier set) */
  verifierId: string;
  /** digest of the verification evidence (replay transcript, attestation, ...) */
  evidenceDigest: string;
}

export interface InverseEntry {
  inverseKind: string;
  /** exact undo vs. best-effort compensation (refund != unsend) */
  fidelity: 'exact' | 'partial';
  verification?: InverseVerification;
}

export interface InverseRegistry {
  lookup(verb: string): InverseEntry | undefined;
  /** verifier ids whose verification counts; committed as part of the digest */
  trustedVerifiers(): readonly string[];
  /** canonical digest of ALL contents; the grant commits this */
  digest(): string;
}

export class InMemoryInverseRegistry implements InverseRegistry {
  private readonly m = new Map<string, InverseEntry>();
  private readonly trusted: string[];
  constructor(trustedVerifiers: readonly string[] = []) {
    this.trusted = [...new Set(trustedVerifiers)].sort(cmp);
  }
  register(verb: string, e: InverseEntry): this {
    this.m.set(verb, { ...e, ...(e.verification ? { verification: { ...e.verification } } : {}) });
    return this;
  }
  lookup(verb: string): InverseEntry | undefined {
    const e = this.m.get(verb);
    return e ? { ...e } : undefined;
  }
  trustedVerifiers(): readonly string[] {
    return this.trusted;
  }
  digest(): string {
    const entries = [...this.m.entries()]
      .sort(([a], [b]) => cmp(a, b))
      .map(([verb, e]) => ({ verb, inverseKind: e.inverseKind, fidelity: e.fidelity, verification: e.verification ?? null }));
    return hashCanonical({ v: 1, trusted: this.trusted, entries });
  }
}

export interface Reversibility {
  class: ReversibilityClass;
  /** 1 reversible, 0.5 compensable, 0 irreversible (feeds RiskInputs.reversibility) */
  value: number;
  inverseKind?: string;
}

/**
 * Reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND
 * the inverse verb is itself authorized by the capability. `verified` is derived from committed
 * evidence, not a flag. Anything else is irreversible. Inverses of inverses are not chased.
 */
export function reversibility(action: Pick<CanonicalAction, 'verb'>, registry: InverseRegistry, authorizedKinds: ReadonlySet<string>): Reversibility {
  const e = registry.lookup(action.verb);
  const trusted = e?.verification ? registry.trustedVerifiers().includes(e.verification.verifierId) : false;
  if (!e || !trusted || !authorizedKinds.has(e.inverseKind)) return { class: 'irreversible', value: 0 };
  return e.fidelity === 'exact'
    ? { class: 'reversible', value: 1, inverseKind: e.inverseKind }
    : { class: 'compensable', value: 0.5, inverseKind: e.inverseKind };
}

// ---- 2. blast radius: reachability over a committed resource graph -----------------------

export type HarmUnits = Readonly<Record<string, number>>;

export interface ResourceNode {
  id: string;
  /** harm if destroyed/exposed, per denomination (rows, usd, ...) */
  harm?: HarmUnits;
}
export interface ResourceEdge {
  from: string;
  to: string;
  kind: string;
}

/**
 * Adjacency model with a content digest the grant commits. Production source of truth: schema
 * foreign keys, IAM/routing tables and endpoint manifests, snapshotted into this shape and
 * committed at grant time (see the design note).
 */
export class ResourceGraph {
  private readonly nodes = new Map<string, ResourceNode>();
  private readonly out = new Map<string, ResourceEdge[]>();
  addNode(n: ResourceNode): this {
    this.nodes.set(n.id, n);
    if (!this.out.has(n.id)) this.out.set(n.id, []);
    return this;
  }
  addEdge(e: ResourceEdge): this {
    if (!this.nodes.has(e.from) || !this.nodes.has(e.to)) throw new Error('edge endpoints must exist');
    this.out.get(e.from)!.push(e);
    return this;
  }
  get size(): number {
    return this.nodes.size;
  }
  node(id: string): ResourceNode | undefined {
    return this.nodes.get(id);
  }
  /** BFS reachable set (including `start`), edge-kind and depth restricted, sorted. */
  reachable(start: string, scope?: Scope): string[] {
    if (!this.nodes.has(start)) return [];
    const kinds = scope?.edgeKinds ? new Set(scope.edgeKinds) : undefined;
    const maxDepth = scope?.maxDepth ?? Infinity;
    const seen = new Set([start]);
    let frontier = [start];
    for (let d = 0; d < maxDepth && frontier.length; d++) {
      const next: string[] = [];
      for (const u of frontier)
        for (const e of this.out.get(u) ?? [])
          if ((!kinds || kinds.has(e.kind)) && !seen.has(e.to)) {
            seen.add(e.to);
            next.push(e.to);
          }
      frontier = next;
    }
    return [...seen].sort(cmp);
  }
  digest(): string {
    const n = [...this.nodes.values()].map((x) => ({ id: x.id, harm: x.harm ?? {} })).sort((a, b) => cmp(a.id, b.id));
    const e = [...this.out.values()].flat().map((x) => ({ from: x.from, to: x.to, kind: x.kind })).sort((a, b) => cmp(`${a.from}\u0000${a.to}\u0000${a.kind}`, `${b.from}\u0000${b.to}\u0000${b.kind}`));
    return hashCanonical({ v: 1, n, e });
  }
}

export interface BlastRadius {
  count: number;
  reachable: string[];
  /** count / |graph| in [0,1]; unknown resource = 1 (fail closed) */
  normalized: number;
  harm: HarmUnits;
}

export function blastRadius(action: Pick<CanonicalAction, 'resource'>, graph: ResourceGraph, scope?: Scope): BlastRadius {
  const reachable = graph.reachable(action.resource, scope);
  if (reachable.length === 0 || graph.size === 0) return { count: 0, reachable, normalized: 1, harm: {} };
  const harm: Record<string, number> = {};
  for (const id of reachable)
    for (const [d, v] of Object.entries(graph.node(id)?.harm ?? {})) if (Number.isFinite(v) && v > 0) harm[d] = (harm[d] ?? 0) + v;
  return { count: reachable.length, reachable, normalized: reachable.length / graph.size, harm };
}

// ---- 3. committed embeddings -------------------------------------------------------------

/**
 * An embedder maps the CANONICAL ACTION to an integer vector. It never sees agent-supplied
 * features. `modelId` is a committed identity: it is a hash of `config` (native) or of the model
 * descriptor (BYO), so two embedders with different behaviour cannot share an id.
 */
export interface Embedder {
  modelId: string;
  /** the committed descriptor behind modelId (native config or BYO descriptor) */
  config: unknown;
  dims: number;
  /** MUST return `dims` safe integers, deterministic for equal canonical actions. May throw. */
  embed(action: CanonicalAction): number[];
}

export class EmbeddingError extends Error {}

/** Largest |component| such that dot products of two `dims`-vectors stay exact in a double. */
const maxComponent = (dims: number) => Math.floor(Math.sqrt(Number.MAX_SAFE_INTEGER / (2 * Math.max(1, dims))));

export function validateVector(v: unknown, dims: number): number[] {
  if (!Array.isArray(v) || v.length !== dims) throw new EmbeddingError(`vector must have exactly ${dims} components`);
  const lim = maxComponent(dims);
  for (const x of v) {
    if (!Number.isSafeInteger(x)) throw new EmbeddingError('vector components must be safe integers');
    if (Math.abs(x as number) > lim) throw new EmbeddingError('vector component out of range');
  }
  return (v as number[]).map((x) => (Object.is(x, -0) ? 0 : x));
}

// -- native: integer feature hashing over n-grams of the canonical action

/**
 * A2i — PARAM-STUFFING defense. How the canonical action's params contribute to the embedding:
 *  - `leaves` (default, back-compat): every flattened `path=value` leaf emits text features, as before.
 *  - `digest`: ALL params collapse to a SINGLE feature = the canonical-params digest, so the semantic vector
 *    is bound to verb+resource plus ONE params token. Adding/removing junk params then moves at most that one
 *    token's buckets instead of flooding the vector, so an agent cannot dilute or inflate the distance-to-goal
 *    by stuffing params.
 */
export type ParamMode = 'leaves' | 'digest';

export interface NativeEmbedderConfig {
  dims: number;
  ngramMin: number;
  ngramMax: number;
  seed: string;
  /** integer weights per field of the canonical action */
  fieldWeights: { verb: number; resource: number; param: number };
  /**
   * A2i — hard cap on the number of flattened param LEAVES the embedder will accept. More than this fails
   * CLOSED (the embed throws → distance 1 → `objectiveRisk` r = 1), so an action cannot dilute/inflate its
   * risk by stuffing unbounded params. Absent ⇒ the protocol default {@link DEFAULT_MAX_PARAM_LEAVES} is
   * enforced anyway (so the default embedder is defended without a modelId change). A smaller explicit value
   * tightens the bound (and, being committed, changes the modelId — intended).
   */
  maxParamLeaves?: number;
  /** A2i — how params enter the vector. Absent ⇒ `leaves` (back-compat). See {@link ParamMode}. */
  paramMode?: ParamMode;
}

export const NATIVE_SCHEME = 'pca-native-hash-ngram-v1';

/**
 * A2i — protocol default cap on flattened param leaves, enforced even when a config omits `maxParamLeaves`
 * (so the stock embedder is defended without changing its committed modelId). Generous enough for every
 * legitimate action, low enough that params cannot flood the vector. A cross-impl constant of the scheme.
 */
export const DEFAULT_MAX_PARAM_LEAVES = 256;

export const DEFAULT_NATIVE_CONFIG: NativeEmbedderConfig = {
  dims: 256,
  ngramMin: 2,
  ngramMax: 4,
  seed: 'pca-native-v1',
  fieldWeights: { verb: 4, resource: 2, param: 1 },
};

function validateNativeConfig(c: NativeEmbedderConfig): void {
  const okInt = (x: number, lo: number, hi: number) => Number.isSafeInteger(x) && x >= lo && x <= hi;
  if (!okInt(c.dims, 8, 65536)) throw new RangeError('native config: dims must be an integer in [8, 65536]');
  if (!okInt(c.ngramMin, 1, 8) || !okInt(c.ngramMax, c.ngramMin, 8)) throw new RangeError('native config: need 1 <= ngramMin <= ngramMax <= 8');
  if (typeof c.seed !== 'string' || !c.seed) throw new RangeError('native config: seed required');
  for (const k of ['verb', 'resource', 'param'] as const) if (!okInt(c.fieldWeights[k], 0, 1000)) throw new RangeError(`native config: fieldWeights.${k} must be an integer in [0, 1000]`);
  if (c.maxParamLeaves !== undefined && !okInt(c.maxParamLeaves, 1, 1_000_000)) throw new RangeError('native config: maxParamLeaves must be an integer in [1, 1000000]');
  if (c.paramMode !== undefined && c.paramMode !== 'leaves' && c.paramMode !== 'digest') throw new RangeError("native config: paramMode must be 'leaves' or 'digest'");
}

/** Flatten params to sorted `path=value` leaves (nested key order and array encoding are irrelevant). */
function paramLeaves(v: unknown, path: string, out: string[]): void {
  if (Array.isArray(v)) v.forEach((x, i) => paramLeaves(x, `${path}[${i}]`, out));
  else if (v !== null && typeof v === 'object') for (const k of Object.keys(v).sort()) paramLeaves((v as Record<string, unknown>)[k], path ? `${path}.${k}` : k, out);
  else out.push(`${path}=${canonicalize(v)}`);
}

function textFeatures(prefix: string, text: string, nmin: number, nmax: number): string[] {
  const out: string[] = [];
  const cps = Array.from(`\u0002${text}\u0003`); // code points, with boundary markers
  for (let n = nmin; n <= nmax; n++) for (let i = 0; i + n <= cps.length; i++) out.push(`${prefix}c${n}:${cps.slice(i, i + n).join('')}`);
  for (const w of text.split(/[^\p{L}\p{N}]+/u)) if (w) out.push(`${prefix}w:${w.toLowerCase()}`);
  return out;
}

/**
 * Native embedder. For each field (verb, resource, each param leaf) emit code-point n-grams and
 * word tokens; each feature f is hashed as SHA-256(seed 0x1F f): bucket = big-endian u32(h[0..4])
 * mod dims, sign = low bit of h[4]; the bucket accumulates ±fieldWeight. Output is an integer
 * vector. Only SHA-256, UTF-8, integer arithmetic and Unicode NFC/code-point iteration are needed,
 * so any language reproduces it bit-for-bit. Semantically shallow (surface similarity), but the
 * agent cannot steer it without changing the actual action.
 */
export function nativeHashEmbedder(config: NativeEmbedderConfig = DEFAULT_NATIVE_CONFIG): Embedder {
  validateNativeConfig(config);
  const cfg: NativeEmbedderConfig = { ...config, fieldWeights: { ...config.fieldWeights } };
  const committed = { scheme: NATIVE_SCHEME, ...cfg };
  const modelId = `native:${hashCanonical(committed)}`;
  const prefix = utf8(`${cfg.seed}\u001f`);
  return {
    modelId,
    config: committed,
    dims: cfg.dims,
    embed(a) {
      const v = new Array<number>(cfg.dims).fill(0);
      const add = (feat: string, w: number) => {
        if (w === 0) return;
        const f = utf8(feat);
        const buf = new Uint8Array(prefix.length + f.length);
        buf.set(prefix);
        buf.set(f, prefix.length);
        const h = sha256(buf);
        const bucket = ((h[0]! * 16777216 + h[1]! * 65536 + h[2]! * 256 + h[3]!) >>> 0) % cfg.dims;
        v[bucket] = v[bucket]! + ((h[4]! & 1) === 0 ? w : -w);
      };
      for (const f of textFeatures('v:', a.verb, cfg.ngramMin, cfg.ngramMax)) add(f, cfg.fieldWeights.verb);
      for (const f of textFeatures('r:', a.resource, cfg.ngramMin, cfg.ngramMax)) add(f, cfg.fieldWeights.resource);
      const leaves: string[] = [];
      paramLeaves(a.params, '', leaves);
      // A2i: fail CLOSED on a param-stuffed action — more leaves than the cap can never produce a (diluted)
      // favorable embedding; the embed throws, which `objectiveRisk` turns into r = 1 (worst case).
      const cap = cfg.maxParamLeaves ?? DEFAULT_MAX_PARAM_LEAVES;
      if (leaves.length > cap) throw new EmbeddingError(`param leaf count ${leaves.length} exceeds cap ${cap}`);
      if (cfg.paramMode === 'digest') {
        // Bind the whole params object to ONE digest token: params touch a single bucket regardless of how
        // many are present, so verb+resource dominate and stuffing cannot flood/dilute the vector.
        add(`p#:${hashCanonical({ t: 'pca-objrisk-params-v1', params: a.params })}`, cfg.fieldWeights.param);
      } else {
        for (const leaf of leaves) for (const f of textFeatures('p:', leaf, cfg.ngramMin, cfg.ngramMax)) add(f, cfg.fieldWeights.param);
      }
      return v;
    },
  };
}

// -- BYO: a customer-supplied model that meets the determinism contract

/**
 * Descriptor the customer commits. modelId = "byo:" + hashCanonical(descriptor). Contract (full
 * text in the design note): pinned weights (`weightsDigest`), fixed-point/quantized inference with
 * no floating-point reduction-order dependence, input = `canonicalActionJson` bytes, fixed `dims`
 * and `quantization`, output = safe integers within the quantization range.
 */
export interface ByoDescriptor {
  name: string;
  version: string;
  /** digest of the pinned weights file(s) */
  weightsDigest: string;
  /** identifier of the exact inference runtime + build (e.g. an onnx-int8 build hash) */
  runtime: string;
  dims: number;
  quantization: { bits: number; scale: number };
  inputEncoding: 'pca-canonical-action-json-v1';
}

export const byoModelId = (d: ByoDescriptor): string => `byo:${hashCanonical(d)}`;

/**
 * `infer` receives the canonical action JSON and returns the integer vector. If `claimedModelId`
 * is given it must equal the descriptor hash (a customer cannot claim someone else's id).
 */
export function byoEmbedder(descriptor: ByoDescriptor, infer: (canonicalJson: string) => number[], claimedModelId?: string): Embedder {
  if (!Number.isSafeInteger(descriptor.dims) || descriptor.dims < 1) throw new RangeError('byo: dims must be a positive integer');
  const { bits } = descriptor.quantization;
  if (!Number.isSafeInteger(bits) || bits < 2 || bits > 31 || !(descriptor.quantization.scale > 0)) throw new RangeError('byo: invalid quantization');
  if (descriptor.inputEncoding !== 'pca-canonical-action-json-v1') throw new RangeError('byo: unsupported inputEncoding');
  const modelId = byoModelId(descriptor);
  if (claimedModelId !== undefined && claimedModelId !== modelId) throw new Error('byo: modelId does not match the committed descriptor');
  const qmax = 2 ** (bits - 1) - 1;
  return {
    modelId,
    config: descriptor,
    dims: descriptor.dims,
    embed(a) {
      const v = validateVector(infer(canonicalActionJson(a)), descriptor.dims);
      for (const x of v) if (Math.abs(x) > qmax) throw new EmbeddingError('byo: component exceeds declared quantization range');
      return v;
    },
  };
}

/** Run conformance cases ({action, vector}) shipped with a model; true iff all reproduce exactly. */
export function conformanceCheck(e: Embedder, cases: readonly { action: ObjAction; vector: readonly number[] }[]): boolean {
  try {
    return cases.every((c) => {
      const v = e.embed(canonicalAction(c.action));
      return v.length === c.vector.length && v.every((x, i) => x === c.vector[i]);
    });
  } catch {
    return false;
  }
}

// -- goal commitment and distance

export const METRIC = 'half-chord-v1';
export const DEFAULT_EPSILON = 1 / 4096;

export interface GoalCommitment {
  embedderModelId: string;
  config: unknown;
  goalVector: number[];
  metric: typeof METRIC;
  /** distances are rounded UP to a multiple of epsilon (conservative; absorbs last-bit noise) */
  epsilon: number;
  /** hashCanonical({embedderModelId, config, goalVector, metric, epsilon}) made at grant time */
  commit: string;
}

const goalCommitInput = (g: Omit<GoalCommitment, 'commit'>) => ({
  embedderModelId: g.embedderModelId,
  config: g.config,
  goalVector: g.goalVector,
  metric: g.metric,
  epsilon: g.epsilon,
});

/** Embed the goal's CANONICAL action and bind it to this embedder. Throws on invalid input. */
export function commitGoal(embedder: Embedder, goalAction: ObjAction, epsilon = DEFAULT_EPSILON): GoalCommitment {
  if (!(epsilon > 0 && epsilon <= 1)) throw new RangeError('epsilon must be in (0, 1]');
  const goalVector = validateVector(embedder.embed(canonicalAction(goalAction)), embedder.dims);
  const g: Omit<GoalCommitment, 'commit'> = { embedderModelId: embedder.modelId, config: embedder.config, goalVector, metric: METRIC, epsilon };
  return { ...g, commit: hashCanonical(goalCommitInput(g)) };
}

export type Checked<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Verifies the commitment hashes AND is bound to exactly this embedder (id, config, dims). */
export function verifyGoalCommitment(g: GoalCommitment, embedder: Embedder): string | null {
  try {
    if (g.metric !== METRIC) return 'unknown metric';
    if (!(g.epsilon > 0 && g.epsilon <= 1)) return 'bad epsilon';
    if (g.commit !== hashCanonical(goalCommitInput(g))) return 'goal commitment hash mismatch';
    if (g.embedderModelId !== embedder.modelId) return 'embedder modelId mismatch';
    if (hashCanonical(g.config) !== hashCanonical(embedder.config)) return 'embedder config mismatch';
    validateVector(g.goalVector, embedder.dims);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : 'invalid goal commitment';
  }
}

/** Integer vectors -> sin(theta/2) = sqrt((1-cos)/2), rounded up to the grid. Only IEEE `/` and `sqrt`. */
export function vectorDistance(a: readonly number[], b: readonly number[], epsilon = DEFAULT_EPSILON): number {
  if (a.length !== b.length) return 1;
  let dot = 0, na = 0, nb = 0, same = true;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
    if (a[i] !== b[i]) same = false;
  }
  if (na === 0 || nb === 0) return 1;
  if (same) return 0;
  const cos = Math.max(-1, Math.min(1, dot / Math.sqrt(na * nb)));
  const d = Math.sqrt((1 - cos) / 2);
  if (d < 1e-9) return 0; // float noise floor, far below epsilon
  return clamp01(Math.ceil(d / epsilon) * epsilon);
}

/** Distance to the committed goal; ok=false (distance 1) on any commitment/embedding failure. */
export function committedDistanceChecked(action: CanonicalAction, goal: GoalCommitment, embedder: Embedder): Checked<number> {
  const bad = verifyGoalCommitment(goal, embedder);
  if (bad) return { ok: false, reason: bad };
  try {
    const v = validateVector(embedder.embed(action), embedder.dims);
    return { ok: true, value: vectorDistance(v, goal.goalVector, goal.epsilon) };
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'embedding failed' };
  }
}

/** Convenience: accepts an agent submission, canonicalizes it, returns the distance (1 on failure). */
export function committedDistance(action: ObjAction, goal: GoalCommitment, embedder: Embedder): number {
  try {
    const r = committedDistanceChecked(canonicalAction(action), goal, embedder);
    return r.ok ? r.value : 1;
  } catch {
    return 1;
  }
}

// ---- 4. split-conformal calibration ------------------------------------------------------

/**
 * `benignScores` = raw scores of acceptable actions, held out from tuning. For a fresh benign
 * action exchangeable with them: p = (1 + #{s_i >= raw})/(n+1), P(p <= a) <= a. Calibrated r =
 * 1 - p, so flagging r_cal > 1-a has false-alarm rate <= a on benign traffic. Non-decreasing in
 * raw. Empty set or non-finite raw => 1.
 */
export function calibrate(rawScore: number, benignScores: readonly number[]): number {
  const n = benignScores.length;
  if (n === 0 || !Number.isFinite(rawScore)) return 1;
  let ge = 0;
  for (const s of benignScores) if (s >= rawScore) ge++;
  return 1 - (1 + ge) / (n + 1);
}

/** Split-conformal quantile: benign raw <= q with probability >= 1 - alpha. Infinity if n is too small. */
export function conformalThreshold(benignScores: readonly number[], alpha: number): number {
  const n = benignScores.length;
  const k = Math.ceil((n + 1) * (1 - alpha));
  if (n === 0 || k > n) return Infinity;
  return [...benignScores].sort((a, b) => a - b)[k - 1]!;
}

/** Digest of a calibration set, committed by the grant. */
export const calibrationDigest = (scores: readonly number[]): string => hashCanonical({ v: 1, scores: [...scores].sort((a, b) => a - b) });

// ---- 5. harm currency --------------------------------------------------------------------

export interface Denomination {
  id: string;
  /** amount that saturates this denomination to 1.0 */
  ceiling: number;
  weight: number;
}

export interface HarmReport {
  units: HarmUnits;
  /** weighted saturating normalization in [0,1] */
  normalized: number;
}

export function harmReport(units: HarmUnits, denoms: readonly Denomination[]): HarmReport {
  let num = 0, den = 0;
  for (const d of denoms) {
    if (!(d.weight > 0) || !(d.ceiling > 0)) continue;
    num += d.weight * Math.min(1, Math.max(0, units[d.id] ?? 0) / d.ceiling);
    den += d.weight;
  }
  return { units, normalized: den === 0 ? 1 : clamp01(num / den) };
}

// ---- composition -------------------------------------------------------------------------

/** Digests the grant committed; the verifier supplies the same ones it holds. */
export interface RiskCommitments {
  registryDigest: string;
  graphDigest: string;
  /** required when `calibration` is used */
  calibrationDigest?: string;
}

export interface ObjectiveRiskContext {
  registry: InverseRegistry;
  authorizedKinds: ReadonlySet<string>;
  graph: ResourceGraph;
  scope?: Scope;
  embedder: Embedder;
  goal: GoalCommitment;
  commitments: RiskCommitments;
  denominations: readonly Denomination[];
  weights: RiskWeights;
  /** L4 information-flow taint (verifier-computed) */
  taint: number;
  /** ageSinceTouch(...) */
  age: number;
  /**
   * Uncertainty from the separate uncertainty-attestation primitive (higher = more uncertain), in
   * [0,1]. It can only RAISE r. Agent-declared confidence is deliberately not an input here: a
   * self-reported value must never lower r.
   */
  attestedUncertainty?: number;
  /** committed benign raw scores; r becomes the conformal-calibrated value */
  calibration?: readonly number[];
}

export interface ObjectiveRisk {
  /** policy-vm-compatible r in [0,1]; exactly 1 when `valid` is false */
  r: number;
  valid: boolean;
  /** why it was rejected (empty when valid) */
  reasons: string[];
  raw: number;
  /** exactly the shape riskScore()/deriveRisk consume */
  inputs: RiskInputs;
  reversibility: Reversibility;
  blast: BlastRadius;
  harm: HarmReport;
  /** commits every fact the number was computed from; verifier compares */
  evidenceDigest: string;
}

const WORST_INPUTS: RiskInputs = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };

function reject(reasons: string[]): ObjectiveRisk {
  return {
    r: 1,
    valid: false,
    reasons,
    raw: 1,
    inputs: { ...WORST_INPUTS },
    reversibility: { class: 'irreversible', value: 0 },
    blast: { count: 0, reachable: [], normalized: 1, harm: {} },
    harm: { units: {}, normalized: 1 },
    evidenceDigest: '',
  };
}

/**
 * Pure function of (canonical action, committed context). Any commitment mismatch (registry,
 * graph, goal/embedder binding, calibration set) or un-encodable action returns the fail-closed
 * r = 1 with `valid: false`; it never throws. Blast input = max(count-normalized, harm-normalized).
 */
export function objectiveRisk(submitted: ObjAction, ctx: ObjectiveRiskContext): ObjectiveRisk {
  let action: CanonicalAction;
  try {
    action = canonicalAction(submitted);
  } catch (e) {
    return reject([`action: ${e instanceof Error ? e.message : 'not canonicalizable'}`]);
  }
  const reasons: string[] = [];
  if (ctx.registry.digest() !== ctx.commitments.registryDigest) reasons.push('registry digest does not match the committed digest');
  if (ctx.graph.digest() !== ctx.commitments.graphDigest) reasons.push('graph digest does not match the committed digest');
  if (ctx.calibration) {
    if (ctx.commitments.calibrationDigest === undefined) reasons.push('calibration set used without a committed digest');
    else if (calibrationDigest(ctx.calibration) !== ctx.commitments.calibrationDigest) reasons.push('calibration digest does not match the committed digest');
  }
  const dist = committedDistanceChecked(action, ctx.goal, ctx.embedder);
  if (!dist.ok) reasons.push(`goal/embedder: ${dist.reason}`);
  if (reasons.length) return reject(reasons);

  const rev = reversibility(action, ctx.registry, ctx.authorizedKinds);
  const blast = blastRadius(action, ctx.graph, ctx.scope);
  const harm = harmReport(blast.harm, ctx.denominations);
  const uncertainty = clamp01(ctx.attestedUncertainty ?? 0);
  const inputs: RiskInputs = {
    semanticDistance: (dist as { ok: true; value: number }).value,
    reversibility: rev.value,
    blastRadius: Math.max(blast.normalized, ctx.denominations.length && Object.keys(blast.harm).length ? harm.normalized : 0),
    taint: ctx.taint,
    confidence: 1 - uncertainty,
    age: ctx.age,
  };
  const raw = riskScore(inputs, ctx.weights);
  const r = ctx.calibration ? calibrate(raw, ctx.calibration) : raw;
  const evidenceDigest = hashCanonical({
    action: canonicalActionDigest(action),
    scope: { edgeKinds: ctx.scope?.edgeKinds ? [...ctx.scope.edgeKinds].sort(cmp) : null, maxDepth: ctx.scope?.maxDepth ?? null },
    authorized: [...ctx.authorizedKinds].sort(cmp),
    registry: ctx.commitments.registryDigest,
    graph: ctx.commitments.graphDigest,
    goal: ctx.goal.commit,
    calibration: ctx.commitments.calibrationDigest ?? null,
    inputs,
  });
  return { r, valid: true, reasons: [], raw, inputs, reversibility: rev, blast, harm, evidenceDigest };
}

// ---- dispute-game oracle -----------------------------------------------------------------

const isObjRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * An {@link ObjectiveOracle} for the contestable dispute game (see `optimistic.ts`), backed by the OBJECTIVE
 * RISK FUNCTIONAL. Given a disputed input and the frozen open-time snapshot, it recomputes the input from the
 * COMMITTED facts (`ctx`: registry, resource graph, embedder, goal, calibration) over the snapshot's canonical
 * action — nothing the agent asserted — and returns the server-authoritative class / value. It fails CLOSED:
 * any commitment mismatch or un-encodable action makes `objectiveRisk.valid` false, so the oracle returns
 * `valid: false` (the dispute is indeterminate and slashes no one) rather than a fabricated worst case.
 */
export function objectiveRiskOracle(ctx: ObjectiveRiskContext): ObjectiveOracle {
  return {
    resolve(input: DisputableInput, snapshot: DecideInput): OracleResolution {
      try {
        const a = snapshot?.action?.action;
        if (!a || typeof a.verb !== 'string' || typeof a.resource !== 'string') {
          return { input, valid: false, reason: 'snapshot action is missing a canonical verb/resource' };
        }
        const submitted: ObjAction = { verb: a.verb, resource: a.resource, params: isObjRecord(a.params) ? a.params : {} };
        const res = objectiveRisk(submitted, ctx);
        if (!res.valid) return { input, valid: false, reason: res.reasons.join('; ') || 'objective risk could not be reproduced' };
        switch (input) {
          case 'reversibility_class':
            return { input, class: res.reversibility.class, valid: true };
          case 'reversibility':
            return { input, value: res.inputs.reversibility, valid: true };
          case 'blastRadius':
            return { input, value: res.inputs.blastRadius, valid: true };
          case 'semanticDistance':
            return { input, value: res.inputs.semanticDistance, valid: true };
          default:
            return { input, valid: false, reason: `unknown disputed input: ${String(input)}` };
        }
      } catch (e) {
        return { input, valid: false, reason: `objective oracle error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
      }
    },
  };
}
