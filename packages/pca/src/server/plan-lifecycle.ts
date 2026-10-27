/**
 * Plan lifecycle (0.5, additive): explicit states around the existing plan commitment (the Merkle root an agent signs into
 * every PCActn) and the principal's plan authorization (`PcaContext.planAuthorized`, `isPlanAuthorized`).
 *
 *   draft ──validate──▶ validated ──commit──▶ committed ──authorize──▶ authorized
 *     └─────────────────────┴──────────────────────┴───────────revoke──────┴──▶ revoked
 *
 *   - `draft`: the nodes are recorded; the root is computed from them (never taken from the caller).
 *   - `validated`: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the
 *     server's own validator (e.g. every node inside the grant's predicates).
 *   - `committed`: the root is fixed. A committed plan is NOT executable: it still needs the principal.
 *   - `authorized`: the principal approved this root for this grant, optionally until `expiresAt`.
 *   - `revoked`: terminal; every later action against the root is denied.
 *
 * "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is `authorized`, the
 * approval has not expired, and its stored nodes still hash to the root. `check()` adds the per-action staleness rules a
 * server applies immediately before execution: the node exists and the operation's verb, resource and params still match
 * what the principal approved (changed params are refused).
 *
 * Wire formats are unchanged: the registry only feeds `plan` / `planAuthorized` into the verifier context (`authorize({
 * plans })`, or `isPlanAuthorized` for `authorizeExecution` / `authorizeToolCall`) and names the state on a denial.
 */

import { CLASS_RANK } from '../reversibility';
import { merkleRoot, paramsDigest, planNodeLeaf, type PlanNode } from '../merkle';
import type { AtomicKv } from './require-pca';
import type { PcaContext, PcaOperation } from './verify';

export type PlanState = 'draft' | 'validated' | 'committed' | 'authorized' | 'revoked';

export interface PlanApproval {
  /** Who approved (the principal's key or account id, for the record). */
  by: string;
  /** The approval lapses after this time (epoch ms). Absent: until revoked. */
  expiresAt?: number;
}

export interface PlanRecord {
  grantRef: string;
  /** Merkle root of `nodes` (computed by the registry). */
  root: string;
  nodes: PlanNode[];
  state: PlanState;
  createdAt: number;
  validatedAt?: number;
  committedAt?: number;
  authorizedAt?: number;
  approval?: PlanApproval;
  revokedAt?: number;
  revokedReason?: string;
}

/** The result of a lifecycle transition. */
export type PlanTransition = { ok: true; record: PlanRecord } | { ok: false; state: PlanState | 'unknown'; reason: string };

/** A plan's state at the moment of use. */
export interface PlanStatus {
  state: PlanState | 'unknown';
  executable: boolean;
  /** Why it is not executable. */
  reason?: string;
  record?: PlanRecord;
}

export interface PlanRegistryOptions {
  /** Where the records live. Default: in memory (one process). Use `openDurableState` (`@atlasauth/pca/durable-state`) or your DB. */
  kv?: AtomicKv;
  /** Key prefix in `kv`. Default `pca-plan:`. */
  prefix?: string;
  /** Clock (epoch ms). Default `Date.now`. */
  now?: () => number;
  /**
   * The server's validation, run by `validate` after the structural checks (e.g. each node is within the grant's
   * predicates, the resources exist). A throw refuses.
   */
  validator?: (rec: PlanRecord) => { ok: true } | { ok: false; reason: string } | Promise<{ ok: true } | { ok: false; reason: string }>;
}

export interface PlanCheckOptions {
  /** The plan node the action executes (the PCActn's `plan.node_id`). */
  nodeId?: string;
  /** The operation about to execute: must match the node (verb, resource, params digest). */
  operation?: PcaOperation;
  now?: number;
}

export interface PlanRegistry {
  /** Record a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused. */
  draft(grantRef: string, nodes: PlanNode[]): Promise<PlanTransition>;
  /** draft -> validated (structural checks, then the server's `validator`). */
  validate(grantRef: string, root: string): Promise<PlanTransition>;
  /** validated -> committed: the root is fixed; it still needs the principal's authorization to execute. */
  commit(grantRef: string, root: string): Promise<PlanTransition>;
  /** committed -> authorized: the principal's approval (call it only after verifying the principal's consent). */
  authorize(grantRef: string, root: string, approval: PlanApproval): Promise<PlanTransition>;
  /** Any state except revoked -> revoked (terminal). */
  revoke(grantRef: string, root: string, reason: string): Promise<PlanTransition>;
  get(grantRef: string, root: string): Promise<PlanRecord | undefined>;
  /** The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). */
  status(grantRef: string, root: string, now?: number): Promise<PlanStatus>;
  /** `status` plus the per-action staleness rules (node exists, the operation matches it). Run it immediately before execution. */
  check(grantRef: string, root: string, opts?: PlanCheckOptions): Promise<PlanStatus>;
  /** For `isPlanAuthorized` options (`authorizeExecution`, `authorizeToolCall`): true only when executable now. */
  isPlanAuthorized(grantRef: string, planRoot: string): Promise<boolean>;
  /** The verifier context for an action against `root`: the stored plan, and `planAuthorized` = executable. Undefined: unknown root. */
  context(grantRef: string, root: string, now?: number): Promise<(Pick<PcaContext, 'plan' | 'planAuthorized'> & { status: PlanStatus }) | undefined>;
}

/** In-process {@link AtomicKv} (the default store of {@link createPlanRegistry}). */
export function memoryAtomicKv(): AtomicKv {
  const m = new Map<string, unknown>();
  return {
    get: async (k) => m.get(k),
    set: async (k, v) => void m.set(k, v),
    async update(k, fn) {
      const next = fn(m.get(k));
      if (next !== undefined) m.set(k, next);
      return m.get(k);
    },
  };
}

const rootOf = (nodes: PlanNode[]): string => merkleRoot(nodes.map(planNodeLeaf));

/** Structural validity of a plan's nodes (the reason, or undefined when valid). */
function structuralProblem(nodes: PlanNode[]): string | undefined {
  if (!Array.isArray(nodes) || nodes.length === 0) return 'a plan needs at least one node';
  const ids = new Set<string>();
  for (const n of nodes) {
    if (!n || typeof n.id !== 'string' || n.id === '') return 'every node needs an id';
    if (ids.has(n.id)) return `duplicate node id '${n.id}'`;
    ids.add(n.id);
    if (typeof n.verb !== 'string' || n.verb === '' || typeof n.resource !== 'string' || n.resource === '') return `node '${n.id}' needs a verb and a resource`;
    if (n.reversibility_class !== undefined && !Object.prototype.hasOwnProperty.call(CLASS_RANK, n.reversibility_class)) {
      return `node '${n.id}' has an unknown reversibility class '${String(n.reversibility_class)}'`;
    }
  }
  return undefined;
}

const isRecord = (v: unknown): v is PlanRecord => v !== null && typeof v === 'object' && typeof (v as PlanRecord).root === 'string' && Array.isArray((v as PlanRecord).nodes);

/** Build a plan registry (see the module doc). */
export function createPlanRegistry(opts: PlanRegistryOptions = {}): PlanRegistry {
  const kv = opts.kv ?? memoryAtomicKv();
  const pre = opts.prefix ?? 'pca-plan:';
  const clock = opts.now ?? Date.now;
  const key = (grantRef: string, root: string) => `${pre}${encodeURIComponent(grantRef)}:${root}`;
  const get = async (grantRef: string, root: string): Promise<PlanRecord | undefined> => {
    const v = await kv.get(key(grantRef, root));
    return isRecord(v) ? v : undefined;
  };

  /** Atomically move `from` -> next (computed from the current record). */
  async function move(grantRef: string, root: string, from: readonly PlanState[], to: string, next: (r: PlanRecord) => PlanRecord): Promise<PlanTransition> {
    let out: PlanTransition = { ok: false, state: 'unknown', reason: `plan ${root} is unknown for this grant` };
    await kv.update(key(grantRef, root), (prev) => {
      if (!isRecord(prev)) return undefined;
      if (!from.includes(prev.state)) {
        out = { ok: false, state: prev.state, reason: `plan ${root} is ${prev.state}: cannot ${to}` };
        return undefined;
      }
      const rec = next(prev);
      out = { ok: true, record: rec };
      return rec;
    });
    return out;
  }

  async function status(grantRef: string, root: string, now = clock()): Promise<PlanStatus> {
    const record = await get(grantRef, root);
    if (!record) return { state: 'unknown', executable: false, reason: `plan ${root} is unknown for this grant` };
    if (record.state !== 'authorized') {
      const why = record.state === 'committed' ? 'committed but not authorized by the principal' : record.state === 'revoked' ? `revoked (${record.revokedReason ?? 'no reason given'})` : `${record.state}, not authorized`;
      return { state: record.state, executable: false, reason: `plan ${root} is ${why}`, record };
    }
    if (record.approval?.expiresAt !== undefined && !(now < record.approval.expiresAt)) {
      return { state: record.state, executable: false, reason: `plan ${root}: the principal's approval expired at ${record.approval.expiresAt}`, record };
    }
    if (rootOf(record.nodes) !== root) return { state: record.state, executable: false, reason: `plan ${root}: the stored nodes no longer hash to the root`, record };
    return { state: record.state, executable: true, record };
  }

  return {
    async draft(grantRef, nodes) {
      if (typeof grantRef !== 'string' || grantRef === '') return { ok: false, state: 'unknown', reason: 'a plan needs a grant' };
      // structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
      let root: string;
      try {
        root = rootOf(nodes);
      } catch (e) {
        return { ok: false, state: 'unknown', reason: `the plan cannot be committed: ${e instanceof Error ? e.message : 'unknown'}` };
      }
      const rec: PlanRecord = { grantRef, root, nodes: structuredClone(nodes), state: 'draft', createdAt: clock() };
      let out: PlanTransition = { ok: true, record: rec };
      await kv.update(key(grantRef, root), (prev) => {
        if (isRecord(prev)) {
          out = { ok: false, state: prev.state, reason: `plan ${root} already exists (${prev.state})` };
          return undefined;
        }
        return rec;
      });
      return out;
    },
    async validate(grantRef, root) {
      const cur = await get(grantRef, root);
      if (!cur) return { ok: false, state: 'unknown', reason: `plan ${root} is unknown for this grant` };
      if (cur.state !== 'draft') return { ok: false, state: cur.state, reason: `plan ${root} is ${cur.state}: cannot validate` };
      const problem = structuralProblem(cur.nodes) ?? (rootOf(cur.nodes) !== root ? 'the stored nodes no longer hash to the root' : undefined);
      if (problem) return { ok: false, state: cur.state, reason: `plan ${root} is invalid: ${problem}` };
      if (opts.validator) {
        let v: { ok: true } | { ok: false; reason: string };
        try {
          v = await opts.validator(structuredClone(cur));
        } catch (e) {
          v = { ok: false, reason: `validator error (fail closed): ${e instanceof Error ? e.message : 'unknown'}` };
        }
        if (v?.ok !== true) return { ok: false, state: cur.state, reason: `plan ${root} is invalid: ${v && v.ok === false ? v.reason : 'refused by the validator'}` };
      }
      return move(grantRef, root, ['draft'], 'validate', (r) => ({ ...r, state: 'validated', validatedAt: clock() }));
    },
    commit: (grantRef, root) => move(grantRef, root, ['validated'], 'commit', (r) => ({ ...r, state: 'committed', committedAt: clock() })),
    async authorize(grantRef, root, approval) {
      if (!approval || typeof approval.by !== 'string' || approval.by === '') return { ok: false, state: (await get(grantRef, root))?.state ?? 'unknown', reason: 'an approval names who approved (`by`)' };
      if (approval.expiresAt !== undefined && !Number.isFinite(approval.expiresAt)) return { ok: false, state: (await get(grantRef, root))?.state ?? 'unknown', reason: 'approval.expiresAt must be a time (epoch ms)' };
      return move(grantRef, root, ['committed'], 'authorize', (r) => ({ ...r, state: 'authorized', authorizedAt: clock(), approval: { ...approval } }));
    },
    revoke: (grantRef, root, reason) =>
      move(grantRef, root, ['draft', 'validated', 'committed', 'authorized'], 'revoke', (r) => ({ ...r, state: 'revoked', revokedAt: clock(), revokedReason: String(reason ?? '') })),
    get,
    status,
    async check(grantRef, root, o = {}) {
      const s = await status(grantRef, root, o.now ?? clock());
      if (!s.executable || !s.record) return s;
      if (o.nodeId === undefined && o.operation === undefined) return s;
      const node = o.nodeId !== undefined ? s.record.nodes.find((n) => n.id === o.nodeId) : undefined;
      if (o.nodeId !== undefined && !node) return { ...s, executable: false, reason: `plan ${root} has no node '${o.nodeId}'` };
      if (o.operation) {
        const op = o.operation;
        const candidates = node ? [node] : s.record.nodes;
        let digest: string;
        try {
          digest = paramsDigest(op.params);
        } catch {
          return { ...s, executable: false, reason: `plan ${root}: the operation's params cannot be hashed` };
        }
        const same = candidates.some((n) => n.verb === op.verb && n.resource === op.resource && (n.params_digest ?? paramsDigest(undefined)) === digest);
        if (!same) return { ...s, executable: false, reason: `plan ${root}: the operation (${op.verb} on ${op.resource} with these params) is not what the principal approved` };
      }
      return s;
    },
    async isPlanAuthorized(grantRef, planRoot) {
      try {
        return (await status(grantRef, planRoot)).executable;
      } catch {
        return false;
      }
    },
    async context(grantRef, root, now) {
      const s = await status(grantRef, root, now ?? clock());
      if (!s.record) return undefined;
      return { plan: structuredClone(s.record.nodes), planAuthorized: s.executable, status: s };
    },
  };
}

