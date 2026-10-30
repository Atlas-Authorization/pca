// Regenerate the native-parity vectors from the TypeScript reference (deterministic):
//   operation-vectors.json   operation records (executeAuthorized state machine, recovery, resolution)   T3
//   plan-vectors.json        plan lifecycle (draft..authorized..revoked, status, per-action check)        T10
//   staleness-vectors.json   revocation staleness: age check, per-class windows, signed epoch, gate       T9
//   assurance-vectors.json   assurance report, requirement gate, multi-root level, signature level        T8/B7
//   tsx scripts/gen-conformance-native-parity.ts [--check]
// Every expectation is RECORDED from the real implementation, never hand-written, so a native that reproduces a file
// agrees with the reference. Reason strings are part of the contract in these files (compared exactly).
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64u } from '../src/hash';
import { publicKeyOf } from '../src/keys';
import { EMPTY_PARAMS_DIGEST, planNodeLeaf, merkleRoot, paramsDigest, type PlanNode } from '../src/merkle';
import {
  REVOCATION_EPOCH_REFRESH_MS,
  REVOCATION_EPOCH_VALIDITY_MS,
  REVOCATION_IRREVERSIBLE_MAX_AGE_MS,
  RevocationSet,
  checkRevocationAge,
  checkRevocationEpoch,
  createRevocationChecker,
  effectiveReversibility,
  revocationMaxAgeMs,
  signRevocationEpoch,
  verifyNonMembership,
  type NonMembershipProof,
  type RevocationStalenessPolicy,
} from '../src/revocation';
import {
  OPERATION_PENDING_TIMEOUT_MS,
  executeAuthorized,
  memoryOperationStore,
  recoverOperation,
  recoverOperations,
  resolveOperation,
  type OperationRecord,
  type OperationStore,
} from '../src/server/operations';
import { createPlanRegistry, memoryAtomicKv } from '../src/server/plan-lifecycle';
import { assuranceReport, multiRootLevel, setAssuranceLabel, signatureLevel, unmetAssurance, type AssuranceReport } from '../src/assurance';
import type { VerifyContext } from '../src/pcactn';

const T0 = 1_800_000_000_000;
const dig = (s: string): string => paramsDigest({ label: s });

// ---------------------------------------------------------------- operations (T3)
type ExecFn = { kind: 'commit'; result?: unknown } | { kind: 'throw'; message: string } | { kind: 'reenter' };
interface ExecStep {
  op: 'execute';
  at: number;
  id: string;
  verb?: string;
  resource?: string;
  params_digest?: string;
  signed_class?: string;
  server_class?: string;
  exp?: number;
  recheck?: 'ok' | { refuse: string } | { throw: string };
  recheck_for?: 'always';
  timeout_ms?: number;
  fn: ExecFn;
  no_store?: boolean;
  not_allowed?: boolean;
}
type OpStep =
  | ExecStep
  | { op: 'seed'; record: OperationRecord }
  | { op: 'recover'; at: number; older_than_ms?: number }
  | { op: 'recover_one'; id: string; at: number; older_than_ms?: number }
  | { op: 'resolve'; id: string; at: number; outcome: { state: 'committed'; result?: unknown } | { state: 'failed'; error: string } }
  | { op: 'get'; id: string };

async function runOps(steps: OpStep[]): Promise<unknown[]> {
  const store: OperationStore = memoryOperationStore();
  const out: unknown[] = [];
  for (const s of steps) {
    if (s.op === 'seed') {
      await store.create({ ...s.record });
      out.push(null);
    } else if (s.op === 'get') {
      out.push((await store.get(s.id)) ?? null);
    } else if (s.op === 'recover') {
      const r = await recoverOperations(store, { now: () => s.at, ...(s.older_than_ms !== undefined ? { olderThanMs: s.older_than_ms } : {}) });
      out.push(r.map((x) => ({ id: x.id, state: x.state })).sort((a, b) => (a.id < b.id ? -1 : 1)));
    } else if (s.op === 'recover_one') {
      const r = await recoverOperation(store, s.id, { now: () => s.at, ...(s.older_than_ms !== undefined ? { olderThanMs: s.older_than_ms } : {}) });
      out.push(r ?? null);
    } else if (s.op === 'resolve') {
      out.push(await resolveOperation(store, s.id, s.outcome, { now: () => s.at }));
    } else {
      let fnCalls = 0;
      const az = s.not_allowed
        ? { verdict: { allow: false }, pcactn: {}, operation: undefined }
        : {
            verdict: { allow: true },
            pcactn: { exp: s.exp, action: s.signed_class === undefined ? {} : { reversibility_class: s.signed_class } },
            operation: { id: s.id, verb: s.verb ?? 'payments.refund', resource: s.resource ?? '/orders/1', params_digest: s.params_digest ?? EMPTY_PARAMS_DIGEST },
          };
      const recheck =
        s.recheck === undefined
          ? undefined
          : s.recheck === 'ok'
            ? () => ({ ok: true as const })
            : 'refuse' in s.recheck
              ? (() => { const reason = (s.recheck as { refuse: string }).refuse; return () => ({ ok: false as const, reason }); })()
              : (() => { const m = (s.recheck as { throw: string }).throw; return () => { throw new Error(m); }; })();
      const opts = {
        store: s.no_store ? (undefined as unknown as OperationStore) : store,
        now: () => s.at,
        ...(recheck ? { recheck } : {}),
        ...(s.recheck_for ? { recheckFor: s.recheck_for } : {}),
        ...(s.server_class !== undefined ? { reversibilityClass: s.server_class } : {}),
        ...(s.timeout_ms !== undefined ? { pendingTimeoutMs: s.timeout_ms } : {}),
      };
      const run = (): Promise<unknown> =>
        executeAuthorized(
          az as never,
          async (h) => {
            fnCalls++;
            if (s.fn.kind === 'throw') throw new Error(s.fn.message);
            if (s.fn.kind === 'reenter') {
              const inner = await executeAuthorized(az as never, () => { throw new Error('inner must not run'); }, opts);
              return inner.status;
            }
            return s.fn.result === undefined ? h.idempotencyKey : s.fn.result;
          },
          opts,
        );
      const outcome = await run();
      out.push({ outcome, fn_calls: fnCalls, record: s.no_store || s.not_allowed ? null : ((await store.get(s.id)) ?? null) });
    }
  }
  return out;
}

const opScenarios: { name: string; description: string; steps: OpStep[] }[] = [];
const scn = (name: string, description: string, steps: OpStep[]) => opScenarios.push({ name, description, steps });
const ex = (o: Partial<ExecStep> & { id: string; at: number }): ExecStep => ({ op: 'execute', signed_class: 'reversible', fn: { kind: 'commit', result: { done: true } }, ...o });

scn('commit-reversible', 'a reversible operation runs once and is committed; the idempotency key is the operation id', [ex({ id: 'op1', at: T0 })]);
scn('retry-is-answered-from-record', 'a second execution of a committed id never runs fn again', [ex({ id: 'op1', at: T0 }), ex({ id: 'op1', at: T0 + 1000 }), { op: 'get', id: 'op1' }]);
scn('fn-throws-is-failed-and-not-rerun', 'a throwing fn is recorded failed; a retry is answered failed without running fn', [ex({ id: 'op1', at: T0, fn: { kind: 'throw', message: 'boom' } }), ex({ id: 'op1', at: T0 + 5 })]);
scn('irreversible-needs-recheck', 'an irreversible operation without a recheck is refused before anything is recorded', [ex({ id: 'op1', at: T0, signed_class: 'irreversible' }), { op: 'get', id: 'op1' }]);
scn('server-class-makes-irreversible', 'the stricter of server and signed class applies', [ex({ id: 'op1', at: T0, signed_class: 'reversible', server_class: 'irreversible' }), ex({ id: 'op2', at: T0, server_class: 'costly' })]);
scn('unknown-class-is-irreversible', 'a missing or unknown server class is irreversible (fail closed)', [ex({ id: 'op1', at: T0, signed_class: 'no-such-class' }), ex({ id: 'op2', at: T0, signed_class: 'no-such-class', recheck: 'ok' })]);
scn('irreversible-recheck-ok', 'an irreversible operation runs after a passing recheck', [ex({ id: 'op1', at: T0, signed_class: 'irreversible', recheck: 'ok' })]);
scn('recheck-refuses-aborts', 'a refusing recheck records aborted and fn never runs; a retry is answered aborted', [ex({ id: 'op1', at: T0, signed_class: 'irreversible', recheck: { refuse: 'grant revoked' } }), ex({ id: 'op1', at: T0 + 1, signed_class: 'irreversible', recheck: 'ok' })]);
scn('recheck-throws-fails-closed', 'a throwing recheck counts as a refusal', [ex({ id: 'op1', at: T0, signed_class: 'irreversible', recheck: { throw: 'store down' } })]);
scn('expired-pcactn-aborts', 'the PCActn expiry is always checked with the recheck', [ex({ id: 'op1', at: T0, signed_class: 'irreversible', recheck: 'ok', exp: T0 - 1 }), ex({ id: 'op2', at: T0, signed_class: 'irreversible', recheck: 'ok', exp: T0 })]);
scn('recheck-always', 'recheck_for always re-checks a reversible operation too', [ex({ id: 'op1', at: T0, recheck: { refuse: 'approval withdrawn' }, recheck_for: 'always' }), ex({ id: 'op2', at: T0, recheck_for: 'always' })]);
scn('missing-store-refused', 'no store is a refusal, nothing runs', [ex({ id: 'op1', at: T0, no_store: true })]);
scn('not-allowed-refused', 'an authorization that did not allow is refused', [ex({ id: 'op1', at: T0, not_allowed: true })]);
scn('reentrant-execution-is-pending', 'a second execution of the same id while the first is running does not run fn and reports pending', [ex({ id: 'op1', at: T0, fn: { kind: 'reenter' } })]);
scn('pending-record-blocks-then-aborts', 'a pending record younger than the timeout answers pending; older than it is settled aborted', [
  { op: 'seed', record: { id: 'op1', state: 'pending', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0 } },
  ex({ id: 'op1', at: T0 + 1000, timeout_ms: 5000 }),
  ex({ id: 'op1', at: T0 + 5000, timeout_ms: 5000 }),
  ex({ id: 'op1', at: T0 + 5001, timeout_ms: 5000 }),
  { op: 'get', id: 'op1' },
]);
scn('executing-record-becomes-uncertain', 'a record still executing after the timeout is uncertain and never re-run; resolve settles it', [
  { op: 'seed', record: { id: 'op1', state: 'executing', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'irreversible', startedAt: T0, executingAt: T0 + 10 } },
  ex({ id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS + 10 }),
  ex({ id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS + 11 }),
  { op: 'resolve', id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS + 12, outcome: { state: 'committed', result: 'reconciled' } },
  { op: 'resolve', id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS + 13, outcome: { state: 'failed', error: 'late' } },
  ex({ id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS + 14 }),
]);
scn('executing-age-counts-from-fn-start', 'an executing record is aged from executingAt, not from the claim (default 5 minute timeout)', [
  { op: 'seed', record: { id: 'op1', state: 'executing', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0, executingAt: T0 + 200_000 } },
  ex({ id: 'op1', at: T0 + OPERATION_PENDING_TIMEOUT_MS }),
  ex({ id: 'op1', at: T0 + 200_000 + OPERATION_PENDING_TIMEOUT_MS + 1 }),
]);
scn('resolve-failed', 'resolve to failed after reconciliation', [
  { op: 'seed', record: { id: 'op1', state: 'uncertain', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'costly', startedAt: T0, error: 'x' } },
  { op: 'resolve', id: 'op1', at: T0 + 1, outcome: { state: 'failed', error: 'never applied' } },
  { op: 'resolve', id: 'nope', at: T0 + 1, outcome: { state: 'failed', error: 'e' } },
  { op: 'get', id: 'op1' },
]);
scn('recover-all-open', 'recover settles every stale open record and reports only those that changed', [
  { op: 'seed', record: { id: 'a', state: 'pending', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0 } },
  { op: 'seed', record: { id: 'b', state: 'executing', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0, executingAt: T0 } },
  { op: 'seed', record: { id: 'c', state: 'pending', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0 + 100_000 } },
  { op: 'seed', record: { id: 'd', state: 'committed', verb: 'v', resource: '/r', params_digest: EMPTY_PARAMS_DIGEST, reversibility: 'reversible', startedAt: T0, result: 1 } },
  { op: 'recover', at: T0 + 60_000, older_than_ms: 30_000 },
  { op: 'recover', at: T0 + 60_000, older_than_ms: 30_000 },
  { op: 'recover_one', id: 'c', at: T0 + 200_000, older_than_ms: 30_000 },
  { op: 'recover_one', id: 'zzz', at: T0 + 200_000 },
]);

// ---------------------------------------------------------------- plans (T10)
type PlanStep =
  | { op: 'draft'; at: number; grant: string; nodes: unknown }
  | { op: 'validate' | 'commit'; at: number; grant: string; root: string }
  | { op: 'authorize'; at: number; grant: string; root: string; approval: unknown }
  | { op: 'revoke'; at: number; grant: string; root: string; reason: string }
  | { op: 'status'; at: number; grant: string; root: string }
  | { op: 'check'; at: number; grant: string; root: string; node_id?: string; operation?: { verb: string; resource: string; params?: unknown } }
  | { op: 'is_plan_authorized'; at: number; grant: string; root: string }
  | { op: 'context'; at: number; grant: string; root: string };

const N1: PlanNode = { id: 'n1', verb: 'payments.refund', resource: '/orders/1', params_digest: paramsDigest({ amount: 5 }), reversibility_class: 'costly' };
const N2: PlanNode = { id: 'n2', verb: 'orders.read', resource: '/orders/1' };
const rootOf = (nodes: PlanNode[]): string => merkleRoot(nodes.map(planNodeLeaf));
const R12 = rootOf([N1, N2]);
const R1 = rootOf([N1]);

async function runPlan(validator: 'accept' | 'refuse' | 'throw' | undefined, steps: PlanStep[]): Promise<unknown[]> {
  let now = T0;
  const reg = createPlanRegistry({
    kv: memoryAtomicKv(),
    now: () => now,
    ...(validator === 'accept' ? { validator: () => ({ ok: true as const }) } : validator === 'refuse' ? { validator: () => ({ ok: false as const, reason: 'node outside the grant' }) } : validator === 'throw' ? { validator: () => { throw new Error('policy down'); } } : {}),
  });
  const out: unknown[] = [];
  for (const s of steps) {
    now = s.at;
    switch (s.op) {
      case 'draft': out.push(await reg.draft(s.grant, s.nodes as PlanNode[])); break;
      case 'validate': out.push(await reg.validate(s.grant, s.root)); break;
      case 'commit': out.push(await reg.commit(s.grant, s.root)); break;
      case 'authorize': out.push(await reg.authorize(s.grant, s.root, s.approval as never)); break;
      case 'revoke': out.push(await reg.revoke(s.grant, s.root, s.reason)); break;
      case 'status': out.push(await reg.status(s.grant, s.root, s.at)); break;
      case 'check':
        out.push(await reg.check(s.grant, s.root, { now: s.at, ...(s.node_id !== undefined ? { nodeId: s.node_id } : {}), ...(s.operation ? { operation: s.operation as never } : {}) }));
        break;
      case 'is_plan_authorized': out.push(await reg.isPlanAuthorized(s.grant, s.root)); break;
      case 'context': out.push((await reg.context(s.grant, s.root, s.at)) ?? null); break;
    }
  }
  return out;
}

const planScenarios: { name: string; description: string; validator?: 'accept' | 'refuse' | 'throw'; steps: PlanStep[] }[] = [];
const pscn = (name: string, description: string, steps: PlanStep[], validator?: 'accept' | 'refuse' | 'throw') => planScenarios.push({ name, description, ...(validator ? { validator } : {}), steps });
const full = (g: string, root: string, at = T0): PlanStep[] => [
  { op: 'validate', at, grant: g, root },
  { op: 'commit', at: at + 1, grant: g, root },
  { op: 'authorize', at: at + 2, grant: g, root, approval: { by: 'principal-key', expiresAt: at + 100_000 } },
];
pscn('happy-path', 'draft, validate, commit, authorize: executable until the approval expires', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1, N2] },
  ...full('g1', R12),
  { op: 'status', at: T0 + 50_000, grant: 'g1', root: R12 },
  { op: 'status', at: T0 + 99_999 + 2, grant: 'g1', root: R12 },
  { op: 'status', at: T0 + 100_002, grant: 'g1', root: R12 },
  { op: 'is_plan_authorized', at: T0 + 10, grant: 'g1', root: R12 },
  { op: 'is_plan_authorized', at: T0 + 200_000, grant: 'g1', root: R12 },
  { op: 'context', at: T0 + 10, grant: 'g1', root: R12 },
]);
pscn('committed-is-not-executable', 'a committed plan still needs the principal', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  { op: 'validate', at: T0, grant: 'g1', root: R1 },
  { op: 'commit', at: T0, grant: 'g1', root: R1 },
  { op: 'status', at: T0, grant: 'g1', root: R1 },
  { op: 'context', at: T0, grant: 'g1', root: R1 },
]);
pscn('transitions-are-ordered', 'no step may be skipped or repeated', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  { op: 'commit', at: T0, grant: 'g1', root: R1 },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: 'p' } },
  { op: 'validate', at: T0, grant: 'g1', root: R1 },
  { op: 'validate', at: T0, grant: 'g1', root: R1 },
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  { op: 'commit', at: T0, grant: 'g1', root: R1 },
  { op: 'commit', at: T0, grant: 'g1', root: R1 },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: 'p' } },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: 'p' } },
  { op: 'status', at: T0, grant: 'g1', root: R1 },
]);
pscn('unknown-plan-and-grant-scoping', 'a root is scoped to its grant; unknown roots are not executable', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  ...full('g1', R1),
  { op: 'status', at: T0 + 3, grant: 'g2', root: R1 },
  { op: 'status', at: T0 + 3, grant: 'g1', root: 'nope' },
  { op: 'validate', at: T0, grant: 'g2', root: R1 },
  { op: 'revoke', at: T0, grant: 'g2', root: R1, reason: 'x' },
  { op: 'context', at: T0, grant: 'g2', root: R1 },
  { op: 'is_plan_authorized', at: T0, grant: 'g2', root: R1 },
]);
pscn('revoke-is-terminal', 'revoke from any live state; a revoked plan never executes again and cannot be revived', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  ...full('g1', R1),
  { op: 'revoke', at: T0 + 10, grant: 'g1', root: R1, reason: 'principal changed their mind' },
  { op: 'status', at: T0 + 11, grant: 'g1', root: R1 },
  { op: 'revoke', at: T0 + 12, grant: 'g1', root: R1, reason: 'again' },
  { op: 'authorize', at: T0 + 13, grant: 'g1', root: R1, approval: { by: 'p' } },
  { op: 'draft', at: T0 + 14, grant: 'g1', nodes: [N1] },
  { op: 'is_plan_authorized', at: T0 + 15, grant: 'g1', root: R1 },
]);
pscn('revoke-a-draft', 'a draft can be revoked', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  { op: 'revoke', at: T0, grant: 'g1', root: R1, reason: 'abandoned' },
  { op: 'validate', at: T0, grant: 'g1', root: R1 },
]);
pscn('structural-validation', 'validate refuses duplicate ids, missing verb or resource, unknown classes, empty plans', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1, { ...N2, id: 'n1' }] },
  { op: 'validate', at: T0, grant: 'g1', root: rootOf([N1, { ...N2, id: 'n1' }]) },
  { op: 'draft', at: T0, grant: 'g1', nodes: [{ id: 'x', verb: '', resource: '/r' }] },
  { op: 'validate', at: T0, grant: 'g1', root: rootOf([{ id: 'x', verb: '', resource: '/r' }]) },
  { op: 'draft', at: T0, grant: 'g1', nodes: [{ id: 'y', verb: 'v', resource: '/r', reversibility_class: 'bogus' }] },
  { op: 'validate', at: T0, grant: 'g1', root: rootOf([{ id: 'y', verb: 'v', resource: '/r', reversibility_class: 'bogus' }]) },
  { op: 'draft', at: T0, grant: '', nodes: [N1] },
  { op: 'draft', at: T0, grant: 'g1', nodes: [] },
  { op: 'validate', at: T0, grant: 'g1', root: 'no-such-root' },
]);
pscn('validator-accepts', 'the server validator runs after the structural checks', [{ op: 'draft', at: T0, grant: 'g1', nodes: [N1] }, { op: 'validate', at: T0, grant: 'g1', root: R1 }], 'accept');
pscn('validator-refuses', 'a refusing validator leaves the plan a draft', [{ op: 'draft', at: T0, grant: 'g1', nodes: [N1] }, { op: 'validate', at: T0, grant: 'g1', root: R1 }, { op: 'status', at: T0, grant: 'g1', root: R1 }], 'refuse');
pscn('validator-throws-fails-closed', 'a throwing validator refuses', [{ op: 'draft', at: T0, grant: 'g1', nodes: [N1] }, { op: 'validate', at: T0, grant: 'g1', root: R1 }], 'throw');
pscn('approval-validation', 'an approval names who approved and an optional finite expiry', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1] },
  { op: 'validate', at: T0, grant: 'g1', root: R1 },
  { op: 'commit', at: T0, grant: 'g1', root: R1 },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: '' } },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: null },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: 'p', expiresAt: null } },
  { op: 'authorize', at: T0, grant: 'g1', root: R1, approval: { by: 'p' } },
  { op: 'status', at: T0 + 1e12, grant: 'g1', root: R1 },
]);
pscn('check-node-and-operation', 'check adds the per-action staleness rules: the node exists, the operation matches what was approved', [
  { op: 'draft', at: T0, grant: 'g1', nodes: [N1, N2] },
  ...full('g1', R12),
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12 },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'n1' },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'missing' },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'n1', operation: { verb: 'payments.refund', resource: '/orders/1', params: { amount: 5 } } },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'n1', operation: { verb: 'payments.refund', resource: '/orders/1', params: { amount: 6 } } },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'n1', operation: { verb: 'payments.refund', resource: '/orders/2', params: { amount: 5 } } },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, node_id: 'n1', operation: { verb: 'orders.read', resource: '/orders/1' } },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, operation: { verb: 'orders.read', resource: '/orders/1' } },
  { op: 'check', at: T0 + 10, grant: 'g1', root: R12, operation: { verb: 'orders.read', resource: '/orders/1', params: { x: 1 } } },
  { op: 'check', at: T0 + 100_002, grant: 'g1', root: R12, node_id: 'n1' },
]);

// ---------------------------------------------------------------- staleness (T9)
const GUARD_SECRET = new Uint8Array(32).fill(11);
const GUARD_PUB = b64u(publicKeyOf(GUARD_SECRET));
const OTHER_PUB = b64u(publicKeyOf(new Uint8Array(32).fill(12)));
const rset = new RevocationSet(['cap-revoked']);
const epochAt = (issued: number, o: { epoch?: number; notAfter?: number; grant?: string; root?: string } = {}) =>
  signRevocationEpoch(GUARD_SECRET, { instance_id: 'i', grant_ref: o.grant ?? 'g1', epoch: o.epoch ?? 0, set_size: rset.size, root: o.root ?? rset.root, issued_at: issued, not_after: o.notAfter ?? issued + 10 * 60_000 });

const CLASSES = ['reversible', 'costly', 'irreversible'] as const;
const POLICIES: RevocationStalenessPolicy[] = [{}, { maxRevocationAgeMs: 60_000 }, { staleness: { costly: 90_000, irreversible: 10_000 } }, { maxRevocationAgeMs: 50_000, staleness: { costly: 90_000 } }, { maxRevocationAgeMs: 500_000, staleness: { irreversible: 300_000 } }];
const maxAge = POLICIES.flatMap((policy) => CLASSES.map((cls) => ({ policy, class: cls, max_age_ms: revocationMaxAgeMs(policy, cls) })));
const CLS_IN: [string | undefined, unknown][] = [[undefined, undefined], ['reversible', undefined], ['reversible', 'reversible'], ['costly', undefined], ['rate_limited', undefined], [undefined, 'rate_limited'], ['reversible', 'costly'], ['costly', 'reversible'], ['reversible', 'irreversible'], ['irreversible', 'reversible'], ['bogus', 'reversible'], ['reversible', 'bogus'], [undefined, 7], ['reversible', null]];
const effective = CLS_IN.map(([server, signed]) => ({ server_class: server ?? null, signed_class: signed === undefined ? null : signed, effective: effectiveReversibility(server, signed) }));
const AGE_IN: [unknown, number, number, string | undefined][] = [
  [T0, T0, 1000, undefined], [T0 - 1000, T0, 1000, undefined], [T0 - 1001, T0, 1000, undefined], [T0 + 60_000, T0, 1000, undefined], [T0 + 60_001, T0, 1000, undefined],
  [undefined, T0, 1000, undefined], [Number.NaN, T0, 1000, 'revocation root'], ['x', T0, 1000, undefined], [null, T0, 1000, undefined], [T0 - 1, T0, Number.NaN, undefined], [T0 - 1, T0, 0, undefined], [T0 - 1, T0, -5, undefined], [T0, T0, 0, 'revocation root'],
];
const ageCases = AGE_IN.map(([issued, now, max, what]) => ({ issued_at: issued === undefined ? null : Number.isNaN(issued as number) ? 'NaN' : issued, now, max_age_ms: Number.isNaN(max) ? 'NaN' : max, ...(what ? { what } : {}), ...(Number.isNaN(max) ? { ok_only: true } : {}), result: checkRevocationAge(issued as number | undefined, now, max, what) }));

const epochCases: unknown[] = [];
const epochAdd = (name: string, ep: unknown, o: { now: number; guardian?: string; grant?: string; last?: number; pcactn_epoch?: number; max_age_ms?: number }) =>
  epochCases.push({
    name,
    epoch: ep,
    guardian_public: o.guardian ?? GUARD_PUB,
    now: o.now,
    ...(o.grant !== undefined ? { grant_ref: o.grant } : {}),
    ...(o.last !== undefined ? { last_accepted_epoch: o.last } : {}),
    ...(o.pcactn_epoch !== undefined ? { pcactn_epoch: o.pcactn_epoch } : {}),
    ...(o.max_age_ms !== undefined ? { max_age_ms: Number.isNaN(o.max_age_ms) ? 'NaN' : o.max_age_ms, ...(Number.isNaN(o.max_age_ms) ? { ok_only: true } : {}) } : {}),
    result: checkRevocationEpoch(ep as never, { guardianPublic: o.guardian ?? GUARD_PUB, now: o.now, grantRef: o.grant, lastAcceptedEpoch: o.last, pcactnEpoch: o.pcactn_epoch, maxAgeMs: o.max_age_ms }),
  });
const E0 = epochAt(T0 - 200_000);
epochAdd('valid-no-cap', E0, { now: T0 });
epochAdd('older-than-cap', E0, { now: T0, max_age_ms: 120_000 });
epochAdd('exactly-at-cap', E0, { now: T0, max_age_ms: 200_000 });
epochAdd('one-ms-over-cap', E0, { now: T0, max_age_ms: 199_999 });
epochAdd('nan-cap-fails-closed', E0, { now: T0, max_age_ms: Number.NaN });
epochAdd('zero-cap', epochAt(T0), { now: T0, max_age_ms: 0 });
epochAdd('expired-before-cap', epochAt(T0 - 700_000), { now: T0 });
epochAdd('not-after-boundary', epochAt(T0 - 10, { notAfter: T0 }), { now: T0 });
epochAdd('issued-in-future', epochAt(T0 + 60_001), { now: T0 });
epochAdd('issued-60s-ahead-ok', epochAt(T0 + 60_000), { now: T0 });
epochAdd('wrong-guardian', E0, { now: T0, guardian: OTHER_PUB });
epochAdd('wrong-grant', E0, { now: T0, grant: 'g2' });
epochAdd('right-grant', E0, { now: T0, grant: 'g1' });
epochAdd('rollback', epochAt(T0, { epoch: 3 }), { now: T0, last: 4 });
epochAdd('same-epoch-ok', epochAt(T0, { epoch: 4 }), { now: T0, last: 4 });
epochAdd('pcactn-predates-epoch', epochAt(T0, { epoch: 5 }), { now: T0, pcactn_epoch: 4 });
epochAdd('pcactn-epoch-ok', epochAt(T0, { epoch: 5 }), { now: T0, pcactn_epoch: 5 });
epochAdd('tampered-root', { ...epochAt(T0), root: b64u(new Uint8Array(32).fill(1)) }, { now: T0 });
epochAdd('tampered-issued-at', { ...epochAt(T0), issued_at: T0 - 1 }, { now: T0 });
epochAdd('tampered-sig', { ...epochAt(T0), sig: b64u(new Uint8Array(64).fill(2)) }, { now: T0 });
epochAdd('unknown-suite', { ...epochAt(T0), alg: 'no-such-suite' }, { now: T0 });
epochAdd('fractional-issued-at', { ...epochAt(T0), issued_at: T0 + 0.5 }, { now: T0 });
epochAdd('string-issued-at', { ...epochAt(T0), issued_at: String(T0) }, { now: T0 });
epochAdd('negative-epoch', { ...epochAt(T0), epoch: -1 }, { now: T0 });
epochAdd('null-epoch', null, { now: T0 });

// the whole gate (signed epoch or bare root, class, policy), recorded from createRevocationChecker with no ids to prove
interface GateIn {
  name: string;
  policy?: RevocationStalenessPolicy;
  allow_unsigned_root_for_irreversible?: boolean;
  server_class?: string;
  signed_class?: string;
  mode: 'epoch' | 'root' | 'none';
  epoch?: unknown;
  root_issued_at?: number | null;
  /** epoch mode only: also hand the checker this bare root (the signed epoch's root must equal it). */
  bare_root?: string;
  now: number;
}
const ON: RevocationStalenessPolicy = { maxRevocationAgeMs: REVOCATION_EPOCH_VALIDITY_MS };
const gateIns: GateIn[] = [];
const g = (x: GateIn) => gateIns.push(x);
for (const cls of CLASSES) {
  const age = (ms: number) => epochAt(T0 - ms);
  g({ name: `epoch-${cls}-fresh`, policy: ON, signed_class: cls, mode: 'epoch', epoch: age(30_000), now: T0 });
  g({ name: `epoch-${cls}-3min`, policy: ON, signed_class: cls, mode: 'epoch', epoch: age(180_000), now: T0 });
  g({ name: `epoch-${cls}-6min`, policy: ON, signed_class: cls, mode: 'epoch', epoch: age(360_000), now: T0 });
  g({ name: `root-${cls}-fresh`, policy: ON, signed_class: cls, mode: 'root', root_issued_at: T0 - 30_000, now: T0 });
  g({ name: `root-${cls}-unknown-age`, policy: ON, signed_class: cls, mode: 'root', root_issued_at: null, now: T0 });
}
g({ name: 'root-irreversible-allowed-fresh', policy: ON, allow_unsigned_root_for_irreversible: true, signed_class: 'irreversible', mode: 'root', root_issued_at: T0 - 30_000, now: T0 });
g({ name: 'root-irreversible-allowed-stale', policy: ON, allow_unsigned_root_for_irreversible: true, signed_class: 'irreversible', mode: 'root', root_issued_at: T0 - 130_000, now: T0 });
g({ name: 'no-class-is-irreversible', policy: ON, mode: 'epoch', epoch: epochAt(T0 - 130_000), now: T0 });
g({ name: 'server-class-stricter', policy: ON, server_class: 'irreversible', signed_class: 'reversible', mode: 'epoch', epoch: epochAt(T0 - 130_000), now: T0 });
g({ name: 'signed-class-cannot-loosen', policy: ON, server_class: 'irreversible', signed_class: 'reversible', mode: 'root', root_issued_at: T0 - 1, now: T0 });
g({ name: 'custom-window', policy: { staleness: { irreversible: 10_000 } }, signed_class: 'irreversible', mode: 'epoch', epoch: epochAt(T0 - 10_001), now: T0 });
g({ name: 'custom-window-at-limit', policy: { staleness: { irreversible: 10_000 } }, signed_class: 'irreversible', mode: 'epoch', epoch: epochAt(T0 - 10_000), now: T0 });
g({ name: 'costly-window', policy: { staleness: { costly: 60_000 } }, signed_class: 'costly', mode: 'epoch', epoch: epochAt(T0 - 61_000), now: T0 });
g({ name: 'no-policy-old-epoch-ok', mode: 'epoch', signed_class: 'irreversible', epoch: epochAt(T0 - 250_000), now: T0 });
g({ name: 'no-policy-root-no-age', mode: 'root', signed_class: 'irreversible', root_issued_at: null, now: T0 });
g({ name: 'no-epoch-supplied', policy: ON, mode: 'none', signed_class: 'reversible', now: T0 });
g({ name: 'root-mismatch', policy: ON, signed_class: 'reversible', mode: 'epoch', epoch: epochAt(T0 - 1_000), bare_root: b64u(new Uint8Array(32).fill(5)), now: T0 });
g({ name: 'root-match', policy: ON, signed_class: 'reversible', mode: 'epoch', epoch: epochAt(T0 - 1_000), bare_root: rset.root, now: T0 });
const gateCases = gateIns.map((x) => {
  const root = x.mode === 'root' ? rset.root : x.bare_root;
  const ctx = { pcactn: { grant_ref: 'g1', cap_chain: [{ id: 'cap-a' }], action: x.signed_class === undefined ? {} : { reversibility_class: x.signed_class }, freshness: { epoch: 0 } }, grant: { id: 'g1' }, nowEpoch: x.now } as unknown as VerifyContext;
  const chk = createRevocationChecker({
    ...(x.policy ?? {}),
    ...(x.allow_unsigned_root_for_irreversible ? { allowUnsignedRootForIrreversible: true } : {}),
    guardianPublic: GUARD_PUB,
    ids: () => [],
    proofFor: () => undefined,
    ...(x.mode === 'epoch' ? { epoch: () => x.epoch as never, ...(root ? { root: () => root } : {}) } : x.mode === 'root' ? { root: () => root, rootIssuedAt: () => (x.root_issued_at === null ? undefined : x.root_issued_at) } : { epoch: () => undefined }),
    ...(x.server_class !== undefined ? { reversibilityClass: () => x.server_class } : {}),
  });
  const r = chk(ctx) as { enforced: boolean; ok?: boolean; reason?: string };
  return { ...x, result: r.ok ? { ok: true } : { ok: false, reason: r.reason } };
});

// per-capability non-membership proofs (sorted Merkle set, UTF-8 byte order, root bound to the set size)
const mset = new RevocationSet(['cap-b', 'cap-d', 'cap-f', 'cap-\u00e9', 'cap-\u{1F600}', 'cap-\uffff']);
const msetRoot = mset.root;
const one = new RevocationSet(['only']);
const empty = new RevocationSet([]);
const flip = (x: string): string => (x[0] === 'A' ? 'B' : 'A') + x.slice(1);
const memCases: unknown[] = [];
const mem = (name: string, set: string, root: string, id: string, proof: unknown) =>
  memCases.push({ name, set, root, id, proof, ok: verifyNonMembership(root, proof as NonMembershipProof, id) });
const proofOf = (st: RevocationSet, id: string): NonMembershipProof => st.nonMembershipProof(id);
for (const id of ['cap-a', 'cap-c', 'cap-e', 'cap-g', 'cap-\u00e8', 'cap-\u{1F601}', 'cap-\ud7ff', 'cap-', 'zzz']) mem(`valid-${id.length}-${[...id].map((c) => c.codePointAt(0)!.toString(16)).join('')}`, 'main', msetRoot, id, proofOf(mset, id));
mem('valid-below-minimum', 'one', one.root, 'a', proofOf(one, 'a'));
mem('valid-above-maximum', 'one', one.root, 'z', proofOf(one, 'z'));
mem('valid-empty-set', 'empty', empty.root, 'anything', proofOf(empty, 'anything'));
mem('empty-set-proof-for-non-empty-root', 'main', msetRoot, 'cap-a', proofOf(empty, 'cap-a'));
mem('revoked-id-with-neighbour-proof', 'main', msetRoot, 'cap-d', proofOf(mset, 'cap-c'));
mem('revoked-id-with-empty-proof', 'main', msetRoot, 'cap-d', { size: mset.size });
mem('proof-for-another-id', 'main', msetRoot, 'cap-a', proofOf(mset, 'cap-g'));
{
  const pr = JSON.parse(JSON.stringify(proofOf(mset, 'cap-c')));
  mem('tampered-sibling', 'main', msetRoot, 'cap-c', { ...pr, lo: { ...pr.lo, proof: { ...pr.lo.proof, path: pr.lo.proof.path.map((x: { side: string; hash: string }, i: number) => (i === 0 ? { ...x, hash: flip(x.hash) } : x)) } } });
  mem('lo-id-swapped', 'main', msetRoot, 'cap-c', { ...pr, lo: { ...pr.lo, id: 'cap-a' } });
  mem('size-mismatch', 'main', msetRoot, 'cap-c', { ...pr, size: pr.size + 1 });
  mem('wrong-root', 'main', one.root, 'cap-c', pr);
  mem('lo-only-but-not-last', 'main', msetRoot, 'cap-c', { size: pr.size, lo: pr.lo });
  mem('hi-only-but-not-first', 'main', msetRoot, 'cap-c', { size: pr.size, hi: pr.hi });
  mem('non-adjacent-neighbours', 'main', msetRoot, 'cap-c', { size: pr.size, lo: proofOf(mset, 'cap-a').hi ? { id: 'cap-b', proof: proofOf(mset, 'cap-c').lo!.proof } : pr.lo, hi: proofOf(mset, 'cap-g').lo ? proofOf(mset, 'cap-g').lo : pr.hi });
  mem('negative-size', 'main', msetRoot, 'cap-c', { ...pr, size: -1 });
  mem('fractional-size', 'main', msetRoot, 'cap-c', { ...pr, size: 6.5 });
  mem('null-proof', 'main', msetRoot, 'cap-c', null);
  mem('no-neighbours', 'main', msetRoot, 'cap-c', { size: pr.size });
}

// the whole gate with capability ids to prove: a signed epoch over the main set; proofs keyed by id (absent = none supplied)
const mEpoch = (issued: number) => signRevocationEpoch(GUARD_SECRET, { instance_id: 'i', grant_ref: 'g1', epoch: 0, set_size: mset.size, root: msetRoot, issued_at: issued, not_after: issued + 600_000 });
interface IdGateIn { name: string; ids: string[]; proofs: Record<string, unknown>; epoch_issued_at: number; now: number }
const idIns: IdGateIn[] = [];
const ig = (name: string, ids: string[], proofs: Record<string, unknown>, epochIssued = T0 - 1_000) => idIns.push({ name, ids, proofs, epoch_issued_at: epochIssued, now: T0 });
const allProofs = (ids: string[]) => Object.fromEntries(ids.map((i) => [i, proofOf(mset, i)]));
ig('all-clear', ['cap-a', 'cap-c'], allProofs(['cap-a', 'cap-c']));
ig('single-clear', ['cap-e'], allProofs(['cap-e']));
ig('no-ids', [], {});
ig('one-revoked', ['cap-a', 'cap-d'], { 'cap-a': proofOf(mset, 'cap-a'), 'cap-d': proofOf(mset, 'cap-c') });
ig('revoked-first', ['cap-b', 'cap-a'], { 'cap-b': proofOf(mset, 'cap-a'), 'cap-a': proofOf(mset, 'cap-a') });
ig('proof-missing', ['cap-a', 'cap-c'], { 'cap-a': proofOf(mset, 'cap-a') });
ig('proof-missing-first', ['cap-c', 'cap-a'], { 'cap-a': proofOf(mset, 'cap-a') });
ig('proof-for-other-id', ['cap-a'], { 'cap-a': proofOf(mset, 'cap-g') });
ig('stale-epoch-with-valid-proofs', ['cap-a'], allProofs(['cap-a']), T0 - 400_000);
ig('non-bmp-ordering', ['cap-\u{1F601}', 'cap-\uffff'.replace('\uffff', '\ud7ff')], allProofs(['cap-\u{1F601}', 'cap-\ud7ff']));
const idGateCases = idIns.map((x) => {
  const ctx = { pcactn: { grant_ref: 'g1', cap_chain: x.ids.map((id) => ({ id })), action: { reversibility_class: 'costly' }, freshness: { epoch: 0 } }, grant: { id: 'g1' }, nowEpoch: x.now } as unknown as VerifyContext;
  const chk = createRevocationChecker({ maxRevocationAgeMs: REVOCATION_EPOCH_VALIDITY_MS, guardianPublic: GUARD_PUB, epoch: () => mEpoch(x.epoch_issued_at), proofFor: (id) => x.proofs[id] as never });
  const r = chk(ctx) as { ok?: boolean; reason?: string };
  return { ...x, result: r.ok ? { ok: true } : { ok: false, reason: r.reason } };
});

// ---------------------------------------------------------------- assurance (T8 / B7)
const sig10 = ['ed25519', 'ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-65', 'hybrid-ed25519-ml-dsa-87', 'hybrid-nested-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'hybrid-ed25519-slh-dsa-sha2-256s'];
const sigLevels = [...sig10, 'no-such-suite', '', 'ED25519'].map((alg) => ({ alg, level: signatureLevel(alg) })).concat([{ alg: null as never, level: signatureLevel(undefined) }]);

interface LabelIn { level: string; vendor?: string; awaiting_audit?: boolean; ceremony?: 'single-party' | 'multi-party' }
interface RepIn {
  name: string;
  checks: Record<string, string>;
  pcactn?: { alg?: string; cap_chain?: { alg?: string }[]; bond_ref?: unknown };
  hooks?: { attestation?: LabelIn | 'unlabelled'; zk?: LabelIn | 'unlabelled'; threshold?: LabelIn | 'unlabelled'; revocation?: LabelIn | 'unlabelled' };
  attestation_hook?: LabelIn | 'unlabelled';
  threshold_t?: number;
  allow_unbound_pq?: boolean;
  degraded?: Record<string, string>;
}
const hookOf = (l: LabelIn | 'unlabelled' | undefined): object | undefined => (l === undefined ? undefined : l === 'unlabelled' ? {} : setAssuranceLabel({}, l));
const buildReport = (x: RepIn): AssuranceReport =>
  assuranceReport({
    checks: x.checks as never,
    ...(x.pcactn ? { pcactn: x.pcactn as never } : {}),
    hooks: { attestation: hookOf(x.hooks?.attestation), zk: hookOf(x.hooks?.zk), threshold: hookOf(x.hooks?.threshold), revocation: hookOf(x.hooks?.revocation) },
    ...(x.attestation_hook !== undefined ? { attestationHook: hookOf(x.attestation_hook) } : {}),
    ...(x.threshold_t !== undefined ? { thresholdT: x.threshold_t } : {}),
    ...(x.allow_unbound_pq ? { allowUnboundPq: true } : {}),
    ...(x.degraded ? { degraded: x.degraded } : {}),
  });
const repIns: RepIn[] = [];
const rep = (x: RepIn) => repIns.push(x);
const P = 'pass';
rep({ name: 'plain-ed25519', checks: { leaf_signature: P, cap_chain: P, replay: P }, pcactn: { cap_chain: [{}, {}] } });
rep({ name: 'leaf-hybrid', checks: { leaf_signature: P }, pcactn: { alg: 'hybrid-ed25519-ml-dsa-65', cap_chain: [] } });
rep({ name: 'leaf-pure-pq', checks: { leaf_signature: P }, pcactn: { alg: 'ml-dsa-65' } });
rep({ name: 'leaf-unknown-suite', checks: { leaf_signature: P }, pcactn: { alg: 'no-such-suite' } });
rep({ name: 'chain-weakest-wins', checks: { cap_chain: P }, pcactn: { cap_chain: [{ alg: 'ml-dsa-65' }, { alg: 'hybrid-ed25519-ml-dsa-65' }, {}] } });
rep({ name: 'chain-all-pq', checks: { cap_chain: P }, pcactn: { cap_chain: [{ alg: 'ml-dsa-65' }, { alg: 'ml-dsa-87' }] } });
rep({ name: 'chain-hybrid-and-pq', checks: { cap_chain: P }, pcactn: { cap_chain: [{ alg: 'ml-dsa-65' }, { alg: 'hybrid-ed25519-ml-dsa-65' }] } });
rep({ name: 'chain-empty', checks: { cap_chain: P }, pcactn: { cap_chain: [] } });
rep({ name: 'unbound-pq-leaf', checks: { leaf_signature: P }, pcactn: { alg: 'ml-dsa-65' }, allow_unbound_pq: true });
rep({ name: 'unbound-pq-ed25519-stays-ed25519', checks: { leaf_signature: P }, pcactn: {}, allow_unbound_pq: true });
rep({ name: 'unbound-pq-chain', checks: { cap_chain: P }, pcactn: { cap_chain: [{ alg: 'ml-dsa-65' }] }, allow_unbound_pq: true });
rep({ name: 'failed-check-has-no-level', checks: { leaf_signature: 'fail', cap_chain: 'not-enforced' }, pcactn: { alg: 'ml-dsa-65', cap_chain: [{ alg: 'ml-dsa-65' }] } });
rep({ name: 'attestation-hardware', checks: { attestation: P }, hooks: { attestation: { level: 'hardware', vendor: 'amd-sev-snp' } } });
rep({ name: 'attestation-software', checks: { attestation: P }, hooks: { attestation: { level: 'software' } } });
rep({ name: 'attestation-unlabelled', checks: { attestation: P }, hooks: { attestation: 'unlabelled' } });
rep({ name: 'attestation-no-hook', checks: { attestation: P } });
rep({ name: 'attestation-hook-override', checks: { attestation: P }, hooks: { attestation: { level: 'software' } }, attestation_hook: { level: 'multi_root', vendor: 'multi' } });
rep({ name: 'attestation-failed', checks: { attestation: 'fail' }, hooks: { attestation: { level: 'hardware' } } });
rep({ name: 'zk-groth16-single-party', checks: { zk_compliance: P }, hooks: { zk: { level: 'groth16', ceremony: 'single-party' } } });
rep({ name: 'zk-groth16-multi-party', checks: { zk_compliance: P }, hooks: { zk: { level: 'groth16', ceremony: 'multi-party', vendor: 'snarkjs' } } });
rep({ name: 'zk-attested-vm', checks: { zk_compliance: P }, hooks: { zk: { level: 'attested_vm' } } });
rep({ name: 'zk-attested-vm-hw', checks: { zk_compliance: P }, hooks: { zk: { level: 'attested_vm_hw' } } });
rep({ name: 'zk-no-hook', checks: { zk_compliance: P } });
rep({ name: 'threshold-multisig', checks: { threshold: P }, hooks: { threshold: { level: 'multisig' } }, threshold_t: 2 });
rep({ name: 'threshold-frost-awaiting-audit-scheme', checks: { threshold: P }, hooks: { threshold: { level: 'frost' } }, threshold_t: 2 });
rep({ name: 'threshold-mpc-labelled-awaiting-audit', checks: { threshold: P }, hooks: { threshold: { level: 'mpc', awaiting_audit: true } } });
rep({ name: 'threshold-multisig-flagged-awaiting-audit', checks: { threshold: P }, hooks: { threshold: { level: 'multisig', awaiting_audit: true } }, threshold_t: 3 });
rep({ name: 'threshold-no-hook', checks: { threshold: P } });
rep({ name: 'threshold-t-not-a-number', checks: { threshold: P }, hooks: { threshold: { level: 'multisig' } } });
rep({ name: 'revocation-labelled', checks: { revocation: P }, hooks: { revocation: { level: 'signed_epoch', vendor: 'guardian' } } });
rep({ name: 'revocation-unlabelled', checks: { revocation: P }, hooks: { revocation: 'unlabelled' } });
rep({ name: 'bond-ref-is-unsupported', checks: { replay: P }, pcactn: { bond_ref: { id: 'b1' } } });
rep({ name: 'bond-ref-with-unsupported-check', checks: { bond: 'unsupported' }, pcactn: { bond_ref: 'x' } });
rep({ name: 'unsupported-check', checks: { zk_compliance: 'unsupported', replay: P } });
rep({ name: 'degraded-pass', checks: { tighten: P, replay: P }, degraded: { tighten: 'model_polarity legacy', replay: 'ignored: not a pass' } });
rep({ name: 'degraded-on-failed-check-ignored', checks: { tighten: 'fail' }, degraded: { tighten: 'model_polarity legacy' } });
rep({ name: 'everything', checks: { leaf_signature: P, cap_chain: P, attestation: P, zk_compliance: P, threshold: P, revocation: P }, pcactn: { alg: 'hybrid-ed25519-ml-dsa-65', cap_chain: [{ alg: 'hybrid-ed25519-ml-dsa-65' }] }, hooks: { attestation: { level: 'multi_root', vendor: 'v' }, zk: { level: 'policyvm_snark', ceremony: 'multi-party' }, threshold: { level: 'multisig' }, revocation: { level: 'signed_epoch' } }, threshold_t: 2 });
const reportCases = repIns.map((x) => ({ ...x, report: buildReport(x) }));

// requirement cases over the recorded reports (and a few hand-built ones); the reason is recorded, never written by hand
const byName = Object.fromEntries(reportCases.map((c) => [c.name, c.report]));
interface ReqIn { name: string; report: AssuranceReport; require: Record<string, unknown> }
const reqIns: ReqIn[] = [];
const rq = (name: string, report: string | AssuranceReport, require: Record<string, unknown>) => reqIns.push({ name, report: typeof report === 'string' ? byName[report]! : report, require });
rq('empty-requirement-passes', 'plain-ed25519', {});
rq('pq-required-ed25519', 'plain-ed25519', { signature: 'pq' });
rq('pq-required-hybrid-leaf-missing-chain', 'leaf-hybrid', { signature: 'pq' });
rq('pq-required-chain-has-ed25519', 'chain-weakest-wins', { signature: 'pq' });
rq('pq-required-chain-all-pq-leaf-absent', 'chain-all-pq', { signature: 'pq' });
rq('pq-required-met', { leaf_signature: { outcome: 'pass', level: 'hybrid', suites: ['h'] }, cap_chain: { outcome: 'pass', level: 'pq', suites: ['p'] } }, { signature: 'pq' });
rq('pq-required-unbound', 'unbound-pq-leaf', { signature: 'pq' });
rq('pq-required-leaf-failed', { leaf_signature: { outcome: 'fail' }, cap_chain: { outcome: 'pass', level: 'pq' } }, { signature: 'pq' });
rq('pq-required-unknown-suite', 'leaf-unknown-suite', { signature: 'pq' });
rq('attestation-hardware-met-by-hardware', 'attestation-hardware', { attestation: 'hardware' });
rq('attestation-hardware-not-met-by-software', 'attestation-software', { attestation: 'hardware' });
rq('attestation-software-met-by-hardware', 'attestation-hardware', { attestation: 'software' });
rq('attestation-multi-root-not-met-by-hardware', 'attestation-hardware', { attestation: 'multi_root' });
rq('attestation-multi-root-met', 'attestation-hook-override', { attestation: 'multi_root' });
rq('attestation-unlabelled', 'attestation-unlabelled', { attestation: 'software' });
rq('attestation-absent', 'plain-ed25519', { attestation: 'software' });
rq('attestation-failed', 'attestation-failed', { attestation: 'software' });
rq('zk-attested-vm-met', 'zk-attested-vm', { zk: 'attested_vm' });
rq('zk-attested-vm-hardware-not-met-by-attested-vm', 'zk-attested-vm', { zk: 'attested_vm_hardware' });
rq('zk-attested-vm-hardware-met', 'zk-attested-vm-hw', { zk: 'attested_vm_hardware' });
rq('zk-attested-vm-hardware-met-by-proof', 'zk-groth16-multi-party', { zk: 'attested_vm_hardware' });
rq('zk-proof-not-met-by-attested-vm', 'zk-attested-vm', { zk: 'proof' });
rq('zk-proof-met-by-snark', 'zk-groth16-single-party', { zk: 'proof' });
rq('zk-snark-met', 'zk-groth16-multi-party', { zk: 'snark' });
rq('zk-snark-not-met-by-stark', { zk_compliance: { outcome: 'pass', level: 'stark' } }, { zk: 'snark' });
rq('zk-proof-met-by-stark', { zk_compliance: { outcome: 'pass', level: 'stark' } }, { zk: 'proof' });
rq('zk-unlabelled', 'zk-no-hook', { zk: 'attested_vm' });
rq('zk-absent', 'plain-ed25519', { zk: 'attested_vm' });
rq('threshold-multisig-allowed', 'threshold-multisig', { threshold: ['multisig'] });
rq('threshold-multisig-not-in-list', 'threshold-multisig', { threshold: ['frost'] });
rq('threshold-frost-listed-accepts-awaiting-audit', 'threshold-frost-awaiting-audit-scheme', { threshold: ['frost'] });
rq('threshold-frost-unlisted-and-awaiting-audit', 'threshold-frost-awaiting-audit-scheme', { threshold: ['multisig'] });
rq('threshold-no-hook', 'threshold-no-hook', { threshold: ['multisig'] });
rq('threshold-multisig-flagged-awaiting-audit-listed', 'threshold-multisig-flagged-awaiting-audit', { threshold: ['multisig'] });
rq('threshold-absent', 'plain-ed25519', { threshold: ['multisig'] });
rq('awaiting-audit-denies-by-default', 'threshold-mpc-labelled-awaiting-audit', {});
rq('awaiting-audit-denied-under-other-dimension', { threshold: { outcome: 'pass', level: 'mpc', awaiting_audit: true }, attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware' });
rq('awaiting-audit-allowed', { threshold: { outcome: 'pass', level: 'mpc', awaiting_audit: true }, attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware', allowAwaitingAudit: true });
// Deprecated input aliases (one release): a report entry's `preview` and the requirement's `allowPreview` mean the same as `awaiting_audit` / `allowAwaitingAudit`.
rq('preview-alias-denies-by-default', { threshold: { outcome: 'pass', level: 'mpc', preview: true } as unknown as AssuranceReport['threshold'], attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware' });
rq('preview-alias-allowed', { threshold: { outcome: 'pass', level: 'mpc', preview: true } as unknown as AssuranceReport['threshold'], attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware', allowPreview: true });
rq('awaiting-audit-allowed-by-alias', { threshold: { outcome: 'pass', level: 'mpc', awaiting_audit: true }, attestation: { outcome: 'pass', level: 'hardware' } }, { attestation: 'hardware', allowPreview: true });
rq('unsupported-denies-even-when-everything-else-met', 'bond-ref-is-unsupported', {});
rq('unsupported-check-denies', 'unsupported-check', { attestation: 'software' });
rq('degraded-denies', 'degraded-pass', {});
rq('degraded-denies-with-met-dimension', 'degraded-pass', { signature: 'pq' });
rq('everything-met', 'everything', { signature: 'pq', attestation: 'multi_root', zk: 'snark', threshold: ['multisig'] });
rq('first-unmet-attestation-before-zk', 'plain-ed25519', { zk: 'snark', attestation: 'software', signature: 'pq' });
const requirementCases = reqIns.map((x) => ({ ...x, unmet: unmetAssurance(x.report, x.require as never) ?? null }));

const mr = (name: string, roots: { level: string; required?: boolean }[], threshold: number) => ({ name, roots, threshold, level: multiRootLevel(roots.map((r) => ({ verifier: setAssuranceLabel({}, { level: r.level }), required: r.required })), threshold) });
const multiRoot = [
  mr('two-hardware', [{ level: 'hardware' }, { level: 'hardware' }], 2),
  mr('one-hardware-needed', [{ level: 'hardware' }, { level: 'hardware' }], 1),
  mr('quorum-can-pick-weakest', [{ level: 'hardware' }, { level: 'software' }, { level: 'hardware' }], 2),
  mr('required-fills-first', [{ level: 'hardware', required: true }, { level: 'software' }, { level: 'hardware' }], 2),
  mr('required-pair', [{ level: 'hardware', required: true }, { level: 'hardware', required: true }, { level: 'software' }], 2),
  mr('all-software', [{ level: 'software' }, { level: 'software' }], 2),
  mr('unlabelled-root', [{ level: 'hardware' }, { level: 'unknown' }], 2),
  mr('threshold-zero', [{ level: 'hardware' }, { level: 'hardware' }], 0),
  mr('threshold-over-count', [{ level: 'hardware' }, { level: 'software' }], 5),
  mr('multi-root-labels', [{ level: 'multi_root' }, { level: 'hardware' }], 2),
].map((x) => x);

// ---------------------------------------------------------------- write
const meta = { format: 1, generator: 'packages/pca/scripts/gen-conformance-native-parity.ts' };
async function build(): Promise<Record<string, unknown>> {
  const operations = [];
  for (const s of opScenarios) operations.push({ ...s, expect: await runOps(s.steps) });
  const plans = [];
  for (const s of planScenarios) plans.push({ ...s, expect: await runPlan(s.validator, s.steps) });
  return {
    'operation-vectors.json': {
      ...meta, suite: 'operation-records', layer: 'extension',
      description:
        'Operation records (T3): execute an authorized operation at most once. Each scenario runs against ONE fresh in-memory OperationStore and a fixed clock per step (`at`, epoch ms); `expect[i]` is the answer to `steps[i]`. `execute` takes a pre-authorized operation {id, verb, resource, params_digest} with a PCActn that carries `exp` and a signed reversibility class (`signed_class`), the server class, an optional recheck (ok / refuse with reason / throw with message), `recheck_for`, `timeout_ms`, and a function that commits `result` (default: the idempotency key), throws `message`, or re-enters the same execution; answers are {outcome, fn_calls, record}. Reason and error strings are compared exactly. `no_store` / `not_allowed` exercise the refusals.',
      constants: { pending_timeout_ms: OPERATION_PENDING_TIMEOUT_MS },
      scenarios: operations,
    },
    'plan-vectors.json': {
      ...meta, suite: 'plan-lifecycle', layer: 'extension',
      description:
        'Plan lifecycle (T10): draft -> validated -> committed -> authorized -> revoked. One fresh registry per scenario; `at` is the clock of each step; `expect[i]` answers `steps[i]` (transition results, statuses, contexts). Roots are Merkle roots of the plan node leaves (planNodeLeaf), so a native must reproduce the commitment. `validator` is the server validator the registry is built with.',
      scenarios: planScenarios.map((s, i) => ({ ...s, expect: plans[i]!.expect })),
    },
    'staleness-vectors.json': {
      ...meta, suite: 'revocation-staleness', layer: 'extension',
      description:
        'Revocation staleness (T9). `constants`; `max_age` (per-class window from a policy); `effective_reversibility` (stricter of server and signed class; missing or unknown = irreversible); `age` (checkRevocationAge); `epoch` (signed guardian epoch, Ed25519, check with an optional verifier-side cap; `alg` of an unregistered suite must be refused); `gate` (the whole decision for a signed epoch / a bare root / nothing under a policy and a class: `mode` epoch|root|none, `root_issued_at: null` = unknown age). Strings "NaN" stand for a NaN number (those cases carry `ok_only`: compare `ok` only, a NaN has no portable text). Reasons compared exactly. `revocation_set` is the sorted set (UTF-8 byte order, root bound to the size) the next two tables use; `membership` (verifyNonMembership: root, id, proof -> ok; `set` names which set the root is: main, one, empty or the wrong one); `gate_ids` (the whole checker with a signed epoch over the main set, issued `epoch_issued_at`, `ids` to prove, `proofs` keyed by id (absent = none supplied), compared on ok and reason exactly).',
      constants: { refresh_ms: REVOCATION_EPOCH_REFRESH_MS, validity_ms: REVOCATION_EPOCH_VALIDITY_MS, irreversible_max_age_ms: REVOCATION_IRREVERSIBLE_MAX_AGE_MS, skew_ms: 60_000 },
      guardian_public: GUARD_PUB,
      revocation_root: rset.root,
      max_age: maxAge,
      effective_reversibility: effective,
      age: ageCases,
      epoch: epochCases,
      gate: gateCases,
      revocation_set: { ids: mset.list(), root: msetRoot, size: mset.size, empty_root: empty.root, single: { ids: one.list(), root: one.root } },
      membership: memCases,
      gate_ids: idGateCases,
    },
    'assurance-vectors.json': {
      ...meta, suite: 'assurance', layer: 'extension',
      description:
        'Assurance labels and the high-assurance gate (T8, B7). `signature_level` (suite -> level); `report` (assuranceReport from checks, the presented PCActn alg / cap_chain algs / bond_ref, the verifier hooks labels {level, vendor?, awaiting_audit?, ceremony?} or "unlabelled", the attestation hook that wins, thresholdT, allowUnboundPq, degraded); `requirement` (unmetAssurance(report, require) -> first unmet reason or null); `multi_root` (multiRootLevel). Labels come from the verifier configuration, never from the presented evidence. Reports and reasons are compared exactly (key order is irrelevant).',
      signature_level: sigLevels,
      report: reportCases,
      requirement: requirementCases,
      multi_root: multiRoot,
    },
  };
}

build().then((files) => {
  const dir = join(__dirname, '..', 'conformance');
  let stale = false;
  for (const [name, doc] of Object.entries(files)) {
    const text = `${JSON.stringify(doc, null, 2)}\n`;
    const path = join(dir, name);
    if (process.argv.includes('--check')) {
      let cur = '';
      try { cur = readFileSync(path, 'utf8'); } catch { /* missing */ }
      if (cur !== text) { console.error(`${name} is stale: run tsx scripts/gen-conformance-native-parity.ts`); stale = true; }
    } else {
      writeFileSync(path, text);
      console.log(`wrote ${path}`);
    }
  }
  if (stale) process.exit(1);
});
