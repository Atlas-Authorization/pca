/**
 * The `pca-state` profile: run the store behind `requirePCA` (a `PcaStateStore`, ideally an `AtomicPcaStateStore`) through
 * the REAL guard, with real signed PCActns, and check the replay-state invariant: one action id (grant, leaf holder,
 * counter) goes from unconsumed to consumed at most once, however many copies arrive, on however many instances or
 * processes, across crashes after the claim and retries after a timeout.
 *
 *  - `claim-burst` / `claim-concurrent` / `claim-durability`: the store's claim, seen as `advance(key, counter)`, through
 *    the linearizability checker of the base kit (a store without `claim` is driven through get / put, under its
 *    `withKeyLock` when it has one).
 *  - `one-instance`: N concurrent copies of one proof to one guard: exactly one admitted, every round.
 *  - `instances`: the copies spread over K guards, each on its own `open()` handle, built with `multiInstance: true`
 *    (a store that only the in-process lock can serialise is refused there, which fails this test).
 *  - `processes`: the same race across K child processes (needs the adapter module path).
 *  - `crash-after-claim`: admitted, then the instance dies before its handler runs (and the backend crashes / restarts when
 *    the adapter can): the same proof is denied afterwards, the next counter admitted. With a module path the instance is a
 *    child process that SIGKILLs itself right after the admission.
 *  - `retry-after-timeout`: the commit lands but its answer is lost (the guard fails closed), and the retry is denied; and
 *    a retry on another instance while the first commit is still in flight: exactly one admitted.
 */
import { fork } from 'node:child_process';
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  DEFAULT_RISK_POLICY,
  PCACTN_VERSION,
  atomicMemoryPcaStore,
  commitPlan,
  conditionsDigest,
  delegate,
  durablePcaStateStore,
  encodeKey,
  generateKeyPair,
  hashCanonical,
  isAtomicPcaStateStore,
  mintGrant,
  requirePCA,
  signPCActn,
  type AtomicPcaStateStore,
  type Capability,
  type PCActn,
  type PcaGuardResult,
  type PcaHolderState,
  type PcaStateStore,
  type PlanNode,
} from '@atlasauth/pca';
import { openDurableState } from '@atlasauth/pca/durable-state';
import { runTest, overall, type Status, type TestReport } from './runner';
import { pickExport } from './load';
import type { StoreAdapter } from './types';

// ------------------------------------------------------------------------------------------------ adapter interface

export interface PcaStateCapabilities {
  /** State survives closing every handle and `restart()` (default true). Declare false only for a process-local store. */
  durable?: boolean;
  /** Several instances / processes can share the backend through separate `open()` handles (default true). */
  shared?: boolean;
}

export interface PcaStateHandle {
  store: PcaStateStore;
  /** Release the handle. The backend's state must survive it. */
  close?(): Promise<void>;
}

export interface PcaStateAdapter {
  name: string;
  capabilities?: PcaStateCapabilities;
  /** One handle = one verifier instance's connection to the shared backend. */
  open(): Promise<PcaStateHandle>;
  restart?(): Promise<void>;
  crash?(): Promise<void>;
  teardown?(): Promise<void>;
}

// ------------------------------------------------------------------------------------------------ fixture

const AUDIENCE = 'pca-store-conformance';

/** A grant plus pre-signed PCActns (counters 1..n) from one agent: JSON, so child processes can share it. */
export interface PcaStateFixture {
  grant: Capability;
  holder: string;
  proofs: PCActn[];
}

export function makePcaStateFixture(n: number, now = Date.now()): PcaStateFixture {
  const principal = generateKeyPair();
  const pPub = encodeKey(principal.publicKey);
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: pPub,
    holder: pPub,
    goal: 'store conformance',
    envelope: {
      predicates: [{ verb: 'read', resource: 'doc:*' }],
      caveats: [{ type: 'expires', at: now + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
      agent_binding: {} as never,
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  const agent = generateKeyPair();
  const holder = encodeKey(agent.publicKey);
  const task = delegate(grant, holder, [{ type: 'expires', at: now + 3_600_000 }], principal.secretKey);
  const node: PlanNode = { id: 'n1', verb: 'read', resource: 'doc:1', params_digest: hashCanonical({}), reversibility_class: 'reversible' };
  const plan = commitPlan([node]);
  const proofs = Array.from({ length: n }, (_, i) =>
    signPCActn(
      {
        ver: PCACTN_VERSION,
        action: { verb: node.verb, resource: node.resource, params_digest: node.params_digest!, reversibility_class: 'reversible' },
        grant_ref: grant.id,
        cap_chain: [grant, task],
        plan: { root: plan.root, inclusion_proof: plan.proofFor('n1'), node_id: 'n1', conditions_digest: conditionsDigest(undefined, undefined) },
        attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
        provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
        counter: i + 1,
        risk_claim: { r: 0, inputs: {} },
        aud: AUDIENCE,
        iat: now,
        exp: now + 3_600_000,
      } as never,
      agent.secretKey,
    ),
  );
  return { grant, holder, proofs };
}

/** The guard under test: the real `requirePCA`, the full default-deny profile, the store as `budgetStore`. */
export function pcaStateGuard(fx: PcaStateFixture, store: PcaStateStore, o: { multiInstance?: boolean } = {}) {
  const node = { id: 'n1', verb: 'read', resource: 'doc:1', params_digest: hashCanonical({}), reversibility_class: 'reversible' };
  return requirePCA({
    audience: AUDIENCE,
    resolveGrant: async (ref) => (ref === fx.grant.id ? fx.grant : null),
    budgetStore: store,
    operation: () => ({ verb: node.verb, resource: node.resource, params: {} }),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    context: () => ({ plan: [node], planAuthorized: true, risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 } }),
    // the kit measures what the store does: a get/put store is exercised in-process unless the caller declares several instances
    multiInstance: o.multiInstance === true,
  });
}

const call = (fx: PcaStateFixture, counter: number) => ({ headers: {}, body: { pcactn: fx.proofs[counter - 1]! } });
type Outcome = 'admitted' | 'replay' | 'error';
/** admitted / denied as a replay (counter check failed) / any other denial (fail closed, e.g. a store error). */
export const outcomeOf = (r: PcaGuardResult): Outcome => (r.ok ? 'admitted' : r.verdict.checks.replay === 'fail' ? 'replay' : 'error');

// ------------------------------------------------------------------------------------------------ claim as `advance`

/** The store's claim seen as the base kit's `advance(stream, counter)`, so its histories go through the linearizability checker. */
export function claimAsStoreAdapter(a: PcaStateAdapter): StoreAdapter {
  return {
    name: `${a.name} (claim as advance)`,
    capabilities: { durable: a.capabilities?.durable ?? true, consumeOnce: false, advance: true },
    async open() {
      const h = await a.open();
      const st = h.store;
      const viaPut = async (k: string, c: number): Promise<boolean> => {
        const run = async (): Promise<boolean> => {
          const cur = await st.get(k);
          if (cur?.lastCounter !== undefined && !(c > cur.lastCounter)) return false;
          await st.put(k, { ...cur, lastCounter: c });
          return true;
        };
        return st.withKeyLock ? st.withKeyLock(k, run) : run();
      };
      return {
        async advance(k, c) {
          if (!isAtomicPcaStateStore(st)) return viaPut(k, c);
          const r = await st.claim(k, { counter: c });
          if (r.ok) return true;
          if (r.reason === 'replay') return false;
          throw new Error('claim reported a budget conflict without a budget');
        },
        close: () => h.close?.() ?? Promise.resolve(),
      };
    },
    ...(a.restart ? { restart: () => a.restart!() } : {}),
    ...(a.crash ? { crash: () => a.crash!() } : {}),
  };
}

// ------------------------------------------------------------------------------------------------ the run

export type PcaStateTestName =
  | 'claim-burst'
  | 'claim-concurrent'
  | 'claim-durability'
  | 'one-instance'
  | 'instances'
  | 'processes'
  | 'crash-after-claim'
  | 'retry-after-timeout';
export const ALL_PCA_STATE_TESTS: readonly PcaStateTestName[] = [
  'claim-burst',
  'claim-concurrent',
  'claim-durability',
  'one-instance',
  'instances',
  'processes',
  'crash-after-claim',
  'retry-after-timeout',
];

export interface PcaStateTestReport {
  test: PcaStateTestName;
  status: Status;
  /** Per round: how many presentations of that round's proof were admitted (must be exactly 1). */
  admitted?: number[];
  note?: string;
  /** The base kit's report for the claim-* tests (counterexamples included). */
  linearizability?: TestReport;
}

export interface PcaStateReport {
  adapter: string;
  stateMode: string;
  status: Exclude<Status, 'skip'>;
  tests: PcaStateTestReport[];
}

export interface PcaStateOptions {
  tests?: readonly PcaStateTestName[];
  /** Rounds per race test (a fresh counter each), default 10. */
  rounds?: number;
  /** Concurrent copies of each proof, default 16. */
  copies?: number;
  /** Instances (guards on separate handles) or processes, default 4 / 3. */
  instances?: number;
  processes?: number;
  /** Options for the base kit's claim-* tests (clients, durationMs, ...). */
  claim?: Parameters<typeof runTest>[3];
  /** Module path (or `builtin:pca-state:<name>`) of the adapter: needed by `processes` and the process half of `crash-after-claim`. */
  module?: string;
  moduleOptions?: Record<string, string>;
  /** Compiled worker entry (default: `pca-state-worker.js` next to this file). */
  workerPath?: string;
}

const skip = (test: PcaStateTestName, note: string): PcaStateTestReport => ({ test, status: 'skip', note });
const exactlyOne = (test: PcaStateTestName, admitted: number[], note?: string): PcaStateTestReport => ({
  test,
  status: admitted.every((n) => n === 1) ? 'pass' : 'fail',
  admitted,
  ...(note ? { note } : {}),
});

async function withHandles<T>(a: PcaStateAdapter, n: number, fn: (hs: PcaStateHandle[]) => Promise<T>): Promise<T> {
  const hs = await Promise.all(Array.from({ length: n }, () => a.open()));
  try {
    return await fn(hs);
  } finally {
    await Promise.all(hs.map((h) => h.close?.()));
  }
}

async function race(fx: PcaStateFixture, guards: ReturnType<typeof pcaStateGuard>[], counter: number, copies: number): Promise<number> {
  const rs = await Promise.all(Array.from({ length: copies }, (_, i) => guards[i % guards.length]!(call(fx, counter))));
  return rs.filter((r) => r.ok).length;
}

async function oneInstance(a: PcaStateAdapter, o: Required<Pick<PcaStateOptions, 'rounds' | 'copies'>>): Promise<PcaStateTestReport> {
  const fx = makePcaStateFixture(o.rounds);
  return withHandles(a, 1, async ([h]) => {
    const g = pcaStateGuard(fx, h!.store);
    const admitted: number[] = [];
    for (let r = 1; r <= o.rounds; r++) admitted.push(await race(fx, [g], r, o.copies));
    return exactlyOne('one-instance', admitted, `state mode ${g.stateMode}`);
  });
}

async function instances(a: PcaStateAdapter, o: Required<Pick<PcaStateOptions, 'rounds' | 'copies' | 'instances'>>): Promise<PcaStateTestReport> {
  if (a.capabilities?.shared === false) return skip('instances', 'the adapter declares shared: false (one instance only)');
  const fx = makePcaStateFixture(o.rounds);
  return withHandles(a, o.instances, async (hs) => {
    let guards: ReturnType<typeof pcaStateGuard>[];
    try {
      guards = hs.map((h) => pcaStateGuard(fx, h.store, { multiInstance: true }));
    } catch (e) {
      return { test: 'instances', status: 'fail', note: `refused in multi-instance mode: ${(e as Error).message}` };
    }
    const admitted: number[] = [];
    for (let r = 1; r <= o.rounds; r++) admitted.push(await race(fx, guards, r, o.copies));
    return exactlyOne('instances', admitted, `${o.instances} instances, state mode ${guards[0]!.stateMode}`);
  });
}

/** Wrap a handle so its commit (claim, or put for a lock-based store) lands but the caller never hears back. */
function commitHook(st: PcaStateStore, around: (commit: () => Promise<unknown>) => Promise<unknown>): PcaStateStore {
  if (isAtomicPcaStateStore(st)) {
    const w: AtomicPcaStateStore = { ...st, claim: (k, c) => around(() => st.claim(k, c)) as ReturnType<AtomicPcaStateStore['claim']> };
    return bindLock(w, st);
  }
  return bindLock({ ...st, put: (k, v) => around(() => st.put(k, v)) as Promise<void> }, st);
}
const bindLock = <S extends PcaStateStore>(w: S, st: PcaStateStore): S => (st.withKeyLock ? Object.assign(w, { withKeyLock: st.withKeyLock.bind(st) }) : w);

async function retryAfterTimeout(a: PcaStateAdapter): Promise<PcaStateTestReport> {
  const fx = makePcaStateFixture(4);
  const shared = a.capabilities?.shared !== false;
  return withHandles(a, shared ? 2 : 1, async (hs) => {
    const other = hs[hs.length - 1]!;
    // 1. the commit lands, its answer is lost: the guard fails closed, the retry (another instance when shared) is a replay
    let lose = true;
    const lossy = commitHook(hs[0]!.store, async (commit) => {
      const r = await commit();
      if (lose) {
        lose = false;
        throw new Error('timeout (answer lost after commit)');
      }
      return r;
    });
    const first = outcomeOf(await pcaStateGuard(fx, lossy)(call(fx, 1)));
    const retry = outcomeOf(await pcaStateGuard(fx, other.store)(call(fx, 1)));
    const next = outcomeOf(await pcaStateGuard(fx, other.store)(call(fx, 2)));
    // 2. the first commit is still in flight when the caller retries elsewhere: exactly one of the two is admitted
    let entered!: () => void;
    const atGate = new Promise<void>((r) => (entered = r));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = commitHook(hs[0]!.store, async (commit) => {
      entered();
      await gate;
      return commit();
    });
    const inflight = pcaStateGuard(fx, slow)(call(fx, 3));
    await Promise.race([atGate, inflight]);
    const retried = pcaStateGuard(fx, other.store)(call(fx, 3));
    release();
    const pair = (await Promise.all([inflight, retried])).filter((r) => r.ok).length;
    const ok = first === 'error' && retry === 'replay' && next === 'admitted' && pair === 1;
    return {
      test: 'retry-after-timeout',
      status: ok ? 'pass' : 'fail',
      admitted: [first === 'admitted' || retry === 'admitted' ? 1 : 0, pair],
      note: `lost answer: first=${first}, retry=${retry}, next counter=${next}; in-flight retry: ${pair} admitted of 2${shared ? '' : ' (one instance: shared: false)'}`,
    };
  });
}

async function crashAfterClaim(a: PcaStateAdapter, o: PcaStateOptions): Promise<PcaStateTestReport> {
  if (a.capabilities?.durable === false) return skip('crash-after-claim', 'the adapter declares durable: false (state dies with the process)');
  const fx = makePcaStateFixture(4);
  const notes: string[] = [];
  // in process: admitted on handle A, which is then abandoned (no close); the backend crashes / restarts when it can
  const h1 = await a.open();
  const first = outcomeOf(await pcaStateGuard(fx, h1.store)(call(fx, 1)));
  if (a.crash) await a.crash();
  if (a.restart) await a.restart();
  const after = await withHandles(a, 1, async ([h]) => {
    const g = pcaStateGuard(fx, h!.store);
    return [outcomeOf(await g(call(fx, 1))), outcomeOf(await g(call(fx, 2)))];
  });
  await h1.close?.().catch(() => undefined);
  let ok = first === 'admitted' && after[0] === 'replay' && after[1] === 'admitted';
  notes.push(`in process: admitted=${first}, same proof after ${a.crash ? 'crash + ' : ''}${a.restart ? 'restart' : 're-open'}=${after[0]}, next counter=${after[1]}`);
  // child process: SIGKILLed right after the admission, before its handler; a new process retries
  if (o.module) {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-pstate-crash-'));
    const fxFile = join(dir, 'fixture.json');
    writeFileSync(fxFile, JSON.stringify(fx));
    const killed = await runWorker(o, { mode: 'admit-then-die', fixture: fxFile, out: join(dir, 'a.jsonl'), counter: 3, copies: 1, instances: 1 });
    if (a.restart) await a.restart();
    const retried = await runWorker(o, { mode: 'race', fixture: fxFile, out: join(dir, 'b.jsonl'), counter: 3, copies: 1, instances: 1 });
    const fresh = await runWorker(o, { mode: 'race', fixture: fxFile, out: join(dir, 'c.jsonl'), counter: 4, copies: 1, instances: 1 });
    const pOk = killed.signal === 'SIGKILL' && killed.admitted === 1 && retried.admitted === 0 && retried.replays === 1 && fresh.admitted === 1;
    ok = ok && pOk;
    notes.push(`child process: killed after admission=${killed.signal === 'SIGKILL' && killed.admitted === 1}, retry in a new process admitted ${retried.admitted}, next counter admitted ${fresh.admitted}`);
  } else notes.push('process half skipped (needs the adapter module path)');
  return { test: 'crash-after-claim', status: ok ? 'pass' : 'fail', note: notes.join('; ') };
}

// ------------------------------------------------------------------------------------------------ child processes

export interface PcaStateWorkerConfig {
  module: string;
  options: Record<string, string>;
  mode: 'race' | 'admit-then-die';
  fixture: string;
  out: string;
  /** race: rounds start at `origin + r * roundMs` in every process (counter = r + 1). */
  counter?: number;
  rounds?: number;
  origin?: number;
  roundMs?: number;
  copies: number;
  instances: number;
}

interface WorkerLine {
  counter: number;
  admitted: number;
  replays: number;
  errors: number;
}

async function runWorker(o: PcaStateOptions, cfg: Omit<PcaStateWorkerConfig, 'module' | 'options'>): Promise<{ admitted: number; replays: number; signal: string | null; lines: WorkerLine[] }> {
  const full: PcaStateWorkerConfig = { module: o.module!, options: o.moduleOptions ?? {}, ...cfg };
  const ch = fork(o.workerPath ?? join(__dirname, 'pca-state-worker.js'), [JSON.stringify(full)], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const signal = await new Promise<string | null>((res) => ch.on('exit', (_c, s) => res(s)));
  const lines = existsSync(cfg.out) ? readFileSync(cfg.out, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as WorkerLine) : [];
  return { admitted: lines.reduce((n, l) => n + l.admitted, 0), replays: lines.reduce((n, l) => n + l.replays, 0), signal, lines };
}

async function processes(a: PcaStateAdapter, o: PcaStateOptions & Required<Pick<PcaStateOptions, 'rounds' | 'copies' | 'processes'>>): Promise<PcaStateTestReport> {
  if (a.capabilities?.shared === false) return skip('processes', 'the adapter declares shared: false (one instance only)');
  if (!o.module) return skip('processes', 'needs the adapter module path (the guards run in child processes)');
  const fx = makePcaStateFixture(o.rounds);
  const dir = mkdtempSync(join(tmpdir(), 'pcasc-pstate-'));
  const fxFile = join(dir, 'fixture.json');
  writeFileSync(fxFile, JSON.stringify(fx));
  const roundMs = 150;
  const origin = Date.now() + 1500; // time for every process to start and open its handles
  const outs = await Promise.all(
    Array.from({ length: o.processes }, (_, p) =>
      runWorker(o, { mode: 'race', fixture: fxFile, out: join(dir, `p${p}.jsonl`), rounds: o.rounds, origin, roundMs, copies: o.copies, instances: 2 }),
    ),
  );
  const admitted = Array.from({ length: o.rounds }, (_, r) => outs.reduce((n, w) => n + w.lines.filter((l) => l.counter === r + 1).reduce((m, l) => m + l.admitted, 0), 0));
  const errors = outs.reduce((n, w) => n + w.lines.reduce((m, l) => m + l.errors, 0), 0);
  const crashed = outs.filter((w) => w.signal !== null || w.lines.length !== o.rounds).length;
  const r = exactlyOne('processes', admitted, `${o.processes} processes x 2 instances x ${o.copies} copies per round; ${errors} fail-closed errors${crashed ? `; ${crashed} worker(s) did not finish` : ''}`);
  return crashed ? { ...r, status: 'fail' } : r;
}

/** Entry of one child process (`pca-state-worker.ts`). */
export async function pcaStateWorkerMain(cfg: PcaStateWorkerConfig): Promise<void> {
  const a = await loadPcaStateAdapter(cfg.module, cfg.options);
  const fx = JSON.parse(readFileSync(cfg.fixture, 'utf8')) as PcaStateFixture;
  const hs = await Promise.all(Array.from({ length: cfg.instances }, () => a.open()));
  const guards = hs.map((h) => pcaStateGuard(fx, h.store, { multiInstance: cfg.instances > 1 || cfg.mode === 'race' }));
  const record = (counter: number, rs: Outcome[]): void =>
    appendFileSync(cfg.out, `${JSON.stringify({ counter, admitted: rs.filter((x) => x === 'admitted').length, replays: rs.filter((x) => x === 'replay').length, errors: rs.filter((x) => x === 'error').length })}\n`);
  if (cfg.mode === 'admit-then-die') {
    const r = outcomeOf(await guards[0]!(call(fx, cfg.counter!)));
    record(cfg.counter!, [r]);
    // the instance dies after the claim committed and before any handler ran
    process.kill(process.pid, 'SIGKILL');
    return;
  }
  const rounds = cfg.rounds ?? 1;
  for (let r = 0; r < rounds; r++) {
    const counter = cfg.counter ?? r + 1;
    const at = (cfg.origin ?? Date.now()) + r * (cfg.roundMs ?? 0);
    while (Date.now() < at) await new Promise((res) => setTimeout(res, Math.min(5, at - Date.now())));
    const rs = await Promise.all(Array.from({ length: cfg.copies }, (_, i) => guards[i % guards.length]!(call(fx, counter))));
    record(counter, rs.map(outcomeOf));
  }
  await Promise.all(hs.map((h) => h.close?.()));
  await a.teardown?.();
}

// ------------------------------------------------------------------------------------------------ runner

export async function runPcaStateConformance(a: PcaStateAdapter, opts: PcaStateOptions = {}): Promise<PcaStateReport> {
  const o = { rounds: opts.rounds ?? 10, copies: opts.copies ?? 16, instances: opts.instances ?? 4, processes: opts.processes ?? 3, ...opts };
  const probe = await a.open();
  const stateMode = pcaStateGuard(makePcaStateFixture(1), probe.store).stateMode;
  await probe.close?.();
  const tests: PcaStateTestReport[] = [];
  for (const t of o.tests ?? ALL_PCA_STATE_TESTS) {
    if (t === 'claim-burst' || t === 'claim-concurrent' || t === 'claim-durability') {
      const base = t === 'claim-burst' ? 'burst' : t === 'claim-concurrent' ? 'concurrent' : 'durability';
      const lr = await runTest(claimAsStoreAdapter(a), base, 'advance', { durationMs: 1000, ...o.claim });
      tests.push({ test: t, status: lr.status, linearizability: lr, ...(lr.note ? { note: lr.note } : {}) });
    } else if (t === 'one-instance') tests.push(await oneInstance(a, o));
    else if (t === 'instances') tests.push(await instances(a, o));
    else if (t === 'processes') tests.push(await processes(a, o));
    else if (t === 'crash-after-claim') tests.push(await crashAfterClaim(a, o));
    else tests.push(await retryAfterTimeout(a));
  }
  return { adapter: a.name, stateMode, status: overall(tests as unknown as TestReport[]), tests };
}

export function formatPcaStateReport(r: PcaStateReport): string {
  const out = [`pca-store-conformance (pca-state): ${r.adapter} [${r.stateMode}] -> ${r.status.toUpperCase()}`];
  for (const t of r.tests) {
    const adm = t.admitted ? `admitted per round [${t.admitted.join(',')}]` : '';
    const lin = t.linearizability ? `${t.linearizability.ops} ops, ${t.linearizability.violations.length} non-linearizable key(s)` : '';
    out.push(`  [${t.status.toUpperCase()}] ${t.test.padEnd(20)} ${[adm, lin, t.note ?? ''].filter(Boolean).join('; ')}`);
  }
  return out.join('\n');
}

// ------------------------------------------------------------------------------------------------ reference adapters

/** GOOD for ONE process: `atomicMemoryPcaStore` (not durable, not shared: the multi-instance tests are skipped). */
export function inMemoryPcaStateAdapter(): PcaStateAdapter {
  const store = atomicMemoryPcaStore();
  return { name: 'in-memory atomic (atomicMemoryPcaStore)', capabilities: { durable: false, shared: false }, open: async () => ({ store }) };
}

/** GOOD: `durablePcaStateStore` over the crash-safe, multi-process file store, one `openDurableState` per handle. */
export function durableFilePcaStateAdapter(options: { dir?: string } = {}): PcaStateAdapter {
  const dir = options.dir ?? mkdtempSync(join(tmpdir(), 'pcasc-pstate-durable-'));
  return {
    name: `durable-state file store, atomic claim (${dir})`,
    capabilities: { durable: true, shared: true },
    open: async () => ({ store: durablePcaStateStore(await openDurableState({ dir })) }),
    restart: async () => undefined,
  };
}

const yieldTurn = (): Promise<void> => new Promise((r) => setImmediate(r));

/** A process-wide map standing in for a "shared" backend in the BAD controls below. */
function sharedMap(): Map<string, PcaHolderState> {
  return new Map();
}

/** BAD: get / put with no claim and no lock: only the in-process lock serialises it (refused by `multiInstance`). */
export function getPutPcaStateAdapter(): PcaStateAdapter {
  const m = sharedMap();
  return {
    name: 'BAD get/put without claim or lock',
    capabilities: { durable: false, shared: true },
    open: async () => ({ store: { get: async (k) => m.get(k), put: async (k, v) => void m.set(k, v) } }),
  };
}

/** BAD: a `claim` that reads, awaits, then writes: two instances both read "fresh" and both admit. */
export function readThenWriteClaimPcaStateAdapter(): PcaStateAdapter {
  const m = sharedMap();
  return {
    name: 'BAD claim as read, await, write',
    capabilities: { durable: false, shared: true },
    open: async () => ({
      store: {
        get: async (k) => m.get(k),
        put: async (k, v) => void m.set(k, v),
        async claim(k, c) {
          const cur = m.get(k);
          await yieldTurn();
          if (cur?.lastCounter !== undefined && !(c.counter > cur.lastCounter)) return { ok: false, reason: 'replay', lastCounter: cur.lastCounter };
          m.set(k, { ...cur, lastCounter: c.counter, ...(c.budgetAfter ? { budget: c.budgetAfter } : {}) });
          return { ok: true };
        },
        async raisePin(k, pin, v) {
          const cur = m.get(k);
          if ((cur?.[pin] ?? -1) < v) m.set(k, { ...cur, [pin]: v });
        },
      } as AtomicPcaStateStore,
    }),
  };
}

/** BAD: a `withKeyLock` that only locks within ONE handle (a per-instance mutex passed off as a shared lock). */
export function localLockPcaStateAdapter(): PcaStateAdapter {
  const m = sharedMap();
  return {
    name: 'BAD per-handle lock passed off as shared',
    capabilities: { durable: false, shared: true },
    async open() {
      const locks = new Map<string, Promise<unknown>>();
      return {
        store: {
          scope: 'shared' as const,
          async get(k: string) {
            const v = m.get(k);
            await yieldTurn();
            return v;
          },
          put: async (k: string, v: PcaHolderState) => void m.set(k, v),
          withKeyLock<T>(k: string, fn: () => Promise<T>): Promise<T> {
            const run = (locks.get(k) ?? Promise.resolve()).then(fn, fn);
            locks.set(k, run.catch(() => undefined));
            return run;
          },
        },
      };
    },
  };
}

/** BAD: atomic and "durable", but a restart forgets every claim (state in process memory). */
export function volatilePcaStateAdapter(): PcaStateAdapter {
  let store = atomicMemoryPcaStore();
  return {
    name: 'BAD volatile atomic store (claims lost on restart)',
    capabilities: { durable: true, shared: true },
    open: async () => ({ store: { ...store, scope: 'shared' } as AtomicPcaStateStore }),
    restart: async () => {
      store = atomicMemoryPcaStore();
    },
  };
}

/** BAD: every handle gets its own (atomic) state while the adapter claims `shared`: instances do not see each other's claims. */
export function unsharedPcaStateAdapter(): PcaStateAdapter {
  return {
    name: 'BAD per-handle state passed off as shared',
    capabilities: { durable: false, shared: true },
    open: async () => ({ store: { ...atomicMemoryPcaStore(), scope: 'shared' } as AtomicPcaStateStore }),
  };
}

export const PCA_STATE_REFERENCE_ADAPTERS: Readonly<Record<string, (options: Record<string, string>) => PcaStateAdapter>> = {
  'in-memory': () => inMemoryPcaStateAdapter(),
  'durable-file': (o) => durableFilePcaStateAdapter({ dir: o.dir }),
  'bad-get-put': () => getPutPcaStateAdapter(),
  'bad-read-then-write-claim': () => readThenWriteClaimPcaStateAdapter(),
  'bad-local-lock': () => localLockPcaStateAdapter(),
  'bad-volatile': () => volatilePcaStateAdapter(),
  'bad-unshared': () => unsharedPcaStateAdapter(),
};

const isPcaStateAdapterLike = (x: unknown): boolean => typeof x === 'function' || (!!x && typeof x === 'object' && typeof (x as { open?: unknown }).open === 'function');

/**
 * Load a pca-state adapter: `builtin:<name>` from {@link PCA_STATE_REFERENCE_ADAPTERS}, or a module exporting
 * `createPcaStateAdapter(options)` / `pcaStateAdapter` (else the base kit's default / `adapter` / `createAdapter`).
 */
export async function loadPcaStateAdapter(spec: string, options: Record<string, string> = {}): Promise<PcaStateAdapter> {
  let exported: unknown;
  if (spec.startsWith('builtin:')) {
    const name = spec.slice('builtin:'.length);
    if (!Object.prototype.hasOwnProperty.call(PCA_STATE_REFERENCE_ADAPTERS, name)) {
      throw new Error(`unknown built-in pca-state adapter '${name}' (known: ${Object.keys(PCA_STATE_REFERENCE_ADAPTERS).join(', ')})`);
    }
    exported = PCA_STATE_REFERENCE_ADAPTERS[name];
  } else {
    const mod = (await import(pathToFileURL(resolve(spec)).href)) as Record<string, unknown>;
    exported = [mod.createPcaStateAdapter, mod.pcaStateAdapter].find(isPcaStateAdapterLike) ?? pickExport(mod);
  }
  const a = (typeof exported === 'function' ? await (exported as (o: Record<string, string>) => unknown)(options) : exported) as PcaStateAdapter | undefined;
  if (!a || typeof a.open !== 'function' || typeof a.name !== 'string') throw new TypeError(`${spec}: does not export a pca-state adapter`);
  return a;
}

