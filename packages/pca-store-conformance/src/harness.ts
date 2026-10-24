/**
 * Workloads that drive a store adapter and record the history: same-key bursts, a windowed concurrent run in which every
 * client contends on the same few keys at once, a retention run (many keys, then every key revisited while still live),
 * and a durability run (write, close every client, restart the backend, read back).
 */
import type { Op, OpKind } from './model';
import { MemoryRecorder, clock, type Recorder } from './recorder';
import type { StoreAdapter, StoreClient } from './types';

export interface WorkloadOptions {
  /** Concurrent clients (each `adapter.open()`), default 16. */
  clients?: number;
  /** Concurrent run length, default 2000 ms. */
  durationMs?: number;
  /** Contention window: every client targets the same `spread` keys within one window (default 5 ms, 3 keys). */
  windowMs?: number;
  spread?: number;
  /** Counter values are drawn from [0, values) so duplicates and reorderings occur (default 20). */
  values?: number;
  /** consumeOnce horizon: retainUntil = now + retentionMs (default 10 minutes, longer than any run). */
  retentionMs?: number;
  /** A call that has not settled after this long is recorded as unknown (open-ended), default 5000 ms. */
  opTimeoutMs?: number;
  /** Same-key burst rounds, default 20. */
  rounds?: number;
  /** Retention run: distinct keys written then revisited, default 500. */
  revisitKeys?: number;
  /** Key prefix. Default: random per run, so runs never collide with each other or with real data. */
  namespace?: string;
  /** PRNG seed (default random). */
  seed?: number;
}

export interface WorkloadResult {
  ops: Op[];
  /** Calls that rejected, timed out or resolved a non-boolean (recorded as unknown). */
  errors: number;
  note?: string;
}

/** Deterministic PRNG (mulberry32): `rand(n)` is an integer in [0, n). */
export function prng(seed: number): (n: number) => number {
  let a = seed >>> 0;
  return (n: number) => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n);
  };
}

export const randomNamespace = (): string => `pcasc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

/** Settle `fn()` as a definite boolean, or 'unknown' on rejection, timeout or a non-boolean answer. */
export async function settle(fn: () => Promise<unknown>, timeoutMs: number): Promise<boolean | 'unknown'> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<'unknown'>((resolve) => {
    timer = setTimeout(() => resolve('unknown'), timeoutMs);
  });
  try {
    const r = await Promise.race([Promise.resolve().then(fn), timeout]);
    return typeof r === 'boolean' ? r : 'unknown';
  } catch {
    return 'unknown';
  } finally {
    clearTimeout(timer);
  }
}

export interface OpContext {
  rec: Recorder;
  retentionMs: number;
  opTimeoutMs: number;
}

/** Record and perform one operation. For `advance`, `value` is the counter; for `consume` it is ignored. */
export async function perform(c: StoreClient, client: string, kind: OpKind, key: string, value: number, ctx: OpContext): Promise<boolean | 'unknown'> {
  const now = Date.now();
  const lo = kind === 'consume' ? now : value;
  const w = kind === 'consume' ? now + ctx.retentionMs : value;
  const op = ctx.rec.invoke(client, kind, key, lo, w);
  const r = await settle(() => (kind === 'consume' ? c.consumeOnce!(key, w, now) : c.advance!(key, value)), ctx.opTimeoutMs);
  ctx.rec.complete(op, r);
  return r;
}

export async function openClients(adapter: StoreAdapter, n: number): Promise<StoreClient[]> {
  return Promise.all(Array.from({ length: n }, () => adapter.open()));
}

export async function closeClients(clients: readonly StoreClient[]): Promise<void> {
  await Promise.all(clients.map(async (c) => c.close?.()));
}

const defaults = (o: WorkloadOptions) => ({
  clients: o.clients ?? 16,
  durationMs: o.durationMs ?? 2000,
  windowMs: o.windowMs ?? 5,
  spread: o.spread ?? 3,
  values: o.values ?? 20,
  retentionMs: o.retentionMs ?? 600_000,
  opTimeoutMs: o.opTimeoutMs ?? 5000,
  rounds: o.rounds ?? 20,
  revisitKeys: o.revisitKeys ?? 500,
  namespace: o.namespace ?? randomNamespace(),
  seed: o.seed ?? Math.floor(Math.random() * 2 ** 31),
});

const countUnknown = (ops: readonly Op[]): number => ops.filter((o) => o.res === 'unknown').length;

/**
 * The client loop of the concurrent run, shared with the multi-process crash harness: until `deadline`, pick one of the
 * `spread` keys of the current window (all clients and processes compute the same window from `origin`) and operate on it.
 */
export async function driveWindowed(
  c: StoreClient,
  client: string,
  kind: OpKind,
  ctx: OpContext,
  o: {
    namespace: string;
    windowMs: number;
    spread: number;
    values: number;
    origin: number;
    deadline: number;
    rand: (n: number) => number;
    /** The clock the deadline and the window are read from (default: the recorder's `clock`). Injectable for tests. */
    now?: () => number;
  },
): Promise<void> {
  const now = o.now ?? clock;
  while (now() < o.deadline) {
    const win = Math.floor((now() - o.origin) / o.windowMs);
    const key = `${o.namespace}:${kind}:${win}:${o.rand(o.spread)}`;
    await perform(c, client, kind, key, o.rand(o.values), ctx);
  }
}

/** `rounds` times: every client fires one operation at the SAME fresh key at once. */
export async function runBurst(adapter: StoreAdapter, kind: OpKind, opts: WorkloadOptions = {}): Promise<WorkloadResult> {
  const o = defaults(opts);
  const rand = prng(o.seed);
  const rec = new MemoryRecorder();
  const ctx = { rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs };
  const clients = await openClients(adapter, o.clients);
  try {
    for (let r = 0; r < o.rounds; r++) {
      const key = `${o.namespace}:${kind}:burst:${r}`;
      await Promise.all(clients.map((c, i) => perform(c, `c${i}`, kind, key, rand(o.values), ctx)));
    }
  } finally {
    await closeClients(clients);
  }
  return { ops: rec.ops, errors: countUnknown(rec.ops) };
}

/** Every client loops on the windowed keys for `durationMs`. */
export async function runConcurrent(adapter: StoreAdapter, kind: OpKind, opts: WorkloadOptions = {}): Promise<WorkloadResult> {
  const o = defaults(opts);
  const rec = new MemoryRecorder();
  const ctx = { rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs };
  const clients = await openClients(adapter, o.clients);
  const origin = clock();
  try {
    await Promise.all(
      clients.map((c, i) => driveWindowed(c, `c${i}`, kind, ctx, { ...o, origin, deadline: origin + o.durationMs, rand: prng(o.seed + i) })),
    );
  } finally {
    await closeClients(clients);
  }
  return { ops: rec.ops, errors: countUnknown(rec.ops) };
}

/**
 * Retention: write `revisitKeys` distinct keys (consume once / advance to 1), then revisit every one while it is still
 * live (same counter): each revisit must answer false. Catches early pruning and capacity eviction of live records.
 */
export async function runRetention(adapter: StoreAdapter, kind: OpKind, opts: WorkloadOptions = {}): Promise<WorkloadResult> {
  const o = defaults(opts);
  const rec = new MemoryRecorder();
  const ctx = { rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs };
  const clients = await openClients(adapter, o.clients);
  const keys = Array.from({ length: o.revisitKeys }, (_, i) => `${o.namespace}:${kind}:keep:${i}`);
  try {
    for (const pass of ['write', 'revisit']) {
      for (let i = 0; i < keys.length; i += clients.length) {
        await Promise.all(clients.map((c, j) => (i + j < keys.length ? perform(c, `${pass}-c${j}`, kind, keys[i + j]!, 1, ctx) : undefined)));
      }
    }
  } finally {
    await closeClients(clients);
  }
  return { ops: rec.ops, errors: countUnknown(rec.ops) };
}

/**
 * Durability: consume a key / advance a stream to 7, close the client, `restart()` the backend when the adapter can, open
 * a new client and read back: the key must stay consumed and the counter must not go backwards (7 refused, 8 accepted).
 */
export async function runDurability(adapter: StoreAdapter, kind: OpKind, opts: WorkloadOptions = {}): Promise<WorkloadResult> {
  const o = defaults(opts);
  const rec = new MemoryRecorder();
  const ctx = { rec, retentionMs: o.retentionMs, opTimeoutMs: o.opTimeoutMs };
  const key = `${o.namespace}:${kind}:durable`;
  const before = await adapter.open();
  try {
    await perform(before, 'before-restart', kind, key, 7, ctx);
  } finally {
    await before.close?.();
  }
  if (adapter.restart) await adapter.restart();
  const after = await adapter.open();
  try {
    await perform(after, 'after-restart', kind, key, 7, ctx);
    if (kind === 'advance') await perform(after, 'after-restart', kind, key, 8, ctx);
  } finally {
    await after.close?.();
  }
  return {
    ops: rec.ops,
    errors: countUnknown(rec.ops),
    note: adapter.restart ? 'backend restarted between write and read' : 'no restart() hook: clients closed and re-opened only',
  };
}
