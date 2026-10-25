/**
 * The conformance run: every test for every operation the adapter implements, each history checked for linearizability,
 * with a report (text or JSON) and a test-runner binding (`describeStoreConformance`) for vitest / jest.
 *
 * A PASS is evidence, not proof: the kit checks the histories it observed. A FAIL is a proof of a contract violation
 * (the counterexample is a recorded history that no sequential order explains), unless the adapter itself is mis-wired.
 */
import { checkHistory, formatOps, type CheckOptions, type KeyResult } from './check';
import { runCrash, type CrashOptions } from './crash';
import { runBurst, runConcurrent, runDurability, runRetention, type WorkloadOptions, type WorkloadResult } from './harness';
import type { OpKind } from './model';
import type { StoreAdapter } from './types';

export type TestName = 'burst' | 'concurrent' | 'retention' | 'durability' | 'crash';
export const ALL_TESTS: readonly TestName[] = ['burst', 'concurrent', 'retention', 'durability', 'crash'];
export type Status = 'pass' | 'fail' | 'skip' | 'unresolved';

export interface ConformanceOptions extends WorkloadOptions, CheckOptions {
  /** Which tests to run (default all). */
  tests?: readonly TestName[];
  /** The crash test runs the adapter in child processes, so it needs the adapter's MODULE path. Without it: skipped. */
  crash?: Partial<CrashOptions> & { module: string };
}

export interface TestReport {
  test: TestName;
  kind: OpKind;
  status: Status;
  ops: number;
  keys: number;
  errors: number;
  violations: KeyResult[];
  unresolved: number;
  note?: string;
}

export interface ConformanceReport {
  adapter: string;
  status: Exclude<Status, 'skip'>;
  tests: TestReport[];
}

const OP_NAME: Record<OpKind, string> = { consume: 'consumeOnce', advance: 'advance' };

/** Which operations the adapter implements: declared capabilities win, else what its first client exposes. */
export async function detectKinds(adapter: StoreAdapter): Promise<OpKind[]> {
  const caps = adapter.capabilities ?? {};
  const c = await adapter.open();
  try {
    const kinds: OpKind[] = [];
    if (caps.consumeOnce ?? typeof c.consumeOnce === 'function') kinds.push('consume');
    if (caps.advance ?? typeof c.advance === 'function') kinds.push('advance');
    return kinds;
  } finally {
    await c.close?.();
  }
}

function judge(test: TestName, kind: OpKind, w: WorkloadResult, opts: CheckOptions): TestReport {
  const h = checkHistory(w.ops, opts);
  const definite = h.outcomes.true + h.outcomes.false;
  const status: Status = h.violations.length > 0 ? 'fail' : h.unresolved.length > 0 || definite === 0 ? 'unresolved' : 'pass';
  const notes = [w.note, definite === 0 ? 'no definite answer was observed (every call failed or timed out)' : undefined].filter(Boolean);
  return {
    test,
    kind,
    status,
    ops: h.ops,
    keys: h.keys,
    errors: w.errors,
    violations: h.violations,
    unresolved: h.unresolved.length,
    ...(notes.length ? { note: notes.join('; ') } : {}),
  };
}

const skip = (test: TestName, kind: OpKind, note: string): TestReport => ({ test, kind, status: 'skip', ops: 0, keys: 0, errors: 0, violations: [], unresolved: 0, note });

export async function runTest(adapter: StoreAdapter, test: TestName, kind: OpKind, opts: ConformanceOptions = {}): Promise<TestReport> {
  if (test === 'durability' && adapter.capabilities?.durable === false) {
    return skip(test, kind, 'the adapter declares durable: false (only correct for one process whose lifetime covers the action lifetime)');
  }
  if (test === 'crash' && !opts.crash?.module) {
    return skip(test, kind, 'needs the adapter module path (the crash test runs the adapter in child processes)');
  }
  const w =
    test === 'burst'
      ? await runBurst(adapter, kind, opts)
      : test === 'concurrent'
        ? await runConcurrent(adapter, kind, opts)
        : test === 'retention'
          ? await runRetention(adapter, kind, opts)
          : test === 'durability'
            ? await runDurability(adapter, kind, opts)
            : await runCrash(kind, { ...opts, ...opts.crash! });
  return judge(test, kind, w, opts);
}

export async function runConformance(adapter: StoreAdapter, opts: ConformanceOptions = {}): Promise<ConformanceReport> {
  const kinds = await detectKinds(adapter);
  if (kinds.length === 0) throw new TypeError(`${adapter.name}: the client implements neither consumeOnce nor advance`);
  const tests: TestReport[] = [];
  for (const test of opts.tests ?? ALL_TESTS) {
    for (const kind of kinds) tests.push(await runTest(adapter, test, kind, opts));
  }
  return { adapter: adapter.name, status: overall(tests), tests };
}

export function overall(tests: readonly TestReport[]): ConformanceReport['status'] {
  if (tests.some((t) => t.status === 'fail')) return 'fail';
  if (tests.some((t) => t.status === 'unresolved')) return 'unresolved';
  return 'pass';
}

/** Human-readable report: one line per test, then each violating key's minimal counterexample (at most `maxKeys` per test). */
export function formatReport(r: ConformanceReport, maxKeys = 3): string {
  const out = [`pca-store-conformance: ${r.adapter} -> ${r.status.toUpperCase()}`];
  for (const t of r.tests) {
    const name = `${t.test}/${OP_NAME[t.kind]}`.padEnd(24);
    const stats = t.status === 'skip' ? '' : `${t.ops} ops, ${t.keys} keys, ${t.errors} errors/timeouts`;
    const extra = [t.violations.length ? `${t.violations.length} NON-LINEARIZABLE key(s)` : '', t.unresolved ? `${t.unresolved} unresolved key(s) (over the search budget)` : '', t.note ?? '']
      .filter(Boolean)
      .join('; ');
    out.push(`  [${t.status.toUpperCase()}] ${name} ${[stats, extra].filter(Boolean).join('; ')}`);
    for (const v of t.violations.slice(0, maxKeys)) {
      out.push(`      key ${v.key} (${v.ops} ops, decided by ${v.method}): ${v.minimized ? 'minimal counterexample' : 'violating history (not shrunk)'}:`);
      for (const line of formatOps(v.counterexample ?? [])) out.push(`        ${line}`);
    }
  }
  return out.join('\n');
}

/** JSON-safe form (Infinity -> null). */
export function reportJson(r: ConformanceReport): string {
  return JSON.stringify(r, (_k, v: unknown) => (v === Infinity ? null : v), 2);
}

type It = (name: string, fn: () => Promise<void>, timeout?: number) => unknown;
type Describe = (name: string, fn: () => void) => unknown;

export interface DescribeOptions extends ConformanceOptions {
  /** Pass vitest's / jest's `describe` and `it` when they are not globals. */
  runner?: { describe: Describe; it: It };
  /** Per-test timeout (default 120 s). */
  timeoutMs?: number;
}

/**
 * Register one test-runner test per conformance test. A fresh adapter per test when given a factory. Each test fails with
 * the formatted report (counterexamples included) when the store fails or the result is unresolved.
 */
export function describeStoreConformance(adapter: StoreAdapter | (() => StoreAdapter | Promise<StoreAdapter>), opts: DescribeOptions = {}): void {
  const g = globalThis as { describe?: Describe; it?: It };
  const describe = opts.runner?.describe ?? g.describe;
  const it = opts.runner?.it ?? g.it;
  if (!describe || !it) throw new Error('describeStoreConformance needs describe/it: pass { runner: { describe, it } } or enable test globals');
  const make = async (): Promise<StoreAdapter> => (typeof adapter === 'function' ? adapter() : adapter);
  describe('PCA store conformance', () => {
    for (const test of opts.tests ?? ALL_TESTS) {
      it(
        test,
        async () => {
          const a = await make();
          try {
            const r = await runConformance(a, { ...opts, tests: [test] });
            if (r.status !== 'pass') throw new Error(formatReport(r));
          } finally {
            await a.teardown?.();
          }
        },
        opts.timeoutMs ?? 120_000,
      );
    }
  });
}
