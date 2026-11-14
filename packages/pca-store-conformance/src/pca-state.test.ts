// The pca-state profile against the reference adapters. GOOD ones must pass; every BAD one must be flagged by the test that
// targets its mistake. The `processes` / process half of `crash-after-claim` fork the COMPILED worker (dist), so the package
// must be built for them; Postgres runs when PCA_SC_PG_URL is set.
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  durableFilePcaStateAdapter,
  formatPcaStateReport,
  getPutPcaStateAdapter,
  inMemoryPcaStateAdapter,
  loadPcaStateAdapter,
  localLockPcaStateAdapter,
  readThenWriteClaimPcaStateAdapter,
  runPcaStateConformance,
  volatilePcaStateAdapter,
  unsharedPcaStateAdapter,
  type PcaStateReport,
} from './pca-state';

const workerPath = join(__dirname, '..', 'dist', 'pca-state-worker.js');
const built = existsSync(workerPath);
const statuses = (r: PcaStateReport) => Object.fromEntries(r.tests.map((t) => [t.test, t.status]));
const fast = { rounds: 6, copies: 12, claim: { clients: 8, durationMs: 600, rounds: 10 } };

describe('pca-state profile: good reference adapters', () => {
  it('in-memory atomic: passes in one process; multi-instance and crash tests are skipped (declared process-local)', async () => {
    const r = await runPcaStateConformance(inMemoryPcaStateAdapter(), fast);
    expect(r.stateMode).toBe('atomic-claim');
    expect(statuses(r)).toEqual({
      'claim-burst': 'pass', 'claim-concurrent': 'pass', 'claim-durability': 'skip',
      'one-instance': 'pass', instances: 'skip', processes: 'skip', 'crash-after-claim': 'skip', 'retry-after-timeout': 'pass',
    });
    expect(r.status).toBe('pass');
    expect(r.tests.find((t) => t.test === 'one-instance')!.admitted).toEqual([1, 1, 1, 1, 1, 1]);
  }, 60_000);

  it.runIf(built)('durable file store: passes every test, including child processes and a SIGKILL after the claim', async () => {
    const a = durableFilePcaStateAdapter();
    const dir = a.name.match(/\((.*)\)$/)![1]!;
    const r = await runPcaStateConformance(a, { ...fast, module: 'builtin:durable-file', moduleOptions: { dir }, workerPath, processes: 3 });
    expect(statuses(r)).toEqual({
      'claim-burst': 'pass', 'claim-concurrent': 'pass', 'claim-durability': 'pass',
      'one-instance': 'pass', instances: 'pass', processes: 'pass', 'crash-after-claim': 'pass', 'retry-after-timeout': 'pass',
    });
    expect(r.tests.find((t) => t.test === 'processes')!.admitted).toEqual([1, 1, 1, 1, 1, 1]);
    expect(r.tests.find((t) => t.test === 'crash-after-claim')!.note).toMatch(/child process: killed after admission=true, retry in a new process admitted 0, next counter admitted 1/);
    expect(formatPcaStateReport(r)).toMatch(/-> PASS/);
  }, 120_000);
});

describe('pca-state profile: BAD adapters are flagged', () => {
  it('get/put without claim or lock: refused in multi-instance mode', async () => {
    const r = await runPcaStateConformance(getPutPcaStateAdapter(), { ...fast, tests: ['one-instance', 'instances'] });
    expect(r.stateMode).toBe('process-lock');
    expect(statuses(r)).toEqual({ 'one-instance': 'pass', instances: 'fail' });
    expect(r.tests[1]!.note).toMatch(/^refused in multi-instance mode: requirePCA: multiInstance needs a budgetStore with `claim`/);
    expect(r.status).toBe('fail');
  }, 60_000);

  it('claim as read, await, write: the same proof is admitted more than once, and the claim history is non-linearizable', async () => {
    const r = await runPcaStateConformance(readThenWriteClaimPcaStateAdapter(), { ...fast, tests: ['one-instance', 'instances', 'claim-burst'] });
    expect(statuses(r)).toEqual({ 'one-instance': 'fail', instances: 'fail', 'claim-burst': 'fail' });
    expect(r.tests[0]!.admitted!.every((n) => n > 1)).toBe(true);
    expect(r.tests[2]!.linearizability!.violations.length).toBeGreaterThan(0);
  }, 60_000);

  it('a per-handle lock passed off as shared: one instance is fine, several instances double-admit', async () => {
    const r = await runPcaStateConformance(localLockPcaStateAdapter(), { ...fast, tests: ['one-instance', 'instances'] });
    expect(r.stateMode).toBe('shared-lock');
    expect(statuses(r)).toEqual({ 'one-instance': 'pass', instances: 'fail' });
    expect(r.tests[1]!.admitted!.some((n) => n > 1)).toBe(true);
  }, 60_000);

  it('a volatile store that claims durability: the claim is forgotten across a restart', async () => {
    const r = await runPcaStateConformance(volatilePcaStateAdapter(), { ...fast, tests: ['crash-after-claim', 'claim-durability', 'retry-after-timeout'] });
    expect(statuses(r)).toEqual({ 'crash-after-claim': 'fail', 'claim-durability': 'fail', 'retry-after-timeout': 'pass' });
    expect(r.tests[0]!.note).toMatch(/same proof after restart=admitted/);
  }, 60_000);

  it.runIf(built)('state that is not really shared across processes: every process admits its own copy of each proof', async () => {
    const r = await runPcaStateConformance(localLockPcaStateAdapter(), { ...fast, tests: ['processes'], module: 'builtin:bad-local-lock', workerPath, processes: 3 });
    expect(statuses(r)).toEqual({ processes: 'fail' });
    // 3 processes x 2 instances per process, each with its own "lock" and (per process) its own map: 6 admissions per proof
    expect(r.tests[0]!.admitted).toEqual([6, 6, 6, 6, 6, 6]);
  }, 60_000);

  it.runIf(built)('get/put without claim or lock across processes: every worker refuses to start in multi-instance mode', async () => {
    const r = await runPcaStateConformance(getPutPcaStateAdapter(), { ...fast, tests: ['processes'], module: 'builtin:bad-get-put', workerPath });
    expect(statuses(r)).toEqual({ processes: 'fail' });
    expect(r.tests[0]!.note).toMatch(/3 worker\(s\) did not finish/);
  }, 60_000);
});

describe('pca-state profile: more controls', () => {
  it('per-handle state passed off as shared: the retry on another instance is admitted again, several instances double-admit', async () => {
    const r = await runPcaStateConformance(unsharedPcaStateAdapter(), { ...fast, tests: ['retry-after-timeout', 'instances'] });
    expect(statuses(r)).toEqual({ 'retry-after-timeout': 'fail', instances: 'fail' });
    expect(r.tests[0]!.note).toMatch(/^lost answer: first=error, retry=admitted, next counter=admitted; in-flight retry: 2 admitted of 2$/);
  }, 60_000);

  it.runIf(built)('a worker process that dies before racing fails the processes test even when the others admit exactly once', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pcasc-flaky-'));
    const module = join(__dirname, '..', 'test', 'fixtures', 'pca-state-flaky.mjs');
    const moduleOptions = { dir, marker: join(dir, 'died'), parent: String(process.pid) };
    const a = await loadPcaStateAdapter(module, moduleOptions);
    const r = await runPcaStateConformance(a, { ...fast, tests: ['processes'], module, moduleOptions, workerPath, processes: 3 });
    expect(existsSync(moduleOptions.marker)).toBe(true);
    expect(r.tests[0]!.admitted).toEqual([1, 1, 1, 1, 1, 1]);
    expect(r.tests[0]!.note).toMatch(/1 worker\(s\) did not finish$/);
    expect(statuses(r)).toEqual({ processes: 'fail' });
  }, 60_000);
});

describe('loadPcaStateAdapter', () => {
  it('loads built-ins by name and refuses an unknown one', async () => {
    expect((await loadPcaStateAdapter('builtin:in-memory')).name).toMatch(/in-memory atomic/);
    await expect(loadPcaStateAdapter('builtin:nope')).rejects.toThrow(/unknown built-in pca-state adapter 'nope'/);
  });
});

const PG = process.env.PCA_SC_PG_URL;
describe.runIf(!!PG && built)('Postgres reference adapter (examples/postgres-pca-state.mjs)', () => {
  it('passes every test, child processes included', async () => {
    const module = join(__dirname, '..', 'examples', 'postgres-pca-state.mjs');
    const a = await loadPcaStateAdapter(module, { url: PG! });
    try {
      const r = await runPcaStateConformance(a, { ...fast, module, moduleOptions: { url: PG! }, workerPath });
      expect(statuses(r)).toEqual({
        'claim-burst': 'pass', 'claim-concurrent': 'pass', 'claim-durability': 'pass',
        'one-instance': 'pass', instances: 'pass', processes: 'pass', 'crash-after-claim': 'pass', 'retry-after-timeout': 'pass',
      });
    } finally {
      await a.teardown?.();
    }
  }, 120_000);
});
