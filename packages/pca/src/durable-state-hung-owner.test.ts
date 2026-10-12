/**
 * Regression for the old age-based lock break (formal/tla DurableLock.tla: dl_hung_steal, dl_dead_only): a holder that
 * stalled (blocked fsync, SIGSTOP, a long GC) had its lock broken by age, resumed, and overwrote the newer commit, so a
 * consume-once update could be told "first" twice; concurrent breakers of a dead lock could also displace a fresh one.
 * The lock is now a set of immutable numbered generation files (formal/tla/DurableLockGen.tla): a live holder is never
 * superseded, a dead holder is superseded by exactly one breaker.
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { openDurableState } from './durable-state';

const PKG = resolve(__dirname, '..');
const WORKER = join(__dirname, 'test-support', 'durable-hung-worker.ts');
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('durable-state: a stalled lock owner is never given away or overwritten', () => {
  it('owner A stalls inside the critical section well past any age threshold; B must WAIT (not steal) and then see A\'s commit: exactly one "first"', async () => {
    const d = mkdtempSync(join(tmpdir(), 'pca-hung-'));
    dirs.push(d);
    await openDurableState({ dir: d });
    const A = spawn(process.execPath, ['--import', 'tsx', WORKER, d, '1800', '300', 'A'], { cwd: PKG });
    let out = '';
    A.stdout.on('data', (b: Buffer) => (out += b.toString()));
    const closed = new Promise<number | null>((res) => A.on('close', (c) => res(c)));
    for (let i = 0; i < 400 && !out.includes('holding'); i++) await new Promise((r) => setTimeout(r, 25));
    expect(out).toContain('holding');
    await new Promise((r) => setTimeout(r, 500)); // A's lock is now old (age no longer matters)
    const t0 = Date.now();
    const B = await openDurableState({ dir: d, lockTimeoutMs: 20_000 });
    let bFirst = false;
    await B.update('nonce', (cur) => {
      bFirst = cur === undefined;
      return cur === undefined ? 'B' : undefined;
    });
    expect(Date.now() - t0).toBeGreaterThan(900); // B waited for A's stall to end instead of breaking the lock
    await closed;
    expect(out).toContain('committed "A"'); // A, the holder, committed first...
    expect(bFirst).toBe(false); // ...and B saw it: nobody was told "first" twice
    const fin = await openDurableState({ dir: d });
    expect(await fin.get('nonce')).toBe('A');
    await fin.verify();
  }, 60_000);

  it('a waiter times out (fails closed) rather than stealing the lock of a live, stalled holder', async () => {
    const d = mkdtempSync(join(tmpdir(), 'pca-hung-'));
    dirs.push(d);
    await openDurableState({ dir: d });
    const A = spawn(process.execPath, ['--import', 'tsx', WORKER, d, '2500', '100', 'A'], { cwd: PKG });
    let out = '';
    A.stdout.on('data', (b: Buffer) => (out += b.toString()));
    const closed = new Promise<number | null>((res) => A.on('close', (c) => res(c)));
    for (let i = 0; i < 400 && !out.includes('holding'); i++) await new Promise((r) => setTimeout(r, 25));
    await expect(openDurableState({ dir: d, lockTimeoutMs: 600 })).rejects.toMatchObject({ code: 'lock-timeout' });
    await closed;
    expect(out).toContain('committed "A"');
  }, 60_000);

  it('a lock left by a DEAD process is taken over by exactly one of many concurrent breakers (generation CAS)', async () => {
    const d = mkdtempSync(join(tmpdir(), 'pca-hung-'));
    dirs.push(d);
    await openDurableState({ dir: d });
    writeFileSync(join(d, 'state.lock'), JSON.stringify({ pid: 2147483000, host: hostname(), nonce: 'dead', t: Date.now() - 100000 }));
    const handles = await Promise.all(Array.from({ length: 12 }, () => openDurableState({ dir: d, lockTimeoutMs: 20_000 })));
    const firsts = await Promise.all(
      handles.map(async (h) => {
        let first = false;
        await h.update('nonce', (cur) => {
          first = cur === undefined;
          return cur === undefined ? 1 : undefined;
        });
        return first;
      }),
    );
    expect(firsts.filter(Boolean)).toHaveLength(1);
    await handles[0]!.verify();
  }, 60_000);
});
