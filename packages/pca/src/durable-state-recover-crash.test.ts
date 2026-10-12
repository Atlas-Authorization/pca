/**
 * R6-CORE-01 follow-up: operator recovery (recoverDurableState) that ITSELF dies midway. A real recovery process is
 * SIGKILLed at every step (test-only hook PCA_DURABLE_TEST_RECOVER_CRASH_AT, NODE_ENV=test only) while the holder it was
 * releasing is PAUSED at each interesting point of its commit. For every combination:
 *   SAFETY   the paused holder's late write is never silently accepted (a late journal is refused with the fence error, a
 *            late head is repaired, a holder paused before its re-check writes nothing), and every acknowledged write
 *            after the crash survives unless the late journal made the store fail closed;
 *   LIVENESS writes resume, either by a same-namespace TAKEOVER of the dead recovery's lock (the taker cuts and fences first
 *            because the lock is marked `recovering`) or by RE-RUNNING recovery (the operator path; also the only path
 *            when the recovery died before it took the lock, since the paused holder then still holds it).
 * Model: formal/tla/DurableFence.tla (ROpCrash, TakeoverFence, Inherit; df_rcrash_*, df_live_*, df_bad_takeover_nofence).
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { openDurableState, recoverDurableState, RECOVER_CRASH_ENV } from './durable-state';

const PKG = resolve(__dirname, '..');
const PAUSED_WORKER = join(__dirname, 'test-support', 'durable-paused-worker.ts');
const RECOVER_WORKER = join(__dirname, 'test-support', 'durable-recover-worker.ts');
const CRASH_WORKER = join(__dirname, 'test-support', 'durable-worker.ts');
const FAKE_NS = 'pid:[4026530001]'; // the paused holder looks like another container: only an operator can release it

const dirs: string[] = [];
const children: ChildProcess[] = [];
afterEach(() => {
  for (const c of children.splice(0)) {
    try {
      c.kill('SIGKILL');
    } catch {
      /* gone */
    }
  }
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const mk = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-rcrash-'));
  dirs.push(d);
  return d;
};

const topLock = (d: string): { g: number; body: Record<string, unknown> } => {
  const g = Math.max(...readdirSync(d).flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : [])));
  return { g, body: JSON.parse(readFileSync(join(d, `state.lock.${g}`), 'utf8')) as Record<string, unknown> };
};
const holderOf = (b: Record<string, unknown>) => ({ host: b['host'] as string, pid: b['pid'] as number, nonce: b['nonce'] as string });
/** Every fence on disk: the `state.fence` list, then each one-fence file `state.fence.<gen>-<rand>` by generation. */
const fences = (d: string): { gen: number; seq: number; from: number }[] => {
  type F = { gen: number; seq: number; from: number };
  const list = existsSync(join(d, 'state.fence')) ? (JSON.parse(readFileSync(join(d, 'state.fence'), 'utf8')) as { fences: F[] }).fences : [];
  const files = readdirSync(d).filter((f) => /^state\.fence\.\d+-[0-9a-f]+$/.test(f)).map((f) => (JSON.parse(readFileSync(join(d, f), 'utf8')) as { fence: F }).fence);
  return [...list, ...files.sort((x, y) => x.gen - y.gen)];
};

type Mode = 'fn' | 'journal' | 'head';
function startPaused(d: string, value: string, mode: Mode) {
  const child = spawn(process.execPath, ['--import', 'tsx', PAUSED_WORKER, d, value, join(d, `go-${value}`), mode, FAKE_NS], { cwd: PKG });
  children.push(child);
  let buf = '';
  let err = '';
  child.stderr?.on('data', (b: Buffer) => (err += b.toString()));
  const paused = new Promise<void>((res, rej) => {
    child.stdout!.on('data', (b: Buffer) => {
      buf += b.toString();
      if (buf.includes('PAUSE-POINT')) res();
    });
    child.on('close', () => rej(new Error(`paused worker exited early: ${buf} ${err}`)));
  });
  const result = new Promise<string>((res) => child.on('close', () => res(/RESULT .*/.exec(buf)?.[0] ?? `no result: ${buf} ${err}`)));
  return { paused, result, go: () => writeFileSync(join(d, `go-${value}`), '') };
}

/** Run a child to completion (or to its SIGKILL). env: extra environment (the crash hook). */
function runChild(script: string, args: string[], env: Record<string, string>): Promise<{ code: number | null; signal: NodeJS.Signals | null; out: string; pid: number }> {
  return new Promise((res) => {
    const child = spawn(process.execPath, ['--import', 'tsx', script, ...args], { cwd: PKG, env: { ...process.env, ...env } });
    children.push(child);
    let out = '';
    child.stdout!.on('data', (b: Buffer) => (out += b.toString()));
    child.stderr!.on('data', (b: Buffer) => (out += b.toString()));
    child.on('close', (code, signal) => res({ code, signal, out, pid: child.pid! }));
  });
}
const crashEnv = (point: string) => ({ NODE_ENV: 'test', [RECOVER_CRASH_ENV]: point });

async function seed(d: string): Promise<void> {
  await (await openDurableState({ dir: d })).set('used-nonces', []);
}

const POINTS = ['before-lock', 'after-lock-temp', 'after-lock', 'after-fence-temp', 'after-fence', 'after-release-temp', 'after-release'] as const;
type Point = (typeof POINTS)[number];
const tookLock = (p: Point) => p !== 'before-lock' && p !== 'after-lock-temp';
const fenceLanded = (p: Point) => p === 'after-fence' || p === 'after-release-temp' || p === 'after-release';

/** The paused holder A, then a recovery process SIGKILLed at `point`; returns A's generation g. */
async function pausedHolderAndCrashedRecovery(d: string, mode: Mode, point: Point) {
  await seed(d);
  const A = startPaused(d, 'nonce-A', mode);
  await A.paused;
  const { g, body } = topLock(d);
  expect(body['ns']).toBe(FAKE_NS);
  const r = await runChild(RECOVER_WORKER, ['recover', d, JSON.stringify(holderOf(body))], crashEnv(point));
  expect(r.signal, r.out).toBe('SIGKILL');
  // the shape the crash left behind
  const top = topLock(d);
  if (!tookLock(point)) {
    expect(top.g).toBe(g); // nothing changed: the paused holder still holds the lock
  } else if (point === 'after-release') {
    expect(top).toMatchObject({ g: g + 2, body: { st: 'free', recoveredFrom: g } });
  } else {
    expect(top.g).toBe(g + 1);
    expect(top.body).toMatchObject({ st: 'held', pid: r.pid, recovering: g }); // a dead process holds the recovery lock
  }
  expect(fences(d).length).toBe(fenceLanded(point) ? 1 : 0);
  if (point === 'after-lock-temp') expect(readdirSync(d).some((f) => f.startsWith(`state.lock.tmp-${r.pid}-`))).toBe(true);
  if (point === 'after-fence-temp') expect(readdirSync(d).some((f) => /^state\.fence\.\d+-[0-9a-f]+\.tmp-/.test(f))).toBe(true);
  return { A, g };
}

/** After the store state is final: what a fresh open must see (safety), and that writes go on (liveness). */
async function checkOutcome(d: string, mode: Mode, bValue: string[]) {
  if (mode === 'journal') {
    // the late journal replaced B's: refused by a fence (never loaded), and the documented exit restores progress
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/fenced generations below/) });
    const q = await openDurableState({ dir: d, recoverFromCorruption: true });
    expect(q.recovered).toBe(true);
    await q.update('used-nonces', () => ['after']);
    expect(await (await openDurableState({ dir: d })).get('used-nonces')).toEqual(['after']);
    return;
  }
  const C = await openDurableState({ dir: d });
  expect(await C.get('used-nonces')).toEqual(bValue);
  await C.verify();
  await C.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-C']);
  expect(await (await openDurableState({ dir: d })).get('used-nonces')).toEqual([...bValue, 'nonce-C']);
  expect(topLock(d).body['st']).toBe('free');
}

describe.each(['fn', 'journal', 'head'] as const)('recovery SIGKILLed at each step, holder paused in mode %s', (mode) => {
  const expectB = mode === 'head' ? ['nonce-A', 'nonce-B'] : ['nonce-B'];

  it.each(POINTS)('%s: same-namespace TAKEOVER of the dead recovery (operator re-run only if it died before the lock)', async (point) => {
    const d = mk();
    const { A, g } = await pausedHolderAndCrashedRecovery(d, mode, point);
    if (!tookLock(point)) {
      // the paused holder (another namespace) still holds the lock: a waiter cannot judge it and must not take it
      await expect(openDurableState({ dir: d, lockTimeoutMs: 300 })).rejects.toMatchObject({ code: 'lock-timeout' });
      expect(recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(topLock(d).body) })).toMatchObject({ released: true });
    }
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    if (tookLock(point) && point !== 'after-release') {
      // B took over the dead recovery's lock (g+1) at g+2 and, because it was marked `recovering`, fenced first
      expect(fences(d).at(-1)).toMatchObject({ gen: g + 2, from: g + 1 });
    }
    expect(fences(d).every((f) => f.gen > g)).toBe(true);
    expect(await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B'])).toEqual(expectB);
    A.go();
    const ar = await A.result;
    if (mode !== 'head') expect(ar).toBe('RESULT err lock-lost');
    await checkOutcome(d, mode, expectB);
  }, 60_000);

  it.each(POINTS)('%s: operator RE-RUNS recovery', async (point) => {
    const d = mk();
    const { A, g } = await pausedHolderAndCrashedRecovery(d, mode, point);
    const top = topLock(d);
    // after-release: the crashed recovery had finished (top is free); a re-run finds nothing to release
    const r = recoverDurableState({ dir: d, force: true, expectedHolder: top.body['st'] === 'held' ? holderOf(top.body) : 'unreadable' });
    expect(r.released).toBe(top.body['st'] === 'held');
    if (r.released) expect(fences(d).at(-1)).toMatchObject({ gen: top.g + 1, from: top.g });
    expect(fences(d).length).toBeGreaterThan(0);
    expect(fences(d).every((f) => f.gen > g)).toBe(true);
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    expect(await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B'])).toEqual(expectB);
    A.go();
    const ar = await A.result;
    if (mode !== 'head') expect(ar).toBe('RESULT err lock-lost');
    await checkOutcome(d, mode, expectB);
  }, 60_000);
});

describe('the taker of a crashed recovery can itself be SIGKILLed (the `recovering` mark is carried on)', () => {
  it.each(['takeover-after-lock', 'takeover-after-fence-temp'] as const)('taker killed at %s: the next taker fences, the late journal is refused', async (tpoint) => {
    const d = mk();
    const { A, g } = await pausedHolderAndCrashedRecovery(d, 'journal', 'after-lock');
    const t = await runChild(RECOVER_WORKER, ['update', d, 'nonce-T'], crashEnv(tpoint));
    expect(t.signal, t.out).toBe('SIGKILL');
    expect(topLock(d)).toMatchObject({ g: g + 2, body: { st: 'held', pid: t.pid, recovering: g } }); // the mark is carried on
    expect(fences(d)).toHaveLength(0); // the dead taker's fence never landed
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    expect(fences(d).at(-1)).toMatchObject({ gen: g + 3, from: g + 2 });
    expect(await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B'])).toEqual(['nonce-B']);
    A.go();
    expect(await A.result).toBe('RESULT err lock-lost');
    await checkOutcome(d, 'journal', ['nonce-B']);
  }, 60_000);

  it('taker killed after its journal rename (unacknowledged), then the paused holder renames late: refused, not loaded', async () => {
    // Without the takeover fence this loaded the paused holder's stale record silently (DurableFence df_bad_takeover_nofence).
    const d = mk();
    const { A, g } = await pausedHolderAndCrashedRecovery(d, 'journal', 'after-lock');
    const t = await runChild(CRASH_WORKER, [d, 'crash', '1', '1', 'after-journal-rename'], {});
    expect(t.signal, t.out).toBe('SIGKILL');
    expect(fences(d).at(-1)).toMatchObject({ gen: g + 2, from: g + 1 });
    A.go();
    expect(await A.result).toBe('RESULT err lock-lost');
    expect(readFileSync(join(d, 'state.journal'), 'utf8')).toContain('nonce-A'); // the late rename did land on disk ...
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/fenced generations below/) }); // ... and is refused
  }, 60_000);
});

describe('the crash hook is test-only', () => {
  it('without NODE_ENV=test the hook is ignored and recovery completes', async () => {
    const d = mk();
    writeFileSync(join(d, 'state.lock.1'), JSON.stringify({ st: 'held', pid: 4_194_000, host: 'h-x', nonce: 'n-x', ns: FAKE_NS }));
    const r = await runChild(RECOVER_WORKER, ['recover', d, JSON.stringify({ host: 'h-x', pid: 4_194_000, nonce: 'n-x' })], { NODE_ENV: 'production', [RECOVER_CRASH_ENV]: 'after-lock' });
    expect(r.signal).toBe(null);
    expect(r.out).toContain('RESULT ok {"released":true');
    expect(topLock(d)).toMatchObject({ g: 3, body: { st: 'free' } });
  }, 60_000);
});
