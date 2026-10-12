/**
 * R6-CORE-01/02/03: operator recovery (recoverDurableState) against a holder that is PAUSED, not dead (SIGSTOP, `docker
 * pause`, cgroup freeze, VM suspend). Recovery must FENCE the old lock generation so that whatever the resumed holder
 * writes late is refused, by construction rather than by timing:
 *   - the holder re-checks it owns the highest generation right before the journal rename AND before the head rename;
 *   - every journal record and the head carry the writer's lock generation; recovery writes `state.fence`
 *     (records after the journal tail it saw need a generation above the fenced one), so a stale record that slips
 *     through the re-check -> rename window is refused on load, and a stale late head is recognised and repaired.
 * The first two describe blocks port the round-6 PoCs (redteam/round6/core/recover_frozen*_poc.mjs): the pause
 * is emulated by a renameSync wrapper that blocks, and the "other container" by a faked /proc/self/ns/pid in the child.
 * The 'real' block runs a real child in a real PID namespace (sudo unshare --pid) and stops it with a real SIGSTOP
 * (Linux with passwordless sudo only; skipped elsewhere).
 */
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { openDurableState, recoverDurableState } from './durable-state';

const PKG = resolve(__dirname, '..');
const WORKER = join(__dirname, 'test-support', 'durable-paused-worker.ts');
const FAKE_NS = 'pid:[4026530001]';
const dirs: string[] = [];
const mk = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-fence-'));
  dirs.push(d);
  return d;
};
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const topLock = (d: string): { g: number; body: Record<string, unknown> } => {
  const g = Math.max(...readdirSync(d).flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : [])));
  return { g, body: JSON.parse(readFileSync(join(d, `state.lock.${g}`), 'utf8')) as Record<string, unknown> };
};
/** Every fence on disk: the `state.fence` list, then each one-fence file `state.fence.<gen>-<rand>` by generation. */
const allFences = (d: string): Record<string, unknown>[] => {
  const list = existsSync(join(d, 'state.fence')) ? (JSON.parse(readFileSync(join(d, 'state.fence'), 'utf8')) as { fences: Record<string, unknown>[] }).fences : [];
  const files = readdirSync(d).filter((f) => /^state\.fence\.\d+-[0-9a-f]+$/.test(f)).sort((a, b) => Number(a.split('.')[2]!.split('-')[0]) - Number(b.split('.')[2]!.split('-')[0]));
  return [...list, ...files.map((f) => (JSON.parse(readFileSync(join(d, f), 'utf8')) as { fence: Record<string, unknown> }).fence)];
};
const holderOf = (b: Record<string, unknown>) => ({ host: b['host'] as string, pid: b['pid'] as number, nonce: b['nonce'] as string });

interface Worker {
  child: ChildProcess;
  out: () => string;
  paused: Promise<void>;
  result: Promise<string>;
}
/** prefix: a wrapper command (sudo unshare ...) or [] to run node directly. */
function startWorker(d: string, value: string, mode: 'fn' | 'journal' | 'head', opts: { fakeNs?: string; prefix?: string[] } = {}): Worker {
  const args = ['--import', 'tsx', WORKER, d, value, join(d, `go-${value}`), mode, ...(opts.fakeNs ? [opts.fakeNs] : [])];
  const prefix = opts.prefix ?? [];
  const child = prefix.length ? spawn(prefix[0]!, [...prefix.slice(1), process.execPath, ...args], { cwd: PKG }) : spawn(process.execPath, args, { cwd: PKG });
  children.push(child);
  let buf = '';
  let err = '';
  child.stderr?.on('data', (b: Buffer) => (err += b.toString()));
  const paused = new Promise<void>((res, rej) => {
    child.stdout!.on('data', (b: Buffer) => {
      buf += b.toString();
      if (buf.includes('PAUSE-POINT')) res();
    });
    child.on('close', () => rej(new Error(`worker exited before its pause point: ${buf} ${err}`)));
  });
  const result = new Promise<string>((res) => child.on('close', () => res(/RESULT .*/.exec(buf)?.[0] ?? `no result: ${buf} ${err}`)));
  return { child, out: () => buf, paused, result };
}
const go = (d: string, value: string) => writeFileSync(join(d, `go-${value}`), '');

async function seed(d: string): Promise<void> {
  const h = await openDurableState({ dir: d });
  await h.set('used-nonces', []);
}

describe('R6-CORE-01 PoC ports (emulated pause, emulated other-namespace holder)', () => {
  it('holder paused AFTER its re-check and BEFORE the journal rename: its late journal is refused on load, never silently accepted', async () => {
    const d = mk();
    await seed(d);
    const A = startWorker(d, 'nonce-A', 'journal', { fakeNs: FAKE_NS });
    await A.paused;
    const { g, body } = topLock(d);
    expect(body['ns']).toBe(FAKE_NS);
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(body) })).toMatchObject({ released: true });
    // the fence: records after the tail the operator cut at need a generation above the recovered one
    expect(allFences(d)).toMatchObject([{ gen: g + 1, seq: 1, from: g }]);
    expect(existsSync(join(d, 'state.fence'))).toBe(false); // one immutable file per fence, no shared list
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    expect(await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B'])).toEqual(['nonce-B']);
    go(d, 'nonce-A');
    // A's rename slips through (it was past its re-check); the head re-check then reports lock-lost.
    expect(await A.result).toBe('RESULT err lock-lost');
    // The store never returns A's stale value. B's overwritten commit is DETECTED (fail closed), not silently lost.
    const e = await openDurableState({ dir: d, lockTimeoutMs: 5000 }).catch((x: unknown) => x as Error & { code?: string });
    expect(e).toMatchObject({ code: 'corrupt' });
    expect((e as Error).message).toMatch(/fenced|stale/);
    // the documented exit: quarantine (files kept for forensics) and start from genesis
    const q = await openDurableState({ dir: d, recoverFromCorruption: true, lockTimeoutMs: 5000 });
    expect(q.recovered).toBe(true);
    const qj = readdirSync(d).find((f) => f.startsWith('state.journal.quarantine-'));
    expect(qj && readFileSync(join(d, qj), 'utf8')).toContain('nonce-A');
  }, 60_000);

  it('holder paused after the journal rename and BEFORE the head rename: its stale head is recognised and repaired; every commit survives', async () => {
    const d = mk();
    await seed(d);
    const A = startWorker(d, 'nonce-A', 'head', { fakeNs: FAKE_NS });
    await A.paused;
    const { body } = topLock(d);
    recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(body) });
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    for (const n of ['nonce-B1', 'nonce-B2', 'nonce-B3']) await B.update('used-nonces', (cur) => [...(cur as string[]), n]);
    go(d, 'nonce-A');
    await A.result; // A's journal record was committed BEFORE the operator's cut: it is legitimately part of the state
    const C = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    expect(await C.get('used-nonces')).toEqual(['nonce-A', 'nonce-B1', 'nonce-B2', 'nonce-B3']);
    const v = await C.verify();
    expect(v.seq).toBe(5);
    expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(5); // the open repaired the stale head
    await C.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-C']);
    expect(await (await openDurableState({ dir: d })).get('used-nonces')).toEqual(['nonce-A', 'nonce-B1', 'nonce-B2', 'nonce-B3', 'nonce-C']);
  }, 60_000);

  it('holder paused inside the critical section (before the re-check): lock-lost, nothing written, the new holder\'s state opens cleanly', async () => {
    const d = mk();
    await seed(d);
    const A = startWorker(d, 'nonce-A', 'fn', { fakeNs: FAKE_NS });
    await A.paused;
    recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(topLock(d).body) });
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B']);
    go(d, 'nonce-A');
    expect(await A.result).toBe('RESULT err lock-lost');
    const C = await openDurableState({ dir: d });
    expect(await C.get('used-nonces')).toEqual(['nonce-B']);
    await C.verify();
  }, 60_000);
});

describe('R6-CORE-01 generation in records, head and fence', () => {
  it('every record and the head carry the writer lock generation; a legacy journal without generations still opens and appends', async () => {
    const d = mk();
    const h = await openDurableState({ dir: d });
    await h.set('a', 1);
    const rec = JSON.parse(readFileSync(join(d, 'state.journal'), 'utf8').trim()) as Record<string, unknown>;
    const head = JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')) as Record<string, unknown>;
    expect(Number.isSafeInteger(rec['gen']) && (rec['gen'] as number) >= 1).toBe(true);
    expect(head['gen']).toBe(rec['gen']);
    // legacy (pre-generation) journal: same bytes the previous version wrote
    const { createHash } = await import('node:crypto');
    const G0 = '0'.repeat(64);
    const lh = createHash('sha256').update('pca-durable-state/v1\n' + JSON.stringify([1, G0, 'set', 'k\n"legacy"', 5])).digest('hex');
    const e = mk();
    writeFileSync(join(e, 'state.journal'), JSON.stringify({ seq: 1, prev: G0, op: 'set', payload: 'k\n"legacy"', ts: 5, h: lh }) + '\n');
    writeFileSync(join(e, 'state.head'), JSON.stringify({ seq: 1, h: lh }) + '\n');
    const s = await openDurableState({ dir: e });
    expect(await s.get('k')).toBe('legacy');
    await s.set('k', 'new');
    expect(await (await openDurableState({ dir: e })).get('k')).toBe('new');
  });

  it('a record whose generation is LOWER than an earlier record\'s is refused (stale writer), with a clear corrupt error', async () => {
    const d = mk();
    const h = await openDurableState({ dir: d });
    await h.set('a', 1);
    await h.set('b', 2);
    const lines = readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    // re-forge record 2 with a lower generation but a valid hash/chain (the generation is covered by the hash)
    const { createHash } = await import('node:crypto');
    const r2: Record<string, unknown> = { ...lines[1]!, gen: (lines[0]!['gen'] as number) - 1 };
    expect(r2['gen'] as number).toBeGreaterThanOrEqual(1); // open took generation 1, so the first set holds >= 3
    r2['h'] = createHash('sha256').update('pca-durable-state/v1\n' + JSON.stringify([r2['seq'], r2['prev'], r2['op'], r2['payload'], r2['ts'], r2['gen']])).digest('hex');
    writeFileSync(join(d, 'state.journal'), [lines[0], r2].map((x) => JSON.stringify(x)).join('\n') + '\n');
    writeFileSync(join(d, 'state.head'), JSON.stringify({ seq: 1, h: lines[0]!['h'], gen: lines[0]!['gen'] }) + '\n');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/older than generation .* of an earlier record/) });
  });

  it('recovery writes the fence BEFORE releasing; records after the cut from a fenced generation are refused', async () => {
    const d = mk();
    const h = await openDurableState({ dir: d });
    await h.set('a', 1); // seq 1
    // a dead holder in another namespace at the next generation
    const g = topLock(d).g + 1;
    writeFileSync(join(d, `state.lock.${g}`), JSON.stringify({ st: 'held', pid: 4_194_000, host: hostname(), nonce: 'n-x', ns: FAKE_NS }));
    recoverDurableState({ dir: d, force: true, expectedHolder: { host: hostname(), pid: 4_194_000, nonce: 'n-x' } });
    expect(allFences(d)).toMatchObject([{ gen: g + 1, seq: 1, from: g }]);
    // the new holder writes with a generation above the fence: accepted
    const s = await openDurableState({ dir: d });
    await s.set('b', 2);
    expect(await s.get('b')).toBe(2);
    // a second recovery adds a second fence (its own file: no fence can be lost by a concurrent or late writer)
    const g2 = topLock(d).g + 1;
    writeFileSync(join(d, `state.lock.${g2}`), JSON.stringify({ st: 'held', pid: 4_194_001, host: hostname(), nonce: 'n-y', ns: FAKE_NS }));
    recoverDurableState({ dir: d, force: true, expectedHolder: { host: hostname(), pid: 4_194_001, nonce: 'n-y' } });
    expect(allFences(d)).toHaveLength(2);
    expect(readdirSync(d).filter((f) => /^state\.fence\.\d+-[0-9a-f]+$/.test(f))).toHaveLength(2);
    // a corrupt fence (one-fence file or the legacy list) fails closed
    const one = readdirSync(d).find((f) => /^state\.fence\.\d+-/.test(f))!;
    const keep = readFileSync(join(d, one), 'utf8');
    writeFileSync(join(d, one), '{nope');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/state\.fence\.\d+-[0-9a-f]+ is not valid JSON/) });
    writeFileSync(join(d, one), keep.replace(/"gen":\d+/, '"gen":99'));
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/names generation \d+ but holds 99/) });
    writeFileSync(join(d, one), keep);
    writeFileSync(join(d, 'state.fence'), '{nope');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/state\.fence/) });
  });
});

// ---- R6-CORE-02: liveness is judged by PID-namespace identity, not by hostname ----
const linux = existsSync('/proc/self/ns/pid');
describe('R6-CORE-02 recovery liveness check keys on the PID namespace', () => {
  it.skipIf(!linux)('a holder alive in THIS pid namespace is never released, even when its recorded hostname differs', () => {
    const d = mk();
    const ns = readlinkSync('/proc/self/ns/pid');
    writeFileSync(join(d, 'state.lock.1'), JSON.stringify({ st: 'held', pid: process.pid, host: 'renamed-host', nonce: 'n-live', ns }));
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: { host: 'renamed-host', pid: process.pid, nonce: 'n-live' } })).toThrow(/alive in this PID namespace/);
    expect(readdirSync(d)).toEqual(['state.lock.1']);
  });
  it.skipIf(!linux)('a DEAD holder in this pid namespace under another hostname is still released', () => {
    const d = mk();
    const ns = readlinkSync('/proc/self/ns/pid');
    writeFileSync(join(d, 'state.lock.1'), JSON.stringify({ st: 'held', pid: 4_194_000, host: 'renamed-host', nonce: 'n-dead', ns }));
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: { host: 'renamed-host', pid: 4_194_000, nonce: 'n-dead' } }).released).toBe(true);
  });
});

// ---- R6-CORE-03: every wedged shape has an explicit, operator-confirmed recovery path ----
describe('R6-CORE-03 recovery for a legacy single-file lock and for incomplete holder records', () => {
  const DEAD = 4_194_000;
  it('legacy single-file state.lock with a dead holder in another namespace: named in lock-timeout, released only with legacyLock: true', async () => {
    const d = mk();
    writeFileSync(join(d, 'state.lock'), JSON.stringify({ pid: DEAD, host: hostname(), nonce: 'n-legacy', ns: FAKE_NS }));
    const e = (await openDurableState({ dir: d, lockTimeoutMs: 100 }).catch((x: unknown) => x)) as Error;
    expect(e).toMatchObject({ code: 'lock-timeout' });
    expect(e.message).toContain(`${join(d, 'state.lock')} (legacy single-file lock`);
    expect(e.message).toContain('legacyLock: true');
    const exp = { host: hostname(), pid: DEAD, nonce: 'n-legacy' };
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp })).toThrow(/legacy single-file .*legacyLock: true/);
    expect(existsSync(join(d, 'state.lock'))).toBe(true);
    expect(() => recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: { ...exp, nonce: 'other' } })).toThrow(/does not match/);
    expect(recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: exp })).toEqual({ released: true, reason: 'released', lockFile: join(d, 'state.lock') });
    expect(existsSync(join(d, 'state.lock'))).toBe(false);
    expect(readdirSync(d).some((f) => f.startsWith('state.lock.legacy-recovered-'))).toBe(true);
    const s = await openDurableState({ dir: d, lockTimeoutMs: 1000 });
    await s.set('k', 1);
    expect(await s.get('k')).toBe(1);
  });
  it('legacy lock with an incomplete record: released only with legacyLock and expectedHolder "unreadable"', async () => {
    const d = mk();
    writeFileSync(join(d, 'state.lock'), JSON.stringify({ pid: DEAD, ns: FAKE_NS }));
    await expect(openDurableState({ dir: d, lockTimeoutMs: 100 })).rejects.toMatchObject({ code: 'lock-timeout' });
    expect(() => recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: { host: hostname(), pid: DEAD, nonce: 'x' } })).toThrow(/incomplete holder record.*'unreadable'/);
    expect(recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: 'unreadable' }).released).toBe(true);
    await expect(openDurableState({ dir: d, lockTimeoutMs: 1000 })).resolves.toBeDefined();
  });
  it('legacyLock: true is refused when the blocker is a generation lock, and is a no-op without a legacy file', () => {
    const d = mk();
    expect(recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: 'unreadable' })).toEqual({ released: false, reason: 'not-held' });
    writeFileSync(join(d, 'state.lock.1'), JSON.stringify({ st: 'held', pid: DEAD, host: 'h', nonce: 'n', ns: FAKE_NS }));
    expect(() => recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: { host: 'h', pid: DEAD, nonce: 'n' } })).toThrow(/legacyLock/);
  });
  it.each([
    ['{}', '{}'],
    ['[]', '[]'],
    ['st only', '{"st":"held"}'],
    ['string pid', JSON.stringify({ st: 'held', pid: String(DEAD), host: hostname(), nonce: 'n', ns: FAKE_NS })],
    ['no nonce', JSON.stringify({ st: 'held', pid: DEAD, host: hostname(), ns: FAKE_NS })],
    ['empty nonce', JSON.stringify({ st: 'held', pid: DEAD, host: hostname(), nonce: '', ns: FAKE_NS })],
    ['no host', JSON.stringify({ st: 'held', pid: DEAD, nonce: 'n', ns: FAKE_NS })],
  ])('incomplete top record (%s): lock-timeout says so; released only with expectedHolder "unreadable"', async (_n, raw) => {
    const d = mk();
    writeFileSync(join(d, 'state.lock.1'), raw);
    const e = (await openDurableState({ dir: d, lockTimeoutMs: 100 }).catch((x: unknown) => x)) as Error;
    expect(e).toMatchObject({ code: 'lock-timeout' });
    expect(e.message).toContain('incomplete holder record');
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: { host: hostname(), pid: DEAD, nonce: 'n' } })).toThrow(/incomplete holder record.*expectedHolder: 'unreadable'/);
    expect(readdirSync(d)).toEqual(['state.lock.1']);
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: 'unreadable' })).toMatchObject({ released: true, lockFile: join(d, 'state.lock.1') });
    const s = await openDurableState({ dir: d, lockTimeoutMs: 1000 });
    await s.set('k', 'v');
    expect(await s.get('k')).toBe('v');
  });
});

// ---- real paused holders: real PID namespace (sudo unshare --pid), real SIGSTOP/SIGCONT. Linux + passwordless sudo only. ----
const canNs =
  process.platform === 'linux' &&
  spawnSync('sudo', ['-n', 'unshare', '--pid', '--fork', '--mount-proc', 'true']).status === 0 &&
  spawnSync('sudo', ['-n', 'unshare', '--uts', 'true']).status === 0 &&
  spawnSync('setpriv', ['--version']).status === 0;
const uid = process.getuid?.() ?? 0;
const gid = process.getgid?.() ?? 0;
const dropPriv = ['setpriv', `--reuid=${uid}`, `--regid=${gid}`, '--clear-groups', 'env', `PATH=${process.env['PATH'] ?? ''}`, `HOME=${process.env['HOME'] ?? '/tmp'}`];
const IN_PID_NS = ['sudo', '-n', 'unshare', '--pid', '--fork', '--mount-proc', ...dropPriv];
const RENAMED_HOST = 'pca-renamed-host';
const IN_UTS_NS = ['sudo', '-n', 'unshare', '--uts', 'sh', '-c', `hostname ${RENAMED_HOST} && exec "$0" "$@"`, ...dropPriv];

/** The worker's pid as seen from HERE (the outer namespace): the node process (our uid) whose argv carries the go-file. */
async function outerPid(goFile: string): Promise<number> {
  for (let i = 0; i < 200; i++) {
    for (const p of readdirSync('/proc')) {
      if (!/^\d+$/.test(p)) continue;
      try {
        const argv = readFileSync(`/proc/${p}/cmdline`, 'utf8').split('\0');
        const st = readFileSync(`/proc/${p}/status`, 'utf8');
        if (argv[0] === process.execPath && argv.includes(goFile) && new RegExp(`^Uid:\\s+${uid}\\s`, 'm').test(st)) return Number(p);
      } catch {
        /* raced */
      }
    }
    await sleep(25);
  }
  throw new Error('worker pid not found');
}
const procState = (pid: number) => readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1]![0];

describe.skipIf(!canNs)('real paused holder in another PID namespace (sudo unshare --pid, SIGSTOP/SIGCONT)', () => {
  async function pausedHolder(mode: 'fn' | 'journal' | 'head') {
    const d = mk();
    await seed(d);
    const A = startWorker(d, 'nonce-A', mode, { prefix: IN_PID_NS });
    await A.paused;
    const pid = await outerPid(join(d, 'go-nonce-A'));
    process.kill(pid, 'SIGSTOP');
    for (let i = 0; i < 100 && procState(pid) !== 'T'; i++) await sleep(10);
    expect(procState(pid)).toBe('T'); // really stopped
    const { body } = topLock(d);
    expect(body['ns']).not.toBe(readlinkSync('/proc/self/ns/pid')); // really another PID namespace
    // the operator sees a stopped container in another namespace and releases its lock
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(body) })).toMatchObject({ released: true });
    return { d, A, pid };
  }
  const resume = (d: string, pid: number) => {
    go(d, 'nonce-A');
    process.kill(pid, 'SIGCONT');
  };

  it('stopped inside the critical section: the resumed holder gets lock-lost and writes nothing; the new holder\'s state opens cleanly', async () => {
    const { d, A, pid } = await pausedHolder('fn');
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    expect(await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B'])).toEqual(['nonce-B']);
    resume(d, pid);
    expect(await A.result).toBe('RESULT err lock-lost');
    const C = await openDurableState({ dir: d });
    expect(await C.get('used-nonces')).toEqual(['nonce-B']);
    expect((await C.verify()).seq).toBe(2);
  }, 60_000);

  it('stopped between its journal rename and its head rename: the late stale head is repaired, nothing is lost', async () => {
    const { d, A, pid } = await pausedHolder('head');
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    for (const n of ['nonce-B1', 'nonce-B2', 'nonce-B3']) await B.update('used-nonces', (cur) => [...(cur as string[]), n]);
    resume(d, pid);
    await A.result;
    const C = await openDurableState({ dir: d });
    expect(await C.get('used-nonces')).toEqual(['nonce-A', 'nonce-B1', 'nonce-B2', 'nonce-B3']);
    await C.verify();
  }, 60_000);

  it('stopped after its re-check, before the journal rename (the residual window): the late journal is refused on load (fail closed)', async () => {
    const { d, A, pid } = await pausedHolder('journal');
    const B = await openDurableState({ dir: d, lockTimeoutMs: 5000 });
    await B.update('used-nonces', (cur) => [...(cur as string[]), 'nonce-B']);
    resume(d, pid);
    expect(await A.result).toBe('RESULT err lock-lost');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/fenced/) });
  }, 60_000);

  it('R6-CORE-02: a LIVE holder in this PID namespace under another hostname (real UTS namespace) is not released', async () => {
    const d = mk();
    await seed(d);
    const A = startWorker(d, 'nonce-A', 'fn', { prefix: IN_UTS_NS });
    await A.paused;
    const { body } = topLock(d);
    expect(body['host']).toBe(RENAMED_HOST);
    expect(body['ns']).toBe(readlinkSync('/proc/self/ns/pid'));
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: holderOf(body) })).toThrow(/alive in this PID namespace/);
    go(d, 'nonce-A');
    expect(await A.result).toBe('RESULT ok ["nonce-A"]');
    expect(await (await openDurableState({ dir: d })).get('used-nonces')).toEqual(['nonce-A']);
  }, 60_000);
});

// ---- the cut is pinned, recovery takes the lock first, quarantine re-fences (formal/tla DurableFence: df_bad_no_pin,
// df_bad_naive_order) ----
describe('R6-CORE-01 the operator cut', () => {
  const G0 = '0'.repeat(64);
  const recOf = (seq: number, prev: string, payload: string, gen: number) => {
    const h = createHash('sha256').update('pca-durable-state/v1\n' + JSON.stringify([seq, prev, 'set', payload, 1, gen])).digest('hex');
    return { seq, prev, op: 'set', payload, ts: 1, gen, h };
  };
  const journal = (d: string) => readFileSync(join(d, 'state.journal'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { seq: number; h: string; gen: number });
  async function recoveredStore() {
    const d = mk();
    const h = await openDurableState({ dir: d });
    await h.set('a', 1);
    await h.set('b', 2);
    const g = topLock(d).g + 1;
    writeFileSync(join(d, `state.lock.${g}`), JSON.stringify({ st: 'held', pid: 4_194_000, host: hostname(), nonce: 'n-x', ns: FAKE_NS }));
    recoverDurableState({ dir: d, force: true, expectedHolder: { host: hostname(), pid: 4_194_000, nonce: 'n-x' } });
    return { d, g, recs: journal(d) };
  }

  it('recovery takes generation g+1 itself, fences the exact tail (seq and record hash), then frees g+2', async () => {
    const { d, g, recs } = await recoveredStore();
    expect(JSON.parse(readFileSync(join(d, `state.lock.${g + 1}`), 'utf8'))).toMatchObject({ st: 'held', pid: process.pid, recovering: g });
    expect(JSON.parse(readFileSync(join(d, `state.lock.${g + 2}`), 'utf8'))).toMatchObject({ st: 'free', recoveredFrom: g });
    expect(topLock(d).g).toBe(g + 2);
    expect(allFences(d)).toEqual([expect.objectContaining({ gen: g + 1, seq: 2, h: recs[1]!.h, from: g })]);
    const s = await openDurableState({ dir: d });
    await s.set('c', 3);
    expect(await s.get('c')).toBe(3);
  });

  it('a journal that no longer reaches the cut is a rollback', async () => {
    const { d, recs } = await recoveredStore();
    writeFileSync(join(d, 'state.journal'), JSON.stringify(recs[0]) + '\n');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'rollback', message: expect.stringMatching(/operator recovery cut it at seq 2/) });
  });

  it('a different record AT the cut (even from a generation above the fence) is refused', async () => {
    const { d, g, recs } = await recoveredStore();
    const other = recOf(2, recs[0]!.h, 'b\n99', g + 5);
    writeFileSync(join(d, 'state.journal'), [recs[0], other].map((r) => JSON.stringify(r)).join('\n') + '\n');
    writeFileSync(join(d, 'state.head'), JSON.stringify({ seq: 2, h: other.h, gen: g + 5 }) + '\n');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/not the record operator recovery cut at/) });
  });

  it('a missing journal after a cut is a rollback; a fence entry without a hash is corrupt', async () => {
    const { d } = await recoveredStore();
    rmSync(join(d, 'state.journal'));
    rmSync(join(d, 'state.head'));
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'rollback', message: expect.stringMatching(/missing but operator recovery cut it at seq 2/) });
    writeFileSync(join(d, 'state.fence'), JSON.stringify({ v: 1, fences: [{ gen: 3, seq: 0 }] }));
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt', message: expect.stringMatching(/state\.fence has an invalid entry/) });
  });

  it('quarantine (recoverFromCorruption) re-fences from genesis: every older generation stays refused, the old fence is kept', async () => {
    const { d } = await recoveredStore();
    writeFileSync(join(d, 'state.journal'), 'garbage\n');
    const s = await openDurableState({ dir: d, recoverFromCorruption: true });
    expect(s.recovered).toBe(true);
    const f = JSON.parse(readFileSync(join(d, 'state.fence'), 'utf8')) as { fences: { gen: number; seq: number; h: string }[] };
    expect(f.fences).toHaveLength(1);
    expect(f.fences[0]).toMatchObject({ seq: 0, h: G0 });
    expect(readdirSync(d).some((x) => /^state\.fence\.\d+-[0-9a-f]+\.quarantine-/.test(x))).toBe(true); // the old fence kept aside
    expect(allFences(d)).toHaveLength(1);
    await s.set('k', 1);
    expect(journal(d)[0]!.gen).toBeGreaterThanOrEqual(f.fences[0]!.gen);
    // a late record from an older generation on top of the fresh journal is refused
    const late = recOf(2, journal(d)[0]!.h, 'k\n2', f.fences[0]!.gen - 1);
    writeFileSync(join(d, 'state.journal'), [journal(d)[0], late].map((r) => JSON.stringify(r)).join('\n') + '\n');
    await expect(openDurableState({ dir: d })).rejects.toMatchObject({ code: 'corrupt' });
  });
});
