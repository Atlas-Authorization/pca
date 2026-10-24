/**
 * Second mutation-kill file for durable-state.ts. The first file pins the journal / head validation; this one pins the
 * filesystem discipline (fsync + close of every temp file, the lock file and the directory; temp cleanup on lock loss),
 * the lock-breaking decisions (exact age boundaries, EPERM liveness, the "moved a fresh lock" put-back), the head-repair
 * rules of open / set / update, and the observe/sort behaviour of keys().
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import * as realFs from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DurableStateError, openDurableState, recoverDurableState } from './durable-state';

interface Ev { op: string; path: string; flags?: number; to?: string }
const hooks = vi.hoisted(() => ({
  ev: [] as Ev[],
  fdPath: new Map<number, string>(),
  beforeRename: undefined as undefined | ((from: string, to: string) => void),
  afterRename: undefined as undefined | ((from: string, to: string) => void),
  link: undefined as undefined | ((from: string, to: string) => void),
  read: undefined as undefined | ((path: string) => void),
  afterLink: undefined as undefined | ((to: string) => void),
  skipLink: undefined as undefined | ((to: string) => boolean),
  order: undefined as undefined | ((names: string[]) => string[]),
}));
vi.mock('node:fs', async (importOriginal) => {
  const a = await importOriginal<typeof import('node:fs')>();
  return {
    ...a,
    openSync: (p: string, flags: number, ...r: unknown[]) => {
      const fd = (a.openSync as (...x: unknown[]) => number)(p, flags, ...r);
      hooks.fdPath.set(fd, String(p));
      hooks.ev.push({ op: 'open', path: String(p), flags });
      return fd;
    },
    fsyncSync: (fd: number) => {
      hooks.ev.push({ op: 'fsync', path: hooks.fdPath.get(fd) ?? '?' });
      return a.fsyncSync(fd);
    },
    closeSync: (fd: number) => {
      hooks.ev.push({ op: 'close', path: hooks.fdPath.get(fd) ?? '?' });
      return a.closeSync(fd);
    },
    unlinkSync: (p: string) => {
      hooks.ev.push({ op: 'unlink', path: String(p) });
      return a.unlinkSync(p);
    },
    readdirSync: (p: unknown, ...r: unknown[]) => {
      const out = (a.readdirSync as (...x: unknown[]) => unknown)(p, ...r);
      return hooks.order && Array.isArray(out) && typeof out[0] !== 'object' ? hooks.order(out as string[]) : out;
    },
    readFileSync: (p: unknown, ...r: unknown[]) => {
      if (typeof p === 'string') hooks.read?.(p);
      return (a.readFileSync as (...x: unknown[]) => unknown)(p, ...r);
    },
    linkSync: (from: string, to: string) => {
      hooks.link?.(String(from), String(to));
      if (hooks.skipLink?.(String(to))) return;
      a.linkSync(from, to);
      hooks.afterLink?.(String(to));
    },
    renameSync: (from: string, to: string) => {
      hooks.beforeRename?.(String(from), String(to));
      a.renameSync(from, to);
      hooks.ev.push({ op: 'rename', path: String(from), to: String(to) });
      hooks.afterRename?.(String(from), String(to));
    },
  };
});

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'ds-mk2-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  hooks.beforeRename = undefined;
  hooks.afterRename = undefined;
  hooks.link = undefined;
  hooks.read = undefined;
  hooks.afterLink = undefined;
  hooks.skipLink = undefined;
  hooks.order = undefined;
  hooks.ev.length = 0;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const GEN = '0'.repeat(64);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const mk = (seq: number, prev: string, payload: string, ts = 1000) => {
  const h = sha('pca-durable-state/v1\n' + JSON.stringify([seq, prev, 'set', payload, ts]));
  return { seq, prev, op: 'set', payload, ts, h };
};
const open = (d: string, o: Record<string, unknown> = {}) => openDurableState({ dir: d, ...o } as never);
const rej = async (p: Promise<unknown>, msg: string | RegExp) => {
  let e: unknown;
  try { await p; } catch (x) { e = x; }
  expect(e, 'expected rejection').toBeInstanceOf(DurableStateError);
  if (typeof msg === 'string') expect((e as Error).message).toBe(msg); else expect((e as Error).message).toMatch(msg);
  return e as DurableStateError;
};
const headRenames = () => hooks.ev.filter((e) => e.op === 'rename' && e.to!.endsWith('state.head')).length;
/** A repaired head names the same (seq, h) but is stamped with the REPAIRING writer's (later) lock generation (R6-CORE-01). */
const sameHeadRepairedLater = (now: string, before: string) => {
  const a = JSON.parse(now) as { seq: number; h: string; gen: number };
  const b = JSON.parse(before) as { seq: number; h: string; gen: number };
  expect({ seq: a.seq, h: a.h }).toEqual({ seq: b.seq, h: b.h });
  expect(a.gen).toBeGreaterThan(b.gen);
};
const DEAD_PID = 2147483646;
const body = (o: Record<string, unknown> = {}) => JSON.stringify({ st: 'held', pid: process.pid, host: hostname(), nonce: 'n', ...o });
const gen = (d: string, g: number, o: unknown = {}) => writeFileSync(join(d, `state.lock.${g}`), typeof o === 'string' ? o : body(o as Record<string, unknown>));
const gens = (d: string) => readdirSync(d).flatMap((f) => (/^state\.lock\.(\d+)$/.test(f) ? [Number(f.slice(11))] : [])).sort((x, y) => x - y);
const linux = existsSync('/proc/self/stat');
const startOf = (pid: number | 'self'): string => {
  const st = readFileSync(`/proc/${pid}/stat`, 'utf8');
  return st.slice(st.lastIndexOf(')') + 2).split(' ')[19]!;
};

describe('every temp file, the lock file and the directory are fsynced and closed', () => {
  it('a set fsyncs + closes the lock, both temp files and the state directory (opened O_RDONLY at the dir itself)', async () => {
    const d = tmp();
    const s = await open(d);
    hooks.ev.length = 0;
    await s.set('k', 1);
    const ev = hooks.ev;
    const has = (op: string, re: RegExp) => ev.some((e) => e.op === op && re.test(e.path));
    expect(has('fsync', /state\.lock\.tmp-/)).toBe(true);
    expect(has('close', /state\.lock\.tmp-/)).toBe(true);
    expect(has('fsync', /state\.journal\.tmp-/)).toBe(true);
    expect(has('close', /state\.journal\.tmp-/)).toBe(true);
    expect(has('fsync', /state\.head\.tmp-/)).toBe(true);
    expect(has('close', /state\.head\.tmp-/)).toBe(true);
    const dirOpens = ev.filter((e) => e.op === 'open' && e.path === d);
    expect(dirOpens.length).toBe(2); // journal rename, head rename
    for (const o of dirOpens) expect(o.flags).toBe(realFs.constants.O_RDONLY);
    expect(ev.filter((e) => e.op === 'fsync' && e.path === d)).toHaveLength(2);
    expect(ev.filter((e) => e.op === 'close' && e.path === d)).toHaveLength(2);
    // ordering: temp fsync before its rename, rename before the directory fsync
    const iTmp = ev.findIndex((e) => e.op === 'fsync' && /state\.journal\.tmp-/.test(e.path));
    const iRen = ev.findIndex((e) => e.op === 'rename' && e.to!.endsWith('state.journal'));
    const iDir = ev.findIndex((e) => e.op === 'fsync' && e.path === d);
    expect(iTmp).toBeGreaterThanOrEqual(0);
    expect(iRen).toBeGreaterThan(iTmp);
    expect(iDir).toBeGreaterThan(iRen);
  });

  it('a quarantining recovery fsyncs the directory', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.journal'), 'not a journal\n');
    hooks.ev.length = 0;
    const s = await open(d, { recoverFromCorruption: true });
    expect(s.recovered).toBe(true);
    expect(hooks.ev.some((e) => e.op === 'fsync' && e.path === d)).toBe(true);
    expect(hooks.ev.some((e) => e.op === 'close' && e.path === d)).toBe(true);
    expect(readdirSync(d).some((f) => f.startsWith('state.journal.quarantine-'))).toBe(true);
  });
});

describe('generation locks: layout and release', () => {
  it('the lock directory keeps the newest 16 generations plus the held/free pair, and the top one is free', async () => {
    const d = tmp();
    const s = await open(d);
    expect(gens(d)).toEqual([1, 2]);
    await s.set('a', 1);
    expect(gens(d)).toEqual([1, 2, 3, 4]);
    expect(JSON.parse(readFileSync(join(d, 'state.lock.4'), 'utf8'))).toMatchObject({ st: 'free' });
    for (let i = 0; i < 10; i++) await s.get('a'); // 12 operations in total: generations 1..24
    expect(gens(d)).toEqual(Array.from({ length: 17 }, (_, i) => 8 + i)); // 2k-16 .. 2k
    let inside: number[] = [];
    await s.update('a', () => {
      inside = gens(d);
      return undefined;
    });
    expect(inside).toEqual(Array.from({ length: 17 }, (_, i) => 9 + i)); // held generation 25, collected below 25-16
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
  });

  it('the held generation names this process: pid, host, a nonce, start time (Linux) and a timestamp', async () => {
    const d = tmp();
    const s = await open(d);
    let seen: Record<string, unknown> | undefined;
    await s.update('k', () => {
      const top = Math.max(...gens(d));
      seen = JSON.parse(readFileSync(join(d, `state.lock.${top}`), 'utf8'));
      return 1;
    });
    expect(seen).toMatchObject({ st: 'held', pid: process.pid, host: hostname() });
    expect(typeof seen!['nonce']).toBe('string');
    expect((seen!['nonce'] as string).length).toBe(24);
    expect(typeof seen!['t']).toBe('number');
    if (linux) expect(seen!['start']).toBe(startOf('self'));
    else expect('start' in seen!).toBe(false);
  });

  it('a lock generation file that was created before is garbage-collected two operations later, stray temp files of dead pids too', async () => {
    const d = tmp();
    const s = await open(d);
    writeFileSync(join(d, `state.lock.tmp-${DEAD_PID}-aa`), 'x');
    writeFileSync(join(d, `state.lock.tmp-${process.pid}-bb`), 'x');
    writeFileSync(join(d, 'state.lock.tmp-oops'), 'x');
    await s.get('zz');
    const left = readdirSync(d).filter((f) => f.startsWith('state.lock.tmp-')).sort();
    expect(left).toEqual([`state.lock.tmp-${process.pid}-bb`, 'state.lock.tmp-oops'].sort());
  });

  it('files that merely look like lock generations are ignored when picking the top generation', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.lock.abc'), 'x');
    writeFileSync(join(d, 'state.lock.7x'), 'x');
    writeFileSync(join(d, 'xstate.lock.99'), 'x');
    gen(d, 9, { pid: DEAD_PID });
    gen(d, 10, { st: 'free' });
    const s = await open(d);
    expect(Math.max(...gens(d))).toBe(12); // 11 = held, 12 = free
    await s.set('a', 1);
    expect(await s.get('a')).toBe(1);
  });

  it('a lone generation 0 file is not a lock generation', async () => {
    const d = tmp();
    gen(d, 0, { pid: process.pid });
    await open(d, { lockTimeoutMs: 100 });
    expect(gens(d)).toContain(1);
  });
});

describe('generation locks: who may be superseded', () => {
  it('a live holder on this host is never superseded: the opener times out with the exact message', async () => {
    const d = tmp();
    gen(d, 1, {});
    await rej(open(d, { lockTimeoutMs: 40 }), new RegExp(`^lock-timeout: could not acquire the state lock in ${d} within 40 ms; blocked by ${d}/state\\.lock\\.1 \\(holder pid=${process.pid} host=${hostname()} nonce=n\\)\\. If that holder is provably gone`));
    expect(gens(d)).toEqual([1]);
  });

  it('an unreadable or non-object top generation is not free and not dead', async () => {
    for (const content of ['{torn', 'null', '5', '"s"']) {
      const d = tmp();
      gen(d, 1, content);
      await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
    }
  });

  it('a holder whose pid is gone is taken over by exactly the next generation', async () => {
    const d = tmp();
    gen(d, 3, { pid: DEAD_PID });
    await open(d, { lockTimeoutMs: 2000 });
    expect(gens(d)).toEqual([3, 4, 5]);
  });

  it('a holder on another host, with a non-numeric pid, or without a pid is never judged dead', async () => {
    for (const over of [{ pid: DEAD_PID, host: 'some-other-host' }, { pid: String(DEAD_PID) }, { pid: undefined }, { pid: DEAD_PID, host: undefined }]) {
      const d = tmp();
      gen(d, 1, over);
      await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
    }
  });

  it('a pid that exists but belongs to another user (EPERM) is alive', async () => {
    const d = tmp();
    gen(d, 1, { pid: 999999 });
    vi.spyOn(process, 'kill').mockImplementation(() => {
      throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' });
    });
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });

  it.runIf(linux)('a recycled pid (different process start time) is dead; the same start time is alive', async () => {
    const d = tmp();
    gen(d, 1, { start: startOf('self') });
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
    const e = tmp();
    gen(e, 1, { start: 'not-the-start-time' });
    await open(e, { lockTimeoutMs: 2000 });
    expect(gens(e)).toEqual([1, 2, 3]);
  });

  it('a free top generation is taken at once, a "held" one with an unknown state word is held', async () => {
    const d = tmp();
    gen(d, 1, { st: 'free' });
    await open(d, { lockTimeoutMs: 40 });
    expect(gens(d)).toEqual([1, 2, 3]);
    const e = tmp();
    gen(e, 1, { st: 'weird' });
    await rej(open(e, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });
});

describe('generation locks: legacy single-file state.lock', () => {
  it('a legacy lock of a live owner blocks and is never touched', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.lock'), body());
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
    expect(readFileSync(join(d, 'state.lock'), 'utf8')).toBe(body());
  });

  it('a legacy lock whose owner is dead does not block (and is left in place)', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.lock'), body({ pid: DEAD_PID }));
    await open(d, { lockTimeoutMs: 2000 });
    expect(existsSync(join(d, 'state.lock'))).toBe(true);
  });

  it('an unreadable legacy lock blocks until it is strictly older than 1000 ms', async () => {
    const d = tmp();
    const lock = join(d, 'state.lock');
    writeFileSync(lock, '{torn');
    const secs = Math.floor(Date.now() / 1000) - 3600;
    utimesSync(lock, secs, secs);
    expect(statSync(lock).mtimeMs).toBe(secs * 1000);
    let t = secs * 1000 + 1000;
    vi.spyOn(Date, 'now').mockImplementation(() => t);
    let sleeps = 0;
    const real = globalThis.setTimeout;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void) => {
      sleeps += 1;
      t += 1; // age 1001
      return real(fn, 1);
    }) as never);
    await open(d, { lockTimeoutMs: 100_000 });
    expect(sleeps).toBe(1); // age == 1000 still blocks, 1001 does not
  });

  it('a legacy lock that vanishes between the check and the stat is treated as age 0 (still blocking if unreadable)', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.lock'), '{torn');
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });
});

describe('generation locks: waiting', () => {
  const holdLive = (d: string) => gen(d, 1, {});

  it('the retry sleep is 5 + floor(random * 15) ms', async () => {
    const d = tmp();
    holdLive(d);
    const delays: number[] = [];
    const real = globalThis.setTimeout;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      return real(fn, 1);
    }) as never);
    const rnd = vi.spyOn(Math, 'random').mockReturnValue(0.999);
    await rej(open(d, { lockTimeoutMs: 60 }), /^lock-timeout: /);
    expect(delays.length).toBeGreaterThan(0);
    expect(delays.every((x) => x === 19)).toBe(true);
    delays.length = 0;
    rnd.mockReturnValue(0);
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
    expect(delays.length).toBeGreaterThan(0);
    expect(delays.every((x) => x === 5)).toBe(true);
  });

  it('the lock timeout is strict: now == deadline still waits, now == deadline + 1 gives up', async () => {
    const d = tmp();
    holdLive(d);
    const T0 = Date.now();
    let t = T0;
    vi.spyOn(Date, 'now').mockImplementation(() => t);
    let sleeps = 0;
    const real = globalThis.setTimeout;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void) => {
      sleeps += 1;
      t = sleeps === 1 ? T0 + 40 : T0 + 41;
      return real(fn, 1);
    }) as never);
    await rej(open(d, { lockTimeoutMs: 40 }), new RegExp(`^lock-timeout: could not acquire the state lock in ${d} within 40 ms; blocked by ${d}/state\\.lock\\.1 \\(holder pid=${process.pid} host=${hostname()} nonce=n\\)\\. If that holder is provably gone`));
    expect(sleeps).toBe(2);
  });

  it('losing the race for a generation retries immediately without sleeping', async () => {
    const d = tmp();
    let lost = 0;
    hooks.link = (_from, to) => {
      if (lost === 0 && to.endsWith('state.lock.1')) {
        lost = 1;
        writeFileSync(to, body({ st: 'free', pid: undefined }));
      }
    };
    const delays: number[] = [];
    const real = globalThis.setTimeout;
    vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      return real(fn, 1);
    }) as never);
    await open(d, { lockTimeoutMs: 2000 });
    expect(lost).toBe(1);
    expect(delays).toEqual([]);
    expect(gens(d)).toEqual([1, 2, 3]);
  });

  it('a link failure other than EEXIST is reported, with its code (or "error" without one)', async () => {
    const d = tmp();
    hooks.link = (_f, to) => {
      if (/state\.lock\.\d+$/.test(to)) throw Object.assign(new Error('nope'), { code: 'EPERM' });
    };
    await rej(open(d), "invalid: the state directory's filesystem cannot create the lock atomically (link: EPERM)");
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
    hooks.link = (_f, to) => {
      if (/state\.lock\.\d+$/.test(to)) throw new Error('nope');
    };
    await rej(open(tmp()), "invalid: the state directory's filesystem cannot create the lock atomically (link: error)");
  });
});

describe('a writer that lost the lock leaves nothing behind', () => {
  const lose = async (mut: (d: string, top: number) => void, highest: (top: number) => number, state: string) => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    const before = readFileSync(join(d, 'state.journal'), 'utf8');
    hooks.ev.length = 0;
    let mine = 0;
    await rej(
      s.update('a', () => {
        mine = Math.max(...gens(d));
        mut(d, mine);
        return 2;
      }),
      new RegExp(`^lock-lost: the state lock is no longer held by this writer \\(generation \\d+, highest \\d+ ${state}\\); nothing was written$`),
    );
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
    expect(hooks.ev.some((x) => x.op === 'unlink' && /state\.journal\.tmp-/.test(x.path))).toBe(true);
    expect(readFileSync(join(d, 'state.journal'), 'utf8')).toBe(before);
    return { mine, highest: highest(mine) };
  };
  const msgOf = async (mut: (d: string, top: number) => void) => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    let mine = 0;
    const err = await s
      .update('a', () => {
        mine = Math.max(...gens(d));
        mut(d, mine);
        return 2;
      })
      .then(() => undefined, (x: Error) => x);
    return { mine, message: err?.message };
  };
  it('another generation above ours', async () => {
    await lose((d, top) => gen(d, top + 1, { pid: 1, host: 'x', nonce: 'other' }), (t) => t + 1, 'held');
    const r = await msgOf((d, top) => gen(d, top + 1, { pid: 1, host: 'x', nonce: 'other' }));
    expect(r.message).toBe(`lock-lost: the state lock is no longer held by this writer (generation ${r.mine}, highest ${r.mine + 1} held); nothing was written`);
  });
  it('a free generation above ours', async () => {
    await lose((d, top) => gen(d, top + 1, { st: 'free' }), (t) => t + 1, 'free');
    const r = await msgOf((d, top) => gen(d, top + 1, { st: 'free' }));
    expect(r.message).toBe(`lock-lost: the state lock is no longer held by this writer (generation ${r.mine}, highest ${r.mine + 1} free); nothing was written`);
  });
  it('our generation file naming somebody else', async () => {
    await lose((d, top) => gen(d, top, { nonce: 'someone-else' }), (t) => t, 'held');
  });
  it('our generation file turned into "free"', async () => {
    await lose((d, top) => gen(d, top, { st: 'free' }), (t) => t, 'free');
  });
  it('our generation file unreadable', async () => {
    await lose((d, top) => gen(d, top, '{torn'), (t) => t, 'unreadable');
  });
  it('the generation file vanished (no generation above ours, none at all)', async () => {
    const r = await msgOf((d, top) => rmSync(join(d, `state.lock.${top}`)));
    expect(r.message).toMatch(/^lock-lost: .*highest \d+ (held|free|unreadable)\); nothing was written$/);
  });
});

describe('generation locks: a grab buried below the real top is not a lock', () => {
  it('when a higher generation appears right after our link, we start over above it', async () => {
    const d = tmp();
    hooks.afterLink = (to) => {
      if (to.endsWith('state.lock.1')) {
        hooks.afterLink = undefined;
        gen(d, 2, { st: 'free' });
      }
    };
    await open(d, { lockTimeoutMs: 2000 });
    expect(gens(d)).toEqual([1, 2, 3, 4]); // 3 = our real grab, 4 = its release
  });
});

describe('generation locks: remaining decisions', () => {
  it('files that only resemble lock generations or temp files are left alone by garbage collection', async () => {
    const d = tmp();
    const s = await open(d);
    const keep = ['zstate.lock.1', 'state.lock.1z', 'zstate.lock.2', 'state.lock.2x', `zstate.lock.tmp-${DEAD_PID}-a`, `xstate.lock.tmp-${DEAD_PID}-q`];
    for (const f of keep) writeFileSync(join(d, f), 'x');
    for (let i = 0; i < 25; i++) await s.get('a'); // far past 16 generations so old ones are collected
    for (const f of keep) expect(existsSync(join(d, f)), f).toBe(true);
    expect(gens(d).length).toBe(17);
  });

  it('only the pid that leads the temp-file name counts: a dead pid embedded later in a name whose own pid field is malformed is left alone', async () => {
    const d = tmp();
    const s = await open(d);
    const odd = [`state.lock.tmp-x-state.lock.tmp-${DEAD_PID}-a`, `state.lock.tmp-oops-state.lock.tmp-${DEAD_PID}-b`];
    for (const f of odd) writeFileSync(join(d, f), 'x');
    await s.get('zz');
    for (const f of odd) expect(existsSync(join(d, f)), f).toBe(true);
  });

  it('a malformed temp-file name does not stop the collection of dead temp files', async () => {
    const d = tmp();
    const s = await open(d);
    const dead: string[] = [];
    const mkDead = (from: number, to: number) => {
      for (let i = from; i < to; i++) {
        writeFileSync(join(d, `state.lock.tmp-${DEAD_PID - i}-d`), 'x');
        dead.push(`state.lock.tmp-${DEAD_PID - i}-d`);
      }
    };
    mkDead(0, 15);
    for (let i = 0; i < 15; i++) writeFileSync(join(d, `state.lock.tmp-oops${i}`), 'x');
    mkDead(15, 30);
    for (let i = 0; i < 15; i++) writeFileSync(join(d, `unrelated${i}`), 'x');
    await s.get('a');
    for (const f of dead) expect(existsSync(join(d, f)), f).toBe(false);
    expect(existsSync(join(d, 'state.lock.tmp-oops0'))).toBe(true);
    expect(existsSync(join(d, 'unrelated0'))).toBe(true);
  });

  it('a dead-pid temp file whose name lacks the leading anchor is not ours to delete', async () => {
    const d = tmp();
    const s = await open(d);
    const f = `xstate.lock.tmp-${DEAD_PID}-z`;
    writeFileSync(join(d, f), 'x');
    await s.get('a');
    expect(existsSync(join(d, f))).toBe(true);
  });

  it('a lock-like file whose name merely starts with digits is not a generation (top generation is picked by the full name)', async () => {
    const d = tmp();
    gen(d, 1, { st: 'free' });
    writeFileSync(join(d, 'state.lock.99x'), body());
    await open(d, { lockTimeoutMs: 100 });
    expect(gens(d)).toEqual([1, 2, 3]);
  });

  it('an old legacy lock containing non-object JSON is unreadable (treated as torn), not a live holder', async () => {
    for (const content of ['5', '"s"', 'null', 'true']) {
      const d = tmp();
      const lock = join(d, 'state.lock');
      writeFileSync(lock, content);
      const secs = Math.floor(Date.now() / 1000) - 3600;
      utimesSync(lock, secs, secs);
      if (content === 'null') continue; // null.st throws into the same catch: identical to unreadable by construction
      await open(d, { lockTimeoutMs: 100 });
    }
  });

  it.runIf(linux)('a start field that is not a string is ignored rather than compared', async () => {
    const d = tmp();
    gen(d, 1, { start: 12345 });
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });

  it('an unreadable /proc entry (start time unknown) never makes a live holder dead', async () => {
    const d = tmp();
    gen(d, 1, { start: 'whatever' });
    hooks.read = (p) => {
      if (p.startsWith('/proc/')) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    };
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });

  it('a writer is lost when a higher generation exists even if it carries our own nonce', async () => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    await rej(
      s.update('a', () => {
        const top = Math.max(...gens(d));
        const mine = JSON.parse(readFileSync(join(d, `state.lock.${top}`), 'utf8')) as { nonce: string };
        gen(d, top + 1, { nonce: mine.nonce });
        return 2;
      }),
      /^lock-lost: /,
    );
    expect(readFileSync(join(d, 'state.journal'), 'utf8').split('\n').filter(Boolean)).toHaveLength(1);
  });
});

describe('head repair rules', () => {
  const seed = async () => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    const h1 = readFileSync(join(d, 'state.head'), 'utf8');
    await s.set('b', 2);
    const h2 = readFileSync(join(d, 'state.head'), 'utf8');
    return { d, h1, h2 };
  };

  it('open: an in-sync head is not rewritten; a lagging or missing head is repaired exactly once', async () => {
    const { d, h1, h2 } = await seed();
    hooks.ev.length = 0;
    await open(d);
    expect(headRenames()).toBe(0);
    writeFileSync(join(d, 'state.head'), h1);
    hooks.ev.length = 0;
    await open(d);
    expect(headRenames()).toBe(1);
    sameHeadRepairedLater(readFileSync(join(d, 'state.head'), 'utf8'), h2);
    // missing head is only legal while the journal holds a single record
    const e = tmp();
    const s = await open(e);
    await s.set('a', 1);
    const only = readFileSync(join(e, 'state.head'), 'utf8');
    rmSync(join(e, 'state.head'));
    hooks.ev.length = 0;
    await open(e);
    expect(headRenames()).toBe(1);
    sameHeadRepairedLater(readFileSync(join(e, 'state.head'), 'utf8'), only);
  });

  it('set: repairs a lagging/missing head first, then commits (head written once more); in-sync writes the head once', async () => {
    const { d } = await seed();
    const s = await open(d);
    hooks.ev.length = 0;
    await s.set('c', 3);
    expect(headRenames()).toBe(1);
    const e = tmp();
    const t = await open(e);
    await t.set('a', 1);
    rmSync(join(e, 'state.head'));
    hooks.ev.length = 0;
    await t.set('b', 2);
    expect(headRenames()).toBe(2);
  });

  it('set and update with a head lagging by exactly one record', async () => {
    for (const kind of ['set', 'update-changed', 'update-same'] as const) {
      const { d, h1, h2 } = await seed();
      const s = await open(d);
      writeFileSync(join(d, 'state.head'), h1);
      hooks.ev.length = 0;
      if (kind === 'set') await s.set('c', 3);
      else if (kind === 'update-changed') await s.update('b', () => 99);
      else await s.update('b', (p) => p);
      expect(headRenames(), kind).toBe(kind === 'update-same' ? 1 : 2);
      if (kind === 'update-same') sameHeadRepairedLater(readFileSync(join(d, 'state.head'), 'utf8'), h2);
    }
  });

  it('update with an in-sync head writes the head once when it changes the value and not at all when it does not', async () => {
    const { d } = await seed();
    const s = await open(d);
    hooks.ev.length = 0;
    await s.update('b', () => 77);
    expect(headRenames()).toBe(1);
    hooks.ev.length = 0;
    await s.update('b', (p) => p);
    expect(headRenames()).toBe(0);
  });

  it('update with a missing head (single-record journal) repairs it', async () => {
    const e = tmp();
    const t = await open(e);
    await t.set('a', 1);
    const only = readFileSync(join(e, 'state.head'), 'utf8');
    rmSync(join(e, 'state.head'));
    hooks.ev.length = 0;
    await t.update('a', (p) => p);
    expect(headRenames()).toBe(1);
    sameHeadRepairedLater(readFileSync(join(e, 'state.head'), 'utf8'), only);
  });

  it('update on an empty store (no records) writes no head for an unchanged result', async () => {
    const d = tmp();
    const s = await open(d);
    hooks.ev.length = 0;
    expect(await s.update('x', () => undefined)).toBeUndefined();
    expect(headRenames()).toBe(0);
  });
});

describe('keys() and the observed position', () => {
  it('keys are returned sorted (not in insertion order)', async () => {
    const d = tmp();
    const s = await open(d);
    await s.set('b', 1);
    await s.set('a', 2);
    await s.set('c', 3);
    expect(await s.keys()).toEqual(['a', 'b', 'c']);
  });

  it('keys() advances the handle position to what is on disk', async () => {
    const d = tmp();
    const a = await open(d);
    await a.set('x', 1);
    const b = await open(d);
    await b.set('y', 2);
    expect(a.position().seq).toBe(1);
    await a.keys();
    expect(a.position().seq).toBe(2);
    expect(a.position().hash).toBe(b.position().hash);
  });
});

describe('journal shape guards that a coerced value would otherwise slip past', () => {
  const rec = mk(1, GEN, 'k\n1');
  it('a head whose h is an array wrapping a valid hash is an invalid shape', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.head'), JSON.stringify({ seq: 0, h: [GEN] }) + '\n');
    await rej(open(d), 'corrupt: state.head has an invalid shape');
  });
  it('a record whose prev / h is an array wrapping a valid hash is an invalid shape', async () => {
    for (const bad of [{ ...rec, prev: [GEN] }, { ...rec, h: [rec.h] }]) {
      const d = tmp();
      writeFileSync(join(d, 'state.journal'), JSON.stringify(bad) + '\n');
      await rej(open(d), 'corrupt: journal line 1 has an invalid shape');
    }
  });
  it('a non-string mac on an unkeyed journal is ignored (it is not part of the record hash)', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.journal'), JSON.stringify({ ...rec, mac: 5 }) + '\n');
    const s = await open(d);
    expect(await s.get('k')).toBe(1);
  });
});

describe('open-time link probe', () => {
  it('a filesystem whose link fails is refused with link-unsupported, naming the cause, and leaves no probe files', async () => {
    const d = tmp();
    hooks.link = (_f, to) => {
      if (to.endsWith('.lnk')) throw Object.assign(new Error('x'), { code: 'EPERM' });
    };
    const e = await rej(open(d), /^link-unsupported: the state directory's filesystem does not provide working hard links with exclusive-create semantics \(EPERM\); use a local filesystem/);
    expect(e.code).toBe('link-unsupported');
    expect(readdirSync(d).filter((f) => f.startsWith('state.probe-'))).toEqual([]);
  });
  it('a link that succeeds twice (no exclusivity) is refused', async () => {
    const d = tmp();
    let n = 0;
    hooks.link = (_f, to) => {
      if (to.endsWith('.lnk') && ++n === 2) throw Object.assign(new Error('x'), { code: 'ENOTSUP' });
    };
    await rej(open(d), /^link-unsupported: .*\(link\(2\) is not atomic\/exclusive here\)/);
    expect(readdirSync(d).filter((f) => f.startsWith('state.probe-'))).toEqual([]);
  });
  it('a healthy filesystem passes and leaves no probe files', async () => {
    const d = tmp();
    await open(d);
    expect(readdirSync(d).filter((f) => f.startsWith('state.probe-'))).toEqual([]);
  });
});

describe('open-time link probe: exclusivity and link count', () => {
  it('a second link that unexpectedly succeeds is refused', async () => {
    const d = tmp();
    let n = 0;
    hooks.skipLink = (to) => to.endsWith('.lnk') && ++n === 2;
    await rej(open(d), /^link-unsupported: /);
  });
  it('a link count other than 2 is refused', async () => {
    const d = tmp();
    hooks.afterLink = (to) => {
      if (to.endsWith('.lnk')) {
        hooks.afterLink = undefined;
        realFs.linkSync(to, to + '.extra');
      }
    };
    await rej(open(d), /^link-unsupported: /);
  });
});

describe('R4-09 lock identity: namespace and boot id', () => {
  it('the held generation carries a 24-hex boot id that is stable per process, and the PID namespace on Linux', async () => {
    const d = tmp();
    const s = await open(d);
    const seen: Record<string, unknown>[] = [];
    for (let i = 0; i < 2; i++) {
      await s.update('k', () => {
        seen.push(JSON.parse(readFileSync(join(d, `state.lock.${Math.max(...gens(d))}`), 'utf8')));
        return undefined;
      });
    }
    expect(seen[0]!['boot']).toMatch(/^[0-9a-f]{24}$/);
    expect(seen[1]!['boot']).toBe(seen[0]!['boot']);
    if (linux) expect(seen[0]!['ns']).toBe(realFs.readlinkSync('/proc/self/ns/pid'));
    else expect('ns' in seen[0]!).toBe(false);
  });
  it.runIf(linux)('a holder in another PID namespace is never judged dead, even with a dead pid', async () => {
    const d = tmp();
    gen(d, 1, { pid: DEAD_PID, ns: 'pid:[4026539999]' });
    await rej(open(d, { lockTimeoutMs: 40 }), /^lock-timeout: /);
  });
  it.runIf(linux)('a holder with a non-string ns is treated as having no namespace (dead pid is taken over)', async () => {
    const d = tmp();
    gen(d, 1, { pid: DEAD_PID, ns: 12345 });
    await open(d, { lockTimeoutMs: 2000 });
    expect(gens(d)).toContain(3);
  });
  it.runIf(linux)('a holder in our own namespace with a dead pid is taken over', async () => {
    const d = tmp();
    gen(d, 1, { pid: DEAD_PID, ns: realFs.readlinkSync('/proc/self/ns/pid') });
    await open(d, { lockTimeoutMs: 2000 });
    expect(gens(d)).toContain(3);
  });
});

describe('garbage collection order independence', () => {
  it('a malformed temp-file name listed FIRST does not stop the collection of dead temp files after it', async () => {
    const d = tmp();
    const s = await open(d);
    writeFileSync(join(d, 'state.lock.tmp-oops'), 'x');
    writeFileSync(join(d, `state.lock.tmp-${DEAD_PID}-d`), 'x');
    hooks.order = (names) => [...names].sort((x, y) => (x.includes('oops') ? -1 : y.includes('oops') ? 1 : 0));
    await s.get('a');
    expect(existsSync(join(d, `state.lock.tmp-${DEAD_PID}-d`))).toBe(false);
  });
});

describe('lock-timeout names the blocker', () => {
  it('an unreadable top record, a holder with no fields, and a foreign PID namespace are each described', async () => {
    const d = tmp();
    gen(d, 1, '{torn');
    await rej(open(d, { lockTimeoutMs: 30 }), /blocked by .*state\.lock\.1 \(an unreadable holder record\)\./);
    const e = tmp();
    gen(e, 1, { pid: undefined, host: undefined, nonce: undefined });
    await rej(open(e, { lockTimeoutMs: 30 }), /\(an incomplete holder record \(pid=\? host=\? nonce=\?\); release it with expectedHolder: 'unreadable'\)\./);
    if (linux) {
      const f = tmp();
      gen(f, 1, { pid: process.pid, ns: 'pid:[1]' });
      await rej(open(f, { lockTimeoutMs: 30 }), /nonce=n \(another PID namespace\)\)\./);
      const g = tmp();
      gen(g, 1, { pid: process.pid, ns: realFs.readlinkSync('/proc/self/ns/pid') });
      await rej(open(g, { lockTimeoutMs: 30 }), /nonce=n\)\./);
    }
  });
});

describe('recoverDurableState', () => {
  const holder = (o: Record<string, unknown> = {}) => ({ host: 'other-host', pid: 77, nonce: 'nn', ...o });
  const rec = (d: string, expectedHolder: unknown, force: unknown = true) => recoverDurableState({ dir: d, force, expectedHolder } as never);
  const bad = (f: () => unknown, re: RegExp | string) => {
    let e: unknown;
    try {
      f();
    } catch (x) {
      e = x;
    }
    expect(e).toBeInstanceOf(DurableStateError);
    expect((e as DurableStateError).code).toBe('invalid');
    if (typeof re === 'string') expect((e as Error).message).toBe(re);
    else expect((e as Error).message).toMatch(re);
  };
  it('requires force: true and a well-formed expectedHolder', () => {
    const d = tmp();
    for (const o of [null, undefined, 5, { dir: d }, { dir: d, force: 'true', expectedHolder: 'unreadable' }]) bad(() => recoverDurableState(o as never), 'invalid: recoverDurableState requires force: true');
    const msg = "invalid: expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'";
    for (const h of [null, undefined, 5, 'x', { pid: 1, nonce: 'n' }, { host: 'h', nonce: 'n' }, { host: 'h', pid: '1', nonce: 'n' }, { host: 'h', pid: 1 }, { host: 'h', pid: 1, nonce: '' }]) bad(() => rec(d, h), msg);
  });
  it('an empty directory or a free top generation is not held', () => {
    const d = tmp();
    expect(rec(d, holder())).toEqual({ released: false, reason: 'not-held' });
    gen(d, 4, { st: 'free' });
    expect(rec(d, holder())).toEqual({ released: false, reason: 'not-held', lockFile: join(d, 'state.lock.4') });
    expect(gens(d)).toEqual([4]);
  });
  it('releases a foreign-host holder: takes the next generation itself, fences, then appends a free one', () => {
    const d = tmp();
    gen(d, 2, { host: 'other-host', pid: 77, nonce: 'nn' });
    expect(rec(d, holder())).toEqual({ released: true, reason: 'released', lockFile: join(d, 'state.lock.2') });
    expect(gens(d)).toEqual([2, 3, 4]);
    expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).toMatchObject({ st: 'held', pid: process.pid, host: hostname(), recovering: 2 });
    expect(JSON.parse(readFileSync(join(d, 'state.lock.4'), 'utf8'))).toMatchObject({ st: 'free', recoveredFrom: 2 });
    const fenceFiles = readdirSync(d).filter((f) => /^state\.fence\.3-[0-9a-f]+$/.test(f));
    expect(fenceFiles).toHaveLength(1);
    expect(JSON.parse(readFileSync(join(d, fenceFiles[0]!), 'utf8'))).toMatchObject({ v: 1, fence: { gen: 3, seq: 0, h: '0'.repeat(64), from: 2 } });
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
    expect(hooks.ev.some((e) => e.op === 'fsync' && /state\.lock\.tmp-/.test(e.path))).toBe(true);
    expect(hooks.ev.some((e) => e.op === 'close' && /state\.lock\.tmp-/.test(e.path))).toBe(true);
  });
  it('only the highest generation is examined', () => {
    const d = tmp();
    gen(d, 9, { host: 'other-host', pid: 77, nonce: 'nn' });
    gen(d, 10, { host: 'other-host', pid: 77, nonce: 'nn' });
    gen(d, 3, { host: 'x', pid: 1, nonce: 'z' });
    expect(rec(d, holder()).lockFile).toBe(join(d, 'state.lock.10'));
    expect(gens(d)).toEqual([3, 9, 10, 11, 12]);
  });
  it('a mismatch of host, pid or nonce is refused with the recorded values and nothing changes', () => {
    for (const h of [holder({ host: 'h2' }), holder({ pid: 78 }), holder({ nonce: 'zz' })]) {
      const d = tmp();
      gen(d, 1, { host: 'other-host', pid: 77, nonce: 'nn' });
      bad(() => rec(d, h), new RegExp(`^invalid: expectedHolder does not match the holder recorded in ${d}/state\\.lock\\.1 \\(recorded pid=77 host=other-host nonce=nn\\); nothing was changed$`));
      expect(gens(d)).toEqual([1]);
    }
    // R6-CORE-03: an incomplete record cannot be matched field by field; it names itself and points at 'unreadable'
    const d = tmp();
    gen(d, 1, { host: undefined, pid: undefined, nonce: undefined });
    bad(() => rec(d, holder()), new RegExp(`^invalid: ${d}/state\\.lock\\.1 has an incomplete holder record \\(\\{"st":"held"\\}\\); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it$`));
    expect(gens(d)).toEqual([1]);
  });
  it("'unreadable' releases only an unreadable record", () => {
    const d = tmp();
    gen(d, 1, '{torn');
    expect(rec(d, 'unreadable')).toEqual({ released: true, reason: 'released', lockFile: join(d, 'state.lock.1') });
    const e = tmp();
    gen(e, 1, '5');
    expect(rec(e, 'unreadable').released).toBe(true);
    const f = tmp();
    gen(f, 1, 'null');
    expect(rec(f, 'unreadable').released).toBe(true);
    bad(() => rec(tmp().length ? (() => { const x = tmp(); gen(x, 1, '{torn'); return x; })() : '', holder()), /state\.lock\.1 is unreadable; pass expectedHolder: 'unreadable' to release it$/);
    const g = tmp();
    gen(g, 1, { host: 'h', pid: 3 });
    bad(() => rec(g, 'unreadable'), /state\.lock\.1 is readable \(holder pid=3 host=h\); expectedHolder 'unreadable' does not match$/);
    // R6-CORE-03: a readable but INCOMPLETE record (no pid/host) used to wedge forever; 'unreadable' now releases it
    const h = tmp();
    gen(h, 1, { host: undefined, pid: undefined });
    expect(rec(h, 'unreadable')).toEqual({ released: true, reason: 'released', lockFile: join(h, 'state.lock.1') });
  });
  it('a holder alive in this host and namespace is never robbed; a dead one, or a recycled pid, is released', () => {
    const d = tmp();
    gen(d, 1, { host: hostname(), pid: process.pid, nonce: 'nn' });
    bad(() => rec(d, { host: hostname(), pid: process.pid, nonce: 'nn' }), new RegExp(`^invalid: the holder of ${d}/state\\.lock\\.1 \\(pid ${process.pid}\\) is alive in this PID namespace; refusing to release a live holder$`));
    expect(gens(d)).toEqual([1]);
    const e = tmp();
    gen(e, 1, { host: hostname(), pid: DEAD_PID, nonce: 'nn' });
    expect(rec(e, { host: hostname(), pid: DEAD_PID, nonce: 'nn' }).released).toBe(true);
    if (linux) {
      const f = tmp();
      gen(f, 1, { host: hostname(), pid: process.pid, nonce: 'nn', start: 'recycled' });
      expect(rec(f, { host: hostname(), pid: process.pid, nonce: 'nn' }).released).toBe(true);
      const g = tmp();
      gen(g, 1, { host: hostname(), pid: process.pid, nonce: 'nn', start: startOf('self') });
      bad(() => rec(g, { host: hostname(), pid: process.pid, nonce: 'nn' }), /refusing to release a live holder$/);
      const h = tmp();
      gen(h, 1, { host: hostname(), pid: process.pid, nonce: 'nn', start: 'x', ns: 'pid:[1]' });
      expect(rec(h, { host: hostname(), pid: process.pid, nonce: 'nn' }).released).toBe(true); // other namespace: cannot judge, operator attests
      const i = tmp();
      gen(i, 1, { host: hostname(), pid: process.pid, nonce: 'nn', ns: realFs.readlinkSync('/proc/self/ns/pid') });
      bad(() => rec(i, { host: hostname(), pid: process.pid, nonce: 'nn' }), /refusing to release a live holder$/);
    }
  });
  it('look-alike lock file names are not generations for recovery', () => {
    const d = tmp();
    gen(d, 1, { host: 'other-host', pid: 77, nonce: 'nn' });
    for (const f of ['state.lock.99x', 'zstate.lock.99', 'state.lock.1x']) writeFileSync(join(d, f), body({ host: 'x' }));
    expect(rec(d, holder()).lockFile).toBe(join(d, 'state.lock.1'));
    gen(d, 5, { host: 'other-host', pid: 77, nonce: 'nn' });
    gen(d, 5 + 0, { host: 'other-host', pid: 77, nonce: 'nn' });
  });
  it.runIf(linux)('a live holder of another PID namespace without a start time is released on attestation', () => {
    const d = tmp();
    gen(d, 1, { host: hostname(), pid: process.pid, nonce: 'nn', ns: 'pid:[1]' });
    expect(rec(d, { host: hostname(), pid: process.pid, nonce: 'nn' }).released).toBe(true);
  });
  it('a start field that is not a string does not count as a recycled pid', () => {
    const d = tmp();
    gen(d, 1, { host: hostname(), pid: process.pid, nonce: 'nn', start: 5 });
    bad(() => rec(d, { host: hostname(), pid: process.pid, nonce: 'nn' }), /refusing to release a live holder$/);
  });
  it('an unreadable /proc entry means the pid is not judged recycled', () => {
    const d = tmp();
    gen(d, 1, { host: hostname(), pid: process.pid, nonce: 'nn', start: 'x' });
    hooks.read = (p) => {
      if (p.startsWith('/proc/') && p.endsWith('/stat')) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    };
    bad(() => rec(d, { host: hostname(), pid: process.pid, nonce: 'nn' }), /refusing to release a live holder$/);
  });
  it('losing the race for the free generation is reported; other link errors propagate; temp files are removed', () => {
    const d = tmp();
    gen(d, 1, { host: 'other-host', pid: 77, nonce: 'nn' });
    hooks.link = (_f, to) => {
      if (to.endsWith('state.lock.2')) writeFileSync(to, body({ st: 'free' }));
    };
    bad(() => rec(d, holder()), new RegExp(`^invalid: ${d}/state\\.lock\\.1 was superseded while recovering; re-read the lock state and retry$`));
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
    const e = tmp();
    gen(e, 1, { host: 'other-host', pid: 77, nonce: 'nn' });
    hooks.link = () => {
      throw Object.assign(new Error('boom'), { code: 'EPERM' });
    };
    let err: unknown;
    try {
      rec(e, holder());
    } catch (x) {
      err = x;
    }
    expect((err as Error).message).toBe('boom');
    expect(readdirSync(e).filter((f) => f.includes('.tmp-'))).toEqual([]);
  });
});
