/**
 * Third mutation-kill file for durable-state.ts (after the R6-CORE-01 follow-up: crashed recovery, takeover fence,
 * one-file-per-fence). Everything here runs IN-PROCESS (a mutant is only active in the test runner, never in a spawned
 * child), using the same node:fs interception harness as mutation-kill-durable-state-2.test.ts:
 *   - fence parsing (list file and one-fence files), their order, and the journal-tail cut recovery records;
 *   - the test-only crash hook (a process.kill spy turns the SIGKILL into a throw, so every crash point is observable);
 *   - holder classification / liveness / attestation checks of recoverDurableState, the legacy path's fence + fsync;
 *   - load(): generation shape, line numbers in errors, fence boundary, the cut pin under compaction, the head-generation
 *     check, every conjunct of the stale-late-head rule; quarantine's lock re-check and re-fence; the takeover fence and
 *     the `recovering` mark; the lock-timeout blocker message; the head re-check outcomes.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DurableStateError, openDurableState, recoverDurableState, RECOVER_CRASH_ENV } from './durable-state';

interface Ev { op: string; path: string; flags?: number; to?: string }
const hooks = vi.hoisted(() => ({
  ev: [] as Ev[],
  fdPath: new Map<number, string>(),
  afterRename: undefined as undefined | ((from: string, to: string) => void),
  read: undefined as undefined | ((path: string) => void),
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
    readdirSync: (p: unknown, ...r: unknown[]) => {
      const out = (a.readdirSync as (...x: unknown[]) => unknown)(p, ...r);
      return hooks.order && Array.isArray(out) && typeof out[0] !== 'object' ? hooks.order(out as string[]) : out;
    },
    readFileSync: (p: unknown, ...r: unknown[]) => {
      if (typeof p === 'string') hooks.read?.(p);
      return (a.readFileSync as (...x: unknown[]) => unknown)(p, ...r);
    },
    renameSync: (from: string, to: string) => {
      a.renameSync(from, to);
      hooks.ev.push({ op: 'rename', path: String(from), to: String(to) });
      hooks.afterRename?.(String(from), String(to));
    },
  };
});

const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'ds-mk3-'));
  dirs.push(d);
  return d;
};
const savedEnv = { node: process.env['NODE_ENV'], crash: process.env[RECOVER_CRASH_ENV] };
afterEach(() => {
  vi.restoreAllMocks();
  hooks.afterRename = undefined;
  hooks.read = undefined;
  hooks.order = undefined;
  hooks.ev.length = 0;
  if (savedEnv.crash === undefined) delete process.env[RECOVER_CRASH_ENV];
  else process.env[RECOVER_CRASH_ENV] = savedEnv.crash;
  if (savedEnv.node === undefined) delete process.env['NODE_ENV'];
  else process.env['NODE_ENV'] = savedEnv.node;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const G0 = '0'.repeat(64);
const HEX = 'ab'.repeat(32);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
type R = { seq: number; prev: string; op: string; payload: string; ts: number; gen?: number; h: string };
/** A record exactly as durable-state writes it (the generation is inside the hash). */
const rec = (seq: number, prev: string, payload: string, gen?: number, op = 'set'): R => {
  const base = gen === undefined ? [seq, prev, op, payload, 1] : [seq, prev, op, payload, 1, gen];
  return { seq, prev, op, payload, ts: 1, ...(gen !== undefined ? { gen } : {}), h: sha('pca-durable-state/v1\n' + JSON.stringify(base)) };
};
/** A chain of `set` records with the given generations. */
const chain = (gens: number[]): R[] => {
  const out: R[] = [];
  for (const [i, g] of gens.entries()) out.push(rec(i + 1, out[i - 1]?.h ?? G0, `k${i + 1}\n${i + 1}`, g));
  return out;
};
const writeJ = (d: string, rs: unknown[]) => writeFileSync(join(d, 'state.journal'), rs.map((r) => JSON.stringify(r)).join('\n') + '\n');
const writeH = (d: string, h: Record<string, unknown>) => writeFileSync(join(d, 'state.head'), JSON.stringify(h) + '\n');
const fenceFile = (d: string, f: Record<string, unknown>, name = 'aaaaaa') => writeFileSync(join(d, `state.fence.${String(f['gen'])}-${name}`), JSON.stringify({ v: 1, fence: f }));
const fenceList = (d: string, raw: string) => writeFileSync(join(d, 'state.fence'), raw);
const fenceEntries = (d: string) => readdirSync(d).filter((f) => /^state\.fence\.\d+-[0-9a-f]+$/.test(f));
const readFenceEntry = (d: string, name: string) => (JSON.parse(readFileSync(join(d, name), 'utf8')) as { fence: Record<string, unknown> }).fence;
const open = (d: string, o: Record<string, unknown> = {}) => openDurableState({ dir: d, lockTimeoutMs: 2000, ...o } as never);
const rej = async (p: Promise<unknown>, msg: string | RegExp) => {
  let e: unknown;
  try {
    await p;
  } catch (x) {
    e = x;
  }
  expect(e, 'expected a DurableStateError').toBeInstanceOf(DurableStateError);
  if (typeof msg === 'string') expect((e as Error).message).toBe(msg);
  else expect((e as Error).message).toMatch(msg);
  return e as DurableStateError;
};
const thrown = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
};
const DEAD_PID = 2147483646;
const FAKE_NS = 'pid:[4026530001]';
const linux = existsSync('/proc/self/ns/pid');
const myNs = linux ? readlinkSync('/proc/self/ns/pid') : undefined;
const startOf = (pid: number): string => {
  const st = readFileSync(`/proc/${pid}/stat`, 'utf8');
  return st.slice(st.lastIndexOf(')') + 2).split(' ')[19]!;
};
const lock = (d: string, g: number, body: unknown) => writeFileSync(join(d, `state.lock.${g}`), typeof body === 'string' ? body : JSON.stringify(body));
const deadOther = (o: Record<string, unknown> = {}) => ({ st: 'held', pid: DEAD_PID, host: hostname(), nonce: 'n-dead', ns: FAKE_NS, ...o });
const exp = { host: hostname(), pid: DEAD_PID, nonce: 'n-dead' };

// ---------------------------------------------------------------------------------------------------------------------
describe('fence parsing: the state.fence list file', () => {
  const cases: [string, string][] = [
    ['{nope', 'corrupt: state.fence is not valid JSON'],
    ['null', 'corrupt: state.fence has an invalid shape'],
    ['5', 'corrupt: state.fence has an invalid shape'],
    ['{"v":2,"fences":[]}', 'corrupt: state.fence has an invalid shape'],
    ['{"v":1,"fences":{}}', 'corrupt: state.fence has an invalid shape'],
    ['{"v":1}', 'corrupt: state.fence has an invalid shape'],
  ];
  it.each(cases)('%s -> %s', async (raw, msg) => {
    const d = tmp();
    fenceList(d, raw);
    await rej(open(d), msg);
  });
  const good = { gen: 2, seq: 0, h: G0 };
  const bad: [string, unknown][] = [
    ['null entry', null],
    ['number entry', 5],
    ['gen 0', { ...good, gen: 0 }],
    ['gen 1.5', { ...good, gen: 1.5 }],
    ['gen "2"', { ...good, gen: '2' }],
    ['gen "abc"', { ...good, gen: 'abc' }],
    ['seq -1', { ...good, seq: -1 }],
    ['seq "0"', { ...good, seq: '0' }],
    ['no h', { gen: 2, seq: 0 }],
    ['h number', { ...good, h: 5 }],
    ['h array of the hex', { ...good, h: [G0] }],
    ['h prefixed', { ...good, h: `x${G0}` }],
    ['h suffixed', { ...good, h: `${G0}x` }],
    ['h upper', { ...good, h: 'AB'.repeat(32) }],
  ];
  it.each(bad)('list entry %s is refused', async (_n, entry) => {
    const d = tmp();
    fenceList(d, JSON.stringify({ v: 1, fences: [good, entry] }));
    await rej(open(d), 'corrupt: state.fence has an invalid entry');
  });
  it('a valid list loads (an empty one too)', async () => {
    const d = tmp();
    fenceList(d, JSON.stringify({ v: 1, fences: [] }));
    await (await open(d)).set('k', 1);
    fenceList(d, JSON.stringify({ v: 1, fences: [good] }));
    expect(await (await open(d)).get('k')).toBe(1);
  });
});

describe('fence parsing: one-fence files state.fence.<gen>-<rand>', () => {
  const name = 'state.fence.2-abcdef';
  it.each([
    ['{nope', `corrupt: ${name} is not valid JSON`],
    ['null', `corrupt: ${name} has an invalid shape`],
    ['5', `corrupt: ${name} has an invalid shape`],
    ['{"v":2,"fence":{"gen":2,"seq":0,"h":"' + G0 + '"}}', `corrupt: ${name} has an invalid shape`],
    ['{"v":1,"fence":null}', `corrupt: ${name} has an invalid entry`],
    ['{"v":1,"fence":{"gen":2,"seq":0}}', `corrupt: ${name} has an invalid entry`],
    ['{"v":1,"fence":{"gen":3,"seq":0,"h":"' + G0 + '"}}', `corrupt: ${name} names generation 2 but holds 3`],
  ])('%s -> %s', async (raw, msg) => {
    const d = tmp();
    writeFileSync(join(d, name), raw);
    await rej(open(d), msg);
  });
  it('names that are not exactly state.fence.<digits>-<hex> are not fences (temp files, quarantined copies, other names)', async () => {
    const d = tmp();
    for (const n of ['state.fence.2-abcdef.tmp-1-2', 'state.fence.2-abcdef.quarantine-1', 'state.fence.x-abc', 'state.fence.2-xyz', 'xstate.fence.2-abc']) writeFileSync(join(d, n), '{nope');
    await (await open(d)).set('k', 1);
  });
});

describe('fence order: list first, then one-fence files by generation, then by name (first violated fence is reported)', () => {
  // records: seq 1 gen 1, seq 2 gen 2. Fences gen 3 and gen 5, both cut at seq 1: record 2 violates both.
  const setup = (names: [string, string]) => {
    const d = tmp();
    const j = chain([1, 2]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: j[1]!.h, gen: 2 });
    fenceFile(d, { gen: 3, seq: 1, h: j[0]!.h }, names[0]);
    fenceFile(d, { gen: 5, seq: 1, h: j[0]!.h }, names[1]);
    return d;
  };
  for (const rev of [false, true]) {
    it(`by generation, whatever the directory order and the names (reversed=${rev})`, async () => {
      const d = setup(['ffffff', '000000']); // name order contradicts generation order
      hooks.order = (n) => [...n].sort((a, b) => (rev ? (a < b ? 1 : -1) : a < b ? -1 : 1));
      await rej(open(d), /operator recovery fenced generations below 3 after seq 1/);
    });
    it(`same generation: by name (reversed=${rev})`, async () => {
      // two cuts of the same generation that the journal no longer reaches: the first in order is reported
      const d = tmp();
      const j = chain([1, 1]);
      writeJ(d, j);
      writeH(d, { seq: 2, h: j[1]!.h, gen: 1 });
      fenceFile(d, { gen: 5, seq: 3, h: HEX }, 'aaaaaa');
      fenceFile(d, { gen: 5, seq: 4, h: HEX }, 'bbbbbb');
      hooks.order = (n) => [...n].sort((a, b) => (rev ? (a < b ? 1 : -1) : a < b ? -1 : 1));
      await rej(open(d), 'rollback: journal is at seq 2 but operator recovery cut it at seq 3 (truncation, or a stale writer replaced it)');
    });
  }
  it('the list file comes before the one-fence files', async () => {
    const d = tmp();
    const j = chain([1, 2]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: j[1]!.h, gen: 2 });
    fenceFile(d, { gen: 3, seq: 1, h: j[0]!.h });
    fenceList(d, JSON.stringify({ v: 1, fences: [{ gen: 7, seq: 1, h: j[0]!.h }] }));
    await rej(open(d), /fenced generations below 7 after seq 1/);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('the cut recovery records (journal tail) and its validation of existing fences', () => {
  const recoverOver = (d: string, lastLine: string) => {
    writeFileSync(join(d, 'state.journal'), `${JSON.stringify(rec(1, G0, 'a\n1', 1))}\n${lastLine}\n`);
    lock(d, 1, deadOther());
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: exp })).toMatchObject({ released: true });
    const [n] = fenceEntries(d);
    return readFenceEntry(d, n!);
  };
  it('a well-formed tail is cut at its seq and hash', () => {
    expect(recoverOver(tmp(), JSON.stringify({ seq: 3, h: HEX }))).toMatchObject({ gen: 2, seq: 3, h: HEX, from: 1 });
  });
  it.each([
    ['seq 0', JSON.stringify({ seq: 0, h: HEX })],
    ['seq "3"', JSON.stringify({ seq: '3', h: HEX })],
    ['seq 1.5', JSON.stringify({ seq: 1.5, h: HEX })],
    ['h as an array holding the hex', JSON.stringify({ seq: 3, h: [HEX] })],
    ['h prefixed', JSON.stringify({ seq: 3, h: `x${HEX}` })],
    ['h suffixed', JSON.stringify({ seq: 3, h: `${HEX}x` })],
    ['h missing', JSON.stringify({ seq: 3 })],
    ['null', 'null'],
    ['a number', '7'],
    ['not JSON', '{nope'],
  ])('a tail that is not a record (%s) cuts at (0, zeros): every later record needs the new generation', (_n, line) => {
    expect(recoverOver(tmp(), line)).toMatchObject({ gen: 2, seq: 0, h: G0 });
  });
  it('no journal at all cuts at (0, zeros)', () => {
    const d = tmp();
    lock(d, 1, deadOther());
    recoverDurableState({ dir: d, force: true, expectedHolder: exp });
    expect(readFenceEntry(d, fenceEntries(d)[0]!)).toMatchObject({ gen: 2, seq: 0, h: G0 });
  });
  it('an unreadable existing fence makes recovery fail closed before it writes a new one', () => {
    const d = tmp();
    lock(d, 1, deadOther());
    fenceList(d, '{nope');
    expect(thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp })).message).toBe('corrupt: state.fence is not valid JSON');
    expect(fenceEntries(d)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('the test-only crash hook fires at exactly its named step (process.kill spy: SIGKILL becomes a throw)', () => {
  const arm = (point: string) => {
    process.env['NODE_ENV'] = 'test';
    process.env[RECOVER_CRASH_ENV] = point;
    const real = process.kill.bind(process);
    return vi.spyOn(process, 'kill').mockImplementation(((pid: number, sig?: string | number) => {
      if (pid === process.pid && sig === 'SIGKILL') throw new Error(`SIGKILL at ${point}`);
      return real(pid, sig as never);
    }) as typeof process.kill);
  };
  const files = (d: string) => readdirSync(d).sort();
  const shapes: [string, (d: string) => void][] = [
    ['before-lock', (d) => expect(files(d)).toEqual(['state.lock.1'])],
    ['after-lock-temp', (d) => {
      expect(existsSync(join(d, 'state.lock.2'))).toBe(false);
      expect(files(d).some((f) => f.startsWith(`state.lock.tmp-${process.pid}-`))).toBe(true);
    }],
    ['after-lock', (d) => {
      expect(JSON.parse(readFileSync(join(d, 'state.lock.2'), 'utf8'))).toMatchObject({ st: 'held', recovering: 1 });
      expect(fenceEntries(d)).toEqual([]);
      expect(files(d).some((f) => f.includes('.tmp-'))).toBe(false);
    }],
    ['after-fence-temp', (d) => {
      expect(fenceEntries(d)).toEqual([]);
      expect(files(d).some((f) => /^state\.fence\.2-[0-9a-f]+\.tmp-/.test(f))).toBe(false); // the temp is cleaned when beforeRename throws
    }],
    ['after-fence', (d) => {
      expect(fenceEntries(d)).toHaveLength(1);
      expect(existsSync(join(d, 'state.lock.3'))).toBe(false);
    }],
    ['after-release-temp', (d) => {
      expect(existsSync(join(d, 'state.lock.3'))).toBe(false);
      expect(fenceEntries(d)).toHaveLength(1);
      expect(files(d).some((f) => f.startsWith(`state.lock.tmp-${process.pid}-`))).toBe(true);
    }],
    ['after-release', (d) => expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).toMatchObject({ st: 'free', recoveredFrom: 1 })],
  ];
  it.each(shapes)('recovery: %s', (point, check) => {
    const d = tmp();
    lock(d, 1, deadOther());
    arm(point);
    expect(thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp })).message).toBe(`SIGKILL at ${point}`);
    check(d);
  });
  it('without NODE_ENV=test the same point does nothing', () => {
    const d = tmp();
    lock(d, 1, deadOther());
    const spy = arm('after-lock');
    process.env['NODE_ENV'] = 'production';
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: exp }).released).toBe(true);
    expect(spy.mock.calls.some((c) => c[1] === 'SIGKILL')).toBe(false);
  });
  const deadRecovery = (d: string) => lock(d, 2, { st: 'held', pid: DEAD_PID, host: hostname(), nonce: 'n-rec', recovering: 1, ...(myNs ? { ns: myNs } : {}) });
  it('takeover: takeover-after-lock (the taker holds its lock, carries the mark, has fenced nothing yet)', async () => {
    const d = tmp();
    deadRecovery(d);
    arm('takeover-after-lock');
    let e: unknown;
    await open(d).catch((x: unknown) => (e = x));
    expect((e as Error).message).toBe('SIGKILL at takeover-after-lock');
    expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).toMatchObject({ st: 'held', pid: process.pid, recovering: 1 });
    expect(fenceEntries(d)).toEqual([]);
  });
  it('takeover: takeover-after-fence-temp (the fence is not renamed)', async () => {
    const d = tmp();
    deadRecovery(d);
    arm('takeover-after-fence-temp');
    let e: unknown;
    await open(d).catch((x: unknown) => (e = x));
    expect((e as Error).message).toBe('SIGKILL at takeover-after-fence-temp');
    expect(fenceEntries(d)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('takeover of a dead lock: the `recovering` mark obliges a fence and is carried on; no mark, no fence', () => {
  it('a dead recovery lock: the taker fences at its own generation and marks its own lock', async () => {
    const d = tmp();
    const j = chain([1]);
    writeJ(d, j);
    writeH(d, { seq: 1, h: j[0]!.h, gen: 1 });
    lock(d, 2, { st: 'held', pid: DEAD_PID, host: hostname(), nonce: 'n-rec', recovering: 1, ...(myNs ? { ns: myNs } : {}) });
    const s = await open(d);
    expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).toMatchObject({ st: 'held', pid: process.pid, recovering: 1 });
    expect(fenceEntries(d).map((n) => readFenceEntry(d, n))).toEqual([expect.objectContaining({ gen: 3, seq: 1, h: j[0]!.h, from: 2 })]);
    await s.set('k', 1);
    expect(fenceEntries(d)).toHaveLength(1); // only the takeover fences, not every acquisition
  });
  it('an ordinary dead holder (no mark): no fence, no mark', async () => {
    const d = tmp();
    lock(d, 2, { st: 'held', pid: DEAD_PID, host: hostname(), nonce: 'n-x', ...(myNs ? { ns: myNs } : {}) });
    const s = await open(d);
    await s.set('k', 1);
    expect(fenceEntries(d)).toEqual([]);
    expect(existsSync(join(d, 'state.fence'))).toBe(false);
    expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).not.toHaveProperty('recovering');
  });
  it('a free top generation carrying a stray mark is not a takeover: no fence', async () => {
    const d = tmp();
    lock(d, 2, { st: 'free', recovering: 1 });
    await (await open(d)).set('k', 1);
    expect(fenceEntries(d)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('recoverDurableState: holder classification, liveness and attestation', () => {
  it('a top lock that is a JSON number is UNREADABLE (not an incomplete record)', () => {
    const d = tmp();
    lock(d, 1, '5');
    expect(thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp })).message).toBe(`invalid: ${join(d, 'state.lock.1')} is unreadable; pass expectedHolder: 'unreadable' to release it`);
  });
  it('the incomplete-record message quotes at most 160 characters of the record', () => {
    const d = tmp();
    const raw = { st: 'held', x: 'y'.repeat(400) };
    lock(d, 1, raw);
    const m = thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp })).message;
    expect(m).toContain(`has an incomplete holder record (${JSON.stringify(raw).slice(0, 160)}); after confirming`);
  });
  it.skipIf(!linux)('an incomplete record naming a LIVE process in this PID namespace is never released', () => {
    const d = tmp();
    lock(d, 1, { st: 'held', pid: process.pid, ns: myNs });
    expect(thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: 'unreadable' })).message).toBe(
      `invalid: the holder of ${join(d, 'state.lock.1')} (pid ${process.pid}) is alive in this PID namespace; refusing to release a live holder`,
    );
  });
  it.skipIf(!linux)('an incomplete record whose pid is not a number is not judged alive (released)', () => {
    const d = tmp();
    lock(d, 1, { st: 'held', pid: String(process.pid), ns: myNs });
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: 'unreadable' }).released).toBe(true);
  });
  it.skipIf(!linux)('the recovery lock records this process: pid, host, boot, ns and start exactly', () => {
    const d = tmp();
    lock(d, 1, deadOther());
    recoverDurableState({ dir: d, force: true, expectedHolder: exp });
    const b = JSON.parse(readFileSync(join(d, 'state.lock.2'), 'utf8')) as Record<string, unknown>;
    expect(b).toMatchObject({ st: 'held', pid: process.pid, host: hostname(), ns: myNs, start: startOf(process.pid), recovering: 1 });
    expect(typeof b['boot']).toBe('string');
    expect(b['nonce']).toMatch(/^[0-9a-f]{24}$/);
  });
});

describe('recoverDurableState: the legacy single-file lock', () => {
  const legacy = (d: string, body: unknown) => writeFileSync(join(d, 'state.lock'), typeof body === 'string' ? body : JSON.stringify(body));
  it('legacyLock with a FREE top generation still releases the legacy lock (the generation lock is not the blocker)', () => {
    const d = tmp();
    lock(d, 2, { st: 'free' });
    legacy(d, deadOther());
    expect(recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: exp })).toEqual({ released: true, reason: 'released', lockFile: join(d, 'state.lock') });
  });
  it('legacyLock when the blocker is a held generation lock: invalid', () => {
    const d = tmp();
    lock(d, 2, deadOther());
    legacy(d, deadOther());
    const e = thrown(() => recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: exp }));
    expect(e).toBeInstanceOf(DurableStateError);
    expect((e as DurableStateError).code).toBe('invalid');
  });
  it('a legacy lock marked free is not held', () => {
    const d = tmp();
    legacy(d, { st: 'free' });
    expect(recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: exp })).toEqual({ released: false, reason: 'not-held', lockFile: join(d, 'state.lock') });
    expect(existsSync(join(d, 'state.lock'))).toBe(true);
  });
  it('releasing it fences first (at the current tail), then moves it aside, then fsyncs the directory', () => {
    const d = tmp();
    const j = chain([1]);
    writeJ(d, j);
    legacy(d, deadOther());
    hooks.ev.length = 0;
    recoverDurableState({ dir: d, force: true, legacyLock: true, expectedHolder: exp });
    expect(fenceEntries(d).map((n) => readFenceEntry(d, n))).toEqual([expect.objectContaining({ gen: 1, seq: 1, h: j[0]!.h, from: 0 })]);
    const iFence = hooks.ev.findIndex((e) => e.op === 'rename' && /state\.fence\.1-/.test(e.to!));
    const iMove = hooks.ev.findIndex((e) => e.op === 'rename' && /state\.lock\.legacy-recovered-/.test(e.to!));
    expect(iFence).toBeGreaterThanOrEqual(0);
    expect(iMove).toBeGreaterThan(iFence);
    expect(hooks.ev.slice(iMove + 1).some((e) => e.op === 'fsync' && e.path === d)).toBe(true);
  });
  it.each([
    ['complete', JSON.stringify({ pid: 7, host: 'h-l', nonce: 'n-l' }), '(holder pid=7 host=h-l nonce=n-l)'],
    ['incomplete', JSON.stringify({ pid: 7 }), '(incomplete holder record)'],
    ['unreadable', '{nope', '(unreadable holder record)'],
  ])('without legacyLock, a %s legacy blocker is named in the refusal', (_k, body, who) => {
    const d = tmp();
    legacy(d, body);
    const e = thrown(() => recoverDurableState({ dir: d, force: true, expectedHolder: exp }));
    expect((e as DurableStateError).code).toBe('invalid');
    expect(e.message).toBe(`invalid: the blocking lock is the legacy single-file ${join(d, 'state.lock')} ${who}; after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')`);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('load(): generations', () => {
  it.each([0, -1, 1.5, '2'])('a record generation %s is an invalid shape', async (g) => {
    const d = tmp();
    const r = { ...rec(1, G0, 'k\n1', 1), gen: g };
    writeJ(d, [r]);
    await rej(open(d), 'corrupt: journal line 1 has an invalid shape');
  });
  it.each([0, -1, 1.5, '2'])('a head generation %s is an invalid shape', async (g) => {
    const d = tmp();
    const j = chain([1]);
    writeJ(d, j);
    writeH(d, { seq: 1, h: j[0]!.h, gen: g });
    await rej(open(d), 'corrupt: state.head has an invalid shape');
  });
  it('a decreasing generation names its line', async () => {
    const d = tmp();
    const j = chain([3, 1]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: j[1]!.h, gen: 3 });
    await rej(open(d), 'corrupt: journal line 2 (seq 2) was written by lock generation 1, older than generation 3 of an earlier record: a stale writer\'s record (refused)');
  });
  it('a fenced record names its line; a record AT the fence generation after the cut is accepted', async () => {
    const d = tmp();
    const j = chain([1, 2]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: j[1]!.h, gen: 2 });
    fenceFile(d, { gen: 3, seq: 1, h: j[0]!.h });
    await rej(
      open(d),
      'corrupt: journal line 2 (seq 2) was written by lock generation 2, but operator recovery fenced generations below 3 after seq 1: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)',
    );
    const e = tmp();
    const k = chain([1, 3]);
    writeJ(e, k);
    writeH(e, { seq: 2, h: k[1]!.h, gen: 3 });
    fenceFile(e, { gen: 3, seq: 1, h: k[0]!.h });
    expect(await (await open(e)).get('k2')).toBe(2);
  });
  it('a later generation compacted past the cut: the cut record is gone and that is accepted', async () => {
    const d = tmp();
    const cpPayload = JSON.stringify([['k', '1']]);
    const cp = rec(5, HEX, cpPayload, 4, 'checkpoint');
    writeJ(d, [cp]);
    writeH(d, { seq: 5, h: cp.h, gen: 4 });
    fenceFile(d, { gen: 3, seq: 2, h: HEX });
    expect(await (await open(d)).get('k')).toBe(1);
  });
});

describe('load(): a journal tail written by a generation older than the head\'s', () => {
  it('one record ahead of the head, from an older generation: refused (the head writer had the lock)', async () => {
    const d = tmp();
    const j = chain([2, 3]);
    writeJ(d, j);
    writeH(d, { seq: 1, h: j[0]!.h, gen: 5 });
    await rej(open(d), 'corrupt: journal tail (seq 2) was written by lock generation 3, older than generation 5 that wrote state.head: a stale writer replaced the journal (refused)');
  });
  it('a different record AT the head\'s position, from an older generation: refused with the same reason', async () => {
    const d = tmp();
    const j = chain([2, 3]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: HEX, gen: 5 });
    await rej(open(d), 'corrupt: journal tail (seq 2) was written by lock generation 3, older than generation 5 that wrote state.head: a stale writer replaced the journal (refused)');
  });
  it('the same record at the head from an older generation is fine; a legacy (no-gen) tail under a generation head is refused', async () => {
    const d = tmp();
    const j = chain([2, 3]);
    writeJ(d, j);
    writeH(d, { seq: 2, h: j[1]!.h, gen: 5 });
    expect(await (await open(d)).get('k2')).toBe(2);
    const e = tmp();
    const r1 = rec(1, G0, 'a\n1');
    writeJ(e, [r1, rec(2, r1.h, 'b\n2')]);
    writeH(e, { seq: 1, h: r1.h, gen: 5 });
    await rej(open(e), 'corrupt: journal tail (seq 2) was written by lock generation 0, older than generation 5 that wrote state.head: a stale writer replaced the journal (refused)');
  });
  it('two records ahead from an older generation is the generic "more than one record ahead" (not the tail rule)', async () => {
    const d = tmp();
    const j = chain([2, 3, 3]);
    writeJ(d, j);
    writeH(d, { seq: 1, h: j[0]!.h, gen: 5 });
    await rej(open(d), 'corrupt: journal (seq 3) is more than one record ahead of state.head (seq 1)');
  });
});

describe('load(): every conjunct of the stale-late-head rule', () => {
  // base: fence gen 5 cut at seq 2; records 1,2 from gen 1, records 3,4 from gen 5; head names record 2, written by gen 1
  const base = () => {
    const j = chain([1, 1, 5, 5]);
    return { j, fence: { gen: 5, seq: 2, h: j[1]!.h }, head: { seq: 2, h: j[1]!.h, gen: 1 } };
  };
  const run = (mut: (b: ReturnType<typeof base>) => void) => {
    const d = tmp();
    const b = base();
    mut(b);
    writeJ(d, b.j);
    writeH(d, b.head);
    fenceFile(d, b.fence);
    return d;
  };
  it('the recognised shape is repaired', async () => {
    const d = run(() => {});
    const s = await open(d);
    expect(await s.get('k4')).toBe(4);
    expect(JSON.parse(readFileSync(join(d, 'state.head'), 'utf8')).seq).toBe(4);
  });
  const corrupt = 'corrupt: journal (seq 4) is more than one record ahead of state.head (seq 2)';
  it('head generation NOT below the fence: refused', async () => {
    await rej(open(run((b) => (b.head.gen = 5))), corrupt);
  });
  it('head position AFTER the cut: refused', async () => {
    const d = tmp();
    const j = chain([1, 1, 1, 5, 5]);
    writeJ(d, j);
    writeH(d, { seq: 3, h: j[2]!.h, gen: 1 });
    fenceFile(d, { gen: 5, seq: 2, h: j[1]!.h });
    await rej(open(d), /fenced generations below 5 after seq 2/);
    // with record 3 from the fenced generation (so the fence passes), a head AFTER the cut is still refused
    const e = tmp();
    const k = chain([1, 1, 5, 5, 5]);
    writeJ(e, k);
    writeH(e, { seq: 3, h: k[2]!.h, gen: 1 });
    fenceFile(e, { gen: 5, seq: 2, h: k[1]!.h });
    await rej(open(e), 'corrupt: journal (seq 5) is more than one record ahead of state.head (seq 3)');
  });
  it('journal NOT extended past the cut: refused', async () => {
    await rej(open(run((b) => (b.fence = { gen: 5, seq: 4, h: b.j[3]!.h }))), corrupt);
  });
  it('the head names a record the journal does not hold (other hash at its seq): refused', async () => {
    await rej(open(run((b) => (b.head.h = HEX))), corrupt);
  });
  it('the head names another position\'s hash: refused', async () => {
    await rej(open(run((b) => (b.head.h = b.j[0]!.h))), corrupt);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('quarantine (recoverFromCorruption)', () => {
  it('a writer that lost the lock while loading moves nothing aside (lock-lost)', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.journal'), 'garbage\n');
    let fired = false;
    hooks.read = (p) => {
      if (!fired && p === join(d, 'state.journal')) {
        fired = true;
        const g = Math.max(...readdirSync(d).flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : [])));
        lock(d, g + 1, { st: 'held', pid: 1, host: 'other-host', nonce: 'n-other' });
      }
    };
    await rej(open(d, { recoverFromCorruption: true }), /^lock-lost: the state lock is no longer held by this writer/);
    expect(readFileSync(join(d, 'state.journal'), 'utf8')).toBe('garbage\n');
    expect(readdirSync(d).some((f) => f.includes('quarantine'))).toBe(false);
  });
  it('without any fence it writes none', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.journal'), 'garbage\n');
    const s = await open(d, { recoverFromCorruption: true });
    expect(s.recovered).toBe(true);
    expect(existsSync(join(d, 'state.fence'))).toBe(false);
    expect(fenceEntries(d)).toEqual([]);
  });
  it('with a fence list and one-fence files: keeps both aside and writes the genesis fence from the quarantining generation', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.journal'), 'garbage\n');
    const list = JSON.stringify({ v: 1, fences: [{ gen: 2, seq: 0, h: G0 }] });
    fenceList(d, list);
    fenceFile(d, { gen: 3, seq: 0, h: G0 }, 'cccccc');
    await open(d, { recoverFromCorruption: true });
    const q = readdirSync(d).find((f) => f.startsWith('state.fence.quarantine-'));
    expect(q && readFileSync(join(d, q), 'utf8')).toBe(list);
    expect(readdirSync(d).some((f) => /^state\.fence\.3-cccccc\.quarantine-/.test(f))).toBe(true);
    expect(fenceEntries(d)).toEqual([]);
    const g = JSON.parse(readFileSync(join(d, 'state.fence'), 'utf8')) as { fences: { gen: number; from: number; seq: number; h: string }[] };
    expect(g.fences).toHaveLength(1);
    expect(g.fences[0]).toMatchObject({ seq: 0, h: G0 });
    expect(g.fences[0]!.from).toBe(g.fences[0]!.gen - 1);
  });
});

// ---------------------------------------------------------------------------------------------------------------------
describe('lock-timeout names the real blocker', () => {
  it('a legacy blocker AND a live/unjudgeable generation holder: the generation lock is named', async () => {
    const d = tmp();
    writeFileSync(join(d, 'state.lock'), JSON.stringify(deadOther({ nonce: 'n-legacy' })));
    lock(d, 1, { st: 'held', pid: 7, host: 'other-host', nonce: 'n-gen' });
    const e = await rej(open(d, { lockTimeoutMs: 50 }), /^lock-timeout: /);
    expect(e.message).toContain(`blocked by ${join(d, 'state.lock.1')} (holder pid=7 host=other-host nonce=n-gen)`);
  });
  it('wrongly typed holder fields are reported as missing, not echoed', async () => {
    const d = tmp();
    lock(d, 1, { st: 'held', pid: '7', host: 5, nonce: 9 });
    const e = await rej(open(d, { lockTimeoutMs: 50 }), /^lock-timeout: /);
    expect(e.message).toContain("(an incomplete holder record (pid=? host=? nonce=?); release it with expectedHolder: 'unreadable')");
  });
});

describe('the head re-check reports what was and was not written', () => {
  const supersede = (d: string) => {
    const g = Math.max(...readdirSync(d).flatMap((f) => (/^state\.lock\.\d+$/.test(f) ? [Number(f.slice(11))] : [])));
    lock(d, g + 1, { st: 'held', pid: 1, host: 'other-host', nonce: 'n-other' });
  };
  it('lock lost after the journal rename: the head is NOT written and the error says the journal record landed', async () => {
    const d = tmp();
    const s = await open(d);
    await s.set('a', 1);
    const headBefore = readFileSync(join(d, 'state.head'), 'utf8');
    hooks.afterRename = (_f, to) => {
      if (to === join(d, 'state.journal')) supersede(d);
    };
    const e = await rej(s.set('b', 2), /^lock-lost: /);
    expect(e.message).toContain('; the journal record (seq 2) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)');
    expect(readFileSync(join(d, 'state.head'), 'utf8')).toBe(headBefore);
  });
  it('lock lost before a head REPAIR: nothing was written', async () => {
    const d = tmp();
    const j = chain([1, 1]);
    writeJ(d, j);
    writeH(d, { seq: 1, h: j[0]!.h, gen: 1 });
    const s = await openDurableState({ dir: d });
    writeH(d, { seq: 1, h: j[0]!.h, gen: 1 }); // lag the head again
    hooks.read = (p) => {
      if (p === join(d, 'state.journal')) {
        hooks.read = undefined;
        supersede(d);
      }
    };
    const e = await rej(s.set('c', 3), /^lock-lost: /);
    expect(e.message.endsWith('; nothing was written')).toBe(true);
  });
});
