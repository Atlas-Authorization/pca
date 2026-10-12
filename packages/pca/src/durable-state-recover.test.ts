import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDurableState, recoverDurableState } from './durable-state';

// R5-F1: a dead holder in another PID namespace (or an unreadable top lock) gives lock-timeout forever. The operator
// recovery path releases it only when the caller proves it looked at THIS lock (host, pid, nonce all match).
const dirs: string[] = [];
const mk = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-recover-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const DEAD_PID = 4_194_000;
const other = { st: 'held', pid: DEAD_PID, host: hostname(), nonce: 'n-abc', ns: 'pid:[4026539999]', boot: 'b', t: Date.now() };
const forge = (d: string, body: Record<string, unknown>, g = 1) => writeFileSync(join(d, `state.lock.${g}`), JSON.stringify(body), { mode: 0o600 });
const holder = { host: hostname(), pid: DEAD_PID, nonce: 'n-abc' };

describe('R5-F1 recoverDurableState', () => {
  it('the lock-timeout error names the lock file, the holder, and the recovery API', async () => {
    const d = mk();
    forge(d, other);
    const e = await openDurableState({ dir: d, lockTimeoutMs: 100 }).catch((x) => x as Error);
    expect(e).toMatchObject({ code: 'lock-timeout' });
    expect((e as Error).message).toContain(join(d, 'state.lock.1'));
    expect((e as Error).message).toContain('n-abc');
    expect((e as Error).message).toContain('recoverDurableState');
  });

  it('releases a dead other-namespace holder with the exact expectedHolder, then opens and keeps state', async () => {
    const d = mk();
    forge(d, other);
    await expect(openDurableState({ dir: d, lockTimeoutMs: 100 })).rejects.toMatchObject({ code: 'lock-timeout' });
    const r = recoverDurableState({ dir: d, force: true, expectedHolder: holder });
    expect(r).toMatchObject({ released: true, reason: 'released' });
    const h = await openDurableState({ dir: d, lockTimeoutMs: 1000 });
    await h.set('k', 'v');
    expect(await h.get('k')).toBe('v');
  });

  it.each([
    ['wrong pid', { pid: DEAD_PID + 1 }],
    ['wrong host', { host: 'elsewhere' }],
    ['wrong nonce', { nonce: 'n-other' }],
    ['empty nonce', { nonce: '' }],
  ])('refuses a mismatching expectedHolder (%s) and changes nothing', async (_n, delta) => {
    const d = mk();
    forge(d, other);
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: { ...holder, ...delta } })).toThrow(/invalid/);
    expect(readdirSync(d)).toEqual(['state.lock.1']);
  });

  it('requires force: true and a well-formed expectedHolder', () => {
    const d = mk();
    forge(d, other);
    expect(() => recoverDurableState({ dir: d, force: false as unknown as true, expectedHolder: holder })).toThrow(/force: true/);
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: { host: 'x' } as never })).toThrow(/expectedHolder/);
    expect(readdirSync(d)).toEqual(['state.lock.1']);
  });

  it('never robs a live same-namespace holder, even with a matching expectedHolder', async () => {
    const d = mk();
    const live = { st: 'held', pid: process.pid, host: hostname(), nonce: 'n-live', t: Date.now() };
    forge(d, live);
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: { host: hostname(), pid: process.pid, nonce: 'n-live' } })).toThrow(/alive/);
    expect(readdirSync(d)).toEqual(['state.lock.1']);
  });

  it('releases an unreadable (empty) top lock only with expectedHolder "unreadable"', async () => {
    const d = mk();
    writeFileSync(join(d, 'state.lock.1'), '');
    await expect(openDurableState({ dir: d, lockTimeoutMs: 100 })).rejects.toMatchObject({ code: 'lock-timeout' });
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: holder })).toThrow(/unreadable/);
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: 'unreadable' }).released).toBe(true);
    await expect(openDurableState({ dir: d, lockTimeoutMs: 1000 })).resolves.toBeDefined();
  });

  it("'unreadable' cannot release a readable held lock", () => {
    const d = mk();
    forge(d, other);
    expect(() => recoverDurableState({ dir: d, force: true, expectedHolder: 'unreadable' })).toThrow(/does not match/);
  });

  it('is a no-op on a free or absent lock, and the old holder cannot resume after recovery', async () => {
    const d = mk();
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: holder })).toMatchObject({ released: false, reason: 'not-held' });
    forge(d, other);
    recoverDurableState({ dir: d, force: true, expectedHolder: holder });
    expect(recoverDurableState({ dir: d, force: true, expectedHolder: holder })).toMatchObject({ released: false, reason: 'not-held' });
    // R6-CORE-01: recovery takes the lock itself (generation 2), cuts and fences, then releases (generation 3)
    const g2 = JSON.parse(readFileSync(join(d, 'state.lock.2'), 'utf8'));
    expect(g2).toMatchObject({ st: 'held', pid: process.pid, recovering: 1 });
    expect(JSON.parse(readFileSync(join(d, 'state.lock.3'), 'utf8'))).toMatchObject({ st: 'free', recoveredFrom: 1 });
  });
});
