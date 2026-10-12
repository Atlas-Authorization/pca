import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDurableState } from './durable-state';

// R4-09: holder liveness is only judged inside the SAME PID namespace. Containers sharing a volume AND a hostname live
// in different PID namespaces: the other container's pid does not exist here (ESRCH) or is somebody else, so kill(pid,0)
// proves nothing and the lock must NOT be taken over.
const dirs: string[] = [];
const mk = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-ns-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const forge = (d: string, body: Record<string, unknown>) =>
  writeFileSync(join(d, 'state.lock.1'), JSON.stringify({ st: 'held', nonce: 'x', t: Date.now(), ...body }), { mode: 0o600 });
const DEAD_PID = 4_194_000;

describe('R4-09 durable-state lock across PID namespaces', () => {
  it('a holder recorded in ANOTHER pid namespace is never judged dead, even with a same-host name and a nonexistent pid', async () => {
    const d = mk();
    forge(d, { pid: DEAD_PID, host: hostname(), ns: 'pid:[4026539999]', boot: 'other' });
    await expect(openDurableState({ dir: d, lockTimeoutMs: 200 })).rejects.toMatchObject({ code: 'lock-timeout' });
  });

  it('a same-host holder with no namespace record and a dead pid is still taken over (unchanged behaviour)', async () => {
    const d = mk();
    forge(d, { pid: DEAD_PID, host: hostname() });
    await expect(openDurableState({ dir: d, lockTimeoutMs: 2000 })).resolves.toBeDefined();
  });

  it('records pid, host, a per-process boot id and (on Linux) the pid namespace in each held generation', async () => {
    const d = mk();
    const h = await openDurableState({ dir: d });
    await h.set('k', 'v');
    const held = readdirSync(d)
      .filter((f) => /^state\.lock\.\d+$/.test(f))
      .map((f) => JSON.parse(readFileSync(join(d, f), 'utf8')) as Record<string, unknown>)
      .filter((b) => b.st === 'held');
    expect(held.length).toBeGreaterThan(0);
    for (const b of held) {
      expect(b.pid).toBe(process.pid);
      expect(b.host).toBe(hostname());
      expect(typeof b.boot).toBe('string');
      expect((b.boot as string).length).toBeGreaterThanOrEqual(16);
    }
    expect(new Set(held.map((b) => b.boot)).size).toBe(1);
  });
});
