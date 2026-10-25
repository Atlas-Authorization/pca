/**
 * r13 g6 kill for launch-local.ts: when a node process closes, the launcher clears that node's kill timer (otherwise every
 * finished launch leaves a pending SIGKILL timer of killAfterMs behind). The timers are observed through spies that call
 * through to the real setTimeout / clearTimeout; a unique killAfterMs identifies the launcher's own kill timers.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { launchLocal } from './launch-local';
import { T } from './test-timing';

let dir = '';
let quickJs = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'pca-launch-timer-'));
  quickJs = join(dir, 'quick.js');
  writeFileSync(quickJs, `process.stdout.write('{"done":true}\\n');\n`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('launchLocal kill timers', () => {
  it('every node kill timer is cleared once its process has closed', async () => {
    const KILL_AFTER = 987_653;
    const realSet = globalThis.setTimeout;
    const created: unknown[] = [];
    const setSpy = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((fn: () => void, ms?: number, ...a: unknown[]) => {
      const h = realSet(fn, ms, ...a);
      if (ms === T(KILL_AFTER)) created.push(h);
      return h;
    }) as typeof setTimeout);
    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
    try {
      const r = await launchLocal({ n: 1, vectors: [{ allow: 1, t: 1, rQuant: 2 }], mainJs: quickJs, offline: 'no-dealer', killAfterMs: KILL_AFTER });
      expect(r.outputs.map((o) => [o.id, o.exitCode, o.json])).toEqual([[0, 0, { done: true }]]);
      const cleared = new Set(clearSpy.mock.calls.map((c) => c[0]));
      expect(created.length).toBe(1);
      expect(created.map((h) => cleared.has(h as never))).toEqual([true]);
    } finally {
      for (const h of created) clearTimeout(h as never);
      setSpy.mockRestore();
      clearSpy.mockRestore();
    }
  });
});
