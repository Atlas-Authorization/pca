import { hostname, tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { openDurableState } from './durable-state';

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('a non-finite lock timeout never waits forever (durable-state)', () => {
  // old `Date.now() > deadline` was false for a NaN deadline, so a held lock was waited on without end
  // (-Infinity times out at once either way; +Infinity is the legitimate wait-forever cap and is not exercised here)
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('a lockTimeoutMs of %s fails closed with lock-timeout', async (lockTimeoutMs) => {
    const d = mkdtempSync(join(tmpdir(), 'pca-durable-inf-'));
    dirs.push(d);
    await openDurableState({ dir: d });
    writeFileSync(join(d, 'state.lock'), JSON.stringify({ pid: process.pid, host: hostname(), nonce: 'x', t: Date.now() }), { mode: 0o600 });
    await expect(openDurableState({ dir: d, lockTimeoutMs })).rejects.toMatchObject({ code: 'lock-timeout' });
  });
});
