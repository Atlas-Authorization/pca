/**
 * r13 mutation kills for durable-state.ts module-level constants and helper arrows (static mutants; each test re-evaluates
 * the module): the journal record hash (DOMAIN, GENESIS, sha, recHash), the HMAC tags (macOf, headMsg) checked against
 * node:crypto directly, macEq / isGen / HEX64 through a reopen and exact refusals of tampered files, the fence file
 * names (FENCE_FILE / FENCE_ENTRY: decoy names are ignored, a real-looking fence name is read and fails closed) and
 * RECOVER_CRASH_ENV.
 */
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./durable-state');
}
const settleAsync = async <T>(f: () => Promise<T>) => {
  try {
    return { ok: true as const, value: await f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const dirs: string[] = [];
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-g7-durable-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const KEY = new Uint8Array(32).fill(9);
const J = (d: string) => join(d, 'state.journal');
const H = (d: string) => join(d, 'state.head');
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const hmac = (msg: string) => createHmac('sha256', KEY).update(msg).digest('hex');

/** A fresh store with one record; a mutant that breaks writing fails the outcome assertion here, not with an error. */
async function seeded() {
  const m = await fresh();
  const d = tmp();
  const r = await settleAsync(async () => {
    const s = await m.openDurableState({ dir: d, hmacKey: KEY, now: () => 1234 });
    await s.set('k', { a: 1 });
    return 'written';
  });
  expect(r).toEqual({ ok: true, value: 'written' });
  return { m, d };
}

describe('durable-state constants (fresh module)', () => {
  it('RECOVER_CRASH_ENV', async () => {
    expect((await fresh()).RECOVER_CRASH_ENV).toBe('PCA_DURABLE_TEST_RECOVER_CRASH_AT');
  });

  it('records chain from 64 zeros under sha256("pca-durable-state/v1\\n" + JSON) and are HMAC-tagged; the head too', async () => {
    const { d } = await seeded();
    const recs = readFileSync(J(d), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(recs).toHaveLength(1);
    const r = recs[0];
    expect(r.prev).toBe('0'.repeat(64));
    expect(r.h).toBe(sha('pca-durable-state/v1\n' + JSON.stringify([r.seq, r.prev, r.op, r.payload, r.ts, r.gen])));
    expect(r.mac).toBe(hmac(r.h));
    expect([r.seq, r.op, r.payload, r.ts]).toEqual([1, 'set', 'k\n{"a":1}', 1234]);
    const head = JSON.parse(readFileSync(H(d), 'utf8'));
    expect(head.mac).toBe(hmac(`head\n${head.seq}\n${head.h}\n${head.gen}`));
  });

  it('reopens with the right key and refuses the wrong one', async () => {
    const { d } = await seeded();
    const m = await fresh();
    expect(await settleAsync(async () => (await m.openDurableState({ dir: d, hmacKey: KEY })).get('k'))).toEqual({ ok: true, value: { a: 1 } });
    const r = await settleAsync(async () => (await m.openDurableState({ dir: d, hmacKey: new Uint8Array(32).fill(8) })).get('k'));
    expect(r).toEqual({ ok: false, error: { name: 'DurableStateError', message: 'key-mismatch: state.head MAC does not verify (wrong key or forged head)' } });
  });

  it('a hash field with a prefix or a suffix is a shape error, not a later mismatch', async () => {
    for (const edit of [(r: Record<string, string>) => ({ ...r, prev: 'x' + r.prev }), (r: Record<string, string>) => ({ ...r, h: r.h + 'x' })]) {
      const { d } = await seeded();
      const r = JSON.parse(readFileSync(J(d), 'utf8').trim());
      writeFileSync(J(d), JSON.stringify(edit(r)) + '\n');
      const m = await fresh();
      expect(await settleAsync(async () => (await m.openDurableState({ dir: d })).get('k'))).toEqual({
        ok: false,
        error: { name: 'DurableStateError', message: 'corrupt: journal line 1 has an invalid shape' },
      });
    }
    const { d } = await seeded();
    const head = JSON.parse(readFileSync(H(d), 'utf8'));
    writeFileSync(H(d), JSON.stringify({ ...head, h: 'x' + head.h }) + '\n');
    const m = await fresh();
    expect(await settleAsync(async () => (await m.openDurableState({ dir: d })).get('k'))).toEqual({
      ok: false,
      error: { name: 'DurableStateError', message: 'corrupt: state.head has an invalid shape' },
    });
  });

  it('only exact state.fence.<gen>-<hex> names are fences', async () => {
    for (const decoy of ['xstate.fence.1-ab', 'state.fence.1-ab.tmp', 'state.fence.1-xy']) {
      const { d } = await seeded();
      writeFileSync(join(d, decoy), 'not json');
      const m = await fresh();
      expect([decoy, await settleAsync(async () => (await m.openDurableState({ dir: d, hmacKey: KEY })).get('k'))]).toEqual([decoy, { ok: true, value: { a: 1 } }]);
    }
    const { d } = await seeded();
    writeFileSync(join(d, 'state.fence.12-abcdef0123'), 'not json');
    const m = await fresh();
    expect(await settleAsync(async () => (await m.openDurableState({ dir: d, hmacKey: KEY })).get('k'))).toEqual({
      ok: false,
      error: { name: 'DurableStateError', message: 'corrupt: state.fence.12-abcdef0123 is not valid JSON' },
    });
  });
});
