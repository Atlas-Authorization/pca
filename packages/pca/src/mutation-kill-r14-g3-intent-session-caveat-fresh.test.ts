/**
 * r14 (g3) static-mutant kills for intent-session-caveat.ts: INTENT_SESSION_CAVEAT and the module-level helpers (isObj,
 * isNonNeg, b32) are built once at import. Each test re-evaluates the module (vi.resetModules + dynamic import) and
 * replays the pinned caveat tables (killSession, k042-sessrevoc-cases) through it, exact reasons.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { assert, describe, expect, it, vi } from 'vitest';

const load = (f: string): any => JSON.parse(gunzipSync(readFileSync(resolve(__dirname, '..', 'testdata', f))).toString('utf8'));
const toTs = (x: any): any => {
  if (Array.isArray(x)) return x.map(toTs);
  if (x && typeof x === 'object') { const o: any = {}; for (const [k, v] of Object.entries(x)) o[k] = toTs(v); return o; }
  return x;
};
async function fresh() {
  vi.resetModules();
  const m = await import('./intent-session-caveat');
  const check = (c: unknown) => { try { return m.intentSessionCaveatError(c); } catch (e) { return assert.fail(`intentSessionCaveatError threw: ${(e as Error).message}`); } };
  return { m, check };
}

describe('intent-session-caveat.ts (fresh module)', () => {
  it('the caveat type constant', async () => {
    const { m, check } = await fresh();
    expect(m.INTENT_SESSION_CAVEAT).toBe('intent_session');
    expect(m.MAX_SESSION_SEQ).toBe(2_147_483_647);
    const d = 'A'.repeat(43);
    expect(check({ type: 'intent_session', session: d, seq: 0, root: d })).toBeNull();
    expect(check({ type: '', session: d, seq: 0, root: d })).toBe('not an intent_session caveat');
  });
  it('the golden caveat tables, exact reasons', async () => {
    const { check } = await fresh();
    for (const c of load('killSession.json.gz').caveat) expect(check(toTs(c.arg)), c.name).toBe(c.ts);
    for (const c of load('k042-sessrevoc-cases.json.gz').caveat) expect(check(JSON.parse(c.c)), c.name).toBe(c.reason);
  });
});
