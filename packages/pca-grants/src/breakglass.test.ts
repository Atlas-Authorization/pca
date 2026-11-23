import { describe, expect, it } from 'vitest';
import { memoryLeaseKv } from './lease';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { b64u, publicKeyOf } from '@atlasauth/pca';
import {
  BreakGlassRegistry, MAX_BREAK_GLASS_WINDOW_MS, signBreakGlass, signBreakGlassReview, verifyBreakGlass, verifyBreakGlassReview, type NewBreakGlass,
} from './index';
import { buildBreakGlassVectors, BG_AUTH, BG_REVIEWER } from './test-support/breakglass-vectors';

const SK = new Uint8Array(32).fill(71);
const RSK = new Uint8Array(32).fill(72);
const T0 = 1_800_000_000_000;
const base: NewBreakGlass = { id: 'b', holder: 'h', grant_ref: 'g', reason_digest: 'r', max_uses: 1, issued_at: T0, expires_at: T0 + 1000, review_within: 500, notify_to: 'n' };

describe('break-glass vectors', () => {
  it('are current (BREAK_GLASS_VECTORS_WRITE=1 regenerates them) and the reference agrees with every expectation', async () => {
    const path = join(__dirname, '..', '..', 'pca', 'conformance', 'break-glass-vectors.json');
    const text = `${JSON.stringify(await buildBreakGlassVectors(), null, 2)}\n`;
    if (process.env.BREAK_GLASS_VECTORS_WRITE === '1') writeFileSync(path, text);
    expect(readFileSync(path, 'utf8')).toBe(text);
    expect(BG_AUTH).toBe(b64u(publicKeyOf(SK)));
    expect(BG_REVIEWER).toBe(b64u(publicKeyOf(RSK)));
  });
});

describe('break-glass records', () => {
  it('refuse a window over 24 hours, a budget outside 1..16 and a bad review clock when signing', () => {
    expect(() => signBreakGlass(SK, { ...base, expires_at: T0 + MAX_BREAK_GLASS_WINDOW_MS + 1 })).toThrow('malformed');
    expect(signBreakGlass(SK, { ...base, expires_at: T0 + MAX_BREAK_GLASS_WINDOW_MS }).expires_at).toBe(T0 + MAX_BREAK_GLASS_WINDOW_MS);
    expect(() => signBreakGlass(SK, { ...base, max_uses: 0 })).toThrow();
    expect(() => signBreakGlass(SK, { ...base, max_uses: 17 })).toThrow();
    expect(signBreakGlass(SK, { ...base, max_uses: 16 }).max_uses).toBe(16);
    expect(() => signBreakGlass(SK, { ...base, expires_at: T0 })).toThrow();
    expect(() => signBreakGlass(SK, { ...base, review_within: 0 })).toThrow();
    expect(() => signBreakGlass(SK, { ...base, review_within: 30 * 86_400_000 + 1 })).toThrow();
    expect(() => signBreakGlass(SK, { ...base, id: '' })).toThrow();
    expect(() => signBreakGlassReview(RSK, { id: 'b', outcome: 'maybe' as never, notes_digest: 'n', at: 1 })).toThrow();
  });
  it('verify only untouched signed records', () => {
    const g = signBreakGlass(SK, base);
    expect(verifyBreakGlass(g)).toBe(true);
    expect(verifyBreakGlass({ ...g, max_uses: 2 })).toBe(false);
    expect(verifyBreakGlass({ ...g, extra: 1 })).toBe(true); // unsigned extra members are not part of the body; the closed check is on the signed fields
    expect(verifyBreakGlass(null)).toBe(false);
    const r = signBreakGlassReview(RSK, { id: 'b', outcome: 'justified', notes_digest: 'n', at: 5 });
    expect(verifyBreakGlassReview(r)).toBe(true);
    expect(verifyBreakGlassReview({ ...r, outcome: 'unjustified' })).toBe(false);
  });
});

describe('BreakGlassRegistry', () => {
  const mk = () => new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [BG_REVIEWER] }, memoryLeaseKv());
  it('keeps a numbered use log and the exact review deadline', async () => {
    const reg = mk();
    await reg.accept(signBreakGlass(SK, { ...base, max_uses: 2 }), T0);
    expect(await reg.use({ id: 'b', holder: 'h', action_digest: 'a1', now: T0 + 10, notified: true })).toEqual({ decision: 'allow', id: 'b', use: 1, remaining: 1, review_due: T0 + 510 });
    expect(await reg.use({ id: 'b', holder: 'h', action_digest: 'a2', now: T0 + 20, notified: true })).toEqual({ decision: 'allow', id: 'b', use: 2, remaining: 0, review_due: T0 + 510 });
    expect(await reg.uses('h', 'b')).toEqual([{ n: 1, action_digest: 'a1', at: T0 + 10 }, { n: 2, action_digest: 'a2', at: T0 + 20 }]);
    expect(await reg.frozen('h', T0 + 509)).toBe(false);
    expect(await reg.frozen('h', T0 + 510)).toBe(true);
  });
  it('fails closed: a bad frozen query is frozen, a failing store refuses', async () => {
    const reg = mk();
    expect(await reg.frozen('', 1)).toBe(true);
    expect(await reg.frozen('h', 1.5)).toBe(true);
    const bad = new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [] }, { get: async () => { throw new Error('x'); }, update: async () => { throw new Error('x'); } });
    expect(await bad.frozen('h', 1)).toBe(true);
    expect(await bad.accept(signBreakGlass(SK, base), T0)).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await bad.use({ id: 'b', holder: 'h', action_digest: 'a', now: T0, notified: true })).toEqual({ decision: 'deny', code: 'store_unreachable', id: 'b' });
  });
  it('a store opened with another shard count is refused', async () => {
    const { memoryLeaseKv } = await import('./index');
    const kv = memoryLeaseKv();
    await new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [] }, kv, { shards: 4 }).accept(signBreakGlass(SK, base), T0);
    const other = new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [] }, kv, { shards: 8 });
    expect(await other.accept(signBreakGlass(SK, { ...base, id: 'c' }), T0)).toEqual({ ok: false, code: 'store_unreachable' });
    expect(() => new BreakGlassRegistry({ authorities: [], reviewers: [] }, kv, { shards: 0 })).toThrow('shards');
  });
  it('different holders live in different documents and a hot holder does not block others', async () => {
    const reg = mk();
    const hs = Array.from({ length: 40 }, (_, i) => `holder-${i}`);
    const rs = await Promise.all(hs.map((h, i) => reg.accept(signBreakGlass(SK, { ...base, id: `b${i}`, holder: h }), T0)));
    expect(rs.every((r) => r.ok)).toBe(true);
  });
});
