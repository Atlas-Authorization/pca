import { describe, expect, it } from 'vitest';
import { memoryLeaseKv } from './lease';
import { BreakGlassRegistry, MAX_BREAK_GLASS_USES, MAX_BREAK_GLASS_WINDOW_MS, MAX_REVIEW_WITHIN_MS, signBreakGlass, signBreakGlassReview, type NewBreakGlass } from './index';
import { BG_AUTH, BG_REVIEWER } from './test-support/breakglass-vectors';

const SK = new Uint8Array(32).fill(71);
const RSK = new Uint8Array(32).fill(72);
const T0 = 1_800_000_000_000;
const base: NewBreakGlass = { id: 'b', holder: 'h', grant_ref: 'g', reason_digest: 'r', max_uses: 2, issued_at: T0, expires_at: T0 + 1000, review_within: 500, notify_to: 'n' };
// one shard, so a use by the wrong holder reaches the record and is refused as wrong_holder, not as unknown
const mk = () => new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [BG_REVIEWER] }, memoryLeaseKv(), { shards: 1 });

describe('break-glass: pinned limits', () => {
  it('window, use budget and review window', () => {
    expect(MAX_BREAK_GLASS_WINDOW_MS).toBe(86_400_000);
    expect(MAX_BREAK_GLASS_USES).toBe(16);
    expect(MAX_REVIEW_WITHIN_MS).toBe(30 * 86_400_000);
  });
});

describe('break-glass registry: missing X gives exact result Y', () => {
  it('accept: a non-integer clock or an unsigned record is bad_record; an unpinned authority is unknown_authority', async () => {
    const rec = signBreakGlass(SK, base);
    expect(await mk().accept(rec, 1.5)).toEqual({ ok: false, code: 'bad_record' });
    expect(await mk().accept(rec, -1)).toEqual({ ok: false, code: 'bad_record' });
    expect(await mk().accept({ ...rec, max_uses: 3 }, T0)).toEqual({ ok: false, code: 'bad_record' });
    expect(await new BreakGlassRegistry({ authorities: [], reviewers: [] }, memoryLeaseKv()).accept(rec, T0)).toEqual({ ok: false, code: 'unknown_authority' });
  });
  it('accept: the same record again is a no-op; a different record under the same id is id_conflict', async () => {
    const reg = mk();
    const rec = signBreakGlass(SK, base);
    expect(await reg.accept(rec, T0)).toEqual({ ok: true, replaced: true });
    expect(await reg.accept(rec, T0)).toEqual({ ok: true, replaced: false });
    expect(await reg.accept(signBreakGlass(SK, { ...base, max_uses: 3 }), T0)).toEqual({ ok: false, code: 'id_conflict' });
  });
  it('use: another holder presenting the id is wrong_holder and spends nothing', async () => {
    const reg = mk();
    await reg.accept(signBreakGlass(SK, base), T0);
    expect(await reg.use({ id: 'b', holder: 'x', action_digest: 'a', now: T0 + 1, notified: true })).toEqual({ decision: 'deny', code: 'wrong_holder', id: 'b' });
    expect(await reg.uses('h', 'b')).toEqual([]);
  });
  it('use: every malformed input is bad_input, including a missing argument and a non-boolean notified flag', async () => {
    const reg = mk();
    await reg.accept(signBreakGlass(SK, base), T0);
    const ok = { id: 'b', holder: 'h', action_digest: 'a', now: T0 + 1, notified: true };
    for (const bad of [undefined, null, { ...ok, id: '' }, { ...ok, holder: 5 }, { ...ok, action_digest: '' }, { ...ok, now: 1.5 }, { ...ok, now: -1 }, { ...ok, notified: 'yes' }, { ...ok, notified: undefined }]) {
      expect(await reg.use(bad as never)).toEqual({ decision: 'deny', code: 'bad_input' });
    }
    expect(await reg.uses('h', 'b')).toEqual([]);
  });
  it('use: an unknown id, an id not yet valid, an expired window, a spent budget and a missing notification each deny with their own code and spend nothing', async () => {
    const reg = mk();
    await reg.accept(signBreakGlass(SK, base), T0);
    const u = (over: object) => reg.use({ id: 'b', holder: 'h', action_digest: 'a', now: T0 + 1, notified: true, ...over });
    expect(await u({ id: 'nope' })).toEqual({ decision: 'deny', code: 'unknown_break_glass', id: 'nope' });
    expect(await u({ now: T0 - 1 })).toEqual({ decision: 'deny', code: 'not_yet_valid', id: 'b' });
    expect(await u({ now: T0 + 1000 })).toEqual({ decision: 'deny', code: 'expired', id: 'b' });
    expect(await u({ notified: false })).toEqual({ decision: 'deny', code: 'not_notified', id: 'b' });
    expect(await reg.uses('h', 'b')).toEqual([]);
    expect((await u({})).decision).toBe('allow');
    expect((await u({})).decision).toBe('allow');
    expect(await u({})).toEqual({ decision: 'deny', code: 'budget_exhausted', id: 'b' });
    expect((await reg.uses('h', 'b')).length).toBe(2);
  });
  it('review: a reviewer that is the holder or the issuing authority is sod; an unpinned reviewer is unknown_reviewer; a malformed review is bad_record', async () => {
    const reg = mk();
    await reg.accept(signBreakGlass(SK, { ...base, holder: BG_REVIEWER }), T0);
    const rev = signBreakGlassReview(RSK, { id: 'b', outcome: 'justified', notes_digest: 'n', at: T0 + 5 });
    expect(await reg.review(rev, BG_REVIEWER, T0 + 10)).toEqual({ ok: false, code: 'sod' });
    expect(await reg.review({ ...rev, outcome: 'unjustified' }, BG_REVIEWER, T0 + 10)).toEqual({ ok: false, code: 'bad_record' });
    expect(await reg.review(rev, '', T0 + 10)).toEqual({ ok: false, code: 'bad_record' });
    expect(await reg.review(rev, BG_REVIEWER, 1.5)).toEqual({ ok: false, code: 'bad_record' });
    expect(await new BreakGlassRegistry({ authorities: [BG_AUTH], reviewers: [] }, memoryLeaseKv()).review(rev, 'h', T0 + 10)).toEqual({ ok: false, code: 'unknown_reviewer' });
    expect(await reg.review(rev, 'someone-else', T0 + 10)).toEqual({ ok: false, code: 'unknown_break_glass' });
  });
});
