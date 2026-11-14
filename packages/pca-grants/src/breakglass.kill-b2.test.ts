import { describe, expect, it } from 'vitest';
import { memoryLeaseKv, type LeaseKv } from './lease';
import { signerOf } from './sig';
import { BreakGlassRegistry, MAX_REVIEW_WITHIN_MS, signBreakGlass, signBreakGlassReview, verifyBreakGlassReview, type NewBreakGlass } from './breakglass';

const SK = new Uint8Array(32).fill(81);
const RSK = new Uint8Array(32).fill(82);
const T0 = 1_800_000_000_000;
const base: NewBreakGlass = { id: 'b', holder: 'h', grant_ref: 'g', reason_digest: 'r', max_uses: 2, issued_at: T0, expires_at: T0 + 100_000, review_within: 500, notify_to: 'n' };
const policy = { authorities: [signerOf(SK)], reviewers: [signerOf(RSK)] };
const review = (over: Record<string, unknown> = {}) => signBreakGlassReview(RSK, { id: 'b', outcome: 'justified', notes_digest: 'n', at: T0 + 5, ...over } as never);
const useIn = (id = 'b', holder = 'h', now = T0 + 1) => ({ id, holder, action_digest: 'd', now, notified: true });
const mkReg = (kv: LeaseKv = memoryLeaseKv(), shards?: number) => new BreakGlassRegistry(policy, kv, shards === undefined ? {} : { shards });
const mismatched = async () => {
  const kv = memoryLeaseKv();
  await kv.update('breakglass/meta', () => ({ v: 1, shards: 8 }));
  return kv;
};
/** A store whose shard writes run and then fail, once armed. */
const failAfter = (kv: LeaseKv, armed: { on: boolean }): LeaseKv => ({
  get: (k) => kv.get(k),
  update: async (k, fn) => {
    const r = await kv.update(k, fn);
    if (armed.on && k !== 'breakglass/meta') throw new Error('write failed');
    return r;
  },
});

describe('break-glass record shape', () => {
  it('review clock bounds are inclusive', () => {
    expect(signBreakGlass(SK, { ...base, review_within: 1 }).review_within).toBe(1);
    expect(signBreakGlass(SK, { ...base, review_within: MAX_REVIEW_WITHIN_MS }).review_within).toBe(MAX_REVIEW_WITHIN_MS);
  });
  it.each([
    ['wrong version', { v: 2 }],
    ['fractional expires_at', { issued_at: 1000, expires_at: 1500.5 }],
    ['negative issued_at', { issued_at: -1, expires_at: 1000 }],
  ])('signing refuses %s', (_n, over) => {
    expect(() => signBreakGlass(SK, { ...base, ...over } as never)).toThrow('malformed');
  });
});

describe('break-glass review records', () => {
  it('signing refuses a malformed review with the exact message', () => {
    for (const over of [{ v: 2 }, { id: '' }, { outcome: 'maybe' }, { notes_digest: '' }, { at: -1 }]) {
      expect(() => review(over), JSON.stringify(over)).toThrow(new RangeError('signBreakGlassReview: malformed'));
    }
  });
  it('verify refuses anything that is not a well-formed signed review', () => {
    for (const x of [null, undefined, 5, {}, { ...review(), id: '' }, { ...review(), outcome: 'maybe' }]) expect(verifyBreakGlassReview(x)).toBe(false);
    expect(verifyBreakGlassReview(review())).toBe(true);
  });
});

describe('BreakGlassRegistry construction and meta', () => {
  it('needs a store with get and update', () => {
    const msg = 'BreakGlassRegistry: a durable key-value store is required (memoryLeaseKv() is for tests and single-process use)';
    const kv = memoryLeaseKv();
    expect(() => mkReg(undefined as never)).not.toThrow(); // default kv
    expect(() => new BreakGlassRegistry(policy, undefined as never)).toThrow(new TypeError(msg));
    expect(() => new BreakGlassRegistry(policy, { update: kv.update } as never)).toThrow(new TypeError(msg));
    expect(() => new BreakGlassRegistry(policy, { get: kv.get } as never)).toThrow(new TypeError(msg));
  });
  it('the shard count is 1..4096', () => {
    const msg = new RangeError('BreakGlassRegistry: shards must be an integer from 1 to 4096');
    expect(() => mkReg(memoryLeaseKv(), 4097)).toThrow(msg);
    expect(() => mkReg(memoryLeaseKv(), 0)).toThrow(msg);
    expect(() => mkReg(memoryLeaseKv(), 4096)).not.toThrow();
  });
  it('pins the shard count under breakglass/meta', async () => {
    const keys: string[] = [];
    const inner = memoryLeaseKv();
    const kv: LeaseKv = { get: (k) => inner.get(k), update: (k, fn) => (keys.push(k), inner.update(k, fn)) };
    await mkReg(kv, 4).frozen('h', T0);
    expect(keys[0]).toBe('breakglass/meta');
    expect(await inner.get('breakglass/meta')).toEqual({ v: 1, shards: 4 });
  });
});

describe('an unusable store fails closed everywhere', () => {
  it('shard-count mismatch refuses accept, use, review, frozen and uses', async () => {
    const kv = await mismatched();
    const r = mkReg(kv);
    expect(await r.accept(signBreakGlass(SK, base), T0)).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await r.use(useIn())).toEqual({ decision: 'deny', code: 'store_unreachable', id: 'b' });
    expect(await r.review(review(), 'h', T0 + 10)).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await r.frozen('h', T0)).toBe(true);
    expect(await r.uses('h', 'b')).toEqual([]);
  });
  it('uses() answers [] when the pinned shard count differs even if data sits at its key', async () => {
    const donor = memoryLeaseKv();
    const d = mkReg(donor, 1);
    await d.accept(signBreakGlass(SK, base), T0);
    await d.use(useIn());
    const kv = await mismatched();
    const doc = await donor.get('breakglass/1/0');
    await kv.update('breakglass/1/0', () => doc);
    expect(await mkReg(kv, 1).uses('h', 'b')).toEqual([]);
  });
  it('a write that fails after running is reported as store_unreachable, not as its tentative outcome', async () => {
    const armed = { on: false };
    const r = mkReg(failAfter(memoryLeaseKv(), armed));
    armed.on = true;
    expect(await r.accept(signBreakGlass(SK, base), T0)).toEqual({ ok: false, code: 'store_unreachable' });
    armed.on = false;
    await r.accept(signBreakGlass(SK, base), T0);
    armed.on = true;
    expect(await r.use(useIn())).toEqual({ decision: 'deny', code: 'store_unreachable', id: 'b' });
    armed.on = false;
    await r.use(useIn());
    armed.on = true;
    expect(await r.review(review(), 'h', T0 + 10)).toEqual({ ok: false, code: 'store_unreachable' });
  });
});

describe('break-glass behaviour', () => {
  it('unknown ids have no uses', async () => {
    const r = mkReg();
    expect(await r.uses('h', 'nope')).toEqual([]);
  });
  it('a review at exactly the first use time is accepted', async () => {
    const r = mkReg();
    await r.accept(signBreakGlass(SK, base), T0);
    await r.use(useIn('b', 'h', T0 + 1));
    expect(await r.review(review({ at: T0 + 1 }), 'h', T0 + 10)).toEqual({ ok: true, replaced: true });
    expect(await mkReg().review(review({ at: T0 }), 'h', T0 + 10)).toMatchObject({ ok: false });
  });
  it('a review before the first use is refused as bad_time', async () => {
    const r = mkReg();
    await r.accept(signBreakGlass(SK, base), T0);
    await r.use(useIn('b', 'h', T0 + 2));
    expect(await r.review(review({ at: T0 + 1 }), 'h', T0 + 10)).toEqual({ ok: false, code: 'bad_time' });
  });
  it('one holder being frozen does not freeze another holder sharing the shard', async () => {
    const r = mkReg(memoryLeaseKv(), 1);
    await r.accept(signBreakGlass(SK, base), T0);
    await r.use(useIn());
    expect(await r.review(review({ outcome: 'unjustified' }), 'h', T0 + 10)).toEqual({ ok: true, replaced: true });
    expect(await r.frozen('h', T0 + 10)).toBe(true);
    expect(await r.frozen('other', T0 + 10)).toBe(false);
    expect(await r.accept(signBreakGlass(SK, { ...base, id: 'c', holder: 'other' }), T0 + 10)).toEqual({ ok: true, replaced: true });
    expect(await r.accept(signBreakGlass(SK, { ...base, id: 'd', holder: 'h' }), T0 + 10)).toEqual({ ok: false, code: 'holder_frozen' });
  });
});
