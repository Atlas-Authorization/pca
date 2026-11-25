import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { DriftMonitor, applyDrift, guardedDecide, type DriftSignal } from '../src/drift';
import type { Act, Decision, Goal, ResSel, Value } from '../src/ir';
import { ONT, baseGoal, ctrue } from './fixtures';

const NOVEL = 'novel resources beyond the allowance';
const key = Buffer.from('k'.repeat(32));
const shell: Goal = {
  v: 1, principal: 'p', ontDigest: 'o', nlDigest: 'n', sources: [], grants: [], prohibits: [], bounds: [],
  validity: { notBefore: 0, notAfter: 1_000_000, maxIdle: 0 }, deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
  escalateOn: [], wildcardAck: [], holes: [],
};
const goalOf = (...res: ResSel[]): Goal => ({ ...shell, grants: res.map((r, i) => ({ gid: `g${i}`, verb: 'v', res: r, cond: ctrue })) });
const act = (res: string, over: Partial<Act> = {}): Act => ({ verb: 'v', res, params: {}, t: 0, sess: 's', prin: 'p', org: 'o', agent: 'a', depth: 0, ...over });
const q = (n: number): Value => ({ k: 'q', q: { u: { k: 'count' }, n } });
/** The reasons of each observation of one count parameter `amt`. */
const magnitudes = (vals: number[], opts: ConstructorParameters<typeof DriftMonitor>[1]): string[][] => {
  const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }), opts);
  return vals.map((n, i) => m.observe(act('r', { params: { amt: q(n) } }), i).reasons);
};
const novelOf = (g: Goal, res: string): string[] => new DriftMonitor(g, { maxNovel: 0 }).observe(act(res), 0).reasons;

describe('drift monitor kills: resource profile', () => {
  it('exact resources are known, others are novel', () => {
    const g = goalOf({ k: 'exact', id: 'a' });
    expect(novelOf(g, 'a')).toStrictEqual([]);
    expect(novelOf(g, 'zzz')).toStrictEqual([NOVEL]);
  });
  it('oneof ids are known, others are novel', () => {
    const g = goalOf({ k: 'oneof', ids: ['b', 'c'] });
    expect(novelOf(g, 'b')).toStrictEqual([]);
    expect(novelOf(g, 'c')).toStrictEqual([]);
    expect(novelOf(g, 'zzz')).toStrictEqual([NOVEL]);
  });
  it('all_of parts contribute their ids, others are novel', () => {
    const g = goalOf({ k: 'all_of', parts: [{ k: 'exact', id: 'p' }, { k: 'oneof', ids: ['q', 'r'] }] });
    for (const r of ['p', 'q', 'r']) expect(novelOf(g, r)).toStrictEqual([]);
    expect(novelOf(g, 'zzz')).toStrictEqual([NOVEL]);
  });
  it('a wildcard or relation names no ids, so nothing is novel', () => {
    expect(novelOf(goalOf({ k: 'any', reason: 'r' }), 'zzz')).toStrictEqual([]);
    expect(novelOf(goalOf({ k: 'related', rel: 'r', anchor: 'a' }), 'zzz')).toStrictEqual([]);
  });
  it('a novel resource is counted once, and only past the allowance', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'a' }), { maxNovel: 1 });
    expect(m.observe(act('x'), 0).reasons).toStrictEqual([]);
    expect(m.observe(act('x'), 1).reasons).toStrictEqual([]);
    expect(m.state().novel).toStrictEqual(['x']);
    expect(m.observe(act('y'), 2).reasons).toStrictEqual([NOVEL]);
  });
  it('a known resource is never recorded as novel', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'a' }), { maxNovel: 0 });
    expect(m.observe(act('a'), 0).reasons).toStrictEqual([]);
    expect(m.state().novel).toStrictEqual([]);
  });
});

describe('drift monitor kills: state, verbs, rate, magnitude, lockdown', () => {
  it('starts empty', () => {
    expect(new DriftMonitor(goalOf()).state()).toStrictEqual({ strikes: 0, times: [], novel: [], seen: {} });
  });
  it('names a verb outside the profile', () => {
    const s = new DriftMonitor(goalOf({ k: 'exact', id: 'r' })).observe(act('r', { verb: 'other' }), 0);
    expect(s.reasons).toStrictEqual(['verb other outside the goal profile']);
  });
  it('a clean observation is no strike', () => {
    const s = new DriftMonitor(goalOf({ k: 'exact', id: 'r' })).observe(act('r'), 0);
    expect(s).toStrictEqual({ anomalous: false, strikes: 0, lockdown: false, reasons: [] });
  });
  it('locks down exactly at the strike limit', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }), { lockdown: 2 });
    expect(m.observe(act('r', { verb: 'other' }), 0)).toStrictEqual({ anomalous: true, strikes: 1, lockdown: false, reasons: ['verb other outside the goal profile'] });
    expect(m.observe(act('r', { verb: 'other' }), 1)).toStrictEqual({ anomalous: true, strikes: 2, lockdown: true, reasons: ['verb other outside the goal profile'] });
  });
  it('the rate window keeps only observations strictly newer than the window start', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }), { windowMs: 10, maxPerWindow: 1 });
    expect(m.observe(act('r'), 0).reasons).toStrictEqual([]);
    expect(m.observe(act('r'), 10).reasons).toStrictEqual([]);
    expect(m.state().times).toStrictEqual([10]);
    expect(m.observe(act('r'), 100).reasons).toStrictEqual([]);
    expect(m.state().times).toStrictEqual([100]);
    expect(m.observe(act('r'), 105).reasons).toStrictEqual(['rate above the profile']);
  });
  it('the rate limit is exclusive', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }), { maxPerWindow: 2 });
    expect(m.observe(act('r'), 0).reasons).toStrictEqual([]);
    expect(m.observe(act('r'), 1).reasons).toStrictEqual([]);
    expect(m.observe(act('r'), 2).reasons).toStrictEqual(['rate above the profile']);
  });
  it('a non-quantity parameter is skipped', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }));
    expect(m.observe(act('r', { params: { who: { k: 's', s: 'x' } } }), 0).reasons).toStrictEqual([]);
    expect(m.state().seen).toStrictEqual({});
  });
  it('magnitude: only a value above factor x the mean of a warmed-up history is flagged', () => {
    const o = { warmup: 2 };
    expect(magnitudes([10, 10, 5], o)).toStrictEqual([[], [], []]);
    expect(magnitudes([10, 10, 30], o)).toStrictEqual([[], [], []]);
    expect(magnitudes([0, 0, 5], o)).toStrictEqual([[], [], []]);
    expect(magnitudes([1, 100], o)).toStrictEqual([[], []]);
    const flagged = ['amt magnitude 3x above the running mean'];
    expect(magnitudes([10, 10, 31], o)).toStrictEqual([[], [], flagged]);
    expect(magnitudes([1, 1, 100], o)).toStrictEqual([[], [], flagged]);
  });
  it('keeps only the last 50 values per parameter', () => {
    const m = new DriftMonitor(goalOf({ k: 'exact', id: 'r' }), { warmup: 1000 });
    for (let n = 1; n <= 60; n++) m.observe(act('r', { params: { amt: q(n) } }), n);
    expect(m.state().seen['amt']).toStrictEqual(Array.from({ length: 50 }, (_, i) => i + 11));
  });
});

describe('drift monitor kills: seal and restore', () => {
  const goal = goalOf({ k: 'exact', id: 'r' });
  it('seals with a lowercase hex HMAC-SHA256 of the state', () => {
    const m = new DriftMonitor(goal);
    m.observe(act('r', { verb: 'other' }), 0);
    const sealed = m.seal(key);
    expect(sealed.mac).toBe(createHmac('sha256', key).update(JSON.stringify(sealed.state)).digest('hex'));
    expect(sealed.mac).toMatch(/^[0-9a-f]{64}$/);
    expect(DriftMonitor.restore(goal, sealed, key).state()).toStrictEqual(sealed.state);
  });
  it('a mac of the wrong length or value fails closed to lockdown with an empty profile', () => {
    const m = new DriftMonitor(goal);
    m.observe(act('r', { verb: 'other' }), 0);
    const { state } = m.seal(key);
    for (const mac of ['abcd', '', '00'.repeat(32)]) {
      expect(DriftMonitor.restore(goal, { state, mac }, key, { lockdown: 3 }).state()).toStrictEqual({ strikes: 3, times: [], novel: [], seen: {} });
    }
  });
});

describe('applyDrift and guardedDecide kills', () => {
  const sig = (anomalous: boolean, lockdown: boolean): DriftSignal => ({ anomalous, strikes: 0, lockdown, reasons: [] });
  it('only an allow with an anomaly or a lockdown is tightened', () => {
    expect(applyDrift('allow', sig(false, false))).toBe('allow');
    expect(applyDrift('allow', sig(true, false))).toBe('escalate');
    expect(applyDrift('allow', sig(false, true))).toBe('escalate');
    expect(applyDrift('allow', sig(true, true))).toBe('escalate');
    for (const d of ['deny', 'escalate'] as Decision[]) for (const [a, l] of [[false, false], [true, false], [false, true], [true, true]] as const) expect(applyDrift(d, sig(a, l))).toBe(d);
  });
  const refund: Act = { verb: 'pay.refund', res: 'ch_1', params: { amount: { k: 'q', q: { u: { k: 'money', ccy: 'USD' }, n: 1000 } } }, t: 10, sess: 's1', prin: 'P1', org: 'O', agent: 'a1', depth: 0 };
  it('guardedDecide returns the base decision and the signal', () => {
    const g = baseGoal();
    expect(guardedDecide(g, ONT, new DriftMonitor(g), { act: refund, rels: ONT.rels }, 10)).toStrictEqual({ decision: 'allow', signal: { anomalous: false, strikes: 0, lockdown: false, reasons: [] } });
  });
  it('guardedDecide escalates an allowed action the monitor finds anomalous', () => {
    const mon = new DriftMonitor({ ...baseGoal(), grants: [{ gid: 'm', verb: 'pay.read', res: { k: 'exact', id: 'zz' }, cond: ctrue }], wildcardAck: [] });
    expect(guardedDecide(baseGoal(), ONT, mon, { act: refund, rels: ONT.rels }, 10)).toStrictEqual({
      decision: 'escalate', signal: { anomalous: true, strikes: 1, lockdown: false, reasons: ['verb pay.refund outside the goal profile'] },
    });
  });
});
