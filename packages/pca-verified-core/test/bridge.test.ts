import { describe, expect, it } from 'vitest';
import {
  CoreState,
  VerdictState,
  VerifiedReplayStoreModel,
  audienceStatus,
  decideChain,
  decideThreshold,
  enforceRequired,
  replayDecide,
  replayPre,
  thresholdRule,
  validityDecision,
  type ChainHop,
  type Res,
} from '../src';

const OK: Res<string> = { ok: true };
const hop = (o: Partial<ChainHop<string, string>> = {}): ChainHop<string, string> => ({
  wellTyped: true,
  hasParent: false,
  rootIssuerOk: true,
  caveats: [],
  parentLinkOk: () => true,
  issuerIsParentHolder: () => true,
  suite: () => OK,
  pq: () => OK,
  sig: () => OK,
  ...o,
});
const eq = (a: string, b: string) => a === b;

describe('bridge sanity', () => {
  it('chain: accepts a prefix-extending chain and rejects drops / alterations / depth', () => {
    const hops = [hop({ caveats: ['a'] }), hop({ caveats: ['a', 'b'] }), hop({ caveats: ['a', 'b', 'c'] })];
    expect(decideChain(3, (i) => hops[i]!, eq, () => OK)).toEqual({ ok: true });
    const drops = [hop({ caveats: ['a', 'b'] }), hop({ caveats: ['a'] })];
    expect(decideChain(2, (i) => drops[i]!, eq, () => OK)).toEqual({ ok: false, error: { kind: 'drops', hop: 1 } });
    const alt = [hop({ caveats: ['a', 'b'] }), hop({ caveats: ['a', 'x'] })];
    expect(decideChain(2, (i) => alt[i]!, eq, () => OK)).toEqual({ ok: false, error: { kind: 'altered', hop: 1, caveat: 1 } });
    expect(decideChain(17, () => hop(), eq, () => OK)).toEqual({ ok: false, error: { kind: 'too-long' } });
    expect(decideChain(1_000_000, () => hop(), eq, () => OK)).toEqual({ ok: false, error: { kind: 'too-long' } });
    expect(decideChain(0, () => hop(), eq, () => OK)).toEqual({ ok: false, error: { kind: 'empty' } });
    expect(decideChain(1, () => hop({ sig: () => ({ ok: false, m: 'bad' }) }), eq, () => OK)).toEqual({ ok: false, error: { kind: 'sig', hop: 0, m: 'bad' } });
  });

  it('threshold: counts distinct roles', () => {
    const k = (s: string) => s;
    const signers = [
      { role: 'agent' as const, keyOk: true, pqOk: true, key: k('A') },
      { role: 'guardian' as const, keyOk: true, pqOk: true, key: k('G') },
      { role: 'principal' as const, keyOk: true, pqOk: true, key: k('P') },
    ];
    const sh = (role: 'agent' | 'guardian' | 'principal', key: string) => ({ wellFormed: true, role, key, algKnown: true, pqPkOk: true, sigOk: () => true });
    expect(decideThreshold(signers, [sh('agent', 'A'), sh('agent', 'A'), sh('guardian', 'G')], 2).ok).toBe(true);
    const r = decideThreshold(signers, [sh('agent', 'A'), sh('agent', 'A')], 2);
    expect(r.ok).toBe(false);
    expect(r.count).toBe(1);
    expect(decideThreshold(signers, [sh('agent', 'A'), sh('guardian', 'G'), sh('principal', 'P')], 3).roles).toEqual(['agent', 'guardian', 'principal']);
    expect(decideThreshold(signers, [], 4).reason).toEqual({ kind: 'invalid-t' });
  });

  it('verdict: audience, validity, core fold, enforce', () => {
    expect(audienceStatus(true, 'absent', false)).toBe('fail');
    expect(audienceStatus(true, 'null', false)).toBe('not-enforced');
    expect(validityDecision(true, 1000, 2000, 1500)).toBe('pass');
    expect(validityDecision(true, 1000, 2000, 2001)).toBe('expired');
    expect(validityDecision(true, 1000, 5_000_000, 1500)).toBe('too-long');
    let st = CoreState.init<string, string>();
    st = st.set('wire', 'pass').fail('audience', () => 'audience: nope').fail('validity', () => 'validity: second');
    expect(st.allow).toBe(false);
    expect(st.reason).toBe('audience: nope');
    expect(st.checks).toEqual([['wire', 'pass'], ['audience', 'fail'], ['validity', 'fail']]);
    expect(CoreState.wireFail<string, string>('wire', 'w').checks).toEqual([['wire', 'fail']]);
    expect(thresholdRule(3, true, 'pass', 2)).toBe('below');
    expect(thresholdRule(3, true, 'pass', 3)).toBe('ok');
    expect(thresholdRule(1, true, undefined, undefined)).toBe('ok');
    const v = VerdictState.init<string, string>([['a', 'pass']]).set('b', 'not-enforced');
    expect(v.finalAllow(true, true)).toBe(true);
    const e = enforceRequired(true, v.checks, v.reasons, ['a', 'b', 'c'], (n, was) => `${n}:${was ?? 'absent'}`);
    expect(e.allow).toBe(false);
    expect(e.checks).toEqual([['a', 'pass'], ['b', 'fail'], ['c', 'fail']]);
    expect(e.reasons).toEqual(['b:not-enforced', 'c:absent']);
  });

  it('replay: pre decision order and the store model', () => {
    const base = { nowOk: true, verifierAudOk: true, isObject: true, audMatches: true, iatOk: true, expOk: true, iat: 1000, exp: 2000, now: 1500, skew: 60000, leafOk: true, componentsOk: true, counterOk: true, hasNonce: true, nonceOk: true, requireNonce: true, hasCounters: true };
    expect(replayPre(base)).toBeUndefined();
    expect(replayPre({ ...base, now: 2001 })).toBe('expired');
    expect(replayPre({ ...base, audMatches: false })).toBe('audience');
    expect(replayDecide(base, false, true)).toBe('replay');
    expect(replayDecide(base, true, true)).toBeUndefined();
    const s = new VerifiedReplayStoreModel(2);
    expect(s.consumeOnce('k1', 100, 10)).toBe('accepted');
    expect(s.consumeOnce('k1', 100, 50)).toBe('dup');
    expect(s.consumeOnce('k2', 100, 50)).toBe('accepted');
    expect(s.consumeOnce('k3', 100, 50)).toBe('rejected');
    expect(s.consumeOnce('k3', 300, 150)).toBe('accepted');
    expect(s.advance('c', 5)).toBe('accepted');
    expect(s.advance('c', 5)).toBe('dup');
    expect(s.advance('c', 6)).toBe('accepted');
  });
});
