/* eslint-disable @typescript-eslint/no-explicit-any */
// Mutation-kill tests for the TypeScript glue that fronts the Dafny-generated core (bridge, chain, replay, threshold, verdict).
// Each wrapper is checked against an independent oracle transcribed from the Dafny source (formal/dafny/*.dfy), over EVERY
// input combination where the domain is small, so each result label / reason string / field is pinned.
import { describe, expect, it } from 'vitest';
import {
  CoreState,
  MAX_CHAIN_DEPTH,
  VerdictState,
  VerifiedReplayStoreModel,
  audienceStatus,
  beaconDecision,
  capChainStatus,
  counterStatus,
  decideChain,
  decideThreshold,
  enforceRequired,
  grantRefBoundStatus,
  hookStatus,
  leafDecision,
  planDecision,
  pqBinding,
  pqResolve,
  replayDecide,
  replayNonceStage,
  replayPre,
  replayRetainUntil,
  replayRetainUntilExact,
  reversibilityDecision,
  suitePolicy,
  thresholdRule,
  useDeclaredClass,
  validityDecision,
  versionStatus,
  withDeniedFallback,
  type ChainHop,
  type ReplayFacts,
  type Res,
  type Status,
} from '../src';
import { bn, dstr, emptyDafnyMap, fromOpt, fromStatus, jstr, none, num, opt, some, toStatus, Common } from '../src/bridge';

const bools = [false, true];
const OK: Res<string> = { ok: true };
const ERR = (m: string): Res<string> => ({ ok: false, m });

describe('bridge', () => {
  it('bn accepts safe integers and rejects everything else with a message naming the value', () => {
    expect(num(bn(0))).toBe(0);
    expect(num(bn(-5))).toBe(-5);
    expect(num(bn(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
    expect(() => bn(1.5)).toThrow(RangeError);
    expect(() => bn(1.5)).toThrow('pca-verified-core: expected a safe integer, got 1.5');
    expect(() => bn(2 ** 53)).toThrow('got 9007199254740992');
    expect(() => bn(Number.NaN)).toThrow('got NaN');
  });
  it('opt / some / none / fromOpt round-trip', () => {
    expect(opt(undefined).is_None).toBe(true);
    expect(opt(undefined).is_Some).toBeFalsy();
    const o = opt(5);
    expect(o.is_Some).toBe(true);
    expect(o.is_None).toBeFalsy();
    expect(fromOpt<number>(o)).toBe(5);
    expect(fromOpt<number>(none())).toBeUndefined();
    expect(fromOpt<number>(some(0))).toBe(0);
    expect(opt(0).is_Some).toBe(true);
    expect(opt(false).is_Some).toBe(true);
  });
  it('status conversions are a bijection', () => {
    const all: Status[] = ['pass', 'fail', 'not-enforced'];
    for (const s of all) expect(toStatus(fromStatus(s))).toBe(s);
    expect(fromStatus('pass').is_Pass).toBe(true);
    expect(fromStatus('fail').is_Fail).toBe(true);
    expect(fromStatus('fail').is_NotEnforced).toBeFalsy();
    expect(fromStatus('not-enforced').is_NotEnforced).toBe(true);
    expect(fromStatus('not-enforced').is_Fail).toBeFalsy();
    expect(Common.Status.create_Fail().is_Fail).toBe(true);
  });
  it('dstr / jstr round-trip without quoting, including non-BMP code points; emptyDafnyMap is empty', () => {
    for (const s of ['', 'abc', 'héllo \u{1F600} x']) expect(jstr(dstr(s))).toBe(s);
    expect(emptyDafnyMap().length).toBe(0);
  });
});

describe('chain', () => {
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
  const run = (hops: ChainHop<string, string>[], alloc: () => Res<string> = () => OK) => decideChain(hops.length, (i) => hops[i]!, eq, alloc);
  const child = (o: Partial<ChainHop<string, string>> = {}) => hop({ hasParent: true, rootIssuerOk: false, ...o });

  it('MAX_CHAIN_DEPTH is 16 and length MAX is accepted while MAX+1 is too-long', () => {
    expect(MAX_CHAIN_DEPTH).toBe(16);
    const ok = (n: number) => decideChain(n, (i) => (i === 0 ? hop() : child()), eq, () => OK);
    expect(ok(MAX_CHAIN_DEPTH)).toEqual({ ok: true });
    expect(ok(MAX_CHAIN_DEPTH + 1)).toEqual({ ok: false, error: { kind: 'too-long' } });
  });
  it('hopAt is called for at most MAX+1 hops however long the chain claims to be, in order', () => {
    const seen: number[] = [];
    decideChain(10 ** 9, (i) => { seen.push(i); return hop(); }, eq, () => OK);
    expect(seen).toEqual(Array.from({ length: MAX_CHAIN_DEPTH + 1 }, (_, i) => i));
    const seen2: number[] = [];
    decideChain(3, (i) => { seen2.push(i); return i === 0 ? hop() : child(); }, eq, () => OK);
    expect(seen2).toEqual([0, 1, 2]);
  });
  it('every error kind, with its payload', () => {
    expect(decideChain(0, () => hop(), eq, () => OK)).toEqual({ ok: false, error: { kind: 'empty' } });
    expect(run([hop({ wellTyped: false })])).toEqual({ ok: false, error: { kind: 'malformed', hop: 0 } });
    expect(run([hop(), child({ wellTyped: false })])).toEqual({ ok: false, error: { kind: 'malformed', hop: 1 } });
    expect(run([hop({ hasParent: true })])).toEqual({ ok: false, error: { kind: 'root-has-parent' } });
    expect(run([hop({ rootIssuerOk: false })])).toEqual({ ok: false, error: { kind: 'root-issuer' } });
    expect(run([hop({ suite: () => ERR('s0') })])).toEqual({ ok: false, error: { kind: 'suite', hop: 0, m: 's0' } });
    expect(run([hop({ pq: () => ERR('p0') })])).toEqual({ ok: false, error: { kind: 'pq', hop: 0, m: 'p0' } });
    expect(run([hop({ sig: () => ERR('g0') })])).toEqual({ ok: false, error: { kind: 'sig', hop: 0, m: 'g0' } });
    expect(run([hop(), child({ parentLinkOk: () => false })])).toEqual({ ok: false, error: { kind: 'parent-link', hop: 1 } });
    expect(run([hop(), child({ issuerIsParentHolder: () => false })])).toEqual({ ok: false, error: { kind: 'issuer-not-holder', hop: 1 } });
    expect(run([hop(), child({ suite: () => ERR('s1') })])).toEqual({ ok: false, error: { kind: 'suite', hop: 1, m: 's1' } });
    expect(run([hop(), child({ pq: () => ERR('p1') })])).toEqual({ ok: false, error: { kind: 'pq', hop: 1, m: 'p1' } });
    expect(run([hop(), child({ sig: () => ERR('g1') })])).toEqual({ ok: false, error: { kind: 'sig', hop: 1, m: 'g1' } });
    expect(run([hop({ caveats: ['a', 'b'] }), child({ caveats: ['a'] })])).toEqual({ ok: false, error: { kind: 'drops', hop: 1 } });
    expect(run([hop({ caveats: ['a', 'b'] }), child({ caveats: ['a', 'x'] })])).toEqual({ ok: false, error: { kind: 'altered', hop: 1, caveat: 1 } });
    expect(run([hop()], () => ERR('al'))).toEqual({ ok: false, error: { kind: 'alloc', m: 'al' } });
    expect(run([hop(), child()], () => ERR('al2'))).toEqual({ ok: false, error: { kind: 'alloc', m: 'al2' } });
    expect(run([hop(), child()])).toEqual({ ok: true });
  });
  it('first failure order within a hop: parent-link, issuer, suite, pq, sig, then attenuation', () => {
    const all = child({
      parentLinkOk: () => false, issuerIsParentHolder: () => false,
      suite: () => ERR('s'), pq: () => ERR('p'), sig: () => ERR('g'), caveats: [],
    });
    const p = [hop({ caveats: ['a'] })];
    expect(run([...p, all]).ok).toBe(false);
    expect((run([...p, all]) as any).error.kind).toBe('parent-link');
    expect((run([...p, { ...all, parentLinkOk: () => true }]) as any).error.kind).toBe('issuer-not-holder');
    expect((run([...p, { ...all, parentLinkOk: () => true, issuerIsParentHolder: () => true }]) as any).error.kind).toBe('suite');
    expect((run([...p, { ...all, parentLinkOk: () => true, issuerIsParentHolder: () => true, suite: () => OK }]) as any).error.kind).toBe('pq');
    expect((run([...p, { ...all, parentLinkOk: () => true, issuerIsParentHolder: () => true, suite: () => OK, pq: () => OK }]) as any).error.kind).toBe('sig');
    expect((run([...p, { ...all, parentLinkOk: () => true, issuerIsParentHolder: () => true, suite: () => OK, pq: () => OK, sig: () => OK }]) as any).error.kind).toBe('drops');
  });
  it('root checks run in order: parent, issuer, suite, pq, sig; alloc is lazy (only after every hop passed)', () => {
    const bad = hop({ hasParent: true, rootIssuerOk: false, suite: () => ERR('s'), pq: () => ERR('p'), sig: () => ERR('g') });
    expect((run([bad]) as any).error.kind).toBe('root-has-parent');
    expect((run([{ ...bad, hasParent: false }]) as any).error.kind).toBe('root-issuer');
    expect((run([{ ...bad, hasParent: false, rootIssuerOk: true }]) as any).error.kind).toBe('suite');
    expect((run([{ ...bad, hasParent: false, rootIssuerOk: true, suite: () => OK }]) as any).error.kind).toBe('pq');
    expect((run([{ ...bad, hasParent: false, rootIssuerOk: true, suite: () => OK, pq: () => OK }]) as any).error.kind).toBe('sig');
    let allocCalls = 0;
    run([hop({ sig: () => ERR('x') })], () => { allocCalls++; return OK; });
    expect(allocCalls).toBe(0);
    run([hop()], () => { allocCalls++; return OK; });
    expect(allocCalls).toBe(1);
  });
});

describe('replay', () => {
  const base: ReplayFacts = {
    nowOk: true, verifierAudOk: true, isObject: true, audMatches: true, iatOk: true, expOk: true,
    iat: 1000, exp: 2000, now: 1500, skew: 10, leafOk: true, componentsOk: true, counterOk: true,
    hasNonce: true, nonceOk: true, requireNonce: false, hasCounters: false,
  };
  it('nonce stage: every combination matches the Dafny NonceStage', () => {
    for (const hasNonce of bools) for (const nonceOk of bools) for (const requireNonce of bools) {
      const exp = hasNonce ? (nonceOk ? 'consume' : 'deny') : requireNonce ? 'deny' : 'skip';
      expect(replayNonceStage({ ...base, hasNonce, nonceOk, requireNonce })).toBe(exp);
    }
  });
  it('decide: every (nonce stage, counters, store answers) combination', () => {
    for (const hasNonce of bools) for (const nonceOk of bools) for (const requireNonce of bools) for (const hasCounters of bools)
      for (const c of bools) for (const a of bools) {
        const f = { ...base, hasNonce, nonceOk, requireNonce, hasCounters };
        const stage = replayNonceStage(f);
        let exp: string | undefined;
        if (stage === 'deny') exp = 'malformed';
        else if (stage === 'consume' && !c) exp = 'replay';
        else if (hasCounters && !a) exp = 'replay';
        expect(replayDecide(f, c, a)).toBe(exp);
      }
  });
  it('pre: each hard failure, with its precedence', () => {
    expect(replayPre(base)).toBeUndefined();
    expect(replayPre({ ...base, nowOk: false })).toBe('malformed');
    expect(replayPre({ ...base, verifierAudOk: false })).toBe('malformed');
    expect(replayPre({ ...base, isObject: false })).toBe('malformed');
    expect(replayPre({ ...base, audMatches: false })).toBe('audience');
    expect(replayPre({ ...base, iat: 1511 })).toBe('not_yet_valid');
    expect(replayPre({ ...base, iat: 1510 })).toBeUndefined();
    expect(replayPre({ ...base, now: 2001 })).toBe('expired');
    expect(replayPre({ ...base, now: 2000 })).toBeUndefined();
    expect(replayPre({ ...base, iatOk: false })).toBe('malformed');
    expect(replayPre({ ...base, expOk: false })).toBe('malformed');
    expect(replayPre({ ...base, leafOk: false })).toBe('malformed');
    expect(replayPre({ ...base, componentsOk: false })).toBe('malformed');
    expect(replayPre({ ...base, counterOk: false })).toBe('malformed');
  });
  it('non-finite numbers behind a false *Ok flag are replaced by 0 and never reach bn()', () => {
    expect(() => replayPre({ ...base, iatOk: false, iat: Number.NaN })).not.toThrow();
    expect(() => replayPre({ ...base, expOk: false, exp: Number.POSITIVE_INFINITY })).not.toThrow();
    expect(() => replayPre({ ...base, nowOk: false, now: 1.5 })).not.toThrow();
    // even with the flag true a non-safe number is neutralised to 0 (the flag is the caller's claim, not trusted blindly)
    expect(() => replayPre({ ...base, iatOk: true, iat: Number.NaN })).not.toThrow();
    // flag false: the supplied value is NOT used (retention horizon is 0 + skew); flag true: it is
    expect(replayRetainUntilExact({ ...base, expOk: false, exp: 100, skew: 5 })).toBe(5n);
    expect(replayRetainUntilExact({ ...base, expOk: true, exp: 100, skew: 5 })).toBe(105n);
  });
  it('retention horizon: exact bigint and safe-integer number with RangeError beyond the safe range', () => {
    expect(replayRetainUntil({ ...base, exp: 2000, skew: 10 })).toBe(2010);
    expect(replayRetainUntilExact({ ...base, exp: Number.MAX_SAFE_INTEGER, skew: 1 })).toBe(9007199254740992n);
    expect(replayRetainUntil({ ...base, exp: Number.MAX_SAFE_INTEGER - 1, skew: 1 })).toBe(Number.MAX_SAFE_INTEGER);
    expect(() => replayRetainUntil({ ...base, exp: Number.MAX_SAFE_INTEGER, skew: 1 })).toThrow(RangeError);
    expect(() => replayRetainUntil({ ...base, exp: Number.MAX_SAFE_INTEGER, skew: 1 })).toThrow(
      'pca-verified-core: retention horizon 9007199254740992 is outside the safe-integer range',
    );
    expect(replayRetainUntil({ ...base, exp: Number.MIN_SAFE_INTEGER + 1, skew: -1 })).toBe(Number.MIN_SAFE_INTEGER);
    expect(() => replayRetainUntil({ ...base, exp: Number.MIN_SAFE_INTEGER, skew: -1 })).toThrow(
      'pca-verified-core: retention horizon -9007199254740992 is outside the safe-integer range',
    );
  });
  it('store model: accepted / dup / rejected, prune and size', () => {
    const s = new VerifiedReplayStoreModel(2);
    expect(s.size).toBe(0);
    expect(s.consumeOnce('a', 100, 10)).toBe('accepted');
    expect(s.size).toBe(1);
    expect(s.consumeOnce('a', 100, 10)).toBe('dup');
    expect(s.consumeOnce('b', 100, 10)).toBe('accepted');
    expect(s.size).toBe(2);
    expect(s.consumeOnce('c', 100, 10)).toBe('rejected');
    expect(s.size).toBe(2);
    s.prune(101);
    expect(s.size).toBe(0);
    expect(s.consumeOnce('c', 200, 101)).toBe('accepted');
    expect(s.advance('st', 5)).toBe('accepted');
    expect(s.advance('st', 5)).toBe('dup');
    expect(s.advance('st', 4)).toBe('dup');
    expect(s.advance('st', 6)).toBe('accepted');
    expect(s.advance('st', -1)).toBe('rejected');
  });
});

describe('threshold', () => {
  type S = { role: 'agent' | 'guardian' | 'principal' | undefined; keyOk: boolean; pqOk: boolean; key: string };
  const sg = (role: S['role'], key: string, o: Partial<S> = {}): S => ({ role, keyOk: true, pqOk: true, key, ...o });
  const sh = (role: S['role'], key: string, o: Record<string, unknown> = {}) => ({ wellFormed: true, role, key, algKnown: true, pqPkOk: true, sigOk: () => true, ...o }) as any;
  const reg = [sg('agent', 'A'), sg('guardian', 'G'), sg('principal', 'P')];

  it('every reason kind and payload', () => {
    expect(decideThreshold(reg, [], 0)).toEqual({ ok: false, count: 0, roles: [], reason: { kind: 'invalid-t' } });
    expect(decideThreshold(reg, [], 4).reason).toEqual({ kind: 'invalid-t' });
    expect(decideThreshold(reg, [], 1.5).reason).toEqual({ kind: 'invalid-t' });
    expect(decideThreshold(reg, [], Number.NaN).reason).toEqual({ kind: 'invalid-t' });
    expect(decideThreshold(reg, [], 2 ** 60).reason).toEqual({ kind: 'invalid-t' });
    expect(decideThreshold([sg(undefined, 'A')], [], 1).reason).toEqual({ kind: 'set-malformed' });
    expect(decideThreshold([sg('agent', 'A', { keyOk: false })], [], 1).reason).toEqual({ kind: 'set-malformed' });
    expect(decideThreshold([sg('agent', 'A', { pqOk: false })], [], 1).reason).toEqual({ kind: 'set-pq' });
    expect(decideThreshold([sg('agent', 'A'), sg('agent', 'B')], [], 1).reason).toEqual({ kind: 'two-keys-for-role', entry: 1 });
    expect(decideThreshold([sg('agent', 'A'), sg('guardian', 'G'), sg('guardian', 'H')], [], 1).reason).toEqual({ kind: 'two-keys-for-role', entry: 2 });
    expect(decideThreshold([sg('agent', 'A'), sg('guardian', 'A')], [], 1).reason).toEqual({ kind: 'one-key-two-roles' });
    expect(decideThreshold(reg, [{ ...sh('agent', 'A'), wellFormed: false }], 1).reason).toEqual({ kind: 'malformed-share' });
    expect(decideThreshold(reg, [], 1)).toEqual({ ok: false, count: 0, roles: [], reason: { kind: 'need-more' } });
    expect(decideThreshold([sg('agent', 'A')], [sh('guardian', 'G')], 1).reason).toEqual({ kind: 'role-not-in-set', share: 0 });
    expect(decideThreshold([sg('agent', 'A')], [sh(undefined, 'Z')], 1).reason).toEqual({ kind: 'role-not-in-set', share: 0 });
    expect(decideThreshold(reg, [sh('agent', 'A'), sh('guardian', 'X')], 3).reason).toEqual({ kind: 'key-not-registered', share: 1 });
    expect(decideThreshold(reg, [sh('agent', 'A', { algKnown: false })], 1).reason).toEqual({ kind: 'unknown-alg', share: 0 });
    expect(decideThreshold(reg, [sh('agent', 'A'), sh('guardian', 'G', { sigOk: () => false })], 3).reason).toEqual({ kind: 'invalid-sig', share: 1 });
  });
  it('success: count, distinct roles, duplicates ignored, t in {1,2,3}', () => {
    const r = decideThreshold(reg, [sh('agent', 'A'), sh('agent', 'A'), sh('principal', 'P')], 2);
    expect(r).toEqual({ ok: true, count: 2, roles: ['agent', 'principal'] });
    expect(decideThreshold(reg, [sh('guardian', 'G')], 1)).toEqual({ ok: true, count: 1, roles: ['guardian'] });
    expect(decideThreshold(reg, [sh('agent', 'A'), sh('guardian', 'G'), sh('principal', 'P')], 3).roles).toEqual(['agent', 'guardian', 'principal']);
    expect(decideThreshold(reg, [sh('principal', 'P'), sh('agent', 'A')], 3).ok).toBe(false);
  });
  it('a non-integer t is treated as invalid, never as t = 1', () => {
    expect(decideThreshold(reg, [sh('agent', 'A')], 0.5).ok).toBe(false);
    expect(decideThreshold(reg, [sh('agent', 'A')], 1).ok).toBe(true);
  });
  it('the baseline adds the agent key when every baseline fact holds, and only then', () => {
    const bl = (o: Record<string, unknown> = {}) => ({ holderIsString: true, holder: 'A', pqKeyOk: () => true, leafSigOk: () => true, ...o }) as any;
    expect(decideThreshold(reg, [], 1, bl())).toEqual({ ok: true, count: 1, roles: ['agent'] });
    expect(decideThreshold(reg, [], 1, undefined).ok).toBe(false);
    expect(decideThreshold(reg, [], 1, bl({ holderIsString: false })).ok).toBe(false);
    expect(decideThreshold(reg, [], 1, bl({ holder: 'Z' })).ok).toBe(false);
    expect(decideThreshold(reg, [], 1, bl({ pqKeyOk: () => false })).ok).toBe(false);
    expect(decideThreshold(reg, [], 1, bl({ leafSigOk: () => false })).ok).toBe(false);
    // already counted through a share: not counted twice
    expect(decideThreshold(reg, [sh('agent', 'A')], 2, bl()).count).toBe(1);
    expect(decideThreshold(reg, [sh('guardian', 'G')], 2, bl())).toEqual({ ok: true, count: 2, roles: ['guardian', 'agent'] });
  });
});

describe('verdict: per-check decisions', () => {
  it('audienceStatus: all 12 combinations', () => {
    for (const hasAud of bools) for (const equal of bools) {
      expect(audienceStatus(hasAud, 'null', equal)).toBe('not-enforced');
      expect(audienceStatus(hasAud, 'absent', equal)).toBe(hasAud ? 'fail' : 'not-enforced');
      expect(audienceStatus(hasAud, 'string', equal)).toBe(equal ? 'pass' : 'fail');
    }
  });
  it('validityDecision: oracle over a boundary grid', () => {
    const oracle = (clockOk: boolean, iat: number, exp: number, now: number) =>
      !clockOk ? 'bad-clock' : !(exp > iat) ? 'not-greater' : exp - iat > 3_600_000 ? 'too-long' : iat > now + 60_000 ? 'future' : now > exp ? 'expired' : 'pass';
    const iats = [0, 1000, 5000];
    const durs = [0, 1, 3_599_999, 3_600_000, 3_600_001];
    const nows = [-100_000, 0, 60_000, 60_001, 1000, 1001, 4_000_000, 3_605_000, 3_605_001, 3_700_000];
    for (const clockOk of bools) for (const iat of iats) for (const d of durs) for (const now of nows) {
      expect(validityDecision(clockOk, iat, iat + d, now)).toBe(oracle(clockOk, iat, iat + d, now));
    }
    // a bad clock ignores the supplied `now` (replaced by 0) - NaN must not throw
    expect(validityDecision(false, 1, 2, Number.NaN)).toBe('bad-clock');
    // exp < iat
    expect(validityDecision(true, 10, 5, 7)).toBe('not-greater');
    // each label reached
    const seen = new Set<string>();
    for (const clockOk of bools) for (const iat of iats) for (const d of durs) for (const now of nows) seen.add(validityDecision(clockOk, iat, iat + d, now));
    expect([...seen].sort()).toEqual(['bad-clock', 'expired', 'future', 'not-greater', 'pass', 'too-long']);
  });
  it('version / counter / grantRefBound', () => {
    expect(versionStatus(true)).toBe('pass');
    expect(versionStatus(false)).toBe('fail');
    expect(counterStatus(true)).toBe('pass');
    expect(counterStatus(false)).toBe('fail');
    for (const a of bools) for (const b of bools) for (const c of bools) expect(grantRefBoundStatus(a, b, c)).toBe(a && b && c ? 'pass' : 'fail');
  });
  it('suitePolicy / pqBinding', () => {
    for (const d of bools) for (const a of bools) expect(suitePolicy(d, a)).toBe(d && !a ? 'not-allowed' : undefined);
    for (const n of bools) for (const u of bools) for (const c of bools) for (const m of bools) {
      const exp = !n || u ? undefined : !c ? 'no-pq-commitment' : !m ? 'pq-mismatch' : undefined;
      expect(pqBinding(n, u, c, m)).toBe(exp);
    }
  });
  it('pqResolve: all 128 combinations', () => {
    const seen = new Set<string>();
    for (let k = 0; k < 128; k++) {
      const [trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound] = [0, 1, 2, 3, 4, 5, 6].map((b) => !!((k >> b) & 1));
      const exp = trusted ? 'trusted' : !artifactKeyOk ? 'refused' : pinPresent ? (pinEquals ? 'pinned' : 'refused') : commitPresent && commitMatches ? 'committed' : allowUnbound ? 'unbound' : 'refused';
      seen.add(exp);
      expect(pqResolve({ trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound })).toBe(exp);
    }
    expect([...seen].sort()).toEqual(['committed', 'pinned', 'refused', 'trusted', 'unbound']);
  });
  it('leafDecision: outcomes and laziness', () => {
    expect(leafDecision(false, () => OK, true, () => true)).toEqual({ kind: 'bad-signature' });
    expect(leafDecision(true, () => ERR('sx'), true, () => true)).toEqual({ kind: 'suite-error', m: 'sx' });
    expect(leafDecision(true, () => OK, false, () => true)).toEqual({ kind: 'bad-signature' });
    expect(leafDecision(true, () => OK, true, () => false)).toEqual({ kind: 'bad-signature' });
    expect(leafDecision(true, () => OK, true, () => true)).toEqual({ kind: 'pass' });
    let suiteCalls = 0, verifyCalls = 0;
    leafDecision(false, () => { suiteCalls++; return OK; }, true, () => { verifyCalls++; return true; });
    expect([suiteCalls, verifyCalls]).toEqual([0, 0]);
    leafDecision(true, () => { suiteCalls++; return ERR('e'); }, true, () => { verifyCalls++; return true; });
    expect([suiteCalls, verifyCalls]).toEqual([1, 0]);
    leafDecision(true, () => OK, false, () => { verifyCalls++; return true; });
    expect(verifyCalls).toBe(0);
  });
  it('capChainStatus: outcomes and laziness', () => {
    let rootCalls = 0, walkCalls = 0;
    const root = (v: boolean) => () => { rootCalls++; return v; };
    const walk = (r: Res<string>) => () => { walkCalls++; return r; };
    expect(capChainStatus(false, root(true), walk(OK))).toEqual({ kind: 'empty' });
    expect([rootCalls, walkCalls]).toEqual([0, 0]);
    expect(capChainStatus(true, root(false), walk(OK))).toEqual({ kind: 'root-not-grant' });
    expect([rootCalls, walkCalls]).toEqual([1, 0]);
    expect(capChainStatus(true, root(true), walk(OK))).toEqual({ kind: 'walked', ok: true });
    expect(capChainStatus(true, root(true), walk(ERR('w')))).toEqual({ kind: 'walked', ok: false, m: 'w' });
    expect([rootCalls, walkCalls]).toEqual([3, 2]);
  });
  it('hookStatus', () => {
    expect(hookStatus(false, true)).toBe('not-enforced');
    expect(hookStatus(false, false)).toBe('not-enforced');
    expect(hookStatus(true, true)).toBe('pass');
    expect(hookStatus(true, false)).toBe('fail');
  });
  it('planDecision', () => {
    for (const rm of bools) for (const au of [true, false, undefined]) {
      expect(planDecision(false, rm, au)).toBe('not-enforced');
      const exp = !rm ? 'mismatch' : au === true ? 'pass' : au === false ? 'unauthorized' : 'not-enforced';
      expect(planDecision(true, rm, au)).toBe(exp);
    }
  });
  it('beaconDecision: all 16 combinations', () => {
    const seen = new Set<string>();
    for (const s of bools) for (const v of bools) for (const r of bools) for (const b of bools) {
      const exp = !s ? 'not-enforced' : !v ? 'rejected' : r ? 'replayed' : !b ? 'unbound' : 'pass';
      seen.add(exp);
      expect(beaconDecision(s, v, r, b)).toBe(exp);
    }
    expect(seen.size).toBe(5);
  });
  it('reversibility / useDeclaredClass', () => {
    for (const d of [0, 1, 2]) {
      expect(reversibilityDecision(d, undefined)).toBe('no-server-class');
      expect(useDeclaredClass(d, undefined)).toBe(true);
      for (const s of [0, 1, 2]) {
        expect(reversibilityDecision(d, s)).toBe(d < s ? 'less-restrictive' : 'pass');
        expect(useDeclaredClass(d, s)).toBe(d > s);
      }
    }
  });
  it('thresholdRule: oracle over all inputs', () => {
    const ths: Array<Status | undefined> = ['pass', 'fail', 'not-enforced', undefined];
    const seen = new Set<string>();
    for (const t of [0, 1, 2, 3]) for (const rel of bools) for (const th of ths) for (const hk of [undefined, 0, 1, 2, 3, 4]) {
      const exp =
        t > 1 && rel && th === 'pass' && !(hk !== undefined && hk >= t) ? 'below'
        : t > 1 && rel && th !== 'pass' ? (th === 'fail' ? 'rejected' : 'no-verifier')
        : 'ok';
      seen.add(exp);
      expect(thresholdRule(t, rel, th, hk)).toBe(exp);
    }
    expect([...seen].sort()).toEqual(['below', 'no-verifier', 'ok', 'rejected']);
  });
  it('withDeniedFallback', () => {
    expect(withDeniedFallback(true, [], 'd')).toEqual([]);
    expect(withDeniedFallback(false, [], 'd')).toEqual(['d']);
    expect(withDeniedFallback(false, ['r'], 'd')).toEqual(['r']);
    expect(withDeniedFallback(true, ['r'], 'd')).toEqual(['r']);
  });
});

describe('verdict: CoreState', () => {
  it('starts allowed with no checks and no reason', () => {
    const s = CoreState.init<string, string>();
    expect(s.allow).toBe(true);
    expect(s.checks).toEqual([]);
    expect(s.reason).toBeUndefined();
    expect(s.get('x')).toBeUndefined();
  });
  it('fail records the first reason only and evaluates why lazily', () => {
    let calls = 0;
    const s = CoreState.init<string, string>().fail('a', () => { calls++; return 'ra'; }).fail('b', () => { calls++; return 'rb'; });
    expect(calls).toBe(1);
    expect(s.reason).toBe('ra');
    expect(s.allow).toBe(false);
    expect(s.get('a')).toBe('fail');
    expect(s.get('b')).toBe('fail');
    expect(s.checks).toEqual([['a', 'fail'], ['b', 'fail']]);
  });
  it('set overwrites a check and a passed-over failure no longer denies (reason hidden when allowed)', () => {
    const s = CoreState.init<string, string>().fail('a', () => 'ra').set('a', 'pass');
    expect(s.get('a')).toBe('pass');
    expect(s.allow).toBe(true);
    expect(s.reason).toBeUndefined();
    expect(CoreState.init<string, string>().set('n', 'not-enforced').get('n')).toBe('not-enforced');
  });
  it('wireFail is terminal; malformed keeps the earlier reason', () => {
    const w = CoreState.wireFail<string, string>('wire', 'why');
    expect(w.allow).toBe(false);
    expect(w.reason).toBe('why');
    expect(w.checks).toEqual([['wire', 'fail']]);
    expect(w.set('wire', 'pass').allow).toBe(false); // terminal: still denied
    const m1 = CoreState.init<string, string>().malformed('malformed', 'boom');
    expect(m1.reason).toBe('boom');
    expect(m1.get('malformed')).toBe('fail');
    expect(m1.allow).toBe(false);
    const m2 = CoreState.init<string, string>().fail('a', () => 'first').malformed('malformed', 'second');
    expect(m2.reason).toBe('first');
    expect(m2.checks).toEqual([['a', 'fail'], ['malformed', 'fail']]);
  });
  it('zkRule: pass and fail are left alone; anything else fails closed with the reason', () => {
    const z = (s?: Status) => {
      let st = CoreState.init<string, string>();
      if (s) st = st.set('zk', s);
      let calls = 0;
      const out = st.zkRule('zk', () => { calls++; return 'zk-why'; });
      return { out, calls };
    };
    expect(z('pass').out.get('zk')).toBe('pass');
    expect(z('pass').calls).toBe(0);
    expect(z('fail').out.get('zk')).toBe('fail');
    expect(z('fail').calls).toBe(0);
    for (const s of ['not-enforced', undefined] as const) {
      const r = z(s);
      expect(r.out.get('zk')).toBe('fail');
      expect(r.out.reason).toBe('zk-why');
      expect(r.out.allow).toBe(false);
      expect(r.calls).toBe(1);
    }
  });
  it('attestGate: only gateOn && required && not-enforced fails', () => {
    for (const gateOn of bools) for (const required of bools) for (const s of ['pass', 'fail', 'not-enforced', undefined] as const) {
      let st = CoreState.init<string, string>();
      if (s) st = st.set('att', s);
      const out = st.attestGate('att', gateOn, required, () => 'att-why');
      const fails = gateOn && required && s === 'not-enforced';
      expect(out.get('att')).toBe(fails ? 'fail' : s);
      expect(out.reason).toBe(fails ? 'att-why' : undefined);
    }
  });
});

describe('verdict: VerdictState and enforceRequired', () => {
  it('init defaults to empty checks and reasons; explicit values are kept in order', () => {
    const e = VerdictState.init<string, string>();
    expect(e.checks).toEqual([]);
    expect(e.reasons).toEqual([]);
    const v = VerdictState.init<string, string>([['a', 'pass'], ['b', 'not-enforced']], ['r1']);
    expect(v.checks).toEqual([['a', 'pass'], ['b', 'not-enforced']]);
    expect(v.reasons).toEqual(['r1']);
  });
  it('fail appends the reason (lazily) and sets the check; set / push / pushAll / get', () => {
    let calls = 0;
    const v = VerdictState.init<string, string>().fail('a', () => { calls++; return 'ra'; }).push('p').pushAll(['q', 'r']).set('b', 'pass');
    expect(calls).toBe(1);
    expect(v.reasons).toEqual(['ra', 'p', 'q', 'r']);
    expect(v.checks).toEqual([['a', 'fail'], ['b', 'pass']]);
    expect(v.get('a')).toBe('fail');
    expect(v.get('b')).toBe('pass');
    expect(v.get('zz')).toBeUndefined();
    expect(VerdictState.init<string, string>().pushAll([]).reasons).toEqual([]);
  });
  it('applyThreshold records a failure with the rendered reason, and nothing on ok', () => {
    const why = (r: string) => `thr:${r}`;
    const mk = () => VerdictState.init<string, string>();
    expect(mk().applyThreshold('t', 3, true, 'pass', 2, why).reasons).toEqual(['thr:below']);
    expect(mk().applyThreshold('t', 3, true, 'fail', undefined, why).reasons).toEqual(['thr:rejected']);
    expect(mk().applyThreshold('t', 3, true, 'not-enforced', undefined, why).reasons).toEqual(['thr:no-verifier']);
    expect(mk().applyThreshold('t', 3, true, undefined, undefined, why).reasons).toEqual(['thr:no-verifier']);
    const ok = mk().applyThreshold('t', 3, true, 'pass', 3, why);
    expect(ok.reasons).toEqual([]);
    expect(ok.checks).toEqual([]);
    const failed = mk().applyThreshold('t', 3, true, 'pass', 2, why);
    expect(failed.get('t')).toBe('fail');
    expect(mk().applyThreshold('t', 1, true, undefined, undefined, why).checks).toEqual([]);
    expect(mk().applyThreshold('t', 3, false, 'fail', undefined, why).checks).toEqual([]);
    // hookT undefined with th pass is a shortfall; hookT equal to the requirement is fine
    expect(mk().applyThreshold('t', 2, true, 'pass', undefined, why).reasons).toEqual(['thr:below']);
    expect(mk().applyThreshold('t', 2, true, 'pass', 2, why).reasons).toEqual([]);
  });
  it('attestationRequiredFails and finalAllow', () => {
    for (const req of bools) for (const s of ['pass', 'fail', 'not-enforced', undefined] as const) {
      const v = s ? VerdictState.init<string, string>([['att', s]]) : VerdictState.init<string, string>();
      expect(v.attestationRequiredFails(req, 'att')).toBe(req && s !== 'pass');
    }
    for (const failing of bools) for (const rel of bools) for (const core of bools) {
      const v = VerdictState.init<string, string>([['a', failing ? 'fail' : 'pass']]);
      expect(v.finalAllow(rel, core)).toBe(!failing && rel && core);
    }
  });
  it('enforceRequired: non-pass required checks turn into fail with the mk reason; fail stays and still gets a reason', () => {
    const checks: Array<[string, Status]> = [['a', 'pass'], ['b', 'not-enforced'], ['c', 'fail']];
    const e = enforceRequired(true, checks, ['r0'], ['a', 'b', 'c', 'd'], (n, was) => `${n}:${was ?? 'absent'}`);
    expect(e.allow).toBe(false);
    expect(e.checks).toEqual([['a', 'pass'], ['b', 'fail'], ['c', 'fail'], ['d', 'fail']]);
    expect(e.reasons.slice(0, 1)).toEqual(['r0']);
    expect(e.reasons).toContain('b:not-enforced');
    expect(e.reasons).toContain('d:absent');
    const ok = enforceRequired(true, checks, [], ['a'], (n) => n);
    expect(ok).toEqual({ allow: true, checks, reasons: [] });
    expect(enforceRequired(false, checks, [], ['a'], (n) => n).allow).toBe(false);
  });
});

describe('Common helpers stay reachable', () => {
  it('Option constructors from the bridge are the Dafny ones', () => {
    expect(some(1).is_Some).toBe(true);
    expect(none().is_None).toBe(true);
  });
});
