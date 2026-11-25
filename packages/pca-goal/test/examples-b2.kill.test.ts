import { generateKeyPair, hashCanonical } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { goalDigest } from '../src/digests';
import {
  boundaryExamples, checkGoalTests, checkPin, EMPTY_HIST, expectedDecision, makeGoalTests, mkAct, reviewSet, signGoalTests, signPin, testsDigest,
  type Example, type ExampleKind, type GoalTest, type GoalTestSet, type PolicyPin,
} from '../src/examples';
import type { Bound, Cond, Decision, Goal, Grant, Ontology, Term, Value } from '../src/ir';
import { signerId } from '../src/sign';
import { baseGoal, CNT, lteAmt, usd, USD } from './fixtures';

const key = () => { const sk = generateKeyPair().secretKey; return { sk, pin: signerId(sk) }; };
const ONTO: Ontology = { verbs: [{ verb: 'pay.refund', cls: 'money_out', params: [] }], rels: [] };
const usdV = (n: number): Value => ({ k: 'q', q: usd(n) });
const cntV = (n: number): Value => ({ k: 'q', q: { u: CNT, n } });
const grant = (gid: string, res = 'r1', cond: Cond = lteAmt(5000)): Grant => ({ gid, verb: 'pay.refund', res: { k: 'exact', id: res }, cond });
const bound = (bid: string, gids: string[], agg: Bound['agg'], value: Term, cap: Bound['cap'], k = ''): Bound =>
  ({ bid, sel: { k: 'gids', gids }, agg, value, key: k, window: { k: 'lifetime' }, scope: { k: 'session' }, cap, onExceed: 'deny' });
const goalOf = (grants: Grant[], bounds: Bound[]): Goal => baseGoal({ grants, bounds, wildcardAck: [] });
const LIT0: Term = { k: 'lit', v: cntV(0) };
const AMOUNT: Term = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } };
const examplesOf = (g: Goal) => boundaryExamples(g, { ont: ONTO }).examples;
const capsOf = (g: Goal) => examplesOf(g).filter((e) => e.kind === 'cap_sequence');
const CAP_ID = /^cap_sequence:[A-Za-z0-9_-]{12}$/;

describe('boundaryExamples cap sequences', () => {
  it('a count bound reaches its cap with cap actions, then one more is refused', () => {
    const act = mkAct('pay.refund', 'r1', { amount: usdV(4999) });
    expect(capsOf(goalOf([grant('g1')], [bound('b1', ['g1'], 'count', LIT0, { u: CNT, n: 3 })]))).toEqual([{
      id: expect.stringMatching(CAP_ID), kind: 'cap_sequence', why: 'reach the b1 cap with 3 action(s), then one more', act,
      hist: { adms: [{ gid: 'g1', act }, { gid: 'g1', act }, { gid: 'g1', act }], last: 0, aggs: {} }, rels: [], decision: 'deny',
    }]);
  });
  it('a sum bound divides the cap by the witness amount', () => {
    const act = mkAct('pay.refund', 'r1', { amount: usdV(4999) });
    expect(capsOf(goalOf([grant('g1')], [bound('bs', ['g1'], 'sum', AMOUNT, usd(12000))]))).toEqual([{
      id: expect.stringMatching(CAP_ID), kind: 'cap_sequence', why: 'reach the bs cap with 2 action(s), then one more', act,
      hist: { adms: [{ gid: 'g1', act }, { gid: 'g1', act }], last: 0, aggs: {} }, rels: [], decision: 'deny',
    }]);
  });
  it('a sequence of 61 or more actions is not generated, one of exactly 60 is', () => {
    expect(capsOf(goalOf([grant('g1')], [bound('b1', ['g1'], 'count', LIT0, { u: CNT, n: 100 })]))).toEqual([]);
    expect(capsOf(goalOf([grant('g1')], [bound('b1', ['g1'], 'count', LIT0, { u: CNT, n: 61 })]))).toEqual([]);
    const at60 = capsOf(goalOf([grant('g1')], [bound('b1', ['g1'], 'count', LIT0, { u: CNT, n: 60 })]));
    expect(at60.map((e) => e.why)).toEqual(['reach the b1 cap with 60 action(s), then one more']);
    expect(at60[0]!.hist.adms).toHaveLength(60);
    expect(at60[0]!.decision).toBe('deny');
  });
  it('a sum bound whose witness amount is zero yields no sequence', () => {
    expect(capsOf(goalOf([grant('g1', 'r1', lteAmt(0))], [bound('bs', ['g1'], 'sum', AMOUNT, usd(0))]))).toEqual([]);
  });
  it('a max bound with a zero witness amount and a zero cap still yields its (empty-prefix) sequence', () => {
    const act = mkAct('pay.refund', 'r1', { amount: usdV(0) });
    expect(capsOf(goalOf([grant('g1', 'r1', lteAmt(0))], [bound('bm', ['g1'], 'max', AMOUNT, usd(0))]))).toEqual([{
      id: expect.stringMatching(CAP_ID), kind: 'cap_sequence', why: 'reach the bm cap with NaN action(s), then one more', act,
      hist: { adms: [], last: -1, aggs: {} }, rels: [], decision: 'allow',
    }]);
  });
  it('a sum bound over a literal value takes no amount from a parameter that is merely named undefined', () => {
    const cond: Cond = { k: 'cmp', op: 'lte', l: { k: 'param', path: 'undefined', ty: { k: 'q', u: USD } }, r: { k: 'lit', v: usdV(100) } };
    const g = goalOf([grant('g1', 'r1', cond)], [bound('bs', ['g1'], 'sum', { k: 'lit', v: usdV(5) }, usd(10))]);
    expect(examplesOf(g).some((e) => e.kind === 'probe')).toBe(true);
    expect(capsOf(g)).toEqual([]);
  });
  it('a distinct bound over a text parameter reads no amount from it', () => {
    const cond: Cond = { k: 'cmp', op: 'eq', l: { k: 'param', path: 'customer', ty: { k: 's' } }, r: { k: 'lit', v: { k: 's', s: 'c1' } } };
    const g = goalOf([grant('g1', 'r1', cond)], [bound('bd', ['g1'], 'distinct', { k: 'param', path: 'customer', ty: { k: 's' } }, { u: CNT, n: 2 }, 'customer')]);
    expect(examplesOf(g).some((e) => e.kind === 'allow_witness')).toBe(true);
    expect(capsOf(g)).toEqual([]);
  });
  it('a bound on a grant that has no witness (shadowed by an identical earlier grant) yields no sequence and no probes for it', () => {
    const g = goalOf([grant('g1'), grant('g2')], [bound('b2', ['g2'], 'count', LIT0, { u: CNT, n: 3 })]);
    const ex = examplesOf(g);
    expect(ex.filter((e) => e.kind === 'cap_sequence')).toEqual([]);
    expect(ex.filter((e) => e.kind === 'probe')).toHaveLength(3);
  });
});

describe('boundaryExamples probes', () => {
  const cond: Cond = { k: 'and', a: lteAmt(5000), b: { k: 'cmp', op: 'lte', l: { k: 'param', path: 'n', ty: { k: 'q', u: CNT } }, r: { k: 'lit', v: cntV(5) } } };
  const probes = (g: Goal): Example[] => examplesOf(g).filter((e) => e.kind === 'probe');
  it('emits an extreme-money probe, an other-resource probe and an other-anchor probe, and none for a non-money quantity', () => {
    const act = mkAct('pay.refund', 'r1', { amount: usdV(4999), n: cntV(4) });
    expect(probes(goalOf([grant('g1', 'r1', cond)], []))).toEqual([
      { id: expect.stringMatching(/^probe:[A-Za-z0-9_-]{12}$/), kind: 'probe', why: 'extreme amount', act: { ...act, params: { amount: usdV(1_000_000_000), n: cntV(4) } }, hist: EMPTY_HIST, rels: [], decision: 'deny' },
      { id: expect.stringMatching(/^probe:[A-Za-z0-9_-]{12}$/), kind: 'probe', why: 'other resource', act: { ...act, res: '\u0000other-resource' }, hist: EMPTY_HIST, rels: [], decision: 'deny' },
      { id: expect.stringMatching(/^probe:[A-Za-z0-9_-]{12}$/), kind: 'probe', why: 'other customer/anchor', act, hist: EMPTY_HIST, rels: [], decision: 'allow' },
    ]);
  });
  it('drops an example whose id repeats (two grants share the same other-resource probe)', () => {
    const g = goalOf([grant('g1', 'r1'), grant('g2', 'r2')], []);
    const ex = examplesOf(g);
    expect(new Set(ex.map((e) => e.id)).size).toBe(ex.length);
    const ps = probes(g);
    expect(ps.filter((e) => e.why === 'other resource')).toHaveLength(1);
    expect(ps).toHaveLength(5);
  });
});

describe('reviewSet', () => {
  const ex = (id: string, kind: ExampleKind, decision: Decision): Example => ({ id, kind, why: '', act: mkAct('v', 'r'), hist: EMPTY_HIST, rels: [], decision });
  const items: Example[] = [
    ex('a', 'boundary', 'deny'), ex('b', 'probe', 'deny'), ex('c', 'member', 'allow'), ex('d', 'probe', 'allow'),
    ex('e', 'cap_sequence', 'allow'), ex('f', 'allow_witness', 'escalate'), ex('g1', 'probe', 'allow'), ex('g0', 'probe', 'allow'),
  ];
  const ids = (xs: Example[]): string[] => xs.map((e) => e.id);
  it('orders by decision (allow, escalate, deny), then kind weight, then id', () => {
    const want = ['d', 'g0', 'g1', 'e', 'c', 'f', 'b', 'a'];
    expect(ids(reviewSet(items, 100))).toEqual(want);
    expect(ids(reviewSet([...items].reverse(), 100))).toEqual(want);
    expect(ids(reviewSet(items, 3))).toEqual(want.slice(0, 3));
  });
  it('orders the kinds probe, cap_sequence, allow_witness, prohibit_trigger, member, boundary within one decision', () => {
    const kinds: ExampleKind[] = ['probe', 'cap_sequence', 'allow_witness', 'prohibit_trigger', 'member', 'boundary'];
    const xs = kinds.map((k, i) => ex(`z${5 - i}`, k, 'allow'));
    expect(reviewSet([...xs].reverse(), 6).map((e) => e.kind)).toEqual(kinds);
    expect(reviewSet(xs, 6).map((e) => e.kind)).toEqual(kinds);
  });
  it('breaks a full tie by id ascending', () => {
    expect(ids(reviewSet([ex('b', 'probe', 'allow'), ex('a', 'probe', 'allow')], 2))).toEqual(['a', 'b']);
    expect(ids(reviewSet([ex('a', 'probe', 'allow'), ex('b', 'probe', 'allow')], 2))).toEqual(['a', 'b']);
  });
  it('keeps the input order of examples whose id is also equal (stable)', () => {
    const x = { ...ex('same', 'probe', 'allow'), why: 'first' };
    const y = { ...ex('same', 'probe', 'allow'), why: 'second' };
    expect(reviewSet([x, y], 2).map((e) => e.why)).toEqual(['first', 'second']);
  });
});

describe('testsDigest', () => {
  const t = (id: string, answer: GoalTest['answer'] = 'allow'): GoalTest => ({ id, act: mkAct('pay.refund', 'r1'), hist: EMPTY_HIST, answer });
  const dig = (tests: GoalTest[]): string => hashCanonical({ d: 'atlas-pca/goal-tests/v1', tests });
  it('is the digest of the id-sorted tests whatever the input order', () => {
    expect(testsDigest([t('a'), t('b')])).toBe(dig([t('a'), t('b')]));
    expect(testsDigest([t('b'), t('a')])).toBe(dig([t('a'), t('b')]));
    expect(testsDigest([t('c'), t('a'), t('b')])).toBe(dig([t('a'), t('b'), t('c')]));
  });
  it('keeps the input order of tests with an equal id', () => {
    expect(testsDigest([t('a', 'allow'), t('a', 'deny')])).toBe(dig([t('a', 'allow'), t('a', 'deny')]));
  });
});

describe('makeGoalTests', () => {
  it('takes goal and ontology digests from the goal and the tests from the confirmed examples', () => {
    const g = baseGoal();
    const rels = [{ rel: 'r', anchor: 'a', members: ['x'] }];
    const example: Example = { id: 'e1', kind: 'member', why: 'w', act: mkAct('pay.refund', 'r1'), hist: EMPTY_HIST, rels, decision: 'allow' };
    const tests: GoalTest[] = [{ id: 'e1', act: example.act, hist: EMPTY_HIST, rels, answer: 'ask' }];
    expect(makeGoalTests(g, [{ example, answer: 'ask' }])).toEqual({ goal_digest: goalDigest(g), ontology_digest: g.ontDigest, tests, tests_digest: testsDigest(tests) });
  });
});

describe('checkGoalTests', () => {
  const t = (id: string, answer: GoalTest['answer']): GoalTest => ({ id, act: mkAct('pay.refund', 'r1'), hist: EMPTY_HIST, answer });
  const tests = [t('t1', 'allow'), t('t2', 'ask'), t('t3', 'deny')];
  const set: GoalTestSet = { goal_digest: 'gd', ontology_digest: 'od', tests, tests_digest: testsDigest(tests) };
  const faithful = (x: GoalTest): Decision => expectedDecision(x.answer);
  it('accepts a faithful recompile', () => {
    const k = key();
    expect(checkGoalTests(signGoalTests(set, k.sk), [k.pin], faithful)).toEqual({ ok: true, failures: [] });
  });
  it('refuses a wrong signer with reason signature and no failures', () => {
    const k = key();
    expect(checkGoalTests(signGoalTests(set, k.sk), [key().pin], faithful)).toEqual({ ok: false, reason: 'signature', failures: [] });
  });
  it('refuses a tampered payload with reason signature', () => {
    const k = key();
    const s = signGoalTests(set, k.sk);
    expect(checkGoalTests({ ...s, payload: { ...s.payload, tests: [t('t1', 'allow')] } }, [k.pin], faithful)).toEqual({ ok: false, reason: 'signature', failures: [] });
  });
  it('refuses a validly signed set whose tests_digest does not match its tests', () => {
    const k = key();
    expect(checkGoalTests(signGoalTests({ ...set, tests_digest: 'bad' }, k.sk), [k.pin], faithful)).toEqual({ ok: false, reason: 'tests_digest', failures: [] });
  });
  it('reports each regression with its id, expected and got decision', () => {
    const k = key();
    const decide = (x: GoalTest): Decision => (x.id === 't1' ? 'deny' : x.id === 't2' ? 'allow' : 'deny');
    expect(checkGoalTests(signGoalTests(set, k.sk), [k.pin], decide)).toEqual({
      ok: false, reason: 'test_regression',
      failures: [{ id: 't1', expected: 'allow', got: 'deny' }, { id: 't2', expected: 'escalate', got: 'allow' }],
    });
  });
});

describe('checkPin', () => {
  const g = baseGoal();
  const ex: Example = { id: 'e1', kind: 'member', why: 'w', act: mkAct('pay.refund', 'r1'), hist: EMPTY_HIST, rels: [], decision: 'allow' };
  const tests = makeGoalTests(g, [{ example: ex, answer: 'allow' }]);
  const pinBody: PolicyPin = { goal_digest: goalDigest(g), policy_digest: 'pd', tests_digest: tests.tests_digest, ontology_digest: g.ontDigest };
  const cur = { goal: g, policy_digest: 'pd', tests };
  it('accepts a pin that matches everything', () => {
    const k = key();
    expect(checkPin(signPin(pinBody, k.sk), [k.pin], cur)).toEqual({ ok: true });
  });
  it('refuses a wrong signer and a tampered pin with reason signature', () => {
    const k = key();
    const p = signPin(pinBody, k.sk);
    expect(checkPin(p, [key().pin], cur)).toEqual({ ok: false, reason: 'signature' });
    expect(checkPin({ ...p, payload: { ...p.payload, policy_digest: 'other' } }, [k.pin], { ...cur, policy_digest: 'other' })).toEqual({ ok: false, reason: 'signature' });
  });
  it('refuses a changed goal, policy and ontology each with its own reason', () => {
    const k = key();
    const p = signPin(pinBody, k.sk);
    expect(checkPin(p, [k.pin], { ...cur, goal: { ...g, v: 2 } })).toEqual({ ok: false, reason: 'goal changed under the pin' });
    expect(checkPin(p, [k.pin], { ...cur, policy_digest: 'other' })).toEqual({ ok: false, reason: 'policy changed under the pin' });
    expect(checkPin(signPin({ ...pinBody, ontology_digest: 'other' }, k.sk), [k.pin], cur)).toEqual({ ok: false, reason: 'ontology changed under the pin' });
  });
  it('refuses changed tests when either the stored digest or the recomputed digest disagrees with the pin', () => {
    const k = key();
    const bad = { ok: false, reason: 'tests changed under the pin' };
    // the pin's digest differs from both the stored and the recomputed digest
    expect(checkPin(signPin({ ...pinBody, tests_digest: 'x' }, k.sk), [k.pin], cur)).toEqual(bad);
    // the pin matches the recomputed digest but the set's stored digest is stale
    expect(checkPin(signPin(pinBody, k.sk), [k.pin], { ...cur, tests: { ...tests, tests_digest: 'stale' } })).toEqual(bad);
    // the pin matches the stored digest but the tests were edited under it
    expect(checkPin(signPin(pinBody, k.sk), [k.pin], { ...cur, tests: { ...tests, tests: [...tests.tests, { id: 'e2', act: ex.act, hist: EMPTY_HIST, answer: 'deny' }] } })).toEqual(bad);
  });
});
