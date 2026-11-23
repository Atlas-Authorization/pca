import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, hashCanonical } from '@atlasauth/pca';
import {
  approveGoal,
  loadApprovedGoal,
  type GoalApproval,
  type GoalSubmission,
  type ReviewKernel,
} from './review';
import { refDecide } from './refsem';
import { nlDigest } from './digests';
import type { GoalTest } from './examples';
import type { Act, Cond, Goal, Hist, Policy, Quantity } from './ir';
import { CNT, ONT, USD, ctrue, usd } from '../test/fixtures';

const INSTRUCTION = 'refund duplicate charge ch_1 for customer C1, at most 200 dollars';
const amt = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } } as const;
const amountLte = (n: number): Cond => ({ k: 'cmp', op: 'lte', l: amt, r: { k: 'lit', v: { k: 'q', q: usd(n) } } });
const cnt = (n: number): Quantity => ({ u: CNT, n });
const T0 = 1_700_000_000_000;

const baseGoal = (): Goal => ({
  v: 1,
  principal: 'user:alice',
  ontDigest: hashCanonical({ ontology: 'payments', version: 1 }),
  nlDigest: nlDigest(INSTRUCTION),
  sources: [],
  grants: [{ gid: 'g1', verb: 'pay.refund', res: { k: 'related', rel: 'charges_of', anchor: 'C1' }, cond: amountLte(20000) }],
  prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'pay.transfer' }, res: { k: 'any', reason: 'never move money out' }, cond: ctrue }],
  bounds: [{ bid: 'b1', sel: { k: 'gids', gids: ['g1'] }, agg: 'count', value: { k: 'lit', v: { k: 'q', q: cnt(1) } }, key: '', window: { k: 'task' }, scope: { k: 'session' }, cap: cnt(3), onExceed: 'escalate' }],
  validity: { notBefore: T0, notAfter: T0 + 86_400_000, maxIdle: 3_600_000 },
  deleg: { maxDepth: 0, narrowOnly: true, mayTouch: [] },
  escalateOn: [],
  wildcardAck: [],
  holes: [],
});

const empty: Hist = { adms: [], last: -1, aggs: {} };
const act = (o: Partial<Act> = {}): Act => ({ verb: 'pay.refund', res: 'ch_1', params: { amount: { k: 'q', q: usd(20000) } }, t: T0 + 10, sess: 's1', prin: 'user:alice', org: 'O', agent: 'a1', depth: 0, ...o });
const TESTS: GoalTest[] = [
  { id: 't-at-cap', act: act(), hist: empty, answer: 'allow' },
  { id: 't-over-cap', act: act({ params: { amount: { k: 'q', q: usd(20001) } } }), hist: empty, answer: 'deny' },
  { id: 't-void', act: act({ params: {} }), hist: empty, answer: 'ask' }, // amount missing: Unknown, never Allow
];

// The reference semantics decides; the compiled policy is a faithful projection of the goal (the proved compiler runs in CI, G-T1).
const kernel: ReviewKernel = {
  compile: (g) => ({ ok: true, policy: { goal: g } as unknown as Policy }),
  policyDigest: (p) => hashCanonical({ policy: p }),
  decide: (g, ont, a, h) => (['deny', 'escalate', 'allow'] as const)[refDecide(g, ont, a, h)]!,
};

const reviewer = generateKeyPair();
const rpk = b64u(reviewer.publicKey);
const NOW = T0;
const sub = (over: Partial<GoalSubmission> = {}): GoalSubmission => ({ goal: baseGoal(), ontology: ONT, instruction: INSTRUCTION, model_set: ['model-a', 'model-b'], tests: TESTS, ...over });
const load = (s: GoalSubmission, a: GoalApproval, o: Partial<Parameters<typeof loadApprovedGoal>[2]> = {}) => loadApprovedGoal(s, a, { kernel, reviewers: [rpk], now: NOW + 1000, ...o });
const reason = (r: ReturnType<typeof load>) => (r.ok ? 'ok' : r.reason);


describe('a non-finite clock never loads an approved goal', () => {
  const s = sub();
  const a = approveGoal(s, reviewer.secretKey, { kernel, now: NOW });
  it('a finite clock inside the window loads', () => {
    expect(reason(load(s, a))).toBe('ok');
  });
  // pre-fix: `approved_at > now` and `now >= expires_at` were both false for NaN, so the window read as open
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('now of %s', (now) => {
    expect(reason(load(s, a, { now }))).not.toBe('ok');
  });
});
