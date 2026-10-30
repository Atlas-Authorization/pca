import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, goalCommitOf, hashCanonical } from '@atlasauth/pca';
import { decideIntentBinding, intentGoal, intentGoalCommit, type EnvelopeIntent } from '@atlasauth/pca/ext/intent';
import {
  GOAL_APPROVAL_KIND,
  GOAL_APPROVAL_SIGNED_FIELDS,
  MAX_GOAL_APPROVAL_TTL_MS,
  REVIEW_LIMITS,
  ReviewError,
  approveGoal,
  cardDigest,
  cardToText,
  diffGoals,
  diffToText,
  effectiveLimits,
  loadApprovedGoal,
  renderPolicyCard,
  type GoalApproval,
  type GoalSubmission,
  type ReviewKernel,
} from './review';
import { refDecide } from './refsem';
import { goalDigest, modelSetDigest, nlDigest } from './digests';
import { testsDigest, type GoalTest } from './examples';
import { signGoalArtifact } from './sign';
import type { Act, Bound, Cond, Goal, Hist, Policy, Quantity } from './ir';
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
const other = generateKeyPair();
const NOW = T0;
const sub = (over: Partial<GoalSubmission> = {}): GoalSubmission => ({ goal: baseGoal(), ontology: ONT, instruction: INSTRUCTION, model_set: ['model-a', 'model-b'], tests: TESTS, ...over });
const approve = (s = sub()) => approveGoal(s, reviewer.secretKey, { kernel, now: NOW });
const load = (s: GoalSubmission, a: GoalApproval, o: Partial<Parameters<typeof loadApprovedGoal>[2]> = {}) => loadApprovedGoal(s, a, { kernel, reviewers: [rpk], now: NOW + 1000, ...o });
const reason = (r: ReturnType<typeof load>) => (r.ok ? 'ok' : r.reason);
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

describe('approveGoal + loadApprovedGoal: the happy path', () => {
  it('a pinned reviewer approval over the exact goal loads, re-derived', () => {
    const s = sub();
    const a = approve(s);
    const r = load(s, a);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.approved.ref.goal_digest).toBe(goalDigest(s.goal));
    const c = kernel.compile(s.goal, ONT);
    if (!c.ok) throw new Error('compile failed');
    expect(r.approved.ref.policy_digest).toBe(kernel.policyDigest(c.policy));
    expect(r.approved.reviewer).toBe(rpk);
    expect(r.approved.goal_string).toBe(`pca-intent:v3:${r.approved.ref.goal_digest}:${r.approved.ref.policy_digest}`);
  });
  it('the approval covers all digests, the reviewer and the window, under the suite-agile signer', () => {
    const a = approve();
    expect([...GOAL_APPROVAL_SIGNED_FIELDS]).toEqual(['v', 'goal_digest', 'policy_digest', 'card_digest', 'ontology_digest', 'tests_digest', 'nl_digest', 'model_set_digest', 'reviewer', 'approved_at', 'expires_at']);
    const s = sub();
    expect(a.goal_digest).toBe(goalDigest(s.goal));
    expect(a.card_digest).toBe(cardDigest(renderPolicyCard(s.goal, TESTS)));
    expect(a.tests_digest).toBe(testsDigest(TESTS));
    expect(a.nl_digest).toBe(nlDigest(INSTRUCTION));
    expect(a.model_set_digest).toBe(modelSetDigest(['model-b', 'model-a', 'model-a']));
    expect(a.ontology_digest).toBe(s.goal.ontDigest);
  });
  it('an approval signed under another artifact kind never verifies (domain separation)', () => {
    const s = sub();
    const { sig: _s, alg: _a, pq_pk: _p, pq_sig: _q, ...body } = approve(s);
    const wrong = signGoalArtifact(GOAL_APPROVAL_KIND + '-x', body, reviewer.secretKey) as GoalApproval;
    expect(reason(load(s, wrong))).toBe('bad_signature');
  });
  it('the grant minted for the approved goal opens under the v3 verifier policy, and only for it (W1)', () => {
    const s = sub();
    const r = load(s, approve(s));
    if (!r.ok) throw new Error('load failed');
    const { goal_string, intent_policy } = r.approved;
    const I: EnvelopeIntent = { ref: b64u(new Uint8Array(32).fill(1)), map_digest: b64u(new Uint8Array(32).fill(2)), goal_salt: 'salt', fidelity_ppm: 0, residual_risk_ppm: 0 };
    const grant = { caveats: [{ type: 'envelope', goal_commit: goalCommitOf(goal_string, 'salt') }] };
    expect(decideIntentBinding(I, grant, intent_policy)).toEqual({ status: 'pass' });
    expect(decideIntentBinding(I, { caveats: [{ type: 'envelope', goal_commit: intentGoalCommit(I) }] }, intent_policy).status).toBe('fail');
    expect(intentGoal(I.ref, I.map_digest)).not.toBe(goal_string);
    const s2 = sub({ goal: { ...baseGoal(), validity: { ...baseGoal().validity, notAfter: T0 + 86_400_001 } } });
    const r2 = load(s2, approve(s2));
    if (!r2.ok) throw new Error('load failed');
    expect(r2.approved.goal_string).not.toBe(goal_string);
    expect(decideIntentBinding(I, grant, r2.approved.intent_policy).status).toBe('fail');
  });
});

describe('tamper tests: every approved field', () => {
  const s = sub();
  const a = approve(s);
  const flip = (x: string) => (x[0] === 'A' ? 'B' : 'A') + x.slice(1);

  const approvalRows: Array<[keyof GoalApproval, GoalApproval, string]> = [
    ['v', { ...a, v: 2 as never }, 'malformed_approval'],
    ['goal_digest', { ...a, goal_digest: flip(a.goal_digest) }, 'goal_digest_mismatch'],
    ['policy_digest', { ...a, policy_digest: flip(a.policy_digest) }, 'policy_digest_mismatch'],
    ['card_digest', { ...a, card_digest: flip(a.card_digest) }, 'card_digest_mismatch'],
    ['ontology_digest', { ...a, ontology_digest: flip(a.ontology_digest) }, 'ontology_mismatch'],
    ['tests_digest', { ...a, tests_digest: flip(a.tests_digest) }, 'tests_digest_mismatch'],
    ['nl_digest', { ...a, nl_digest: flip(a.nl_digest) }, 'nl_digest_mismatch'],
    ['model_set_digest', { ...a, model_set_digest: flip(a.model_set_digest) }, 'model_set_digest_mismatch'],
    ['reviewer', { ...a, reviewer: b64u(other.publicKey) }, 'reviewer_not_pinned'],
    ['approved_at', { ...a, approved_at: a.approved_at + 1 }, 'bad_signature'],
    ['expires_at', { ...a, expires_at: a.expires_at - 1 }, 'bad_signature'],
    ['sig', { ...a, sig: approveGoal(s, other.secretKey, { kernel, now: NOW }).sig }, 'bad_signature'],
  ];
  it.each(approvalRows.map(([f, ap, r]) => [f, ap, r] as const))('approval field %s changed: %s', (_f, ap, r) => {
    expect(reason(load(s, ap))).toBe(r);
  });
  it('every signed field is exercised above', () => {
    expect(new Set(approvalRows.map(([f]) => f))).toEqual(new Set([...GOAL_APPROVAL_SIGNED_FIELDS, 'sig']));
  });
  it('a suite member injected into an Ed25519 approval is refused', () => {
    expect(reason(load(s, { ...a, pq_pk: 'AAAA' }))).toBe('bad_signature');
  });
  it('a re-signed approval by an unpinned key never loads', () => {
    expect(reason(load(s, approveGoal(s, other.secretKey, { kernel, now: NOW })))).toBe('reviewer_not_pinned');
  });

  const goalRows: Array<[string, (g: Goal) => void, string]> = [
    ['principal', (g) => { g.principal = 'user:mallory'; }, 'goal_digest_mismatch'],
    ['ontDigest', (g) => { g.ontDigest = flip(g.ontDigest); }, 'goal_digest_mismatch'],
    ['nlDigest', (g) => { g.nlDigest = flip(g.nlDigest); }, 'instruction_mismatch'],
    ['sources', (g) => { g.sources = ['AAAA']; }, 'goal_digest_mismatch'],
    ['grants (verb)', (g) => { g.grants[0]!.verb = 'pay.transfer'; }, 'tests_contradicted'] /* the confirmed examples catch it before the digest compare */,
    ['grants (extra)', (g) => { g.grants.push({ gid: 'g2', verb: 'pay.read', res: { k: 'exact', id: 'acct:1' }, cond: ctrue }); }, 'goal_digest_mismatch'],
    ['grants (cap)', (g) => { g.grants[0]!.cond = amountLte(2_000_000); }, 'tests_contradicted'],
    ['grants (resource)', (g) => { g.grants[0]!.res = { k: 'exact', id: 'customer:C999' }; }, 'tests_contradicted'],
    ['prohibits', (g) => { g.prohibits = []; }, 'goal_digest_mismatch'],
    ['bounds', (g) => { g.bounds[0]!.cap = cnt(300); }, 'goal_digest_mismatch'],
    ['validity', (g) => { g.validity.notAfter += 1; }, 'goal_digest_mismatch'],
    ['deleg', (g) => { g.deleg.maxDepth = 4; }, 'goal_digest_mismatch'],
    ['escalateOn', (g) => { g.escalateOn = [amountLte(1)]; }, 'goal_digest_mismatch'],
    ['wildcardAck', (g) => { g.wildcardAck = ['p1', 'p2']; }, 'goal_digest_mismatch'],
    ['holes', (g) => { g.holes = [{ hid: 'h1', q: 'which customer?', domain: ['C1', 'C2'], affects: ['g1'], global: false }]; }, 'holes'],
    ['v', (g) => { g.v = 2; }, 'goal_digest_mismatch'],
  ];
  it.each(goalRows.map(([n, m, r]) => [n, m, r] as const))('goal field %s tampered after approval: %s', (_n, mut, r) => {
    const g = clone(s.goal);
    mut(g);
    expect(reason(load({ ...s, goal: g }, a))).toBe(r);
  });
  it('every top-level Goal member is exercised above', () => {
    const covered = new Set(goalRows.map(([n]) => n.split(' ')[0]));
    for (const k of Object.keys(baseGoal())) expect(covered.has(k)).toBe(true);
  });

  it('the instruction text, model set and tests are bound too', () => {
    expect(reason(load({ ...s, instruction: INSTRUCTION + ' and also refund everything' }, a))).toBe('instruction_mismatch');
    expect(reason(load({ ...s, model_set: ['model-a'] }, a))).toBe('model_set_digest_mismatch');
    expect(reason(load({ ...s, model_set: [] }, a))).toBe('model_set_digest_mismatch');
    expect(reason(load({ ...s, tests: TESTS.slice(1) }, a))).toBe('tests_digest_mismatch');
    expect(reason(load({ ...s, tests: [...TESTS, { id: 't-new', act: act({ verb: 'pay.read', res: 'x', params: {} }), hist: empty, answer: 'deny' }] }, a))).toBe('tests_digest_mismatch');
    expect(reason(load({ ...s, tests: TESTS.map((t) => (t.id === 't-over-cap' ? { ...t, answer: 'allow' as const } : t)) }, a))).toBe('tests_contradicted');
    expect(reason(load({ ...s, tests: undefined }, a))).toBe('tests_digest_mismatch');
  });
  it('a recompile that drifts (another compiler or ontology version) is refused: the policy digest is re-derived', () => {
    const drifted: ReviewKernel = { ...kernel, policyDigest: (p) => hashCanonical({ policy: p, compiler: 'v2' }) };
    expect(reason(load(s, a, { kernel: drifted }))).toBe('policy_digest_mismatch');
  });
  it('a pinned ontology that differs from the goal ontology is refused', () => {
    expect(reason(load(s, a, { ontology_digest: flip(s.goal.ontDigest) }))).toBe('ontology_mismatch');
    expect(reason(load(s, a, { ontology_digest: s.goal.ontDigest }))).toBe('ok');
  });
});

describe('loader refusals', () => {
  const s = sub();
  const a = approve(s);
  it('no reviewers pinned, or an unpinned one', () => {
    expect(reason(load(s, a, { reviewers: [] }))).toBe('no_reviewers_pinned');
    expect(reason(load(s, a, { reviewers: undefined as never }))).toBe('no_reviewers_pinned');
    expect(reason(load(s, a, { reviewers: [b64u(other.publicKey)] }))).toBe('reviewer_not_pinned');
    expect(reason(load(s, a, { reviewers: [{ pk: rpk }] }))).toBe('ok');
  });
  it('time: not yet valid, expired at the boundary, ttl beyond the maximum', () => {
    expect(reason(load(s, a, { now: NOW - 1 }))).toBe('not_yet_valid');
    expect(reason(load(s, a, { now: a.expires_at - 1 }))).toBe('ok');
    expect(reason(load(s, a, { now: a.expires_at }))).toBe('expired');
    expect(reason(load(s, { ...a, expires_at: a.approved_at + MAX_GOAL_APPROVAL_TTL_MS + 1 }))).toBe('ttl_too_long');
    expect(reason(load(s, { ...a, expires_at: a.approved_at }))).toBe('ttl_too_long');
  });
  it('approving: invalid ttl is refused', () => {
    for (const ttlMs of [0, -1, NaN, MAX_GOAL_APPROVAL_TTL_MS + 1]) expect(() => approveGoal(s, reviewer.secretKey, { kernel, now: NOW, ttlMs })).toThrow('approveGoal: invalid time or ttl');
    expect(() => approveGoal(s, reviewer.secretKey, { kernel, now: NaN })).toThrow('approveGoal: invalid time or ttl');
  });
  it('holes: not signable, not loadable', () => {
    const g = { ...baseGoal(), holes: [{ hid: 'h1', q: 'locale of "1,000"?', domain: ['1000', '1.000'], affects: [], global: true }] };
    expect(() => approve(sub({ goal: g }))).toThrow('approveGoal: holes');
    expect(reason(load(sub({ goal: g }), a))).toBe('holes');
  });
  it('an `any` resource needs an explicit acknowledgement', () => {
    const g2: Goal = { ...baseGoal(), grants: [{ gid: 'g1', verb: 'pay.refund', res: { k: 'any', reason: 'all' }, cond: amountLte(1) }], wildcardAck: [] };
    expect(() => approve(sub({ goal: g2, tests: [] }))).toThrow('approveGoal: wildcard_unacknowledged');
    const acked = { ...g2, wildcardAck: ['g1'] };
    const l = renderPolicyCard(acked).lines.find((x) => x.id === 'g1')!;
    expect(l.severity).toBe('red');
    expect(l.text).toContain('WILDCARD acknowledged');
    expect(reason(load(sub({ goal: acked, tests: [] }), approve(sub({ goal: acked, tests: [] }))))).toBe('ok');
  });
  it('compile error, analyzer error, throwing kernel', () => {
    const noCompile: ReviewKernel = { ...kernel, compile: () => ({ ok: false, reasons: ['ill_typed_grant'] }) };
    const bad: ReviewKernel = { ...kernel, analyze: () => ['vacuous'] };
    const boom: ReviewKernel = { ...kernel, compile: () => { throw new Error('boom'); } };
    expect(reason(load(s, a, { kernel: noCompile }))).toBe('compile_error');
    expect(reason(load(s, a, { kernel: bad }))).toBe('analyzer_error');
    expect(reason(load(s, a, { kernel: boom }))).toBe('compile_error');
  });
  it('tests with a kernel that cannot decide are refused (never silently skipped)', () => {
    const blind: ReviewKernel = { compile: kernel.compile, policyDigest: kernel.policyDigest };
    expect(reason(load(s, a, { kernel: blind }))).toBe('tests_unverifiable');
    const noTests = sub({ tests: [] });
    expect(reason(load(noTests, approveGoal(noTests, reviewer.secretKey, { kernel: blind, now: NOW }), { kernel: blind }))).toBe('ok');
  });
  it('never throws on garbage', () => {
    for (const bad of [null, undefined, 5, 'x', [], {}]) {
      expect(reason(load(bad as never, a))).toMatch(/^malformed_/);
      expect(reason(load(s, bad as never))).toBe('malformed_approval');
    }
    expect(reason(load({ ...s, goal: { ...baseGoal(), validity: { notBefore: undefined as never, notAfter: 1, maxIdle: 1 } } }, a))).toMatch(/^(malformed_goal|unrenderable)$/);
    expect(reason(load({ ...s, instruction: 5 as never }, a))).toBe('malformed_submission');
  });
});

describe('PolicyCard', () => {
  it('is deterministic and renders every clause with exact numbers', () => {
    const c1 = renderPolicyCard(baseGoal(), TESTS);
    const c2 = renderPolicyCard(clone(baseGoal()), clone(TESTS));
    expect(cardDigest(c1)).toBe(cardDigest(c2));
    expect(c1.lines.map((l) => l.id)).toEqual(['principal', 'g1', 'p1', 'b1', 'validity', 'delegation', 'example:t-at-cap', 'example:t-over-cap', 'example:t-void']);
    const text = cardToText(c1);
    expect(text).toContain('USD minor units');
    expect(text).toContain('20000 USD minor units');
    expect(text).toContain('pay.refund');
    expect(text).toContain('charges_of');
    expect(text).toContain('ask the principal');
    expect(text).toContain(String(T0 + 86_400_000));
    expect(text).toContain('Nothing outside this card is allowed');
    expect(c1.goal_digest).toBe(goalDigest(baseGoal()));
  });
  it('each clause carries a digest that changes with the clause', () => {
    const a = renderPolicyCard(baseGoal());
    const g = baseGoal();
    g.grants[0]!.cond = amountLte(20001);
    const b = renderPolicyCard(g);
    expect(a.lines.find((l) => l.id === 'g1')!.clause_digest).not.toBe(b.lines.find((l) => l.id === 'g1')!.clause_digest);
    expect(a.lines.find((l) => l.id === 'p1')!.clause_digest).toBe(b.lines.find((l) => l.id === 'p1')!.clause_digest);
    expect(cardDigest(a)).not.toBe(cardDigest(b));
  });
  it('any change to the goal changes the card digest', () => {
    const base = cardDigest(renderPolicyCard(baseGoal()));
    const muts: Array<(g: Goal) => void> = [
      (g) => { g.grants[0]!.verb = 'pay.read'; },
      (g) => { g.bounds[0]!.cap = cnt(4); },
      (g) => { g.validity.maxIdle += 1; },
      (g) => { g.deleg.mayTouch = ['g1']; },
      (g) => { g.escalateOn = [amountLte(5)]; },
      (g) => { g.prohibits[0]!.target = { k: 'effect', cls: 'money_out' }; },
      (g) => { g.principal = 'user:bob'; },
      (g) => { g.grants[0]!.res = { k: 'all_of', parts: [{ k: 'related', rel: 'charges_of', anchor: 'C1' }, { k: 'oneof', ids: ['ch_1'] }] }; },
    ];
    for (const m of muts) {
      const g = baseGoal();
      m(g);
      expect(cardDigest(renderPolicyCard(g))).not.toBe(base);
    }
  });
  it('the card shows an all_of selector as an explicit conjunction', () => {
    const g = baseGoal();
    g.grants[0]!.res = { k: 'all_of', parts: [{ k: 'related', rel: 'charges_of', anchor: 'C1' }, { k: 'oneof', ids: ['ch_1'] }] };
    expect(renderPolicyCard(g).lines.find((l) => l.id === 'g1')!.text).toContain('ALL OF (');
  });
  it('wildcards and a non-narrowing delegation are rendered in red', () => {
    const c = renderPolicyCard({ ...baseGoal(), deleg: { maxDepth: 2, narrowOnly: false, mayTouch: [] } });
    expect(c.lines.find((l) => l.id === 'p1')!.severity).toBe('red');
    expect(c.lines.find((l) => l.id === 'delegation')!.severity).toBe('red');
    expect(c.lines.find((l) => l.id === 'g1')!.severity).toBe('info');
    expect(cardToText(c)).toMatch(/!! NEVER/);
  });
  it('a draft can be displayed with its holes in red, but not signed', () => {
    const g = { ...baseGoal(), holes: [{ hid: 'h1', q: 'which customer?', domain: ['C1', 'C2'], affects: ['g1'], global: false }] };
    expect(() => renderPolicyCard(g)).toThrow(ReviewError);
    const c = renderPolicyCard(g, [], { allowHoles: true });
    expect(c.lines.filter((l) => l.kind === 'hole')).toHaveLength(1);
    expect(c.lines.find((l) => l.kind === 'hole')!.severity).toBe('red');
  });
  it('an unknown clause shape is rendered as its canonical JSON, never dropped', () => {
    const g = baseGoal();
    (g.grants[0] as unknown as { cond: unknown }).cond = { k: 'future_op', x: 1 };
    expect(renderPolicyCard(g).lines.find((l) => l.id === 'g1')!.text).toContain('{"k":"future_op","x":1}');
  });
});

describe('reviewer-fatigue limits refuse, never truncate', () => {
  const many = (n: number): Goal => ({ ...baseGoal(), grants: Array.from({ length: n }, (_, i) => ({ gid: `g${String(i).padStart(3, '0')}`, verb: 'pay.refund', res: { k: 'exact' as const, id: `charge:${i}` }, cond: amountLte(1) })) });
  it('the cap is exact: at the cap renders, one over is refused with card_too_large', () => {
    expect(renderPolicyCard(many(REVIEW_LIMITS.max_grants)).lines.length).toBeGreaterThan(REVIEW_LIMITS.max_grants);
    expect(() => renderPolicyCard(many(REVIEW_LIMITS.max_grants + 1))).toThrow(/card_too_large/);
    expect(() => renderPolicyCard(baseGoal(), Array.from({ length: REVIEW_LIMITS.max_examples + 1 }, (_, i) => ({ ...TESTS[0]!, id: `e${i}` })))).toThrow(/card_too_large/);
  });
  it.each([
    ['prohibits', (g: Goal, n: number) => { g.prohibits = Array.from({ length: n }, (_, i) => ({ pid: `p${i}`, target: { k: 'verb' as const, verb: 'x.y' }, res: { k: 'exact' as const, id: 'r' }, cond: ctrue })); }, REVIEW_LIMITS.max_prohibits],
    ['bounds', (g: Goal, n: number) => { g.bounds = Array.from({ length: n }, (_, i): Bound => ({ ...baseGoal().bounds[0]!, bid: `b${i}` })); }, REVIEW_LIMITS.max_bounds],
    ['escalateOn', (g: Goal, n: number) => { g.escalateOn = Array.from({ length: n }, () => amountLte(1)); }, REVIEW_LIMITS.max_escalate_on],
  ])('%s: over the cap is refused', (_k, set, max) => {
    const g = { ...baseGoal(), wildcardAck: ['p1'] };
    set(g, max + 1);
    expect(() => renderPolicyCard(g)).toThrow(/card_too_large/);
  });
  it('a card over the byte cap is refused', () => {
    const g = baseGoal();
    g.grants[0]!.res = { k: 'oneof', ids: Array.from({ length: 2000 }, (_, i) => `charge:ch_${i}`) };
    expect(() => renderPolicyCard(g)).toThrow(/card_too_large/);
  });
  it('limit overrides can only tighten', () => {
    expect(effectiveLimits({ max_grants: 10_000 }).max_grants).toBe(REVIEW_LIMITS.max_grants);
    expect(effectiveLimits({ max_grants: 1 }).max_grants).toBe(1);
    expect(effectiveLimits({ max_grants: -1 as never }).max_grants).toBe(REVIEW_LIMITS.max_grants);
    expect(() => renderPolicyCard(many(2), [], { limits: { max_grants: 1 } })).toThrow(/card_too_large/);
  });
  it('the loader and approver refuse an oversize goal', () => {
    const g = many(REVIEW_LIMITS.max_grants + 1);
    const s = sub({ goal: g, tests: [] });
    expect(() => approve(s)).toThrow('approveGoal: card_too_large');
    expect(reason(load(s, approve()))).toBe('card_too_large');
    expect(reason(load(sub(), approve(), { limits: { max_card_lines: 3 } }))).toBe('card_too_large');
  });
});

describe('semantic diff', () => {
  const dir = (mut: (g: Goal) => void, id?: string) => {
    const g = baseGoal();
    mut(g);
    const d = diffGoals(baseGoal(), g);
    return id ? d.changes.find((c) => c.id === id)?.direction : d.changes.map((c) => c.direction);
  };
  const g2 = (id = 'g2'): Goal['grants'][number] => ({ gid: id, verb: 'pay.read', res: { k: 'exact', id: 'a' }, cond: ctrue });
  it('no change, no diff', () => {
    expect(diffGoals(baseGoal(), baseGoal()).changes).toEqual([]);
  });
  it('grants: added widens, removed narrows, narrower-by-conjunction narrows, anything else is unknown', () => {
    expect(dir((g) => { g.grants.push(g2()); }, 'g2')).toBe('widen');
    expect(dir((g) => { g.grants = []; }, 'g1')).toBe('narrow');
    expect(dir((g) => { g.grants[0]!.cond = { k: 'and', a: amountLte(20000), b: { k: 'not', c: amountLte(5) } }; }, 'g1')).toBe('narrow');
    expect(dir((g) => { g.grants[0]!.cond = amountLte(30000); }, 'g1')).toBe('unknown');
    expect(dir((g) => { g.grants[0]!.verb = 'pay.read'; }, 'g1')).toBe('unknown');
  });
  it('prohibitions: removed widens, added narrows', () => {
    expect(dir((g) => { g.prohibits = []; }, 'p1')).toBe('widen');
    expect(dir((g) => { g.prohibits.push({ pid: 'p2', target: { k: 'verb', verb: 'x.y' }, res: { k: 'exact', id: 'r' }, cond: ctrue }); }, 'p2')).toBe('narrow');
  });
  it('bounds: a higher cap widens, a lower cap narrows, a changed unit is unknown, removed widens', () => {
    expect(dir((g) => { g.bounds[0]!.cap = cnt(4); }, 'b1')).toBe('widen');
    expect(dir((g) => { g.bounds[0]!.cap = cnt(2); }, 'b1')).toBe('narrow');
    expect(dir((g) => { g.bounds[0]!.cap = usd(1); }, 'b1')).toBe('unknown');
    expect(dir((g) => { g.bounds[0]!.window = { k: 'lifetime' }; }, 'b1')).toBe('unknown');
    expect(dir((g) => { g.bounds = []; }, 'b1')).toBe('widen');
  });
  it('validity and delegation (maxIdle 0 means no idle limit, the widest)', () => {
    expect(dir((g) => { g.validity.notAfter += 1; }, 'validity')).toBe('widen');
    expect(dir((g) => { g.validity.notAfter -= 1; }, 'validity')).toBe('narrow');
    expect(dir((g) => { g.validity.notAfter += 1; g.validity.maxIdle -= 1; }, 'validity')).toBe('unknown');
    expect(dir((g) => { g.validity.maxIdle = 0; }, 'validity')).toBe('widen');
    expect(dir((g) => { g.deleg.maxDepth = 2; }, 'delegation')).toBe('widen');
    expect(dir((g) => { g.deleg.narrowOnly = false; }, 'delegation')).toBe('widen');
    expect(dir((g) => { g.deleg.mayTouch = ['g1']; }, 'delegation')).toBe('widen');
  });
  it('escalation triggers: added narrows, removed widens; a new ontology or principal is never neutral', () => {
    expect(dir((g) => { g.escalateOn = [amountLte(1)]; })).toEqual(['narrow']);
    const withEsc = { ...baseGoal(), escalateOn: [amountLte(1)] };
    expect(diffGoals(withEsc, baseGoal()).changes[0]!.direction).toBe('widen');
    expect(dir((g) => { g.ontDigest = 'AAAA'; }, 'ontology')).toBe('unknown');
    expect(dir((g) => { g.principal = 'user:bob'; }, 'principal')).toBe('unknown');
    expect(dir((g) => { g.wildcardAck = ['g1']; }, 'wildcard_ack')).toBe('unknown');
    expect(dir((g) => { g.nlDigest = 'AAAA'; }, 'instruction')).toBe('neutral');
  });
  it('widenings are listed first and counted', () => {
    const g = baseGoal();
    g.bounds[0]!.cap = cnt(2);
    g.grants.push(g2());
    const d = diffGoals(baseGoal(), g);
    expect(d.changes.map((c) => c.id)).toEqual(['g2', 'b1']);
    expect(d.widenings).toBe(1);
    expect(d.from_goal_digest).toBe(goalDigest(baseGoal()));
    expect(d.to_goal_digest).toBe(goalDigest(g));
    expect(diffToText(d).split('\n')[0]).toMatch(/^!! /);
  });
  it('newly allowed witnesses come from the kernel, first; without a kernel the diff says it is incomplete', () => {
    const w = act({ verb: 'pay.read', res: 'a', params: {} });
    const g = baseGoal();
    g.grants.push(g2());
    const withK = diffGoals(baseGoal(), g, { newlyAllowed: () => ({ witnesses: [w], complete: true }) }, { ontology: ONT });
    expect(withK.newly_allowed).toEqual([w]);
    expect(withK.newly_allowed_complete).toBe(true);
    expect(diffToText(withK).split('\n')[0]).toContain('NEWLY ALLOWED');
    const partial = diffGoals(baseGoal(), g, { newlyAllowed: () => ({ witnesses: [w], complete: false }) }, { ontology: ONT });
    expect(partial.newly_allowed_complete).toBe(false);
    const none = diffGoals(baseGoal(), g);
    expect(none.newly_allowed_complete).toBe(false);
    expect(diffToText(none)).toContain('incomplete or unavailable');
  });
  it('fatigue: too many widenings or changes refuse the diff', () => {
    const g = baseGoal();
    for (let i = 0; i < REVIEW_LIMITS.max_diff_widenings + 1; i++) g.grants.push(g2(`n${String(i).padStart(3, '0')}`));
    expect(() => diffGoals(baseGoal(), g)).toThrow(/too_many_widenings/);
    expect(() => diffGoals(baseGoal(), g, undefined, { limits: { max_diff_widenings: 10_000 } })).toThrow(/too_many_widenings/);
  });
  it('approving against a base enforces the diff caps', () => {
    const g = baseGoal();
    for (let i = 0; i < 3; i++) g.grants.push({ gid: `n${i}`, verb: 'pay.refund', res: { k: 'exact', id: `c${i}` }, cond: amountLte(1) });
    const s = sub({ goal: g, tests: [] });
    expect(() => approveGoal(s, reviewer.secretKey, { kernel, now: NOW, base: baseGoal() })).not.toThrow();
    expect(() => approveGoal(s, reviewer.secretKey, { kernel, now: NOW, base: baseGoal(), limits: { max_diff_widenings: 2 } })).toThrow(/too_many_widenings/);
  });
});
