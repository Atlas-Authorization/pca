import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, generateKeyPair, hashCanonical } from '@atlasauth/pca';
import {
  MAX_GOAL_APPROVAL_TTL_MS,
  ReviewError,
  approveGoal,
  cardToText,
  diffGoals,
  diffToText,
  loadApprovedGoal,
  renderPolicyCard,
  type DiffCard,
  type GoalApproval,
  type GoalSubmission,
  type PolicyCard,
  type ReviewKernel,
} from './review';
import { boundLine } from './card';
import { refDecide } from './refsem';
import { nlDigest } from './digests';
import type { GoalTest } from './examples';
import type { Act, Bound, Cond, Delegation, Goal, Hist, Hole, Policy, Prohibit, Quantity, Validity } from './ir';
import { CNT, ONT, USD, ctrue, usd } from '../test/fixtures';

const INSTRUCTION = 'refund duplicate charge ch_1 for customer C1, at most 200 dollars';
const amt = { k: 'param', path: 'amount', ty: { k: 'q', u: USD } } as const;
const amountLte = (n: number): Cond => ({ k: 'cmp', op: 'lte', l: amt, r: { k: 'lit', v: { k: 'q', q: usd(n) } } });
const cnt = (n: number): Quantity => ({ u: CNT, n });
const T0 = 1_700_000_000_000;
const cj = (v: unknown): string => new TextDecoder().decode(canonicalBytes(v));

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
  { id: 't-void', act: act({ params: {} }), hist: empty, answer: 'ask' },
];

const policyOf = (g: Goal): Policy => ({ preds: [], prohs: [], ceils: [], escs: [], validity: g.validity, deleg: g.deleg });
const kernel: ReviewKernel = {
  compile: (g) => ({ ok: true, policy: policyOf(g) }),
  policyDigest: (p) => hashCanonical({ policy: p }),
  decide: (g, ont, a, h) => (['deny', 'escalate', 'allow'] as const)[refDecide(g, ont, a, h)]!,
};

const reviewer = generateKeyPair();
const rpk = b64u(reviewer.publicKey);
const other = generateKeyPair();
const NOW = T0;
const sub = (over: Partial<GoalSubmission> = {}): GoalSubmission => ({ goal: baseGoal(), ontology: ONT, instruction: INSTRUCTION, model_set: ['model-a', 'model-b'], tests: TESTS, ...over });
const approve = (s = sub(), ttlMs?: number) => approveGoal(s, reviewer.secretKey, { kernel, now: NOW, ...(ttlMs === undefined ? {} : { ttlMs }) });
const load = (s: GoalSubmission, a: GoalApproval, o: Partial<Parameters<typeof loadApprovedGoal>[2]> = {}) => loadApprovedGoal(s, a, { kernel, reviewers: [rpk], now: NOW + 1000, ...o });
const reason = (r: ReturnType<typeof load>) => (r.ok ? 'ok' : r.reason);

const refusal = (f: () => unknown): { code: string; message: string } => {
  try {
    f();
  } catch (e) {
    if (e instanceof ReviewError) return { code: e.code, message: e.message };
    throw e;
  }
  throw new Error('expected a ReviewError');
};
const broken = (f: keyof Goal, v: unknown): Goal => Object.assign(baseGoal(), { [f]: v });
const dirOf = (prev: Goal, next: Goal, id: string): string | undefined => diffGoals(prev, next).changes.find((c) => c.id === id)?.direction;

describe('PolicyCard: refusal messages are exact', () => {
  const tail = ': split the goal into smaller goals';
  it('a clause with no canonical form is unrenderable, with its explanation', () => {
    const g = { ...baseGoal(), principal: Number.NaN as never };
    expect(refusal(() => renderPolicyCard(g))).toEqual({ code: 'unrenderable', message: 'goal review: unrenderable: a clause has no canonical form (float, undefined or cycle)' });
    expect(reason(load(sub({ goal: g }), approve()))).toBe('unrenderable');
  });
  it('each fatigue cap names what exceeded it, how many, and the cap', () => {
    const msg = (what: string, n: number, max: number) => ({ code: 'card_too_large', message: `goal review: card_too_large: ${n} ${what} exceed the cap of ${max}${tail}` });
    expect(refusal(() => renderPolicyCard(baseGoal(), [], { limits: { max_grants: 0 } }))).toEqual(msg('grants', 1, 0));
    expect(refusal(() => renderPolicyCard(baseGoal(), [], { limits: { max_prohibits: 0 } }))).toEqual(msg('prohibitions', 1, 0));
    expect(refusal(() => renderPolicyCard(baseGoal(), [], { limits: { max_bounds: 0 } }))).toEqual(msg('bounds', 1, 0));
    expect(refusal(() => renderPolicyCard({ ...baseGoal(), escalateOn: [amountLte(1)] }, [], { limits: { max_escalate_on: 0 } }))).toEqual(msg('escalation triggers', 1, 0));
    expect(refusal(() => renderPolicyCard(baseGoal(), TESTS, { limits: { max_examples: 2 } }))).toEqual(msg('boundary examples', 3, 2));
  });
  it('the byte cap reports the exact size of the card', () => {
    const n = canonicalBytes(renderPolicyCard(baseGoal())).length;
    expect(refusal(() => renderPolicyCard(baseGoal(), [], { limits: { max_card_bytes: 100 } }))).toEqual({ code: 'card_too_large', message: `goal review: card_too_large: ${n} bytes of card exceed the cap of 100${tail}` });
  });
  it('holes and an unacknowledged wildcard explain themselves', () => {
    const hole: Hole = { hid: 'h1', q: 'which customer?', domain: ['C1', 'C2'], affects: ['g1'], global: false };
    expect(refusal(() => renderPolicyCard({ ...baseGoal(), holes: [hole] }))).toEqual({ code: 'holes', message: 'goal review: holes: 1 unresolved question(s): a goal with holes is a draft and cannot be signed' });
    const wild: Goal = { ...baseGoal(), grants: [{ gid: 'g1', verb: 'pay.refund', res: { k: 'any', reason: 'all' }, cond: amountLte(1) }], wildcardAck: [] };
    expect(refusal(() => renderPolicyCard(wild))).toEqual({ code: 'wildcard_unacknowledged', message: 'goal review: wildcard_unacknowledged: grant "g1" allows ANY resource without a wildcard acknowledgement' });
  });
  it('every field of a Goal must have its shape or the card is refused as not a Goal IR', () => {
    const notGoal = { code: 'unrenderable', message: 'goal review: unrenderable: not a Goal IR' };
    for (const f of ['grants', 'prohibits', 'bounds', 'escalateOn', 'holes', 'validity', 'deleg'] as const) {
      for (const bad of [5, 'x', null]) {
        expect(refusal(() => renderPolicyCard(broken(f, bad)))).toEqual(notGoal);
      }
    }
    for (const f of ['grants', 'prohibits', 'bounds', 'escalateOn', 'holes'] as const) {
      expect(refusal(() => renderPolicyCard(broken(f, {})))).toEqual(notGoal);
    }
    for (const f of ['validity', 'deleg'] as const) expect(refusal(() => renderPolicyCard(broken(f, [])))).toEqual(notGoal);
    for (const bad of [null, 5, 'x', []]) expect(refusal(() => renderPolicyCard(bad as never))).toEqual(notGoal);
  });
});

describe('PolicyCard: the clause count is exact', () => {
  const many = (): { goal: Goal; tests: GoalTest[] } => ({
    goal: {
      ...baseGoal(),
      grants: Array.from({ length: 2 }, (_, i) => ({ gid: `g${i}`, verb: 'pay.refund', res: { k: 'exact' as const, id: 'r' }, cond: ctrue })),
      prohibits: Array.from({ length: 3 }, (_, i): Prohibit => ({ pid: `p${i}`, target: { k: 'verb', verb: 'x.y' }, res: { k: 'exact', id: 'r' }, cond: ctrue })),
      bounds: Array.from({ length: 4 }, (_, i): Bound => ({ ...baseGoal().bounds[0]!, bid: `b${i}` })),
      escalateOn: Array.from({ length: 5 }, (_, i) => amountLte(i + 1)),
      holes: Array.from({ length: 6 }, (_, i): Hole => ({ hid: `h${i}`, q: 'q', domain: ['a'], affects: [], global: true })),
    },
    tests: Array.from({ length: 7 }, (_, i) => ({ ...TESTS[0]!, id: `e${i}` })),
  });
  it('3 fixed lines + 2 grants + 3 prohibitions + 4 bounds + 5 triggers + 6 holes + 7 examples = 30 lines: a card of exactly the cap renders, one under refuses', () => {
    const { goal, tests } = many();
    expect(renderPolicyCard(goal, tests, { allowHoles: true, limits: { max_card_lines: 30 } }).lines).toHaveLength(30);
    expect(refusal(() => renderPolicyCard(goal, tests, { allowHoles: true, limits: { max_card_lines: 29 } }))).toEqual({
      code: 'card_too_large',
      message: 'goal review: card_too_large: 30 card lines exceed the cap of 29: split the goal into smaller goals',
    });
  });
});

describe('PolicyCard: the cheap pre-check runs before any text is produced', () => {
  it('a goal over the line cap is refused as card_too_large even when a clause could not be rendered', () => {
    const goal: Goal = {
      ...baseGoal(),
      principal: Number.NaN as never,
      grants: Array.from({ length: 2 }, (_, i) => ({ gid: `g${i}`, verb: 'pay.refund', res: { k: 'exact' as const, id: 'r' }, cond: ctrue })),
      prohibits: Array.from({ length: 3 }, (_, i): Prohibit => ({ pid: `p${i}`, target: { k: 'verb', verb: 'x.y' }, res: { k: 'exact', id: 'r' }, cond: ctrue })),
      bounds: Array.from({ length: 4 }, (_, i): Bound => ({ ...baseGoal().bounds[0]!, bid: `b${i}` })),
      escalateOn: Array.from({ length: 5 }, (_, i) => amountLte(i + 1)),
      holes: Array.from({ length: 6 }, (_, i): Hole => ({ hid: `h${i}`, q: 'q', domain: ['a'], affects: [], global: true })),
    };
    const tests = Array.from({ length: 7 }, (_, i) => ({ ...TESTS[0]!, id: `e${i}` }));
    expect(refusal(() => renderPolicyCard(goal, tests, { allowHoles: true, limits: { max_card_lines: 29 } }))).toEqual({
      code: 'card_too_large',
      message: 'goal review: card_too_large: 30 card lines exceed the cap of 29: split the goal into smaller goals',
    });
  });
  it('a wildcard acknowledgement list that is not an array acknowledges nothing', () => {
    const wild: Goal = { ...baseGoal(), grants: [{ gid: 'Stryker was here', verb: 'pay.refund', res: { k: 'any', reason: 'all' }, cond: amountLte(1) }], wildcardAck: undefined as never };
    expect(refusal(() => renderPolicyCard(wild)).code).toBe('wildcard_unacknowledged');
  });
  it('a goal that has no canonical form outside its rendered clauses is unrenderable', () => {
    const g: Goal = { ...baseGoal(), sources: [Number.NaN as never] };
    expect(refusal(() => renderPolicyCard(g))).toEqual({ code: 'unrenderable', message: 'goal review: unrenderable: the Goal has no canonical form (float, undefined or cycle)' });
    expect(refusal(() => diffGoals(g, baseGoal()))).toEqual({ code: 'unrenderable', message: 'goal review: unrenderable: the Goal has no canonical form (float, undefined or cycle)' });
  });
});

describe('PolicyCard: lines for escalation, holes, examples and clauses with no resource', () => {
  const hole: Hole = { hid: 'h1', q: 'which customer?', domain: ['C1', 'C2'], affects: ['g1'], global: false };
  const shape = (c: PolicyCard) => c.lines.map(({ id, kind, severity, text }) => ({ id, kind, severity, text }));
  it('an escalation trigger and a hole carry their exact id, kind, severity and sentence', () => {
    const c = renderPolicyCard({ ...baseGoal(), escalateOn: [amountLte(1)], holes: [hole] }, [], { allowHoles: true });
    expect(shape(c).filter((l) => l.kind === 'escalate' || l.kind === 'hole')).toEqual([
      { id: 'escalate_on[0]', kind: 'escalate', severity: 'info', text: 'ASK THE PRINCIPAL when param "amount" (USD minor units) <= 1 USD minor units.' },
      { id: 'hole[0]', kind: 'hole', severity: 'red', text: 'UNRESOLVED "h1": "which customer?" options ["C1", "C2"] affects ["g1"]. Everything depending on it is dropped.' },
    ]);
  });
  it('an example mentions the earlier admitted actions only when there are some', () => {
    const withHist: GoalTest = { id: 'h', act: act(), hist: { adms: [{ gid: 'g1', act: act() }], last: T0 + 10, aggs: {} }, answer: 'allow' };
    const noHist: GoalTest = { id: 'n', act: act(), hist: empty, answer: 'deny' };
    const lines = renderPolicyCard(baseGoal(), [withHist, noHist]).lines.filter((l) => l.kind === 'example');
    const head = `EXAMPLE you confirmed: "pay.refund" on "ch_1" with ${cj(act().params)}`;
    expect(lines.map((l) => [l.id, l.severity, l.text])).toEqual([
      ['example:h', 'info', `${head} after 1 earlier admitted action(s) must be ALLOWED.`],
      ['example:n', 'info', `${head} must be DENIED.`],
    ]);
  });
  it('a grant or prohibition with no resource is shown as its canonical JSON, not refused', () => {
    const noResGrant = { gid: 'g1', verb: 'pay.refund', cond: ctrue };
    const noResProhibit = { pid: 'p1', target: { k: 'verb', verb: 'x.y' }, cond: ctrue };
    const c = renderPolicyCard({ ...baseGoal(), grants: [noResGrant as never], prohibits: [noResProhibit as never] });
    expect(shape(c).filter((l) => l.kind === 'grant' || l.kind === 'prohibit')).toEqual([
      { id: 'g1', kind: 'grant', severity: 'info', text: cj(noResGrant) },
      { id: 'p1', kind: 'prohibit', severity: 'info', text: cj(noResProhibit) },
    ]);
  });
  it('only an `any` prohibition is red', () => {
    const g: Goal = { ...baseGoal(), prohibits: [{ pid: 'p1', target: { k: 'verb', verb: 'x.y' }, res: { k: 'exact', id: 'r' }, cond: ctrue }] };
    expect(renderPolicyCard(g).lines.find((l) => l.id === 'p1')).toMatchObject({ severity: 'info', text: 'NEVER "p1": verb "x.y" on exactly "r" when always.' });
  });
});

describe('cardToText: red lines are marked, the rest indented, one per line', () => {
  it('exact output', () => {
    const card: PolicyCard = {
      v: 1,
      goal_digest: 'g',
      ontology_digest: 'o',
      nl_digest: 'n',
      principal: 'p',
      lines: [
        { id: 'a', kind: 'meta', severity: 'red', text: 'RED ONE', clause_digest: 'd1' },
        { id: 'b', kind: 'grant', severity: 'info', text: 'INFO ONE', clause_digest: 'd2' },
        { id: 'c', kind: 'hole', severity: 'red', text: 'RED TWO', clause_digest: 'd3' },
      ],
    };
    expect(cardToText(card)).toBe('!! RED ONE\n   INFO ONE\n!! RED TWO');
  });
});

describe('diffToText: exact output', () => {
  const card = (over: Partial<DiffCard>): DiffCard => ({ v: 1, from_goal_digest: 'a', to_goal_digest: 'b', newly_allowed: [], newly_allowed_complete: true, changes: [], widenings: 0, ...over });
  it('widen and unknown are marked, narrow and neutral are indented, complete lists add no warning', () => {
    const d = card({
      changes: [
        { change: 'added', kind: 'grant', id: 'a', direction: 'widen', text: 'W' },
        { change: 'changed', kind: 'grant', id: 'b', direction: 'unknown', text: 'U' },
        { change: 'removed', kind: 'grant', id: 'c', direction: 'narrow', text: 'N' },
        { change: 'changed', kind: 'meta', id: 'd', direction: 'neutral', text: 'E' },
      ],
    });
    expect(diffToText(d)).toBe('!! W\n!! U\n   N\n   E');
  });
  it('witnesses come first and an incomplete list says so', () => {
    const d = card({ newly_allowed: [act({ verb: 'pay.read', res: 'a', params: {} })], newly_allowed_complete: false, changes: [{ change: 'added', kind: 'grant', id: 'a', direction: 'narrow', text: 'T' }] });
    expect(diffToText(d)).toBe('!! NEWLY ALLOWED: "pay.read" on "a" with {}\n!! The list of newly allowed actions is incomplete or unavailable: read every widening below.\n   T');
  });
});

describe('semantic diff: exact changes', () => {
  const g2: Goal['grants'][number] = { gid: 'g2', verb: 'pay.read', res: { k: 'exact', id: 'a' }, cond: ctrue };
  const p2: Prohibit = { pid: 'p2', target: { k: 'effect', cls: 'money_out' }, res: { k: 'exact', id: 'r' }, cond: ctrue };
  const b2: Bound = { ...baseGoal().bounds[0]!, bid: 'b2' };
  const esc = amountLte(1);
  const escText = 'escalation when param "amount" (USD minor units) <= 1 USD minor units';
  const g1Text = 'grant "g1": "pay.refund" on charges_of of "C1" when param "amount" (USD minor units) <= 20000 USD minor units';
  const p1Text = 'prohibition "p1": "pay.transfer" on ANY RESOURCE (reason: "never move money out") when always';
  const b1Text = (cap: number) => `bound "b1": ${boundLine({ ...baseGoal().bounds[0]!, cap: cnt(cap) })} (${cap} count)`;

  it('added clauses: kind, id, direction and sentence', () => {
    const next: Goal = { ...baseGoal(), grants: [...baseGoal().grants, g2], prohibits: [...baseGoal().prohibits, p2], bounds: [...baseGoal().bounds, b2], escalateOn: [esc] };
    expect(diffGoals(baseGoal(), next).changes).toEqual([
      { change: 'added', kind: 'grant', id: 'g2', direction: 'widen', text: 'ADDED grant "g2": "pay.read" on exactly "a" when always' },
      { change: 'added', kind: 'prohibit', id: 'p2', direction: 'narrow', text: 'ADDED prohibition "p2": effect class "money_out" on exactly "r" when always' },
      { change: 'added', kind: 'bound', id: 'b2', direction: 'narrow', text: 'ADDED bound "b2": LIMIT "b2": count over grants ["g1"], per task, scope session, at most 3 count; beyond that: ask the principal (3 count)' },
      { change: 'added', kind: 'escalate', id: cj(esc), direction: 'narrow', text: `ADDED ${escText}` },
    ]);
  });
  it('removed clauses: widenings first, then the narrowing', () => {
    const prev: Goal = { ...baseGoal(), escalateOn: [esc] };
    const next: Goal = { ...baseGoal(), grants: [], prohibits: [], bounds: [], escalateOn: [] };
    const d = diffGoals(prev, next);
    expect(d.changes).toEqual([
      { change: 'removed', kind: 'prohibit', id: 'p1', direction: 'widen', text: `REMOVED ${p1Text}` },
      { change: 'removed', kind: 'bound', id: 'b1', direction: 'widen', text: `REMOVED ${b1Text(3)}` },
      { change: 'removed', kind: 'escalate', id: cj(esc), direction: 'widen', text: `REMOVED ${escText}` },
      { change: 'removed', kind: 'grant', id: 'g1', direction: 'narrow', text: `REMOVED ${g1Text}` },
    ]);
    expect(d.widenings).toBe(3);
  });
  it('changed clauses show the new and the old sentence', () => {
    const next = baseGoal();
    next.grants[0]!.cond = amountLte(30000);
    next.bounds[0]!.cap = cnt(4);
    expect(diffGoals(baseGoal(), next).changes).toEqual([
      { change: 'changed', kind: 'grant', id: 'g1', direction: 'unknown', text: `CHANGED ${g1Text.replace('20000', '30000')} (was: ${g1Text})` },
      { change: 'changed', kind: 'bound', id: 'b1', direction: 'widen', text: `CHANGED ${b1Text(4)} (was: ${b1Text(3)})` },
    ]);
  });
  it('validity, delegation, principal, ontology, wildcard acknowledgements and instruction', () => {
    const prev = baseGoal();
    const next: Goal = {
      ...baseGoal(),
      principal: 'user:bob',
      ontDigest: 'ont-b',
      wildcardAck: ['g1'],
      nlDigest: 'nl-b',
      validity: { ...prev.validity, notAfter: prev.validity.notAfter + 1 },
      deleg: { maxDepth: 1, narrowOnly: true, mayTouch: [] },
    };
    const d = diffGoals(prev, next);
    expect(d.changes).toEqual([
      { change: 'changed', kind: 'validity', id: 'validity', direction: 'widen', text: `CHANGED validity: ${cj(next.validity)} (was: ${cj(prev.validity)})` },
      { change: 'changed', kind: 'delegation', id: 'delegation', direction: 'widen', text: `CHANGED delegation: ${cj(next.deleg)} (was: ${cj(prev.deleg)})` },
      { change: 'changed', kind: 'meta', id: 'principal', direction: 'unknown', text: 'CHANGED principal: "user:bob" (was: "user:alice")' },
      { change: 'changed', kind: 'meta', id: 'ontology', direction: 'unknown', text: `CHANGED ontology: every term now means what the new vocabulary says (was ${cj(prev.ontDigest)}, now "ont-b")` },
      { change: 'changed', kind: 'meta', id: 'wildcard_ack', direction: 'unknown', text: 'CHANGED wildcard acknowledgements: ["g1"] (was: [])' },
      { change: 'changed', kind: 'meta', id: 'instruction', direction: 'neutral', text: 'CHANGED the instruction text the goal was interpreted from' },
    ]);
    expect(d.widenings).toBe(5);
  });
  it('an unknown change counts as a widening and is listed before a narrowing', () => {
    const next: Goal = { ...baseGoal(), grants: [], principal: 'user:bob' };
    const d = diffGoals(baseGoal(), next);
    expect(d.changes.map((c) => c.id)).toEqual(['principal', 'g1']);
    expect(d.widenings).toBe(1);
  });
});

describe('semantic diff: directions', () => {
  const withCond = (cond: Cond): Goal => ({ ...baseGoal(), grants: [{ ...baseGoal().grants[0]!, cond }] });
  it('adding a restriction to an unrestricted grant narrows it; dropping one of two conjuncts does not', () => {
    expect(dirOf(withCond(ctrue), withCond(amountLte(5)), 'g1')).toBe('narrow');
    const both: Cond = { k: 'and', a: amountLte(20000), b: { k: 'not', c: amountLte(5) } };
    expect(dirOf(withCond(both), withCond(amountLte(20000)), 'g1')).toBe('unknown');
    expect(dirOf(withCond(amountLte(20000)), withCond(both), 'g1')).toBe('narrow');
  });
  const validity = (v: Partial<Validity>): Goal => ({ ...baseGoal(), validity: { ...baseGoal().validity, ...v } });
  it('validity: a later start narrows, an earlier start widens, mixed moves are unknown', () => {
    const v = baseGoal().validity;
    expect(dirOf(baseGoal(), validity({ notBefore: v.notBefore + 1 }), 'validity')).toBe('narrow');
    expect(dirOf(baseGoal(), validity({ notBefore: v.notBefore - 1 }), 'validity')).toBe('widen');
    expect(dirOf(baseGoal(), validity({ notBefore: v.notBefore - 1, notAfter: v.notAfter - 1 }), 'validity')).toBe('unknown');
    expect(dirOf(baseGoal(), validity({ notBefore: v.notBefore + 1, notAfter: v.notAfter + 1 }), 'validity')).toBe('unknown');
  });
  const deleg = (d: Delegation): Goal => ({ ...baseGoal(), deleg: d });
  const o: Delegation = { maxDepth: 2, narrowOnly: true, mayTouch: ['g1', 'g2'] };
  it('delegation: a subset narrows, a superset widens, anything else is unknown', () => {
    expect(dirOf(deleg(o), deleg({ maxDepth: 2, narrowOnly: true, mayTouch: ['g1'] }), 'delegation')).toBe('narrow');
    expect(dirOf(deleg(o), deleg({ maxDepth: 1, narrowOnly: true, mayTouch: ['g1'] }), 'delegation')).toBe('narrow');
    expect(dirOf(deleg(o), deleg({ maxDepth: 2, narrowOnly: true, mayTouch: ['g1', 'g9'] }), 'delegation')).toBe('unknown');
    expect(dirOf(deleg(o), deleg({ maxDepth: 2, narrowOnly: true, mayTouch: ['g1', 'g2', 'g3'] }), 'delegation')).toBe('widen');
    expect(dirOf(deleg(o), deleg({ maxDepth: 1, narrowOnly: true, mayTouch: ['g1', 'g2', 'g3'] }), 'delegation')).toBe('unknown');
    expect(dirOf(deleg({ ...o, narrowOnly: false }), deleg({ maxDepth: 2, narrowOnly: true, mayTouch: ['g1', 'g2', 'g3'] }), 'delegation')).toBe('unknown');
  });
});

describe('semantic diff: caps and the kernel witness list', () => {
  const g2 = (id: string): Goal['grants'][number] => ({ gid: id, verb: 'pay.read', res: { k: 'exact', id: 'a' }, cond: ctrue });
  const grow = (n: number): Goal => ({ ...baseGoal(), grants: [...baseGoal().grants, ...Array.from({ length: n }, (_, i) => g2(`n${i}`))] });
  it('the change cap is exact and its message says how many', () => {
    expect(diffGoals(baseGoal(), grow(2), undefined, { limits: { max_diff_changes: 2 } }).changes).toHaveLength(2);
    expect(refusal(() => diffGoals(baseGoal(), grow(2), undefined, { limits: { max_diff_changes: 1 } }))).toEqual({
      code: 'diff_too_large',
      message: 'goal review: diff_too_large: 2 changes exceed the cap of 1: review the new goal as a whole instead',
    });
  });
  it('the widening cap is exact and its message says how many', () => {
    expect(diffGoals(baseGoal(), grow(2), undefined, { limits: { max_diff_widenings: 2 } }).widenings).toBe(2);
    expect(refusal(() => diffGoals(baseGoal(), grow(3), undefined, { limits: { max_diff_widenings: 2 } }))).toEqual({
      code: 'too_many_widenings',
      message: 'goal review: too_many_widenings: 3 widenings exceed the cap of 2 per review',
    });
  });
  const w1 = act({ verb: 'pay.read', res: 'a', params: {} });
  const w2 = act({ verb: 'pay.read', res: 'b', params: {} });
  it('a missing kernel, or a kernel without newlyAllowed, gives an empty incomplete list', () => {
    for (const k of [undefined, {}]) {
      const d = diffGoals(baseGoal(), grow(1), k, { ontology: ONT });
      expect(d.newly_allowed).toEqual([]);
      expect(d.newly_allowed_complete).toBe(false);
    }
  });
  it('witnesses are cut to the cap, and the list is complete only when the kernel says so and nothing was cut', () => {
    const run = (witnesses: Act[], complete: boolean) => diffGoals(baseGoal(), grow(1), { newlyAllowed: () => ({ witnesses, complete }) }, { ontology: ONT, limits: { max_witnesses: 1 } });
    const exact = run([w1], true);
    expect(exact.newly_allowed).toEqual([w1]);
    expect(exact.newly_allowed_complete).toBe(true);
    const cut = run([w1, w2], true);
    expect(cut.newly_allowed).toEqual([w1]);
    expect(cut.newly_allowed_complete).toBe(false);
    expect(run([w1], false).newly_allowed_complete).toBe(false);
  });
  it('the kernel is asked for at most the witness cap', () => {
    const asked: number[] = [];
    diffGoals(baseGoal(), grow(1), { newlyAllowed: (_p, _n, _o, limit) => { asked.push(limit); return { witnesses: [], complete: true }; } }, { ontology: ONT, limits: { max_witnesses: 3 } });
    expect(asked).toEqual([3]);
  });
});

describe('submissions the loader and approver refuse as malformed', () => {
  const a = approve();
  const rows: Array<[string, Partial<GoalSubmission>]> = [
    ['goal is a number', { goal: 5 as never }],
    ['goal is a string', { goal: 'x' as never }],
    ['goal is null', { goal: null as never }],
    ['goal is an array', { goal: [] as never }],
    ['ontology is a number', { ontology: 5 as never }],
    ['ontology is a string', { ontology: 'x' as never }],
    ['ontology is null', { ontology: null as never }],
    ['ontology is an array', { ontology: [] as never }],
    ['instruction is a number', { instruction: 5 as never }],
    ['model_set is not an array', { model_set: 'x' as never }],
    ['model_set holds a number', { model_set: ['a', 1 as never] }],
    ['tests is a string', { tests: 'x' as never }],
    ['tests is null', { tests: null as never }],
  ];
  it.each(rows)('%s', (_n, over) => {
    expect(reason(load(sub(over), a))).toBe('malformed_submission');
    expect(() => approve(sub(over))).toThrow(/^approveGoal: malformed_submission$/);
  });
  it.each([[null], [undefined], [5], ['x'], [[]]])('the submission itself is %s', (bad) => {
    expect(reason(load(bad as never, a))).toBe('malformed_submission');
    expect(() => approveGoal(bad as never, reviewer.secretKey, { kernel, now: NOW })).toThrow(/^approveGoal: malformed_submission$/);
  });
  it('a goal whose clause list holds a non-object is malformed_goal, not a ReviewError code', () => {
    const s = sub({ goal: { ...baseGoal(), grants: [null as never] }, tests: [] });
    expect(reason(load(s, a))).toBe('malformed_goal');
    expect(() => approve(s)).toThrow(/^approveGoal: malformed_goal$/);
  });
});

describe('malformed approvals', () => {
  const s = sub();
  const a = approve(s);
  it.each([
    ['v', { ...a, v: 2 as never }],
    ['sig is a number', { ...a, sig: 5 as never }],
    ['reviewer is a number', { ...a, reviewer: 5 as never }],
    ['approved_at is a string', { ...a, approved_at: String(a.approved_at) as never }],
    ['approved_at is a float', { ...a, approved_at: 1.5 }],
    ['expires_at is a string', { ...a, expires_at: String(a.expires_at) as never }],
    ['expires_at is a float', { ...a, expires_at: 1.5 }],
    ['goal_digest is a number', { ...a, goal_digest: 5 as never }],
    ['policy_digest is a number', { ...a, policy_digest: 5 as never }],
    ['card_digest is a number', { ...a, card_digest: 5 as never }],
    ['ontology_digest is a number', { ...a, ontology_digest: 5 as never }],
    ['tests_digest is a number', { ...a, tests_digest: 5 as never }],
    ['nl_digest is a number', { ...a, nl_digest: 5 as never }],
    ['model_set_digest is a number', { ...a, model_set_digest: 5 as never }],
    ['an array carrying every member', Object.assign([], a) as never],
  ] as Array<[string, GoalApproval]>)('%s', (_n, ap) => {
    expect(reason(load(s, ap))).toBe('malformed_approval');
  });
});

describe('the loader window and pins are exact', () => {
  const s = sub();
  it('an approval is valid from approved_at itself', () => {
    const a = approve(s);
    expect(reason(load(s, a, { now: a.approved_at }))).toBe('ok');
  });
  it('a ttl of exactly the maximum signs and loads', () => {
    const a = approve(s, MAX_GOAL_APPROVAL_TTL_MS);
    expect(a.expires_at - a.approved_at).toBe(MAX_GOAL_APPROVAL_TTL_MS);
    expect(reason(load(s, a))).toBe('ok');
  });
  it('any one of several pinned reviewers is enough', () => {
    const a = approve(s);
    expect(reason(load(s, a, { reviewers: [b64u(other.publicKey), rpk] }))).toBe('ok');
    expect(reason(load(s, a, { reviewers: [b64u(other.publicKey), { pk: rpk }] }))).toBe('ok');
  });
});

describe('semantic diff: prohibitions', () => {
  const A = amountLte(20000);
  const B: Cond = { k: 'not', c: amountLte(5) };
  const both: Cond = { k: 'and', a: A, b: B };
  const withP = (p: Partial<Prohibit>): Goal => ({ ...baseGoal(), prohibits: [{ ...baseGoal().prohibits[0]!, cond: A, ...p }] });
  it('a prohibition that triggers on more narrows, one that triggers on less does not', () => {
    expect(diffGoals(withP({ cond: both }), withP({ cond: A })).changes.map((c) => [c.id, c.direction])).toEqual([['p1', 'narrow']]);
    expect(diffGoals(withP({ cond: A }), withP({ cond: both })).changes.map((c) => [c.id, c.direction])).toEqual([['p1', 'unknown']]);
  });
  it('a different target or resource is unknown even when the condition is the same', () => {
    expect(dirOf(withP({}), withP({ target: { k: 'verb', verb: 'pay.read' } }), 'p1')).toBe('unknown');
    expect(dirOf(withP({}), withP({ res: { k: 'exact', id: 'r' } }), 'p1')).toBe('unknown');
    expect(dirOf(withP({ cond: both }), withP({ cond: A, target: { k: 'verb', verb: 'pay.read' } }), 'p1')).toBe('unknown');
  });
});

describe('derive: kernel failures map to their own reasons', () => {
  const s = sub();
  const a = approve(s);
  it('a throwing analyzer or policy digest is analyzer_error', () => {
    const boomA: ReviewKernel = { ...kernel, analyze: () => { throw new Error('boom'); } };
    const boomD: ReviewKernel = { ...kernel, policyDigest: () => { throw new Error('boom'); } };
    expect(reason(load(s, a, { kernel: boomA }))).toBe('analyzer_error');
    expect(reason(load(s, a, { kernel: boomD }))).toBe('analyzer_error');
    expect(() => approveGoal(s, reviewer.secretKey, { kernel: boomD, now: NOW })).toThrow(/^approveGoal: analyzer_error$/);
  });
  it('a throwing decide is tests_unverifiable', () => {
    const boom: ReviewKernel = { ...kernel, decide: () => { throw new Error('boom'); } };
    expect(reason(load(s, a, { kernel: boom }))).toBe('tests_unverifiable');
  });
  it('a model id with no canonical form is malformed_goal', () => {
    const bad = sub({ model_set: ['\ud800'] });
    expect(reason(load(bad, a))).toBe('malformed_goal');
    expect(() => approve(bad)).toThrow(/^approveGoal: malformed_goal$/);
  });
  it('an example with its own relations is decided against them', () => {
    const t: GoalTest = { id: 't-rels', act: act({ res: 'ch_9' }), hist: empty, answer: 'allow', rels: [{ rel: 'charges_of', anchor: 'C1', members: ['ch_9'] }] };
    const own = sub({ tests: [t] });
    expect(reason(load(own, approve(own)))).toBe('ok');
    const { rels: _rels, ...plain } = t;
    const noRels = sub({ tests: [plain] });
    expect(() => approve(noRels)).toThrow(/^approveGoal: tests_contradicted$/);
  });
  it('a loader that throws internally answers malformed_approval', () => {
    expect(loadApprovedGoal(s, a, undefined as never)).toEqual({ ok: false, reason: 'malformed_approval' });
  });
});
