import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, hashCanonical } from '@atlasauth/pca';
import { IntentLearner, numCells, type Omega, type VerbSpace, type NumDim } from '@atlasauth/pca-intent';
import { act, assertion, D, fakeView, harness, makeIR, SHOP, SKY } from './fixtures.test-util';
import {
  actionValuesOf,
  boxCells,
  DEFAULT_FATIGUE,
  deviceChallenge,
  EMPTY_NOISE,
  estimateNoise,
  learnerView,
  pcaActionDigest,
  recordCanary,
  resolveCoords,
  SlidingWindowCounter,
  type AnswerResult,
  type CellAt,
  type GrantView,
  type TrustedChannel,
} from './index';

const NF = { ...DEFAULT_FATIGUE, assumeNoiseFree: true };
type H = ReturnType<typeof harness>;
const book = (total: number, addOns = 'none') => act('air.book', { add_ons: addOns, total }, 'skyair.example/bookings');
const coords = (total: [number, number], addOns = 'none') => ({ 'action.params.add_ons': [addOns], 'action.params.total': total, 'env.prov.action.params.add_ons': ['trusted|first_party'] });
const add = (q: number) => act('cart.add', { qty: q }, 'shop/cart', 'reversible');
const addC = (i: number) => ({ 'action.params.qty': [i, i] as [number, number] });
const buy = (n: number) => act('cart.buy', { amount: n }, 'shop/orders');
const buyC = (i: number) => ({ 'action.params.amount': [i, i] as [number, number] });
const cand = (q: number) => ({ verb: 'cart.add', values: { 'action.params.qty': q } });
const shop = (over: Parameters<typeof harness>[0] = {}) => harness({ omega: SHOP, units: {}, lift: undefined, ...over });
const ok = <K extends string>(r: AnswerResult, kind: K): Extract<AnswerResult, { kind: K }> => {
  if (!r.ok || r.kind !== kind) throw new Error(`expected ${kind}, got ${JSON.stringify(r)}`);
  return r as Extract<AnswerResult, { kind: K }>;
};
const recv = (h: H, a: ReturnType<typeof act>, c: Record<string, unknown>, id: string, over: Parameters<typeof makeIR>[3] = {}) => h.ch.receive(makeIR(h, a, c as never, { question_id: id, ...over }), { action: a });
type Q = NonNullable<ReturnType<TrustedChannel['nextScreen']>>['questions'][number];
const drain = (h: H) => {
  const out: Q[] = [];
  for (let s = h.ch.nextScreen(); s; s = h.ch.nextScreen()) out.push(...s.questions);
  return out;
};

describe('learnerView', () => {
  it('names an unknown verb and resolves the right verb space', () => {
    const l = new IntentLearner(SHOP, {});
    l.observe({ verb: 'cart.add', values: { 'action.params.qty': 5 } }, 0, 'runtime');
    const v = learnerView(l);
    expect(() => v.p('nope', [0])).toThrow('learnerView: unknown verb nope');
    expect(v.vetoed('cart.add', [3])).toBe(true);
    expect(v.vetoed('cart.buy', [3])).toBe(false);
  });
  it('the ceiling predicate is inverted into outsideCeiling and receives the cell', () => {
    const l = new IntentLearner(SHOP, {});
    const seen: unknown[] = [];
    const inside = learnerView(l, { insideCeiling: (verb, idx) => (seen.push([verb, idx]), true) });
    expect(inside.outsideCeiling('cart.add', [1])).toBe(false);
    expect(seen).toEqual([['cart.add', [1]]]);
    expect(learnerView(l, { insideCeiling: () => false }).outsideCeiling('cart.add', [1])).toBe(true);
    expect(learnerView(l).outsideCeiling('cart.add', [1])).toBe(false);
  });
});

describe('question ids come from the injected randomness', () => {
  it('maps each draw onto the 64-symbol alphabet', () => {
    const h = shop({ fatigue: NF, rand: () => 0.5 });
    expect(h.ch.clarify({ candidates: [cand(7)], reason: 'other' }).questionId).toBe('q_gggggggggg');
  });
});

describe('receive refusals carry exact reasons', () => {
  const a = book(77800);
  it('session, map, action and cell checks', () => {
    const h = harness();
    expect(h.ch.receive(makeIR(h, a, coords([2, 3]), { session: D('other') }), { action: a })).toEqual({ ok: false, code: 'wrong_session', reason: 'the question is for another session' });
    expect(h.ch.receive(makeIR(h, a, coords([2, 3])), { action: book(77801) })).toEqual({ ok: false, code: 'action_mismatch', reason: 'the action does not match the signed action digest' });
    expect(h.ch.receive(makeIR(h, a, coords([3, 3])), { action: a })).toEqual({ ok: false, code: 'cell_mismatch', reason: "the action's cell (re-derived by the wallet) is not the cell the site names" });
    const ir = makeIR(h, a, coords([2, 3]));
    h.map.d = D('map-1');
    expect(h.ch.receive(ir, { action: a })).toEqual({ ok: false, code: 'stale_map', reason: 'the question names another map version' });
  });
  it('why a cell is not a question', () => {
    const run = (view: GrantView) => {
      const h = harness({ view });
      return h.ch.receive(makeIR(h, a, coords([2, 3])), { action: a });
    };
    expect(run(fakeView({ outside: ['air.book|0,3,0'] }))).toEqual({ ok: false, code: 'not_uncertain', reason: 'the cell is outside a ceiling: the principal cannot widen it' });
    expect(run(fakeView({ vetoed: ['air.book|0,3,0'] }))).toEqual({ ok: false, code: 'not_uncertain', reason: 'the cell was vetoed' });
    expect(run(fakeView({ p: { 'air.book|0,2,0': 0 } }))).toEqual({ ok: false, code: 'not_uncertain', reason: 'the cell is denied' });
    expect(run(fakeView({ p: { 'air.book|0,2,0': 1 } }))).toEqual({ ok: false, code: 'not_uncertain', reason: 'the cell is already in the grant' });
  });
  it('a cell is asked once even when only one cell of the box was asked; a duplicate id is refused', () => {
    const h = harness({ fatigue: NF });
    expect(recv(h, book(50000), coords([2, 2]), 'q_1').ok).toBe(true);
    expect(recv(h, book(80000), coords([2, 3]), 'q_2')).toEqual({ ok: false, code: 'already_asked', reason: 'a cell is asked at most once per session' });
    expect(recv(h, book(80000), coords([3, 3]), 'q_1')).toEqual({ ok: false, code: 'already_asked', reason: 'duplicate question id' });
    expect(recv(h, book(80000), coords([3, 3]), 'q_3').ok).toBe(true);
  });
  it('gate refusals: exact reasons, and only a frozen refusal is listed in the summary', () => {
    const frozen = harness({ shared: { hourly: new SlidingWindowCounter(), noise: { n: recordCanary(EMPTY_NOISE, 0, 1) }, clock: { t: 1 } } });
    expect(frozen.ch.receive(makeIR(frozen, a, coords([2, 3])), { action: a })).toEqual({ ok: false, code: 'frozen', reason: 'the estimated false-yes rate is above η_stop: no more questions this session' });
    expect(frozen.ch.summary()).toEqual({ frozen: true, refused: [{ verb: 'air.book', coords: coords([2, 3]) }], asked: 0, canaries: 0 });
    const cap = harness({ caps: { perSession: 1 } });
    expect(recv(cap, book(50000), coords([2, 2]), 'q_a').ok).toBe(true);
    expect(recv(cap, book(80000), coords([3, 3]), 'q_b')).toEqual({ ok: false, code: 'cap_session', reason: 'at most 1 questions per session' });
    expect(cap.ch.summary().refused).toEqual([]);
    const hour = harness({ caps: { perHour: 1 } });
    expect(recv(hour, book(50000), coords([2, 2]), 'q_a').ok).toBe(true);
    expect(recv(hour, book(80000), coords([3, 3]), 'q_b')).toEqual({ ok: false, code: 'cap_hour', reason: 'at most 1 questions per hour' });
    expect(hour.ch.summary().refused).toEqual([]);
  });
  it('a lift that moves the action to another verb cannot be rendered', () => {
    const verb = (name: string): VerbSpace => ({ verb: name, reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'cat', path: 'action.params.k', values: [{ kind: 'exact', value: 'a' }, { kind: 'exact', value: 'b' }, { kind: 'other', value: '⊥' }] }] });
    const TWO: Omega = { v: 1, approximate: [], verbs: [verb('v.one'), verb('v.two')] };
    const h = harness({ omega: TWO, units: {}, lift: (x) => ({ verb: 'v.two', values: actionValuesOf(x).values }) });
    const x = act('v.one', { k: 'a' }, 'r', 'reversible');
    expect(recv(h, x, { 'action.params.k': ['a'] }, 'q_r')).toEqual({ ok: false, code: 'render_failed', reason: 'the card could not be rendered' });
    expect(h.ch.questionsAsked()).toBe(0);
  });
});

describe('box size limit', () => {
  it('a box of exactly maxBoxCells is accepted, one more is refused', () => {
    const a = book(77800);
    const n = boxCells((resolveCoords(SKY, 'air.book', coords([2, 3])) as { box: number[][] }).box).length;
    expect(n).toBeGreaterThan(1);
    expect(recv(harness({ maxBoxCells: n }), a, coords([2, 3]), 'q_ok').ok).toBe(true);
    expect(recv(harness({ maxBoxCells: n - 1 }), a, coords([2, 3]), 'q_big')).toEqual({ ok: false, code: 'cell_too_large', reason: 'the question covers too many cells' });
  });
  it('the default limit is 4096 cells', () => {
    const dim: NumDim = { kind: 'num', path: 'action.params.qty', lo: 0, hi: 10000, cuts: Array.from({ length: 5000 }, (_, i) => i + 1), dist: 'uniform' };
    const BIG: Omega = { v: 1, approximate: [], verbs: [{ verb: 'cart.add', reversibility: 'reversible', weight: 1, dims: [dim] }] };
    expect(numCells(dim).length).toBeGreaterThan(4097);
    const h = harness({ omega: BIG, units: {}, lift: undefined, fatigue: NF });
    expect(recv(h, add(0), { 'action.params.qty': [0, 4096] }, 'q_big')).toEqual({ ok: false, code: 'cell_too_large', reason: 'the question covers too many cells' });
    expect(recv(h, add(0), { 'action.params.qty': [0, 4095] }, 'q_fit').ok).toBe(true);
  });
});

describe('friction of a question', () => {
  it('a supplied harm model drives the tier', () => {
    const h = shop({ harm: { verb: () => 50, dim: () => 1 } });
    expect(recv(h, add(3), addC(2), 'q_h')).toEqual({ ok: true, questionId: 'q_h', friction: 'hold' });
  });
  it('a verb with no mass is a tap, not an unknown harm', () => {
    const Z: Omega = { v: 1, approximate: [], verbs: [{ verb: 'cart.add', reversibility: 'reversible', weight: 0, dims: [{ kind: 'num', path: 'action.params.qty', lo: 0, hi: 100, cuts: [1, 5, 10, 50], dist: 'uniform' }] }] };
    const h = harness({ omega: Z, units: {}, lift: undefined });
    expect(recv(h, add(3), addC(2), 'q_z')).toEqual({ ok: true, questionId: 'q_z', friction: 'tap' });
  });
  it('the site minimum raises the tier; a reversible cell stays a tap under estimated noise', () => {
    expect(recv(shop({ fatigue: NF }), add(3), addC(2), 'q_a', { friction: 'hold' })).toMatchObject({ ok: true, friction: 'hold' });
    expect(recv(shop(), add(3), addC(2), 'q_b')).toMatchObject({ ok: true, friction: 'tap' });
  });
  it('a typed tier with nothing to type becomes a device tier', () => {
    const OM: Omega = { v: 1, approximate: [], verbs: [{ verb: 'do.thing', reversibility: 'irreversible', weight: 1, dims: [{ kind: 'cat', path: 'action.params.kind', values: [{ kind: 'exact', value: 'a' }, { kind: 'other', value: '⊥' }] }] }] };
    const h = harness({ omega: OM, units: {}, lift: undefined, fatigue: NF });
    const x = act('do.thing', { kind: 'a' });
    expect(recv(h, x, { 'action.params.kind': ['a'] }, 'q_d')).toEqual({ ok: true, questionId: 'q_d', friction: 'device' });
    expect(h.ch.nextScreen()!.questions[0]!.card.friction).toBe('device');
  });
});

describe('provenance and identity widening raise friction', () => {
  const PROV = 'env.prov.action.params.payee';
  const MIX: Omega = {
    v: 1,
    approximate: [],
    verbs: [
      {
        verb: 'msg.send',
        reversibility: 'reversible',
        weight: 1,
        dims: [
          { kind: 'num', path: 'action.params.qty', lo: 0, hi: 100, cuts: [10], dist: 'uniform' },
          { kind: 'cat', path: 'action.params.payee', values: [{ kind: 'exact', value: 'ann' }, { kind: 'exact', value: 'bob' }, { kind: 'other', value: '⊥' }] },
          { kind: 'cat', path: PROV, values: [{ kind: 'exact', value: 'trusted|first_party' }, { kind: 'exact', value: 'tool|web|agent' }, { kind: 'prefix', value: 'trusted' }, { kind: 'other', value: '⊥' }] },
          { kind: 'num', path: 'env.prov.score', lo: 0, hi: 10, cuts: [5], dist: 'uniform' },
        ],
      },
    ],
  };
  const x = act('msg.send', { qty: 3, payee: 'ann' }, 'r', 'reversible');
  const run = (over: Parameters<typeof harness>[0], prov: string, provCoords: string[], payee: string[] = ['ann']) => {
    const h = harness({
      omega: MIX,
      units: {},
      fatigue: NF,
      lift: (a) => ({ verb: a.verb, values: { ...actionValuesOf(a).values, [PROV]: prov, 'env.prov.score': 2 } }),
      ...over,
    });
    return recv(h, x, { 'action.params.qty': [0, 0], 'action.params.payee': payee, [PROV]: provCoords, 'env.prov.score': [0, 0] }, 'q_m');
  };
  const critical = { sensitivity: { 'action.params.payee': 'critical' as const } };
  it('a critical parameter whose value came from the web or an agent needs typing', () => {
    expect(run(critical, 'tool|web|agent', ['tool|web|agent'])).toMatchObject({ ok: true, friction: 'typed' });
  });
  it('trusted provenance leaves it a tap, and so does a parameter that is not critical', () => {
    expect(run(critical, 'trusted|first_party', ['trusted|first_party'])).toMatchObject({ ok: true, friction: 'tap' });
    expect(run({ sensitivity: {} }, 'tool|web|agent', ['tool|web|agent'])).toMatchObject({ ok: true, friction: 'tap' });
    expect(run({}, 'tool|web|agent', ['tool|web|agent'])).toMatchObject({ ok: true, friction: 'tap' });
  });
  it('a prefix value is treated as unbounded, never as its literal', () => {
    expect(run(critical, 'trusted-abc', ['trusted'])).toMatchObject({ ok: true, friction: 'typed' });
  });
  it('widening an identity parameter beyond named values needs a device', () => {
    const irr = { reversibility: () => 'irreversible' as const, identityPaths: ['action.params.payee', 'action.params.qty'] };
    expect(run(irr, 'trusted|first_party', ['trusted|first_party'], ['ann'])).toMatchObject({ ok: true, friction: 'typed' });
    expect(run(irr, 'trusted|first_party', ['trusted|first_party'], ['ann', 'bob'])).toMatchObject({ ok: true, friction: 'typed' });
    expect(run(irr, 'trusted|first_party', ['trusted|first_party'], ['ann', '⊥'])).toMatchObject({ ok: true, friction: 'device' });
    expect(run({ ...irr, identityPaths: ['action.params.qty'] }, 'trusted|first_party', ['trusted|first_party'], ['ann', '⊥'])).toMatchObject({ ok: true, friction: 'typed' });
  });
});

describe('ordering of pending questions', () => {
  const CAT = (name: string): Omega => ({ v: 1, approximate: [], verbs: [{ verb: name, reversibility: 'reversible', weight: 1, dims: [{ kind: 'cat', path: 'action.params.k', values: ['a', 'b', 'c', 'd', 'e', 'f'].map((value) => ({ kind: 'exact' as const, value })) }] }] });
  it('equal friction and weight: the lower first cell index comes first, whatever the ids say', () => {
    const h = harness({ omega: CAT('v.cat'), units: {}, lift: undefined });
    const q = (k: string, set: string[], id: string) => recv(h, act('v.cat', { k }, 'r', 'reversible'), { 'action.params.k': set }, id);
    expect(q('d', ['d', 'e'], 'q_m').ok).toBe(true);
    expect(q('a', ['a', 'f'], 'q_z').ok).toBe(true);
    expect(q('b', ['b', 'c'], 'q_a').ok).toBe(true);
    expect(h.ch.nextScreen()!.questions.map((x) => x.questionId)).toEqual(['q_z', 'q_a', 'q_m']);
  });
  it('then the id decides, in either arrival order', () => {
    const verb = (name: string): VerbSpace => ({ verb: name, reversibility: 'reversible', weight: 0.5, dims: [{ kind: 'cat', path: 'action.params.k', values: [{ kind: 'exact', value: 'a' }, { kind: 'other', value: '⊥' }] }] });
    const TWO: Omega = { v: 1, approximate: [], verbs: [verb('v.one'), verb('v.two')] };
    for (const order of [['v.one', 'q_b', 'v.two', 'q_a'], ['v.two', 'q_a', 'v.one', 'q_b']] as const) {
      const h = harness({ omega: TWO, units: {}, lift: undefined });
      for (let i = 0; i < 4; i += 2) expect(recv(h, act(order[i]!, { k: 'a' }, 'r', 'reversible'), { 'action.params.k': ['a'] }, order[i + 1]!).ok).toBe(true);
      expect(h.ch.nextScreen()!.questions.map((x) => x.questionId)).toEqual(['q_a', 'q_b']);
    }
  });
  it('hold questions share a screen', () => {
    const h = shop({ fatigue: NF, friction: { hTap: 0.5, hDevice: 1e9 } });
    recv(h, add(3), addC(2), 'q_1');
    recv(h, add(7), addC(4), 'q_2');
    expect(h.ch.nextScreen()!.questions.map((x) => x.questionId).sort()).toEqual(['q_1', 'q_2']);
  });
  it('expiry is strictly after expires_at, and an expired question is gone', () => {
    const h = shop({ fatigue: NF });
    const t = h.clock.t;
    recv(h, add(3), addC(2), 'q_e1', { expires_at: t + 10 });
    recv(h, add(7), addC(4), 'q_e2', { expires_at: t + 10 });
    h.ch.nextScreen();
    recv(h, add(20), addC(6), 'q_e3', { expires_at: t + 5 });
    h.clock.t = t + 10;
    expect(ok(h.ch.answer('q_e1', { answer: 'no' }), 'veto').ok).toBe(true);
    h.clock.t = t + 11;
    expect(h.ch.answer('q_e2', { answer: 'no' })).toEqual({ ok: false, code: 'expired', reason: 'the question expired' });
    expect(h.ch.answer('q_e2', { answer: 'no' })).toEqual({ ok: false, code: 'unknown_question', reason: 'no such pending question' });
    expect(h.ch.nextScreen()).toBeNull();
    expect(h.ch.answer('q_e3', { answer: 'no' })).toMatchObject({ code: 'unknown_question' });
  });
  it('a question can be shown at its last valid instant', () => {
    const h = shop({ fatigue: NF });
    recv(h, add(3), addC(2), 'q_x', { expires_at: h.clock.t + 10 });
    h.clock.t += 10;
    expect(h.ch.nextScreen()!.questions).toHaveLength(1);
  });
  it('answers before display are refused with the reason', () => {
    const h = shop({ fatigue: NF });
    recv(h, add(3), addC(2), 'q_n');
    expect(h.ch.answer('q_n', { answer: 'no' })).toEqual({ ok: false, code: 'not_shown', reason: 'the question was never shown' });
  });
});

describe('the interstitial screen', () => {
  it('is empty and numbered; the second confirmation is a real screen later', () => {
    const h = harness();
    const a = book(77800);
    recv(h, a, coords([2, 3]), 'q_i');
    h.ch.nextScreen();
    ok(h.ch.answer('q_i', { answer: 'yes', typed: '778' }), 'pending_confirmation');
    expect(h.ch.nextScreen()).toEqual({ screen: 2, kind: 'interstitial', questions: [] });
  });
});

describe('answers and consent', () => {
  it('a reversible plain yes is just an answer under estimated noise; a partial yes on an irreversible cell too', () => {
    const t = shop();
    recv(t, add(3), addC(2), 'q_t');
    t.ch.nextScreen();
    expect(ok(t.ch.answer('q_t', { answer: 'yes' }), 'answer').answer.source).toBe('elicitation');
    const h = harness();
    recv(h, book(50000), coords([2, 2]), 'q_p');
    h.ch.nextScreen();
    ok(h.ch.answer('q_p', { answer: 'partly', partial: { path: 'action.params.total', upTo: 45000 }, typed: '500' }), 'answer');
  });
  it('consent for the exact action is only signed for a plain yes to an irreversible site question', () => {
    const rev = shop({ fatigue: NF });
    recv(rev, add(3), addC(2), 'q_r', { friction: 'typed' });
    rev.ch.nextScreen();
    const a = ok(rev.ch.answer('q_r', { answer: 'yes', typed: '3' }), 'answer').answer;
    expect(a.ux.consent_for_action).toBeUndefined();
    expect(a.ux.action_digest).toBeUndefined();
    const irr = harness({ fatigue: NF });
    const x = book(77800);
    recv(irr, x, coords([2, 3]), 'q_i');
    recv(irr, book(50000, 'tripshield'), coords([2, 2], 'tripshield'), 'q_j');
    drain(irr);
    const no = ok(irr.ch.answer('q_i', { answer: 'no' }), 'veto').answer;
    expect(no.ux.consent_for_action).toBeUndefined();
    expect(no.ux.action_digest).toBeUndefined();
    const part = ok(irr.ch.answer('q_j', { answer: 'partly', partial: { path: 'action.params.total', upTo: 45000 }, typed: '500' }), 'answer').answer;
    expect(part.ux.consent_for_action).toBeUndefined();
  });
  it('a clarification answer is signed as a clarification and is never a consent', () => {
    const h = shop({ fatigue: NF });
    const id = h.ch.clarify({ candidates: [cand(3)], reason: 'other' }).questionId!;
    h.ch.nextScreen();
    const a = ok(h.ch.answer(id, { answer: 'yes' }), 'answer').answer;
    expect(a.source).toBe('clarification');
    expect(a.ux.consent_for_action).toBeUndefined();
  });
  it('under estimated noise an irreversible clarification needs a confirmation too, and a reversible one stays a tap', () => {
    const h = shop();
    const id = h.ch.clarify({ candidates: [{ verb: 'cart.buy', values: { 'action.params.amount': 500 } }], reason: 'other' }).questionId!;
    const card = h.ch.nextScreen()!.questions[0]!.card;
    expect(card.friction).toBe('typed');
    ok(h.ch.answer(id, { answer: 'yes', typed: '500' }), 'pending_confirmation');
    const g = shop();
    g.ch.clarify({ candidates: [cand(3)], reason: 'other' });
    expect(g.ch.nextScreen()!.questions[0]!.card.friction).toBe('tap');
  });
});

describe('typed and hold evidence', () => {
  it('reasons for a missing or wrong typed value', () => {
    const h = shop({ fatigue: NF });
    recv(h, buy(500), buyC(2), 'q_t');
    h.ch.nextScreen();
    expect(h.ch.answer('q_t', { answer: 'yes' })).toEqual({ ok: false, code: 'tier_evidence', reason: 'type the value shown on the card' });
    expect(h.ch.answer('q_t', { answer: 'yes', typed: '499' })).toEqual({ ok: false, code: 'typed_mismatch', reason: 'the typed value does not match the card' });
    expect(h.ch.answer('q_t', { answer: 'yes', typed: '500' }).ok).toBe(true);
  });
  it('a value that cannot be typed is never matched by a value that cannot be parsed', () => {
    const h = shop({ fatigue: NF, lift: () => ({ verb: 'cart.buy', values: { 'action.params.amount': -0 } }) });
    expect(recv(h, buy(50), buyC(0), 'q_n').ok).toBe(true);
    h.ch.nextScreen();
    expect(h.ch.answer('q_n', { answer: 'yes', typed: 'zzz' })).toEqual({ ok: false, code: 'typed_mismatch', reason: 'the typed value does not match the card' });
  });
  it('typing works without a unit table', () => {
    const h = shop({ fatigue: NF, units: undefined });
    recv(h, buy(500), buyC(2), 'q_u');
    h.ch.nextScreen();
    expect(h.ch.answer('q_u', { answer: 'yes', typed: '500' }).ok).toBe(true);
  });
  it('the hold reason names the minimum', () => {
    const h = shop({ fatigue: NF, friction: { hTap: 0.5, hDevice: 1e9 } });
    recv(h, add(3), addC(2), 'q_h');
    h.ch.nextScreen();
    expect(h.ch.answer('q_h', { answer: 'yes', holdMs: 5 })).toEqual({ ok: false, code: 'tier_evidence', reason: 'hold for at least 2000 ms' });
  });
});

describe('device evidence', () => {
  const rpId = 'wallet.atlas.example';
  const origin = 'https://wallet.atlas.example';
  const setup = (over: Parameters<typeof harness>[0] = {}, withDevice = true) => {
    const cred = generateKeyPair();
    const signCounts: Record<string, number> = {};
    const device = { rpId, origins: [origin], credentials: { cred1: { kty: 'OKP' as const, crv: 'Ed25519' as const, x: b64u(cred.publicKey) } }, signCounts };
    const h = shop({ fatigue: NF, ...(withDevice ? { device } : {}), ...over });
    return { h, cred, signCounts };
  };
  it('refuses with the specific reason, binds the action for an irreversible site question and records the counter', () => {
    const { h, cred, signCounts } = setup({ friction: { hTap: 5, hDevice: 20 } });
    recv(h, buy(500), buyC(2), 'q_d');
    const card = h.ch.nextScreen()!.questions[0]!.card;
    expect(card.friction).toBe('device');
    const expected = deviceChallenge({ questionId: 'q_d', renderedDigest: card.rendered_digest, y: 1, actionDigest: pcaActionDigest(buy(500)) });
    expect(h.ch.deviceChallengeFor('q_d')).toBe(expected);
    expect(h.ch.answer('q_d', { answer: 'yes' })).toEqual({ ok: false, code: 'tier_evidence', reason: 'a security-key assertion is required' });
    const good = assertion(cred, expected, rpId, origin);
    expect(h.ch.answer('q_d', { answer: 'yes', webauthn: { credential_id: 'nope', ...good } })).toEqual({ ok: false, code: 'tier_evidence', reason: 'unknown credential or malformed assertion' });
    for (const field of ['authenticator_data', 'client_data_json', 'signature'] as const) {
      expect(h.ch.answer('q_d', { answer: 'yes', webauthn: { credential_id: 'cred1', ...good, [field]: '!!!' } })).toEqual({ ok: false, code: 'tier_evidence', reason: 'unknown credential or malformed assertion' });
    }
    const bad = h.ch.answer('q_d', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, D('other'), rpId, origin) } });
    expect(bad).toMatchObject({ ok: false, code: 'tier_evidence' });
    expect((bad as { reason: string }).reason.startsWith('security key: ')).toBe(true);
    expect(signCounts).toEqual({});
    const r = ok(h.ch.answer('q_d', { answer: 'yes', webauthn: { credential_id: 'cred1', ...good } }), 'answer').answer;
    expect(r.ux.consent_for_action).toBe(true);
    expect(r.ux.action_digest).toBe(pcaActionDigest(buy(500)));
    expect(signCounts).toEqual({ cred1: 7 });
  });
  it('without a device trust no assertion is accepted', () => {
    const { h, cred } = setup({ friction: { hTap: 5, hDevice: 20 } }, false);
    recv(h, buy(500), buyC(2), 'q_d');
    h.ch.nextScreen();
    const ch = h.ch.deviceChallengeFor('q_d')!;
    expect(h.ch.answer('q_d', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, ch, rpId, origin) } })).toEqual({ ok: false, code: 'tier_evidence', reason: 'a security-key assertion is required' });
  });
  it('a reversible device question does not bind an action digest; a tap question has no challenge', () => {
    const { h, cred } = setup();
    recv(h, add(3), addC(2), 'q_r', { friction: 'device' });
    recv(h, add(20), addC(6), 'q_t');
    expect(h.ch.deviceChallengeFor('q_r')).toBeNull();
    const qs = drain(h);
    const card = qs.find((q) => q.questionId === 'q_r')!.card;
    const expected = deviceChallenge({ questionId: 'q_r', renderedDigest: card.rendered_digest, y: 1 });
    expect(h.ch.deviceChallengeFor('q_r')).toBe(expected);
    expect(h.ch.deviceChallengeFor('q_t')).toBeNull();
    const r = ok(h.ch.answer('q_r', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, expected, rpId, origin) } }), 'answer').answer;
    expect(r.ux.action_digest).toBeUndefined();
    expect(r.ux.consent_for_action).toBeUndefined();
  });
});

describe('clarification', () => {
  it('a malformed body is a 400 with no verdicts', () => {
    expect(shop().ch.clarify('x')).toEqual({ status: 400, verdicts: [], error: 'body must be an object' });
  });
  it('a frozen session answers 200 and a capped one 429', () => {
    const frozen = shop({ fatigue: NF, shared: { hourly: new SlidingWindowCounter(), noise: { n: recordCanary(EMPTY_NOISE, 0, 1) }, clock: { t: 1 } } });
    expect(frozen.ch.clarify({ candidates: [cand(7)], reason: 'other' })).toEqual({ status: 200, verdicts: [{ index: 0, verdict: 'uncertain' }], refused: 'frozen' });
    const cap = shop({ fatigue: NF, caps: { perSession: 0 } });
    expect(cap.ch.clarify({ candidates: [cand(7)], reason: 'other' })).toEqual({ status: 429, verdicts: [{ index: 0, verdict: 'uncertain' }], refused: 'cap_session' });
  });
  it('asks the cell of the candidate verb', () => {
    const h = shop({ fatigue: NF });
    expect(h.ch.clarify({ candidates: [{ verb: 'cart.buy', values: { 'action.params.amount': 500 } }], reason: 'other' }).questionId).toBeDefined();
    expect(h.ch.nextScreen()!.questions[0]!.card.coords).toEqual({ 'action.params.amount': [2, 2] });
  });
  it('lifts a candidate into the wallet space before choosing', () => {
    const h = harness({ fatigue: NF, liftCandidate: (v) => ({ verb: v.verb, values: { ...v.values, 'env.prov.action.params.add_ons': 'trusted|first_party' } }) });
    const r = h.ch.clarify({ candidates: [{ verb: 'air.book', values: { 'action.params.add_ons': 'none', 'action.params.total': 77800 } }], reason: 'other' });
    expect(r.questionId).toBeDefined();
    expect(r.verdicts).toEqual([{ index: 0, verdict: 'uncertain' }]);
  });
  it('a cell whose coordinates are ambiguous cannot be rendered and is not marked asked', () => {
    const DUP: Omega = { v: 1, approximate: [], verbs: [{ verb: 'do.it', reversibility: 'reversible', weight: 1, dims: [{ kind: 'cat', path: 'action.params.k', values: [{ kind: 'exact', value: 'x' }, { kind: 'prefix', value: 'x' }, { kind: 'other', value: '⊥' }] }] }] };
    const h = harness({ omega: DUP, units: {}, lift: undefined, fatigue: NF });
    const body = { candidates: [{ verb: 'do.it', values: { 'action.params.k': 'x' } }], reason: 'other' };
    expect(h.ch.clarify(body)).toEqual({ status: 200, verdicts: [{ index: 0, verdict: 'uncertain' }], refused: 'render_failed' });
    expect(h.ch.clarify(body).verdicts).toEqual([{ index: 0, verdict: 'uncertain' }]);
    expect(h.ch.questionsAsked()).toBe(0);
  });
  it('the supplied harm model sets the risk weight used to break ties', () => {
    const harm = { verb: () => 1, dim: (_d: unknown, x: number | string) => (typeof x === 'number' && x <= 9 ? 1000 : 1) };
    const h = shop({ fatigue: NF, harm, view: fakeView({ p: { 'cart.add|4': 0.5, 'cart.add|6': 0.5 } }) });
    h.ch.clarify({ candidates: [cand(7), cand(20)], reason: 'other' });
    expect(h.ch.nextScreen()!.questions[0]!.card.coords).toEqual({ 'action.params.qty': [4, 4] });
  });
});

// The noise bounds feed the clarification planner capped just below 1/2. The cap only shows when two candidates' gains
// differ by about the planner's tie tolerance, so the pair is solved against the real estimate.
describe('clarification noise caps', () => {
  const H = (p: number) => (p <= 0 || p >= 1 ? 0 : -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p)));
  const gain = (p: number, ep: number, en: number) => H(p * (1 - en) + (1 - p) * ep) - (p * H(en) + (1 - p) * H(ep));
  const CAP = 0.5 - 1e-9;
  const solve = (f: (p: number) => number, lo: number, hi: number) => {
    for (let i = 0; i < 200; i++) {
      const m = (lo + hi) / 2;
      if (f(lo) * f(m) <= 0) hi = m;
      else lo = m;
    }
    return (lo + hi) / 2;
  };
  const e = estimateNoise(EMPTY_NOISE, 0.05).etaPosUpper;
  const p1 = 0.3;
  // `capPos`: the false-yes bound is capped (heavy load); otherwise the false-no bound is (many false noes).
  const pick = (capPos: boolean, lightIsFirst: boolean, tie: number) => {
    const lifted = (p: number) => (capPos ? gain(p, 0.5, e) : gain(p, e, 0.5));
    const capped = (p: number) => (capPos ? gain(p, CAP, e) : gain(p, e, CAP));
    const p2 = solve((p) => lifted(p1) - lifted(p) - tie, 0.55, 0.95);
    expect(Math.abs(lifted(p1) - lifted(p2))).toBeLessThan(1e-12);
    expect(Math.abs(capped(p1) - capped(p2))).toBeGreaterThan(1e-12);
    const hourly = new SlidingWindowCounter();
    if (capPos) hourly.tryAdd(1_000_000, 99);
    const noise = capPos ? EMPTY_NOISE : { falseYes: 0, correctNo: 0, falseNo: 40, correctYes: 0 };
    const fatigue = { ...NF, etaStop: 1, ...(capPos ? { betaF: 1 } : {}) };
    const p = lightIsFirst ? { 'cart.add|4': p1, 'cart.add|6': p2 } : { 'cart.add|6': p1, 'cart.add|4': p2 };
    const h = shop({ fatigue, view: fakeView({ p }), shared: { hourly, noise: { n: noise }, clock: { t: 1_000_000 } } });
    h.ch.clarify({ candidates: lightIsFirst ? [cand(7), cand(20)] : [cand(20), cand(7)], reason: 'other' });
    return h.ch.nextScreen()!.questions[0]!.card.coords;
  };
  it('a capped false-yes bound still lets the larger gain win', () => {
    expect(pick(true, true, 9.5e-13)).toEqual({ 'action.params.qty': [4, 4] });
  });
  it('a capped false-no bound still lets the larger gain win', () => {
    expect(pick(false, false, -9.5e-13)).toEqual({ 'action.params.qty': [4, 4] });
  });
});

describe('canaries', () => {
  const sc = (outside: string[], confirmed: CellAt[] = [{ verb: 'cart.add', idx: [2] }]) => fakeView({ confirmed, outside });
  it('a low-harm session gets at most one canary, rendered like its real question', () => {
    const h = shop({ rho: 1, view: sc(['cart.add|1', 'cart.add|3']), friction: { hTap: 0.5, hDevice: 1e9 } });
    expect(recv(h, add(20), addC(6), 'q_a1').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(1);
    const qs = h.ch.nextScreen()!.questions;
    expect(qs).toHaveLength(2);
    const canary = qs.find((q) => q.questionId !== 'q_a1')!;
    expect(canary.card.friction).toBe('hold');
    expect(canary.card.kind).toBe('question');
    expect(Object.keys(canary.card.coords)).toEqual(['action.params.qty']);
    expect(recv(h, add(70), addC(8), 'q_a2').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(1);
  });
  it('a session with a high-harm question pending may get a second canary', () => {
    const h = shop({ rho: 1, view: sc(['cart.add|1', 'cart.add|3']) });
    recv(h, add(20), addC(6), 'q_b1');
    expect(h.ch.summary().canaries).toBe(1);
    recv(h, buy(500), buyC(2), 'q_b2');
    expect(h.ch.summary().canaries).toBe(2);
  });
  it('a canary is drawn for the right verb', () => {
    const h = shop({ rho: 1, view: sc(['cart.buy|0'], [{ verb: 'cart.buy', idx: [1] }]) });
    expect(recv(h, buy(5000), buyC(4), 'q_v').ok).toBe(true);
    const cards = drain(h).filter((q) => q.questionId !== 'q_v');
    expect(cards.map((q) => q.card.coords)).toEqual([{ 'action.params.amount': [0, 0] }]);
  });
  it('a used canary cell is not used again', () => {
    const outside = new Set(['cart.add|1']);
    const base = sc([]);
    const view: GrantView = { ...base, outsideCeiling: (v, idx) => outside.has(`${v}|${idx.join(',')}`) };
    const seq = [0, 0, 0.01, 0.11, 0.21, 0.31, 0.41, 0.51, 0.61, 0.71, 0.81, 0.91];
    let i = 0;
    const h = shop({ rho: 1, view, rand: () => seq[i++ % 12]! });
    recv(h, add(20), addC(6), 'q_d1');
    expect(h.ch.summary().canaries).toBe(1);
    const first = h.ch.nextScreen()!.questions;
    const c1 = first.find((q) => q.questionId !== 'q_d1')!;
    expect(c1.card.coords).toEqual({ 'action.params.qty': [1, 1] });
    expect(ok(h.ch.answer(c1.questionId, { answer: 'no' }), 'canary').answer.ux.canary).toBe(true);
    outside.add('cart.add|3');
    recv(h, buy(500), buyC(2), 'q_d2');
    expect(h.ch.summary().canaries).toBe(2);
    const later = drain(h).filter((q) => q.questionId !== 'q_d2');
    expect(later.map((q) => q.card.coords)).toEqual([{ 'action.params.qty': [3, 3] }]);
  });
  it('a cell with a pending confirmation is not drawn as a known-yes canary', () => {
    const h = harness({ rho: 1 });
    recv(h, book(50000), coords([2, 2]), 'q_c1');
    h.ch.nextScreen();
    ok(h.ch.answer('q_c1', { answer: 'yes', typed: '500' }), 'pending_confirmation');
    recv(h, book(50000, 'tripshield'), coords([2, 2], 'tripshield'), 'q_c2');
    expect(h.ch.summary().canaries).toBe(0);
  });
  it('a canary that cannot be rendered is skipped', () => {
    const DUP: Omega = { v: 1, approximate: [], verbs: [{ verb: 'do.it', reversibility: 'reversible', weight: 1, dims: [{ kind: 'cat', path: 'action.params.k', values: [{ kind: 'exact', value: 'x' }, { kind: 'prefix', value: 'x' }, { kind: 'other', value: '⊥' }] }] }] };
    const h = harness({ omega: DUP, units: {}, lift: undefined, rho: 1, view: fakeView({ confirmed: [{ verb: 'do.it', idx: [0] }], outside: ['do.it|1'] }) });
    expect(recv(h, act('do.it', { k: 'zzz' }, 'r', 'reversible'), { 'action.params.k': ['⊥'] }, 'q_x').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(0);
  });
  it('a clarification can also draw a canary', () => {
    const h = shop({ rho: 1, view: sc(['cart.add|1']), fatigue: NF });
    expect(h.ch.clarify({ candidates: [cand(20)], reason: 'other' }).questionId).toBeDefined();
    expect(h.ch.summary().canaries).toBe(1);
  });
});

describe('only a verified, whole, high-friction yes is a known-yes cell', () => {
  const canariesAfter = (h: H, second: () => unknown) => {
    second();
    return h.ch.summary().canaries;
  };
  it('a tap yes is not', () => {
    const h = shop({ rho: 1 });
    recv(h, add(3), addC(2), 'q_1');
    h.ch.nextScreen();
    ok(h.ch.answer('q_1', { answer: 'yes' }), 'answer');
    expect(canariesAfter(h, () => recv(h, add(20), addC(6), 'q_2'))).toBe(0);
  });
  it('a single-cell typed yes is, and the canary re-asks exactly that cell', () => {
    const h = shop({ rho: 1, fatigue: NF });
    recv(h, buy(500), buyC(2), 'q_1');
    h.ch.nextScreen();
    ok(h.ch.answer('q_1', { answer: 'yes', typed: '500' }), 'answer');
    recv(h, buy(5000), buyC(4), 'q_2');
    expect(h.ch.summary().canaries).toBe(1);
    const c = drain(h).filter((q) => q.questionId !== 'q_2');
    expect(c.map((q) => q.card.coords)).toEqual([{ 'action.params.amount': [2, 2] }]);
  });
  it('a partial typed yes is not', () => {
    const h = shop({ rho: 1, fatigue: NF });
    recv(h, buy(500), buyC(2), 'q_1');
    h.ch.nextScreen();
    ok(h.ch.answer('q_1', { answer: 'partly', partial: { path: 'action.params.amount', upTo: 500 }, typed: '500' }), 'answer');
    expect(canariesAfter(h, () => recv(h, buy(5000), buyC(4), 'q_2'))).toBe(0);
  });
  it('a multi-cell box is not', () => {
    const h = harness({ rho: 1, fatigue: NF });
    recv(h, book(77800), coords([2, 3]), 'q_1');
    h.ch.nextScreen();
    ok(h.ch.answer('q_1', { answer: 'yes', typed: '778' }), 'answer');
    expect(canariesAfter(h, () => recv(h, book(50000, 'tripshield'), coords([2, 2], 'tripshield'), 'q_2'))).toBe(0);
  });
});

describe('stateDigest', () => {
  it('is the canonical hash of the ordered pending questions and the sorted asked cells', () => {
    const h = harness({ fatigue: NF });
    recv(h, book(80000), coords([3, 3]), 'q_s2');
    recv(h, book(50000), coords([2, 2]), 'q_s1');
    const qs = drain(h);
    expect(qs).toHaveLength(2);
    const expected = hashCanonical({
      d: 'atlas-pca/wallet-channel-state/v1',
      p: qs.map((q) => ({ id: q.questionId, k: 'real', d: q.card.rendered_digest })),
      a: ['air.book|0,2,0', 'air.book|0,3,0'],
      n: 2,
    });
    expect(h.ch.stateDigest()).toBe(expected);
  });
});
