import { describe, expect, it } from 'vitest';
import { type Reversibility } from '@atlasauth/pca/ext/research';
import { type VerbSpace } from '@atlasauth/pca-intent';
import { act, harness, makeIR, SHOP } from './fixtures.test-util';
import { boundaryNeighbours, DEFAULT_FATIGUE, type AnswerResult, type FatigueModel } from './index';

type Cmp = (a: unknown, b: unknown) => number;
// Records the comparator passed to the first sort whose first element matches `pick`, so a tie-break that sort output
// cannot show (keys that are never equal, or items that never tie) can still be checked directly.
const captureSort = (pick: (first: unknown) => boolean, run: () => void): Cmp => {
  const orig = Array.prototype.sort;
  let got: Cmp | undefined;
  Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
    if (fn && !got && this.length > 0 && pick(this[0])) got = fn;
    return orig.call(this, fn);
  } as typeof orig;
  try { run(); } finally { Array.prototype.sort = orig; }
  if (!got) throw new Error('no comparator captured');
  return got;
};

describe('boundaryNeighbours sorts by key', () => {
  it('the key comparator returns -1, 1 and 0', () => {
    const isEntry = (x: unknown) => Array.isArray(x) && typeof x[0] === 'string' && typeof (x[1] as { verb?: unknown })?.verb === 'string';
    const cmp = captureSort(isEntry, () => { boundaryNeighbours(SHOP, [{ verb: 'cart.add', idx: [2] }]); });
    const v = { verb: 'cart.add', idx: [1] };
    expect(cmp(['b', v], ['a', v])).toBe(1);
    expect(cmp(['a', v], ['b', v])).toBe(-1);
    expect(cmp(['a', v], ['a', v])).toBe(0);
  });
});

describe('the pending queue order', () => {
  it('items equal in friction, weight and cell are ordered by id: -1, 1 and 0', () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: { ...DEFAULT_FATIGUE, assumeNoiseFree: true } });
    const a = act('cart.add', { qty: 3 }, 'shop/cart', 'reversible');
    expect(h.ch.receive(makeIR(h, a, { 'action.params.qty': [2, 2] } as never, { question_id: 'q_1' }), { action: a }).ok).toBe(true);
    const isItem = (x: unknown) => typeof x === 'object' && x !== null && 'card' in x && 'flat' in x;
    const cmp = captureSort(isItem, () => { h.ch.nextScreen(); });
    const item = (id: string) => ({ id, card: { friction: 'tap' }, weight: 0.5, flat: 2 });
    expect(cmp(item('b'), item('a'))).toBe(1);
    expect(cmp(item('a'), item('b'))).toBe(-1);
    expect(cmp(item('a'), item('a'))).toBe(0);
  });
});

describe('double confirmation is counted per cell', () => {
  const ok = <K extends string>(r: AnswerResult, kind: K): void => {
    if (!r.ok || r.kind !== kind) throw new Error(`expected ${kind}, got ${JSON.stringify(r)}`);
  };
  it('typed confirmations of another cell never complete a weak confirmation of this cell', () => {
    // Value-dependent reversibility can call one box irreversible when the question is received and reversible when its
    // friction is priced, so an irreversible question can carry a tap card while the noise estimate does not yet ask
    // for two confirmations.
    const fatigue: FatigueModel = { ...DEFAULT_FATIGUE, assumeNoiseFree: true };
    const armed = { add: false };
    const reversibility = (vs: VerbSpace): Reversibility => {
      if (vs.verb !== 'cart.add') return vs.reversibility;
      if (!armed.add) return 'reversible';
      armed.add = false;
      return 'irreversible';
    };
    const h = harness({ omega: SHOP, units: {}, lift: undefined, rho: 0, fatigue, reversibility });
    const add = act('cart.add', { qty: 3 }, 'shop/cart', 'reversible');
    armed.add = true;
    expect(h.ch.receive(makeIR(h, add, { 'action.params.qty': [2, 2] } as never, { question_id: 'q_a' }), { action: add })).toEqual({ ok: true, questionId: 'q_a', friction: 'tap' });
    fatigue.assumeNoiseFree = false;
    expect(h.ch.admission().doubleConfirmIrreversible).toBe(true);
    const buy = act('cart.buy', { amount: 500 }, 'shop/orders');
    expect(h.ch.receive(makeIR(h, buy, { 'action.params.amount': [2, 2] } as never, { question_id: 'q_b' }), { action: buy })).toMatchObject({ ok: true, friction: 'typed' });

    const s1 = h.ch.nextScreen()!;
    expect(s1.questions.map((q) => q.questionId)).toEqual(['q_b']);
    ok(h.ch.answer('q_b', { answer: 'yes', typed: '500' }), 'pending_confirmation');
    const s2 = h.ch.nextScreen()!;
    expect(s2.questions.map((q) => q.questionId)).toEqual(['q_a']);
    ok(h.ch.answer('q_a', { answer: 'yes' }), 'pending_confirmation');
    const s3 = h.ch.nextScreen()!;
    expect(s3.questions).toHaveLength(1);
    expect(s3.questions[0]!.card.friction).toBe('typed');
    ok(h.ch.answer(s3.questions[0]!.questionId, { answer: 'yes', typed: '500' }), 'confirmed');
    const s4 = h.ch.nextScreen()!;
    expect(s4.screen).toBe(4);
    expect(s4.questions).toHaveLength(1);
    expect(s4.questions[0]!.card.friction).toBe('tap');
    ok(h.ch.answer(s4.questions[0]!.questionId, { answer: 'yes' }), 'pending_confirmation');
  });
});
