import { describe, expect, it } from 'vitest';
import { DEFAULT_FATIGUE, TrustedChannel } from './index';
import { act, harness, makeIR, SHOP } from './fixtures.test-util';

const book = (total: number, addOns = 'none') => act('air.book', { add_ons: addOns, total }, 'skyair.example/bookings');
const coords = (total: [number, number], addOns = 'none') => ({ 'action.params.add_ons': [addOns], 'action.params.total': total, 'env.prov.action.params.add_ons': ['trusted|first_party'] });
const first = (h: ReturnType<typeof harness>) => {
  const a = book(50000);
  return h.ch.receive(makeIR(h, a, coords([2, 2]) as never, { question_id: 'q_a' }), { action: a });
};

describe('a NaN question cap never lifts the cap (channel gate)', () => {
  // pre-fix: `sessionQuestions >= NaN` and `count >= NaN` were false, so a NaN cap admitted every question
  it('perSession of NaN refuses the first question', () => {
    expect(first(harness({ caps: { perSession: Number.NaN } }))).toMatchObject({ ok: false, code: 'cap_session' });
  });
  it('perHour of NaN refuses the first question', () => {
    expect(first(harness({ caps: { perHour: Number.NaN } }))).toMatchObject({ ok: false, code: 'cap_hour' });
  });
  it('perSession of -Infinity refuses the first question', () => {
    expect(first(harness({ caps: { perSession: Number.NEGATIVE_INFINITY } }))).toMatchObject({ ok: false, code: 'cap_session' });
  });
});

describe('a non-finite clock expires a pending question (channel)', () => {
  const add = (q: number) => act('cart.add', { qty: q }, 'shop/cart', 'reversible');
  const addC = (i: number) => ({ 'action.params.qty': [i, i] as [number, number] });
  const setup = () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: { ...DEFAULT_FATIGUE, assumeNoiseFree: true } });
    const a = add(3);
    h.ch.receive(makeIR(h, a, addC(2) as never, { question_id: 'q_e', expires_at: h.clock.t + 10 }), { action: a });
    return h;
  };
  // pre-fix: `now > expiresAt` was false for NaN, so an expired question stayed answerable
  it('answer with a NaN clock is expired', () => {
    const h = setup();
    expect(h.ch.nextScreen()).not.toBeNull();
    h.clock.t = Number.NaN;
    expect(h.ch.answer('q_e', { answer: 'no' })).toEqual({ ok: false, code: 'expired', reason: 'the question expired' });
  });
  it('nextScreen with a NaN clock drops the question', () => {
    const h = setup();
    h.clock.t = Number.NaN;
    expect(h.ch.nextScreen()).toBeNull();
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'unknown_question' });
  });
  it('answer with a +Infinity clock is expired', () => {
    const h = setup();
    expect(h.ch.nextScreen()).not.toBeNull();
    h.clock.t = Number.POSITIVE_INFINITY;
    expect(h.ch.answer('q_e', { answer: 'no' })).toEqual({ ok: false, code: 'expired', reason: 'the question expired' });
  });
  // old code: `-Infinity <= expiresAt` is true, so the question never expired
  it('answer with a -Infinity clock is expired', () => {
    const h = setup();
    expect(h.ch.nextScreen()).not.toBeNull();
    h.clock.t = Number.NEGATIVE_INFINITY;
    expect(h.ch.answer('q_e', { answer: 'no' })).toEqual({ ok: false, code: 'expired', reason: 'the question expired' });
  });
  it('nextScreen with a -Infinity clock drops the question', () => {
    const h = setup();
    h.clock.t = Number.NEGATIVE_INFINITY;
    expect(h.ch.nextScreen()).toBeNull();
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'unknown_question' });
  });
});

describe('a non-finite clock refuses an otherwise admissible question at the hourly gate', () => {
  // The signature check reads the clock first, so it sees a finite time; only the cap gate then sees the non-finite one.
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('clock of %s refuses the first question', (t) => {
    const finite = harness({});
    expect(first(finite)).toMatchObject({ ok: true, questionId: 'q_a' });

    const h = harness({});
    const a = book(50000);
    const ir = makeIR(h, a, coords([2, 2]) as never, { question_id: 'q_a' });
    let reads = 0;
    h.opts.now = () => (reads++ === 0 ? h.clock.t : t);
    const ch = new TrustedChannel(h.opts);
    expect(ch.receive(ir, { action: a })).toEqual({ ok: false, code: 'cap_hour', reason: 'at most 12 questions per hour' });
  });
});
