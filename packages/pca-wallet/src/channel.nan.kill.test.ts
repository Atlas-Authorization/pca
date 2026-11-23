import { describe, expect, it } from 'vitest';
import { DEFAULT_FATIGUE } from './index';
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
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'expired' });
  });
  it('nextScreen with a NaN clock drops the question', () => {
    const h = setup();
    h.clock.t = Number.NaN;
    expect(h.ch.nextScreen()).toBeNull();
  });
  it('answer with a +Infinity clock is expired', () => {
    const h = setup();
    expect(h.ch.nextScreen()).not.toBeNull();
    h.clock.t = Number.POSITIVE_INFINITY;
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'expired' });
  });
});
