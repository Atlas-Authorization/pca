import { describe, expect, it } from 'vitest';
import type { Omega } from '@atlasauth/pca-intent';
import { act, fakeView, harness, makeIR, SHOP } from './fixtures.test-util';
import { actionValuesOf, DEFAULT_FATIGUE } from './index';

const NF = { ...DEFAULT_FATIGUE, assumeNoiseFree: true };
type H = ReturnType<typeof harness>;
const add = (q: number) => act('cart.add', { qty: q }, 'shop/cart', 'reversible');
const addC = (i: number) => ({ 'action.params.qty': [i, i] as [number, number] });
const cand = (q: number) => ({ verb: 'cart.add', values: { 'action.params.qty': q } });
const shop = (over: Parameters<typeof harness>[0] = {}) => harness({ omega: SHOP, units: {}, lift: undefined, ...over });
const recv = (h: H, a: ReturnType<typeof act>, c: Record<string, unknown>, id: string) => h.ch.receive(makeIR(h, a, c as never, { question_id: id }), { action: a });

describe('provenance is read only from env.prov. dimensions', () => {
  const PROV = 'env.prov.action.params.payee';
  // not under env.prov., but its name past the first nine characters is the critical parameter
  const OTHER = 'env.acc.aaction.params.payee';
  const OM: Omega = {
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
          { kind: 'cat', path: PROV, values: [{ kind: 'exact', value: 'trusted|first_party' }, { kind: 'other', value: '⊥' }] },
          { kind: 'cat', path: OTHER, values: [{ kind: 'exact', value: 'tool|web|agent' }, { kind: 'other', value: '⊥' }] },
        ],
      },
    ],
  };
  it('a tainted-looking dimension outside env.prov. does not make a critical parameter tainted', () => {
    const x = act('msg.send', { qty: 3, payee: 'ann' }, 'r', 'reversible');
    const h = harness({
      omega: OM,
      units: {},
      fatigue: NF,
      sensitivity: { 'action.params.payee': 'critical' },
      lift: (a) => ({ verb: a.verb, values: { ...actionValuesOf(a).values, [PROV]: 'trusted|first_party', [OTHER]: 'tool|web|agent' } }),
    });
    const r = recv(h, x, { 'action.params.qty': [0, 0], 'action.params.payee': ['ann'], [PROV]: ['trusted|first_party'], [OTHER]: ['tool|web|agent'] }, 'q_p');
    expect(r).toMatchObject({ ok: true, friction: 'tap' });
  });
});

describe('what a received question and a clarification are', () => {
  it('a received question is rendered as a question', () => {
    const h = shop({ fatigue: NF });
    expect(recv(h, add(3), addC(2), 'q_k').ok).toBe(true);
    expect(h.ch.nextScreen()!.questions[0]!.card.kind).toBe('question');
  });

  it('a canary is not drawn on the cell a clarification is already asking about', () => {
    // cell 3 (qty 5) is asked about, then becomes a known no once the canary draw reads the confirmed region
    const base = fakeView({ confirmed: [{ verb: 'cart.add', idx: [2] }] });
    let drawing = false;
    const view = { ...base, confirmed: () => ((drawing = true), base.confirmed()), outsideCeiling: (_v: string, idx: readonly number[]) => drawing && idx[0] === 3 };
    const h = shop({ rho: 1, view, fatigue: NF });
    expect(h.ch.clarify({ candidates: [cand(5)], reason: 'other' }).questionId).toBeDefined();
    expect(drawing).toBe(true);
    expect(h.ch.summary().canaries).toBe(0);
  });

  it('a pending clarification of a high-friction cell lifts the one-canary limit of a low-harm session', () => {
    const view = fakeView({ confirmed: [{ verb: 'cart.add', idx: [2] }], outside: ['cart.add|1', 'cart.add|3'] });
    const h = shop({ rho: 1, view, fatigue: NF });
    expect(recv(h, add(20), addC(6), 'q_b1').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(1);
    const c = h.ch.clarify({ candidates: [{ verb: 'cart.buy', values: { 'action.params.amount': 500 } }], reason: 'other' });
    expect(c.questionId).toBeDefined();
    expect(h.ch.summary().canaries).toBe(2);
  });

  it('a pending canary of a high-friction cell does not lift the limit: only real questions count', () => {
    const view = fakeView({ confirmed: [{ verb: 'cart.buy', idx: [1] }], outside: ['cart.buy|0', 'cart.buy|2'] });
    const h = shop({ rho: 1, view, fatigue: NF, friction: { hTap: 0.5, hDevice: 1e9 } });
    expect(recv(h, add(20), addC(6), 'q_1').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(1);
    expect(recv(h, add(70), addC(8), 'q_2').ok).toBe(true);
    expect(h.ch.summary().canaries).toBe(1);
  });
});
