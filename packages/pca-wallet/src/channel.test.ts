import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { cellRep, IntentLearner, rng } from '@atlasauth/pca-intent';
import { act, assertion, D, fakeView, harness, makeIR, SESSION, SHOP } from './fixtures.test-util';
import {
  cardText,
  clarifyHandler,
  DEFAULT_FATIGUE,
  learnerView,
  pcaActionDigest,
  questionHandler,
  recordCanary,
  REASON_LABELS,
  SlidingWindowCounter,
  EMPTY_NOISE,
  typedDigest,
  verifyIntentAnswer,
  type AnswerResult,
  type TrustedChannel,
} from './index';

const NF = { ...DEFAULT_FATIGUE, assumeNoiseFree: true };
const book = (total: number, addOns = 'none') => act('air.book', { add_ons: addOns, total }, 'skyair.example/bookings');
const coords = (total: [number, number], addOns = 'none') => ({ 'action.params.add_ons': [addOns], 'action.params.total': total, 'env.prov.action.params.add_ons': ['trusted|first_party'] });
const ok = <K extends string>(r: AnswerResult, kind: K): Extract<AnswerResult, { kind: K }> => {
  if (!r.ok || r.kind !== kind) throw new Error(`expected ${kind}, got ${JSON.stringify(r)}`);
  return r as Extract<AnswerResult, { kind: K }>;
};

describe('the §4 walkthrough through the trusted channel', () => {
  it('asks attempt 2 at typed tier, checks the typed total, and under estimated noise needs a second confirmation two screens later', () => {
    const h = harness();
    const a = book(77800);
    const ir = makeIR(h, a, coords([2, 3]), { friction: 'typed', question_id: 'q_7Hk2' });
    expect(h.ch.receive(ir, { action: a })).toEqual({ ok: true, questionId: 'q_7Hk2', friction: 'typed' });
    const s1 = h.ch.nextScreen()!;
    expect(s1.questions).toHaveLength(1);
    const text = cardText(s1.questions[0]!.card);
    expect(text).toContain('SkyAir asks on behalf of your request "Book me and Sam');
    expect(text).toContain('$400.01 – $800.00 (this action: $778.00)');
    h.clock.t += 5_000;
    expect(h.ch.answer('q_7Hk2', { answer: 'yes', typed: '777' })).toMatchObject({ ok: false, code: 'typed_mismatch' });
    expect(h.ch.answer('q_7Hk2', { answer: 'yes' })).toMatchObject({ ok: false, code: 'tier_evidence' });
    const first = ok(h.ch.answer('q_7Hk2', { answer: 'yes', typed: '778' }), 'pending_confirmation').answer;
    expect(h.ch.nextScreen()!.kind).toBe('interstitial');
    const s3 = h.ch.nextScreen()!;
    expect(s3.kind).toBe('questions');
    const q2 = s3.questions[0]!.questionId;
    const [a1, a2] = ok(h.ch.answer(q2, { answer: 'yes', typed: '$778.00' }), 'confirmed').answers;
    expect(a1).toBe(first);
    for (const x of [a1, a2]) {
      expect(verifyIntentAnswer(x, [b64u(h.ana.publicKey)])).toEqual({ ok: true });
      expect(x.ux).toMatchObject({ tier: 'typed', consent_for_action: true, action_digest: pcaActionDigest(a), canary: false });
      expect(x.cell).toEqual(coords([2, 3]));
      expect(x.session).toBe(SESSION);
    }
    expect(a1.ux.typed_digest).toBe(typedDigest('q_7Hk2', '77800'));
    expect(a2.ux.typed_digest).toBe(typedDigest(q2, '77800'));
    expect(h.ch.questionsAsked()).toBe(1);
  });
  it('under the noise-free assumption one typed yes is the answer and the JIT consent for this exact action', () => {
    const h = harness({ fatigue: NF });
    const a = book(77800);
    h.ch.receive(makeIR(h, a, coords([2, 3]), { friction: 'typed', question_id: 'q_1' }), { action: a });
    h.ch.nextScreen();
    const r = ok(h.ch.answer('q_1', { answer: 'yes', typed: '778.00' }), 'answer').answer;
    expect(r.ux.consent_for_action).toBe(true);
    expect(r.source).toBe('elicitation');
  });
  it('a "No" is a signed veto; a "Partly…" is a structured yes for part, never a consent', () => {
    const h = harness({ fatigue: NF });
    const a = book(77800);
    h.ch.receive(makeIR(h, a, coords([2, 3]), { question_id: 'q_no' }), { action: a });
    h.ch.nextScreen();
    expect(ok(h.ch.answer('q_no', { answer: 'no' }), 'veto').answer.y).toBe(0);
    const b = book(50000, 'tripshield');
    h.ch.receive(makeIR(h, b, coords([2, 2], 'tripshield'), { question_id: 'q_part' }), { action: b });
    h.ch.nextScreen();
    expect(h.ch.answer('q_part', { answer: 'partly', partial: { path: 'action.params.total', upTo: 90000 }, typed: '500' })).toMatchObject({ ok: false, code: 'bad_response' });
    const p = ok(h.ch.answer('q_part', { answer: 'partly', partial: { path: 'action.params.total', upTo: 45000 }, typed: '500' }), 'answer').answer;
    expect(p.partial).toEqual({ path: 'action.params.total', upTo: 45000 });
    expect(p.ux.consent_for_action).toBeUndefined();
  });
});

describe('selection belongs to the verifier: every receive check fails closed', () => {
  const a = book(77800);
  it.each([
    ['bad_site_signature', (h: ReturnType<typeof harness>) => ({ ir: { ...makeIR(h, a, coords([2, 3])), friction: 'device' as const }, action: a })],
    ['bad_site_signature', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, coords([2, 3]), { kid: 'unknown-kid' }), action: a })],
    ['wrong_session', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, coords([2, 3]), { session: D('other') }), action: a })],
    ['action_mismatch', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, coords([2, 3])), action: book(77900) })],
    ['action_mismatch', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, coords([2, 3])), action: { ...a, resource: 'skyair.example/other' } })],
    ['cell_mismatch', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, coords([0, 1])), action: a })],
    ['cell_mismatch', (h: ReturnType<typeof harness>) => ({ ir: makeIR(h, a, { ...coords([2, 3]), 'action.params.payee': ['x'] }), action: a })],
  ])('%s', (code: string, make: (h: ReturnType<typeof harness>) => { ir: Parameters<TrustedChannel['receive']>[0]; action: Parameters<TrustedChannel['receive']>[1]['action'] }) => {
    const h = harness();
    const { ir, action } = make(h);
    expect(h.ch.receive(ir, { action })).toMatchObject({ ok: false, code });
    expect(h.ch.questionsAsked()).toBe(0);
  });
  it('stale map, expired question', () => {
    const h = harness();
    const ir = makeIR(h, a, coords([2, 3]));
    h.map.d = D('map-1');
    expect(h.ch.receive(ir, { action: a })).toMatchObject({ ok: false, code: 'stale_map' });
    const h2 = harness();
    const ir2 = makeIR(h2, a, coords([2, 3]), { expires_at: h2.clock.t - 1 });
    expect(h2.ch.receive(ir2, { action: a })).toMatchObject({ ok: false, code: 'bad_site_signature' });
  });
  it('never asks about a decided cell, a vetoed cell or a cell outside a ceiling', () => {
    for (const view of [fakeView({ p: { 'air.book|0,2,0': 1 } }), fakeView({ p: { 'air.book|0,2,0': 0 } }), fakeView({ vetoed: ['air.book|0,3,0'] }), fakeView({ outside: ['air.book|0,3,0'] })]) {
      const h = harness({ view });
      expect(h.ch.receive(makeIR(h, a, coords([2, 3])), { action: a })).toMatchObject({ ok: false, code: 'not_uncertain' });
    }
  });
  it('T13: a cell is asked at most once per session', () => {
    const h = harness();
    expect(h.ch.receive(makeIR(h, a, coords([2, 3]), { question_id: 'q_a' }), { action: a }).ok).toBe(true);
    expect(h.ch.receive(makeIR(h, book(79000), coords([2, 2]), { question_id: 'q_b' }), { action: book(79000) })).toMatchObject({ ok: false, code: 'already_asked' });
  });
  it('per-session cap, and a per-hour cap shared across sessions (an accumulator the agent cannot split around)', () => {
    const h = harness({ caps: { perSession: 2 } });
    expect(h.ch.receive(makeIR(h, book(50000), coords([2, 2])), { action: book(50000) }).ok).toBe(true);
    expect(h.ch.receive(makeIR(h, book(80000), coords([3, 3])), { action: book(80000) }).ok).toBe(true);
    expect(h.ch.receive(makeIR(h, book(50000, 'tripshield'), coords([2, 2], 'tripshield')), { action: book(50000, 'tripshield') })).toMatchObject({ ok: false, code: 'cap_session' });

    const shared = { hourly: new SlidingWindowCounter(), noise: { n: EMPTY_NOISE }, clock: { t: 5_000_000 } };
    const s1 = harness({ caps: { perHour: 3 }, shared });
    const s2 = harness({ caps: { perHour: 3 }, shared });
    expect(s1.ch.receive(makeIR(s1, book(50000), coords([2, 2])), { action: book(50000) }).ok).toBe(true);
    expect(s1.ch.receive(makeIR(s1, book(80000), coords([3, 3])), { action: book(80000) }).ok).toBe(true);
    expect(s2.ch.receive(makeIR(s2, book(50000), coords([2, 2])), { action: book(50000) }).ok).toBe(true);
    expect(s2.ch.receive(makeIR(s2, book(80000), coords([3, 3])), { action: book(80000) })).toMatchObject({ ok: false, code: 'cap_hour' });
    shared.clock.t += 3_600_001;
    expect(s2.ch.receive(makeIR(s2, book(80000), coords([3, 3])), { action: book(80000) }).ok).toBe(true);
  });
  it('a frozen session refuses and lists the cell in the end-of-session summary', () => {
    const h = harness({ shared: { hourly: new SlidingWindowCounter(), noise: { n: recordCanary(EMPTY_NOISE, 0, 1) }, clock: { t: 1 } } });
    expect(h.ch.receive(makeIR(h, a, coords([2, 3])), { action: a })).toMatchObject({ ok: false, code: 'frozen' });
    expect(h.ch.summary()).toMatchObject({ frozen: true, refused: [{ verb: 'air.book', coords: coords([2, 3]) }], asked: 0 });
  });
});

describe('ordering belongs to the wallet', () => {
  it('friction desc, then E[h|c]·μ̃(c) desc; a typed question is alone on its screen; tap questions share up to 3', () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF });
    const add = (q: number) => act('cart.add', { qty: q }, 'shop/cart', 'reversible');
    const cellOf = (i: number) => ({ 'action.params.qty': [i, i] as [number, number] });
    const ids: Record<number, string> = {};
    for (const [q, i] of [[3, 2], [7, 4], [20, 6], [70, 8]] as const) {
      const r = h.ch.receive(makeIR(h, add(q), cellOf(i), { question_id: `q_add${q}` }), { action: add(q) });
      if (!r.ok) throw new Error(r.reason);
      expect(r.friction).toBe('tap');
      ids[q] = r.questionId;
    }
    const buy = act('cart.buy', { amount: 500 }, 'shop/orders');
    expect(h.ch.receive(makeIR(h, buy, { 'action.params.amount': [2, 2] }, { question_id: 'q_buy' }), { action: buy })).toMatchObject({ ok: true, friction: 'typed' });
    expect(h.ch.nextScreen()!.questions.map((q) => q.questionId)).toEqual(['q_buy']);
    expect(h.ch.nextScreen()!.questions.map((q) => q.questionId)).toEqual([ids[70], ids[20], ids[7]]);
    expect(h.ch.nextScreen()!.questions.map((q) => q.questionId)).toEqual([ids[3]]);
    expect(h.ch.nextScreen()).toBeNull();
  });
});

describe('T16: canaries never change the grant', () => {
  const add = (q: number) => ({ verb: 'cart.add', values: { 'action.params.qty': q } });
  const addA = (q: number) => act('cart.add', { qty: q }, 'shop/cart', 'reversible');
  const setup = () => {
    const l = new IntentLearner(SHOP, {});
    l.observe(add(3), 1, 'elicitation'); // confirms the cell [2, 4]
    l.observe(add(5), 0, 'runtime'); // vetoes {5}: a known-no right at the boundary
    return l;
  };
  it('a canary is inserted near the boundary, looks like a question, and its answer only moves the noise counts', () => {
    const l = setup();
    const h = harness({ omega: SHOP, units: {}, lift: undefined, view: learnerView(l), rho: 1, fatigue: NF });
    const before = JSON.stringify(l.cells());
    const nObs = l.observations.length;
    expect(h.ch.receive(makeIR(h, addA(1), { 'action.params.qty': [1, 1] }, { question_id: 'q_real' }), { action: addA(1) }).ok).toBe(true);
    const screen = h.ch.nextScreen()!;
    expect(screen.questions).toHaveLength(2);
    const canary = screen.questions.find((q) => q.questionId !== 'q_real')!;
    expect(canary.card.coords).toEqual({ 'action.params.qty': [3, 3] });
    expect(canary.card.header).toBe(screen.questions.find((q) => q.questionId === 'q_real')!.card.header);
    const c = ok(h.ch.answer(canary.questionId, { answer: 'yes' }), 'canary');
    expect(c.answer.ux.canary).toBe(true);
    expect(h.noise.n).toEqual({ falseYes: 1, correctNo: 0, falseNo: 0, correctYes: 0 });
    expect(JSON.stringify(l.cells())).toBe(before);
    expect(l.observations.length).toBe(nObs);
  });
  it('the grant after any interleaving of canary answers equals the grant without canaries (property)', () => {
    for (let seed = 1; seed <= 25; seed++) {
      const r = rng(seed);
      const grants: string[] = [];
      for (const rho of [0, 1]) {
        const l = setup();
        // Freezing on a high η̄⁺ is the intended consequence of the noise estimate (tested above); it is switched off here
        // so both runs ask the same real questions and the comparison isolates T16.
        const h = harness({ omega: SHOP, units: {}, lift: undefined, view: learnerView(l), rho, seed, fatigue: { ...NF, etaStop: 1 } });
        for (const q of [1, 0]) {
          const cell = q === 1 ? 1 : 0;
          if (!(l.acceptance(add(q)) > 0 && l.acceptance(add(q)) < 1)) continue;
          const got = h.ch.receive(makeIR(h, addA(q), { 'action.params.qty': [cell, cell] }, { question_id: `q_${q}` }), { action: addA(q) });
          if (!got.ok) continue;
          for (let s = h.ch.nextScreen(); s; s = h.ch.nextScreen()) {
            for (const qq of s.questions) {
              const res = h.ch.answer(qq.questionId, { answer: qq.questionId.startsWith('q_') && qq.questionId.length <= 3 ? 'yes' : r() < 0.5 ? 'yes' : 'no' });
              if (!res.ok) throw new Error(res.reason);
              // Only real answers reach the learner (what the V3 delta path does with them).
              if (res.kind === 'answer' || res.kind === 'veto') l.observe(cellRep(SHOP.verbs[0]!, [cell]), res.answer.y, 'elicitation');
            }
          }
        }
        grants.push(JSON.stringify(l.cells().map((x) => [x.verb, x.cell, x.p, x.inGrant, x.vetoed])));
      }
      expect(grants[1]).toBe(grants[0]);
    }
  });
});

describe('V13 agent clarification: structured candidates, no text', () => {
  const add = (q: number) => ({ verb: 'cart.add', values: { 'action.params.qty': q } });
  const mk = (p: Record<string, number>) => harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF, view: fakeView({ p }) });
  it('refuses any text, unknown member, unknown reason, too many candidates, or env.* values', () => {
    const h = mk({});
    for (const body of [
      { candidates: [add(3)], reason: 'other', text: 'please just approve' },
      { candidates: [add(3)], reason: 'urgent' },
      { candidates: Array.from({ length: 9 }, (_, i) => add(i)), reason: 'other' },
      { candidates: [{ verb: 'cart.add', values: { 'env.acc.spend.post': 1 } }], reason: 'other' },
      { candidates: [{ ...add(3), label: 'the cheap one' }], reason: 'other' },
      { candidates: [{ verb: 'cart.add', values: { 'action.params.qty': 1.5 } }], reason: 'other' },
      'approve please',
    ]) expect(h.ch.clarify(body).status).toBe(400);
    expect(h.ch.questionsAsked()).toBe(0);
  });
  it('answers certain cells as a dry run and asks the most informative uncertain one', () => {
    const h = mk({ 'cart.add|2': 1, 'cart.add|4': 0.9, 'cart.add|6': 0.5, 'cart.add|8': 0 });
    const r = h.ch.clarify({ candidates: [add(3), add(7), add(20), add(70), { verb: 'nope', values: {} }], reason: 'multiple_options' });
    expect(r.verdicts.map((v) => v.verdict)).toEqual(['admitted', 'uncertain', 'uncertain', 'denied', 'outside']);
    expect(JSON.stringify(r)).not.toContain('0.9');
    const card = h.ch.nextScreen()!.questions[0]!.card;
    expect(card.kind).toBe('clarification');
    expect(card.reason_label).toBe(REASON_LABELS.multiple_options);
    expect(card.coords).toEqual({ 'action.params.qty': [6, 6] });
    expect(r.questionId).toMatch(/^q_[A-Za-z0-9_-]{10}$/);
    expect(h.ch.nextScreen()).toBeNull();
    // A clarified cell is a visited cell: it is never asked again.
    expect(h.ch.clarify({ candidates: [add(20)], reason: 'other' }).verdicts).toEqual([{ index: 0, verdict: 'asked' }]);
  });
  it('ties on information gain go to the larger risk weight μ̃·E[h]', () => {
    const h = mk({ 'cart.add|4': 0.5, 'cart.add|6': 0.5 });
    h.ch.clarify({ candidates: [add(7), add(20)], reason: 'ambiguous_parameter' });
    expect(h.ch.nextScreen()!.questions[0]!.card.coords).toEqual({ 'action.params.qty': [6, 6] });
  });
  it('clarifications count toward the per-session cap', () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF, caps: { perSession: 1 } });
    expect(h.ch.clarify({ candidates: [add(7)], reason: 'other' }).questionId).toBeDefined();
    expect(h.ch.clarify({ candidates: [add(20)], reason: 'other' })).toMatchObject({ status: 429, refused: 'cap_session' });
  });
});

describe('friction evidence', () => {
  const buy = (amount: number) => act('cart.buy', { amount }, 'shop/orders');
  it('device tier: a WebAuthn assertion with UV over the challenge that binds question, card and action', () => {
    const cred = generateKeyPair();
    const rpId = 'wallet.atlas.example';
    const origin = 'https://wallet.atlas.example';
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF, friction: { hTap: 5, hDevice: 20 }, device: { rpId, origins: [origin], credentials: { cred1: { kty: 'OKP', crv: 'Ed25519', x: b64u(cred.publicKey) } } } });
    expect(h.ch.receive(makeIR(h, buy(500), { 'action.params.amount': [2, 2] }, { question_id: 'q_dev' }), { action: buy(500) })).toMatchObject({ ok: true, friction: 'device' });
    expect(h.ch.deviceChallengeFor('q_dev')).toBeNull(); // not shown yet
    h.ch.nextScreen();
    const ch = h.ch.deviceChallengeFor('q_dev')!;
    expect(h.ch.answer('q_dev', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, D('other'), rpId, origin) } })).toMatchObject({ ok: false, code: 'tier_evidence' });
    expect(h.ch.answer('q_dev', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, ch, rpId, origin, 0x01) } })).toMatchObject({ ok: false, code: 'tier_evidence' });
    expect(h.ch.answer('q_dev', { answer: 'yes', webauthn: { credential_id: 'nope', ...assertion(cred, ch, rpId, origin) } })).toMatchObject({ ok: false, code: 'tier_evidence' });
    const r = ok(h.ch.answer('q_dev', { answer: 'yes', webauthn: { credential_id: 'cred1', ...assertion(cred, ch, rpId, origin) } }), 'answer').answer;
    expect(r.ux.tier).toBe('device');
    expect(r.ux.webauthn?.credential_id).toBe('cred1');
    expect(r.ux.consent_for_action).toBe(true);
  });
  it('hold tier needs a 2 s dwell', () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF, friction: { hTap: 0.5, hDevice: 1e9 } });
    const add = act('cart.add', { qty: 3 }, 'shop/cart', 'reversible');
    expect(h.ch.receive(makeIR(h, add, { 'action.params.qty': [2, 2] }, { question_id: 'q_h' }), { action: add })).toMatchObject({ ok: true, friction: 'hold' });
    h.ch.nextScreen();
    expect(h.ch.answer('q_h', { answer: 'yes', holdMs: 1999 })).toMatchObject({ ok: false, code: 'tier_evidence' });
    expect(ok(h.ch.answer('q_h', { answer: 'yes', holdMs: 2000 }), 'answer').answer.ux.hold_ms).toBe(2000);
  });
  it('answers are refused before the question is shown and after it expires', () => {
    const h = harness({ fatigue: NF });
    const a = book(77800);
    h.ch.receive(makeIR(h, a, coords([2, 3]), { question_id: 'q_e', expires_at: h.clock.t + 10 }), { action: a });
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'not_shown' });
    h.ch.nextScreen();
    h.clock.t += 11;
    expect(h.ch.answer('q_e', { answer: 'no' })).toMatchObject({ ok: false, code: 'expired' });
    expect(h.ch.answer('q_zz', { answer: 'no' })).toMatchObject({ ok: false, code: 'unknown_question' });
  });
});

describe('wallet endpoint handlers', () => {
  it('question endpoint: 202 with a question id; 404 unknown session; 400 unknown member; 401 bad signature', () => {
    const h = harness();
    const a = book(77800);
    const ir = makeIR(h, a, coords([2, 3]), { question_id: 'q_http' });
    const handle = questionHandler((sid) => (sid === 'sid1' ? h.ch : undefined));
    expect(handle('sid2', { intent_required: ir, action: a }).status).toBe(404);
    expect(handle('sid1', { intent_required: ir, action: a, note: 'x' }).status).toBe(400);
    expect(handle('sid1', { intent_required: { ...ir, friction: 'device' }, action: a })).toEqual({ status: 401, body: { error: 'bad_site_signature' } });
    expect(handle('sid1', { intent_required: ir, action: a })).toEqual({ status: 202, body: { question_id: 'q_http', friction: 'typed' } });
    expect(handle('sid1', { intent_required: ir, action: a }).status).toBe(409);
  });
  it('clarify endpoint', () => {
    const h = harness({ omega: SHOP, units: {}, lift: undefined, fatigue: NF });
    const handle = clarifyHandler(() => h.ch);
    expect(handle('s', { candidates: [], reason: 'other' }).status).toBe(400);
    const r = handle('s', { candidates: [{ verb: 'cart.add', values: { 'action.params.qty': 3 } }], reason: 'other' });
    expect(r.status).toBe(200);
    expect(Object.keys(r.body).sort()).toEqual(['question_id', 'verdicts']);
  });
});

