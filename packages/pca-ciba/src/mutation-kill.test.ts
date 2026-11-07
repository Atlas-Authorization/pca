/** Mutation-kill tests for the CIBA binding-message builder, request validation and broker. Exact strings, exact boundaries. */
import { describe, expect, it } from 'vitest';
import type { RiskPolicy, StepUpRequest, TrustBudget } from '@atlasauth/pca';
import { cibaDecisionToCosign, requiresCiba, toCibaAuthRequest } from './index';
import { createCibaBroker } from './testing';

const su = (o: Record<string, unknown> = {}): StepUpRequest =>
  ({ id: 'su-1', verb: 'stripe.payout', resource: 'acct:1', tier: 3, reason: 'r', goalCommit: '', r: 0.5, ...o }) as unknown as StepUpRequest;
const bm = (o: Record<string, unknown> = {}, opts: Record<string, unknown> = {}) => toCibaAuthRequest(su(o), opts).binding_message;
const thrown = (f: () => unknown): Error => {
  try {
    f();
  } catch (e) {
    return e as Error;
  }
  throw new Error('no throw');
};

describe('toCibaAuthRequest fields', () => {
  it('defaults', () => {
    const r = toCibaAuthRequest(su());
    expect(r).toStrictEqual({
      auth_req_id: r.auth_req_id,
      binding_message: 'Approve stripe.payout on acct:1',
      scope: 'openid urn:atlas:pca:stepup:stripe.payout',
      requested_expiry: 300,
      interval: 5,
      stepUpId: 'su-1',
      tier: 3,
    });
    expect(r.auth_req_id).toMatch(/^[A-Za-z0-9._-]{22,}$/);
    expect(toCibaAuthRequest(su()).auth_req_id).toBe(r.auth_req_id); // deterministic per step-up id
    expect(toCibaAuthRequest(su({ id: 'su-2' })).auth_req_id).not.toBe(r.auth_req_id);
  });
  it('options are carried', () => {
    const r = toCibaAuthRequest(su({ tier: 2 }), { expiresInSec: 60, interval: 7, loginHint: 'a@b', stepUpScope: false, authReqId: 'x'.repeat(22) });
    expect(r).toStrictEqual({ auth_req_id: 'x'.repeat(22), binding_message: r.binding_message, scope: 'openid', requested_expiry: 60, interval: 7, login_hint: 'a@b', stepUpId: 'su-1', tier: 2 });
    expect(toCibaAuthRequest(su(), { stepUpScope: true }).scope).toBe('openid urn:atlas:pca:stepup:stripe.payout');
  });
  it('expiry and interval must be positive safe integers', () => {
    for (const v of [0, -1, 1.5, NaN, Infinity, 2 ** 53]) {
      expect(thrown(() => toCibaAuthRequest(su(), { expiresInSec: v })).message).toBe(`ciba: requested_expiry must be a positive integer number of seconds, got ${String(v)}`);
      expect(thrown(() => toCibaAuthRequest(su(), { interval: v })).message).toBe(`ciba: interval must be a positive integer number of seconds, got ${String(v)}`);
    }
    expect(toCibaAuthRequest(su(), { expiresInSec: 1, interval: 1 }).requested_expiry).toBe(1);
  });
  it('the verb must be a valid OAuth scope token', () => {
    for (const verb of ['a b', 'a"b', 'a\\b', 'aé']) expect(thrown(() => toCibaAuthRequest(su({ verb }))).message).toBe('ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)');
    expect(toCibaAuthRequest(su({ verb: 'a.b:c' })).scope).toBe('openid urn:atlas:pca:stepup:a.b:c');
    // a valid scope-token that is not a plain identifier is refused by the renderer (R3-05)
    expect(thrown(() => toCibaAuthRequest(su({ verb: 'a!#[]~' }))).message).toMatch(/plain identifier/);
  });
  it('auth_req_id: charset and 22..1024 length', () => {
    const msg = 'ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)';
    for (const id of ['x'.repeat(21), 'x'.repeat(1025), `${'x'.repeat(21)} `, `${'x'.repeat(21)}+`, '']) expect(thrown(() => toCibaAuthRequest(su(), { authReqId: id })).message).toBe(msg);
    expect(toCibaAuthRequest(su(), { authReqId: 'x'.repeat(22) }).auth_req_id).toHaveLength(22);
    expect(toCibaAuthRequest(su(), { authReqId: 'a._-'.repeat(256) }).auth_req_id).toHaveLength(1024);
  });
  it('bindingMessage.maxChars must be a positive integer', () => {
    for (const v of [0, -1, 1.5, NaN]) expect(thrown(() => toCibaAuthRequest(su(), { bindingMessage: { maxChars: v } })).message).toBe('ciba: bindingMessage.maxChars must be a positive integer');
  });
});

describe('binding message text', () => {
  it('amount fragments: amount, currency and payee are ALWAYS shown, in fixed order', () => {
    const o = (p: Record<string, unknown>) => ({ params: p });
    expect(bm(o({ amount: 80, currency: 'USD', payee: 'bob' }))).toBe('Approve stripe.payout 80 USD to "bob" on acct:1');
    expect(bm(o({ amount: '12.50', currency: 'usd', to: 'bob' }))).toBe('Approve stripe.payout 12.50 USD to "bob" on acct:1');
    expect(bm(o({ amount: 0, currency: 'eur', recipient: 'Acme GmbH' }))).toBe('Approve stripe.payout 0 EUR to "Acme GmbH" on acct:1');
    // key order in params does not change the message
    expect(bm(o({ payee: 'bob', currency: 'EUR', amount: 5 }))).toBe(bm(o({ amount: 5, currency: 'EUR', payee: 'bob' })));
    expect(bm(o({ amount: null }))).toBe('Approve stripe.payout on acct:1');
    expect(bm(o({ amount: undefined, other: undefined }))).toBe('Approve stripe.payout on acct:1');
    expect(bm(o({}))).toBe('Approve stripe.payout on acct:1');
    expect(bm(o({ payee: 'bob' }))).toBe('Approve stripe.payout to "bob" on acct:1');
  });
  it('R3-05: any params field the renderer does not display is refused (the PoC: amt / total / unknown keys)', () => {
    const ok = { amount: 1, currency: 'USD', payee: 'acct:bob' };
    for (const extra of [{ amt: 1_000_000 }, { total: 1 }, { quantity: 9 }, { limit: 1 }, { memo: 'x' }, { nested: { amount: 1 } }, { fee: 3 }]) {
      expect(thrown(() => bm({ params: { ...ok, ...extra } })).message, JSON.stringify(extra)).toMatch(/not displayed in the approval message/);
    }
    expect(thrown(() => bm({ params: { ...ok, to: 'attacker' } })).message).toMatch(/more than one payee/);
    expect(thrown(() => bm({ params: { amount: 1, currency: 'USD' } })).message).toMatch(/needs a payee/);
    expect(thrown(() => bm({ params: { amount: 1, payee: 'bob' } })).message).toMatch(/3-letter currency/);
    expect(thrown(() => bm({ params: { currency: 'USD' } })).message).toMatch(/currency without an amount/);
    // tokenOnly applies the same rules
    expect(thrown(() => bm({ params: { ...ok, total: 1_000_000 } }, { bindingMessage: { tokenOnly: true, maxChars: 80 } })).message).toMatch(/not displayed/);
    expect(thrown(() => bm({ params: { amount: 1, currency: 'USD' } }, { bindingMessage: { tokenOnly: true, maxChars: 80 } })).message).toMatch(/needs a payee/);
  });
  it.each([-5, '-5', '5e3', '05', '1,000', 'abc', NaN, Infinity, true, {}])('rejects a non-plain amount %j', (amount) => {
    expect(thrown(() => bm({ params: { amount, currency: 'USD', payee: 'bob' } })).message).toMatch(/plain non-negative decimal amount/);
  });
  it('rejects a bad currency with exact messages', () => {
    for (const currency of ['US', 5, 'USDX', undefined]) {
      expect(thrown(() => bm({ params: { amount: 5, currency, payee: 'bob' } })).message).toBe('ciba: the binding message needs a 3-letter currency code next to the amount');
    }
  });
  it('payee: control, bidi and invisible characters, quotes and over-long values are refused, never altered', () => {
    const p = (payee: unknown) => bm({ params: { amount: 1, currency: 'USD', payee } });
    for (const bad of ['a\u202eb', 'a\u0000b', 'a\nb', 'a\u200bb', 'a\u2028b', 'a\u2066b', 'a"b', 'a\\b', ' a', 'a ', 'a  b', '', 'x'.repeat(65), { n: 1 }, ['a'], 5]) {
      expect(thrown(() => p(bad)).message, JSON.stringify(bad)).toMatch(/payee/);
    }
    expect(p('x'.repeat(64))).toContain(`"${'x'.repeat(64)}"`);
    expect(thrown(() => p('pay because you asked x to y')).message).toMatch(/explanation clause/);
    expect(p('Ünïcode Ltd')).toContain('"Ünïcode Ltd"');
  });
  it('verb and resource must be plain identifiers; free text, controls, bidi and forged clauses are refused', () => {
    for (const resource of ['a\u0000b', 'a b', "it's", 'x"y', 'a\u202eb', 'a\nb', '', ' x', 'x'.repeat(65), 'Because you asked', '-lead']) {
      expect(thrown(() => bm({ resource })).message, JSON.stringify(resource)).toMatch(/plain identifier/);
    }
    for (const verb of ['a b', "it's", '', 'a\u202eb']) expect(thrown(() => bm({ verb })).message).toMatch(/scope-token|plain identifier/);
    expect(bm({ resource: 'acct:1/sub#2@x+y_z.w-1' })).toBe('Approve stripe.payout on acct:1/sub#2@x+y_z.w-1');
  });
  it('maxChars: exact fit passes, one over refuses with the counts', () => {
    const head = 'Approve stripe.payout on acct:1';
    expect(bm({}, { bindingMessage: { maxChars: head.length } })).toBe(head);
    expect(thrown(() => bm({}, { bindingMessage: { maxChars: head.length - 1 } })).message).toBe(
      `ciba: the binding message needs ${head.length} characters but bindingMessage.maxChars is ${head.length - 1}; refusing to truncate what the person approves`,
    );
  });
  it('goal clause: plain goal, goal commit fallback, clipping, sanitising, room rules', () => {
    const head = 'Approve stripe.payout on acct:1';
    const pre = " — because you asked your agent to '";
    expect(bm({ goal: 'pay refunds' })).toBe(`${head}${pre}pay refunds'`);
    expect(bm({ goal: '  it’s  "q"\n' })).toBe(`${head}${pre}it′s "q"'`);
    expect(bm({ goal: '', goalCommit: 'abcdefghijklmnop' })).toBe(`${head}${pre}goal abcdefghij…'`);
    expect(bm({ goal: ' \u0000 ', goalCommit: 'abcdefghijklmnop' })).toBe(`${head}${pre}goal abcdefghij…'`);
    expect(bm({ goalCommit: 'abc' })).toBe(`${head}${pre}goal abc…'`);
    expect(bm({ goalCommit: '' })).toBe(head);
    expect(bm({ goal: ' ', goalCommit: '' })).toBe(head);
    expect(bm({ goal: 'g'.repeat(100) })).toBe(`${head}${pre}${'g'.repeat(100)}'`);
    expect(bm({ goal: 'g'.repeat(101) })).toBe(`${head}${pre}${'g'.repeat(99)}…'`);
    expect(bm({ goal: 'x' }, { actsFor: 'support-bot' })).toBe(`${head} — because you asked support-bot to 'x'`);
    expect(bm({ goal: 'x' }, { actsFor: '   ' })).toBe(`${head}${pre}x'`);
    expect(bm({ goal: 'x' }, { actsFor: 'n'.repeat(41) })).toBe(`${head} — because you asked ${'n'.repeat(39)}… to 'x'`);
    expect(bm({ goal: 'x' }, { actsFor: 'n'.repeat(40) })).toBe(`${head} — because you asked ${'n'.repeat(40)} to 'x'`);
    // room arithmetic: the closing quote counts
    const full = `${head}${pre}goalgoal'`;
    expect(bm({ goal: 'goalgoal' }, { bindingMessage: { maxChars: full.length } })).toBe(full);
    // one char short of the whole goal: clipped to the room (7 chars + ellipsis = room 7... room>=8 required)
    const prefixLen = Array.from(head + pre).length;
    const tight = prefixLen + 8 + 1;
    expect(bm({ goal: 'g'.repeat(20) }, { bindingMessage: { maxChars: tight } })).toBe(`${head}${pre}${'g'.repeat(7)}…'`);
    expect(Array.from(bm({ goal: 'g'.repeat(20) }, { bindingMessage: { maxChars: tight } })).length).toBe(tight);
    expect(bm({ goal: 'g'.repeat(20) }, { bindingMessage: { maxChars: tight - 1 } })).toBe(head);
    expect(bm({ goal: 'g'.repeat(8) }, { bindingMessage: { maxChars: tight } })).toBe(`${head}${pre}${'g'.repeat(8)}'`);
  });
  it('clip counts code points, not UTF-16 units', () => {
    const goal = '😀'.repeat(101);
    expect(bm({ goal })).toBe(`Approve stripe.payout on acct:1 — because you asked your agent to '${'😀'.repeat(99)}…'`);
  });
});

describe('tokenOnly binding message', () => {
  const t = (o: Record<string, unknown>, max?: number) => bm(o, { bindingMessage: { tokenOnly: true, ...(max === undefined ? {} : { maxChars: max }) } });
  it('joins verb, amount, currency, payee and resource with hyphens in fixed order', () => {
    expect(t({})).toBe('Approve-stripe.payout-acct-1');
    expect(t({ params: { amount: 80, currency: 'USD', payee: 'bob' } }, 80)).toBe('Approve-stripe.payout-80-USD-to-bob-acct-1');
    expect(t({ params: { amount: 80, currency: 'eur', to: 'acct:bob' } }, 80)).toBe('Approve-stripe.payout-80-EUR-to-acct-bob-acct-1');
    expect(t({ params: { amount: null } })).toBe('Approve-stripe.payout-acct-1');
    expect(t({ verb: 'a.b', resource: 'x:y' })).toBe('Approve-a.b-x-y');
  });
  it('the default limit is 50, an explicit one is honoured; exact fit passes', () => {
    const s = 'Approve-stripe.payout-acct-1';
    expect(t({}, s.length)).toBe(s);
    expect(thrown(() => t({}, s.length - 1)).message).toBe(
      `ciba: the binding message needs ${s.length} characters but bindingMessage.maxChars is ${s.length - 1}; refusing to truncate what the person approves`,
    );
    const long = { resource: 'r'.repeat(40) };
    expect(thrown(() => t(long)).message).toContain('bindingMessage.maxChars is 50');
    expect(t({ resource: 'r'.repeat(50 - 'Approve-stripe.payout-'.length) })).toHaveLength(50);
  });
  it('rejections', () => {
    const amt = 'ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)';
    for (const amount of [-5, NaN, 1e21, '05']) expect(thrown(() => t({ params: { amount, currency: 'USD', payee: 'b' } }, 80)).message).toBe(amt);
    expect(thrown(() => t({ params: { amount: 5, currency: 'US', payee: 'b' } })).message).toMatch(/3-letter currency/);
    expect(thrown(() => t({ params: { amount: 5, currency: undefined, payee: 'b' } })).message).toMatch(/3-letter currency/);
    expect(thrown(() => t({ params: { amount: 5, currency: 'USD', payee: 'bøb' } }, 80)).message).toMatch(/ASCII payee/);
    expect(thrown(() => t({ params: { amount: 5, currency: 'USD', payee: '...' } }, 80)).message).toMatch(/cannot represent/);
    expect(thrown(() => t({ verb: '!!!' })).message).toMatch(/plain identifier/);
    expect(thrown(() => t({ resource: '...' })).message).toMatch(/plain identifier/);
  });
});

describe('broker', () => {
  const mk = () => {
    let now = 1_000_000;
    const completed: unknown[] = [];
    const b = createCibaBroker({ now: () => now, onComplete: (s) => completed.push(s) });
    return { b, completed, tick: (ms: number) => (now += ms), set: (t: number) => (now = t) };
  };
  it('start is idempotent while live, new once expired/denied; fields set from the request', () => {
    const { b, tick } = mk();
    const r1 = b.start(su(), { interval: 5, expiresInSec: 100 });
    expect(b.start(su())).toBe(r1);
    expect(b.get(r1.auth_req_id)).toMatchObject({ status: 'pending', createdAt: 1_000_000, expiresAt: 1_100_000, auth_req_id: r1.auth_req_id });
    tick(99_999);
    expect(b.start(su())).toBe(r1);
    tick(1);
    const r2 = b.start(su());
    expect(r2).not.toBe(r1);
    expect(r2.auth_req_id).not.toBe(r1.auth_req_id);
    b.resolve(r2.auth_req_id, 'deny', 'bob');
    expect(b.start(su())).not.toBe(r2);
  });
  it('an approved step-up is returned again; a different step-up is separate', () => {
    const { b } = mk();
    const r = b.start(su());
    b.resolve(r.auth_req_id, 'approve', 'alice');
    expect(b.start(su())).toBe(r);
    expect(b.start(su({ id: 'other' }))).not.toBe(r);
  });
  it('poll and get', () => {
    const { b, tick } = mk();
    const r = b.start(su(), { expiresInSec: 10 });
    expect(b.poll(r.auth_req_id)).toStrictEqual({ status: 'pending' });
    expect(thrown(() => b.poll('nope')).message).toBe('ciba: unknown auth_req_id nope');
    expect(b.get('nope')).toBeUndefined();
    tick(9_999);
    expect(b.poll(r.auth_req_id).status).toBe('pending');
    tick(1);
    expect(b.poll(r.auth_req_id).status).toBe('expired');
    expect(b.get(r.auth_req_id)?.status).toBe('expired');
    expect('decidedBy' in (b.get(r.auth_req_id) as object)).toBe(false);
  });
  it('resolve records the decision once, fires onComplete, refuses unknown / finished / expired', () => {
    const { b, completed, tick } = mk();
    const r = b.start(su(), { expiresInSec: 10 });
    expect(thrown(() => b.resolve('nope', 'approve', 'x')).message).toBe('ciba: unknown auth_req_id nope');
    tick(500);
    const snap = b.resolve(r.auth_req_id, 'approve', 'alice');
    expect(snap).toMatchObject({ status: 'approved', decidedBy: 'alice', decidedAt: 1_000_500 });
    expect(completed).toEqual([snap]);
    expect(thrown(() => b.resolve(r.auth_req_id, 'deny', 'eve')).message).toBe(`ciba: cannot resolve ${r.auth_req_id} — already approved`);
    expect(b.get(r.auth_req_id)).toMatchObject({ status: 'approved', decidedBy: 'alice' });
    const r2 = b.start(su({ id: 'x2' }), { expiresInSec: 1 });
    tick(1000);
    expect(thrown(() => b.resolve(r2.auth_req_id, 'approve', 'a')).message).toBe(`ciba: cannot resolve ${r2.auth_req_id} — already expired`);
    const r3 = b.start(su({ id: 'x3' }));
    expect(b.resolve(r3.auth_req_id, 'deny', 'd').status).toBe('denied');
    const nocb = createCibaBroker({ now: () => 5 });
    expect(nocb.resolve(nocb.start(su()).auth_req_id, 'approve', 'z').status).toBe('approved');
  });
  it('token endpoint semantics: pending, slow_down (+5 s), denied, expired, single-use approved, unknown', () => {
    const { b, tick } = mk();
    expect(b.token('nope')).toStrictEqual({ ok: false, error: 'invalid_grant', interval: 5 });
    const r = b.start(su(), { interval: 5, expiresInSec: 100 });
    expect(b.token(r.auth_req_id)).toStrictEqual({ ok: false, error: 'authorization_pending', interval: 5 });
    tick(4_999);
    expect(b.token(r.auth_req_id)).toStrictEqual({ ok: false, error: 'slow_down', interval: 10 });
    tick(9_999); // polling too soon again measured from the last poll: still slow_down
    expect(b.token(r.auth_req_id)).toStrictEqual({ ok: false, error: 'slow_down', interval: 15 });
    tick(15_000); // exactly the interval: allowed
    expect(b.token(r.auth_req_id)).toStrictEqual({ ok: false, error: 'authorization_pending', interval: 15 });
    b.resolve(r.auth_req_id, 'approve', 'alice');
    tick(15_000);
    const ok = b.token(r.auth_req_id);
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.session).toMatchObject({ status: 'approved', decidedBy: 'alice', auth_req_id: r.auth_req_id });
    expect(b.token(r.auth_req_id)).toStrictEqual({ ok: false, error: 'invalid_grant', interval: 15 });
    const d = b.start(su({ id: 'd' }), { interval: 1 });
    b.resolve(d.auth_req_id, 'deny', 'n');
    expect(b.token(d.auth_req_id)).toStrictEqual({ ok: false, error: 'access_denied', interval: 1 });
    const e = b.start(su({ id: 'e' }), { interval: 1, expiresInSec: 1 });
    tick(1000);
    expect(b.token(e.auth_req_id)).toStrictEqual({ ok: false, error: 'expired_token', interval: 1 });
  });
});

describe('requiresCiba / cibaDecisionToCosign', () => {
  const policy = { theta1: 0.3, theta2: 0.6, bMax: 10, rho: 1, kappa: 100 } as unknown as RiskPolicy;
  const budget = { B: 2, t: 0 } as unknown as TrustBudget;
  it('requires CIBA only for a tier-3 step-up review', () => {
    expect(requiresCiba({ kind: 'step_up', request: su({ tier: 3 }) } as never)).toBe(true);
    expect(requiresCiba({ kind: 'step_up', request: su({ tier: 2 }) } as never)).toBe(false);
    expect(requiresCiba({ kind: 'auto' } as never)).toBe(false);
    expect(requiresCiba({ kind: 'deny', request: su({ tier: 3 }) } as never)).toBe(false);
  });
  it('approve recharges the budget (partial or full); deny leaves it untouched', () => {
    const deny = cibaDecisionToCosign('deny', budget, policy, 5);
    expect(deny).toStrictEqual({ budget, cosigned: false });
    expect(deny.budget).toBe(budget);
    const part = cibaDecisionToCosign('approve', budget, policy, 5);
    const full = cibaDecisionToCosign('approve', budget, policy, 5, { full: true });
    expect(part.cosigned).toBe(true);
    expect(full.cosigned).toBe(true);
    expect(full.budget).not.toStrictEqual(part.budget);
    expect(full.budget.B).toBe(10);
    expect(part.budget.B).toBeGreaterThanOrEqual(budget.B);
    expect(part.budget).not.toBe(budget);
  });
});

describe('remaining binding-message boundaries', () => {
  it('exotic amount and currency values are refused (both renderers)', () => {
    for (const o of [{ tokenOnly: true, maxChars: 80 }, undefined]) {
      const opts = o === undefined ? {} : { bindingMessage: o };
      expect(thrown(() => bm({ params: { amount: { toString: () => '5' }, currency: 'USD', payee: 'b' } }, opts)).message).toMatch(/plain non-negative/);
      expect(thrown(() => bm({ params: { amount: ['5'], currency: 'USD', payee: 'b' } }, opts)).message).toMatch(/plain non-negative/);
      expect(thrown(() => bm({ params: { amount: 5n, currency: 'USD', payee: 'b' } }, opts)).message).toMatch(/plain non-negative/);
      expect(thrown(() => bm({ params: { amount: 5, currency: ['EUR'], payee: 'b' } }, opts)).message).toMatch(/3-letter currency/);
    }
  });
  it('maxChars of exactly 1 is a valid setting (it then fails on length, not on validation)', () => {
    expect(thrown(() => bm({}, { bindingMessage: { maxChars: 1 } })).message).toMatch(/needs \d+ characters but bindingMessage.maxChars is 1;/);
  });
  it('a goal that exactly fills a small room is kept whole; one char less drops the goal', () => {
    const head = 'Approve stripe.payout on acct:1';
    const pre = " — because you asked your agent to '";
    const limit = Array.from(head + pre).length + 3 + 1;
    expect(bm({ goal: 'abc' }, { bindingMessage: { maxChars: limit } })).toBe(`${head}${pre}abc'`);
    expect(bm({ goal: 'abc' }, { bindingMessage: { maxChars: limit - 1 } })).toBe(head);
  });
  it('tokenOnly collapses and trims punctuation runs', () => {
    const t = (o: Record<string, unknown>) => bm(o, { bindingMessage: { tokenOnly: true } });
    expect(t({ resource: 'x--y' })).toBe('Approve-stripe.payout-x-y');
    expect(t({ resource: 'x:::y' })).toBe('Approve-stripe.payout-x-y');
    expect(t({ resource: 'x..' })).toBe('Approve-stripe.payout-x');
    expect(t({ resource: 'x:/#' })).toBe('Approve-stripe.payout-x');
    // non-identifier resources never reach the tokeniser
    for (const resource of ['x   y', 'xééy', '..x', '-.-x.-.']) expect(thrown(() => t({ resource })).message).toMatch(/plain identifier/);
    expect(t({ resource: 'a-b.c_d' })).toBe('Approve-stripe.payout-a-b.c_d');
  });
  it('the derived auth_req_id is pinned (domain-separated hash of the step-up id)', () => {
    expect(toCibaAuthRequest(su()).auth_req_id).toBe(PINNED_ID);
  });
  it('pending sessions carry no decision fields', () => {
    const b = createCibaBroker({ now: () => 5 });
    const r = b.start(su());
    const s = b.get(r.auth_req_id) as object;
    expect('decidedAt' in s).toBe(false);
    expect('decidedBy' in s).toBe(false);
  });
});
const PINNED_ID = 'iESR0p-v_edt921OLtfu4WSDOBgIHAugkg7APz8w4_w';

describe('structured-action renderer (R3-05) boundaries', () => {
  it('goal text: control and format characters become spaces, then whitespace collapses', () => {
    const g = (goal: string) => bm({ goal });
    expect(g('pay\u0000refunds')).toContain("to 'pay refunds'");
    expect(g('pay​refunds')).toContain("to 'pay refunds'");
    expect(g('pay refunds')).toContain("to 'pay refunds'");
    expect(g('a\t\n  b')).toContain("to 'a b'");
  });
  it('a verb or resource that is not a string is refused even when its string form would pass', () => {
    const msg = (what: string) =>
      `ciba: the step-up ${what} must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message`;
    expect(thrown(() => bm({ verb: ['stripe.payout'] })).message).toBe(msg('verb'));
    expect(thrown(() => bm({ resource: ['acct:1'] })).message).toBe(msg('resource'));
    expect(thrown(() => bm({ resource: 'a b' })).message).toBe(msg('resource'));
    expect(thrown(() => bm({ resource: '-acct' })).message).toBe(msg('resource'));
    expect(thrown(() => bm({ resource: 'a'.repeat(65) })).message).toBe(msg('resource'));
    expect(bm({ resource: 'a'.repeat(64) })).toContain(`on ${'a'.repeat(64)}`);
    expect(thrown(() => bm({ verb: 'v'.repeat(65) })).message).toBe(msg('verb'));
  });
  it('params must be a plain object; undisplayed and duplicate payee fields are named in the refusal', () => {
    for (const params of ['x', 5, true, [], ['a']]) expect(thrown(() => bm({ params })).message).toBe('ciba: step-up params must be an object');
    expect(bm({ params: null })).toBe('Approve stripe.payout on acct:1');
    expect(thrown(() => bm({ params: { memo: 'x', note: 'y', amount: undefined } })).message).toBe(
      'ciba: step-up params field(s) memo, note are not displayed in the approval message (displayable: amount, currency, payee/to/recipient/beneficiary/destination); refusing so the person never approves a hidden field',
    );
    expect(bm({ params: { memo: undefined } })).toBe('Approve stripe.payout on acct:1');
    expect(thrown(() => bm({ params: { payee: 'a', to: 'b', recipient: 'c' } })).message).toBe(
      'ciba: more than one payee field (payee, to, recipient) in params; the approver would see only one',
    );
    expect(bm({ params: { payee: 'a', to: null, recipient: undefined } })).toBe('Approve stripe.payout to "a" on acct:1');
  });
  it('tokenOnly: leading and trailing punctuation of the payee is trimmed (all of it)', () => {
    const t = (payee: string) => bm({ params: { payee } }, { bindingMessage: { tokenOnly: true } });
    expect(t('..x')).toBe('Approve-stripe.payout-to-x-acct:1'.replace('acct:1', 'acct-1'));
    expect(t('x..')).toBe('Approve-stripe.payout-to-x-acct-1');
    expect(t('--.-x-.--')).toBe('Approve-stripe.payout-to-x-acct-1');
  });
});
