/**
 * Adversarial tests: what a malicious agent (holder) or an on-path attacker can do with a valid chain.
 * Every case must be refused.
 */
import { describe, expect, it } from 'vitest';
import {
  b64uDecode,
  checkCheckoutConstraints,
  checkPaymentConstraints,
  hopSdJwt,
  issueOpenCheckoutMandate,
  issueOpenPaymentMandate,
  parseSdJwtHop,
  presentClosedCheckout,
  signJwtEs256,
  splitChain,
  verifyCheckoutChain,
  verifyDelegationChain,
  type OpenCheckoutMandateClaims,
  type OpenPaymentMandateClaims,
  type PaymentMandateClaims,
  type UcpCheckout,
} from './index';
import { MERCHANT, NOW_S, makeScenario, purchaseOptions, verifyScenario } from './testkit';

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

describe('exhaustive single-character mutation of a valid purchase', () => {
  const s = makeScenario();
  const baseline = verifyScenario(s);

  it('the unmodified purchase verifies', () => {
    expect(baseline.ok, baseline.ok ? '' : baseline.reason).toBe(true);
  });

  for (const which of ['checkout', 'payment'] as const) {
    it(`no single-character change anywhere in the ${which} chain is accepted`, () => {
      const token = which === 'checkout' ? s.checkoutChain : s.paymentChain;
      let tried = 0;
      for (let i = 0; i < token.length; i++) {
        const c = token[i] as string;
        if (c === '~' || c === '.') continue; // structural separators are covered by the structure tests
        const sub = B64U[(B64U.indexOf(c) + 1) % 64] as string;
        const mutated = token.slice(0, i) + sub + token.slice(i + 1);
        const r = which === 'checkout' ? verifyScenario(s, {}, { checkout: mutated }) : verifyScenario(s, {}, { payment: mutated });
        if (r.ok) throw new Error(`mutation at ${i} (${c} -> ${sub}) was accepted`);
        tried++;
      }
      expect(tried).toBeGreaterThan(1000);
    }, 120_000);
  }

  it('dropping, duplicating or reordering structure is refused', () => {
    const [open, closed] = [splitChain(s.paymentChain)[0] as string, splitChain(s.paymentChain)[1] as string];
    const variants = [
      open, // the closed mandate is missing
      closed, // the open mandate is missing
      `${closed}~${open}`, // reversed
      `${open}~${closed}~${closed}`, // extra hop
      s.paymentChain.replace('~~', '~'), // separator collapsed
      `${s.paymentChain}extra`, // trailing garbage (would be a KB-JWT in RFC 9901 form)
      s.paymentChain.slice(0, -1), // trailing '~' removed
      '',
    ];
    for (const v of variants) expect(verifyScenario(s, {}, { payment: v }).ok, v.slice(0, 40)).toBe(false);
  });
});

describe('a malicious agent cannot widen an open mandate by withholding disclosures', () => {
  const s = makeScenario();

  /** Re-present the closed checkout on top of an open checkout the agent has redacted before signing sd_hash. */
  const redactedOpenCheckout = (drop: (decoded: unknown[]) => boolean): string => {
    const hop = parseSdJwtHop(s.openCheckout);
    const kept = hop.disclosures.filter((d) => !drop(JSON.parse(b64uDecode(d, 'd').toString()) as unknown[]));
    return hopSdJwt({ jwt: hop.jwt, disclosures: kept });
  };

  it('withholding every acceptable_items entry (the SDK reads an empty set as a wildcard) is refused here', () => {
    const open = redactedOpenCheckout((d) => typeof d[1] === 'object' && d[1] !== null && 'title' in (d[1] as object) && !('vct' in (d[1] as object)) && (d[1] as { id: string }).id.startsWith('sku-'));
    // the agent now quotes an item the user never allowed
    const payload = {
      id: 'chk_evil', merchant: MERCHANT, status: 'ready_for_complete', currency: 'USD',
      line_items: [{ id: 'li_1', item: { id: 'forbidden-sku', title: 'Forbidden', price: 2000 }, quantity: 2, totals: [{ type: 'subtotal', amount: 4000 }] }],
      totals: [{ type: 'subtotal', amount: 4000 }, { type: 'total', amount: 4000 }], links: [],
    };
    const jwt = signJwtEs256({ header: { kid: 'merchant-key-1' }, payload: payload as never, privateKey: s.merchantKey.privateKey });
    const chain = presentClosedCheckout({ open, agentKey: s.agent, checkoutJwt: jwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: NOW_S + 5 });
    const o = purchaseOptions(s);
    const r = verifyCheckoutChain(chain, { resolveIssuerKey: o.resolveIssuerKey, resolveMerchantKey: o.resolveMerchantKey, ...o.checkout, now: o.now as number });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/line items do not satisfy|violated/);
  });

  it('withholding the allowed-merchants entries leaves an empty allowlist, which allows nobody', () => {
    const open = redactedOpenCheckout((d) => typeof d[1] === 'object' && d[1] !== null && (d[1] as { id?: string }).id === 'merchant_1');
    const chain = presentClosedCheckout({ open, agentKey: s.agent, checkoutJwt: s.checkoutJwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: NOW_S + 5 });
    const o = purchaseOptions(s);
    const r = verifyCheckoutChain(chain, { resolveIssuerKey: o.resolveIssuerKey, resolveMerchantKey: o.resolveMerchantKey, ...o.checkout, now: o.now as number });
    expect(!r.ok && r.reason).toMatch(/not in the allowed list/);
  });

  it('withholding the whole mandate disclosure leaves nothing to verify', () => {
    const open = redactedOpenCheckout((d) => typeof d[1] === 'object' && d[1] !== null && 'vct' in (d[1] as object));
    expect(() => presentClosedCheckout({ open, agentKey: s.agent, checkoutJwt: s.checkoutJwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: NOW_S + 5 })).not.toThrow();
    const chain = presentClosedCheckout({ open, agentKey: s.agent, checkoutJwt: s.checkoutJwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: NOW_S + 5 });
    const o = purchaseOptions(s);
    const r = verifyDelegationChain(chain, { resolveIssuerKey: o.resolveIssuerKey, ...o.checkout, now: o.now as number });
    expect(!r.ok && r.reason).toMatch(/not referenced|exactly one mandate/);
  });
});

describe('direct constraint semantics (stricter than the reference SDK where noted)', () => {
  const open = (constraints: unknown[]): OpenCheckoutMandateClaims => ({ vct: 'mandate.checkout.open.1', constraints, cnf: { jwk: {} } } as unknown as OpenCheckoutMandateClaims);
  const cart = (items: [string, number][]): UcpCheckout => ({
    id: 'c', currency: 'USD', merchant: MERCHANT, totals: [],
    line_items: items.map(([id, quantity], i) => ({ id: `l${i}`, item: { id, title: id, price: 1 }, quantity })),
  });
  const req = (id: string, ids: string[], quantity: number) => ({ id, acceptable_items: ids.map((i) => ({ id: i, title: i })), quantity });
  const li = (...r: ReturnType<typeof req>[]) => open([{ type: 'checkout.line_items', items: r }]);

  it('line items: exact fulfilment passes; too few, too many, unlisted, reused all fail (max-flow rule of the documentation)', () => {
    const c = li(req('shoes', ['red', 'blue'], 1), req('socks', ['best'], 1));
    expect(checkCheckoutConstraints(c, cart([['red', 1], ['best', 1]]))).toEqual([]);
    expect(checkCheckoutConstraints(c, cart([['blue', 1], ['best', 1]]))).toEqual([]);
    expect(checkCheckoutConstraints(c, cart([['red', 1], ['blue', 1]]))).toHaveLength(1); // both shoes: one slot only
    expect(checkCheckoutConstraints(c, cart([['red', 1]]))).toHaveLength(1); // too few: the SDK accepts this
    expect(checkCheckoutConstraints(c, cart([['red', 1], ['best', 1], ['best', 1]]))).toHaveLength(1); // too many
    expect(checkCheckoutConstraints(c, cart([['red', 1], ['best', 1], ['extra', 1]]))).toHaveLength(1); // unlisted
    expect(checkCheckoutConstraints(c, cart([['red', 2]]))).toHaveLength(1);
  });

  it('line items: a requirement with no acceptable items matches nothing (the SDK treats it as a wildcard)', () => {
    expect(checkCheckoutConstraints(li(req('any', [], 1)), cart([['anything', 1]]))).toHaveLength(1);
  });

  it('line items: shared acceptable items are assigned by maximal flow, not greedily', () => {
    const c = li(req('a', ['x', 'y'], 1), req('b', ['x'], 1));
    expect(checkCheckoutConstraints(c, cart([['x', 1], ['y', 1]]))).toEqual([]); // x must go to b, y to a
    expect(checkCheckoutConstraints(c, cart([['y', 2]]))).toHaveLength(1);
  });

  const popen = (constraints: unknown[]): OpenPaymentMandateClaims => ({ vct: 'mandate.payment.open.1', constraints, cnf: { jwk: {} } } as unknown as OpenPaymentMandateClaims);
  const closed = (over: Partial<PaymentMandateClaims> = {}): PaymentMandateClaims => ({
    vct: 'mandate.payment.1', transaction_id: 't', payee: MERCHANT, payment_amount: { amount: 1000, currency: 'USD' }, payment_instrument: { id: 'i1', type: 'card' }, ...over,
  });
  const run = (constraints: unknown[], c: PaymentMandateClaims, extra: Record<string, unknown> = {}): string[] =>
    checkPaymentConstraints({ ...popen(constraints), ...extra } as OpenPaymentMandateClaims, c, { now: NOW_S, openCheckoutHash: 'H', context: { totalAmount: 0, totalUses: 0 } });

  it('amount range: min, max, currency', () => {
    const r = [{ type: 'payment.amount_range', currency: 'USD', min: 500, max: 1000 }];
    expect(run(r, closed())).toEqual([]);
    expect(run(r, closed({ payment_amount: { amount: 499, currency: 'USD' } }))).toHaveLength(1);
    expect(run(r, closed({ payment_amount: { amount: 1001, currency: 'USD' } }))).toHaveLength(1);
    expect(run(r, closed({ payment_amount: { amount: 600, currency: 'EUR' } }))).toHaveLength(1);
  });

  it('payees match by id when both have one, otherwise by name AND website', () => {
    expect(run([{ type: 'payment.allowed_payees', allowed: [{ id: 'merchant_1', name: 'Whatever' }] }], closed())).toEqual([]);
    expect(run([{ type: 'payment.allowed_payees', allowed: [{ id: 'merchant_2', name: 'Demo Merchant' }] }], closed())).toHaveLength(1);
    expect(run([{ type: 'payment.allowed_payees', allowed: [{ id: '', name: 'Demo Merchant', website: 'https://demo-merchant.example' }] }], closed())).toEqual([]);
    expect(run([{ type: 'payment.allowed_payees', allowed: [{ id: '', name: 'Demo Merchant' }] }], closed())).toHaveLength(1); // no website: not enough
    expect(run([{ type: 'payment.allowed_payees', allowed: [] }], closed())).toHaveLength(1);
  });

  it('instruments, PISPs, pre-set claims and the reference', () => {
    expect(run([{ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'i1', type: 'card' }] }], closed())).toEqual([]);
    expect(run([{ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'i2', type: 'card' }] }], closed())).toHaveLength(1);
    const p = { legal_name: 'L', brand_name: 'B', domain_name: 'd.example' };
    expect(run([{ type: 'payment.allowed_pisps', allowed: [p] }], closed())).toEqual(['missing PISP in the closed mandate']);
    expect(run([{ type: 'payment.allowed_pisps', allowed: [p] }], closed({ pisp: p }))).toEqual([]);
    expect(run([{ type: 'payment.allowed_pisps', allowed: [p] }], closed({ pisp: { ...p, brand_name: 'X' } }))).toHaveLength(1);
    expect(run([], closed(), { payment_amount: { amount: 1, currency: 'USD' } })).toEqual(['pre-set payment_amount mismatch']);
    expect(run([{ type: 'payment.reference', conditional_transaction_id: 'H' }], closed())).toEqual([]);
    expect(run([{ type: 'payment.reference', conditional_transaction_id: 'other' }], closed())).toHaveLength(1);
  });

  it('budget uses major units (x100) and fails closed on other exponents and inexact products', () => {
    const b = [{ type: 'payment.budget', currency: 'USD', max: 15.0 }];
    const ctx = (totalAmount: number) => checkPaymentConstraints(popen(b), closed(), { now: NOW_S, context: { totalAmount, totalUses: 0 } });
    expect(ctx(500)).toEqual([]); // 500 + 1000 = 1500 = 15.00 USD
    expect(ctx(501)).toHaveLength(1);
    expect(checkPaymentConstraints(popen(b), closed(), { now: NOW_S })).toEqual(['mandate context is required to evaluate a budget']);
    expect(run([{ type: 'payment.budget', currency: 'JPY', max: 1 }], closed({ payment_amount: { amount: 1, currency: 'JPY' } }))[0]).toMatch(/unsupported/);
    expect(run([{ type: 'payment.budget', currency: 'USD', max: 10.001 }], closed())[0]).toMatch(/whole number of minor units/);
  });

  it('execution date: instants, not strings; an absent date means "now"', () => {
    const w = (nb: string | undefined, na: string | undefined) => [{ type: 'payment.execution_date', ...(nb ? { not_before: nb } : {}), ...(na ? { not_after: na } : {}) }];
    const now = new Date(NOW_S * 1000).toISOString();
    expect(run(w(undefined, undefined), closed())).toEqual([]);
    expect(run(w('2099-01-01T00:00:00Z', undefined), closed())).toHaveLength(1); // immediate execution before the window opens
    expect(run(w(undefined, '2000-01-01T00:00:00Z'), closed())).toHaveLength(1);
    expect(run(w('2027-01-01T00:00:00+00:00', undefined), closed({ execution_date: '2027-01-01T01:00:00+02:00' }))).toHaveLength(1); // 23:00Z on Dec 31: before, though the strings sort after
    expect(run(w(undefined, now), closed({ execution_date: now }))).toEqual([]);
    expect(run(w('not a date', undefined), closed())[0]).toMatch(/not a valid instant/);
  });

  it('recurrence: occurrence cap, per-period frequency, and the requires-range-and-budget rule', () => {
    const rec = (frequency: string, max?: number) => ({ type: 'payment.agent_recurrence', frequency, ...(max ? { max_occurrences: max } : {}) });
    const base = [{ type: 'payment.amount_range', currency: 'USD', max: 5000 }, { type: 'payment.budget', currency: 'USD', max: 100 }];
    const at = (context: { totalAmount: number; totalUses: number; lastUsedDate?: number }, c: object[]) => checkPaymentConstraints(popen(c), closed(), { now: NOW_S, context });
    expect(at({ totalAmount: 0, totalUses: 2 }, [...base, rec('ON_DEMAND', 3)])).toEqual([]);
    expect(at({ totalAmount: 0, totalUses: 3 }, [...base, rec('ON_DEMAND', 3)])).toHaveLength(1);
    expect(run([rec('ON_DEMAND')], closed())).toHaveLength(2); // needs amount_range and budget
    const lastWeek = NOW_S - 8 * 86_400;
    const today = NOW_S - 60;
    for (const f of ['DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY']) {
      expect(at({ totalAmount: 0, totalUses: 1, lastUsedDate: today }, [...base, rec(f)]), `${f} used just now`).toHaveLength(1);
      expect(at({ totalAmount: 0, totalUses: 0 }, [...base, rec(f)]), `${f} unused`).toEqual([]);
    }
    expect(at({ totalAmount: 0, totalUses: 1, lastUsedDate: lastWeek }, [...base, rec('DAILY')])).toEqual([]);
    expect(at({ totalAmount: 0, totalUses: 1, lastUsedDate: lastWeek }, [...base, rec('ANNUALLY')])).toHaveLength(1);
  });

  it('an unknown constraint type never passes (payment or checkout)', () => {
    expect(run([{ type: 'payment.mystery' }], closed())).toEqual(['unknown constraint type payment.mystery']);
    expect(checkCheckoutConstraints(open([{ type: 'checkout.mystery' }]), cart([['a', 1]]))).toEqual(['unknown constraint type checkout.mystery']);
  });
});

describe('issuance validates its inputs', () => {
  const s = makeScenario();
  const common = { issuer: { privateKey: s.issuer.privateKey, kid: 'k' }, agentJwk: s.agent.publicJwk, iat: NOW_S, exp: NOW_S + 60 };
  it('refuses malformed constraints, missing reference, bad times and bad keys', () => {
    expect(() => issueOpenPaymentMandate({ ...common, constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 10.5 }] })).toThrow(/integer/);
    expect(() => issueOpenPaymentMandate({ ...common, constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 10 }] })).toThrow(/payment.reference/);
    expect(() => issueOpenPaymentMandate({ ...common, exp: NOW_S, constraints: [{ type: 'payment.reference', conditional_transaction_id: 'x' }] })).toThrow(/iat < exp/);
    expect(() => issueOpenPaymentMandate({ ...common, agentJwk: { ...s.agent.publicJwk, y: s.agent.publicJwk.x }, constraints: [{ type: 'payment.reference', conditional_transaction_id: 'x' }] })).toThrow(/P-256/);
    expect(() => issueOpenCheckoutMandate({ ...common, constraints: [{ type: 'checkout.allowed_merchants', allowed: [MERCHANT] }] })).toThrow(/line_items/);
    expect(() => issueOpenCheckoutMandate({ ...common, constraints: [{ type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: [], quantity: 0 }] }] })).toThrow(/positive integer/);
  });
});

describe('structure fuzzing: verification never throws and never accepts', () => {
  const s = makeScenario();
  // xorshift32: a deterministic pseudo-random sequence (reproducible failures)
  const rng = (seed: number) => () => {
    seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0;
    return seed / 0x1_0000_0000;
  };

  it('random edits at separator characters (~ and .) are all refused without an exception', () => {
    const r = rng(0xc0ffee);
    const token = s.paymentChain;
    const seps = [...token].flatMap((c, i) => (c === '~' || c === '.' ? [i] : []));
    for (let n = 0; n < 600; n++) {
      const at = seps[Math.floor(r() * seps.length)] as number;
      const op = Math.floor(r() * 4);
      const mutated =
        op === 0 ? token.slice(0, at) + token.slice(at + 1) // delete
        : op === 1 ? token.slice(0, at) + token[at] + token.slice(at) // duplicate
        : op === 2 ? token.slice(0, at) + (token[at] === '~' ? '.' : '~') + token.slice(at + 1) // swap kind
        : token.slice(0, at) + token.slice(at + 1 + Math.floor(r() * 40)); // cut a run
      expect(() => verifyScenario(s, {}, { payment: mutated })).not.toThrow();
      expect(verifyScenario(s, {}, { payment: mutated }).ok, `op ${op} at ${at}`).toBe(false);
    }
  });

  it('arbitrary garbage and truncations are refused without an exception', () => {
    const r = rng(0xbadc0de);
    const alphabet = 'abcXYZ019-_.~=+/ \n"{}[]';
    for (let n = 0; n < 400; n++) {
      const len = Math.floor(r() * 300);
      const g = Array.from({ length: len }, () => alphabet[Math.floor(r() * alphabet.length)]).join('');
      expect(() => verifyScenario(s, {}, { payment: g, checkout: g })).not.toThrow();
      expect(verifyScenario(s, {}, { payment: g }).ok).toBe(false);
    }
    for (let cut = 0; cut < s.checkoutChain.length; cut += 37) {
      expect(verifyScenario(s, {}, { checkout: s.checkoutChain.slice(0, cut) }).ok, `cut ${cut}`).toBe(false);
    }
  });

  it('splitChain edge cases', () => {
    expect(splitChain('a~d~')).toEqual(['a~d~']);
    expect(splitChain('a~d~~b~e~')).toEqual(['a~d~', 'b~e~']);
    expect(splitChain('a~~b~')).toEqual(['a~', 'b~']);
    expect(() => splitChain('')).toThrow();
    expect(() => splitChain(Array.from({ length: 9 }, () => 'a~').join('~'))).toThrow(/more than 8 hops/);
  });
});
