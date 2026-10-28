import { describe, expect, it } from 'vitest';
import { agent, approvalChallengeB64u, approvalRenderDigest, b64u, bindingWords, generateKeyPair, paramsDigest, reviewAction } from '@atlasauth/pca';
import {
  ActionKitError, approvalBatch, approverRenderCheck, cibaApprovalDetails, minorToDecimal, psd2Linking, renderApproval, renderDigestForAction, renderersFromDefs, singleTapAllowed, spcExpectation,
} from '../src';
import { FIXED, TRANSFER } from './vectors-approval';

const conf = { attestationVerified: () => true };
const ok = { amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
const code = (f: () => unknown): string => { try { f(); return 'no error'; } catch (e) { return e instanceof ActionKitError ? e.code : `other: ${String(e)}`; } };

describe('canonical approval render', () => {
  it('renders every supplied parameter, sorted, with the currency resolved', () => {
    expect(renderApproval(TRANSFER, ok, conf)).toMatchObject({
      v: 1, kind: 'pca-approval-render', verb: 'bank.transfer.send', unreviewed: false,
      fields: [
        { id: 'amount', class: 'money.amount', value: 12_500, unit: { kind: 'money', ccy: 'EUR', exp: 2 } },
        { id: 'currency', class: 'money.currency', value: 'EUR' },
        { id: 'payee', class: 'party.payee', value: 'Acme GmbH' },
      ],
    });
  });
  it('is independent of parameter order and flattens nested parameters', () => {
    expect(approvalRenderDigest(renderApproval(TRANSFER, { payee: 'Acme GmbH', amount: 12_500, currency: 'EUR' }))).toBe(approvalRenderDigest(renderApproval(TRANSFER, ok)));
    expect(renderApproval(FIXED, { amount: 1, to: { iban: 'DE89370400440532013000', name: 'A' } }).fields.map((f) => f.id)).toEqual(['amount', 'to.iban', 'to.name']);
  });
  it('an unconfirmed definition renders UNREVIEWED with a different digest, and forbids single tap', () => {
    const u = renderApproval(TRANSFER, ok);
    const c = renderApproval(TRANSFER, ok, conf);
    expect(u.unreviewed).toBe(true);
    expect(singleTapAllowed(u)).toBe(false);
    expect(singleTapAllowed(c)).toBe(true);
    expect(approvalRenderDigest(u)).not.toBe(approvalRenderDigest(c));
  });
  it('refuses anything it cannot show completely', () => {
    expect(code(() => renderApproval(TRANSFER, { ...ok, hidden: 1 }))).toBe('render_undeclared_param');
    expect(code(() => renderApproval(TRANSFER, { amount: 5, currency: 'EUR' }))).toBe('render_missing_param');
    expect(code(() => renderApproval(TRANSFER, { amount: 5, currency: 9, payee: 'x' }))).toBe('render_unresolved_currency');
    expect(code(() => renderApproval(TRANSFER, [] as unknown as Record<string, unknown>))).toBe('render_bad_params');
  });
  it('changing any value, the currency, the payee, the verb or the def changes the digest', () => {
    const d = (p: Record<string, unknown>) => approvalRenderDigest(renderApproval(TRANSFER, p, conf));
    const base = d(ok);
    for (const p of [{ ...ok, amount: 12_501 }, { ...ok, currency: 'USD' }, { ...ok, payee: 'Acme GmbH ' }, { ...ok, memo: 'x' }]) expect(d(p)).not.toBe(base);
    expect(approvalRenderDigest(renderApproval({ ...TRANSFER, title: 'Other' }, ok, conf))).not.toBe(base); // the def digest is committed
    expect(approvalRenderDigest(renderApproval({ ...TRANSFER, review: { state: 'confirmed' } }, ok, conf))).toBe(base); // review state is not part of the digest
    expect(approvalRenderDigest(renderApproval({ ...TRANSFER, effects: ['pay', 'send'] }, ok, conf))).not.toBe(base);
  });
  it('the verifier recomputes from the executed params and refuses a mismatch', () => {
    const a = { action: { verb: 'bank.transfer.send', params_digest: paramsDigest(ok) } };
    expect(renderDigestForAction(TRANSFER, ok, a, conf)).toBe(approvalRenderDigest(renderApproval(TRANSFER, ok, conf)));
    expect(code(() => renderDigestForAction(TRANSFER, { ...ok, amount: 1 }, a, conf))).toBe('render_params_mismatch');
    expect(code(() => renderDigestForAction(TRANSFER, ok, { action: { ...a.action, verb: 'bank.transfer.eur' } }, conf))).toBe('render_verb_mismatch');
  });
  it('the approver client refuses to sign a render it cannot reproduce', () => {
    const d = approvalRenderDigest(renderApproval(TRANSFER, ok, conf));
    expect(approverRenderCheck(TRANSFER, ok, d, conf)).toBe(d);
    expect(code(() => approverRenderCheck(TRANSFER, { ...ok, amount: 99 }, d, conf))).toBe('render_mismatch');
    expect(code(() => approverRenderCheck(TRANSFER, ok, d))).toBe('render_mismatch');
  });
});

describe('challenge', () => {
  const a = b64u(new Uint8Array(32).fill(1));
  const r = b64u(new Uint8Array(32).fill(2));
  it('is domain separated, order sensitive and refuses non-canonical input', () => {
    expect(approvalChallengeB64u(a, r)).toHaveLength(43);
    expect(approvalChallengeB64u(a, r)).not.toBe(approvalChallengeB64u(r, a));
    expect(() => approvalChallengeB64u('AAAA', r)).toThrow();
    expect(() => approvalChallengeB64u(a, `${r}=`)).toThrow();
  });
  it('binding words are 6 hyphenated words of the digest', () => {
    expect(bindingWords(r)).toBe('aged-aged-aged-aged-aged-aged');
  });
});

describe('PSD2 RTS Art. 5 dynamic linking', () => {
  it('extracts the amount and the payee, only from a confirmed definition', () => {
    expect(psd2Linking(renderApproval(TRANSFER, ok, conf))).toEqual({ amount_minor: 12_500, currency: 'EUR', exp: 2, payee: 'Acme GmbH' });
    expect(code(() => psd2Linking(renderApproval(TRANSFER, ok)))).toBe('psd2_unlinkable');
  });
  it('formats minor units without floating point', () => {
    expect(minorToDecimal(12_500, 2)).toBe('125.00');
    expect(minorToDecimal(5, 2)).toBe('0.05');
    expect(minorToDecimal(7, 0)).toBe('7');
    expect(minorToDecimal(123456789012, 3)).toBe('123456789.012');
    expect(() => minorToDecimal(-1, 2)).toThrow();
  });
  it('the SPC expectation carries the exact total and the payee', () => {
    expect(spcExpectation(renderApproval(TRANSFER, ok, conf), 'https://approve.example')).toEqual({ topOrigin: 'https://approve.example', total: { currency: 'EUR', value: '125.00' }, payeeName: 'Acme GmbH' });
    expect(spcExpectation(renderApproval(TRANSFER, { ...ok, payee: 'https://acme.example' }, conf), 'https://approve.example', 'origin').payeeOrigin).toBe('https://acme.example');
  });
  it('a batch commits to per-currency totals, the payee set and every item', () => {
    const it = (amount: number, currency: string, payee: string, c: string) => ({ action_digest: b64u(new Uint8Array(32).fill(c.charCodeAt(0))), render: renderApproval(TRANSFER, { amount, currency, payee }, conf) });
    const b = approvalBatch([it(1000, 'EUR', 'A', 'a'), it(250, 'EUR', 'B', 'b'), it(5, 'USD', 'A', 'c')]);
    expect(b.batch.totals).toEqual([{ ccy: 'EUR', exp: 2, minor: 1250 }, { ccy: 'USD', exp: 2, minor: 5 }]);
    expect(b.batch.n).toBe(3);
    const swapped = approvalBatch([it(1000, 'EUR', 'A', 'a'), it(250, 'EUR', 'C', 'b'), it(5, 'USD', 'A', 'c')]);
    expect(swapped.batch.payees_root).not.toBe(b.batch.payees_root);
    expect(swapped.render_digest).not.toBe(b.render_digest);
    const moved = approvalBatch([it(1000, 'EUR', 'A', 'a'), it(251, 'EUR', 'B', 'b'), it(5, 'USD', 'A', 'c')]);
    expect(moved.batch.totals[0]!.minor).toBe(1251);
    expect(code(() => approvalBatch([]))).toBe('psd2_unlinkable');
  });
  it('CIBA carries the render as RAR authorization_details with a match code', () => {
    const r = renderApproval(TRANSFER, ok, conf);
    const c = cibaApprovalDetails(r);
    expect(c.authorization_details[0]).toMatchObject({ type: 'pca_approval', render_digest: approvalRenderDigest(r) });
    expect(c.match_code).toBe(bindingWords(approvalRenderDigest(r)));
  });
});

describe('step-up renderer derived from the pinned definitions', () => {
  const payout = { ...TRANSFER, verb: 'stripe.payout', params: { amount: TRANSFER.params.amount!, currency: TRANSFER.params.currency!, payee: TRANSFER.params.payee! } };
  const mk = () => agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const params = { amount: 80, currency: 'USD', payee: 'bob' };
  it('reviewAction binds the render with no hand-written renderer, and a verb with no pinned definition is a deny', () => {
    const r = reviewAction(mk(), 'stripe.payout', 'acct:1', params, { now: 1, renderer: renderersFromDefs([payout], conf) });
    expect(r.kind).toBe('step_up');
    if (r.kind === 'step_up') {
      expect(r.request.render?.verb).toBe('stripe.payout');
      expect(r.request.renderDigest).toBe(approvalRenderDigest(renderApproval(payout, params, conf)));
    }
    const missing = reviewAction(mk(), 'stripe.payout', 'acct:1', params, { now: 1, renderer: renderersFromDefs([], conf) });
    expect(missing.kind).toBe('deny');
    const undeclared = reviewAction(mk(), 'stripe.payout', 'acct:1', { ...params, hidden: 1 }, { now: 1, renderer: renderersFromDefs([payout], conf) });
    expect(undeclared.kind).toBe('deny');
  });
});
