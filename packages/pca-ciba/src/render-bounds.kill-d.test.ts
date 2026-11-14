import { describe, expect, it } from 'vitest';
import { agent, approvalRenderDigest, bindingWords, generateKeyPair, reviewAction, type ApprovalRender } from '@atlasauth/pca';
import { toCibaAuthRequest } from './index';

const render: ApprovalRender = {
  v: 1,
  kind: 'pca-approval-render',
  verb: 'stripe.payout',
  def_digest: 'A'.repeat(43),
  unreviewed: false,
  fields: [
    { id: 'amount', class: 'money.amount', value: 80, unit: { kind: 'money', ccy: 'USD', exp: 2 } },
    { id: 'payee', class: 'party.payee', value: 'bob' },
  ],
};
const stepUp = () => {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1, renderer: () => render });
  if (r.kind !== 'step_up') throw new Error('expected a step-up');
  return r.request;
};
const words = () => bindingWords(approvalRenderDigest(render));

describe('render and digest must both be present and agree', () => {
  it('a render without its digest is refused', () => {
    expect(() => toCibaAuthRequest({ ...stepUp(), renderDigest: undefined })).toThrow(/do not agree/);
  });
  it('a digest without its render is refused', () => {
    expect(() => toCibaAuthRequest({ ...stepUp(), render: undefined })).toThrow(/do not agree/);
  });
});

describe('the match-code reserve is exact', () => {
  const W = () => words().length;
  it('token-only: the whole message fits maxChars exactly, and one character less is refused', () => {
    const su = stepUp();
    const compact = 'Approve-stripe.payout-80-USD-to-bob-acct-1';
    const fits = compact.length + W() + 14;
    const ok = toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: fits } });
    expect(ok.binding_message).toBe(`${compact}-match-${words()}`);
    expect(ok.binding_message.length).toBeLessThanOrEqual(fits);
    expect(() => toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: fits - 1 } })).toThrow(/refusing to truncate/);
  });
  it('rich form: the head fits maxChars minus the reserve exactly, and one character less is refused', () => {
    const su = stepUp();
    const head = 'Approve stripe.payout 80 USD to "bob" on acct:1';
    const fits = head.length + W() + 14;
    const ok = toCibaAuthRequest(su, { bindingMessage: { maxChars: fits } });
    expect(ok.binding_message.startsWith(head)).toBe(true);
    expect(ok.binding_message.endsWith(` [match code ${words()}]`)).toBe(true);
    expect(() => toCibaAuthRequest(su, { bindingMessage: { maxChars: fits - 1 } })).toThrow(/refusing to truncate/);
  });
});
