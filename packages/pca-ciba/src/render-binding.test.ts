import { describe, expect, it } from 'vitest';
import { agent, approvalRenderDigest, bindingWords, generateKeyPair, reviewAction, type ApprovalRender } from '@atlasauth/pca';
import { toCibaAuthRequest } from './index';

const render: ApprovalRender = {
  v: 1, kind: 'pca-approval-render', verb: 'stripe.payout', def_digest: 'A'.repeat(43), unreviewed: false,
  fields: [{ id: 'amount', class: 'money.amount', value: 80, unit: { kind: 'money', ccy: 'USD', exp: 2 } }, { id: 'payee', class: 'party.payee', value: 'bob' }],
};
const stepUp = () => {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1, renderer: () => render });
  if (r.kind !== 'step_up') throw new Error('expected a step-up');
  return r.request;
};

describe('CIBA carries the canonical render (K7)', () => {
  it('adds RAR authorization_details, the digest and a match code in the binding message', () => {
    const su = stepUp();
    const c = toCibaAuthRequest(su);
    const rd = approvalRenderDigest(render);
    expect(c.render_digest).toBe(rd);
    expect(c.authorization_details).toEqual([{ type: 'pca_approval', render, render_digest: rd }]);
    expect(c.binding_message).toContain(`[match code ${bindingWords(rd)}]`);
  });
  it('token-only providers get the code as hyphenated tokens, or a refusal when it does not fit', () => {
    const su = stepUp();
    const c = toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: 120 } });
    expect(c.binding_message).toMatch(/^[A-Za-z0-9._-]+$/);
    expect(c.binding_message.endsWith(`-match-${bindingWords(approvalRenderDigest(render))}`)).toBe(true);
    expect(() => toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: 50 } })).toThrow(RangeError);
  });
  it('refuses a step-up whose render and digest disagree', () => {
    const su = stepUp();
    expect(() => toCibaAuthRequest({ ...su, renderDigest: 'B'.repeat(43) })).toThrow(/do not agree/);
    expect(() => toCibaAuthRequest({ ...su, render: undefined })).toThrow(/do not agree/);
  });
  it('without a render nothing changes', () => {
    const su = stepUp();
    const plain = toCibaAuthRequest({ ...su, render: undefined, renderDigest: undefined });
    expect(plain.authorization_details).toBeUndefined();
    expect(plain.binding_message).not.toContain('match code');
  });
});
