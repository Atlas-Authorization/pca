import { describe, expect, it } from 'vitest';
import { generateKeyPair, publicKeyOf } from './keys';
import { b64u } from './hash';
import { checkFreshAt, signFreshAt, type FreshAtState } from './fresh-at';

const NOW = 1_800_000_000_000;
const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };
const T = generateKeyPair();
const o = { signer: b64u(publicKeyOf(T.secretKey)), scope: 'inst_A', now: NOW };
const token = signFreshAt(T.secretKey, 'inst_A', S, NOW - 1000);

describe('a non-finite clock or counter never admits a freshness token', () => {
  it('the example token is ok at the example clock', () => {
    expect(checkFreshAt(token, S, o)).toEqual({ decision: 'ok' });
  });
  // old: with no maxTokenAgeMs a +Infinity clock passed the future check and nothing checked age
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a verifier clock of %s is refused', (now) => {
    expect(checkFreshAt(token, S, { ...o, now })).toEqual({ decision: 'deny', code: 'token_from_the_future' });
  });
  // old `local >= token` was true for a +Infinity local counter, so a stale local state read as caught up
  it.each(['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'] as const)('a +Infinity local %s is not caught up', (k) => {
    const r = checkFreshAt(token, { ...S, [k]: Number.POSITIVE_INFINITY }, o);
    expect(r).toEqual({ decision: 'escalate', code: 'stale_state', behind: [k] });
  });
});
