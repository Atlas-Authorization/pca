import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { FreshAtIssuer, checkFreshAt, freshAtDigest, gateDecision, mergeFreshAt, signFreshAt, verifyFreshAt, type FreshAtState, type FreshAtVerdict } from './fresh-at';
import { signerOf } from './sig';

const kp = generateKeyPair();
const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };
const opts = (now = 1000) => ({ signer: signerOf(kp.secretKey), scope: 'inst_1', now });

describe('fresh_at consistency tokens', () => {
  it('a token verifies for its signer and for nobody else', () => {
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(verifyFreshAt(t, signerOf(kp.secretKey))).toBe(true);
    expect(verifyFreshAt(t, signerOf(generateKeyPair().secretKey))).toBe(false);
    expect(verifyFreshAt({ ...t, revocation_epoch: 4 }, signerOf(kp.secretKey))).toBe(false);
    expect(verifyFreshAt({ ...t, scope: 'inst_2' }, signerOf(kp.secretKey))).toBe(false);
  });
  it('equal or newer local state is ok', () => {
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(checkFreshAt(t, S, opts())).toEqual({ decision: 'ok' });
    expect(checkFreshAt(t, { ...S, ledger_tree_size: 101, budget_version: 9 }, opts())).toEqual({ decision: 'ok' });
  });
  it('NEW ENEMY: a verifier at an older revocation epoch escalates stale_state, naming the field', () => {
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(checkFreshAt(t, { ...S, revocation_epoch: 4 }, opts())).toEqual({ decision: 'escalate', code: 'stale_state', behind: ['revocation_epoch'] });
    expect(checkFreshAt(t, { ...S, revocation_epoch: 4, budget_version: 6 }, opts())).toEqual({ decision: 'escalate', code: 'stale_state', behind: ['revocation_epoch', 'budget_version'] });
  });
  it('wrong scope, forgery, future and over-age tokens are denied', () => {
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(checkFreshAt(t, S, { ...opts(), scope: 'inst_2' })).toEqual({ decision: 'deny', code: 'wrong_scope' });
    expect(checkFreshAt({ ...t, sig: t.sig.slice(1) + 'A' }, S, opts())).toEqual({ decision: 'deny', code: 'bad_token' });
    expect(checkFreshAt(null, S, opts())).toEqual({ decision: 'deny', code: 'bad_token' });
    expect(checkFreshAt(t, S, opts(1000 - 60_001))).toEqual({ decision: 'deny', code: 'token_from_the_future' });
    expect(checkFreshAt(t, S, { ...opts(11_000), maxTokenAgeMs: 10_000 })).toEqual({ decision: 'ok' });
    expect(checkFreshAt(t, S, { ...opts(11_001), maxTokenAgeMs: 10_000 })).toEqual({ decision: 'deny', code: 'token_too_old' });
  });
  it('same policy revision with a different digest is a fork (deny), a lower local revision is stale', () => {
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(checkFreshAt(t, { ...S, policy_digest: 'other' }, opts())).toEqual({ decision: 'deny', code: 'policy_fork' });
    expect(checkFreshAt(t, { ...S, policy_revision: 2, policy_digest: 'pd2' }, opts())).toEqual({ decision: 'escalate', code: 'stale_state', behind: ['policy_revision'] });
  });
  it('gateDecision only tightens', () => {
    const ok = { decision: 'ok' } as const;
    const esc: FreshAtVerdict = { decision: 'escalate', code: 'stale_state', behind: ['budget_version'] };
    const den = { decision: 'deny', code: 'bad_token' } as const;
    expect(gateDecision('allow', ok)).toBe('allow');
    expect(gateDecision('allow', esc)).toBe('escalate');
    expect(gateDecision('allow', den)).toBe('deny');
    expect(gateDecision('escalate', ok)).toBe('escalate');
    expect(gateDecision('deny', ok)).toBe('deny');
    expect(gateDecision('escalate', den)).toBe('deny');
  });
  it('mergeFreshAt is the field-wise max and never lowers', () => {
    const m = mergeFreshAt(S, { revocation_epoch: 9, ledger_tree_size: 1, budget_version: 7, policy_revision: 2, policy_digest: 'old' });
    expect(m).toEqual({ revocation_epoch: 9, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' });
    expect(mergeFreshAt(S, { ...S, policy_revision: 4, policy_digest: 'pd4' }).policy_digest).toBe('pd4');
  });
  it('the issuer advances monotonically and its own tokens check ok at once; an old token still passes, a revoke token makes a lagging peer stale', () => {
    const a = new FreshAtIssuer(kp.secretKey, 'inst_1', S);
    const before = a.advance({}, 1000);
    const revoke = a.advance({ revocation_epoch: 6 }, 1001);
    expect(a.current.revocation_epoch).toBe(6);
    expect(a.advance({ revocation_epoch: 2, budget_version: 1 }, 1002).revocation_epoch).toBe(6);
    expect(a.check(before, 1002)).toEqual({ decision: 'ok' });
    expect(a.check(revoke, 1002)).toEqual({ decision: 'ok' });
    const lagging = new FreshAtIssuer(kp.secretKey, 'inst_1', S);
    expect(lagging.check(revoke, 1002)).toEqual({ decision: 'escalate', code: 'stale_state', behind: ['revocation_epoch'] });
  });
  it('rejects a malformed state at signing time and has a stable digest', () => {
    expect(() => signFreshAt(kp.secretKey, 'inst_1', { ...S, budget_version: -1 }, 1)).toThrow(RangeError);
    const t = signFreshAt(kp.secretKey, 'inst_1', S, 1000);
    expect(freshAtDigest(t)).toBe(freshAtDigest({ ...t }));
    expect(freshAtDigest(t)).not.toBe(freshAtDigest({ ...t, issued_at: 1001 }));
  });
});
