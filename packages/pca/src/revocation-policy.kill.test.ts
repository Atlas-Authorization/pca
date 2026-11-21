/**
 * Revocation staleness configuration and refusals pinned exactly: the irreversible default window, the positive-ms
 * validation (non-numbers and infinities are refused), stalenessPolicyOn, the unknown-issue-time reason, a PCActn without
 * an action, and the full shape of the unsigned-root refusals.
 */
import { describe, expect, it } from 'vitest';
import type { VerifyContext } from './pcactn';
import {
  REVOCATION_IRREVERSIBLE_MAX_AGE_MS,
  RevocationSet,
  checkRevocationAge,
  createRevocationChecker,
  stalenessPolicyOn,
  validateRevocationStaleness,
  type RevocationStalenessPolicy,
} from './revocation';

const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const set = new RevocationSet(['cap-revoked']);
const ctx = (action: unknown): VerifyContext =>
  ({ pcactn: { grant_ref: 'g1', cap_chain: [{ id: 'cap-a' }], ...(action === undefined ? {} : { action }), freshness: { epoch: 0 } }, grant: { id: 'g1' }, nowEpoch: NOW }) as unknown as VerifyContext;
const outcome = async (f: () => unknown): Promise<unknown> => {
  try {
    return await f();
  } catch (e) {
    return `THREW: ${(e as Error).message}`;
  }
};

describe('revocation staleness configuration', () => {
  it('the irreversible default window is two refresh periods (2 min)', () => {
    expect(REVOCATION_IRREVERSIBLE_MAX_AGE_MS).toBe(120_000);
  });
  it('a non-number or an infinite age is refused; a positive finite one is accepted', () => {
    for (const v of ['5', Number.POSITIVE_INFINITY, Number.NaN, 0, -1]) {
      expect(() => validateRevocationStaleness({ maxRevocationAgeMs: v as never })).toThrow('maxRevocationAgeMs must be a positive number of milliseconds');
    }
    expect(() => validateRevocationStaleness({ maxRevocationAgeMs: 1, staleness: { irreversible: 1, rate_limited: 1, costly: 1 } })).not.toThrow();
  });
  it('stalenessPolicyOn is true only when an age option is set', () => {
    expect(stalenessPolicyOn({})).toBe(false);
    expect(stalenessPolicyOn({ allowUnsignedRootForIrreversible: true })).toBe(false);
    expect(stalenessPolicyOn({ maxRevocationAgeMs: 1 })).toBe(true);
    expect(stalenessPolicyOn({ staleness: {} })).toBe(true);
  });
  it('an unknown issue time (NaN, a string, undefined) is unverifiable, never "in the future"', () => {
    for (const t of [Number.NaN, '5', undefined]) {
      expect(checkRevocationAge(t as never, NOW, 1000)).toEqual({ ok: false, reason: 'revocation state age is unknown (unverifiable revocation state)' });
    }
  });
});

describe('createRevocationChecker unsigned-root refusals', () => {
  const checker = (o: RevocationStalenessPolicy & { rootIssuedAt?: () => number | undefined }) =>
    createRevocationChecker({ root: () => set.root, proofFor: (id) => set.nonMembershipProof(id), ...o });
  it('a PCActn without an action counts as irreversible (never a throw)', async () => {
    expect(await outcome(() => checker({ staleness: {} })(ctx(undefined)))).toEqual({
      enforced: true,
      ok: false,
      reason: 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)',
    });
  });
  it('a stale unsigned root for a reversible action is an enforced refusal with the age reason', async () => {
    expect(await outcome(() => checker({ maxRevocationAgeMs: 1000, rootIssuedAt: () => NOW - 5000 })(ctx({ reversibility_class: 'reversible' })))).toEqual({
      enforced: true,
      ok: false,
      reason: "revocation root is 5000 ms old, over the verifier's maximum of 1000 ms (stale revocation state)",
    });
  });
});
