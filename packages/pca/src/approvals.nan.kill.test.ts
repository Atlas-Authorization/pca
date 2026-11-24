import { describe, expect, it } from 'vitest';
import { classApprovalCovers, type ClassApproval } from './approvals';

const A: ClassApproval = { id: 'c1', verbs: ['stripe.refund'], grantedAt: 1_000, ttlMs: 10_000, by: 'owner' };

describe('a non-finite clock or ttl never admits (approvals)', () => {
  it('a standing approval covers a finite in-window clock', () => {
    expect(classApprovalCovers(A, 'stripe.refund', 'r', 2_000)).toBe(true);
  });
  // old check `now < grantedAt || now >= grantedAt + ttl` was false for NaN on either side, so the approval covered
  it('a NaN clock does not cover', () => {
    expect(classApprovalCovers(A, 'stripe.refund', 'r', Number.NaN)).toBe(false);
  });
  it('a NaN grantedAt or ttl does not cover', () => {
    expect(classApprovalCovers({ ...A, grantedAt: Number.NaN }, 'stripe.refund', 'r', 2_000)).toBe(false);
    expect(classApprovalCovers({ ...A, ttlMs: Number.NaN }, 'stripe.refund', 'r', 2_000)).toBe(false);
  });
  it('an infinite clock does not cover', () => {
    expect(classApprovalCovers(A, 'stripe.refund', 'r', Number.POSITIVE_INFINITY)).toBe(false);
    expect(classApprovalCovers(A, 'stripe.refund', 'r', Number.NEGATIVE_INFINITY)).toBe(false);
  });
  // old check admitted an infinite ttl (now < grantedAt + Inf) and a -Infinity grantedAt (now < -Inf fails, but +Inf ttl with finite grantedAt admits)
  it('an infinite ttl or grantedAt does not cover', () => {
    for (const v of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(classApprovalCovers({ ...A, ttlMs: v }, 'stripe.refund', 'r', 2_000)).toBe(false);
      expect(classApprovalCovers({ ...A, grantedAt: v }, 'stripe.refund', 'r', 2_000)).toBe(false);
    }
  });
});
