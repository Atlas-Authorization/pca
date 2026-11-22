import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import { approveDraft, draftPolicyFromNL, loadApprovedPolicy } from './nl';

const reviewer = generateKeyPair();
const rpk = b64u(reviewer.publicKey);
const NOW = 1_700_000_000_000;

describe('a non-finite clock never loads an approval (nl)', () => {
  // old checks `approved_at > now` and `now >= expires_at` were both false for NaN, so the approval loaded as in-window
  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('a clock of %s is refused', async (now) => {
    const draft = await draftPolicyFromNL({ instruction: 'x', complete: () => JSON.stringify({ permissions: { stripe: ['refund'] }, limits: { refund: '$200/day' } }) });
    const approval = approveDraft(draft, reviewer.secretKey, { now: NOW });
    expect(loadApprovedPolicy(draft, approval, { reviewers: [rpk], now: NOW + 1000 }).ok).toBe(true);
    expect(loadApprovedPolicy(draft, approval, { reviewers: [rpk], now }).ok).toBe(false);
  });
});
