import type { Predicate } from '@atlasauth/pca';
import type { VerbShape } from './types';

/** Shared test policy: refunds up to 500 on any account. */
export const refund = (max = 500, resource = '/acct/*'): Predicate => ({ verb: 'stripe.refund', resource, where: [{ field: 'action.params.amount', op: 'lte', value: max }] });

export const refundShape: VerbShape = {
  verb: 'stripe.refund',
  params: {
    amount: { type: 'integer', semantic: 'money.amount', sensitivity: 'material', min: 0, max: 100000 },
    reason: { type: 'string', values: ['duplicate', 'fraud', 'requested'], sensitivity: 'free' },
  },
};

/** A small deterministic generator (mulberry32) so property tests are reproducible. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
