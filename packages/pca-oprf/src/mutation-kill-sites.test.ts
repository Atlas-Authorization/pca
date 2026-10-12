/** Site kill (oprf.ts:429): blindEvaluate's default mode is 'oprf', so a call that omits it returns NO DLEQ proof. */
import { describe, expect, it } from 'vitest';
import { blind, blindEvaluate, randomKeyPair } from './oprf';

describe('blindEvaluate default mode', () => {
  it('omitting mode is plain OPRF: only evaluatedElement, no proof', () => {
    const kp = randomKeyPair();
    const { blindedElement } = blind(new TextEncoder().encode('input'));
    const res = blindEvaluate(kp.secretKey, blindedElement);
    expect(Object.keys(res)).toEqual(['evaluatedElement']);
    expect((res as { proof?: unknown }).proof).toBeUndefined();
    expect(blindEvaluate(kp.secretKey, blindedElement, 'oprf')).toEqual(res);
  });
});
