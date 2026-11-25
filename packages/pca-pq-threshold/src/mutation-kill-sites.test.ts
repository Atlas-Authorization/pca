/** Site kill (index.ts:343): verifyHybridThreshold turns a throwing action / options into its exact refusal verdict. */
import { describe, expect, it } from 'vitest';
import { HYBRID_ARTIFACT_VERSION, verifyHybridThreshold } from './index';

const ART = { v: HYBRID_ARTIFACT_VERSION } as never;

const REFUSAL = {
  ok: false,
  frost: false,
  pq: { ok: false, count: 0, need: 0, reason: 'malformed action or verifier options' },
  reason: 'malformed action or verifier options',
};

describe('verifyHybridThreshold fail-closed catch', () => {
  it('null options give the refusal verdict, not undefined', () => {
    expect(verifyHybridThreshold({} as never, ART, null as never)).toEqual(REFUSAL);
  });
  it('a malformed action gives the refusal verdict', () => {
    expect(verifyHybridThreshold(null as never, ART, {} as never)).toEqual(REFUSAL);
  });
});
